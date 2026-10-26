//! FFI boundary (DoD line 6, artifacts part 1): the read-path verdicts exposed
//! over the C ABI compute the SAME verdict as the in-process Rust path, on real
//! vectors, and every error flattens to its stable status code + offending index.
//!
//! These tests call the `extern "C"` exports directly from Rust (same process),
//! proving the FFI LOGIC — pointer marshalling, the error→status mapping, the
//! header projection, the null/empty guards. External C linkage + symbol
//! retention are proven separately by the CI-only C smoke test (artifacts part 2).

use std::fs;
use std::path::PathBuf;
use std::ptr;

use sextant::ffi::{
    SEXTANT_ABI_VERSION, SextantErrorDetail, SextantHeaderView, SextantStatus, sextant_abi_version,
    sextant_header_decode, sextant_status_message, sextant_verify_segment,
};
use sextant::header::HeaderView;

/// Epoch-300 active nonce (Koios), shared by every preprod vector's `.eta0`
/// sidecar — the segment is verified against this named value, as in the chain slice.
const EPOCH_300_ETA0: &str = "aa845533c5f8631a864010ae89c23ee1cee0ed7717e4ac00a25ad50f4eeb6c30";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The stored contiguous preprod run (block bytes in on-chain order) and the epoch
/// nonce they share — the same segment the chain slice verifies.
fn preprod_segment() -> (Vec<Vec<u8>>, [u8; 32]) {
    let mut rows: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut eta0: Option<[u8; 32]> = None;
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with("preprod-")
            || path.extension().and_then(|e| e.to_str()) != Some("block")
        {
            continue;
        }
        let Ok(eta0_hex) = fs::read_to_string(path.with_extension("eta0")) else {
            continue;
        };
        let seen: [u8; 32] = unhex(&eta0_hex).try_into().expect("eta0 is 32 bytes");
        match eta0 {
            Some(e) => assert_eq!(e, seen, "preprod segment spans one epoch (one eta0)"),
            None => eta0 = Some(seen),
        }
        let bytes = unhex(&fs::read_to_string(&path).expect("read vector"));
        let view = HeaderView::from_block_cbor(&bytes).expect("decode");
        rows.push((view.slot, bytes));
    }
    rows.sort_by_key(|r| r.0);
    (
        rows.into_iter().map(|r| r.1).collect(),
        eta0.expect("at least one preprod vector with an eta0 sidecar"),
    )
}

/// Call `sextant_verify_segment` over borrowed block slices and an optional eta0
/// (`None` passes a null pointer to exercise the null guard).
fn verify_segment_ffi(
    blocks: &[Vec<u8>],
    eta0: Option<&[u8; 32]>,
    detail: &mut SextantErrorDetail,
) -> i32 {
    let ptrs: Vec<*const u8> = blocks.iter().map(|b| b.as_ptr()).collect();
    let lens: Vec<usize> = blocks.iter().map(|b| b.len()).collect();
    let eta0_ptr = eta0.map_or(ptr::null(), |e| e.as_ptr());
    unsafe { sextant_verify_segment(ptrs.as_ptr(), lens.as_ptr(), blocks.len(), eta0_ptr, detail) }
}

fn no_detail() -> SextantErrorDetail {
    SextantErrorDetail {
        index: 0,
        detail: 0,
    }
}

// --- UTxO-read fixtures (the same real preprod order the Rust example reads: tx
// 242f2037…a636#0, epoch 300, certified block 4927469). Shared by the ungated
// utxo_ffi tests and the mithril end-to-end compose. ---
const UTXO_CERTIFIED_ROOT_HEX: &str =
    "83c012fdc3e756fb5230d1a6554fbf743ccea171b37d536a64350c4f5d774129";
const UTXO_CERTIFIED_BLOCK: u64 = 4927469;
/// Output 0's script address; the tamper flips the coin byte that follows it.
const UTXO_OUT0_ADDR_HEX: &str = "7015e93b4326724b8e2d3abc3a6aaef29ce6d6877cfc815eb8f3bd3699";

fn utxo_tx_body() -> Vec<u8> {
    unhex(&fs::read_to_string(vectors_dir().join("mithril-tx-body.cbor")).expect("read tx body"))
}

fn utxo_proof_hex() -> Vec<u8> {
    let bytes = fs::read(vectors_dir().join("mithril-txproof.json")).expect("read txproof");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse txproof");
    v["certified_transactions"][0]["proof"]
        .as_str()
        .expect("proof field")
        .as_bytes()
        .to_vec()
}

fn utxo_certified_root() -> [u8; 32] {
    unhex(UTXO_CERTIFIED_ROOT_HEX)
        .try_into()
        .expect("32-byte certified root")
}

/// Flip output 0's coin byte (the analogue of `gate::tamper_output0_coin`): a
/// spoofed provider response whose body no longer hashes to the certified leaf.
fn tamper_output0_coin(body: &[u8]) -> Vec<u8> {
    let addr = unhex(UTXO_OUT0_ADDR_HEX);
    let pos = body
        .windows(addr.len())
        .position(|w| w == addr.as_slice())
        .expect("output 0 address present in the body");
    let coin_byte = pos + addr.len() + 3;
    let mut t = body.to_vec();
    t[coin_byte] ^= 0x01;
    t
}

/// RED anchor: the known-good preprod segment verifies through the C ABI with a
/// clean `{index:-1, detail:0}`.
#[test]
fn verify_segment_good() {
    let (blocks, eta0) = preprod_segment();
    assert!(blocks.len() >= 20, "DoD floor of ≥20 vectors");
    assert_eq!(hex::encode(eta0), EPOCH_300_ETA0, "named epoch-300 nonce");

    let mut d = no_detail();
    let rc = verify_segment_ffi(&blocks, Some(&eta0), &mut d);
    assert_eq!(rc, SextantStatus::Ok as i32);
    assert_eq!(d.index, -1);
    assert_eq!(d.detail, 0);
}

/// A dropped block breaks the hash link at its position; the status carries the
/// class and the offending index.
#[test]
fn verify_segment_broken_link_reports_index() {
    let (blocks, eta0) = preprod_segment();
    let drop = blocks.len() / 2;
    let mut blocks = blocks;
    blocks.remove(drop);

    let mut d = no_detail();
    let rc = verify_segment_ffi(&blocks, Some(&eta0), &mut d);
    assert_eq!(rc, SextantStatus::ChainBrokenLink as i32);
    assert_eq!(d.index, drop as i64);
    assert_eq!(d.detail, 0);
}

/// A tampered leader-VRF proof rejects at its block, and `detail` carries the inner
/// VRF leaf code (the 110-band), not the block index.
#[test]
fn verify_segment_tampered_vrf_reports_index_and_detail() {
    let (blocks, eta0) = preprod_segment();
    let k = blocks.len() / 2;
    let view = HeaderView::from_block_cbor(&blocks[k]).expect("decode");
    let mut tampered = blocks.clone();
    let block = &mut tampered[k];
    let at = block
        .windows(view.vrf_proof.len())
        .position(|w| w == view.vrf_proof)
        .expect("vrf_proof present in block bytes");
    block[at + view.vrf_proof.len() / 2] ^= 0x01;

    let mut d = no_detail();
    let rc = verify_segment_ffi(&tampered, Some(&eta0), &mut d);
    assert_eq!(rc, SextantStatus::ChainVrf as i32);
    assert_eq!(d.index, k as i64);
    assert!(
        (110..=113).contains(&d.detail),
        "detail carries the inner VRF leaf code, got {}",
        d.detail,
    );
}

/// A null `eta0` pointer is a caller error, reported without touching the verifier.
#[test]
fn verify_segment_null_eta0_is_rejected() {
    let (blocks, _eta0) = preprod_segment();
    let mut d = no_detail();
    let rc = verify_segment_ffi(&blocks, None, &mut d);
    assert_eq!(rc, SextantStatus::ErrNullPointer as i32);
}

/// A zero-count segment is an empty-input caller error.
#[test]
fn verify_segment_empty_is_rejected() {
    let mut d = no_detail();
    let rc = verify_segment_ffi(&[], Some(&[0u8; 32]), &mut d);
    assert_eq!(rc, SextantStatus::ErrEmptyInput as i32);
}

/// `sextant_header_decode` fills the fixed struct with the same fields the Rust
/// path decodes, including the opcert scalars and (for a mid-chain block) a present
/// `prev_hash`.
#[test]
fn header_decode_matches_rust_path() {
    let (blocks, _eta0) = preprod_segment();
    let bytes = &blocks[0];
    let view = HeaderView::from_block_cbor(bytes).expect("decode");

    let mut out: SextantHeaderView = unsafe { std::mem::zeroed() };
    let mut d = no_detail();
    let rc = unsafe { sextant_header_decode(bytes.as_ptr(), bytes.len(), &mut out, &mut d) };
    assert_eq!(rc, SextantStatus::Ok as i32);
    assert_eq!(d.index, -1);

    assert_eq!(out.block_number, view.block_number);
    assert_eq!(out.slot, view.slot);
    assert_eq!(out.era, view.era);
    assert_eq!(out.block_hash, view.block_hash);
    assert_eq!(out.has_prev_hash, 1);
    assert_eq!(
        out.prev_hash,
        view.prev_hash.expect("mid-chain block has a parent")
    );
    assert_eq!(out.issuer_vkey, view.issuer_vkey);
    assert_eq!(out.vrf_vkey, view.vrf_vkey);
    assert_eq!(out.vrf_output, view.vrf_output);
    assert_eq!(out.opcert_hot_vkey, view.opcert.hot_vkey);
    assert_eq!(out.opcert_sequence_number, view.opcert.sequence_number);
    assert_eq!(out.opcert_kes_period, view.opcert.kes_period);
}

/// Malformed CBOR and an unsupported era each map to their decode status; the
/// unsupported-era detail carries the era scalar the standalone decode path surfaces.
#[test]
fn header_decode_rejects_malformed_and_unsupported_era() {
    let (blocks, _eta0) = preprod_segment();
    let mut out: SextantHeaderView = unsafe { std::mem::zeroed() };
    let mut d = no_detail();

    let rc = unsafe { sextant_header_decode(blocks[0].as_ptr(), 10, &mut out, &mut d) };
    assert_eq!(rc, SextantStatus::DecodeMalformedCbor as i32);

    let mut era5 = blocks[0].clone();
    assert_eq!(era5[0], 0x82, "outer [era, block] definite array");
    era5[1] = 0x05; // Alonzo — not a supported Praos era
    let rc = unsafe { sextant_header_decode(era5.as_ptr(), era5.len(), &mut out, &mut d) };
    assert_eq!(rc, SextantStatus::DecodeUnsupportedEra as i32);
    assert_eq!(d.index, -1);
    assert_eq!(d.detail, 5, "standalone decode surfaces the era scalar");
}

/// `sextant_status_message` answers a sizing query on a null buffer and copies the
/// message bytes when given one.
#[test]
fn status_message_sizes_then_copies() {
    let status = SextantStatus::ChainVrf as i32;
    let need = unsafe { sextant_status_message(status, ptr::null_mut(), 0) };
    assert!(need > 0, "a known status has a non-empty message");

    let mut buf = vec![0u8; need];
    let n = unsafe { sextant_status_message(status, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(n, need);
    assert!(!std::str::from_utf8(&buf[..n]).expect("utf8").is_empty());
}

#[test]
fn abi_version_is_six() {
    assert_eq!(sextant_abi_version(), 6);
    assert_eq!(sextant_abi_version(), SEXTANT_ABI_VERSION);
}

/// The CORE (ungated, wasm-safe) UTxO-read export over the real golden order: every
/// included body is refused with `UtxoValidityNotEstablished` (412), as the in-process
/// `verify_utxo_read` refuses it, after the inclusion, decode and index checks keep their
/// order; no return writes the out-struct or either buffer — sentinel bytes survive every
/// call — and the boundary guards never write the detail.
mod utxo_ffi {
    use super::{
        UTXO_CERTIFIED_BLOCK, tamper_output0_coin, utxo_certified_root, utxo_proof_hex,
        utxo_tx_body,
    };
    use sextant::ffi::{
        SEXTANT_SPEND_NOT_ESTABLISHED, SextantErrorDetail, SextantStatus, SextantVerifiedOutput,
        sextant_verify_utxo_read,
    };
    use std::mem::{MaybeUninit, size_of};
    use std::ptr;

    const STRUCT_SENTINEL: u8 = 0x5a;
    const BUFFER_SENTINEL: u8 = 0xaa;

    /// An out-struct with every byte set to [`STRUCT_SENTINEL`], so any write shows.
    fn sentinel() -> SextantVerifiedOutput {
        let mut out = MaybeUninit::<SextantVerifiedOutput>::uninit();
        // SAFETY: every byte is written, and the struct is a padding-free `#[repr(C)]`
        // aggregate of integers that takes any bit pattern.
        unsafe {
            out.as_mut_ptr().write_bytes(STRUCT_SENTINEL, 1);
            out.assume_init()
        }
    }

    fn struct_bytes(out: &SextantVerifiedOutput) -> &[u8] {
        // SAFETY: the struct is padding-free, so all of its bytes are initialised.
        unsafe {
            std::slice::from_raw_parts(
                (out as *const SextantVerifiedOutput).cast::<u8>(),
                size_of::<SextantVerifiedOutput>(),
            )
        }
    }

    fn sentinel_detail() -> SextantErrorDetail {
        SextantErrorDetail {
            index: 77,
            detail: 77,
        }
    }

    /// Call the export over borrowed inputs into sentinel-filled outputs, `buffers`
    /// choosing 256-byte buffers or a `NULL`/`0` sizing probe, and report the status and
    /// whether the struct and both buffers came back as they went in.
    fn read(
        body: &[u8],
        out_index: usize,
        root: &[u8; 32],
        buffers: bool,
    ) -> (i32, bool, SextantErrorDetail) {
        let proof = utxo_proof_hex();
        let mut out = sentinel();
        let mut addr = [BUFFER_SENTINEL; 256];
        let mut datum = [BUFFER_SENTINEL; 256];
        let mut d = sentinel_detail();
        let (addr_ptr, addr_cap, datum_ptr, datum_cap) = if buffers {
            (
                addr.as_mut_ptr(),
                addr.len(),
                datum.as_mut_ptr(),
                datum.len(),
            )
        } else {
            (ptr::null_mut(), 0, ptr::null_mut(), 0)
        };
        let rc = unsafe {
            sextant_verify_utxo_read(
                body.as_ptr(),
                body.len(),
                out_index,
                proof.as_ptr(),
                proof.len(),
                root.as_ptr(),
                UTXO_CERTIFIED_BLOCK,
                &mut out,
                addr_ptr,
                addr_cap,
                datum_ptr,
                datum_cap,
                &mut d,
            )
        };
        let untouched = struct_bytes(&out).iter().all(|b| *b == STRUCT_SENTINEL)
            && addr.iter().chain(&datum).all(|b| *b == BUFFER_SENTINEL);
        (rc, untouched, d)
    }

    /// Both outputs of the golden order are included and refused: 412, the detail
    /// `{-1, 0}`, and nothing marshalled — with room in the buffers and as a sizing probe
    /// alike, so no `-3` lengths leak either.
    #[test]
    fn an_included_read_refuses_and_writes_no_output() {
        let (body, root) = (utxo_tx_body(), utxo_certified_root());
        for index in [0, 1] {
            for buffers in [true, false] {
                let (rc, untouched, d) = read(&body, index, &root, buffers);
                assert_eq!(rc, SextantStatus::UtxoValidityNotEstablished as i32);
                assert!(untouched, "{index} {buffers}");
                assert_eq!((d.index, d.detail), (-1, 0));
            }
        }
    }

    /// The refusals keep their order and their codes, each leaving the outputs alone: a
    /// spoofed body is not included (400) even at an index past its outputs, a wrong root
    /// recomputes to no certified root, and an index past the outputs of the included
    /// body is 411, ahead of 412.
    #[test]
    fn the_refusals_keep_their_order_and_write_no_output() {
        let (body, root) = (utxo_tx_body(), utxo_certified_root());
        let spoof = tamper_output0_coin(&body);
        let mut wrong_root = root;
        wrong_root[0] ^= 0x01;
        for (case, rc, expected) in [
            (
                "spoof",
                read(&spoof, 0, &root, true),
                SextantStatus::UtxoInclusionNotIncluded,
            ),
            (
                "spoof past the end",
                read(&spoof, 99, &root, true),
                SextantStatus::UtxoInclusionNotIncluded,
            ),
            (
                "past the end",
                read(&body, 2, &root, true),
                SextantStatus::UtxoOutputIndexOutOfRange,
            ),
        ] {
            assert_eq!(rc.0, expected as i32, "{case}");
            assert!(rc.1, "{case}");
            assert_eq!((rc.2.index, rc.2.detail), (-1, 0), "{case}");
        }
        let (rc, untouched, _) = read(&body, 0, &wrong_root, true);
        assert!(
            [
                SextantStatus::UtxoInclusionNotIncluded as i32,
                SextantStatus::UtxoInclusionRootMismatch as i32
            ]
            .contains(&rc),
            "{rc}"
        );
        assert!(untouched);
    }

    /// Null required pointers and a zero-length tx body are caller errors, reported
    /// without touching the verifier, the out-struct or the detail; a null pointer is
    /// reported ahead of an empty one.
    #[test]
    fn null_and_empty_guards() {
        let (body, proof, root) = (utxo_tx_body(), utxo_proof_hex(), utxo_certified_root());
        let mut out = sentinel();
        let mut d = sentinel_detail();
        let call = |tx: *const u8,
                    len: usize,
                    out: *mut SextantVerifiedOutput,
                    d: &mut SextantErrorDetail| unsafe {
            sextant_verify_utxo_read(
                tx,
                len,
                0,
                proof.as_ptr(),
                proof.len(),
                root.as_ptr(),
                UTXO_CERTIFIED_BLOCK,
                out,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                d,
            )
        };
        assert_eq!(
            call(ptr::null(), 0, &mut out, &mut d),
            SextantStatus::ErrNullPointer as i32
        );
        assert_eq!(
            call(body.as_ptr(), body.len(), ptr::null_mut(), &mut d),
            SextantStatus::ErrNullPointer as i32
        );
        assert_eq!(
            call(body.as_ptr(), 0, &mut out, &mut d),
            SextantStatus::ErrEmptyInput as i32
        );
        assert!(struct_bytes(&out).iter().all(|b| *b == STRUCT_SENTINEL));
        assert_eq!((d.index, d.detail), (77, 77));
    }

    /// The honest-scope constant is the only defined spend-status value, and it is 0.
    #[test]
    fn spend_status_constant_is_zero() {
        assert_eq!(SEXTANT_SPEND_NOT_ESTABLISHED, 0);
    }
}

#[cfg(feature = "mithril")]
mod mithril_ffi {
    use super::{
        UTXO_CERTIFIED_BLOCK, UTXO_CERTIFIED_ROOT_HEX, no_detail, tamper_output0_coin,
        utxo_proof_hex, utxo_tx_body, vectors_dir,
    };
    use sextant::ffi::{
        SextantErrorDetail, SextantStatus, SextantVerifiedOutput,
        sextant_mithril_verify_chain_anchored, sextant_verify_utxo_read,
    };
    use sextant::mithril::Certificate;
    use std::fs;
    use std::ptr;

    /// The real preprod genesis anchor (epoch-196 re-genesis) and its epoch-197 child
    /// tip — the endpoints `verify_chain_anchored` names.
    const GENESIS_HASH: &str = "69bc3bdfff0bb134675396e83b301f43e763d576d4b85856f6b3cb806af7ad59";
    const TIP_HASH: &str = "fc979366ab86682b08901ad69c4de5c9cce503684fba038807d44c59f2d56b72";

    fn genesis_vkey() -> [u8; 32] {
        let text =
            fs::read_to_string(vectors_dir().join("mithril-genesis.vkey")).expect("read vkey");
        hex::decode(text.trim())
            .expect("vkey hex")
            .try_into()
            .expect("32-byte genesis vkey")
    }

    fn read_json(name: &str) -> Vec<u8> {
        fs::read(vectors_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    /// The 106-cert genesis→tip anchor chain, split into per-certificate JSON blobs
    /// (oldest first) — the array the FFI export consumes cert-by-cert. The tip is a
    /// real `CardanoTransactions` certificate, so the verify surfaces a certified root.
    fn anchor_chain_certs() -> Vec<Vec<u8>> {
        let bytes = fs::read(vectors_dir().join("mithril-anchor-chain.json")).expect("read chain");
        let arr: Vec<serde_json::Value> =
            serde_json::from_slice(&bytes).expect("chain is an array");
        arr.iter()
            .map(|c| serde_json::to_vec(c).expect("reserialize cert"))
            .collect()
    }

    /// Reseal a JSON certificate after a field tamper: recompute its content hash on
    /// Sextant's own path and splice it back into the `hash` field so the integrity
    /// check passes and a *deeper* verifier (link / STM) is what rejects it.
    fn reseal_json(json: &str, old_hash: &str) -> Vec<u8> {
        let cert = Certificate::from_json(json.as_bytes()).expect("valid json to reseal");
        let new_hash = cert.compute_hash();
        json.replacen(old_hash, &new_hash, 1).into_bytes()
    }

    fn flip_first_hex_char(s: &str) -> String {
        let mut chars: Vec<char> = s.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        chars.into_iter().collect()
    }

    /// The full out-param surface of one anchored verify: the verdict, the hex
    /// root/tip, the length, the certified-transactions triple, and the detail.
    struct Anchored {
        rc: i32,
        root: [u8; 64],
        tip: [u8; 64],
        length: u64,
        ct_root: [u8; 32],
        ct_block: u64,
        has_ct: u8,
        detail: SextantErrorDetail,
    }

    fn anchored(certs: &[Vec<u8>], vkey: Option<&[u8; 32]>) -> Anchored {
        let ptrs: Vec<*const u8> = certs.iter().map(|c| c.as_ptr()).collect();
        let lens: Vec<usize> = certs.iter().map(|c| c.len()).collect();
        let vkey_ptr = vkey.map_or(ptr::null(), |v| v.as_ptr());
        let mut root = [0u8; 64];
        let mut tip = [0u8; 64];
        let mut length = 0u64;
        let mut ct_root = [0u8; 32];
        let mut ct_block = 0u64;
        let mut has_ct = 0u8;
        let mut detail = no_detail();
        let rc = unsafe {
            sextant_mithril_verify_chain_anchored(
                ptrs.as_ptr(),
                lens.as_ptr(),
                certs.len(),
                vkey_ptr,
                root.as_mut_ptr(),
                tip.as_mut_ptr(),
                &mut length,
                ct_root.as_mut_ptr(),
                &mut ct_block,
                &mut has_ct,
                &mut detail,
            )
        };
        Anchored {
            rc,
            root,
            tip,
            length,
            ct_root,
            ct_block,
            has_ct,
            detail,
        }
    }

    /// The genesis-anchored `[genesis, child]` segment verifies through the C ABI and
    /// names the root+tip; its tip being a stake-distribution cert, it surfaces NO
    /// certified transaction set (`has_ct == 0`, root zeroed) — the None branch.
    #[test]
    fn anchored_good_names_root_and_tip() {
        let certs = vec![
            read_json("mithril-genesis-cert.json"),
            read_json("mithril-genesis-child.json"),
        ];
        let a = anchored(&certs, Some(&genesis_vkey()));
        assert_eq!(a.rc, SextantStatus::Ok as i32);
        assert_eq!(std::str::from_utf8(&a.root).expect("utf8"), GENESIS_HASH);
        assert_eq!(std::str::from_utf8(&a.tip).expect("utf8"), TIP_HASH);
        assert_eq!(a.length, 2);
        assert_eq!(a.has_ct, 0, "a stake-distribution tip certifies no tx set");
        assert_eq!(a.ct_root, [0u8; 32]);
        assert_eq!(a.ct_block, 0);
        assert_eq!(a.detail.index, -1);
    }

    /// A certificate that is not valid JSON is reported with its position and the
    /// dedicated malformed-JSON status.
    #[test]
    fn anchored_bad_json_reports_index() {
        let certs = vec![
            read_json("mithril-genesis-cert.json"),
            b"{ not a certificate".to_vec(),
        ];
        let a = anchored(&certs, Some(&genesis_vkey()));
        assert_eq!(a.rc, SextantStatus::MithrilStdMalformedCertJson as i32);
        assert_eq!(a.detail.index, 1);
    }

    /// A wrong genesis verification key rejects at the genesis-anchor layer — proving
    /// the `AnchoredError::Genesis` arm flattens to its leaf code.
    #[test]
    fn anchored_wrong_vkey_rejects_at_genesis() {
        let certs = vec![
            read_json("mithril-genesis-cert.json"),
            read_json("mithril-genesis-child.json"),
        ];
        let mut vkey = genesis_vkey();
        vkey[0] ^= 0x01;
        let a = anchored(&certs, Some(&vkey));
        assert_eq!(a.rc, SextantStatus::MithrilGenesisInvalidSignature as i32);
    }

    /// A self-consistent (resealed) child whose link is broken rejects past the
    /// integrity guard — proving `AnchoredError::Chain(BrokenLink)` flattens with
    /// its certificate index.
    #[test]
    fn anchored_broken_link_reports_index() {
        let genesis = read_json("mithril-genesis-cert.json");
        let child_str = fs::read_to_string(vectors_dir().join("mithril-genesis-child.json"))
            .expect("read child");
        let child = Certificate::from_json(child_str.as_bytes()).expect("parse child");
        let relinked = child_str.replacen(&child.previous_hash, &"00".repeat(32), 1);
        let resealed = reseal_json(&relinked, &child.hash);

        let a = anchored(&[genesis, resealed], Some(&genesis_vkey()));
        assert_eq!(a.rc, SextantStatus::MithrilChainBrokenLink as i32);
        assert_eq!(a.detail.index, 1);
    }

    /// A self-consistent (resealed) child whose multi-signature is corrupted rejects
    /// at the standard-cert layer — proving `AnchoredError::Standard{index}` flattens
    /// to a 320-band leaf with the offending index.
    #[test]
    fn anchored_tampered_authority_reports_index() {
        let genesis = read_json("mithril-genesis-cert.json");
        let child_str = fs::read_to_string(vectors_dir().join("mithril-genesis-child.json"))
            .expect("read child");
        let child = Certificate::from_json(child_str.as_bytes()).expect("parse child");
        let corrupted = child_str.replacen(
            &child.multi_signature,
            &flip_first_hex_char(&child.multi_signature),
            1,
        );
        let resealed = reseal_json(&corrupted, &child.hash);

        let a = anchored(&[genesis, resealed], Some(&genesis_vkey()));
        assert!(
            (320..=326).contains(&a.rc),
            "standard-cert layer rejection (320 band), got {}",
            a.rc,
        );
        assert_eq!(a.detail.index, 1);
    }

    /// The full 106-cert chain verifies and its `CardanoTransactions` tip surfaces the
    /// certified root+height — the only way a consumer obtains a certified root, so it
    /// is honest by construction (it exists only after the genesis-anchored verify).
    #[test]
    fn anchored_surfaces_the_certified_transaction_root() {
        let a = anchored(&anchor_chain_certs(), Some(&genesis_vkey()));
        assert_eq!(a.rc, SextantStatus::Ok as i32);
        assert_eq!(a.has_ct, 1);
        assert_eq!(a.ct_block, UTXO_CERTIFIED_BLOCK);
        assert_eq!(hex::encode(a.ct_root), UTXO_CERTIFIED_ROOT_HEX);
    }

    /// End-to-end C-ABI compose: authenticate the chain to genesis, take the certified
    /// root from the AUTHENTICATED tip, and feed it straight into the UTxO-read export.
    /// The authentic body is included under it and still refused (412): inclusion
    /// establishes no output, so the struct and buffers stay as they were. A spoofed
    /// body is not included (400).
    #[test]
    fn anchored_root_admits_the_body_and_establishes_no_output() {
        let a = anchored(&anchor_chain_certs(), Some(&genesis_vkey()));
        assert_eq!(a.rc, SextantStatus::Ok as i32);
        assert_eq!(a.has_ct, 1);

        let proof = utxo_proof_hex();
        let read = |body: &[u8]| {
            let mut out: SextantVerifiedOutput = unsafe { std::mem::zeroed() };
            let mut addr = [0u8; 64];
            let mut datum = [0u8; 256];
            let mut d = no_detail();
            let rc = unsafe {
                sextant_verify_utxo_read(
                    body.as_ptr(),
                    body.len(),
                    0,
                    proof.as_ptr(),
                    proof.len(),
                    a.ct_root.as_ptr(),
                    a.ct_block,
                    &mut out,
                    addr.as_mut_ptr(),
                    addr.len(),
                    datum.as_mut_ptr(),
                    datum.len(),
                    &mut d,
                )
            };
            let untouched = out.lovelace == 0
                && out.certified_at == 0
                && out.address_len == 0
                && out.datum_len == 0
                && addr.iter().chain(&datum).all(|b| *b == 0);
            (rc, untouched)
        };

        let body = utxo_tx_body();
        assert_eq!(a.ct_block, UTXO_CERTIFIED_BLOCK);
        assert_eq!(
            read(&body),
            (SextantStatus::UtxoValidityNotEstablished as i32, true)
        );
        assert_eq!(
            read(&tamper_output0_coin(&body)),
            (SextantStatus::UtxoInclusionNotIncluded as i32, true)
        );
    }
}
