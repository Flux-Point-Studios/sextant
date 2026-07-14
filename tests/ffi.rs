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
const UTXO_EXPECTED_LOVELACE: u64 = 5_000_000;
const UTXO_EXPECTED_ADDR_LEN: usize = 29;
const UTXO_EXPECTED_DATUM_HEX: &str = "d8799fbfd8799f4040ffd8799f1a09d00ed6ffd8799f581c3c0307006496e072a496c0742e55af0c64284b5bf668f2b420fe4f3540ffd8799f1a3b9aca00ffff1b0000019f53ec4417ff";
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
fn abi_version_is_five() {
    assert_eq!(sextant_abi_version(), 5);
    assert_eq!(sextant_abi_version(), SEXTANT_ABI_VERSION);
}

/// The CORE (ungated, wasm-safe) UTxO-read export: it computes the SAME verdict as
/// the in-process `verify_utxo_read` on the real golden order, marshals the
/// variable-length address/datum via the caller-sizing (`-3`) protocol, and rejects
/// a spoofed body as not-included — all without pulling any mithril/blst symbol.
mod utxo_ffi {
    use super::{
        UTXO_CERTIFIED_BLOCK, UTXO_EXPECTED_ADDR_LEN, UTXO_EXPECTED_DATUM_HEX,
        UTXO_EXPECTED_LOVELACE, UTXO_OUT0_ADDR_HEX, no_detail, tamper_output0_coin, unhex,
        utxo_certified_root, utxo_proof_hex, utxo_tx_body,
    };
    use sextant::ffi::{
        SEXTANT_SPEND_NOT_ESTABLISHED, SextantErrorDetail, SextantStatus, SextantVerifiedOutput,
        sextant_verify_utxo_read,
    };
    use std::ptr;

    fn zeroed() -> SextantVerifiedOutput {
        // SAFETY: `SextantVerifiedOutput` is a plain `#[repr(C)]` scalar aggregate.
        unsafe { std::mem::zeroed() }
    }

    /// Call the export over borrowed inputs and raw output buffers (raw so a test can
    /// pass `NULL`/`0` as a sizing probe).
    #[allow(clippy::too_many_arguments)]
    fn verify_raw(
        body: &[u8],
        out_index: usize,
        proof: &[u8],
        root: &[u8; 32],
        block: u64,
        out: *mut SextantVerifiedOutput,
        addr_buf: *mut u8,
        addr_cap: usize,
        datum_buf: *mut u8,
        datum_cap: usize,
        detail: *mut SextantErrorDetail,
    ) -> i32 {
        unsafe {
            sextant_verify_utxo_read(
                body.as_ptr(),
                body.len(),
                out_index,
                proof.as_ptr(),
                proof.len(),
                root.as_ptr(),
                block,
                out,
                addr_buf,
                addr_cap,
                datum_buf,
                datum_cap,
                detail,
            )
        }
    }

    /// The golden order verifies through the C ABI: the struct scalars match the
    /// in-process verdict and the variable-length address + inline datum land in the
    /// caller buffers.
    #[test]
    fn good_read_fills_struct_and_buffers() {
        let (body, proof, root) = (utxo_tx_body(), utxo_proof_hex(), utxo_certified_root());
        let expected_datum = unhex(UTXO_EXPECTED_DATUM_HEX);
        let mut out = zeroed();
        let mut addr = [0u8; 64];
        let mut datum = [0u8; 256];
        let mut d = no_detail();

        let rc = verify_raw(
            &body,
            0,
            &proof,
            &root,
            UTXO_CERTIFIED_BLOCK,
            &mut out,
            addr.as_mut_ptr(),
            addr.len(),
            datum.as_mut_ptr(),
            datum.len(),
            &mut d,
        );

        assert_eq!(rc, SextantStatus::Ok as i32);
        assert_eq!(out.lovelace, UTXO_EXPECTED_LOVELACE);
        assert_eq!(out.certified_at, UTXO_CERTIFIED_BLOCK);
        assert_eq!(out.address_len, UTXO_EXPECTED_ADDR_LEN);
        assert_eq!(out.datum_kind, 2, "an inline datum");
        assert_eq!(out.datum_len, expected_datum.len());
        assert_eq!(out.spend_status, SEXTANT_SPEND_NOT_ESTABLISHED);
        assert_eq!(out._reserved, [0u8; 6]);
        assert_eq!(
            &addr[..out.address_len],
            unhex(UTXO_OUT0_ADDR_HEX).as_slice()
        );
        assert_eq!(&datum[..out.datum_len], expected_datum.as_slice());
        assert_eq!(d.index, -1);
    }

    /// A pure sizing probe (`NULL` buffers, caps `0`) reports `-3` with the true
    /// lengths and touches no buffer.
    #[test]
    fn sizing_query_null_bufs() {
        let (body, proof, root) = (utxo_tx_body(), utxo_proof_hex(), utxo_certified_root());
        let mut out = zeroed();
        let mut d = no_detail();
        let rc = verify_raw(
            &body,
            0,
            &proof,
            &root,
            UTXO_CERTIFIED_BLOCK,
            &mut out,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            0,
            &mut d,
        );
        assert_eq!(rc, SextantStatus::ErrBufferTooSmall as i32);
        assert_eq!(out.address_len, UTXO_EXPECTED_ADDR_LEN);
        assert_eq!(out.datum_len, unhex(UTXO_EXPECTED_DATUM_HEX).len());
        assert_eq!(out.datum_kind, 2);
        assert_eq!(out.spend_status, SEXTANT_SPEND_NOT_ESTABLISHED);
    }

    /// Exact caps succeed; a datum buffer one byte short of the true length rejects
    /// with `-3` and copies NOTHING (not a truncated prefix) into either buffer.
    #[test]
    fn buffer_too_small_reports_true_lengths() {
        let (body, proof, root) = (utxo_tx_body(), utxo_proof_hex(), utxo_certified_root());
        let expected_datum = unhex(UTXO_EXPECTED_DATUM_HEX);

        // Exact caps -> Ok, full datum delivered.
        let mut out = zeroed();
        let mut addr = vec![0u8; UTXO_EXPECTED_ADDR_LEN];
        let mut datum = vec![0u8; expected_datum.len()];
        let mut d = no_detail();
        let rc = verify_raw(
            &body,
            0,
            &proof,
            &root,
            UTXO_CERTIFIED_BLOCK,
            &mut out,
            addr.as_mut_ptr(),
            addr.len(),
            datum.as_mut_ptr(),
            datum.len(),
            &mut d,
        );
        assert_eq!(rc, SextantStatus::Ok as i32);
        assert_eq!(datum, expected_datum);

        // Address fits, datum one byte short -> -3 and NO partial copy on either buffer.
        let mut out = zeroed();
        let mut addr = vec![0u8; UTXO_EXPECTED_ADDR_LEN];
        let mut datum = vec![0xAAu8; expected_datum.len() - 1];
        let rc = verify_raw(
            &body,
            0,
            &proof,
            &root,
            UTXO_CERTIFIED_BLOCK,
            &mut out,
            addr.as_mut_ptr(),
            addr.len(),
            datum.as_mut_ptr(),
            datum.len(),
            &mut d,
        );
        assert_eq!(rc, SextantStatus::ErrBufferTooSmall as i32);
        assert_eq!(out.address_len, UTXO_EXPECTED_ADDR_LEN);
        assert_eq!(out.datum_len, expected_datum.len());
        assert_eq!(
            addr,
            vec![0u8; UTXO_EXPECTED_ADDR_LEN],
            "address left untouched"
        );
        assert_eq!(
            datum,
            vec![0xAAu8; expected_datum.len() - 1],
            "datum left untouched (no truncated prefix)"
        );
    }

    /// A spoofed body (one output-coin byte flipped) hashes to a value the proof does
    /// not attest — rejected as not-included (400) before any output is decoded.
    #[test]
    fn tampered_bytes_not_included() {
        let (proof, root) = (utxo_proof_hex(), utxo_certified_root());
        let body = tamper_output0_coin(&utxo_tx_body());
        let mut out = zeroed();
        let mut addr = [0u8; 64];
        let mut datum = [0u8; 256];
        let mut d = no_detail();
        let rc = verify_raw(
            &body,
            0,
            &proof,
            &root,
            UTXO_CERTIFIED_BLOCK,
            &mut out,
            addr.as_mut_ptr(),
            addr.len(),
            datum.as_mut_ptr(),
            datum.len(),
            &mut d,
        );
        assert_eq!(rc, SextantStatus::UtxoInclusionNotIncluded as i32);
    }

    /// An output index past the end (real bytes, so inclusion passes first) reports
    /// the out-of-range status.
    #[test]
    fn out_of_range_index() {
        let (body, proof, root) = (utxo_tx_body(), utxo_proof_hex(), utxo_certified_root());
        let mut out = zeroed();
        let mut addr = [0u8; 64];
        let mut datum = [0u8; 256];
        let mut d = no_detail();
        let rc = verify_raw(
            &body,
            99,
            &proof,
            &root,
            UTXO_CERTIFIED_BLOCK,
            &mut out,
            addr.as_mut_ptr(),
            addr.len(),
            datum.as_mut_ptr(),
            datum.len(),
            &mut d,
        );
        assert_eq!(rc, SextantStatus::UtxoOutputIndexOutOfRange as i32);
    }

    /// Null required pointers and a zero-length tx body are caller errors, reported
    /// without touching the verifier.
    #[test]
    fn null_and_empty_guards() {
        let (body, proof, root) = (utxo_tx_body(), utxo_proof_hex(), utxo_certified_root());
        let mut out = zeroed();
        let mut addr = [0u8; 64];
        let mut datum = [0u8; 256];
        let mut d = no_detail();

        // Null tx_bytes.
        let rc = unsafe {
            sextant_verify_utxo_read(
                ptr::null(),
                10,
                0,
                proof.as_ptr(),
                proof.len(),
                root.as_ptr(),
                UTXO_CERTIFIED_BLOCK,
                &mut out,
                addr.as_mut_ptr(),
                addr.len(),
                datum.as_mut_ptr(),
                datum.len(),
                &mut d,
            )
        };
        assert_eq!(rc, SextantStatus::ErrNullPointer as i32);

        // Null out struct.
        let rc = verify_raw(
            &body,
            0,
            &proof,
            &root,
            UTXO_CERTIFIED_BLOCK,
            ptr::null_mut(),
            addr.as_mut_ptr(),
            addr.len(),
            datum.as_mut_ptr(),
            datum.len(),
            &mut d,
        );
        assert_eq!(rc, SextantStatus::ErrNullPointer as i32);

        // Zero-length tx bytes (non-null ptr, len 0) -> empty input.
        let rc = verify_raw(
            &[],
            0,
            &proof,
            &root,
            UTXO_CERTIFIED_BLOCK,
            &mut out,
            addr.as_mut_ptr(),
            addr.len(),
            datum.as_mut_ptr(),
            datum.len(),
            &mut d,
        );
        assert_eq!(rc, SextantStatus::ErrEmptyInput as i32);
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
        UTXO_CERTIFIED_BLOCK, UTXO_CERTIFIED_ROOT_HEX, UTXO_EXPECTED_DATUM_HEX,
        UTXO_EXPECTED_LOVELACE, no_detail, tamper_output0_coin, unhex, utxo_proof_hex,
        utxo_tx_body, vectors_dir,
    };
    use sextant::ffi::{
        SEXTANT_SPEND_NOT_ESTABLISHED, SextantErrorDetail, SextantStatus, SextantVerifiedOutput,
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
    /// root from the AUTHENTICATED tip, feed it straight into the UTxO-read export, and
    /// run the order predicate — then a spoofed body rejects as not-included (400).
    #[test]
    fn anchored_root_feeds_a_verified_utxo_read() {
        let a = anchored(&anchor_chain_certs(), Some(&genesis_vkey()));
        assert_eq!(a.rc, SextantStatus::Ok as i32);
        assert_eq!(a.has_ct, 1);

        let proof = utxo_proof_hex();
        let expected_datum = unhex(UTXO_EXPECTED_DATUM_HEX);
        let mut out: SextantVerifiedOutput = unsafe { std::mem::zeroed() };
        let mut addr = [0u8; 64];
        let mut datum = [0u8; 256];
        let mut d = no_detail();

        // Authentic body -> Ok, meets the order predicate over the verified output.
        let body = utxo_tx_body();
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
        assert_eq!(rc, SextantStatus::Ok as i32);
        assert_eq!(out.certified_at, UTXO_CERTIFIED_BLOCK);
        let proceed = out.lovelace >= UTXO_EXPECTED_LOVELACE
            && out.datum_kind == 2
            && datum[..out.datum_len] == expected_datum[..];
        assert!(proceed, "the authentic certified order meets the predicate");
        assert_eq!(out.spend_status, SEXTANT_SPEND_NOT_ESTABLISHED);

        // Spoofed body -> not included (400); never reaches the predicate.
        let spoof = tamper_output0_coin(&body);
        let rc = unsafe {
            sextant_verify_utxo_read(
                spoof.as_ptr(),
                spoof.len(),
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
        assert_eq!(rc, SextantStatus::UtxoInclusionNotIncluded as i32);
    }
}
