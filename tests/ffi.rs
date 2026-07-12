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
fn abi_version_is_one() {
    assert_eq!(sextant_abi_version(), 1);
    assert_eq!(sextant_abi_version(), SEXTANT_ABI_VERSION);
}

#[cfg(feature = "mithril")]
mod mithril_ffi {
    use super::{no_detail, vectors_dir};
    use sextant::ffi::{SextantErrorDetail, SextantStatus, sextant_mithril_verify_chain_anchored};
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

    #[allow(clippy::too_many_arguments)]
    fn anchored_ffi(
        certs: &[Vec<u8>],
        vkey: Option<&[u8; 32]>,
        root: &mut [u8; 64],
        tip: &mut [u8; 64],
        length: &mut u64,
        detail: &mut SextantErrorDetail,
    ) -> i32 {
        let ptrs: Vec<*const u8> = certs.iter().map(|c| c.as_ptr()).collect();
        let lens: Vec<usize> = certs.iter().map(|c| c.len()).collect();
        let vkey_ptr = vkey.map_or(ptr::null(), |v| v.as_ptr());
        unsafe {
            sextant_mithril_verify_chain_anchored(
                ptrs.as_ptr(),
                lens.as_ptr(),
                certs.len(),
                vkey_ptr,
                root.as_mut_ptr(),
                tip.as_mut_ptr(),
                length,
                detail,
            )
        }
    }

    /// The real genesis-anchored segment verifies through the C ABI, and the hex
    /// out-buffers name the genesis root and the tip.
    #[test]
    fn anchored_good_names_root_and_tip() {
        let certs = vec![
            read_json("mithril-genesis-cert.json"),
            read_json("mithril-genesis-child.json"),
        ];
        let (mut root, mut tip, mut len, mut d) = ([0u8; 64], [0u8; 64], 0u64, no_detail());
        let rc = anchored_ffi(
            &certs,
            Some(&genesis_vkey()),
            &mut root,
            &mut tip,
            &mut len,
            &mut d,
        );
        assert_eq!(rc, SextantStatus::Ok as i32);
        assert_eq!(std::str::from_utf8(&root).expect("utf8"), GENESIS_HASH);
        assert_eq!(std::str::from_utf8(&tip).expect("utf8"), TIP_HASH);
        assert_eq!(len, 2);
        assert_eq!(d.index, -1);
    }

    /// A certificate that is not valid JSON is reported with its position and the
    /// dedicated malformed-JSON status.
    #[test]
    fn anchored_bad_json_reports_index() {
        let certs = vec![
            read_json("mithril-genesis-cert.json"),
            b"{ not a certificate".to_vec(),
        ];
        let (mut root, mut tip, mut len, mut d) = ([0u8; 64], [0u8; 64], 0u64, no_detail());
        let rc = anchored_ffi(
            &certs,
            Some(&genesis_vkey()),
            &mut root,
            &mut tip,
            &mut len,
            &mut d,
        );
        assert_eq!(rc, SextantStatus::MithrilStdMalformedCertJson as i32);
        assert_eq!(d.index, 1);
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
        let (mut root, mut tip, mut len, mut d) = ([0u8; 64], [0u8; 64], 0u64, no_detail());
        let rc = anchored_ffi(&certs, Some(&vkey), &mut root, &mut tip, &mut len, &mut d);
        assert_eq!(rc, SextantStatus::MithrilGenesisInvalidSignature as i32);
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

        let (mut root, mut tip, mut len, mut d) = ([0u8; 64], [0u8; 64], 0u64, no_detail());
        let rc = anchored_ffi(
            &[genesis, resealed],
            Some(&genesis_vkey()),
            &mut root,
            &mut tip,
            &mut len,
            &mut d,
        );
        assert_eq!(rc, SextantStatus::MithrilChainBrokenLink as i32);
        assert_eq!(d.index, 1);
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

        let (mut root, mut tip, mut len, mut d) = ([0u8; 64], [0u8; 64], 0u64, no_detail());
        let rc = anchored_ffi(
            &[genesis, resealed],
            Some(&genesis_vkey()),
            &mut root,
            &mut tip,
            &mut len,
            &mut d,
        );
        assert!(
            (320..=326).contains(&rc),
            "standard-cert layer rejection (320 band), got {rc}",
        );
        assert_eq!(d.index, 1);
    }
}
