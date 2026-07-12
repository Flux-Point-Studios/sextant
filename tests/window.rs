//! Body-commitment binding (BEYOND-DoD Tier1 slice 2): a block's transaction
//! bodies bind to its header's `block_body_hash` commitment on Sextant's own path.
//!
//! `chain::verify_segment` authenticates headers only; the spend signal a
//! windowed-unspent verdict scans lives in the bodies. This slice recomputes the
//! `hashAlonzoSegWits` commitment over a block's four raw body segments and
//! requires it to equal header_body index 7 — so authentic headers with swapped
//! bodies are rejected.
//!
//! Oracle: cardano-node ground truth. Every committed `block_body_hash` in these
//! fixtures was produced by cardano-node over that block's real bodies and
//! accepted by the network, so `recompute == committed` across every real block
//! (with non-empty tx_bodies AND witness_sets, and the empty aux/invalid segments
//! present) pins the formula — all four segments, in order, hashed verbatim. A
//! misordered, omitted, or wrongly-hashed segment would diverge on real blocks.
//! The negatives prove the check is non-vacuous.

use std::fs;
use std::path::PathBuf;

use sextant::header::HeaderView;
use sextant::window::{BindError, verify_body_commitment};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// Every real block fixture (preprod, boundary, mainnet), decoded from hex.
fn all_blocks() -> Vec<(String, Vec<u8>)> {
    let mut blocks = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        if path.extension().and_then(|e| e.to_str()) != Some("block") {
            continue;
        }
        blocks.push((
            name,
            unhex(&fs::read_to_string(&path).expect("read vector")),
        ));
    }
    blocks.sort_by(|a, b| a.0.cmp(&b.0));
    blocks
}

/// Every real block's bodies bind to its header commitment: the recomputed
/// `hashAlonzoSegWits` equals the on-chain `block_body_hash` cardano-node signed.
#[test]
fn authentic_block_body_binds_to_its_header_commitment() {
    let blocks = all_blocks();
    assert!(
        blocks.len() >= 20,
        "expected the real fixture corpus, found {}",
        blocks.len(),
    );
    for (name, bytes) in &blocks {
        let view = verify_body_commitment(bytes)
            .unwrap_or_else(|e| panic!("{name}: body should bind to its header: {e:?}"));
        // The bind's decode agrees with the plain header decode.
        assert_eq!(
            view,
            HeaderView::from_block_cbor(bytes).expect("decode"),
            "{name}: decode_block and from_block_cbor disagree",
        );
    }
}

/// Splice a different block's `transaction_bodies` segment into a block that keeps
/// its own (authentic) header: the header still commits to the original bodies, so
/// the recomputed commitment no longer matches. Real headers + swapped bodies is
/// the exact hostile-provider attack this bind closes.
#[test]
fn swapped_body_fails_the_bind() {
    let blocks = all_blocks();
    let a = &blocks[0].1;
    let b = &blocks[1].1;

    let (_, spans_a) = HeaderView::decode_block(a).expect("decode a");
    let (_, spans_b) = HeaderView::decode_block(b).expect("decode b");
    let a_bodies = &a[spans_a.tx_bodies.clone()];
    let b_bodies = &b[spans_b.tx_bodies.clone()];
    assert_ne!(
        a_bodies, b_bodies,
        "the two blocks must have distinct bodies"
    );

    // a's header + b's transaction_bodies + a's remaining segments.
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&a[..spans_a.tx_bodies.start]);
    spliced.extend_from_slice(b_bodies);
    spliced.extend_from_slice(&a[spans_a.tx_bodies.end..]);

    assert_eq!(
        verify_body_commitment(&spliced),
        Err(BindError::BodyCommitmentMismatch),
        "a header must not bind to bodies it does not commit to",
    );
}

/// Tampering the header's committed `block_body_hash` (flipping a byte of the
/// 32-byte value in place, so the CBOR stays a valid bytestring) breaks the bind
/// from the header side: authentic bodies no longer match a forged commitment.
/// Together with the body-side swap, this pins the equality check as real.
#[test]
fn tampered_commitment_fails_the_bind() {
    let (_, bytes) = &all_blocks()[0];
    let view = HeaderView::from_block_cbor(bytes).expect("decode");
    // The committed hash lives in the header (block index 0), which precedes the
    // bodies, so its first occurrence is the real one; flip a data byte of it.
    let at = bytes
        .windows(32)
        .position(|w| w == view.block_body_hash)
        .expect("committed block_body_hash present in the header bytes");
    let mut tampered = bytes.clone();
    tampered[at + 16] ^= 0x01;
    assert_eq!(
        verify_body_commitment(&tampered),
        Err(BindError::BodyCommitmentMismatch),
    );
}

/// A block that does not decode fails closed to `Decode`, never a panic and never
/// a false bind.
#[test]
fn malformed_block_fails_closed_to_decode() {
    let (_, bytes) = &all_blocks()[0];
    let mut truncated = bytes.clone();
    truncated.truncate(bytes.len() / 2);
    assert!(matches!(
        verify_body_commitment(&truncated),
        Err(BindError::Decode(_)),
    ));
}
