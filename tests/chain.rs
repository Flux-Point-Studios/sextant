//! Chain-following (DoD line 3, part 2): the stored consecutive preprod run is a
//! hash-linked, fully-verified chain segment on Sextant's own path.
//!
//! The 22 preprod vectors were BlockFetched as a contiguous range, so they form
//! one unbroken segment of epoch 300 (block numbers 4921916..=4921937). Chain
//! following composes the per-header crypto already proven in the vrf/kes/opcert
//! slices with the Blake2b-256 header link (`prev_hash == parent block hash`):
//!
//! * each header links to its predecessor by hash (reordering, dropping, or
//!   splicing a block breaks the link);
//! * each header's operational certificate, leader-VRF (against the epoch nonce),
//!   and KES body signature verify.
//!
//! pallas is the independent oracle for the two new header fields (`block_hash`,
//! `prev_hash`); cardano-node ground truth (these blocks were minted and accepted
//! on the live network) is the oracle for the composed verdict.
//!
//! Single-epoch only — the epoch-boundary nonce-evolution proof is part 3, which
//! reuses `verify_segment`.

use std::fs;
use std::path::PathBuf;

use sextant::chain::{self, ChainError};
use sextant::header::HeaderView;

/// Epoch-300 active nonce (Koios), shared by every preprod vector's `.eta0`
/// sidecar; pinned so the chain segment is verified against a named value.
const EPOCH_300_ETA0: &str = "aa845533c5f8631a864010ae89c23ee1cee0ed7717e4ac00a25ad50f4eeb6c30";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The stored preprod run: every `preprod-*.block` with an `.eta0` sidecar,
/// ordered by slot (the on-chain order), and the epoch nonce they share.
struct Segment {
    blocks: Vec<Vec<u8>>,
    eta0: [u8; 32],
}

fn preprod_segment() -> Segment {
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
        let view = HeaderView::from_block_cbor(&bytes)
            .unwrap_or_else(|e| panic!("decode {}: {e:?}", path.display()));
        rows.push((view.slot, bytes));
    }
    rows.sort_by_key(|r| r.0); // on-chain order
    Segment {
        blocks: rows.into_iter().map(|r| r.1).collect(),
        eta0: eta0.expect("at least one preprod vector with an eta0 sidecar"),
    }
}

/// The core slice: the stored preprod run is a contiguous, hash-linked, fully
/// crypto-verified chain segment — epoch 300, verified against its named nonce.
#[test]
fn preprod_run_is_a_contiguous_verified_chain() {
    let seg = preprod_segment();
    assert!(
        seg.blocks.len() >= 20,
        "DoD requires ≥20 chain-following vectors, found {}",
        seg.blocks.len(),
    );
    assert_eq!(
        hex::encode(seg.eta0),
        EPOCH_300_ETA0,
        "segment is verified against the named epoch-300 nonce",
    );

    // Sextant's own decoded fields witness the monotonic on-chain order: block
    // numbers advance by exactly one and slots strictly increase.
    let views: Vec<HeaderView> = seg
        .blocks
        .iter()
        .map(|b| HeaderView::from_block_cbor(b).expect("decode"))
        .collect();
    for pair in views.windows(2) {
        assert_eq!(
            pair[1].block_number,
            pair[0].block_number + 1,
            "block numbers are consecutive",
        );
        assert!(pair[1].slot > pair[0].slot, "slots strictly increase");
    }

    // Links + full per-header crypto (opcert, leader-VRF vs eta0, KES) all verify.
    chain::verify_segment(&seg.blocks, &seg.eta0)
        .expect("stored preprod run is a valid chain segment");
}

/// The two new header fields are byte-identical to pallas: `block_hash` is the
/// Blake2b-256 of the header CBOR (what a child's `prev_hash` references), and
/// `prev_hash` is the parent link the decoder now surfaces.
#[test]
fn block_hash_and_prev_hash_match_pallas() {
    for b in preprod_segment().blocks {
        let view = HeaderView::from_block_cbor(&b).expect("decode");
        let block = pallas_traverse::MultiEraBlock::decode(&b).expect("pallas decode");
        let hdr = block.header();
        assert_eq!(hex::encode(view.block_hash), hdr.hash().to_string());
        assert_eq!(
            view.prev_hash.map(hex::encode),
            hdr.previous_hash().map(|h| h.to_string()),
        );
    }
}

/// Reordering the segment breaks the hash chain: a child no longer links to the
/// block presented as its parent.
#[test]
fn reordered_segment_is_rejected() {
    let seg = preprod_segment();
    let mut blocks = seg.blocks;
    blocks.reverse();
    assert!(
        matches!(
            chain::verify_segment(&blocks, &seg.eta0),
            Err(ChainError::BrokenLink { .. })
        ),
        "a reversed chain must fail the hash link",
    );
}

/// Dropping a block from the middle breaks the link at the join: the following
/// block's `prev_hash` references the removed block, not its new predecessor.
#[test]
fn dropped_block_breaks_the_chain() {
    let seg = preprod_segment();
    let drop = seg.blocks.len() / 2;
    let mut blocks = seg.blocks;
    blocks.remove(drop);
    assert_eq!(
        chain::verify_segment(&blocks, &seg.eta0),
        Err(ChainError::BrokenLink { index: drop }),
    );
}

/// Flip one byte of a chosen header field in a middle block and confirm the
/// segment rejects it at that block, via the matching crypto verifier. Each
/// field isolates a different check: the opcert signature, the leader-VRF proof,
/// and the KES body signature are all wired into chain following.
#[test]
fn tampered_block_in_segment_is_rejected() {
    let seg = preprod_segment();
    let k = seg.blocks.len() / 2;
    let view = HeaderView::from_block_cbor(&seg.blocks[k]).expect("decode");

    // (field bytes to corrupt, expected error at index k)
    let corrupt = |needle: &[u8]| -> Vec<Vec<u8>> {
        let mut blocks = seg.blocks.clone();
        let block = &mut blocks[k];
        let at = block
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("field present in block bytes");
        block[at + needle.len() / 2] ^= 0x01;
        blocks
    };

    // opcert signature → OpCert (checked before KES, which its edit also breaks).
    assert!(matches!(
        chain::verify_segment(&corrupt(&view.opcert.sigma), &seg.eta0),
        Err(ChainError::OpCert { index, .. }) if index == k,
    ));
    // leader-VRF proof → Vrf (checked before KES).
    assert!(matches!(
        chain::verify_segment(&corrupt(&view.vrf_proof), &seg.eta0),
        Err(ChainError::Vrf { index, .. }) if index == k,
    ));
    // KES body signature (header field outside header_body) → Kes.
    assert!(matches!(
        chain::verify_segment(&corrupt(&view.body_signature), &seg.eta0),
        Err(ChainError::Kes { index, .. }) if index == k,
    ));
}

/// The wrong epoch nonce makes every block's leader-VRF reject: chain following
/// binds leader election to the epoch nonce, the hook the part-3 boundary proof
/// hangs on (a block verifies only against its own epoch's nonce).
#[test]
fn wrong_epoch_nonce_rejects_the_segment() {
    let seg = preprod_segment();
    let mut eta0 = seg.eta0;
    eta0[0] ^= 0x01;
    assert!(matches!(
        chain::verify_segment(&seg.blocks, &eta0),
        Err(ChainError::Vrf { index: 0, .. })
    ));
}

/// A malformed block anywhere in the segment is reported at its position, never
/// a panic or a silent skip.
#[test]
fn malformed_block_is_reported_at_its_index() {
    let seg = preprod_segment();
    let mut blocks = seg.blocks;
    blocks[1].truncate(10); // corrupt the second block's CBOR
    assert!(matches!(
        chain::verify_segment(&blocks, &seg.eta0),
        Err(ChainError::Decode { index: 1, .. })
    ));
}
