//! Real epoch boundary (DoD line 3, part 3): a short contiguous preprod run that
//! spans the 299→300 epoch turn is the on-chain proof that the epoch nonce
//! evolved.
//!
//! part 2 (`tests/chain.rs`) followed a single-epoch (300) run against one nonce.
//! This slice follows a run that crosses into a new epoch and shows leader
//! election is bound to the *per-epoch* nonce: every block verifies against ITS
//! epoch's η0 and rejects the other epoch's. A block that verified under either
//! nonce would mean the nonce did not gate leader election; a block that verified
//! under the *wrong* epoch's nonce would mean it did not evolve. Neither holds —
//! the switch at the boundary is exactly the evolution.
//!
//! Vectors are `boundary-<slot>.block` with a `boundary-<slot>.eta0` sidecar (the
//! block's epoch nonce), harvested by `cargo run -p harvest boundary`. The
//! `boundary-` prefix keeps them out of part 2's single-epoch preprod sweep while
//! the all-`*.block` decode/VRF sweeps still auto-verify them against pallas.

use std::fs;
use std::path::PathBuf;

use sextant::chain::{self, ChainError};
use sextant::header::HeaderView;

/// The evolved value the boundary proves: epoch-300's active nonce (Koios), the
/// same value part 2 pins for the stored epoch-300 run.
const EPOCH_300_ETA0: &str = "aa845533c5f8631a864010ae89c23ee1cee0ed7717e4ac00a25ad50f4eeb6c30";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// One block of the boundary run: its raw bytes, decoded slot, and epoch nonce.
struct Block {
    bytes: Vec<u8>,
    slot: u64,
    eta0: [u8; 32],
}

/// Load every `boundary-<slot>.block` with its `.eta0` sidecar, ordered by slot
/// (the on-chain order).
fn boundary_run() -> Vec<Block> {
    let mut rows: Vec<Block> = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with("boundary-")
            || path.extension().and_then(|e| e.to_str()) != Some("block")
        {
            continue;
        }
        let eta0: [u8; 32] = unhex(
            &fs::read_to_string(path.with_extension("eta0")).expect("boundary vector has .eta0"),
        )
        .try_into()
        .expect("eta0 is 32 bytes");
        let bytes = unhex(&fs::read_to_string(&path).expect("read vector"));
        let slot = HeaderView::from_block_cbor(&bytes)
            .unwrap_or_else(|e| panic!("decode {}: {e:?}", path.display()))
            .slot;
        rows.push(Block { bytes, slot, eta0 });
    }
    rows.sort_by_key(|b| b.slot);
    rows
}

/// The run split at its single epoch boundary: the pre-boundary sub-run (epoch
/// 299, the earlier nonce) and the post-boundary sub-run (epoch 300, the later
/// nonce). The split asserts the run is a clean single boundary — every lower
/// slot shares one nonce, every higher slot the other, with exactly one switch.
struct Boundary {
    pre: Vec<Vec<u8>>,
    post: Vec<Vec<u8>>,
    eta0_pre: [u8; 32],
    eta0_post: [u8; 32],
}

fn split_at_boundary() -> Boundary {
    let run = boundary_run();
    assert!(
        run.len() >= 4,
        "boundary run needs blocks on both sides of the turn, found {}",
        run.len(),
    );
    // In slot order the earliest block's nonce is η0(299), the latest is η0(300).
    let eta0_pre = run.first().unwrap().eta0;
    let eta0_post = run.last().unwrap().eta0;
    assert_ne!(
        eta0_pre, eta0_post,
        "the run must span an epoch boundary (two distinct nonces)",
    );

    let mut pre: Vec<Vec<u8>> = Vec::new();
    let mut post: Vec<Vec<u8>> = Vec::new();
    let mut switched = false;
    for b in &run {
        if !switched && b.eta0 == eta0_pre {
            pre.push(b.bytes.clone());
        } else {
            assert_eq!(b.eta0, eta0_post, "run spans more than two epochs");
            switched = true;
            post.push(b.bytes.clone());
        }
    }
    assert!(
        !pre.is_empty() && !post.is_empty(),
        "boundary run must have blocks on both sides",
    );
    Boundary {
        pre,
        post,
        eta0_pre,
        eta0_post,
    }
}

/// The headline: the harvested run is one contiguous chain across the 299→300
/// turn, each sub-run verifies against its own epoch's nonce, and the boundary
/// links by hash — so η0 evolved from `eta0_pre` to the named η0(300).
#[test]
fn boundary_run_crosses_epoch_299_to_300_and_the_nonce_evolved() {
    let b = split_at_boundary();

    // Name the evolved value: the post-boundary nonce is epoch-300's η0, the same
    // value part 2 verified the stored epoch-300 run against.
    assert_eq!(
        hex::encode(b.eta0_post),
        EPOCH_300_ETA0,
        "post-boundary nonce is the named epoch-300 η0",
    );
    assert_ne!(b.eta0_pre, b.eta0_post, "η0 evolved across the boundary");

    // Each sub-run is a valid chain segment under ITS epoch's nonce: links + full
    // per-header crypto (opcert, leader-VRF vs the epoch nonce, KES).
    chain::verify_segment(&b.pre, &b.eta0_pre).expect("epoch-299 sub-run verifies against η0(299)");
    chain::verify_segment(&b.post, &b.eta0_post)
        .expect("epoch-300 sub-run verifies against η0(300)");

    // The boundary itself is a real chain link: the last epoch-299 header hashes
    // to the first epoch-300 header's prev_hash, and heights are consecutive — the
    // two sub-runs are one unbroken chain, not two disjoint fragments.
    let last_pre = HeaderView::from_block_cbor(b.pre.last().unwrap()).expect("decode");
    let first_post = HeaderView::from_block_cbor(&b.post[0]).expect("decode");
    assert_eq!(
        first_post.prev_hash,
        Some(last_pre.block_hash),
        "the boundary links by hash across the epoch turn",
    );
    assert_eq!(
        first_post.block_number,
        last_pre.block_number + 1,
        "block height is contiguous across the boundary",
    );
    assert!(
        first_post.slot > last_pre.slot,
        "the epoch turn advances the slot",
    );
}

/// The evolution proof: leader election is gated on the per-epoch nonce, so each
/// side's blocks REJECT the other epoch's nonce. If an epoch-299 block verified
/// under η0(300) the nonce would not have evolved; it does not.
#[test]
fn each_side_rejects_the_other_epochs_nonce() {
    let b = split_at_boundary();

    // Epoch-299 blocks under η0(300): the first block's leader-VRF fails.
    assert!(
        matches!(
            chain::verify_segment(&b.pre, &b.eta0_post),
            Err(ChainError::Vrf { index: 0, .. })
        ),
        "epoch-299 blocks must reject epoch-300's nonce",
    );
    // Epoch-300 blocks under η0(299): symmetric.
    assert!(
        matches!(
            chain::verify_segment(&b.post, &b.eta0_pre),
            Err(ChainError::Vrf { index: 0, .. })
        ),
        "epoch-300 blocks must reject epoch-299's nonce",
    );
}
