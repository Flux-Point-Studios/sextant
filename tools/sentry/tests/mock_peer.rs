//! F6 gate (a) — the REQUIRED deterministic mock-peer test. A scripted event stream (the
//! same `SyncEvent`s a live relay produces, minus the network) drives the sentry through
//! the two behaviors a quiet live window might never exercise: a ROLLBACK and an EPOCH
//! TURN. Both are injected here, so they can never ship on zero evidence.
//!
//! Oracle: cardano-node ground truth over the committed preprod vectors. The 22-block
//! window (4921916..=4921937) carries the create+spend graph (beaa9166 created in
//! block[0], its `#1` spent in block[1] by 760076f2); the boundary run crosses the
//! 299→300 epoch turn.

use std::fs;
use std::path::PathBuf;

use sentry::{DriveOutcome, SyncEvent, bootstrap, drive};
use sextant::follow::{Rollback, SlotSchedule};
use sextant::header::HeaderView;
use sextant::utxo::{CertifiedTransactions, OutPoint};
use sextant::window::{Freshness, WatchVerdict};

const WATCHED_TX: &str = "beaa9166c061e56457b5d84de4b3d15c9386b202d2585ff247f47af0dcd32a5e";
const SPENDING_TX: &str = "760076f24ea0a151d28a32fb627a17122c92cb7bfb02041995bc98a421687844";
const REQUIRE_THROUGH: u64 = 4_921_937;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn hash32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte hex")
}

fn vectors_dir() -> PathBuf {
    // tools/sentry/Cargo.toml → ../../tests/vectors
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors")
}

fn watched(index: u16) -> OutPoint {
    OutPoint {
        tx_id: hash32(WATCHED_TX),
        index,
    }
}

/// The epoch-300 Mithril anchor the preprod window sits inside (tip 4921937 ≤ 4927469).
fn anchor() -> CertifiedTransactions {
    CertifiedTransactions {
        merkle_root: String::new(),
        epoch: 300,
        block_number: 4_927_469,
    }
}

fn preprod_schedule() -> SlotSchedule {
    SlotSchedule {
        epoch: 300,
        epoch_first_slot: 127_958_400,
        epoch_length_slots: 432_000,
    }
}

fn fresh() -> Freshness {
    Freshness {
        slot_now: 128_046_016 + 60,
        max_lag: 100_000,
    }
}

/// Every `<prefix>-<slot>.block` with its `.eta0` sidecar, in on-chain (slot) order.
fn load_run(prefix: &str) -> Vec<(u64, Vec<u8>, [u8; 32])> {
    let mut rows: Vec<(u64, Vec<u8>, [u8; 32])> = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with(prefix) || path.extension().and_then(|e| e.to_str()) != Some("block") {
            continue;
        }
        let bytes = unhex(&fs::read_to_string(&path).expect("read block"));
        let eta0: [u8; 32] = unhex(&fs::read_to_string(path.with_extension("eta0")).expect("eta0"))
            .try_into()
            .expect("32-byte eta0");
        let view = HeaderView::from_block_cbor(&bytes).expect("decode block");
        rows.push((view.slot, bytes, eta0));
    }
    rows.sort_by_key(|r| r.0);
    rows
}

/// The point (slot, block_hash) of a block, as chain-sync would name it in a RollBackward.
fn point_of(block: &[u8]) -> (u64, [u8; 32]) {
    let v = HeaderView::from_block_cbor(block).expect("decode");
    (v.slot, v.block_hash)
}

/// GATE (rollback): the sentry drives the real 22-block window as a RollForward stream,
/// observes the spend of `beaa9166#1`, then a RollBackward reorgs the spend out and a
/// re-Forward re-observes it — the exact rollback path a live reorg takes, through the
/// same `drive` mapping the transport uses.
#[test]
fn mock_peer_window_with_a_spend_reorg_rollback() {
    let run = load_run("preprod-");
    assert!(run.len() >= 20, "expected the 22-block window");
    let eta0 = run[0].2;
    let blocks: Vec<Vec<u8>> = run.iter().map(|r| r.1.clone()).collect();

    // Bootstrap on block[0] (the creating block), watching the spent #1.
    let mut follower = bootstrap(
        watched(1),
        &anchor(),
        REQUIRE_THROUGH,
        preprod_schedule(),
        &[(300, eta0)],
        &blocks[0],
    )
    .expect("bootstrap on the creating block");

    // RollForward the rest of the window: the spend at block[1] is observed and sticks.
    for block in &blocks[1..] {
        match drive(&mut follower, SyncEvent::Forward(block.clone())) {
            DriveOutcome::Appended(_) => {}
            other => panic!("authentic forward block should append, got {other:?}"),
        }
    }
    assert!(
        matches!(
            follower.verdict(fresh()),
            WatchVerdict::SpentObserved { at_height: 4_921_917, spending_txid, .. }
                if spending_txid == hash32(SPENDING_TX)
        ),
        "the full stream observes the spend of #1",
    );

    // RollBackward to block[0] (below the spend): the spend is reorged out.
    let (slot, hash) = point_of(&blocks[0]);
    assert_eq!(
        drive(&mut follower, SyncEvent::Backward { slot, hash }),
        DriveOutcome::RolledBack(Rollback::Truncated {
            tip_height: 4_921_916
        }),
    );
    assert!(
        !matches!(
            follower.verdict(fresh()),
            WatchVerdict::SpentObserved { .. }
        ),
        "a reorged-out spend must not linger",
    );

    // RollForward block[1] again: the spend is re-observed on the (real) continuation.
    match drive(&mut follower, SyncEvent::Forward(blocks[1].clone())) {
        DriveOutcome::Appended(4_921_917) => {}
        other => panic!("re-forwarding the spending block should append it, got {other:?}"),
    }
    assert!(
        matches!(
            follower.verdict(fresh()),
            WatchVerdict::SpentObserved {
                at_height: 4_921_917,
                ..
            }
        ),
        "the spend is re-observed after the reorg",
    );
}

/// GATE (epoch turn + rollback): the sentry drives the boundary run across the 299→300
/// turn (both nonces staged up front), rolls back below the turn, and re-forwards the
/// post-turn side with NO re-staging — proving the transport's nonce handling survives a
/// rollback across an epoch boundary. The watch is never created here (a dummy), so the
/// verdict stays a non-answer; this gate is about the append/rollback mechanics.
#[test]
fn mock_peer_epoch_turn_with_a_rollback_below_the_turn() {
    let run = load_run("boundary-");
    assert!(run.len() >= 4, "the boundary run must straddle the turn");
    // The run spans epochs 299 and 300; stage both nonces from the sidecars.
    let mut eta0s: Vec<(u64, [u8; 32])> = Vec::new();
    let schedule = preprod_schedule();
    for (slot, _, eta0) in &run {
        let epoch = schedule.epoch_of(*slot);
        if !eta0s.iter().any(|(e, _)| *e == epoch) {
            eta0s.push((epoch, *eta0));
        }
    }
    assert!(
        eta0s.iter().any(|(e, _)| *e == 299) && eta0s.iter().any(|(e, _)| *e == 300),
        "the boundary run must cross 299→300 (got epochs {:?})",
        eta0s.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
    );
    let blocks: Vec<Vec<u8>> = run.iter().map(|r| r.1.clone()).collect();
    let dummy = OutPoint {
        tx_id: [0u8; 32],
        index: 0,
    };

    // Bootstrap on the first block; require_through 0 (this gate is about the mechanics).
    let mut follower = bootstrap(dummy, &anchor(), 0, schedule, &eta0s, &blocks[0])
        .expect("bootstrap on the boundary run's first block");

    // The first post-turn block index: the first whose epoch differs from block[0]'s.
    let epoch0 = schedule.epoch_of(run[0].0);
    let turn = run
        .iter()
        .position(|(slot, _, _)| schedule.epoch_of(*slot) != epoch0)
        .expect("the run crosses a turn");

    // RollForward the whole run: every block on both sides of the turn appends.
    for block in &blocks[1..] {
        match drive(&mut follower, SyncEvent::Forward(block.clone())) {
            DriveOutcome::Appended(_) => {}
            other => panic!("boundary block should append under its epoch nonce, got {other:?}"),
        }
    }

    // RollBackward to the last pre-turn block: below the turn, still in the ring.
    let (slot, hash) = point_of(&blocks[turn - 1]);
    match drive(&mut follower, SyncEvent::Backward { slot, hash }) {
        DriveOutcome::RolledBack(Rollback::Truncated { .. }) => {}
        other => panic!("a rollback below the turn should truncate in-ring, got {other:?}"),
    }

    // Re-forward the post-turn side with NO re-staging — the nonce map is slot-keyed and
    // untouched by rollback, so the epoch-300 blocks still verify.
    for block in &blocks[turn..] {
        match drive(&mut follower, SyncEvent::Forward(block.clone())) {
            DriveOutcome::Appended(_) => {}
            other => {
                panic!("re-forwarding across the turn should append (no re-stage), got {other:?}")
            }
        }
    }
}
