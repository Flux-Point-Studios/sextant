//! F1 — `WindowFollower` incremental core, differentially checked against the batch
//! oracle ([`sextant::window::verify_watched_window`]).
//!
//! The follower answers the SAME windowed-unspent question as the batch, but by
//! appending one block at a time (O(block-bytes) per append, never O(window)) so a
//! live consumer never re-scans the whole window on each new block. The batch is the
//! frozen oracle: every follower verdict must equal the batch verdict over the same
//! ACCEPTED prefix.
//!
//! ## The pinned equivalence relation
//! A naive "byte-equal on every prefix + mutation" gate is unsatisfiable, so the
//! relation is precise:
//!  * every block ACCEPTED by `append` → `follower.verdict()` equals the batch over the
//!    accepted prefix (re-proved after EVERY append, so the truncation regression is
//!    re-established incrementally: a short prefix is `Stalled{WindowTooShort}` on both
//!    sides, and a recorded spend stays authoritative even as the prefix grows);
//!  * a REFUSED `append` at block *i* leaves state untouched, and its refusal reason maps
//!    (via [`AppendRefusal::as_stall_reason`]) to the batch stall reason over the accepted
//!    prefix PLUS block *i* — cross-checking the map against the independent oracle.
//!
//! Oracle: cardano-node ground truth over the committed 22-block preprod window
//! (block numbers 4921916..=4921937, one epoch). A tx-graph probe pinned the facts:
//! tx `beaa9166…` is created in block[0] with three outputs; `#0` is never spent
//! (→ `Unspent`); `#1` is spent in block[1] by `760076f2…` (→ `SpentObserved`).

use std::fs;
use std::path::PathBuf;

use sextant::follow::{AppendRefusal, Rollback, SlotSchedule, WindowFollower};
use sextant::header::HeaderView;
use sextant::utxo::{CertifiedTransactions, OutPoint};
use sextant::window::{Freshness, StallReason, WatchVerdict, verify_watched_window};

/// Epoch-300 active nonce (Koios); the preprod window's shared epoch nonce.
const EPOCH_300_ETA0: &str = "aa845533c5f8631a864010ae89c23ee1cee0ed7717e4ac00a25ad50f4eeb6c30";
/// The watched transaction, created in the window's first block (4921916).
const WATCHED_TX: &str = "beaa9166c061e56457b5d84de4b3d15c9386b202d2585ff247f47af0dcd32a5e";
/// The transaction that spends beaa9166…#1 in block[1] (4921917).
const SPENDING_TX: &str = "760076f24ea0a151d28a32fb627a17122c92cb7bfb02041995bc98a421687844";
/// The caller's required coverage floor: the window's own tip height (4921937). Only
/// the full window reaches it; every shorter prefix is `WindowTooShort`.
const REQUIRE_THROUGH: u64 = 4_921_937;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn hash32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn watched(index: u16) -> OutPoint {
    OutPoint {
        tx_id: hash32(WATCHED_TX),
        index,
    }
}

fn eta0() -> [u8; 32] {
    hash32(EPOCH_300_ETA0)
}

/// The real Mithril-certified transactions anchor for epoch 300
/// (`CardanoTransactions(300, 4927469)`): the certified region the window sits inside
/// (tip 4921937 <= 4927469).
fn anchor() -> CertifiedTransactions {
    CertifiedTransactions {
        merkle_root: "83c012fdc3e756fb5230d1a6554fbf743ccea171b37d536a64350c4f5d774129".to_string(),
        epoch: 300,
        block_number: 4_927_469,
    }
}

/// A freshness bound the window tip (slot 128046016) comfortably meets.
fn fresh() -> Freshness {
    Freshness {
        slot_now: 128_046_016 + 60,
        max_lag: 100_000,
    }
}

/// Preprod Shelley slot schedule: epoch 300 begins at slot 127_958_400 and every epoch
/// is 432_000 slots. Every window block's slot (≥ 128_046_016) is epoch 300, so one
/// staged nonce covers the single-epoch window.
fn preprod_schedule() -> SlotSchedule {
    SlotSchedule {
        epoch: 300,
        epoch_first_slot: 127_958_400,
        epoch_length_slots: 432_000,
    }
}

/// A preprod-window follower (single epoch 300) with `nonce` staged for it — the shared
/// constructor the single-epoch equivalence tests use under the F2 map API.
fn preprod_follower(watch: OutPoint, nonce: [u8; 32]) -> WindowFollower {
    let mut f = WindowFollower::new(watch, &anchor(), REQUIRE_THROUGH, preprod_schedule());
    f.supply_next_eta0(300, nonce);
    f
}

/// The stored contiguous preprod window: every `preprod-*.block` in on-chain order
/// (by slot), block numbers 4921916..=4921937.
fn preprod_window() -> Vec<Vec<u8>> {
    let mut rows: Vec<(u64, Vec<u8>)> = Vec::new();
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
        let bytes = unhex(&fs::read_to_string(&path).expect("read vector"));
        let view = HeaderView::from_block_cbor(&bytes).expect("decode preprod block");
        rows.push((view.slot, bytes));
    }
    rows.sort_by_key(|r| r.0);
    rows.into_iter().map(|r| r.1).collect()
}

/// The batch verdict over an accepted prefix — the frozen oracle the follower is
/// checked against.
fn batch(watch: OutPoint, blocks: &[Vec<u8>], nonce: &[u8; 32]) -> WatchVerdict {
    verify_watched_window(watch, &anchor(), REQUIRE_THROUGH, blocks, nonce, fresh())
}

/// ONE long-lived follower per watched outpoint over the full 22-block window: read
/// `verdict()` after EVERY append and require it to equal the batch over the accepted
/// prefix. Re-proves the truncation regression incrementally (every shorter prefix is
/// `WindowTooShort`) and the terminal verdict, for both the never-spent `#0` (→
/// `Unspent`) and the spent `#1` (→ a sticky `SpentObserved`).
#[test]
fn follower_matches_batch_per_prefix_over_the_full_window() {
    for index in [0u16, 1] {
        let blocks = preprod_window();
        assert!(blocks.len() >= 20, "expected the 22-block window");
        let mut follower = preprod_follower(watched(index), eta0());
        let mut accepted: Vec<Vec<u8>> = Vec::new();
        for block in &blocks {
            let appended = follower
                .append(block)
                .expect("an authentic in-order block is accepted");
            accepted.push(block.clone());
            let want = batch(watched(index), &accepted, &eta0());
            assert_eq!(
                follower.verdict(fresh()),
                want,
                "watched #{index}: follower must match the batch over the {}-block prefix",
                accepted.len(),
            );
            assert_eq!(
                appended.block_number,
                HeaderView::from_block_cbor(block).unwrap().block_number,
                "append reports the accepted tip height",
            );
        }
        match index {
            0 => assert!(
                matches!(follower.verdict(fresh()), WatchVerdict::Unspent { .. }),
                "the never-spent outpoint is Unspent over the full verified window",
            ),
            1 => assert!(
                matches!(
                    follower.verdict(fresh()),
                    WatchVerdict::SpentObserved {
                        at_height: 4_921_917,
                        spending_txid,
                        ..
                    } if spending_txid == hash32(SPENDING_TX)
                ),
                "the spent outpoint stays SpentObserved after the spend, through the tail",
            ),
            _ => unreachable!(),
        }
    }
}

/// Splice block `b`'s `transaction_bodies` into block `a`, keeping `a`'s authentic
/// header and remaining segments — the real-header + swapped-bodies attack.
fn splice_bodies(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (_, spans_a) = HeaderView::decode_block(a).expect("decode a");
    let (_, spans_b) = HeaderView::decode_block(b).expect("decode b");
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&a[..spans_a.tx_bodies.start]);
    spliced.extend_from_slice(&b[spans_b.tx_bodies.clone()]);
    spliced.extend_from_slice(&a[spans_a.tx_bodies.end..]);
    spliced
}

/// Accept `clean_prefix_len` authentic blocks, then feed one `bad_block`. The follower
/// must REFUSE (leaving state untouched), and the refusal must map to the stall reason
/// the batch reports over the accepted prefix PLUS the bad block — the equivalence gate
/// for a refused append, cross-checked against the independent oracle. Returns the
/// refusal so a caller can pin the exact variant.
fn refusal_matches_batch(
    watch_index: u16,
    clean_prefix_len: usize,
    bad_block: Vec<u8>,
    follower_eta0: [u8; 32],
) -> AppendRefusal {
    let window = preprod_window();
    let mut follower = preprod_follower(watched(watch_index), follower_eta0);
    let mut accepted: Vec<Vec<u8>> = Vec::new();
    for b in window.iter().take(clean_prefix_len) {
        follower.append(b).expect("clean prefix block is accepted");
        accepted.push(b.clone());
    }

    let before = follower.verdict(fresh());
    let refusal = follower
        .append(&bad_block)
        .expect_err("the mutated block must be refused");
    assert_eq!(
        follower.verdict(fresh()),
        before,
        "a refused append must leave the follower's state untouched",
    );

    let mut probe = accepted;
    probe.push(bad_block);
    match batch(watched(watch_index), &probe, &follower_eta0) {
        WatchVerdict::Stalled { reason, .. } => assert_eq!(
            reason,
            refusal
                .as_stall_reason()
                .expect("a batch-comparable refusal maps to a stall reason"),
            "the refusal must map to the batch stall reason over the same prefix",
        ),
        other => panic!("the batch over the mutated prefix should stall, got {other:?}"),
    }
    refusal
}

/// A dropped mid-window block breaks the hash link: feeding the successor of a dropped
/// block is refused `BrokenLink` → the batch's `BrokenSegment`.
#[test]
fn dropped_block_successor_is_refused_broken_link() {
    let window = preprod_window();
    // Accept blocks[0..2), then feed block[3] — block[2] is withheld.
    let refusal = refusal_matches_batch(0, 2, window[3].clone(), eta0());
    assert_eq!(refusal, AppendRefusal::BrokenLink);
}

/// Real header + swapped bodies: block[2]'s authentic header decodes, links, and its
/// crypto verifies, but the spliced-in bodies no longer hash to its commitment →
/// refused `BodyCommitmentMismatch`, matching the batch.
#[test]
fn spliced_body_block_is_refused_body_commitment_mismatch() {
    let window = preprod_window();
    let spliced = splice_bodies(&window[2], &window[3]);
    let refusal = refusal_matches_batch(0, 2, spliced, eta0());
    assert_eq!(refusal, AppendRefusal::BodyCommitmentMismatch);
}

/// A tampered header (a flipped byte inside the leader-VRF proof) decodes and links, but
/// the leader-VRF no longer verifies → refused `Crypto` → the batch's `BrokenSegment`.
#[test]
fn tampered_header_block_is_refused_crypto() {
    let window = preprod_window();
    let mut bad = window[2].clone();
    let view = HeaderView::from_block_cbor(&bad).expect("decode");
    // The 80-byte VRF proof is a bytestring inside header_body; flip a data byte of it
    // so it stays a valid 80-byte CBOR bytestring but no longer verifies.
    let at = bad
        .windows(80)
        .position(|w| w == view.vrf_proof)
        .expect("vrf proof present in the block bytes");
    bad[at + 40] ^= 0x01;
    let refusal = refusal_matches_batch(0, 2, bad, eta0());
    assert_eq!(refusal, AppendRefusal::Crypto);
}

/// A truncated block does not decode → refused `Decode` → the batch's `BrokenSegment`.
#[test]
fn truncated_block_is_refused_decode() {
    let window = preprod_window();
    let mut bad = window[2].clone();
    bad.truncate(bad.len() / 2);
    let refusal = refusal_matches_batch(0, 2, bad, eta0());
    assert_eq!(refusal, AppendRefusal::Decode);
}

/// The wrong epoch nonce makes the very first block's leader-VRF fail: refused `Crypto`
/// on an empty follower (no clean prefix), matching the batch under the same nonce.
#[test]
fn wrong_epoch_nonce_refuses_the_first_block_crypto() {
    let window = preprod_window();
    let wrong = [0x11u8; 32];
    let refusal = refusal_matches_batch(0, 0, window[0].clone(), wrong);
    assert_eq!(refusal, AppendRefusal::Crypto);
}

/// The pinned relation's "follower is MORE correct" case: a spend recorded in an
/// ACCEPTED prefix stays the verdict even after a later append is REFUSED — the batch
/// fed the broken tail would collapse to a stall, but the definite refuse was already
/// observed in verified blocks and a broken tail cannot un-observe it.
#[test]
fn recorded_spend_survives_a_refused_append() {
    let window = preprod_window();
    let mut follower = preprod_follower(watched(1), eta0());
    for b in window.iter().take(3) {
        follower.append(b).expect("clean prefix accepted");
    }
    let spent = follower.verdict(fresh());
    assert!(
        matches!(
            spent,
            WatchVerdict::SpentObserved { at_height: 4_921_917, spending_txid, .. }
                if spending_txid == hash32(SPENDING_TX)
        ),
        "the spend at block[1] is recorded, got {spent:?}",
    );
    // A truncated block is refused...
    let mut bad = window[3].clone();
    bad.truncate(bad.len() / 2);
    assert_eq!(follower.append(&bad), Err(AppendRefusal::Decode));
    // ...and the definite refuse is unchanged by the refusal.
    assert_eq!(follower.verdict(fresh()), spent);
}

/// One block of the harvested 299→300 boundary run: its bytes, decoded slot, and its
/// epoch's η0 sidecar (from `boundary-<slot>.eta0`).
struct BoundaryBlock {
    bytes: Vec<u8>,
    slot: u64,
    eta0: [u8; 32],
}

/// Every `boundary-<slot>.block` with its `.eta0` sidecar, in on-chain (slot) order.
/// The run is a contiguous chain that crosses the 299→300 turn: the earlier blocks
/// carry η0(299), the later blocks η0(300).
fn boundary_run() -> Vec<BoundaryBlock> {
    let mut rows: Vec<BoundaryBlock> = Vec::new();
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
        let bytes = unhex(&fs::read_to_string(&path).expect("read boundary vector"));
        let eta0: [u8; 32] = unhex(
            &fs::read_to_string(path.with_extension("eta0")).expect("boundary vector has .eta0"),
        )
        .try_into()
        .expect("eta0 is 32 bytes");
        let slot = HeaderView::from_block_cbor(&bytes)
            .expect("decode boundary block")
            .slot;
        rows.push(BoundaryBlock { bytes, slot, eta0 });
    }
    rows.sort_by_key(|b| b.slot);
    rows
}

/// A watch outpoint the boundary run never creates or spends — the boundary tests
/// exercise epoch-aware nonce selection, not the spend scan, so the follower's verdict
/// is not asserted here (a dummy watch stays `CreationNotObserved`).
fn dummy_watch() -> OutPoint {
    OutPoint {
        tx_id: [0u8; 32],
        index: 0,
    }
}

/// The headline F2 property: one follower crosses the 299→300 epoch boundary, selecting
/// each side's nonce from the map by the block's slot. Both epoch nonces are staged up
/// front; every block — on either side of the turn — is accepted. A single-nonce
/// follower could verify only one side.
#[test]
fn follower_crosses_the_epoch_boundary_selecting_each_side_nonce() {
    let run = boundary_run();
    assert!(run.len() >= 4, "the run must straddle the turn");
    let schedule = preprod_schedule();
    // The run genuinely spans two epochs under the schedule.
    let pre_epoch = schedule.epoch_of(run.first().unwrap().slot);
    let post_epoch = schedule.epoch_of(run.last().unwrap().slot);
    assert_eq!(
        post_epoch,
        pre_epoch + 1,
        "the run crosses exactly one boundary"
    );

    let mut follower = WindowFollower::new(dummy_watch(), &anchor(), 0, schedule);
    // Stage both epochs' nonces (the harvester wrote each block's epoch η0 as its
    // sidecar; the schedule agrees with that assignment, cross-checked per block below).
    for b in &run {
        follower.supply_next_eta0(schedule.epoch_of(b.slot), b.eta0);
    }

    let mut saw_pre = false;
    let mut saw_post = false;
    for b in &run {
        let epoch = schedule.epoch_of(b.slot);
        // The schedule's epoch for this slot is the epoch whose η0 the harvester
        // attached — so the nonce the follower selects is the block's real epoch nonce.
        assert_eq!(
            follower.append(&b.bytes),
            Ok(sextant::follow::Appended {
                block_number: HeaderView::from_block_cbor(&b.bytes).unwrap().block_number,
            }),
            "block at slot {} (epoch {epoch}) is accepted under its epoch nonce",
            b.slot
        );
        saw_pre |= epoch == pre_epoch;
        saw_post |= epoch == post_epoch;
    }
    assert!(
        saw_pre && saw_post,
        "the follower verified blocks on both sides of the turn"
    );
}

/// Split the boundary run at its single turn: the pre-turn side (earlier epoch) and the
/// first post-turn block (later epoch). Both epochs are computed from the schedule.
fn first_post_turn_block(run: &[BoundaryBlock], schedule: &SlotSchedule) -> (u64, usize) {
    let pre_epoch = schedule.epoch_of(run.first().unwrap().slot);
    let post_epoch = pre_epoch + 1;
    let idx = run
        .iter()
        .position(|b| schedule.epoch_of(b.slot) == post_epoch)
        .expect("the run crosses the turn");
    (post_epoch, idx)
}

/// A missing staged nonce at the turn is fail-closed and liveness-only: the first
/// post-turn block whose η0 has not been supplied is refused `EpochNonceUnavailable`
/// (the refusal has no single-epoch batch counterpart, so it maps to `None`), and once
/// the nonce is staged the SAME block appends — the refusal left the state untouched.
#[test]
fn missing_staged_nonce_at_the_turn_refuses_then_supplied_nonce_is_accepted() {
    let run = boundary_run();
    let schedule = preprod_schedule();
    let (post_epoch, first_post) = first_post_turn_block(&run, &schedule);
    let pre_epoch = schedule.epoch_of(run.first().unwrap().slot);

    let mut follower = WindowFollower::new(dummy_watch(), &anchor(), 0, schedule);
    // Stage ONLY the earlier epoch's nonce.
    follower.supply_next_eta0(pre_epoch, run[0].eta0);

    for b in &run[..first_post] {
        follower
            .append(&b.bytes)
            .expect("pre-turn block accepted under its staged nonce");
    }
    assert_eq!(
        follower.append(&run[first_post].bytes),
        Err(AppendRefusal::EpochNonceUnavailable),
        "a post-turn block whose epoch nonce is not staged is refused, fail-closed",
    );
    assert_eq!(
        AppendRefusal::EpochNonceUnavailable.as_stall_reason(),
        None,
        "the cross-epoch refusal has no single-epoch batch counterpart",
    );
    // Liveness: staging the epoch nonce accepts the same block the refusal left pending.
    follower.supply_next_eta0(post_epoch, run[first_post].eta0);
    follower
        .append(&run[first_post].bytes)
        .expect("the block appends once its epoch nonce is staged");
}

/// A staged-but-WRONG epoch nonce fails the leader-VRF (`Crypto`, not
/// `EpochNonceUnavailable`), and correcting it — overwritable while unused — accepts the
/// same block. The nonce is an input to verify, never a verdict, so a wrong one only
/// costs liveness.
#[test]
fn wrong_staged_nonce_refuses_crypto_then_corrected_nonce_is_accepted() {
    let run = boundary_run();
    let schedule = preprod_schedule();
    let (post_epoch, first_post) = first_post_turn_block(&run, &schedule);
    let pre_epoch = schedule.epoch_of(run.first().unwrap().slot);

    let mut follower = WindowFollower::new(dummy_watch(), &anchor(), 0, schedule);
    follower.supply_next_eta0(pre_epoch, run[0].eta0);
    follower.supply_next_eta0(post_epoch, [0x11u8; 32]); // wrong η0 for the later epoch

    for b in &run[..first_post] {
        follower.append(&b.bytes).expect("pre-turn block accepted");
    }
    assert_eq!(
        follower.append(&run[first_post].bytes),
        Err(AppendRefusal::Crypto),
        "a staged-but-wrong epoch nonce fails the leader-VRF, not EpochNonceUnavailable",
    );
    // Overwrite the mis-staged nonce with the correct η0 and the same block is accepted.
    follower.supply_next_eta0(post_epoch, run[first_post].eta0);
    follower
        .append(&run[first_post].bytes)
        .expect("the corrected epoch nonce accepts the block");
}

/// A refused append does not brick the follower: after a refusal it still accepts the
/// correct next block and advances the verified tip.
#[test]
fn refused_append_leaves_the_follower_able_to_resume() {
    let window = preprod_window();
    let mut follower = preprod_follower(watched(0), eta0());
    for b in window.iter().take(2) {
        follower.append(b).expect("clean prefix accepted");
    }
    let before = follower.verdict(fresh());
    // An out-of-order block is refused, and state is untouched...
    assert!(follower.append(&window[5]).is_err());
    assert_eq!(follower.verdict(fresh()), before);
    // ...then the correct next block (4921918) is accepted, advancing the tip.
    let appended = follower
        .append(&window[2])
        .expect("the correct next block resumes following");
    assert_eq!(appended.block_number, 4_921_918);
}

// --- F3: rollback truncation + eviction-as-finalization -----------------------------

/// A chain-sync `RollBackward` to a block still in the follower's fact ring truncates the
/// accepted run to end at that block and recomputes the window's facts from the
/// survivors, so the verdict re-converges to the batch over the surviving prefix — then
/// re-appending the successors re-converges to the full-window verdict. The whole
/// 22-block window fits well inside the default ring, so nothing is finalized here; this
/// pins the in-ring arm against the frozen batch oracle.
#[test]
fn in_ring_rollback_truncates_and_reconverges_with_the_batch() {
    let window = preprod_window();
    let mut follower = preprod_follower(watched(0), eta0());
    for b in &window {
        follower
            .append(b)
            .expect("authentic in-order block accepted");
    }
    assert_eq!(
        follower.verdict(fresh()),
        batch(watched(0), &window, &eta0()),
        "the full window matches the batch",
    );

    // Roll back to block[10]'s point (still in the ring).
    let target = HeaderView::from_block_cbor(&window[10]).unwrap();
    assert_eq!(
        follower.rollback(target.slot, &target.block_hash),
        Rollback::Truncated {
            tip_height: target.block_number
        },
        "a target still in the ring is an in-ring truncation",
    );
    assert_eq!(
        follower.verdict(fresh()),
        batch(watched(0), &window[..=10], &eta0()),
        "after truncation the follower equals the batch over the surviving prefix",
    );

    // Re-append the successors: the follower re-converges to the full-window verdict.
    for b in &window[11..] {
        follower.append(b).expect("re-appended successor accepted");
    }
    assert_eq!(
        follower.verdict(fresh()),
        batch(watched(0), &window, &eta0()),
        "re-appending the tail re-converges to the full-window verdict",
    );
}

/// A rollback to the follow base — the predecessor the first appended block hung from
/// (its `prev_hash`, in the block[0] fixture) — empties the window but keeps the follower
/// anchored: the verdict becomes `Stalled{CreationNotObserved}` (creation is no longer
/// observed in the emptied window, distinct from a never-started `EmptyWindow`), and
/// re-appending from block[0] re-converges with the batch.
#[test]
fn rollback_to_the_follow_base_stalls_creation_not_observed_then_re_appends() {
    let window = preprod_window();
    let mut follower = preprod_follower(watched(0), eta0());
    for b in window.iter().take(4) {
        follower.append(b).expect("prefix block accepted");
    }
    let base = HeaderView::from_block_cbor(&window[0])
        .unwrap()
        .prev_hash
        .expect("a window block has a parent (the follow base)");
    assert_eq!(
        follower.rollback(0, &base),
        Rollback::ToBase,
        "the block[0] predecessor is the follow base",
    );
    assert!(
        matches!(
            follower.verdict(fresh()),
            WatchVerdict::Stalled {
                reason: StallReason::CreationNotObserved,
                ..
            }
        ),
        "an emptied-to-base window has not re-observed the outpoint's creation",
    );

    for b in window.iter().take(4) {
        follower
            .append(b)
            .expect("re-append from the base accepted");
    }
    assert_eq!(
        follower.verdict(fresh()),
        batch(watched(0), &window[..4], &eta0()),
        "re-appending from the base re-converges with the batch",
    );
}

/// A rollback to a point the follower does not retain — neither in the ring nor the
/// follow base — is deeper than the common-prefix horizon the ring covers, so it is
/// fail-closed: the follower is poisoned and its verdict is `Stalled{RollbackBeyondWindow}`
/// until the caller discards it and restarts from a fresh anchor. NEVER a false verdict.
#[test]
fn rollback_beyond_the_window_poisons_the_follower() {
    let window = preprod_window();
    let mut follower = preprod_follower(watched(0), eta0());
    for b in window.iter().take(4) {
        follower.append(b).expect("prefix block accepted");
    }
    let fabricated = [0xABu8; 32];
    assert_eq!(
        follower.rollback(999, &fabricated),
        Rollback::BeyondWindow,
        "an unretained target is beyond the window",
    );
    assert!(
        matches!(
            follower.verdict(fresh()),
            WatchVerdict::Stalled {
                reason: StallReason::RollbackBeyondWindow,
                ..
            }
        ),
        "a beyond-window rollback poisons the follower fail-closed",
    );
}
