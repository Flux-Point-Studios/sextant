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

// ---- BEYOND-DoD Tier1 slice 3: verify_watched_window ----
//
// The forward spend-scan over a header-verified, hash-linked, body-committed
// window. Oracle: cardano-node ground truth. The stored 22-block preprod segment
// (block numbers 4921916..=4921937, all <= certified_at 4927469) contains a real
// create+spend graph a tx-graph probe pinned:
//   * tx beaa9166… is created in block[0] (4921916) with three outputs;
//   * beaa9166…#0 is never spent in the segment (→ Unspent);
//   * beaa9166…#1 is spent in block[1] (4921917) by tx 760076f2… (→ SpentObserved).
// The adversary's only evasion — withhold the spending block — cannot advance the
// verified tip, so it collapses to Stalled, never a false Unspent.

use sextant::utxo::{CertifiedTransactions, OutPoint};
use sextant::window::{Freshness, StallReason, WatchBasis, WatchVerdict, verify_watched_window};

/// Epoch-300 active nonce (Koios); the preprod window's shared epoch nonce.
const EPOCH_300_ETA0: &str = "aa845533c5f8631a864010ae89c23ee1cee0ed7717e4ac00a25ad50f4eeb6c30";
/// The watched transaction, created in the window's first block (4921916).
const WATCHED_TX: &str = "beaa9166c061e56457b5d84de4b3d15c9386b202d2585ff247f47af0dcd32a5e";
/// The transaction that spends beaa9166…#1 in block[1] (4921917).
const SPENDING_TX: &str = "760076f24ea0a151d28a32fb627a17122c92cb7bfb02041995bc98a421687844";

fn hash32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte hex")
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

/// The real Mithril-certified transactions anchor for epoch 300 (from
/// `mithril-txproof-cert.json`, `CardanoTransactions(300, 4927469)`): the certified
/// region the window sits inside (tip 4921937 <= 4927469). `tests/mithril_chain.rs`
/// proves a genesis-anchored cert surfaces exactly this `(root, epoch, block)`.
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

/// POSITIVE: an outpoint the whole verified window never spends yields `Unspent`,
/// stamped as-of the verified tip with both assumptions surfaced on the basis.
#[test]
fn unspent_outpoint_in_verified_window_yields_unspent_as_of_tip() {
    let blocks = preprod_window();
    assert!(blocks.len() >= 20, "expected the 22-block window");
    let verdict = verify_watched_window(watched(0), &anchor(), &blocks, &eta0(), fresh());
    match verdict {
        WatchVerdict::Unspent { as_of, basis } => {
            assert_eq!(as_of.as_of_height, 4_921_937, "as-of tip height");
            assert_eq!(as_of.as_of_slot, 128_046_016, "as-of tip slot");
            assert_eq!(as_of.anchor_height, 4_927_469, "certified anchor height");
            match basis {
                WatchBasis::WatchedWindow(a) => assert!(
                    a.mithril_quorum && a.data_complete,
                    "both assumptions must be stamped on an Unspent",
                ),
                _ => panic!("unexpected basis {basis:?}"),
            }
        }
        other => panic!("expected Unspent, got {other:?}"),
    }
}

/// NEGATIVE (definite refuse): an outpoint spent inside the window yields
/// `SpentObserved` naming the spending block and transaction.
#[test]
fn spending_block_in_window_yields_spent_observed_at_block() {
    let blocks = preprod_window();
    let verdict = verify_watched_window(watched(1), &anchor(), &blocks, &eta0(), fresh());
    match verdict {
        WatchVerdict::SpentObserved {
            at_height,
            at_slot,
            spending_txid,
        } => {
            assert_eq!(at_height, 4_921_917, "spent in block[1]");
            assert_eq!(at_slot, 128_045_548);
            assert_eq!(spending_txid, hash32(SPENDING_TX));
        }
        other => panic!("expected SpentObserved, got {other:?}"),
    }
}

/// THE CARDINAL EVASION: withholding the spending block cannot advance the verified
/// tip. Dropping block[1] (which spends #1) breaks the hash chain → `verify_segment`
/// rejects → `Stalled{BrokenSegment}`, NEVER a false `Unspent`.
#[test]
fn dropped_spending_block_yields_stalled_never_unspent() {
    let mut blocks = preprod_window();
    blocks.remove(1);
    let verdict = verify_watched_window(watched(1), &anchor(), &blocks, &eta0(), fresh());
    assert!(
        matches!(
            verdict,
            WatchVerdict::Stalled {
                reason: StallReason::BrokenSegment,
                ..
            }
        ),
        "a withheld spending block must stall, got {verdict:?}",
    );
    assert!(!matches!(verdict, WatchVerdict::Unspent { .. }));
}

/// THE "START AFTER THE SPEND" EVASION: a window that does not observe the outpoint's
/// creation cannot vouch it was ever unspent. Dropping the creating block (block[0])
/// leaves a still-contiguous, still-verified run — but creation is unseen, so an
/// otherwise-unspent #0 yields `Stalled{CreationNotObserved}`, never `Unspent`.
#[test]
fn window_that_misses_creation_yields_stalled_never_unspent() {
    let mut blocks = preprod_window();
    blocks.remove(0);
    let verdict = verify_watched_window(watched(0), &anchor(), &blocks, &eta0(), fresh());
    assert!(
        matches!(
            verdict,
            WatchVerdict::Stalled {
                reason: StallReason::CreationNotObserved,
                ..
            }
        ),
        "creation-not-observed must stall, got {verdict:?}",
    );
}

/// A window reaching ABOVE the certified anchor is outside the Mithril-vouched
/// region — data-completeness is no longer quorum-backed, so it cannot be a clean
/// `Unspent`. An anchor certifying only below the tip yields `Stalled{TipAboveAnchor}`.
#[test]
fn window_tip_above_certified_anchor_yields_stalled() {
    let blocks = preprod_window();
    let low = CertifiedTransactions {
        block_number: 4_921_930, // below the window tip 4921937
        ..anchor()
    };
    let verdict = verify_watched_window(watched(0), &low, &blocks, &eta0(), fresh());
    assert!(
        matches!(
            verdict,
            WatchVerdict::Stalled {
                reason: StallReason::TipAboveAnchor,
                ..
            }
        ),
        "a tip above the certified region must stall, got {verdict:?}",
    );
}

/// A verified tip older than the caller's lag bound is a non-answer for that caller
/// — `Stalled{TipTooOld}`, never `Unspent` read as current.
#[test]
fn stale_tip_yields_stalled_tip_too_old() {
    let blocks = preprod_window();
    let stale = Freshness {
        slot_now: 128_046_016 + 1_000_000,
        max_lag: 100,
    };
    let verdict = verify_watched_window(watched(0), &anchor(), &blocks, &eta0(), stale);
    assert!(
        matches!(
            verdict,
            WatchVerdict::Stalled {
                reason: StallReason::TipTooOld,
                ..
            }
        ),
        "a stale tip must stall, got {verdict:?}",
    );
}

/// THE CRUX WIRED IN: real headers + swapped bodies. Splicing block[2]'s
/// `transaction_bodies` into block[1] leaves block[1]'s authentic header (so headers
/// still verify + link), but the swapped bodies no longer hash to block[1]'s
/// commitment. A scan that trusted the swapped bodies could read a false verdict; the
/// body-commitment bind forces `Stalled{BodyCommitmentMismatch}` instead.
#[test]
fn swapped_body_in_window_yields_stalled_never_unspent() {
    let mut blocks = preprod_window();
    let (_, spans1) = HeaderView::decode_block(&blocks[1]).expect("decode block[1]");
    let (_, spans2) = HeaderView::decode_block(&blocks[2]).expect("decode block[2]");
    let b2_bodies = blocks[2][spans2.tx_bodies.clone()].to_vec();
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&blocks[1][..spans1.tx_bodies.start]);
    spliced.extend_from_slice(&b2_bodies);
    spliced.extend_from_slice(&blocks[1][spans1.tx_bodies.end..]);
    blocks[1] = spliced;

    let verdict = verify_watched_window(watched(0), &anchor(), &blocks, &eta0(), fresh());
    assert!(
        matches!(
            verdict,
            WatchVerdict::Stalled {
                reason: StallReason::BodyCommitmentMismatch,
                ..
            }
        ),
        "swapped bodies must stall, got {verdict:?}",
    );
    assert!(!matches!(verdict, WatchVerdict::Unspent { .. }));
}

/// A PHANTOM outpoint — the creating transaction is in the window, but it produced no
/// output at the watched index — must not read as `Unspent`. Creation is bound to the
/// output's actual existence, not merely the transaction's presence, so watching a
/// never-created index yields `Stalled{CreationNotObserved}`.
#[test]
fn phantom_output_index_yields_stalled_never_unspent() {
    let blocks = preprod_window();
    // beaa9166 has three outputs (0, 1, 2); index 5 was never created.
    let verdict = verify_watched_window(watched(5), &anchor(), &blocks, &eta0(), fresh());
    assert!(
        matches!(
            verdict,
            WatchVerdict::Stalled {
                reason: StallReason::CreationNotObserved,
                ..
            }
        ),
        "a phantom outpoint must stall, got {verdict:?}",
    );
    assert!(!matches!(verdict, WatchVerdict::Unspent { .. }));
}

/// An empty window carries no verified tip and cannot answer.
#[test]
fn empty_window_yields_stalled() {
    let blocks: Vec<Vec<u8>> = Vec::new();
    let verdict = verify_watched_window(watched(0), &anchor(), &blocks, &eta0(), fresh());
    assert!(matches!(
        verdict,
        WatchVerdict::Stalled {
            reason: StallReason::EmptyWindow,
            ..
        }
    ));
}
