//! F5: the live window follower over the C ABI.
//!
//! The incremental `WindowFollower` (src/follow.rs) exposed as opaque-handle exports.
//! The gate: replaying the committed preprod window through the C follower produces the
//! SAME three-valued verdict the in-process Rust follower does, and rollback / re-anchor
//! over the boundary match the Rust outcomes. ABI 3->4 — the `SextantWatchVerdict`
//! reserved byte is reinterpreted as `spend_region`, and the follower exports are new.
//!
//! These call the `extern "C"` exports directly from Rust (same process): they prove the
//! FFI LOGIC — the opaque-handle lifecycle, the outcome->code mapping, the verdict
//! projection, the null guards. External C linkage is proven by the CI-only smoke test.

use std::fs;
use std::path::PathBuf;
use std::ptr;

use sextant::ffi::{
    SEXTANT_ABI_VERSION, SEXTANT_FOLLOWER_REANCHOR_ADVANCED,
    SEXTANT_FOLLOWER_REANCHOR_NOT_MONOTONE, SEXTANT_FOLLOWER_ROLLBACK_BEYOND_WINDOW,
    SEXTANT_FOLLOWER_ROLLBACK_TRUNCATED, SEXTANT_WATCH_NO_SPEND_OBSERVED,
    SEXTANT_WATCH_REGION_HEADER_VOUCHED, SEXTANT_WATCH_SPEND_OBSERVED,
    SEXTANT_WATCH_STALL_BROKEN_SEGMENT, SEXTANT_WATCH_STALL_EPOCH_NONCE_UNAVAILABLE,
    SEXTANT_WATCH_STALL_ROLLBACK_BEYOND_WINDOW, SEXTANT_WATCH_STALL_WINDOW_TOO_SHORT,
    SEXTANT_WATCH_STALLED, SextantFollower, SextantStatus, SextantWatchVerdict,
    sextant_abi_version, sextant_follower_append, sextant_follower_destroy, sextant_follower_new,
    sextant_follower_re_anchor, sextant_follower_rollback, sextant_follower_supply_next_eta0,
    sextant_follower_verdict,
};
use sextant::follow::{SlotSchedule, WindowFollower};
use sextant::header::HeaderView;
use sextant::utxo::{CertifiedTransactions, OutPoint};
use sextant::window::{Freshness, SpendRegion, WatchVerdict};

const EPOCH_300_ETA0: &str = "aa845533c5f8631a864010ae89c23ee1cee0ed7717e4ac00a25ad50f4eeb6c30";
const WATCHED_TX: &str = "beaa9166c061e56457b5d84de4b3d15c9386b202d2585ff247f47af0dcd32a5e";
const SPENDING_TX: &str = "760076f24ea0a151d28a32fb627a17122c92cb7bfb02041995bc98a421687844";
const ANCHOR_ROOT: &str = "83c012fdc3e756fb5230d1a6554fbf743ccea171b37d536a64350c4f5d774129";
const ANCHOR_HEIGHT: u64 = 4_927_469;
const REQUIRE_THROUGH: u64 = 4_921_937;
const SCHEDULE_EPOCH: u64 = 300;
const SCHEDULE_FIRST_SLOT: u64 = 127_958_400;
const SCHEDULE_LEN: u64 = 432_000;
const SLOT_NOW: u64 = 128_046_016 + 60;
const MAX_LAG: u64 = 100_000;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn hash32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte hex")
}

fn eta0() -> [u8; 32] {
    hash32(EPOCH_300_ETA0)
}

/// The committed preprod window, block bytes in on-chain order (by slot).
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
        let view = HeaderView::from_block_cbor(&bytes).expect("decode");
        rows.push((view.slot, bytes));
    }
    rows.sort_by_key(|r| r.0);
    rows.into_iter().map(|r| r.1).collect()
}

/// The aggregator `proof` hex for the one certified tx Sextant holds a committed
/// inclusion proof for (`242f2037…`, NOT the window's spend). Wrong-tx by design:
/// re-anchoring the window's `760076f2…` spend with it must NOT upgrade the region.
fn txproof_hex() -> Vec<u8> {
    let bytes = fs::read(vectors_dir().join("mithril-txproof.json")).expect("read txproof");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse txproof");
    v["certified_transactions"][0]["proof"]
        .as_str()
        .expect("proof field")
        .as_bytes()
        .to_vec()
}

fn zeroed() -> SextantWatchVerdict {
    // SAFETY: `SextantWatchVerdict` is a plain `#[repr(C)]` scalar aggregate.
    unsafe { std::mem::zeroed() }
}

fn schedule() -> SlotSchedule {
    SlotSchedule {
        epoch: SCHEDULE_EPOCH,
        epoch_first_slot: SCHEDULE_FIRST_SLOT,
        epoch_length_slots: SCHEDULE_LEN,
    }
}

/// A fresh C follower for `watch_index` with its epoch-300 nonce staged.
fn new_follower(watch_index: u16) -> *mut SextantFollower {
    let f = new_follower_bare(watch_index);
    let e = eta0();
    let rc = unsafe { sextant_follower_supply_next_eta0(f, SCHEDULE_EPOCH, e.as_ptr()) };
    assert_eq!(rc, SextantStatus::Ok as i32);
    f
}

/// A fresh C follower for `watch_index` with NO nonce staged.
fn new_follower_bare(watch_index: u16) -> *mut SextantFollower {
    let txid = hash32(WATCHED_TX);
    let f = unsafe {
        sextant_follower_new(
            txid.as_ptr(),
            watch_index,
            ANCHOR_HEIGHT,
            REQUIRE_THROUGH,
            SCHEDULE_EPOCH,
            SCHEDULE_FIRST_SLOT,
            SCHEDULE_LEN,
        )
    };
    assert!(!f.is_null(), "follower_new returned null for a valid txid");
    f
}

/// Append every block; assert each is accepted (rc 0) and reports its block number.
fn replay_all(f: *mut SextantFollower, blocks: &[Vec<u8>]) {
    for (i, b) in blocks.iter().enumerate() {
        let mut n = 0u64;
        let rc = unsafe { sextant_follower_append(f, b.as_ptr(), b.len(), &mut n) };
        assert_eq!(rc, SextantStatus::Ok as i32, "block {i} accepted");
        let expect = HeaderView::from_block_cbor(b).expect("decode").block_number;
        assert_eq!(n, expect, "block {i} reports its number");
    }
}

/// The Rust follower's verdict, built the same way — the oracle the C boundary must match.
fn rust_verdict(watch_index: u16, blocks: &[Vec<u8>]) -> WatchVerdict {
    let anchor = CertifiedTransactions {
        merkle_root: String::new(),
        epoch: 0,
        block_number: ANCHOR_HEIGHT,
    };
    let mut f = WindowFollower::new(
        OutPoint {
            tx_id: hash32(WATCHED_TX),
            index: watch_index,
        },
        &anchor,
        REQUIRE_THROUGH,
        schedule(),
    );
    f.supply_next_eta0(SCHEDULE_EPOCH, eta0());
    for b in blocks {
        f.append(b).expect("block accepted");
    }
    f.verdict(Freshness {
        slot_now: SLOT_NOW,
        max_lag: MAX_LAG,
    })
}

fn c_verdict(f: *mut SextantFollower) -> SextantWatchVerdict {
    let mut out = zeroed();
    let rc = unsafe { sextant_follower_verdict(f, SLOT_NOW, MAX_LAG, &mut out) };
    assert_eq!(rc, SextantStatus::Ok as i32);
    out
}

/// F5 bumps the ABI contract 3 -> 4 (the reserved byte becomes `spend_region`).
#[test]
fn abi_version_is_four() {
    assert_eq!(SEXTANT_ABI_VERSION, 4);
    assert_eq!(sextant_abi_version(), 4);
}

/// Replaying the whole window through the C follower yields `SPEND_OBSERVED` naming the
/// spending block + txid, carrying the new `spend_region` field (HeaderVouched — the
/// follower binds no block to the certified set until a re-anchor proof). The Rust
/// follower over the same input agrees.
#[test]
fn replaying_the_window_yields_spend_observed_header_vouched() {
    let blocks = preprod_window();
    assert!(blocks.len() >= 20, "expected the 22-block window");
    let f = new_follower(1);
    replay_all(f, &blocks);
    let v = c_verdict(f);
    assert_eq!(v.kind, SEXTANT_WATCH_SPEND_OBSERVED);
    assert_eq!(v.spend_at_height, 4_921_917);
    assert_eq!(v.spending_txid, hash32(SPENDING_TX));
    assert_eq!(v.spend_region, SEXTANT_WATCH_REGION_HEADER_VOUCHED);

    // vs the Rust verdict.
    match rust_verdict(1, &blocks) {
        WatchVerdict::SpentObserved {
            at_height,
            spending_txid,
            region,
            ..
        } => {
            assert_eq!(v.spend_at_height, at_height);
            assert_eq!(v.spending_txid, spending_txid);
            assert_eq!(region, SpendRegion::HeaderVouched);
        }
        other => panic!("expected SpentObserved, got {other:?}"),
    }
    unsafe { sextant_follower_destroy(f) };
}

/// A never-spent outpoint over the full window yields `NO_SPEND_OBSERVED` as of the
/// verified tip, `spend_region` zero (n/a for a no-spend verdict).
#[test]
fn never_spent_outpoint_yields_no_spend_observed() {
    let blocks = preprod_window();
    let f = new_follower(0);
    replay_all(f, &blocks);
    let v = c_verdict(f);
    assert_eq!(v.kind, SEXTANT_WATCH_NO_SPEND_OBSERVED);
    assert_eq!(v.as_of_height, 4_921_937);
    assert_eq!(v.anchor_height, ANCHOR_HEIGHT);
    assert_eq!(v.spend_region, 0, "no-spend carries no region");
    assert_eq!(v._reserved, [0u8; 3]);
    unsafe { sextant_follower_destroy(f) };
}

/// A `RollBackward` to a point in the fact ring truncates the accepted run; rolling back
/// before the spend drops it, and the shortened window now stalls `WINDOW_TOO_SHORT` (its
/// tip is below `require_through`).
#[test]
fn rollback_before_the_spend_truncates_to_window_too_short() {
    let blocks = preprod_window();
    let f = new_follower(1);
    replay_all(f, &blocks);
    let v0 = HeaderView::from_block_cbor(&blocks[0]).expect("decode");
    let mut tip = 0u64;
    let rc = unsafe { sextant_follower_rollback(f, v0.slot, v0.block_hash.as_ptr(), &mut tip) };
    assert_eq!(rc, SEXTANT_FOLLOWER_ROLLBACK_TRUNCATED);
    assert_eq!(tip, 4_921_916, "tip restored to the creating block");
    let v = c_verdict(f);
    assert_eq!(v.kind, SEXTANT_WATCH_STALLED);
    assert_eq!(v.stall_reason, SEXTANT_WATCH_STALL_WINDOW_TOO_SHORT);
    assert_ne!(
        v.kind, SEXTANT_WATCH_SPEND_OBSERVED,
        "the spend was rolled off"
    );
    unsafe { sextant_follower_destroy(f) };
}

/// A rollback deeper than the retained horizon poisons the follower: the outcome is
/// `BEYOND_WINDOW` and its verdict is thereafter `STALLED(ROLLBACK_BEYOND_WINDOW)`.
#[test]
fn rollback_beyond_window_poisons_the_follower() {
    let blocks = preprod_window();
    let f = new_follower(0);
    replay_all(f, &blocks);
    let unknown = [0xABu8; 32];
    let mut tip = 7u64;
    let rc = unsafe { sextant_follower_rollback(f, 0, unknown.as_ptr(), &mut tip) };
    assert_eq!(rc, SEXTANT_FOLLOWER_ROLLBACK_BEYOND_WINDOW);
    let v = c_verdict(f);
    assert_eq!(v.kind, SEXTANT_WATCH_STALLED);
    assert_eq!(v.stall_reason, SEXTANT_WATCH_STALL_ROLLBACK_BEYOND_WINDOW);
    unsafe { sextant_follower_destroy(f) };
}

/// A block whose epoch nonce was never staged is refused fail-closed with the
/// follower-only `EPOCH_NONCE_UNAVAILABLE` code (11) — never accepted, never a panic.
#[test]
fn append_without_a_staged_nonce_refuses_epoch_nonce_unavailable() {
    let blocks = preprod_window();
    let f = new_follower_bare(0);
    let b = &blocks[0];
    let mut n = 123u64;
    let rc = unsafe { sextant_follower_append(f, b.as_ptr(), b.len(), &mut n) };
    assert_eq!(rc, SEXTANT_WATCH_STALL_EPOCH_NONCE_UNAVAILABLE as i32);
    unsafe { sextant_follower_destroy(f) };
}

/// Appending out of order (block[2] after block[0], skipping block[1]) breaks the hash
/// link and is refused `BROKEN_SEGMENT`.
#[test]
fn appending_out_of_order_refuses_broken_segment() {
    let blocks = preprod_window();
    let f = new_follower(0);
    let mut n = 0u64;
    let rc = unsafe { sextant_follower_append(f, blocks[0].as_ptr(), blocks[0].len(), &mut n) };
    assert_eq!(rc, SextantStatus::Ok as i32);
    let rc = unsafe { sextant_follower_append(f, blocks[2].as_ptr(), blocks[2].len(), &mut n) };
    assert_eq!(rc, SEXTANT_WATCH_STALL_BROKEN_SEGMENT as i32);
    unsafe { sextant_follower_destroy(f) };
}

/// `re_anchor` is monotone (a lower anchor is `NOT_MONOTONE`); advancing with a proof for
/// a DIFFERENT tx than the observed spend advances the anchor but does not upgrade the
/// region (`ADVANCED`, not `ADVANCED_SPEND_CERTIFIED`).
#[test]
fn re_anchor_is_monotone_and_a_wrong_tx_proof_does_not_certify() {
    let blocks = preprod_window();
    let f = new_follower(1);
    replay_all(f, &blocks);
    let root = hash32(ANCHOR_ROOT);
    // A lower anchor is refused.
    let rc = unsafe { sextant_follower_re_anchor(f, 1_000_000, root.as_ptr(), ptr::null(), 0) };
    assert_eq!(rc, SEXTANT_FOLLOWER_REANCHOR_NOT_MONOTONE);
    // Advance with the committed proof (for 242f2037…, not the window's spend): the anchor
    // advances but the spend region is NOT upgraded.
    let proof = txproof_hex();
    let rc = unsafe {
        sextant_follower_re_anchor(f, ANCHOR_HEIGHT, root.as_ptr(), proof.as_ptr(), proof.len())
    };
    assert_eq!(rc, SEXTANT_FOLLOWER_REANCHOR_ADVANCED);
    let v = c_verdict(f);
    assert_eq!(v.kind, SEXTANT_WATCH_SPEND_OBSERVED);
    assert_eq!(
        v.spend_region, SEXTANT_WATCH_REGION_HEADER_VOUCHED,
        "a wrong-tx proof never certifies the observed spend"
    );
    unsafe { sextant_follower_destroy(f) };
}

/// Boundary guards: a null txid yields a null handle; a null handle / out are caller
/// errors; destroying null is a no-op.
#[test]
fn null_guards() {
    let null_err = SextantStatus::ErrNullPointer as i32;
    // Null txid -> null handle.
    let h = unsafe { sextant_follower_new(ptr::null(), 0, 0, 0, 0, 0, 0) };
    assert!(h.is_null());
    // Null handle on the mutation/read exports.
    let mut n = 0u64;
    let block = [0u8; 4];
    assert_eq!(
        unsafe { sextant_follower_append(ptr::null_mut(), block.as_ptr(), block.len(), &mut n) },
        null_err
    );
    let mut out = zeroed();
    assert_eq!(
        unsafe { sextant_follower_verdict(ptr::null_mut(), 0, 0, &mut out) },
        null_err
    );
    // A live follower with a null `out` on verdict.
    let f = new_follower(0);
    assert_eq!(
        unsafe { sextant_follower_verdict(f, 0, 0, ptr::null_mut()) },
        null_err
    );
    unsafe { sextant_follower_destroy(f) };
    // Destroying null must not crash.
    unsafe { sextant_follower_destroy(ptr::null_mut()) };
}
