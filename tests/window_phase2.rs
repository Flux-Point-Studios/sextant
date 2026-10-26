//! The windowed watch reads creation by the creating transaction's phase-2 outcome, as
//! the ledger does: a phase-2-valid transaction creates its regular outputs, and a
//! phase-2-invalid one creates only its collateral return, at the index after them. The
//! fixture is mainnet block 13,591,743 (epoch 639), whose transaction 7 failed phase 2.

use std::fs;
use std::path::PathBuf;

use pallas_traverse::MultiEraBlock;
use sextant::ffi::{
    SEXTANT_WATCH_NO_SPEND_OBSERVED, SEXTANT_WATCH_STALL_CREATION_NOT_OBSERVED,
    SEXTANT_WATCH_STALLED, SextantStatus, SextantWatchVerdict, sextant_follower_append,
    sextant_follower_destroy, sextant_follower_new, sextant_follower_supply_next_eta0,
    sextant_follower_verdict, sextant_verify_watched_window,
};
use sextant::follow::{SlotSchedule, WindowFollower};
use sextant::header::HeaderView;
use sextant::utxo::{CertifiedTransactions, OutPoint};
use sextant::window::{Freshness, StallReason, WatchVerdict, verify_watched_window};

/// The block hash Koios reports for mainnet height 13,591,743, which BLAKE2b-256 of the
/// fixture's raw header must reproduce.
const BLOCK_HASH: &str = "f258395bec389a78f685862811adafe031122566df38fa2895d6c256a0c2c7e1";
const TX0: &str = "1ae09b7f678f8053665727c23a6d0ebb232c40f699e56dcc40de261f72c2bde9";
const TX7: &str = "6532eb693c0a1170a07061a38e6dbaac8a3acfa57e43d497a33e0d072d40379a";
/// The epoch-639 nonce, an input taken from Koios epoch_params. It is provenance, not
/// authority: the block's leader VRF verifies under it, and a wrong one could only make
/// the window stall.
const ETA0_639: &str = "0202e995b06e8e36974ef05ee13f1a93f6603e3e4e277d945da2cdf8206537dd";

fn block() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/invalid-mainnet-13591743.block");
    hex::decode(fs::read_to_string(path).expect("fixture").trim()).expect("hex")
}

fn hash32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str)
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

fn watch(tx_id: &str, index: u16) -> WatchVerdict {
    let block = block();
    let (view, _) = HeaderView::decode_block(&block).expect("block");
    let anchor = CertifiedTransactions {
        merkle_root: "00".repeat(32),
        epoch: 639,
        block_number: view.block_number,
    };
    let fresh = Freshness {
        slot_now: view.slot,
        max_lag: 0,
    };
    verify_watched_window(
        OutPoint {
            tx_id: hash32(tx_id),
            index,
        },
        &anchor,
        view.block_number,
        &[block],
        &hash32(ETA0_639),
        fresh,
    )
}

#[test]
fn the_fixture_is_mainnet_block_13591743_whose_transaction_7_failed_phase_2() {
    let block = block();
    let (view, _) = HeaderView::decode_block(&block).expect("block");
    assert_eq!(
        (view.block_number, view.block_hash),
        (13_591_743, hash32(BLOCK_HASH))
    );
    let decoded = MultiEraBlock::decode(&block).expect("pallas");
    let txs = decoded.txs();
    let id = |i: usize| hex::encode(txs[i].hash());
    assert_eq!(
        (id(0), id(7), txs.len()),
        (TX0.to_owned(), TX7.to_owned(), 21)
    );
    assert!(txs[0].is_valid() && !txs[7].is_valid());
    let produced: Vec<usize> = txs[7].produces().iter().map(|(index, _)| *index).collect();
    assert_eq!(
        produced,
        [3],
        "the ledger created only the collateral return"
    );
}

#[test]
fn a_valid_transactions_output_is_created() {
    assert!(matches!(watch(TX0, 0), WatchVerdict::Unspent { .. }));
}

#[test]
fn an_output_a_phase_2_invalid_transaction_never_created_is_not_observed() {
    assert!(matches!(
        watch(TX7, 0),
        WatchVerdict::Stalled {
            reason: StallReason::CreationNotObserved,
            ..
        }
    ));
}

#[test]
fn the_collateral_return_of_a_phase_2_invalid_transaction_is_created() {
    assert!(matches!(watch(TX7, 3), WatchVerdict::Unspent { .. }));
}

/// The batch window, the incremental follower and both C exports read the block alike:
/// `TX0#0` and the collateral return `TX7#3` are created and unspent through it, and
/// `TX7#0`, which the ledger never created, is not observed.
#[test]
fn the_follower_and_the_c_exports_read_phase_2_as_the_batch_does() {
    let block = block();
    let (view, _) = HeaderView::decode_block(&block).expect("block");
    // Mainnet's Shelley schedule: epoch 208 begins at slot 4,492,800, every epoch 432,000 slots.
    let schedule = SlotSchedule {
        epoch: 208,
        epoch_first_slot: 4_492_800,
        epoch_length_slots: 432_000,
    };
    assert_eq!(schedule.epoch_of(view.slot), 639);
    let anchor = CertifiedTransactions {
        merkle_root: String::new(),
        epoch: 639,
        block_number: view.block_number,
    };
    let fresh = Freshness {
        slot_now: view.slot,
        max_lag: 0,
    };
    let eta0 = hash32(ETA0_639);
    for (tx, index, created) in [(TX0, 0, true), (TX7, 0, false), (TX7, 3, true)] {
        let outpoint = OutPoint {
            tx_id: hash32(tx),
            index,
        };
        let batch = watch(tx, index);
        assert_eq!(
            matches!(batch, WatchVerdict::Unspent { .. }),
            created,
            "{tx} {index}"
        );
        if !created {
            assert!(matches!(
                batch,
                WatchVerdict::Stalled {
                    reason: StallReason::CreationNotObserved,
                    ..
                }
            ));
        }

        let mut follower = WindowFollower::new(outpoint, &anchor, view.block_number, schedule);
        follower.supply_next_eta0(639, eta0);
        follower
            .append(&block)
            .expect("the follower accepts the block");
        assert_eq!(follower.verdict(fresh), batch, "{tx} {index}");

        let (kind, reason) = if created {
            (SEXTANT_WATCH_NO_SPEND_OBSERVED, 0)
        } else {
            (
                SEXTANT_WATCH_STALLED,
                SEXTANT_WATCH_STALL_CREATION_NOT_OBSERVED,
            )
        };
        let ptrs = [block.as_ptr()];
        let lens = [block.len()];
        let mut c_batch: SextantWatchVerdict = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            sextant_verify_watched_window(
                ptrs.as_ptr(),
                lens.as_ptr(),
                1,
                eta0.as_ptr(),
                view.block_number,
                outpoint.tx_id.as_ptr(),
                index,
                view.block_number,
                view.slot,
                0,
                &mut c_batch,
            )
        };
        assert_eq!(rc, SextantStatus::Ok as i32);
        assert_eq!(
            (c_batch.kind, c_batch.stall_reason),
            (kind, reason),
            "{tx} {index}"
        );

        let handle = unsafe {
            sextant_follower_new(
                outpoint.tx_id.as_ptr(),
                index,
                view.block_number,
                view.block_number,
                schedule.epoch,
                schedule.epoch_first_slot,
                schedule.epoch_length_slots,
            )
        };
        assert!(!handle.is_null());
        let mut tip = 0u64;
        let mut c_follower: SextantWatchVerdict = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(
                sextant_follower_supply_next_eta0(handle, 639, eta0.as_ptr()),
                SextantStatus::Ok as i32
            );
            assert_eq!(
                sextant_follower_append(handle, block.as_ptr(), block.len(), &mut tip),
                SextantStatus::Ok as i32
            );
            assert_eq!(
                sextant_follower_verdict(handle, view.slot, 0, &mut c_follower),
                SextantStatus::Ok as i32
            );
            sextant_follower_destroy(handle);
        }
        assert_eq!(tip, view.block_number);
        assert_eq!(
            (c_follower.kind, c_follower.stall_reason),
            (kind, reason),
            "{tx} {index}"
        );
    }
}
