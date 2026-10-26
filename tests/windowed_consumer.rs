//! DoD line 7 (Live) and BEYOND-DoD Tier1: the windowed consumer's execution path performs
//! one verified UTxO read over real committed preprod data before a spend decision — an
//! authenticated windowed watch, then the watched output read from its creating block in
//! that window — proceeding only on a no-spend-observed verdict over an output that meets
//! the order predicate, and refusing every evasion fail-closed.
//!
//! The consumer (a Masumi-escrow / ADAM-spend-gate stand-in) runs ONE control flow over
//! UNTRUSTED provider bytes: authenticate the 106-cert Mithril chain to the pinned genesis
//! key, take the certified anchor from the AUTHENTICATED tip (never a provider height),
//! scan a header-verified, body-committed window for a spend of the watched outpoint, and
//! read the output under the expected hash the verified window's header view carries.
//! These tests mirror the example binary's assertions so CI judges the line done.

#![cfg(feature = "mithril")]

#[path = "../examples/windowed_spend_gate/gate.rs"]
mod gate;

use gate::{Decision, Request};
use sextant::header::HeaderView;
use sextant::utxo::OutPoint;

fn request<'a>(
    vkey: &'a [u8; 32],
    chain: &'a [u8],
    eta0: &'a [u8; 32],
    window: &'a [Vec<u8>],
    watched: OutPoint,
    order_address: &'a [u8],
) -> Request<'a> {
    Request {
        anchor_chain_json: chain,
        genesis_vkey: vkey,
        eta0,
        window_blocks: window,
        watched,
        require_through: gate::REQUIRE_THROUGH,
        freshness: gate::fresh(),
        order_address,
        min_lovelace: gate::MIN_LOVELACE,
    }
}

/// The never-spent order output proceeds: the composed genesis-anchored verify + windowed
/// scan yields no spend of `beaa9166…#0`, the output read from its creating block (4921916,
/// under the hash the window's own header view carries) pays the order address the floor,
/// and the PROCEED line carries the mandatory honest scope — basis, anchor, as-of tip,
/// freshness lag, both surfaced assumptions, and the header-vouched creating block.
#[test]
fn consumer_proceeds_on_a_no_spend_observed_window() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let eta0 = gate::eta0();
    let window = gate::preprod_window();
    let address = gate::order_address();

    let out = gate::evaluate(&request(
        &vkey,
        &chain,
        &eta0,
        &window,
        gate::watched(0),
        &address,
    ));

    assert_eq!(out.decision, Decision::Proceed);
    assert_eq!(out.as_of_height, Some(4_921_937));
    assert_eq!(out.refuse_reason, None);
    let created = out.created.as_ref().expect("the created output");
    let creating = HeaderView::from_block_cbor(&window[0]).expect("the window's first block");
    assert_eq!(
        (created.block_hash, created.block_number, created.slot),
        (creating.block_hash, 4_921_916, creating.slot)
    );
    assert_eq!(
        (
            created.address.clone(),
            created.lovelace,
            created.phase2_valid
        ),
        (address, gate::MIN_LOVELACE, true)
    );

    let proceed = out
        .log
        .iter()
        .find(|l| l.contains("-> PROCEED"))
        .expect("a PROCEED gate line");
    let created_token = format!("created=block:{}@4921916", hex::encode(creating.block_hash));
    for token in [
        "basis=WatchedWindow",
        "anchor=4927469",
        "as_of=4921937@slot128046016",
        "lag=",
        "assumptions=mithril_quorum,data_complete",
        created_token.as_str(),
        "trust=header-vouched",
    ] {
        assert!(
            proceed.contains(token),
            "the PROCEED line must name {token}: {proceed}"
        );
    }
    assert!(
        proceed.contains("NOT absolute"),
        "the PROCEED note states the honest windowed scope: {proceed}"
    );
    assert!(
        out.log.iter().any(|l| l.contains("beaa9166…2a5e#0")),
        "the log names the watched outpoint ref"
    );
}

/// The order predicate is load-bearing: the same created output refuses under a floor one
/// lovelace above what it pays, and under an address it does not pay.
#[test]
fn consumer_refuses_a_created_output_that_misses_the_order() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let eta0 = gate::eta0();
    let window = gate::preprod_window();
    let address = gate::order_address();
    let mut other = address.clone();
    other[1] ^= 0x01;

    let mut short_paid = request(&vkey, &chain, &eta0, &window, gate::watched(0), &address);
    short_paid.min_lovelace += 1;
    let elsewhere = request(&vkey, &chain, &eta0, &window, gate::watched(0), &other);
    for out in [gate::evaluate(&short_paid), gate::evaluate(&elsewhere)] {
        assert_eq!(out.decision, Decision::Refuse);
        assert_eq!(out.refuse_reason.as_deref(), Some("OrderPredicate"));
        assert!(
            out.log.iter().all(|l| !l.contains("PROCEED")),
            "{:?}",
            out.log
        );
    }
}

/// A tampered creating block cannot reach the read: one flipped byte of the order
/// output's address breaks the block's body commitment, the window stalls, and the
/// consumer refuses before any output is read.
#[test]
fn consumer_refuses_a_window_whose_creating_block_was_tampered() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let eta0 = gate::eta0();
    let mut window = gate::preprod_window();
    let address = gate::order_address();
    let at = window[0]
        .windows(address.len())
        .position(|w| w == address.as_slice())
        .expect("the order address in its creating block");
    window[0][at + 1] ^= 0x01;

    let out = gate::evaluate(&request(
        &vkey,
        &chain,
        &eta0,
        &window,
        gate::watched(0),
        &address,
    ));

    assert_eq!(out.decision, Decision::Refuse);
    assert_eq!(
        out.refuse_reason.as_deref(),
        Some("Stall:BodyCommitmentMismatch")
    );
    assert_eq!(out.created, None);
}

/// An index the watched transaction never created is a non-answer: the window observes
/// no creation of `beaa9166…#7`, so the consumer refuses before any output is read.
#[test]
fn consumer_refuses_an_output_the_window_never_created() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let eta0 = gate::eta0();
    let window = gate::preprod_window();
    let address = gate::order_address();

    let out = gate::evaluate(&request(
        &vkey,
        &chain,
        &eta0,
        &window,
        gate::watched(7),
        &address,
    ));

    assert_eq!(out.decision, Decision::Refuse);
    assert_eq!(
        out.refuse_reason.as_deref(),
        Some("Stall:CreationNotObserved")
    );
    assert_eq!(out.created, None);
}

/// The spent outpoint over the SAME authenticated window is a definite refuse: a spend of
/// `beaa9166…#1` is observed in the verified body stream, never read as no-spend.
#[test]
fn consumer_refuses_a_spent_outpoint() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let eta0 = gate::eta0();
    let window = gate::preprod_window();
    let address = gate::order_address();

    let out = gate::evaluate(&request(
        &vkey,
        &chain,
        &eta0,
        &window,
        gate::watched(1),
        &address,
    ));

    assert_eq!(out.decision, Decision::Refuse);
    assert_eq!(out.refuse_reason.as_deref(), Some("SpendObserved"));
    assert!(
        out.log
            .iter()
            .any(|l| l.contains("spend observed") && l.contains(gate::SPENDING_TX_HEX)),
        "the WARN line names the spending transaction"
    );
}

/// The truncation evasion at consumer altitude: serving only the creating block for a spent
/// outpoint yields a non-answer (`WindowTooShort`), never a false no-spend — the caller's
/// `require_through` floor is load-bearing here.
#[test]
fn consumer_refuses_a_truncated_window_never_proceeds() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let eta0 = gate::eta0();
    let window = gate::preprod_window();
    let truncated = vec![window[0].clone()];
    let address = gate::order_address();

    let out = gate::evaluate(&request(
        &vkey,
        &chain,
        &eta0,
        &truncated,
        gate::watched(1),
        &address,
    ));

    assert_eq!(out.decision, Decision::Refuse);
    assert_eq!(out.refuse_reason.as_deref(), Some("Stall:WindowTooShort"));
}

/// The genesis anchor is load-bearing: a wrong genesis key fails the whole chain to anchor,
/// so no certified anchor is produced and the consumer refuses before any window scan.
#[test]
fn consumer_refuses_an_unanchored_cert_chain() {
    let chain = gate::anchor_chain_json();
    let mut vkey = gate::genesis_vkey();
    vkey[0] ^= 0x01;
    let eta0 = gate::eta0();
    let window = gate::preprod_window();
    let address = gate::order_address();

    let out = gate::evaluate(&request(
        &vkey,
        &chain,
        &eta0,
        &window,
        gate::watched(0),
        &address,
    ));

    assert_eq!(out.decision, Decision::Refuse);
    assert_eq!(out.refuse_reason.as_deref(), Some("Genesis"));
}

/// The example binary's own control flow (PROCEED then four refusals) exits zero — the
/// line proof is its stdout, and this asserts the run itself is fail-closed-green.
#[test]
fn the_example_runs_all_legs_and_exits_zero() {
    assert_eq!(gate::run_demo(), 0);
}
