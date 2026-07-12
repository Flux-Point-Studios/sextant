//! BEYOND-DoD Tier1: the windowed-unspent consumer's execution path performs one
//! authenticated windowed watch over real committed preprod data before a spend decision,
//! proceeding only on a no-spend-observed verdict and refusing every evasion fail-closed.
//!
//! The consumer (a Masumi-escrow / ADAM-spend-gate stand-in) runs ONE control flow over
//! UNTRUSTED provider bytes: authenticate the 106-cert Mithril chain to the pinned genesis
//! key, take the certified anchor from the AUTHENTICATED tip (never a provider height),
//! then scan a header-verified, body-committed window for a spend of the watched outpoint.
//! These tests mirror the example binary's assertions so CI judges the slice done.

#![cfg(feature = "mithril")]

#[path = "../examples/windowed_spend_gate/gate.rs"]
mod gate;

use gate::{Decision, Request};
use sextant::utxo::OutPoint;

fn request<'a>(
    vkey: &'a [u8; 32],
    chain: &'a [u8],
    eta0: &'a [u8; 32],
    window: &'a [Vec<u8>],
    watched: OutPoint,
) -> Request<'a> {
    Request {
        anchor_chain_json: chain,
        genesis_vkey: vkey,
        eta0,
        window_blocks: window,
        watched,
        require_through: gate::REQUIRE_THROUGH,
        freshness: gate::fresh(),
    }
}

/// The never-spent outpoint proceeds: the composed genesis-anchored verify + windowed scan
/// yields no spend of `beaa9166…#0`, and the PROCEED line carries the mandatory honest
/// scope — basis, anchor, as-of tip, freshness lag, and both surfaced assumptions.
#[test]
fn consumer_proceeds_on_a_no_spend_observed_window() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let eta0 = gate::eta0();
    let window = gate::preprod_window();

    let out = gate::evaluate(&request(&vkey, &chain, &eta0, &window, gate::watched(0)));

    assert_eq!(out.decision, Decision::Proceed);
    assert_eq!(out.as_of_height, Some(4_921_937));
    assert_eq!(out.refuse_reason, None);

    let proceed = out
        .log
        .iter()
        .find(|l| l.contains("-> PROCEED"))
        .expect("a PROCEED gate line");
    for token in [
        "basis=WatchedWindow",
        "anchor=4927469",
        "as_of=4921937@slot128046016",
        "lag=",
        "assumptions=mithril_quorum,data_complete",
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

/// The spent outpoint over the SAME authenticated window is a definite refuse: a spend of
/// `beaa9166…#1` is observed in the verified body stream, never read as no-spend.
#[test]
fn consumer_refuses_a_spent_outpoint() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let eta0 = gate::eta0();
    let window = gate::preprod_window();

    let out = gate::evaluate(&request(&vkey, &chain, &eta0, &window, gate::watched(1)));

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

    let out = gate::evaluate(&request(&vkey, &chain, &eta0, &truncated, gate::watched(1)));

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

    let out = gate::evaluate(&request(&vkey, &chain, &eta0, &window, gate::watched(0)));

    assert_eq!(out.decision, Decision::Refuse);
    assert_eq!(out.refuse_reason.as_deref(), Some("Genesis"));
}

/// The example binary's own control flow (PROCEED then three refuse evasions) exits zero —
/// the slice proof is its stdout, and this asserts the run itself is fail-closed-green.
#[test]
fn the_example_runs_all_legs_and_exits_zero() {
    assert_eq!(gate::run_demo(), 0);
}
