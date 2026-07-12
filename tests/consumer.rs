//! DoD line 7 (Live): the first downstream consumer's execution path performs one
//! verified UTxO read on real committed preprod data before a spend decision, and
//! rejects a spoofed provider response in the same test.
//!
//! The consumer (a keeper/batcher stand-in for the out-of-scope write-path) runs
//! ONE control flow over UNTRUSTED provider bytes: authenticate the 106-cert Mithril
//! chain back to the pinned genesis key, take the certified transaction root from the
//! AUTHENTICATED certificate (never a provider root), verify the UTxO's certified
//! inclusion, then make a single boolean spend decision. These tests mirror the
//! example binary's assertions so CI judges the line done.

#![cfg(feature = "mithril")]

#[path = "../examples/verified_read_gate/gate.rs"]
mod gate;

use gate::{Decision, Request};

/// Build a `Request` over the authentic committed fixtures, with `tx_body` supplied
/// by the caller so the spoof leg can pass tampered bytes through the SAME gate.
fn request<'a>(
    vkey: &'a [u8; 32],
    chain: &'a [u8],
    body: &'a [u8],
    proof: &'a [u8],
) -> Request<'a> {
    Request {
        anchor_chain_json: chain,
        genesis_vkey: vkey,
        tx_body: body,
        proof_hex: proof,
        out_index: gate::OUT_INDEX,
        min_lovelace: gate::MIN_LOVELACE,
        expected_datum: gate::expected_datum(),
    }
}

/// The authentic order proceeds: the composed genesis-anchored verify path yields
/// output 0 of tx `242f2037…a636`, the gate predicate is met, and the PROCEED log
/// line carries the certified height and the mandatory NotEstablished note.
#[test]
fn consumer_proceeds_on_the_authentic_certified_order() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let body = gate::tx_body();
    let proof = gate::proof_hex();

    let out = gate::evaluate(&request(&vkey, &chain, &body, &proof));

    assert_eq!(out.decision, Decision::Proceed);
    assert_eq!(out.certified_at, Some(4_927_469));
    assert_eq!(out.refuse_reason, None);

    assert!(
        out.log
            .iter()
            .any(|l| l.contains("read.verify") && l.contains("certified_at=4927469")),
        "a read.verify line carries the certified height"
    );
    let proceed = out
        .log
        .iter()
        .find(|l| l.contains("-> PROCEED"))
        .expect("a PROCEED gate line");
    assert!(
        proceed.contains("spend_status=NotEstablished"),
        "the PROCEED note must state the honest unspent scope: {proceed}"
    );
    assert!(
        out.log.iter().any(|l| l.contains("242f2037…a636#0")),
        "the log names the UTxO ref"
    );
}

/// The DoD's "rejects a spoofed RPC response in the same test": the SAME consumer
/// gate first accepts the authentic order, then — fed a tampered provider response
/// (one output-coin byte flipped) — refuses it fail-closed, because the tampered
/// bytes no longer hash to a certified transaction leaf (`NotIncluded`) and no
/// verified output ever exists to gate on.
#[test]
fn consumer_refuses_a_spoofed_tampered_utxo() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let body = gate::tx_body();
    let proof = gate::proof_hex();

    // Same gate, authentic bytes → PROCEED.
    let genuine = gate::evaluate(&request(&vkey, &chain, &body, &proof));
    assert_eq!(genuine.decision, Decision::Proceed);

    // Same gate, spoofed bytes → REFUSE (fail-closed, no verified output).
    let tampered = gate::tamper_output0_coin(&body);
    assert_ne!(tampered, body, "the tamper actually changed the bytes");
    let spoofed = gate::evaluate(&request(&vkey, &chain, &tampered, &proof));

    assert_eq!(spoofed.decision, Decision::Refuse);
    assert_eq!(spoofed.refuse_reason.as_deref(), Some("NotIncluded"));
    assert!(
        spoofed
            .log
            .iter()
            .any(|l| l.contains("provider=spoofed") && l.contains("reason=NotIncluded")),
        "the WARN line names the spoofed provider and the reason"
    );
}

/// The genesis anchor is load-bearing at consumer altitude: swap in a wrong genesis
/// verification key and the whole chain fails to anchor, so no certified root is ever
/// produced and the consumer refuses.
#[test]
fn consumer_refuses_an_unanchored_cert_chain() {
    let chain = gate::anchor_chain_json();
    let mut vkey = gate::genesis_vkey();
    vkey[0] ^= 0x01; // not the network genesis anchor
    let body = gate::tx_body();
    let proof = gate::proof_hex();

    let out = gate::evaluate(&request(&vkey, &chain, &body, &proof));

    assert_eq!(out.decision, Decision::Refuse);
    assert_eq!(out.refuse_reason.as_deref(), Some("Genesis"));
}

/// The example binary's own control flow (accept path then spoof path) exits zero —
/// the DoD proof is its stdout, and this asserts the run itself is fail-closed-green.
#[test]
fn the_example_runs_both_paths_and_exits_zero() {
    assert_eq!(gate::run_demo(), 0);
}
