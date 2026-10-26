//! The body-only consumer: a certified inclusion read on real committed preprod data
//! proves provenance and establishes no output, so it never reaches a spend decision.
//! DoD line 7 (one verified UTxO read before a spend decision) is carried by the windowed
//! consumer, which reads the output from its creating block (`tests/windowed_consumer.rs`).
//!
//! The consumer runs ONE control flow over UNTRUSTED provider bytes: authenticate the
//! 106-cert Mithril chain back to the pinned genesis key, take the certified transaction
//! root from the AUTHENTICATED certificate (never a provider root), and verify the
//! transaction's certified inclusion. These tests mirror the example binary's assertions.

#![cfg(feature = "mithril")]

#[path = "../examples/verified_read_gate/gate.rs"]
mod gate;

use gate::Request;

/// Build a `Request` over the authentic committed fixtures, with `tx_body` supplied
/// by the caller so the spoof leg can pass tampered bytes through the SAME check.
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
    }
}

/// The authentic order is found included in the genesis-certified set at 4927469 and
/// refused all the same: its body carries no phase-2 outcome, so no output is
/// established, and no line of the log proceeds.
#[test]
fn the_authentic_order_is_included_and_refused_for_want_of_its_phase_2_outcome() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let body = gate::tx_body();
    let proof = gate::proof_hex();

    let out = gate::evaluate(&request(&vkey, &chain, &body, &proof));

    assert_eq!(out.refuse_reason, "ValidityNotEstablished");
    assert_eq!(out.certified_at, Some(4_927_469));
    assert!(
        out.log.iter().any(|l| l.contains("read.verify")
            && l.contains("certified_at=4927469")
            && l.contains("included=yes")
            && l.contains("created=not-established")),
        "a read.verify line carries the certified height and what stays unestablished"
    );
    assert!(
        out.log.iter().any(|l| l.contains("242f2037…a636#0")),
        "the log names the UTxO ref"
    );
    assert!(
        out.log.iter().all(|l| !l.contains("PROCEED")),
        "{:?}",
        out.log
    );
    assert!(out.log.iter().any(|l| l.contains("-> REFUSE")));
}

/// A tampered provider response (one output-coin byte flipped) no longer hashes to a
/// certified transaction leaf, so the same check refuses it as `NotIncluded`, before any
/// question of an output.
#[test]
fn consumer_refuses_a_spoofed_tampered_utxo() {
    let chain = gate::anchor_chain_json();
    let vkey = gate::genesis_vkey();
    let body = gate::tx_body();
    let proof = gate::proof_hex();

    let tampered = gate::tamper_output0_coin(&body);
    assert_ne!(tampered, body, "the tamper actually changed the bytes");
    let spoofed = gate::evaluate(&request(&vkey, &chain, &tampered, &proof));

    assert_eq!(spoofed.refuse_reason, "NotIncluded");
    assert_eq!(spoofed.certified_at, None);
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

    assert_eq!(out.refuse_reason, "Genesis");
    assert_eq!(out.certified_at, None);
}

/// The example binary's own control flow (authentic path then spoof path) exits zero.
#[test]
fn the_example_runs_both_paths_and_exits_zero() {
    assert_eq!(gate::run_demo(), 0);
}
