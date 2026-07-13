//! The certified transaction frontier a verdict's `mithril_quorum` bit rests on must come
//! from what the stake quorum actually SIGNED, not from a certificate field an attacker can
//! recompute the content hash around.
//!
//! A Mithril certificate's STM multi-signature signs `signed_message = H(protocol_message)`.
//! The `(epoch, block_number)` in `signed_entity_type` is fed into the certificate's CONTENT
//! hash but is NOT part of `protocol_message` — so it is authenticated only by the hash the
//! aggregator itself computes, never by the multi-signature. The signed frontier lives in the
//! `current_epoch` / `latest_block_number` protocol-message parts (alongside the signed
//! `cardano_transactions_merkle_root`). `Certificate::certified_transactions` must read the
//! signed parts; reading `signed_entity_type` lets a hostile aggregator inflate the block
//! number, keep the chain genesis-anchored + STM-verified, and lift `mithril_quorum=true`
//! for a tip that is not actually certified.
#![cfg(feature = "mithril")]

use std::path::PathBuf;

use sextant::mithril::{Certificate, verify_chain_anchored};
use sextant::utxo::CertifiedTransactions;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn committed_chain() -> (Vec<Certificate>, [u8; 32]) {
    let vkey_hex = std::fs::read_to_string(vectors_dir().join("mithril-genesis.vkey"))
        .expect("committed genesis vkey");
    let genesis_vkey: [u8; 32] = hex::decode(vkey_hex.trim())
        .expect("hex vkey")
        .try_into()
        .expect("32-byte vkey");
    let bytes = std::fs::read(vectors_dir().join("mithril-anchor-chain.json"))
        .expect("committed anchor chain");
    let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).expect("chain array");
    let certs = json
        .iter()
        .map(|c| Certificate::from_json(serde_json::to_vec(c).unwrap().as_slice()).expect("cert"))
        .collect();
    (certs, genesis_vkey)
}

/// Baseline: the genuine committed chain is genesis-anchored and certifies block 4927469 —
/// where `signed_entity_type` and the signed `latest_block_number` agree.
#[test]
fn committed_chain_certifies_the_signed_block() {
    let (certs, vkey) = committed_chain();
    let verified = verify_chain_anchored(&certs, &vkey).expect("genesis-anchored");
    let ct: CertifiedTransactions = verified
        .certified_transactions
        .expect("tip certifies a transaction set");
    assert_eq!(ct.block_number, 4_927_469);
    assert_eq!(ct.epoch, 300);
}

/// The exploit: inflate the tip cert's `signed_entity_type` block number and recompute its
/// content hash. The chain STILL verifies to genesis (the STM signature is over
/// `protocol_message`, which is untouched) — proving `signed_entity_type` is not
/// quorum-authenticated. The certified frontier must nonetheless remain the SIGNED
/// `latest_block_number` (4927469), never the attacker's inflated value.
#[test]
fn certified_block_number_ignores_a_forged_signed_entity_type() {
    use sextant::mithril::SignedEntityType;

    let (mut certs, vkey) = committed_chain();
    let tip = certs.last_mut().expect("non-empty chain");

    // Keep the epoch, inflate the block number the verdict's mithril_quorum bit rests on.
    let SignedEntityType::CardanoTransactions(epoch, _) = tip.signed_entity_type else {
        panic!("committed tip is a CardanoTransactions cert");
    };
    tip.signed_entity_type = SignedEntityType::CardanoTransactions(epoch, 14_927_469);
    // Re-seal the content hash so the chain-integrity check still passes; the STM
    // multi-signature (over the unchanged protocol_message) is not touched.
    tip.hash = tip.compute_hash();

    // The forged cert is still accepted as genesis-anchored + STM-verified — this is the
    // exact surface: a hostile aggregator's inflated frontier passes verification.
    let verified =
        verify_chain_anchored(&certs, &vkey).expect("forged block number still verifies");

    // ...but the certified frontier is the SIGNED value, so the lie is inert.
    let ct = verified
        .certified_transactions
        .expect("tip certifies a transaction set");
    assert_eq!(
        ct.block_number, 4_927_469,
        "certified block number must be the STM-signed latest_block_number, \
         not the forgeable signed_entity_type",
    );
}
