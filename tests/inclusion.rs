//! Proof-based Cardano-transaction inclusion (DoD line 5, UTxO part 2): the
//! pure-Rust BLAKE2s-256 Merkle-Mountain-Range verifier reproduces mithril's
//! `MKMapProof<BlockRange>` verify on Sextant's own path, in the default
//! (non-`mithril`, no-blst, wasm-safe) graph.
//!
//! The oracle is the real chain itself: the golden vector
//! `tests/vectors/mithril-txproof.json` is a real release-preprod
//! `CardanoTransactionsProofs` for transaction `242f2037…a636`, and its proof
//! must recompute — on Sextant's own recompute, never trusting the proof's stated
//! `inner_root` — to the certified transaction Merkle root
//! `83c012fd…5d774129`. That root is the `cardano_transactions_merkle_root`
//! committed by the certifying certificate `mithril-txproof-cert.json`, which the
//! existing `verify_standard` STM-authenticates back toward the genesis key — so
//! `Ok` binds the transaction to a genesis-anchored commitment. The provider is
//! trusted for the proof *bytes* only; a mutated path node or a substituted
//! sub-tree recomputes to a different root and is rejected.

use sextant::inclusion::{InclusionError, verify_tx_inclusion};
use std::fs;
use std::path::PathBuf;

/// Transaction whose inclusion the golden proof attests.
const TX_HASH_HEX: &str = "242f2037b427ff20ef97a076a7d845c74530be4e5a97b59bb18a519fcfa7a636";
/// The certified transaction Merkle root the proof must recompute to — the
/// `cardano_transactions_merkle_root` of certificate `b3582978…deea`.
const CERTIFIED_ROOT_HEX: &str = "83c012fdc3e756fb5230d1a6554fbf743ccea171b37d536a64350c4f5d774129";

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The aggregator `proof` field (HEX of the JSON `MKMapProof`) for the golden
/// transaction, exactly as `verify_tx_inclusion` consumes it.
fn golden_proof_hex() -> Vec<u8> {
    let bytes = fs::read(vectors_dir().join("mithril-txproof.json")).expect("read txproof");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse txproof");
    v["certified_transactions"][0]["proof"]
        .as_str()
        .expect("proof field")
        .as_bytes()
        .to_vec()
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("32-byte hex");
    out
}

/// The parsed proof JSON as a mutable `Value`, for adversarial mutations.
fn golden_proof_value() -> serde_json::Value {
    let hexstr = String::from_utf8(golden_proof_hex()).unwrap();
    let json = hex::decode(&hexstr).expect("proof is hex");
    serde_json::from_slice(&json).expect("proof is JSON")
}

/// Re-encode a mutated proof `Value` back to the HEX(JSON) wire form.
fn reencode(v: &serde_json::Value) -> Vec<u8> {
    let json = serde_json::to_vec(v).expect("serialize proof");
    hex::encode(json).into_bytes()
}

#[test]
fn real_preprod_proof_recomputes_the_certified_root_and_includes_the_tx() {
    assert_eq!(
        verify_tx_inclusion(
            &golden_proof_hex(),
            &hex32(TX_HASH_HEX),
            &hex32(CERTIFIED_ROOT_HEX)
        ),
        Ok(())
    );
}

#[test]
fn a_mutated_master_path_node_is_rejected_as_root_mismatch() {
    let mut v = golden_proof_value();
    let byte = &mut v["master_proof"]["inner_proof_items"][0]["hash"][0];
    *byte = serde_json::json!(byte.as_u64().unwrap() ^ 1);
    assert_eq!(
        verify_tx_inclusion(
            &reencode(&v),
            &hex32(TX_HASH_HEX),
            &hex32(CERTIFIED_ROOT_HEX)
        ),
        Err(InclusionError::RootMismatch)
    );
}

#[test]
fn a_mutated_sub_tree_path_node_is_rejected() {
    // Flipping a node inside the block-range sub-proof changes the recomputed
    // sub-tree root, so the leaf it merges into is no longer the one the master
    // tree carries — the master recompute no longer reaches the certified root.
    let mut v = golden_proof_value();
    let byte = &mut v["sub_proofs"][0][1]["master_proof"]["inner_proof_items"][0]["hash"][0];
    *byte = serde_json::json!(byte.as_u64().unwrap() ^ 1);
    assert_eq!(
        verify_tx_inclusion(
            &reencode(&v),
            &hex32(TX_HASH_HEX),
            &hex32(CERTIFIED_ROOT_HEX)
        ),
        Err(InclusionError::RootMismatch)
    );
}

#[test]
fn a_transaction_not_in_the_proof_is_not_included() {
    assert_eq!(
        verify_tx_inclusion(&golden_proof_hex(), &[0xde; 32], &hex32(CERTIFIED_ROOT_HEX)),
        Err(InclusionError::NotIncluded)
    );
}

#[test]
fn the_wrong_certified_root_is_rejected() {
    assert_eq!(
        verify_tx_inclusion(&golden_proof_hex(), &hex32(TX_HASH_HEX), &[0xab; 32]),
        Err(InclusionError::RootMismatch)
    );
}

#[test]
fn malformed_proof_bytes_are_rejected_without_panicking() {
    let tx = hex32(TX_HASH_HEX);
    let root = hex32(CERTIFIED_ROOT_HEX);
    // Not hex.
    assert_eq!(
        verify_tx_inclusion(b"not hex zz", &tx, &root),
        Err(InclusionError::MalformedProof)
    );
    // Empty.
    assert_eq!(
        verify_tx_inclusion(b"", &tx, &root),
        Err(InclusionError::MalformedProof)
    );
    // Valid hex, not JSON.
    assert_eq!(
        verify_tx_inclusion(b"deadbeef", &tx, &root),
        Err(InclusionError::MalformedProof)
    );
    // Odd-length hex.
    assert_eq!(
        verify_tx_inclusion(b"abc", &tx, &root),
        Err(InclusionError::MalformedProof)
    );
}

/// The certified root the verifier checks against is not a bare constant — it is
/// the STM-authenticated `cardano_transactions_merkle_root` of the certificate the
/// proof names, and that certificate authenticates back toward the genesis key via
/// the existing Mithril verifiers. This ties the pure-crypto inclusion proof to
/// the genesis-anchored chain of trust.
#[cfg(feature = "mithril")]
#[test]
fn the_certified_root_is_stm_authenticated_and_the_proof_binds_to_it() {
    use sextant::mithril::{Certificate, verify_standard};

    let cert_bytes = fs::read(vectors_dir().join("mithril-txproof-cert.json")).expect("read cert");
    let cert = Certificate::from_json(&cert_bytes).expect("parse cert");

    // The proof names this certificate as the one that certifies it.
    let proof_bytes = fs::read(vectors_dir().join("mithril-txproof.json")).unwrap();
    let proof_v: serde_json::Value = serde_json::from_slice(&proof_bytes).unwrap();
    assert_eq!(proof_v["certificate_hash"].as_str().unwrap(), cert.hash);

    // Authenticate the certificate by its stake-based threshold multi-signature.
    verify_standard(&cert).expect("real preprod CardanoTransactions cert STM-verifies");

    // The commitment the cert signed names the exact root the proof recomputes to.
    let ct = cert
        .certified_transactions()
        .expect("a CardanoTransactions certificate");
    assert_eq!(ct.merkle_root, CERTIFIED_ROOT_HEX);
    assert_eq!(ct.block_number, 4927469);

    // The STM-authenticated root is what the transaction proof binds into.
    assert_eq!(
        verify_tx_inclusion(
            &golden_proof_hex(),
            &hex32(TX_HASH_HEX),
            &hex32(&ct.merkle_root)
        ),
        Ok(())
    );
}
