//! UTxO read verification (DoD line 5, UTxO part 3 — CLOSES the line): the read
//! path proves an output's bytes are the authentic, genesis-anchored on-chain
//! bytes of a Mithril-certified transaction, and carries the honest verdict that
//! it CANNOT establish liveness (unspent).
//!
//! The oracle is the real chain: `tests/vectors/mithril-tx-body.cbor` is the exact
//! `KeepRaw` transaction-body CBOR of the golden preprod transaction, so
//! `blake2b256(body) == 242f2037…a636` — the certified txid the part-2 inclusion
//! proof (`mithril-txproof.json`) attests, whose Merkle root
//! (`83c012fd…5d774129`) is the `cardano_transactions_merkle_root` an STM-
//! authenticated certificate committed. `verify_utxo_read` hashes the SUPPLIED
//! bytes (never a provider-supplied hash), certifies inclusion of that hash, then
//! decodes the requested output on Sextant's own minicbor path.

use sextant::inclusion::InclusionError;
use sextant::utxo::{Datum, SpendStatus, UtxoError, verify_utxo_read};
use std::fs;
use std::path::PathBuf;

/// The STM-authenticated certified transaction Merkle root the proof recomputes to.
const CERTIFIED_ROOT_HEX: &str = "83c012fdc3e756fb5230d1a6554fbf743ccea171b37d536a64350c4f5d774129";
/// The certified height carried on every verdict (`latest_block_number` == the
/// certifying cert's `CardanoTransactions` block).
const CERTIFIED_BLOCK: u64 = 4_927_469;

/// Output 0: a script address holding 5 ADA and an inline datum (an on-chain order).
const OUT0_ADDR_HEX: &str = "7015e93b4326724b8e2d3abc3a6aaef29ce6d6877cfc815eb8f3bd3699";
const OUT0_LOVELACE: u64 = 5_000_000;
const OUT0_DATUM_HEX: &str = "d8799fbfd8799f4040ffd8799f1a09d00ed6ffd8799f581c3c0307006496e072a496c0742e55af0c64284b5bf668f2b420fe4f3540ffd8799f1a3b9aca00ffff1b0000019f53ec4417ff";

/// Output 1: a base payment address holding ~4867 ADA, no datum (legacy array form).
const OUT1_ADDR_HEX: &str = "007dedab05f07efa1093e73b17a9433ca2f53151015e9b30e17e6a17b1667a2455db60b2c4a4ddd2342c21463d55a465dddc409f9a604ddf05";
const OUT1_LOVELACE: u64 = 4_867_657_971;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The raw transaction-body CBOR (the fixture is its lowercase hex).
fn tx_body() -> Vec<u8> {
    let hexstr = fs::read_to_string(vectors_dir().join("mithril-tx-body.cbor")).expect("read body");
    hex::decode(hexstr.trim()).expect("body is hex")
}

/// The aggregator `proof` field (HEX of the JSON `MKMapProof`) for the golden tx.
fn proof_hex() -> Vec<u8> {
    let bytes = fs::read(vectors_dir().join("mithril-txproof.json")).expect("read txproof");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse txproof");
    v["certified_transactions"][0]["proof"]
        .as_str()
        .expect("proof field")
        .as_bytes()
        .to_vec()
}

fn root() -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(CERTIFIED_ROOT_HEX, &mut out).unwrap();
    out
}

#[test]
fn verify_utxo_read_yields_the_certified_output_bytes() {
    let body = tx_body();
    let proof = proof_hex();
    let root = root();

    // Output 0: script address + 5 ADA + inline datum.
    let out0 =
        verify_utxo_read(&body, 0, &proof, &root, CERTIFIED_BLOCK).expect("output 0 verifies");
    assert_eq!(out0.address, hex::decode(OUT0_ADDR_HEX).unwrap());
    assert_eq!(out0.lovelace, OUT0_LOVELACE);
    assert_eq!(
        out0.datum,
        Some(Datum::Inline(hex::decode(OUT0_DATUM_HEX).unwrap()))
    );
    assert_eq!(out0.certified_at, CERTIFIED_BLOCK);
    assert_eq!(out0.spend_status, SpendStatus::NotEstablished);

    // Output 1: base payment address + ~4867 ADA + no datum (legacy array form).
    let out1 =
        verify_utxo_read(&body, 1, &proof, &root, CERTIFIED_BLOCK).expect("output 1 verifies");
    assert_eq!(out1.address, hex::decode(OUT1_ADDR_HEX).unwrap());
    assert_eq!(out1.lovelace, OUT1_LOVELACE);
    assert_eq!(out1.datum, None);
    assert_eq!(out1.certified_at, CERTIFIED_BLOCK);
    assert_eq!(out1.spend_status, SpendStatus::NotEstablished);
}

/// The DoD negative: tampering with the economic content of the claimed output
/// changes the transaction hash, so the supplied bytes are no longer the certified
/// transaction — the hash-binding rejects it as not-included BEFORE any decode.
#[test]
fn tampered_utxo_claim_is_rejected() {
    let body = tx_body();
    let addr0 = hex::decode(OUT0_ADDR_HEX).unwrap();
    // Output 0's value follows its address as `01 82 1a <coin:4>`; flip a coin byte.
    let addr_pos = body
        .windows(addr0.len())
        .position(|w| w == addr0.as_slice())
        .expect("output 0 address present");
    let coin_byte = addr_pos + addr0.len() + 3; // skip key(01) array(82) uint32-tag(1a)
    let mut tampered = body.clone();
    tampered[coin_byte] ^= 0x01;
    assert_ne!(tampered, body);

    assert_eq!(
        verify_utxo_read(&tampered, 0, &proof_hex(), &root(), CERTIFIED_BLOCK),
        Err(UtxoError::Inclusion(InclusionError::NotIncluded))
    );
}

/// The substituted-bytes guard: a DIFFERENT transaction's bytes (here the golden tx
/// with one input mutated — same outputs, different txid) do not hash to a leaf of
/// this proof, so they cannot be laundered through it. `verify_utxo_read` hashes the
/// bytes it is given, never a provider-supplied hash.
#[test]
fn a_different_transactions_bytes_are_rejected_under_this_proof() {
    let mut other = tx_body();
    // Byte 9 is the first input's txid — mutating it yields a distinct transaction.
    other[9] ^= 0x01;
    assert_eq!(
        verify_utxo_read(&other, 0, &proof_hex(), &root(), CERTIFIED_BLOCK),
        Err(UtxoError::Inclusion(InclusionError::NotIncluded))
    );
}

/// Honesty guard: the read path can NEVER return a positive-liveness verdict. The
/// certified transaction set is a monotone "created" predicate ~100 blocks behind
/// tip; Cardano commits to no UTxO-set accumulator, so unspent is undecidable here.
/// `SpendStatus` has exactly one inhabitant and no code path narrows it.
#[test]
fn the_verdict_never_claims_liveness() {
    let out = verify_utxo_read(&tx_body(), 0, &proof_hex(), &root(), CERTIFIED_BLOCK).unwrap();
    // The verdict is the honest tier. The compile-time tripwire that no liveness
    // tier exists lives in the crate's own unit tests: `SpendStatus` is
    // `#[non_exhaustive]`, so an external exhaustive match is not permitted here.
    assert_eq!(out.spend_status, SpendStatus::NotEstablished);
}

/// An output index past the transaction's output list is rejected — reachable only
/// on the certified bytes, since inclusion is checked first.
#[test]
fn an_output_index_past_the_end_is_rejected() {
    assert_eq!(
        verify_utxo_read(&tx_body(), 2, &proof_hex(), &root(), CERTIFIED_BLOCK),
        Err(UtxoError::OutputIndexOutOfRange)
    );
}

/// The end-to-end genesis-anchored read: the certified root the output verifies
/// against is not a bare constant — it is the `cardano_transactions_merkle_root`
/// an STM-authenticated certificate committed (and that certificate authenticates
/// back toward the genesis key via the existing Mithril verifiers). Composing
/// `verify_standard` → `certified_transactions()` → `verify_utxo_read` binds the
/// decoded output to the genesis-anchored chain of trust, on Sextant's own path.
#[cfg(feature = "mithril")]
#[test]
fn the_output_is_read_against_an_stm_authenticated_certified_root() {
    use sextant::mithril::{Certificate, verify_standard};

    let cert_bytes = fs::read(vectors_dir().join("mithril-txproof-cert.json")).expect("read cert");
    let cert = Certificate::from_json(&cert_bytes).expect("parse cert");

    // The proof names this certificate as the one that certifies it.
    let proof_bytes = fs::read(vectors_dir().join("mithril-txproof.json")).unwrap();
    let proof_v: serde_json::Value = serde_json::from_slice(&proof_bytes).unwrap();
    assert_eq!(proof_v["certificate_hash"].as_str().unwrap(), cert.hash);

    // Authenticate the certificate by its stake-based threshold multi-signature.
    verify_standard(&cert).expect("real preprod CardanoTransactions cert STM-verifies");

    // The commitment the cert signed names the exact root and height.
    let ct = cert
        .certified_transactions()
        .expect("a CardanoTransactions certificate");
    assert_eq!(ct.merkle_root, CERTIFIED_ROOT_HEX);
    assert_eq!(ct.block_number, CERTIFIED_BLOCK);

    let mut authenticated_root = [0u8; 32];
    hex::decode_to_slice(&ct.merkle_root, &mut authenticated_root).unwrap();

    let out = verify_utxo_read(
        &tx_body(),
        0,
        &proof_hex(),
        &authenticated_root,
        ct.block_number,
    )
    .expect("output verifies against the STM-authenticated root");
    assert_eq!(out.lovelace, OUT0_LOVELACE);
    assert_eq!(out.certified_at, CERTIFIED_BLOCK);
    assert_eq!(out.spend_status, SpendStatus::NotEstablished);
}

/// Independent cross-decoder differential: pallas decodes the same golden transaction
/// body and its `MultiEraOutput` accessors yield `{address, lovelace, datum-presence}`
/// on a code path independent of Sextant's own minicbor `decode_output`. Parity on
/// EVERY output is the oracle the rest of this library's verdicts carry (pallas for
/// header/opcert/KES, cardano-crypto for VRF, ckb for the MMR proof) — so a future
/// divergence from the ledger on some output shape is caught, not silently wrong.
#[test]
fn utxo_output_decode_matches_pallas_on_every_output() {
    use pallas_codec::minicbor;
    use pallas_primitives::conway::TransactionBody;
    use pallas_traverse::{Era, MultiEraOutput};

    let body_bytes = tx_body();
    let body: TransactionBody =
        minicbor::decode(&body_bytes).expect("pallas decodes the Conway body");
    assert!(body.outputs.len() >= 2, "golden tx has both test outputs");

    for i in 0..body.outputs.len() {
        let out_bytes = minicbor::to_vec(&body.outputs[i]).expect("re-encode output");
        let oracle = MultiEraOutput::decode(Era::Conway, &out_bytes).expect("pallas output");

        let sextant = verify_utxo_read(&body_bytes, i, &proof_hex(), &root(), CERTIFIED_BLOCK)
            .unwrap_or_else(|e| panic!("output {i} verifies: {e:?}"));

        assert_eq!(
            sextant.address,
            oracle.address().expect("pallas address").to_vec(),
            "output {i}: address disagrees with pallas",
        );
        assert_eq!(
            sextant.lovelace,
            oracle.value().coin(),
            "output {i}: lovelace disagrees with pallas",
        );
        assert_eq!(
            sextant.datum.is_some(),
            oracle.datum().is_some(),
            "output {i}: datum-presence disagrees with pallas",
        );
    }
}
