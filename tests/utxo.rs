//! UTxO read verification (DoD line 5, UTxO part 3): the read path checks a body's
//! certified inclusion in the Mithril transaction set, and an included body establishes
//! no output — its phase-2 outcome lives in its block, not its body — so the read refuses
//! with `ValidityNotEstablished` once every earlier check has passed.
//!
//! The oracle is the real chain: `tests/vectors/mithril-tx-body.cbor` is the exact
//! `KeepRaw` transaction-body CBOR of the golden preprod transaction, so
//! `blake2b256(body) == 242f2037…a636` — the certified txid the part-2 inclusion
//! proof (`mithril-txproof.json`) attests, whose Merkle root
//! (`83c012fd…5d774129`) is the `cardano_transactions_merkle_root` an STM-
//! authenticated certificate committed. `verify_utxo_read` hashes the SUPPLIED
//! bytes (never a provider-supplied hash), certifies inclusion of that hash, then
//! decodes the requested output on Sextant's own minicbor path before it refuses.

use sextant::inclusion::InclusionError;
use sextant::utxo::{OutPoint, SpendSet, UtxoError, decode_spends, verify_utxo_read};
use std::fs;
use std::path::PathBuf;

/// The STM-authenticated certified transaction Merkle root the proof recomputes to.
const CERTIFIED_ROOT_HEX: &str = "83c012fdc3e756fb5230d1a6554fbf743ccea171b37d536a64350c4f5d774129";
/// The certified height of the certifying cert's `CardanoTransactions` block.
const CERTIFIED_BLOCK: u64 = 4_927_469;

/// Output 0's script address, which the tamper leg flips a coin byte after.
const OUT0_ADDR_HEX: &str = "7015e93b4326724b8e2d3abc3a6aaef29ce6d6877cfc815eb8f3bd3699";

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

/// Both outputs of the certified golden transaction decode, and neither is established:
/// the body carries no phase-2 outcome, so an included read refuses rather than return
/// an output the transaction may never have created.
#[test]
fn an_included_body_establishes_no_output() {
    let body = tx_body();
    let proof = proof_hex();
    let root = root();
    for index in [0, 1] {
        assert_eq!(
            verify_utxo_read(&body, index, &proof, &root, CERTIFIED_BLOCK),
            Err(UtxoError::ValidityNotEstablished),
            "{index}"
        );
    }
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

/// An output index past the transaction's output list is rejected — reachable only
/// on the certified bytes, since inclusion is checked first, and ahead of the refusal
/// every included body ends in.
#[test]
fn an_output_index_past_the_end_is_rejected() {
    assert_eq!(
        verify_utxo_read(&tx_body(), 2, &proof_hex(), &root(), CERTIFIED_BLOCK),
        Err(UtxoError::OutputIndexOutOfRange)
    );
}

/// The genesis-anchored root admits the body: the certified root is the
/// `cardano_transactions_merkle_root` an STM-authenticated certificate committed, the
/// golden body is included under it (the read reaches its final refusal), and under any
/// other root it is not.
#[cfg(feature = "mithril")]
#[test]
fn the_body_is_included_under_an_stm_authenticated_certified_root() {
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

    assert_eq!(
        verify_utxo_read(
            &tx_body(),
            0,
            &proof_hex(),
            &authenticated_root,
            ct.block_number,
        ),
        Err(UtxoError::ValidityNotEstablished)
    );
    authenticated_root[0] ^= 0x01;
    assert!(matches!(
        verify_utxo_read(
            &tx_body(),
            0,
            &proof_hex(),
            &authenticated_root,
            ct.block_number,
        ),
        Err(UtxoError::Inclusion(_))
    ));
}

/// Independent cross-decoder differential for the tx-INPUT decoder: pallas decodes
/// the same golden transaction body and its own `inputs` + `collateral` sets are the
/// oracle for `decode_spends`, on a code path independent of Sextant's minicbor. A
/// spend the decoder silently drops (a set-encoding it doesn't accept, a collateral
/// input it omits) is a spend a later watcher would wrongly read as unspent — so
/// parity with the ledger's own decoder on real bytes is the guard that closes it.
#[test]
fn decode_spends_matches_pallas_inputs_on_the_golden_tx() {
    use pallas_codec::minicbor;
    use pallas_primitives::conway::TransactionBody;

    let body_bytes = tx_body();
    let body: TransactionBody = minicbor::decode(&body_bytes).expect("pallas decodes the body");

    let mut expected = SpendSet::new();
    for inp in body.inputs.iter() {
        expected.insert(OutPoint {
            tx_id: <[u8; 32]>::try_from(inp.transaction_id.as_ref()).unwrap(),
            index: u16::try_from(inp.index).unwrap(),
        });
    }
    if let Some(coll) = body.collateral.as_ref() {
        for inp in coll.iter() {
            expected.insert(OutPoint {
                tx_id: <[u8; 32]>::try_from(inp.transaction_id.as_ref()).unwrap(),
                index: u16::try_from(inp.index).unwrap(),
            });
        }
    }

    assert!(
        !expected.is_empty(),
        "the golden tx spends at least one input"
    );
    assert_eq!(
        decode_spends(&body_bytes).expect("sextant decodes the spends"),
        expected,
        "decode_spends disagrees with pallas on the golden tx's consumed outpoints",
    );
}
