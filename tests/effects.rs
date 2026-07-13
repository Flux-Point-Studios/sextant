//! Tier-2 T2 differential proof: Sextant's own-path block→UTxO-effects extraction is
//! byte-identical to pallas's independent `consumes`/`produces` for EVERY transaction — valid
//! and phase-2-invalid — across the committed vectors, the same discipline the MMR, VRF, KES,
//! and Ed25519 paths hold against their independent oracles. The vectors include a real mainnet
//! phase-2 failure (`invalid-mainnet-13591743.block`, tx 7: collateral consumed, collateral
//! return produced) and a valid tx whose input and collateral sets overlap
//! (`mainnet-collat-overlap-9668317.block`) — the two shapes a naive decoder mishandles.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use pallas_traverse::MultiEraBlock;
use sextant::effects::extract_block_effects;
use sextant::utxo::OutPoint;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

/// Every committed `*.block` vector (preprod run + the indefinite-tx_bodies block), as raw CBOR.
fn block_vectors() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if path.extension().and_then(|e| e.to_str()) != Some("block") {
            continue;
        }
        out.push((
            name.to_string(),
            unhex(&fs::read_to_string(&path).expect("read vector")),
        ));
    }
    assert!(!out.is_empty(), "expected committed *.block vectors");
    out
}

fn h32(h: &pallas_crypto::hash::Hash<32>) -> [u8; 32] {
    <[u8; 32]>::try_from(h.as_ref()).expect("32-byte hash")
}

/// Pallas's independent view of a block's per-transaction effects, valid transactions only.
fn pallas_effects(block: &[u8]) -> Vec<(BTreeSet<OutPoint>, BTreeSet<OutPoint>)> {
    let b = MultiEraBlock::decode(block).expect("pallas decodes the block");
    b.txs()
        .iter()
        .map(|tx| {
            let spent = tx
                .consumes()
                .iter()
                .map(|i| OutPoint {
                    tx_id: h32(i.hash()),
                    index: i.index() as u16,
                })
                .collect();
            let tx_id = h32(&tx.hash());
            let created = tx
                .produces()
                .iter()
                .map(|(idx, _)| OutPoint {
                    tx_id,
                    index: *idx as u16,
                })
                .collect();
            (spent, created)
        })
        .collect()
}

fn has_invalid(block: &[u8]) -> bool {
    MultiEraBlock::decode(block)
        .expect("pallas decode")
        .txs()
        .iter()
        .any(|tx| !tx.is_valid())
}

#[test]
fn extraction_matches_pallas_consumes_and_produces_on_every_committed_block() {
    let mut checked_txs = 0usize;
    let mut checked_invalid = false;
    for (name, block) in block_vectors() {
        checked_invalid |= has_invalid(&block);
        let ours = extract_block_effects(&block)
            .unwrap_or_else(|e| panic!("{name}: extraction failed: {e:?}"));
        let theirs = pallas_effects(&block);
        assert_eq!(
            ours.txs.len(),
            theirs.len(),
            "{name}: transaction count disagrees with pallas",
        );
        for (i, (tx, (p_spent, p_created))) in ours.txs.iter().zip(theirs.iter()).enumerate() {
            let our_spent: BTreeSet<OutPoint> = tx.spent.iter().copied().collect();
            let our_created: BTreeSet<OutPoint> = tx.created.iter().copied().collect();
            assert_eq!(
                &our_spent, p_spent,
                "{name} tx {i}: spent set differs from pallas"
            );
            assert_eq!(
                &our_created, p_created,
                "{name} tx {i}: created set differs from pallas",
            );
            checked_txs += 1;
        }
    }
    assert!(
        checked_txs > 0,
        "the committed vectors must contain at least one transaction to differential-test",
    );
    assert!(
        checked_invalid,
        "the vectors must include a phase-2-invalid block so the collateral delta is proven, \
         not just the valid path",
    );
}

#[test]
fn block_coordinates_match_pallas() {
    for (name, block) in block_vectors() {
        let ours = extract_block_effects(&block).expect("extract");
        let b = MultiEraBlock::decode(&block).expect("pallas decode");
        assert_eq!(ours.number, b.number(), "{name}: block number");
        assert_eq!(ours.hash, h32(&b.hash()), "{name}: block hash");
        let expected_prev = b
            .header()
            .previous_hash()
            .map(|h| h32(&h))
            .unwrap_or([0u8; 32]);
        assert_eq!(ours.prev_hash, expected_prev, "{name}: prev_hash");
    }
}
