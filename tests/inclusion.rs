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

use ckb_merkle_mountain_range::{MMR, Merge, Result as MmrResult, util::MemStore};
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

// ---- Anti-malleability regression (adversarial review of the MMR verifier) ----
//
// A genuine `MKMapProof<BlockRange>` — its master map and every sub-tree root built
// here with `ckb-merkle-mountain-range`, so the recompute target is a real MMR root —
// commits eight block ranges, one of which legitimately holds a single transaction
// (a 1-leaf sub-tree whose root is that tx's ascii-hex leaf). Appending an unrelated
// transaction `X` as a second leaf into that single-tx sub-proof makes a naive
// recompute silently drop `X` at the peak while membership still reports it present,
// yielding a false `Ok`. The restored ckb recompute guards reject the unconsumed /
// duplicate leaf. This test returns `Ok` (fails) on the pre-guard verifier and passes
// with the guards in place — it is the standing regression for the CRITICAL.

#[derive(Clone, PartialEq, Eq, Debug)]
struct MmrNode(Vec<u8>);

struct MmrMerge;
impl Merge for MmrMerge {
    type Item = MmrNode;
    fn merge(left: &MmrNode, right: &MmrNode) -> MmrResult<MmrNode> {
        Ok(MmrNode(node_merge(&left.0, &right.0)))
    }
}

fn blake2s256(data: &[u8]) -> Vec<u8> {
    use blake2::VarBlake2s;
    use blake2::digest::{Update, VariableOutput};
    let mut h = VarBlake2s::new(32).unwrap();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(|r| out.copy_from_slice(r));
    out.to_vec()
}

fn node_merge(a: &[u8], b: &[u8]) -> Vec<u8> {
    blake2s256(&[a, b].concat())
}

/// mithril's MKTree leaf form of a tx hash: its lowercase-hex ASCII bytes.
fn ascii_hex_leaf(tx: &[u8; 32]) -> Vec<u8> {
    hex::encode(tx).into_bytes()
}

/// An `MkTreeNode` on the wire: `{"hash":[u8,..]}`.
fn wire_node(hash: &[u8]) -> serde_json::Value {
    let bytes: Vec<serde_json::Value> = hash.iter().map(|b| serde_json::json!(b)).collect();
    serde_json::json!({ "hash": bytes })
}

/// HEX(JSON) — the exact form `verify_tx_inclusion` consumes.
fn to_wire(v: &serde_json::Value) -> Vec<u8> {
    hex::encode(serde_json::to_vec(v).unwrap()).into_bytes()
}

/// Build an MMR over `leaf_values`; return `(root, mmr_size, proof_items, leaf_pos)`
/// for a single-leaf inclusion proof of `target_idx`.
fn mmr_single_proof(
    leaf_values: &[Vec<u8>],
    target_idx: usize,
) -> (Vec<u8>, u64, Vec<Vec<u8>>, u64) {
    let store = MemStore::<MmrNode>::default();
    let mut mmr = MMR::<MmrNode, MmrMerge, _>::new(0, &store);
    let mut positions = Vec::new();
    for v in leaf_values {
        positions.push(mmr.push(MmrNode(v.clone())).unwrap());
    }
    let root = mmr.get_root().unwrap().0;
    let proof = mmr.gen_proof(vec![positions[target_idx]]).unwrap();
    let items: Vec<Vec<u8>> = proof.proof_items().iter().map(|n| n.0.clone()).collect();
    (root, proof.mmr_size(), items, positions[target_idx])
}

#[test]
fn a_smuggled_tx_in_a_single_tx_block_range_is_rejected() {
    let ranges: [(u64, u64); 8] = [
        (0, 14),
        (15, 29),
        (30, 44),
        (45, 59),
        (60, 74),
        (75, 89),
        (90, 104),
        (105, 119),
    ];
    let target = 3usize;
    let real_tx = [0x42u8; 32];

    // Range 3 is a single-tx range (1-leaf sub-tree); the others hold three txs each.
    let sub_roots: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            if i == target {
                ascii_hex_leaf(&real_tx)
            } else {
                let leaves: Vec<Vec<u8>> = (0..3)
                    .map(|j| ascii_hex_leaf(&[(i as u8) * 10 + j as u8; 32]))
                    .collect();
                mmr_single_proof(&leaves, 0).0
            }
        })
        .collect();

    // Genuine master map over merge("{start}-{end}", sub_root) — the STM-signed root.
    let master_leaves: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            node_merge(
                format!("{}-{}", ranges[i].0, ranges[i].1).as_bytes(),
                &sub_roots[i],
            )
        })
        .collect();
    let (master_root, master_size, master_items, master_pos) =
        mmr_single_proof(&master_leaves, target);
    let mut certified_root = [0u8; 32];
    certified_root.copy_from_slice(&master_root);

    let master_items_json: Vec<serde_json::Value> =
        master_items.iter().map(|h| wire_node(h)).collect();
    let range_json = serde_json::json!({
        "inner_range": { "start": ranges[target].0, "end": ranges[target].1 }
    });

    let x = [0xEEu8; 32]; // attacker tx, in no range

    // Forged: genuine master path for range 3, but range 3's single-leaf sub-proof
    // carries the real tx AND X at the same leaf position.
    let forged = serde_json::json!({
        "master_proof": {
            "inner_leaves": [ [master_pos, wire_node(&master_leaves[target])] ],
            "inner_proof_size": master_size,
            "inner_proof_items": master_items_json.clone(),
        },
        "sub_proofs": [[ range_json.clone(), {
            "master_proof": {
                "inner_leaves": [
                    [0u64, wire_node(&ascii_hex_leaf(&real_tx))],
                    [0u64, wire_node(&ascii_hex_leaf(&x))]
                ],
                "inner_proof_size": 1u64,
                "inner_proof_items": [],
            },
            "sub_proofs": []
        }]]
    });
    assert_ne!(
        verify_tx_inclusion(&to_wire(&forged), &x, &certified_root),
        Ok(()),
        "a tx smuggled into a single-tx block range must not verify"
    );

    // Control: the genuine single-tx proof still verifies for the real tx.
    let genuine = serde_json::json!({
        "master_proof": {
            "inner_leaves": [ [master_pos, wire_node(&master_leaves[target])] ],
            "inner_proof_size": master_size,
            "inner_proof_items": master_items_json,
        },
        "sub_proofs": [[ range_json, {
            "master_proof": {
                "inner_leaves": [ [0u64, wire_node(&ascii_hex_leaf(&real_tx))] ],
                "inner_proof_size": 1u64,
                "inner_proof_items": [],
            },
            "sub_proofs": []
        }]]
    });
    assert_eq!(
        verify_tx_inclusion(&to_wire(&genuine), &real_tx, &certified_root),
        Ok(()),
        "the genuine single-tx block range must still verify"
    );
}

/// A distinct-position (non-duplicate) smuggle whose sub-proof still recomputes to the
/// genuine single-tx sub-root by returning early at the peak with a residual leaf left
/// in the queue. The dedup guard cannot catch it (the two leaves sit at different
/// positions); the queue-empty-at-peak guard (and, independently, the internal-node
/// position guard, since the real leaf is declared at internal pos 2) closes it. This
/// pins the queue-empty guard as load-bearing: dedup alone does not close this family.
#[test]
fn a_residual_leaf_at_a_peak_return_is_rejected() {
    let ranges: [(u64, u64); 8] = [
        (0, 14),
        (15, 29),
        (30, 44),
        (45, 59),
        (60, 74),
        (75, 89),
        (90, 104),
        (105, 119),
    ];
    let target = 3usize;
    let real_tx = [0x42u8; 32];

    let sub_roots: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            if i == target {
                ascii_hex_leaf(&real_tx)
            } else {
                let leaves: Vec<Vec<u8>> = (0..3)
                    .map(|j| ascii_hex_leaf(&[(i as u8) * 10 + j as u8; 32]))
                    .collect();
                mmr_single_proof(&leaves, 0).0
            }
        })
        .collect();

    let master_leaves: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            node_merge(
                format!("{}-{}", ranges[i].0, ranges[i].1).as_bytes(),
                &sub_roots[i],
            )
        })
        .collect();
    let (master_root, master_size, master_items, master_pos) =
        mmr_single_proof(&master_leaves, target);
    let mut certified_root = [0u8; 32];
    certified_root.copy_from_slice(&master_root);
    let master_items_json: Vec<serde_json::Value> =
        master_items.iter().map(|h| wire_node(h)).collect();

    let x = [0xEEu8; 32];

    // Range 3's sub-proof: inner_proof_size 3, real tx declared at (internal) pos 2, X at
    // pos 0, one bogus sibling item. Pre-fix, the recompute pops X, folds toward the peak,
    // returns the real leaf at the peak while X's partial fold is still queued — dropped.
    let sub = serde_json::json!({
        "master_proof": {
            "inner_leaves": [
                [2u64, wire_node(&ascii_hex_leaf(&real_tx))],
                [0u64, wire_node(&ascii_hex_leaf(&x))]
            ],
            "inner_proof_size": 3u64,
            "inner_proof_items": [ wire_node(&[0u8; 32]) ],
        },
        "sub_proofs": []
    });
    let forged = serde_json::json!({
        "master_proof": {
            "inner_leaves": [ [master_pos, wire_node(&master_leaves[target])] ],
            "inner_proof_size": master_size,
            "inner_proof_items": master_items_json,
        },
        "sub_proofs": [[
            { "inner_range": { "start": ranges[target].0, "end": ranges[target].1 } },
            sub
        ]]
    });
    assert_ne!(
        verify_tx_inclusion(&to_wire(&forged), &x, &certified_root),
        Ok(()),
        "a residual queued leaf at a peak return must not smuggle a tx"
    );
}
