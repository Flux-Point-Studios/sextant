//! Proof-based Cardano-transaction inclusion verification.
//!
//! Reproduces mithril's `MKMapProof<BlockRange>` verify on Sextant's own path: a
//! pure BLAKE2s-256 Merkle-Mountain-Range recompute over the aggregator's
//! `GET /proof/cardano-transaction` payload. No blst, no mithril-stm — the
//! verifier lives in the default (wasm-safe) graph so a wasm consumer can check
//! inclusion, and the blst-bearing certificate authentication (`crate::mithril`)
//! passes the certified root *into* it as an input.
//!
//! ## What a genuine `Ok` proves — and what it does not
//! `Ok` means: transaction `H` is a member of the Mithril-certified transaction
//! set whose Merkle root is `certified_root`. When `certified_root` comes off a
//! [`crate::mithril::verify_chain_anchored`]-authenticated certificate, that
//! membership is bound back to the network genesis key. It does **not** prove `H`
//! is unspent — Cardano commits to no UTxO-set accumulator; the certified set is a
//! monotone "created" predicate that trails tip by ~100 blocks. Unspent is the
//! ledger's to decide at submission; part 3's `verify_utxo_read` carries the
//! honesty in its return type.
//!
//! ## The provider supplies bytes, never a verdict
//! The proof's stated `inner_root` fields are deliberately **not** deserialized
//! and never trusted. Every Merkle root is recomputed from the leaves and the
//! sibling path, and the master recompute is asserted equal to the externally
//! supplied `certified_root`. A mutated path node, a substituted sub-tree, or the
//! wrong root recomputes to a value that is not `certified_root` and is rejected.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use serde::Deserialize;

use crate::hash::blake2s256;

/// Cap on the provider-supplied proof bytes (hex length). The real preprod proof
/// is ~6 KiB; this bounds `serde_json`'s allocation on a hostile payload well
/// above any genuine multi-transaction batch proof.
const MAX_PROOF_HEX: usize = 8 * 1024 * 1024;

/// Cap on a Merkle-Mountain-Range node count. The real proof's master range is
/// ~6.3·10⁵ nodes; this bounds the peak walk and keeps every derived MMR position
/// far below `u64` overflow, on untrusted `inner_proof_size` bytes.
const MAX_MMR_SIZE: u64 = 1 << 40;

/// Why a Cardano-transaction inclusion proof did not verify. Every variant is an
/// ordinary recoverable outcome on untrusted aggregator bytes — never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InclusionError {
    /// The proof bytes are not hex, exceed the size cap, are not JSON, or encode a
    /// structurally corrupt Merkle path (one that does not reduce to a peak).
    MalformedProof,
    /// The transaction hash is not a leaf of the proof.
    NotIncluded,
    /// The proof's recomputed Merkle root does not equal the certified root — a
    /// mutated path node, a substituted sub-tree, or the wrong certified root. The
    /// proof does not attest inclusion in the certified transaction set.
    RootMismatch,
}

impl core::fmt::Display for InclusionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InclusionError::MalformedProof => write!(f, "transaction inclusion proof is malformed"),
            InclusionError::NotIncluded => {
                write!(f, "transaction is not a leaf of the inclusion proof")
            }
            InclusionError::RootMismatch => write!(
                f,
                "recomputed Merkle root does not equal the certified transaction root"
            ),
        }
    }
}

impl core::error::Error for InclusionError {}

// ---- Wire structs. Untrusted input; `inner_root` is deliberately absent so it is
// never deserialized and never trusted — the root is always recomputed. serde
// ignores it (and any other extra field) by default. ----

#[derive(Deserialize)]
struct MkTreeNode {
    hash: Vec<u8>,
}

#[derive(Deserialize)]
struct MkProof {
    inner_leaves: Vec<(u64, MkTreeNode)>,
    inner_proof_size: u64,
    inner_proof_items: Vec<MkTreeNode>,
}

#[derive(Deserialize)]
struct BlockRangeBounds {
    start: u64,
    end: u64,
}

#[derive(Deserialize)]
struct BlockRange {
    inner_range: BlockRangeBounds,
}

#[derive(Deserialize)]
struct MkMapProof {
    master_proof: MkProof,
    sub_proofs: Vec<(BlockRange, MkMapProof)>,
}

/// The `MergeMKTreeNode` node merge: `BLAKE2s-256(left ‖ right)`.
fn merge(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(left.len() + right.len());
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    blake2s256(&buf)
}

// ---- Merkle-Mountain-Range recompute, ported verbatim from
// `ckb-merkle-mountain-range` (the crate mithril's `MKProof` rides), with checked
// arithmetic and a size cap so untrusted `inner_proof_size` / positions can never
// overflow, underflow, or diverge. ----

fn all_ones(num: u64) -> bool {
    num != 0 && num.count_zeros() == num.leading_zeros()
}

fn jump_left(pos: u64) -> u64 {
    let bit_length = 64 - pos.leading_zeros();
    let most_significant_bits = 1u64 << (bit_length - 1);
    pos - (most_significant_bits - 1)
}

fn pos_height_in_tree(mut pos: u64) -> u32 {
    pos += 1;
    while !all_ones(pos) {
        pos = jump_left(pos);
    }
    (64 - pos.leading_zeros()) - 1
}

fn sibling_offset(height: u32) -> u64 {
    (2u64 << height) - 1
}

fn parent_offset(height: u32) -> u64 {
    2u64 << height
}

fn get_peak_pos_by_height(height: u32) -> u64 {
    (1u64 << (height + 1)) - 2
}

fn left_peak_height_pos(mmr_size: u64) -> (u32, u64) {
    let mut height = 1u32;
    let mut prev_pos = 0u64;
    let mut pos = get_peak_pos_by_height(height);
    while pos < mmr_size {
        height += 1;
        prev_pos = pos;
        pos = get_peak_pos_by_height(height);
    }
    (height - 1, prev_pos)
}

fn get_right_peak(mut height: u32, mut pos: u64, mmr_size: u64) -> Option<(u32, u64)> {
    pos += sibling_offset(height);
    while pos > mmr_size - 1 {
        if height == 0 {
            return None;
        }
        pos = pos.saturating_sub(parent_offset(height - 1));
        height -= 1;
    }
    Some((height, pos))
}

fn get_peaks(mmr_size: u64) -> Vec<u64> {
    let mut positions = Vec::new();
    let (mut height, mut pos) = left_peak_height_pos(mmr_size);
    positions.push(pos);
    while height > 0 {
        match get_right_peak(height, pos, mmr_size) {
            Some((h, p)) => {
                height = h;
                pos = p;
                positions.push(pos);
            }
            None => break,
        }
    }
    positions
}

fn calculate_peak_root(
    leaves: Vec<(u64, Vec<u8>)>,
    peak_pos: u64,
    proof_items: &mut core::slice::Iter<'_, Vec<u8>>,
) -> Result<Vec<u8>, InclusionError> {
    let mut queue: VecDeque<(u64, Vec<u8>, u32)> = leaves
        .into_iter()
        .map(|(pos, item)| (pos, item, 0u32))
        .collect();
    while let Some((pos, item, height)) = queue.pop_front() {
        if pos == peak_pos {
            if queue.is_empty() {
                return Ok(item);
            }
            return Err(InclusionError::MalformedProof);
        }
        let next_height = pos_height_in_tree(pos + 1);
        let (sib_pos, parent_pos) = if next_height > height {
            (
                pos.checked_sub(sibling_offset(height))
                    .ok_or(InclusionError::MalformedProof)?,
                pos + 1,
            )
        } else {
            (pos + sibling_offset(height), pos + parent_offset(height))
        };
        let sibling_item = if queue.front().map(|(p, _, _)| *p) == Some(sib_pos) {
            queue.pop_front().map(|(_, item, _)| item).unwrap()
        } else {
            proof_items
                .next()
                .ok_or(InclusionError::MalformedProof)?
                .clone()
        };
        let parent_item = if next_height > height {
            merge(&sibling_item, &item)
        } else {
            merge(&item, &sibling_item)
        };
        if parent_pos > peak_pos {
            return Err(InclusionError::MalformedProof);
        }
        queue.push_back((parent_pos, parent_item.to_vec(), height + 1));
    }
    Err(InclusionError::MalformedProof)
}

fn calculate_peaks_hashes(
    mut leaves: Vec<(u64, Vec<u8>)>,
    mmr_size: u64,
    proof_items: &mut core::slice::Iter<'_, Vec<u8>>,
) -> Result<Vec<Vec<u8>>, InclusionError> {
    if leaves.iter().any(|(pos, _)| pos_height_in_tree(*pos) > 0) {
        return Err(InclusionError::MalformedProof);
    }
    if mmr_size == 1 && leaves.len() == 1 && leaves[0].0 == 0 {
        return Ok(vec![leaves.remove(0).1]);
    }
    leaves.sort_by_key(|(pos, _)| *pos);
    if leaves.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(InclusionError::MalformedProof);
    }
    let peaks = get_peaks(mmr_size);
    let mut peaks_hashes: Vec<Vec<u8>> = Vec::with_capacity(peaks.len() + 1);
    let mut leaves = leaves.into_iter().peekable();
    for peak_pos in peaks {
        let mut peak_leaves = Vec::new();
        while let Some((pos, _)) = leaves.peek() {
            if *pos <= peak_pos {
                peak_leaves.push(leaves.next().unwrap());
            } else {
                break;
            }
        }
        let peak_root = if peak_leaves.len() == 1 && peak_leaves[0].0 == peak_pos {
            peak_leaves.pop().unwrap().1
        } else if peak_leaves.is_empty() {
            match proof_items.next() {
                Some(root) => root.clone(),
                None => break,
            }
        } else {
            calculate_peak_root(peak_leaves, peak_pos, proof_items)?
        };
        peaks_hashes.push(peak_root);
    }
    if leaves.next().is_some() {
        return Err(InclusionError::MalformedProof);
    }
    if let Some(rhs) = proof_items.next() {
        peaks_hashes.push(rhs.clone());
    }
    if proof_items.next().is_some() {
        return Err(InclusionError::MalformedProof);
    }
    Ok(peaks_hashes)
}

fn bagging_peaks_hashes(mut peaks_hashes: Vec<Vec<u8>>) -> Result<Vec<u8>, InclusionError> {
    while peaks_hashes.len() > 1 {
        let right = peaks_hashes.pop().unwrap();
        let left = peaks_hashes.pop().unwrap();
        peaks_hashes.push(merge(&right, &left).to_vec());
    }
    peaks_hashes.pop().ok_or(InclusionError::MalformedProof)
}

/// Recompute an MMR root from `(leaf-position, leaf)` pairs, the total node count,
/// and the sibling-path proof items — never trusting any stated root.
fn calculate_root(
    leaves: Vec<(u64, Vec<u8>)>,
    mmr_size: u64,
    proof_items: &[Vec<u8>],
) -> Result<Vec<u8>, InclusionError> {
    if mmr_size == 0 || mmr_size > MAX_MMR_SIZE {
        return Err(InclusionError::MalformedProof);
    }
    if leaves.iter().any(|(pos, _)| *pos >= mmr_size) {
        return Err(InclusionError::MalformedProof);
    }
    let mut items = proof_items.iter();
    let peaks = calculate_peaks_hashes(leaves, mmr_size, &mut items)?;
    bagging_peaks_hashes(peaks)
}

/// The MMR root of a single `MKProof`.
fn mkproof_root(proof: &MkProof) -> Result<Vec<u8>, InclusionError> {
    let leaves: Vec<(u64, Vec<u8>)> = proof
        .inner_leaves
        .iter()
        .map(|(pos, node)| (*pos, node.hash.clone()))
        .collect();
    let items: Vec<Vec<u8>> = proof
        .inner_proof_items
        .iter()
        .map(|n| n.hash.clone())
        .collect();
    calculate_root(leaves, proof.inner_proof_size, &items)
}

/// The master-tree leaf a block range contributes: `merge(MKTreeNode::from(range),
/// sub_tree_root)`, where `MKTreeNode::from(range)` is the ASCII of `"{start}-{end}"`.
fn range_leaf(range: &BlockRange, sub_root: &[u8]) -> [u8; 32] {
    let key = format!("{}-{}", range.inner_range.start, range.inner_range.end);
    merge(key.as_bytes(), sub_root)
}

/// Recompute this map node's master root, requiring every sub-proof's recomputed
/// root to be bound into the master tree as its `merge(range, sub_root)` leaf. A
/// forged or mutated sub-tree yields a root whose master leaf the master proof does
/// not carry — so the bind fails and the transaction is not attested.
fn verify_binds(node: &MkMapProof) -> Result<Vec<u8>, InclusionError> {
    for (range, sub) in &node.sub_proofs {
        let sub_root = verify_binds(sub)?;
        let expected = range_leaf(range, &sub_root);
        let bound = node
            .master_proof
            .inner_leaves
            .iter()
            .any(|(_, leaf)| leaf.hash == expected);
        if !bound {
            return Err(InclusionError::RootMismatch);
        }
    }
    mkproof_root(&node.master_proof)
}

/// Every leaf value carried anywhere in the proof tree.
fn collect_leaves<'a>(node: &'a MkMapProof, out: &mut Vec<&'a [u8]>) {
    for (_, leaf) in &node.master_proof.inner_leaves {
        out.push(leaf.hash.as_slice());
    }
    for (_, sub) in &node.sub_proofs {
        collect_leaves(sub, out);
    }
}

fn hex_lower_ascii(bytes: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn decode_hex(s: &[u8]) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks_exact(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Some(out)
}

/// Verify that transaction `tx_hash` is a member of the Mithril-certified
/// transaction set whose Merkle root is `certified_root`, given the aggregator's
/// HEX(JSON) `MKMapProof<BlockRange>` proof bytes.
///
/// `proof_hex` is the aggregator `proof` field verbatim (hex of the JSON proof).
/// `tx_hash` is the 32-byte Cardano transaction hash — it appears in the proof as
/// its lowercase-hex ASCII (mithril's MKTree leaf form), never the raw bytes.
/// `certified_root` is the transaction Merkle root, which a caller must obtain from
/// a [`crate::mithril::verify_chain_anchored`]-authenticated certificate for the
/// membership to be genesis-anchored.
///
/// The master Merkle root is recomputed from the proof (never the proof's stated
/// `inner_root`) and asserted equal to `certified_root`.
pub fn verify_tx_inclusion(
    proof_hex: &[u8],
    tx_hash: &[u8; 32],
    certified_root: &[u8; 32],
) -> Result<(), InclusionError> {
    if proof_hex.len() > MAX_PROOF_HEX {
        return Err(InclusionError::MalformedProof);
    }
    let json = decode_hex(proof_hex).ok_or(InclusionError::MalformedProof)?;
    let proof: MkMapProof =
        serde_json::from_slice(&json).map_err(|_| InclusionError::MalformedProof)?;

    // Membership: the transaction's ASCII-hex leaf must be present in the proof.
    let tx_leaf = hex_lower_ascii(tx_hash);
    let mut leaves = Vec::new();
    collect_leaves(&proof, &mut leaves);
    if !leaves.contains(&tx_leaf.as_slice()) {
        return Err(InclusionError::NotIncluded);
    }

    // Binding + recompute: the whole proof reduces to the certified root.
    let root = verify_binds(&proof)?;
    if root.as_slice() != certified_root.as_slice() {
        return Err(InclusionError::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ckb_merkle_mountain_range::{MMR, Merge, Result as MmrResult, util::MemStore};

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Node(Vec<u8>);

    struct MergeNode;
    impl Merge for MergeNode {
        type Item = Node;
        fn merge(left: &Node, right: &Node) -> MmrResult<Node> {
            Ok(Node(super::merge(&left.0, &right.0).to_vec()))
        }
    }

    /// Sextant's own recompute agrees with the independent `ckb-merkle-mountain-
    /// range` construction across leaf counts that exercise multiple peaks and
    /// multi-leaf peaks — shapes the single real 1-leaf vector does not reach.
    #[test]
    fn calculate_root_matches_ckb_across_shapes() {
        for count in [1u64, 2, 3, 5, 7, 8, 11, 16, 100] {
            let store = MemStore::<Node>::default();
            let mut mmr = MMR::<Node, MergeNode, _>::new(0, &store);
            let mut positions = Vec::new();
            for i in 0..count {
                let leaf = Node(super::merge(b"leaf", &i.to_be_bytes()).to_vec());
                positions.push(mmr.push(leaf).unwrap());
            }
            let ckb_root = mmr.get_root().unwrap();

            // Prove every leaf; each proof must recompute the same root on our path.
            for (i, &pos) in positions.iter().enumerate() {
                let proof = mmr.gen_proof(vec![pos]).unwrap();
                let items: Vec<Vec<u8>> = proof.proof_items().iter().map(|n| n.0.clone()).collect();
                let leaf = Node(super::merge(b"leaf", &(i as u64).to_be_bytes()).to_vec());
                let ours =
                    super::calculate_root(vec![(pos, leaf.0.clone())], proof.mmr_size(), &items)
                        .unwrap();
                assert_eq!(ours, ckb_root.0, "count={count} leaf={i}");
            }
        }
    }

    /// A ckb proof whose sibling path is mutated must not recompute the true root.
    #[test]
    fn a_mutated_ckb_proof_item_diverges_from_the_true_root() {
        let store = MemStore::<Node>::default();
        let mut mmr = MMR::<Node, MergeNode, _>::new(0, &store);
        let positions: Vec<u64> = (0..7u64)
            .map(|i| {
                mmr.push(Node(super::merge(b"leaf", &i.to_be_bytes()).to_vec()))
                    .unwrap()
            })
            .collect();
        let ckb_root = mmr.get_root().unwrap();
        let proof = mmr.gen_proof(vec![positions[0]]).unwrap();
        let mut items: Vec<Vec<u8>> = proof.proof_items().iter().map(|n| n.0.clone()).collect();
        items[0][0] ^= 1;
        let leaf = Node(super::merge(b"leaf", &0u64.to_be_bytes()).to_vec());
        let ours =
            super::calculate_root(vec![(positions[0], leaf.0)], proof.mmr_size(), &items).unwrap();
        assert_ne!(ours, ckb_root.0);
    }
}
