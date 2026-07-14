//! The self-verified UTxO-set engine (BEYOND-DoD Tier-2, slice T1).
//!
//! Tier-1's [`crate::follow::WindowFollower`] answers "is this outpoint unspent?" only for a
//! coin whose *creation* it can observe inside a verified window — unbounded for an old coin.
//! Tier-2 re-bases that claim: hold the whole UTxO set, self-computed by applying verified
//! blocks, so membership answers "is this outpoint unspent at the applied tip?" for ANY
//! outpoint of ANY age. Composed with the shipped no-spend window, the flagship claim becomes
//! *membership at a certified snapshot S + no spend observed through a verified tip* — with no
//! single trusted party (the snapshot is the Mithril-quorum-certified immutable chain, replayed
//! on our own path).
//!
//! This slice is the sans-io core: a [`UtxoSet`] handed one block's *effects* at a time
//! (the outpoints each transaction consumes and creates — extracted from a verified block by a
//! later slice, never parsed here). It maintains the set with a bounded rollback history and
//! answers membership. Its discipline mirrors the WindowFollower's:
//!
//! * **Contiguity** — a block must extend the tip by `prev_hash`/number+1, or it is refused.
//! * **Completeness is load-bearing** — the set is complete from its base, so a transaction
//!   spending an outpoint NOT in the set is a malformed/out-of-order block, not a silent skip.
//! * **Fail-closed and ATOMIC** — a block's mutations run in one store transaction; on any
//!   refusal (a logic error or a persistent-store I/O failure) the transaction is aborted and
//!   the store is exactly as it was, and the tip/undo advance only after it commits. There is no
//!   hand-rolled, itself-fallible revert that could leave a torn set.
//! * **Eviction-as-finalization** — only the last `depth` blocks are reversible (the Praos
//!   stability window, k = 2160); older application is finalized, matching what a rollback can
//!   reach on a live chain.
//!
//! Rollback is exact: each applied block records its ordered insert/remove operations, and a
//! rollback replays them in reverse inside one atomic transaction — so an outpoint created and
//! then spent *within one block* (in-block transaction chaining) reverses to its true pre-block
//! absence, and a store failure mid-rollback leaves the set unchanged rather than wedged.

//! The membership backing is abstracted behind [`UtxoStore`] (default in-memory [`MemStore`]):
//! the wasm/mobile core carries only the set-in-RAM path, while a native host swaps in a
//! persistent store (redb) via [`UtxoSet::with_store`] without any file I/O entering this core.

use std::collections::{BTreeSet, VecDeque};

use crate::utxo::{OutPoint, SpendStatus};

/// The trust-class ladder enum lives with the [`SpendStatus`] ladder it qualifies (`crate::utxo`);
/// re-exported here because it names the Tier-2 [`SnapshotAnchor`] this engine produces.
pub use crate::utxo::AnchorBasis;

/// One transaction's effect on the set: the outpoints it consumes (its inputs) and the ones it
/// creates (its outputs, as `this_tx_id # output_index`). A later slice extracts these from a
/// verified block on Sextant's own path; the engine applies them, it does not parse.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxEffect {
    /// Outpoints this transaction spends.
    pub spent: Vec<OutPoint>,
    /// Outpoints this transaction creates.
    pub created: Vec<OutPoint>,
}

/// One block's ordered per-transaction effects and its chain position. `txs` are in on-chain
/// order, so in-block chaining (a later transaction spending an earlier one's output in the
/// same block) applies correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEffects {
    /// The block number (height).
    pub number: u64,
    /// The block's own hash — the tip identifier after it applies.
    pub hash: [u8; 32],
    /// The parent block's hash — the contiguity link.
    pub prev_hash: [u8; 32],
    /// Per-transaction effects, in on-chain order.
    pub txs: Vec<TxEffect>,
}

/// The chain position the set has been applied through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetTip {
    /// Block number the set is current as of.
    pub number: u64,
    /// Block hash the set is current as of.
    pub hash: [u8; 32],
}

/// A Tier-2 snapshot anchor: the verified tip S the UTxO set is based at, together with the
/// [`AnchorBasis`] its state rests on. The T3 bootstrap produces one; the composed Tier-2 verdict
/// surfaces it, so a consumer always weighs the anchor's trust class alongside the membership
/// answer — a stake-quorum recomputation is not the same as a single-key snapshot, and the type
/// makes the difference impossible to drop. [`AnchorBasis`] is the ladder's trust-class enum
/// (re-exported below), distinct from [`crate::utxo::SpendStatus`], which grades what is proven
/// ABOUT an outpoint; this grades the ANCHOR the whole set is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotAnchor {
    /// The verified tip the snapshot's UTxO set is current as of.
    pub tip: SetTip,
    /// The trust class the snapshot's state was established under.
    pub basis: AnchorBasis,
}

/// Why applying a block failed. Every arm leaves the set UNCHANGED (a partial application is
/// reverted before returning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// The block does not extend the current tip (`prev_hash` or number mismatch).
    NotContiguous {
        /// The tip hash the block should have named as its parent.
        expected_prev: [u8; 32],
        /// The parent hash the block actually named.
        got_prev: [u8; 32],
    },
    /// A transaction spends an outpoint absent from the complete set — a malformed or
    /// out-of-order block, never a valid on-chain one.
    SpendOfUnknownOutput(OutPoint),
    /// A transaction creates an outpoint already in the set — impossible on a valid chain
    /// (a fresh transaction id is unique), so a red flag, not a silent overwrite.
    DuplicateOutput(OutPoint),
    /// The backing store failed (persistent-store I/O). The block is not applied.
    Store(StoreError),
}

/// Why a rollback failed. The set is left UNCHANGED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackError {
    /// The target point is not reachable within the retained (`depth`-deep) undo history — it
    /// is finalized (older than the rollback window) or was never on the applied chain.
    Unreachable,
    /// The backing store failed (persistent-store I/O) while reversing a block.
    Store(StoreError),
}

/// A storage-layer failure — disk I/O in a persistent store, and nothing else. The in-memory
/// [`MemStore`] never produces one; a redb/sqlite adapter maps its I/O errors here so a read or
/// write failure fails the verdict CLOSED rather than answering wrongly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

/// The membership backing of a [`UtxoSet`] — the ONE seam a persistent store plugs into, so the
/// sans-io engine and the wasm-safe core stay file-free (redb/sqlite live in a native host
/// adapter that implements this, never in the trust core). Reads are direct; ALL mutation goes
/// through an ATOMIC [`UtxoTxn`], so a block applies all-or-nothing: on any error the engine
/// drops the transaction (abort) and the store is exactly as it was — no hand-rolled, itself-
/// fallible revert that could leave a torn set.
pub trait UtxoStore {
    /// A write transaction over this store — the atomic unit a block's mutations apply within.
    type Txn<'s>: UtxoTxn
    where
        Self: 's;
    /// Begin a write transaction. Dropping it without [`UtxoTxn::commit`] aborts, restoring the
    /// pre-transaction state (a rollback the backend guarantees — redb drops its write txn).
    fn transaction(&mut self) -> Result<Self::Txn<'_>, StoreError>;
    /// Whether `o` is in the committed set.
    fn contains(&self, o: &OutPoint) -> Result<bool, StoreError>;
    /// The number of outpoints in the committed set.
    fn len(&self) -> Result<usize, StoreError>;
    /// Whether the committed set holds no outpoints.
    fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }
}

/// An in-flight write transaction over a [`UtxoStore`]. `insert`/`remove` are read-your-writes
/// WITHIN the transaction (an output created earlier in a block is visible to a later spend);
/// `commit` durably persists ALL of them atomically, and dropping without commit aborts.
pub trait UtxoTxn {
    /// Insert `o`; `Ok(true)` iff it was newly added (was absent).
    fn insert(&mut self, o: &OutPoint) -> Result<bool, StoreError>;
    /// Remove `o`; `Ok(true)` iff it was present.
    fn remove(&mut self, o: &OutPoint) -> Result<bool, StoreError>;
    /// Durably persist every mutation in this transaction, atomically.
    fn commit(self) -> Result<(), StoreError>;
}

/// The default in-memory store: a `BTreeSet` (wasm-safe, deterministic, like the follower's
/// `BTreeMap`). Infallible — every method returns `Ok`. The wasm/mobile footprint uses this and
/// never carries an on-disk full set.
#[derive(Debug, Default, Clone)]
pub struct MemStore {
    set: BTreeSet<OutPoint>,
}

impl MemStore {
    /// An empty in-memory store.
    pub fn new() -> Self {
        MemStore::default()
    }
}

impl FromIterator<OutPoint> for MemStore {
    fn from_iter<I: IntoIterator<Item = OutPoint>>(iter: I) -> Self {
        MemStore {
            set: iter.into_iter().collect(),
        }
    }
}

impl UtxoStore for MemStore {
    type Txn<'s> = MemTxn<'s>;
    fn transaction(&mut self) -> Result<MemTxn<'_>, StoreError> {
        Ok(MemTxn {
            set: &mut self.set,
            undo: Vec::new(),
            committed: false,
        })
    }
    fn contains(&self, o: &OutPoint) -> Result<bool, StoreError> {
        Ok(self.set.contains(o))
    }
    fn len(&self) -> Result<usize, StoreError> {
        Ok(self.set.len())
    }
}

/// An in-memory write transaction: mutations apply to the set immediately (so reads within the
/// transaction see them) and are recorded; `commit` keeps them, while a drop without commit
/// reverses them exactly — an infallible, atomic abort.
pub struct MemTxn<'s> {
    set: &'s mut BTreeSet<OutPoint>,
    undo: Vec<Op>,
    committed: bool,
}

impl UtxoTxn for MemTxn<'_> {
    fn insert(&mut self, o: &OutPoint) -> Result<bool, StoreError> {
        let newly = self.set.insert(*o);
        if newly {
            self.undo.push(Op::Inserted(*o));
        }
        Ok(newly)
    }
    fn remove(&mut self, o: &OutPoint) -> Result<bool, StoreError> {
        let present = self.set.remove(o);
        if present {
            self.undo.push(Op::Removed(*o));
        }
        Ok(present)
    }
    fn commit(mut self) -> Result<(), StoreError> {
        self.committed = true;
        Ok(())
    }
}

impl Drop for MemTxn<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for op in self.undo.iter().rev() {
            match op {
                Op::Inserted(x) => {
                    self.set.remove(x);
                }
                Op::Removed(x) => {
                    self.set.insert(*x);
                }
            }
        }
    }
}

/// One applied block's exact forward operations, retained in the engine's undo log so a later
/// chain rollback can reverse them (each reversal is itself run inside one atomic transaction).
#[derive(Clone, Copy)]
enum Op {
    Inserted(OutPoint),
    Removed(OutPoint),
}

struct Undo {
    tip: SetTip,
    prev_hash: [u8; 32],
    ops: Vec<Op>,
}

/// A self-verified UTxO set: the outpoints currently unspent, maintained by applying verified
/// blocks with a bounded rollback history. Sans-io — it is handed a block's effects, never a
/// socket or a clock. Generic over its [`UtxoStore`] backing; defaults to the in-memory
/// [`MemStore`], so `UtxoSet::new(depth)` and the wasm build carry no persistent-store deps,
/// while a native host swaps in a redb/sqlite store via [`UtxoSet::with_store`].
pub struct UtxoSet<S: UtxoStore = MemStore> {
    store: S,
    tip: Option<SetTip>,
    undo: VecDeque<Undo>,
    depth: usize,
}

impl UtxoSet<MemStore> {
    /// An empty in-memory set at no tip. `depth` is the retained rollback window in blocks; a
    /// live follower uses the Praos stability window (k = 2160).
    pub fn new(depth: usize) -> Self {
        UtxoSet::with_store(MemStore::new(), None, depth)
    }

    /// An in-memory set seeded from a bootstrapped snapshot: the outpoints unspent as of `tip`.
    /// The snapshot is the finalized base (no rollback history); the first `apply` must name
    /// `tip.hash` as its parent.
    pub fn from_snapshot(
        tip: SetTip,
        unspent: impl IntoIterator<Item = OutPoint>,
        depth: usize,
    ) -> Self {
        UtxoSet::with_store(unspent.into_iter().collect(), Some(tip), depth)
    }
}

impl<S: UtxoStore> UtxoSet<S> {
    /// Build a set over an arbitrary store — the seam a native host uses to back the set with a
    /// persistent store already seeded to `tip` (or `None` for an empty from-genesis start).
    pub fn with_store(store: S, tip: Option<SetTip>, depth: usize) -> Self {
        UtxoSet {
            store,
            tip,
            undo: VecDeque::new(),
            depth,
        }
    }

    /// The chain position the set is current as of (`None` before the first apply).
    pub fn tip(&self) -> Option<SetTip> {
        self.tip
    }

    /// The number of unspent outpoints held.
    pub fn len(&self) -> Result<usize, StoreError> {
        self.store.len()
    }

    /// Whether the set holds no unspent outpoints.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.store.len()? == 0)
    }

    /// Whether `o` is unspent at the applied tip — the Tier-2 membership answer.
    pub fn is_unspent(&self, o: &OutPoint) -> Result<bool, StoreError> {
        self.store.contains(o)
    }

    /// The composed Tier-2 spend verdict for `o`: [`SpendStatus::CertifiedUnspent`] when `o` is a
    /// member of the certified set at the current tip (unspent across the verified window from S),
    /// carrying `basis` (the membership@S trust class) and the tip block number it holds through;
    /// otherwise [`SpendStatus::NotEstablished`] — `o` is not in the set (spent in the window, or
    /// never in the certified snapshot), so no certified-unspent evidence exists. Never a false
    /// positive: the answer is `CertifiedUnspent` only for a genuine set member. `basis` comes from
    /// the run's [`SnapshotAnchor`], so the caller cannot produce the verdict without it.
    pub fn certified_spend_status(
        &self,
        basis: AnchorBasis,
        o: &OutPoint,
    ) -> Result<SpendStatus, StoreError> {
        if self.is_unspent(o)? {
            Ok(SpendStatus::CertifiedUnspent {
                basis,
                through_block: self.tip().map(|t| t.number).unwrap_or(0),
            })
        } else {
            Ok(SpendStatus::NotEstablished)
        }
    }

    /// Apply a verified block: remove every consumed outpoint, add every created one, in
    /// transaction order. Contiguity is enforced against the current tip. The mutations run in
    /// ONE atomic store transaction — on ANY inconsistency (a logic error or a store failure) the
    /// transaction is aborted and the store is left exactly as it was; the tip and undo history
    /// advance only after the transaction commits. No hand-rolled revert, so no torn state.
    pub fn apply(&mut self, block: &BlockEffects) -> Result<(), ApplyError> {
        if let Some(tip) = self.tip {
            // `checked_add`: a tip at u64::MAX has no successor number, so `None` is refused as
            // non-contiguous rather than overflow-panicking (debug) or wrapping `number+1` to 0
            // and admitting a forged `number:0` block (release).
            let contiguous =
                block.prev_hash == tip.hash && tip.number.checked_add(1) == Some(block.number);
            if !contiguous {
                return Err(ApplyError::NotContiguous {
                    expected_prev: tip.hash,
                    got_prev: block.prev_hash,
                });
            }
        }

        let ops = self.commit_block(block)?;

        let tip = SetTip {
            number: block.number,
            hash: block.hash,
        };
        self.tip = Some(tip);
        self.undo.push_back(Undo {
            tip,
            prev_hash: block.prev_hash,
            ops,
        });
        while self.undo.len() > self.depth {
            self.undo.pop_front();
        }
        Ok(())
    }

    /// Apply a block's effects inside one atomic transaction and commit, returning the exact
    /// forward ops for the undo log. On any logic or store error the transaction is dropped
    /// (aborted) before returning, so the store is unchanged — the caller does not touch the
    /// tip/undo on `Err`.
    fn commit_block(&mut self, block: &BlockEffects) -> Result<Vec<Op>, ApplyError> {
        let mut ops: Vec<Op> = Vec::new();
        let mut txn = self.store.transaction().map_err(ApplyError::Store)?;
        for tx in &block.txs {
            for inp in &tx.spent {
                match txn.remove(inp) {
                    Ok(true) => ops.push(Op::Removed(*inp)),
                    Ok(false) => return Err(ApplyError::SpendOfUnknownOutput(*inp)),
                    Err(e) => return Err(ApplyError::Store(e)),
                }
            }
            for out in &tx.created {
                match txn.insert(out) {
                    Ok(true) => ops.push(Op::Inserted(*out)),
                    Ok(false) => return Err(ApplyError::DuplicateOutput(*out)),
                    Err(e) => return Err(ApplyError::Store(e)),
                }
            }
        }
        txn.commit().map_err(ApplyError::Store)?;
        Ok(ops)
    }

    /// Roll the set back so `to` becomes the tip, reversing each later block's exact operations.
    /// `to` must be a point still within the retained undo window: the current tip (a no-op),
    /// a retained block, or the finalized base the window rests on. A target older than the
    /// window is [`RollbackError::Unreachable`] — Praos bounds a real rollback to `depth`, so a
    /// deeper one is a fault. The reversal runs in ONE atomic transaction and the undo/tip are
    /// mutated only after it commits, so a store failure mid-reversal leaves the set UNCHANGED
    /// (never torn, never a block left un-rollbackable).
    pub fn rollback_to(&mut self, to: &[u8; 32]) -> Result<(), RollbackError> {
        if self.tip.map(|t| &t.hash == to).unwrap_or(false) {
            return Ok(());
        }
        if !self.undo.iter().any(|u| &u.prev_hash == to) {
            return Err(RollbackError::Unreachable);
        }
        // Reverse the trailing undo entries down to the one whose parent is `to`.
        let mut to_reverse = 0;
        for u in self.undo.iter().rev() {
            to_reverse += 1;
            if &u.prev_hash == to {
                break;
            }
        }
        let oldest = &self.undo[self.undo.len() - to_reverse];
        let new_tip = SetTip {
            number: oldest.tip.number.saturating_sub(1),
            hash: oldest.prev_hash,
        };
        // Collect the reversed ops (newest block first) into a local so the transaction below
        // borrows only the store, not the undo log.
        let reverse_ops: Vec<Op> = self
            .undo
            .iter()
            .rev()
            .take(to_reverse)
            .flat_map(|u| u.ops.iter().rev().copied())
            .collect();

        let mut txn = self.store.transaction().map_err(RollbackError::Store)?;
        for op in &reverse_ops {
            let r = match op {
                Op::Inserted(x) => txn.remove(x),
                Op::Removed(x) => txn.insert(x),
            };
            r.map_err(RollbackError::Store)?;
        }
        txn.commit().map_err(RollbackError::Store)?;

        // Committed: advance the engine's own bookkeeping.
        for _ in 0..to_reverse {
            self.undo.pop_back();
        }
        self.tip = Some(new_tip);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(tx: u8, index: u16) -> OutPoint {
        OutPoint {
            tx_id: [tx; 32],
            index,
        }
    }

    fn h(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// A block at `number` with hash `h(number)` extending `h(number-1)`, carrying one tx.
    fn block(number: u64, spent: &[OutPoint], created: &[OutPoint]) -> BlockEffects {
        BlockEffects {
            number,
            hash: h(number as u8),
            prev_hash: h((number - 1) as u8),
            txs: vec![TxEffect {
                spent: spent.to_vec(),
                created: created.to_vec(),
            }],
        }
    }

    #[test]
    fn anchor_basis_classes_are_distinct_and_ride_the_snapshot() {
        // The single-key ancillary basis and the stake-quorum basis are DISTINCT variants — a
        // consumer can never read one as the other. `SnapshotAnchor` carries the basis with the
        // tip so the trust class can never be dropped from a membership verdict.
        assert_ne!(AnchorBasis::AncillarySigned, AnchorBasis::StmCertified);
        let tip = SetTip {
            number: 42,
            hash: h(1),
        };
        let weak = SnapshotAnchor {
            tip,
            basis: AnchorBasis::AncillarySigned,
        };
        let strong = SnapshotAnchor {
            tip,
            basis: AnchorBasis::StmCertified,
        };
        assert_eq!(weak.tip, strong.tip);
        assert_ne!(weak.basis, strong.basis);
    }

    #[test]
    fn apply_creates_and_spends_membership() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0), op(1, 1)])).unwrap();
        assert!(u.is_unspent(&op(1, 0)).unwrap());
        assert!(u.is_unspent(&op(1, 1)).unwrap());
        assert_eq!(u.len().unwrap(), 2);
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );

        u.apply(&block(2, &[op(1, 0)], &[op(2, 0)])).unwrap();
        assert!(!u.is_unspent(&op(1, 0)).unwrap(), "spent output is gone");
        assert!(u.is_unspent(&op(1, 1)).unwrap(), "unspent sibling remains");
        assert!(u.is_unspent(&op(2, 0)).unwrap());
    }

    #[test]
    fn in_block_chain_creates_then_spends_to_net_absent() {
        // tx A creates op(1,0); tx B (same block, later) spends it -> net absent post-block.
        let mut u = UtxoSet::new(10);
        let blk = BlockEffects {
            number: 1,
            hash: h(1),
            prev_hash: h(0),
            txs: vec![
                TxEffect {
                    spent: vec![],
                    created: vec![op(1, 0)],
                },
                TxEffect {
                    spent: vec![op(1, 0)],
                    created: vec![op(2, 0)],
                },
            ],
        };
        u.apply(&blk).unwrap();
        assert!(
            !u.is_unspent(&op(1, 0)).unwrap(),
            "created-then-spent in one block is absent"
        );
        assert!(u.is_unspent(&op(2, 0)).unwrap());
        assert_eq!(u.len().unwrap(), 1);
    }

    #[test]
    fn spend_of_unknown_output_fails_closed() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0)])).unwrap();
        // Block 2 spends op(1,0) (ok) then op(9,9) (never created) -> the whole block reverts.
        let err = u
            .apply(&BlockEffects {
                number: 2,
                hash: h(2),
                prev_hash: h(1),
                txs: vec![TxEffect {
                    spent: vec![op(1, 0), op(9, 9)],
                    created: vec![op(2, 0)],
                }],
            })
            .unwrap_err();
        assert_eq!(err, ApplyError::SpendOfUnknownOutput(op(9, 9)));
        // Fail-closed: op(1,0) is back, op(2,0) never landed, tip unmoved.
        assert!(u.is_unspent(&op(1, 0)).unwrap());
        assert!(!u.is_unspent(&op(2, 0)).unwrap());
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );
        assert_eq!(u.len().unwrap(), 1);
    }

    #[test]
    fn duplicate_output_fails_closed() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0)])).unwrap();
        let err = u.apply(&block(2, &[], &[op(1, 0)])).unwrap_err();
        assert_eq!(err, ApplyError::DuplicateOutput(op(1, 0)));
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );
        assert_eq!(u.len().unwrap(), 1);
    }

    #[test]
    fn non_contiguous_block_is_refused() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0)])).unwrap();
        // Block claims a parent that is not the tip.
        let err = u
            .apply(&BlockEffects {
                number: 2,
                hash: h(2),
                prev_hash: h(7),
                txs: vec![],
            })
            .unwrap_err();
        assert_eq!(
            err,
            ApplyError::NotContiguous {
                expected_prev: h(1),
                got_prev: h(7),
            }
        );
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );
    }

    #[test]
    fn rollback_reverses_a_block_exactly() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0), op(1, 1)])).unwrap();
        u.apply(&block(2, &[op(1, 0)], &[op(2, 0)])).unwrap();
        // Roll back block 2: op(1,0) returns, op(2,0) gone, tip back to block 1.
        u.rollback_to(&h(1)).unwrap();
        assert!(u.is_unspent(&op(1, 0)).unwrap());
        assert!(u.is_unspent(&op(1, 1)).unwrap());
        assert!(!u.is_unspent(&op(2, 0)).unwrap());
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );
        assert_eq!(u.len().unwrap(), 2);
    }

    #[test]
    fn rollback_reverses_an_in_block_chain() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0)])).unwrap();
        // Block 2 creates op(2,0) then spends it in a later tx, and spends op(1,0).
        u.apply(&BlockEffects {
            number: 2,
            hash: h(2),
            prev_hash: h(1),
            txs: vec![
                TxEffect {
                    spent: vec![op(1, 0)],
                    created: vec![op(2, 0)],
                },
                TxEffect {
                    spent: vec![op(2, 0)],
                    created: vec![op(3, 0)],
                },
            ],
        })
        .unwrap();
        assert!(!u.is_unspent(&op(1, 0)).unwrap());
        assert!(!u.is_unspent(&op(2, 0)).unwrap());
        assert!(u.is_unspent(&op(3, 0)).unwrap());
        // Rolling back restores exactly the block-1 state.
        u.rollback_to(&h(1)).unwrap();
        assert!(u.is_unspent(&op(1, 0)).unwrap());
        assert!(!u.is_unspent(&op(2, 0)).unwrap());
        assert!(!u.is_unspent(&op(3, 0)).unwrap());
        assert_eq!(u.len().unwrap(), 1);
    }

    #[test]
    fn rollback_across_multiple_blocks_to_a_retained_ancestor() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0)])).unwrap();
        u.apply(&block(2, &[], &[op(2, 0)])).unwrap();
        u.apply(&block(3, &[op(1, 0)], &[op(3, 0)])).unwrap();
        u.rollback_to(&h(1)).unwrap();
        assert!(u.is_unspent(&op(1, 0)).unwrap());
        assert!(!u.is_unspent(&op(2, 0)).unwrap());
        assert!(!u.is_unspent(&op(3, 0)).unwrap());
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );
    }

    #[test]
    fn rollback_beyond_retained_history_is_unreachable() {
        // depth 2: after applying 3 blocks, block 1 is finalized (evicted from the undo window).
        let mut u = UtxoSet::new(2);
        u.apply(&block(1, &[], &[op(1, 0)])).unwrap();
        u.apply(&block(2, &[], &[op(2, 0)])).unwrap();
        u.apply(&block(3, &[], &[op(3, 0)])).unwrap();
        // Rolling back to block 1's parent (h(0)) needs undoing block 1, which is finalized.
        assert_eq!(u.rollback_to(&h(0)), Err(RollbackError::Unreachable));
        // Unchanged.
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 3,
                hash: h(3)
            })
        );
        assert!(u.is_unspent(&op(1, 0)).unwrap());
    }

    #[test]
    fn apply_at_max_block_number_fails_closed_not_overflow() {
        // A tip at u64::MAX has no valid successor number: extending it must be refused, never
        // overflow-panic (debug) nor wrap `number+1` to 0 and admit a forged `number:0` block
        // with the right parent hash (release). from_snapshot's base number is unchecked, so a
        // hostile/buggy snapshot could seed MAX.
        let base = SetTip {
            number: u64::MAX,
            hash: h(200),
        };
        let mut u = UtxoSet::from_snapshot(base, [op(1, 0)], 10);
        let err = u
            .apply(&BlockEffects {
                number: 0,
                hash: h(201),
                prev_hash: h(200),
                txs: vec![],
            })
            .unwrap_err();
        assert!(matches!(err, ApplyError::NotContiguous { .. }));
        assert_eq!(u.tip(), Some(base));
        assert!(u.is_unspent(&op(1, 0)).unwrap());
    }

    #[test]
    fn from_snapshot_seeds_membership_and_extends() {
        let base = SetTip {
            number: 100,
            hash: h(100),
        };
        let mut u = UtxoSet::from_snapshot(base, [op(50, 0), op(60, 1)], 10);
        assert!(u.is_unspent(&op(50, 0)).unwrap());
        assert_eq!(u.tip(), Some(base));
        // The next block must name the snapshot as its parent and spend from the snapshot set.
        u.apply(&BlockEffects {
            number: 101,
            hash: h(101),
            prev_hash: h(100),
            txs: vec![TxEffect {
                spent: vec![op(50, 0)],
                created: vec![op(101, 0)],
            }],
        })
        .unwrap();
        assert!(!u.is_unspent(&op(50, 0)).unwrap());
        assert!(u.is_unspent(&op(101, 0)).unwrap());
        // Cannot roll back past the finalized snapshot base.
        assert_eq!(u.rollback_to(&h(99)), Err(RollbackError::Unreachable));
    }

    #[test]
    fn certified_spend_status_grades_membership_with_the_basis_and_recency() {
        let base = SetTip {
            number: 100,
            hash: h(100),
        };
        let mut u = UtxoSet::from_snapshot(base, [op(50, 0)], 10);

        // A member at the anchor tip: CertifiedUnspent, carrying the basis and the tip it holds
        // through (still S = 100 before any block applies).
        assert_eq!(
            u.certified_spend_status(AnchorBasis::AncillarySigned, &op(50, 0)),
            Ok(SpendStatus::CertifiedUnspent {
                basis: AnchorBasis::AncillarySigned,
                through_block: 100,
            })
        );
        // A non-member: no certified-unspent evidence, never a false positive.
        assert_eq!(
            u.certified_spend_status(AnchorBasis::AncillarySigned, &op(99, 9)),
            Ok(SpendStatus::NotEstablished)
        );

        // Advance the window; the recency rides the current tip, and the spent member drops to
        // NotEstablished while a created one becomes CertifiedUnspent.
        u.apply(&BlockEffects {
            number: 101,
            hash: h(101),
            prev_hash: h(100),
            txs: vec![TxEffect {
                spent: vec![op(50, 0)],
                created: vec![op(101, 0)],
            }],
        })
        .unwrap();
        assert_eq!(
            u.certified_spend_status(AnchorBasis::StmCertified, &op(101, 0)),
            Ok(SpendStatus::CertifiedUnspent {
                basis: AnchorBasis::StmCertified,
                through_block: 101,
            })
        );
        assert_eq!(
            u.certified_spend_status(AnchorBasis::StmCertified, &op(50, 0)),
            Ok(SpendStatus::NotEstablished)
        );
    }

    /// A store whose transaction fails on its `fail_at`-th mutation — injects the persistent-store
    /// I/O failure the atomicity of `apply`/`rollback_to` must survive. Its transaction aborts on
    /// drop (reverses the ops it applied), exactly like `MemTxn`, so a failed apply/rollback must
    /// leave the committed set unchanged.
    struct FaultyStore {
        set: BTreeSet<OutPoint>,
        fail_at: Option<usize>,
    }

    struct FaultyTxn<'s> {
        set: &'s mut BTreeSet<OutPoint>,
        undo: Vec<Op>,
        committed: bool,
        count: usize,
        fail_at: Option<usize>,
    }

    impl FaultyTxn<'_> {
        fn tick(&mut self) -> Result<(), StoreError> {
            self.count += 1;
            if Some(self.count) == self.fail_at {
                Err(StoreError("injected I/O failure".into()))
            } else {
                Ok(())
            }
        }
    }

    impl UtxoTxn for FaultyTxn<'_> {
        fn insert(&mut self, o: &OutPoint) -> Result<bool, StoreError> {
            self.tick()?;
            let newly = self.set.insert(*o);
            if newly {
                self.undo.push(Op::Inserted(*o));
            }
            Ok(newly)
        }
        fn remove(&mut self, o: &OutPoint) -> Result<bool, StoreError> {
            self.tick()?;
            let present = self.set.remove(o);
            if present {
                self.undo.push(Op::Removed(*o));
            }
            Ok(present)
        }
        fn commit(mut self) -> Result<(), StoreError> {
            self.committed = true;
            Ok(())
        }
    }

    impl Drop for FaultyTxn<'_> {
        fn drop(&mut self) {
            if self.committed {
                return;
            }
            for op in self.undo.iter().rev() {
                match op {
                    Op::Inserted(x) => {
                        self.set.remove(x);
                    }
                    Op::Removed(x) => {
                        self.set.insert(*x);
                    }
                }
            }
        }
    }

    impl UtxoStore for FaultyStore {
        type Txn<'s> = FaultyTxn<'s>;
        fn transaction(&mut self) -> Result<FaultyTxn<'_>, StoreError> {
            Ok(FaultyTxn {
                set: &mut self.set,
                undo: Vec::new(),
                committed: false,
                count: 0,
                fail_at: self.fail_at,
            })
        }
        fn contains(&self, o: &OutPoint) -> Result<bool, StoreError> {
            Ok(self.set.contains(o))
        }
        fn len(&self) -> Result<usize, StoreError> {
            Ok(self.set.len())
        }
    }

    #[test]
    fn apply_is_atomic_under_a_store_failure() {
        // Seed {A, B}. A block removes A, removes B, creates C — the store fails on the 3rd op
        // (the create). The whole block must abort: A and B are NOT lost, C never lands, tip
        // unmoved. (Before the transactional seam, the partial revert lost A and B.)
        let (a, b, c) = (op(1, 0), op(2, 0), op(3, 0));
        let store = FaultyStore {
            set: [a, b].into_iter().collect(),
            fail_at: Some(3),
        };
        let mut set = UtxoSet::with_store(
            store,
            Some(SetTip {
                number: 0,
                hash: h(0),
            }),
            10,
        );
        let err = set
            .apply(&BlockEffects {
                number: 1,
                hash: h(1),
                prev_hash: h(0),
                txs: vec![TxEffect {
                    spent: vec![a, b],
                    created: vec![c],
                }],
            })
            .unwrap_err();
        assert!(matches!(err, ApplyError::Store(_)));
        assert!(
            set.is_unspent(&a).unwrap(),
            "A restored by abort — not lost"
        );
        assert!(
            set.is_unspent(&b).unwrap(),
            "B restored by abort — not lost"
        );
        assert!(!set.is_unspent(&c).unwrap());
        assert_eq!(
            set.tip(),
            Some(SetTip {
                number: 0,
                hash: h(0)
            })
        );
        assert_eq!(set.len().unwrap(), 2);
    }

    #[test]
    fn rollback_is_atomic_under_a_store_failure() {
        // Apply blocks 1 and 2 cleanly, then a rollback whose store fails mid-reversal must leave
        // the set EXACTLY at block 2 — not torn, and NOT left un-rollbackable. (Before the fix,
        // the popped undo entry was destroyed and the block became permanently un-rollbackable.)
        let store = FaultyStore {
            set: BTreeSet::new(),
            fail_at: None,
        };
        let mut set = UtxoSet::with_store(store, None, 10);
        set.apply(&block(1, &[], &[op(1, 0)])).unwrap();
        set.apply(&block(2, &[], &[op(2, 0), op(2, 1)])).unwrap();

        // Arm a fault on the first reversal op, then attempt the rollback.
        set.store.fail_at = Some(1);
        let err = set.rollback_to(&h(1)).unwrap_err();
        assert!(matches!(err, RollbackError::Store(_)));
        // Unchanged: still at block 2, all outputs present.
        assert_eq!(
            set.tip(),
            Some(SetTip {
                number: 2,
                hash: h(2)
            })
        );
        assert!(set.is_unspent(&op(2, 0)).unwrap());
        assert!(set.is_unspent(&op(2, 1)).unwrap());
        assert!(set.is_unspent(&op(1, 0)).unwrap());

        // NOT wedged: once the fault clears, the same rollback succeeds.
        set.store.fail_at = None;
        set.rollback_to(&h(1)).unwrap();
        assert_eq!(
            set.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );
        assert!(!set.is_unspent(&op(2, 0)).unwrap());
        assert!(set.is_unspent(&op(1, 0)).unwrap());
    }
}
