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
//! * **Fail-closed** — every refusal leaves the set exactly as it was; a partially-applied
//!   block is reverted before the error returns.
//! * **Eviction-as-finalization** — only the last `depth` blocks are reversible (the Praos
//!   stability window, k = 2160); older application is finalized, matching what a rollback can
//!   reach on a live chain.
//!
//! Rollback is exact: each applied block records its ordered insert/remove operations, and an
//! undo replays them in reverse — so an outpoint created and then spent *within one block*
//! (in-block transaction chaining) reverses to its true pre-block absence.

use std::collections::{BTreeSet, VecDeque};

use crate::utxo::OutPoint;

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
}

/// Why a rollback failed. The set is left UNCHANGED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackError {
    /// The target point is not reachable within the retained (`depth`-deep) undo history — it
    /// is finalized (older than the rollback window) or was never on the applied chain.
    Unreachable,
}

/// One applied block's exact forward operations, for an exact reverse.
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
/// socket or a clock.
pub struct UtxoSet {
    set: BTreeSet<OutPoint>,
    tip: Option<SetTip>,
    undo: VecDeque<Undo>,
    depth: usize,
}

impl UtxoSet {
    /// An empty set at no tip — the start of a from-genesis replay. `depth` is the retained
    /// rollback window in blocks; a live follower uses the Praos stability window (k = 2160).
    pub fn new(depth: usize) -> Self {
        UtxoSet {
            set: BTreeSet::new(),
            tip: None,
            undo: VecDeque::new(),
            depth,
        }
    }

    /// Seed the set from a bootstrapped snapshot: the outpoints unspent as of `tip` (a later
    /// slice hands over the replay result). The snapshot is the finalized base, so it carries
    /// no rollback history; the first `apply` must name `tip.hash` as its parent.
    pub fn from_snapshot(
        tip: SetTip,
        unspent: impl IntoIterator<Item = OutPoint>,
        depth: usize,
    ) -> Self {
        UtxoSet {
            set: unspent.into_iter().collect(),
            tip: Some(tip),
            undo: VecDeque::new(),
            depth,
        }
    }

    /// The chain position the set is current as of (`None` before the first apply).
    pub fn tip(&self) -> Option<SetTip> {
        self.tip
    }

    /// The number of unspent outpoints held.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether the set holds no unspent outpoints.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Whether `o` is unspent at the applied tip — the Tier-2 membership answer.
    pub fn is_unspent(&self, o: &OutPoint) -> bool {
        self.set.contains(o)
    }

    /// Apply a verified block: remove every consumed outpoint, add every created one, in
    /// transaction order. Contiguity is enforced against the current tip. On ANY inconsistency
    /// the set is left exactly as it was and the error is returned (fail-closed).
    pub fn apply(&mut self, block: &BlockEffects) -> Result<(), ApplyError> {
        if let Some(tip) = self.tip
            && (block.prev_hash != tip.hash || block.number != tip.number + 1)
        {
            return Err(ApplyError::NotContiguous {
                expected_prev: tip.hash,
                got_prev: block.prev_hash,
            });
        }

        let mut ops: Vec<Op> = Vec::new();
        for tx in &block.txs {
            for inp in &tx.spent {
                if self.set.remove(inp) {
                    ops.push(Op::Removed(*inp));
                } else {
                    self.revert(&ops);
                    return Err(ApplyError::SpendOfUnknownOutput(*inp));
                }
            }
            for out in &tx.created {
                if self.set.insert(*out) {
                    ops.push(Op::Inserted(*out));
                } else {
                    self.revert(&ops);
                    return Err(ApplyError::DuplicateOutput(*out));
                }
            }
        }

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

    /// Roll the set back so `to` becomes the tip, reversing each later block's exact operations.
    /// `to` must be a point still within the retained undo window: the current tip (a no-op),
    /// a retained block, or the finalized base the window rests on. A target older than the
    /// window is [`RollbackError::Unreachable`] — Praos bounds a real rollback to `depth`, so a
    /// deeper one is a fault, and the set is left UNCHANGED.
    pub fn rollback_to(&mut self, to: &[u8; 32]) -> Result<(), RollbackError> {
        let at_tip = self.tip.map(|t| &t.hash == to).unwrap_or(false);
        // A valid target is either the current tip or the parent of some retained block (which
        // becomes the tip once that block and everything after it is undone).
        let reachable = at_tip || self.undo.iter().any(|u| &u.prev_hash == to);
        if !reachable {
            return Err(RollbackError::Unreachable);
        }
        while self.tip.map(|t| &t.hash != to).unwrap_or(false) {
            let u = self
                .undo
                .pop_back()
                .expect("reachability guarantees a block to undo before reaching `to`");
            self.revert(&u.ops);
            self.tip = Some(SetTip {
                number: u.tip.number.saturating_sub(1),
                hash: u.prev_hash,
            });
        }
        Ok(())
    }

    /// Reverse a block's operations in exact reverse order: a removal re-inserts, an insertion
    /// removes. Applied to the partial ops of a failed block, or a full block on rollback.
    fn revert(&mut self, ops: &[Op]) {
        for op in ops.iter().rev() {
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
    fn apply_creates_and_spends_membership() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0), op(1, 1)])).unwrap();
        assert!(u.is_unspent(&op(1, 0)));
        assert!(u.is_unspent(&op(1, 1)));
        assert_eq!(u.len(), 2);
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );

        u.apply(&block(2, &[op(1, 0)], &[op(2, 0)])).unwrap();
        assert!(!u.is_unspent(&op(1, 0)), "spent output is gone");
        assert!(u.is_unspent(&op(1, 1)), "unspent sibling remains");
        assert!(u.is_unspent(&op(2, 0)));
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
            !u.is_unspent(&op(1, 0)),
            "created-then-spent in one block is absent"
        );
        assert!(u.is_unspent(&op(2, 0)));
        assert_eq!(u.len(), 1);
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
        assert!(u.is_unspent(&op(1, 0)));
        assert!(!u.is_unspent(&op(2, 0)));
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );
        assert_eq!(u.len(), 1);
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
        assert_eq!(u.len(), 1);
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
        assert!(u.is_unspent(&op(1, 0)));
        assert!(u.is_unspent(&op(1, 1)));
        assert!(!u.is_unspent(&op(2, 0)));
        assert_eq!(
            u.tip(),
            Some(SetTip {
                number: 1,
                hash: h(1)
            })
        );
        assert_eq!(u.len(), 2);
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
        assert!(!u.is_unspent(&op(1, 0)));
        assert!(!u.is_unspent(&op(2, 0)));
        assert!(u.is_unspent(&op(3, 0)));
        // Rolling back restores exactly the block-1 state.
        u.rollback_to(&h(1)).unwrap();
        assert!(u.is_unspent(&op(1, 0)));
        assert!(!u.is_unspent(&op(2, 0)));
        assert!(!u.is_unspent(&op(3, 0)));
        assert_eq!(u.len(), 1);
    }

    #[test]
    fn rollback_across_multiple_blocks_to_a_retained_ancestor() {
        let mut u = UtxoSet::new(10);
        u.apply(&block(1, &[], &[op(1, 0)])).unwrap();
        u.apply(&block(2, &[], &[op(2, 0)])).unwrap();
        u.apply(&block(3, &[op(1, 0)], &[op(3, 0)])).unwrap();
        u.rollback_to(&h(1)).unwrap();
        assert!(u.is_unspent(&op(1, 0)));
        assert!(!u.is_unspent(&op(2, 0)));
        assert!(!u.is_unspent(&op(3, 0)));
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
        assert!(u.is_unspent(&op(1, 0)));
    }

    #[test]
    fn from_snapshot_seeds_membership_and_extends() {
        let base = SetTip {
            number: 100,
            hash: h(100),
        };
        let mut u = UtxoSet::from_snapshot(base, [op(50, 0), op(60, 1)], 10);
        assert!(u.is_unspent(&op(50, 0)));
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
        assert!(!u.is_unspent(&op(50, 0)));
        assert!(u.is_unspent(&op(101, 0)));
        // Cannot roll back past the finalized snapshot base.
        assert_eq!(u.rollback_to(&h(99)), Err(RollbackError::Unreachable));
    }
}
