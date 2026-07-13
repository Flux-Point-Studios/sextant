//! Incremental window follower (BEYOND-DoD Epic F, F1): a sans-io state machine that
//! turns the batch windowed-unspent verdict into a live, append-one-block-at-a-time
//! follower.
//!
//! [`crate::window::verify_watched_window`] answers "is the watched outpoint spent
//! across this certified, header-verified window?" by re-verifying the whole window on
//! every call — O(window) work. A live consumer that receives one new block at a time
//! (a chain-sync follower) would redo that whole scan per block. [`WindowFollower`]
//! does the same verification incrementally: each [`WindowFollower::append`] verifies
//! exactly one block (O(block-bytes), never O(window)) and folds its facts into a small
//! running state, and [`WindowFollower::verdict`] reads the current three-valued
//! [`WatchVerdict`] off that state.
//!
//! ## The batch is the frozen oracle
//! The follower shares the batch's exact per-block units — the per-header crypto
//! ([`crate::chain::verify_header`]) and the per-block body-bind + spend scan
//! ([`crate::window::scan_block_facts`]) — so it is a faithful incremental form of the
//! batch, not a parallel re-implementation. The equivalence is pinned and tested
//! (`tests/follow.rs`): over any prefix whose every block `append` ACCEPTED,
//! `verdict()` equals the batch over that accepted prefix; a REFUSED append leaves
//! state untouched and its reason maps (via [`AppendRefusal::as_stall_reason`]) to the
//! batch stall reason over the same prefix.
//!
//! ## Honest scope
//! Same as the batch: the follower proves "no spend of the watched outpoint observed
//! through a header-verified, hash-linked, body-committed run that observed its
//! creation and reached `require_through`" — never absolute/eternal/tip-state unspent.
//! A withheld spending block STRUCTURALLY cannot advance the verified tip (its
//! successor fails to link), so it collapses to a non-answer, never a false no-spend.
//!
//! F1 is single-epoch: every appended block is leader-verified against one `eta0`.
//! Crossing an epoch boundary (a per-epoch nonce map) is a later follower slice; a
//! block from another epoch is refused ([`AppendRefusal::Crypto`]) until then.

use crate::chain;
use crate::header::HeaderView;
use crate::utxo::{CertifiedTransactions, OutPoint};
use crate::window::{
    Freshness, ScanFailure, StallReason, WatchBasis, WatchVerdict, WatchedTip, WindowAssumptions,
    scan_block_facts,
};

/// The outcome of a successful [`WindowFollower::append`]: the block was verified and
/// became the follower's new verified tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    /// The accepted block's number — the follower's new verified tip height.
    pub block_number: u64,
}

/// Why [`WindowFollower::append`] refused a block. A refusal leaves the follower's state
/// untouched — the block simply does not advance the verified tip, and a later correct
/// block can still be appended.
///
/// Each variant maps to the [`StallReason`] the batch
/// [`crate::window::verify_watched_window`] reports over the same prefix (see
/// [`AppendRefusal::as_stall_reason`]), so a follower verdict is the batch verdict
/// computed incrementally. `#[non_exhaustive]` so later follower slices add refusals
/// (epoch-nonce-unavailable, rollback-beyond-window) additively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AppendRefusal {
    /// The block did not decode as a Praos block.
    Decode,
    /// The block's `prev_hash` did not link to the follower's verified tip — a gap,
    /// reorder, or fork.
    BrokenLink,
    /// The block hash-links but its number is not the tip's + 1. A genuinely signed
    /// header from a colluding elected leader can carry ANY block number, so without
    /// this check it could vault the verified tip past `require_through` without the
    /// intervening blocks ever being served — the truncation evasion resurrected by
    /// number inflation. The batch oracle catches the same shape with its terminal
    /// contiguity check.
    NotContiguous,
    /// The block's operational certificate, leader-VRF (against the follower's epoch
    /// nonce), or KES body signature did not verify.
    Crypto,
    /// The block's transaction bodies did not hash to its header's commitment: a real
    /// header with swapped or tampered bodies.
    BodyCommitmentMismatch,
    /// The block's body stream was not a decodable transaction sequence.
    MalformedBody,
}

impl AppendRefusal {
    /// The batch [`StallReason`] this refusal corresponds to. A decode, link, or crypto
    /// refusal collapses to [`StallReason::BrokenSegment`] — exactly as
    /// [`crate::chain::verify_segment`] collapses a decode/link/opcert/VRF/KES failure —
    /// while a body-side refusal keeps its distinct reason. This is the pinned
    /// equivalence map: a refused append at block *i* corresponds to the batch stalling
    /// over the accepted prefix plus block *i* for `as_stall_reason()`.
    pub fn as_stall_reason(self) -> StallReason {
        match self {
            AppendRefusal::Decode | AppendRefusal::BrokenLink | AppendRefusal::Crypto => {
                StallReason::BrokenSegment
            }
            AppendRefusal::NotContiguous => StallReason::MissingBlock,
            AppendRefusal::BodyCommitmentMismatch => StallReason::BodyCommitmentMismatch,
            AppendRefusal::MalformedBody => StallReason::MalformedBody,
        }
    }
}

/// The first observed spend of the watched outpoint, recorded stickily: once a
/// verified block spends the outpoint, that is a definite refuse the follower reports
/// thereafter even if a later append is refused (the spend was observed in an accepted
/// prefix — the follower is MORE correct than the batch over a longer, broken prefix).
#[derive(Debug, Clone, Copy)]
struct ObservedSpend {
    at_height: u64,
    at_slot: u64,
    spending_txid: [u8; 32],
}

/// A live follower for a spend of one watched outpoint across a certified,
/// header-verified window. Append blocks in on-chain order; read the verdict at any
/// point. Sans-io: it verifies bytes it is handed and holds no transport.
pub struct WindowFollower {
    watch: OutPoint,
    /// The Mithril-certified height the window is anchored to; the verified tip must
    /// stay at or below it for a quorum-backed no-spend verdict.
    anchor_height: u64,
    /// The caller's hard lower bound on the verified tip — a window that has not reached
    /// it is [`StallReason::WindowTooShort`], closing the truncation evasion.
    require_through: u64,
    /// The single epoch nonce every appended block's leader-VRF is checked against (F1).
    eta0: [u8; 32],
    /// The last accepted header: the linkage parent for the next append and the tip the
    /// verdict is answered as of. `None` before the first accepted block.
    tip: Option<HeaderView>,
    /// Whether the watched outpoint's creation has been observed in an accepted block.
    create_seen: bool,
    /// The first observed spend, if any (sticky).
    spend: Option<ObservedSpend>,
}

impl WindowFollower {
    /// Start following for a spend of `watch`, answered as of a verified tip at or above
    /// `require_through`, inside the Mithril-certified region `anchor`, under the single
    /// epoch nonce `eta0` (F1 is single-epoch — see the module docs).
    pub fn new(
        watch: OutPoint,
        anchor: &CertifiedTransactions,
        require_through: u64,
        eta0: [u8; 32],
    ) -> Self {
        Self {
            watch,
            anchor_height: anchor.block_number,
            require_through,
            eta0,
            tip: None,
            create_seen: false,
            spend: None,
        }
    }

    /// Verify and fold one block (ledger `[era, block]` CBOR) into the follower's state.
    /// The block must decode, link to the current verified tip by hash, have its
    /// operational certificate / leader-VRF / KES verify, and have its bodies bind to
    /// its header commitment; only then is it accepted and its spend facts recorded.
    ///
    /// O(block-bytes): one header's crypto + one block's body-bind and spend scan, never
    /// a re-scan of the window. A refusal leaves the follower's state UNTOUCHED — nothing
    /// is committed until every check passes — so a later correct block still appends.
    pub fn append(&mut self, block: &[u8]) -> Result<Appended, AppendRefusal> {
        // 1. Decode the header for the link + crypto checks (mirrors verify_segment's
        //    per-header work).
        let view = HeaderView::from_block_cbor(block).map_err(|_| AppendRefusal::Decode)?;
        // 2. Extend the accepted run: link to the tip by hash (a gap, reorder, or fork
        //    is refused, exactly as verify_segment's BrokenLink), AND advance the block
        //    number by exactly one. The number check is load-bearing on its own: a
        //    genuinely signed header from a colluding elected leader can carry any
        //    number, and without it a hash-linked skipper could vault the tip past
        //    `require_through` without the intervening blocks — the batch oracle's
        //    terminal contiguity check (MissingBlock), enforced here per append.
        if let Some(prev) = &self.tip {
            if view.prev_hash != Some(prev.block_hash) {
                return Err(AppendRefusal::BrokenLink);
            }
            if view.block_number != prev.block_number + 1 {
                return Err(AppendRefusal::NotContiguous);
            }
        }
        // 3. Crypto: opcert -> leader-VRF (vs eta0) -> KES, the shared per-header unit.
        //    The batch collapses opcert/VRF/KES to BrokenSegment too, so the class, not
        //    the inner cause, is what a windowed verdict turns on.
        chain::verify_header(&view, &self.eta0).map_err(|_| AppendRefusal::Crypto)?;
        // 4. Bind the bodies to the header commitment and scan them, the shared per-block
        //    unit. Its decode cannot fail (step 1 already decoded), but map it fail-closed.
        let facts = scan_block_facts(block, &self.watch).map_err(|e| match e {
            ScanFailure::Decode => AppendRefusal::Decode,
            ScanFailure::BodyCommitmentMismatch => AppendRefusal::BodyCommitmentMismatch,
            ScanFailure::MalformedBody => AppendRefusal::MalformedBody,
        })?;

        // 5. Every check passed: commit. Nothing above mutated `self`, so the follower is
        //    untouched on any refusal.
        if facts.created_here {
            self.create_seen = true;
        }
        if let Some(spending_txid) = facts.spent_by {
            self.spend.get_or_insert(ObservedSpend {
                at_height: facts.view.block_number,
                at_slot: facts.view.slot,
                spending_txid,
            });
        }
        let block_number = facts.view.block_number;
        self.tip = Some(facts.view);
        Ok(Appended { block_number })
    }

    /// The current three-valued windowed verdict, answered as of the verified tip under
    /// the caller's `freshness` bound. Mirrors the batch's terminal decision exactly: a
    /// recorded spend is a definite [`WatchVerdict::SpentObserved`]; otherwise the run
    /// must have observed the outpoint's creation, reached `require_through`, stayed at
    /// or below the certified anchor, and be fresh, or it is a distinct-reason
    /// [`WatchVerdict::Stalled`] — never a false [`WatchVerdict::Unspent`].
    pub fn verdict(&self, freshness: Freshness) -> WatchVerdict {
        if let Some(spend) = &self.spend {
            return WatchVerdict::SpentObserved {
                at_height: spend.at_height,
                at_slot: spend.at_slot,
                spending_txid: spend.spending_txid,
            };
        }
        let Some(tip) = &self.tip else {
            return stalled(0, StallReason::EmptyWindow);
        };
        // Contiguity is enforced per append (hash link + number+1), so the accepted run
        // is gap-free and the batch's terminal MissingBlock check cannot diverge here.
        if !self.create_seen {
            return stalled(tip.block_number, StallReason::CreationNotObserved);
        }
        if tip.block_number < self.require_through {
            return stalled(tip.block_number, StallReason::WindowTooShort);
        }
        if tip.block_number > self.anchor_height {
            return stalled(tip.block_number, StallReason::TipAboveAnchor);
        }
        if freshness.slot_now.saturating_sub(tip.slot) > freshness.max_lag {
            return stalled(tip.block_number, StallReason::TipTooOld);
        }
        WatchVerdict::Unspent {
            as_of: WatchedTip {
                anchor_height: self.anchor_height,
                as_of_height: tip.block_number,
                as_of_slot: tip.slot,
            },
            basis: WatchBasis::WatchedWindow(WindowAssumptions {
                mithril_quorum: true,
                data_complete: true,
            }),
        }
    }
}

/// Build a `Stalled` verdict — a non-answer carrying how far the follower verified.
fn stalled(verified_through: u64, reason: StallReason) -> WatchVerdict {
    WatchVerdict::Stalled {
        verified_through,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// The two lowest preprod window blocks (4921916, 4921917) and their shared epoch
    /// nonce, from the committed vectors + `.eta0` sidecars.
    fn first_two_blocks_and_eta0() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
        let mut rows: Vec<(u64, Vec<u8>, [u8; 32])> = Vec::new();
        for entry in fs::read_dir(&dir).expect("read vectors dir") {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if !name.starts_with("preprod-")
                || path.extension().and_then(|e| e.to_str()) != Some("block")
            {
                continue;
            }
            let bytes = hex::decode(fs::read_to_string(&path).expect("read block vector").trim())
                .expect("block hex");
            let eta0: [u8; 32] = hex::decode(
                fs::read_to_string(path.with_extension("eta0"))
                    .expect("read eta0 sidecar")
                    .trim(),
            )
            .expect("eta0 hex")
            .try_into()
            .expect("32-byte eta0");
            let view = HeaderView::from_block_cbor(&bytes).expect("decode block");
            rows.push((view.slot, bytes, eta0));
        }
        rows.sort_by_key(|r| r.0);
        let eta0 = rows[0].2;
        assert_eq!(rows[1].2, eta0, "one epoch, one nonce");
        (rows[0].1.clone(), rows[1].1.clone(), eta0)
    }

    /// The colluding-elected-leader shape: a genuinely signed header that hash-links to
    /// the tip but SKIPS a block number could vault the verified tip past
    /// `require_through` without serving the intervening blocks — the truncation
    /// evasion resurrected by number inflation. The batch oracle catches it with its
    /// terminal contiguity check (`MissingBlock`); the follower must refuse the append.
    /// Simulated with real signed blocks by lowering the carried tip number so the
    /// genuine successor (hash-links, crypto-valid) presents as a number skip.
    #[test]
    fn number_skipping_block_is_refused_not_contiguous() {
        let (b0, b1, eta0) = first_two_blocks_and_eta0();
        let anchor = CertifiedTransactions {
            merkle_root: String::new(),
            epoch: 300,
            block_number: 4_927_469,
        };
        let watch = OutPoint {
            tx_id: [0u8; 32],
            index: 0,
        };
        let mut follower = WindowFollower::new(watch, &anchor, 4_921_937, eta0);
        follower.append(&b0).expect("the first block is accepted");
        follower
            .tip
            .as_mut()
            .expect("tip set after the first append")
            .block_number -= 1;
        assert_eq!(
            follower.append(&b1),
            Err(AppendRefusal::NotContiguous),
            "a hash-linked block whose number is not tip+1 must be refused",
        );
        assert_eq!(
            AppendRefusal::NotContiguous.as_stall_reason(),
            StallReason::MissingBlock,
            "the refusal maps to the batch oracle's contiguity stall",
        );
    }
}
