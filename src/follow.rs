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
//! ## Trust boundary (surfaced, not verified)
//! Like the batch, the verdict rests on the surfaced `mithril_quorum` assumption (see
//! [`crate::window::WindowAssumptions`]): the followed chain is TRUSTED to be the
//! Mithril-certified one. The read path binds neither each block to the certified
//! transaction root nor checks leader eligibility (it holds no stake distribution), so a
//! provider colluding with a registered block producer could forge a valid-header chain
//! that omits a spend, or advance `as_of_slot` with a recent slot on a stale run. Slot
//! contiguity is not a defense here — a forged slot is a FORWARD jump, which any monotone
//! check admits. The assumption is surfaced, never faked as a check; its closure is a
//! Tier-2 certified-UTxO-set binding, not a follower change.
//!
//! ## Crossing epoch boundaries (F2)
//! Each block's leader-VRF is checked against ITS epoch nonce, selected from a
//! [`SlotSchedule`] (slot → epoch) and a small epoch → η0 map ([`WindowFollower::supply_next_eta0`]).
//! Nonce selection is a per-block MAP LOOKUP, never a mutated "current nonce": a mutated
//! current-nonce would leave a rollback below an epoch turn pointing at the wrong epoch's
//! nonce, so re-appended pre-turn blocks would spuriously fail. [`WindowFollower::append`]
//! only READS the nonce map — it never mutates it (nor does a refusal), so nonce state is
//! independent of the block-tracking state a rollback truncates. A block whose epoch nonce
//! has not been staged is refused [`AppendRefusal::EpochNonceUnavailable`] (fail-closed,
//! liveness-only: it never advances the tip, and a later append after the nonce is staged
//! still succeeds).
//!
//! ## Rollback + eviction-as-finalization (F3)
//! A live chain-sync consumer receives `RollBackward` as well as `RollForward`, so the
//! follower retains the last [`RING_CAP`] accepted blocks' facts in a ring
//! ([`BlockFact`]) and [`WindowFollower::rollback`] truncates the accepted run to the
//! rolled-back-to point, recomputing the window's facts from the survivors. `RING_CAP` is
//! Cardano's Ouroboros security parameter k = 2160: a fact evicted below it is
//! common-prefix-deep and can NEVER be rolled back, so eviction FINALIZES it — folding
//! `created_here`/`spending_txid` into the sticky `creation_final`/`spend_final`
//! aggregates that [`WindowFollower::rollback`] never clears (a naive
//! recompute-from-survivors would make a spend that scrolled below the cap evaporate).
//! A rollback target the follower does not retain — deeper than the ring and not the
//! follow base — is fail-closed to [`crate::window::StallReason::RollbackBeyondWindow`]:
//! the follower cannot reconstruct that history, so it is poisoned until the caller
//! discards it and restarts. The nonce map is untouched by rollback (F2), so crossing an
//! epoch boundary and rolling back below it needs no re-staging.

use std::collections::{BTreeMap, VecDeque};

use crate::chain;
use crate::header::HeaderView;
use crate::utxo::{CertifiedTransactions, OutPoint};
use crate::window::{
    Freshness, ScanFailure, StallReason, WatchBasis, WatchVerdict, WatchedTip, WindowAssumptions,
    scan_block_facts,
};

/// A Shelley-era slot→epoch schedule. Epochs are fixed-length, so one known
/// `(epoch, epoch_first_slot)` anchor plus `epoch_length_slots` maps any slot to its
/// epoch. The follower uses it to pick which epoch nonce a block's leader-VRF is checked
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotSchedule {
    /// A known epoch number.
    pub epoch: u64,
    /// The first slot of `epoch`.
    pub epoch_first_slot: u64,
    /// The number of slots in every epoch (constant across the Shelley era).
    pub epoch_length_slots: u64,
}

impl SlotSchedule {
    /// The epoch a slot falls in. Total over all `u64` slots — a colluding elected leader
    /// can sign any slot inside the KES-signed header body, so this must never panic; a
    /// zero `epoch_length_slots` (a caller config error) collapses to the single anchor
    /// epoch rather than dividing by zero.
    pub fn epoch_of(&self, slot: u64) -> u64 {
        let len = self.epoch_length_slots;
        if len == 0 {
            return self.epoch;
        }
        if slot >= self.epoch_first_slot {
            self.epoch
                .saturating_add((slot - self.epoch_first_slot) / len)
        } else {
            // Slots below the anchor: round the distance up so the anchor's own first
            // slot is epoch, one slot earlier is epoch − 1, etc. Computed without
            // `below + len` (which could overflow) via a remainder correction.
            let below = self.epoch_first_slot - slot;
            let epochs_below = below / len + u64::from(!below.is_multiple_of(len));
            self.epoch.saturating_sub(epochs_below)
        }
    }
}

/// The follower's rollback horizon: it retains the last `RING_CAP` accepted blocks' facts
/// so a chain-sync `RollBackward` within this depth can truncate and recompute. Set to
/// Cardano's Ouroboros security parameter k = 2160 — the common-prefix bound — so a fact
/// evicted below it can never be rolled back and is safely finalized. At ~5 fields × 8
/// bytes the ring is well under 200 KB.
const RING_CAP: usize = 2160;

/// One accepted block's read-path facts, retained in the follower's rollback ring. A
/// rollback truncates the ring to the target and the window's facts recompute from the
/// survivors; a fact evicted below `RING_CAP` is finalized into the sticky aggregates
/// (see [`WindowFollower`]).
#[derive(Debug, Clone, Copy)]
struct BlockFact {
    height: u64,
    slot: u64,
    block_hash: [u8; 32],
    created_here: bool,
    spending_txid: Option<[u8; 32]>,
}

/// The follower's verified tip — the linkage parent for the next append and the point the
/// verdict is answered as of. Only the three fields append and verdict read from a header
/// are kept, so a rollback can restore the tip from a retained [`BlockFact`] without a
/// full [`HeaderView`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tip {
    block_number: u64,
    slot: u64,
    block_hash: [u8; 32],
}

/// Which arm a [`WindowFollower::rollback`] target fell in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rollback {
    /// The target is a block still in the fact ring: the accepted run was truncated to end
    /// at it and the window's facts recompute from the survivors (plus the finalized
    /// aggregates). The follower stays live — re-append the target's successors. Carries
    /// the new verified-tip height.
    Truncated {
        /// The verified tip's block number after truncation.
        tip_height: u64,
    },
    /// The target is the follow base — the predecessor the first appended block hung from,
    /// reachable only while the whole window still fits in the ring. The window is empty
    /// again but the follower stays anchored; re-append from the first block. Finalized
    /// aggregates are kept.
    ToBase,
    /// The target is neither in the ring nor the follow base: deeper than the follower
    /// retains, so a rollback beyond the common-prefix horizon the ring covers. The
    /// follower cannot reconstruct the intervening state — its verdict is now
    /// [`crate::window::StallReason::RollbackBeyondWindow`] and the caller must discard it
    /// and restart from a fresh anchor.
    BeyondWindow,
}

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
    /// The epoch nonce for this block's epoch had not been staged via
    /// [`WindowFollower::supply_next_eta0`] when the block arrived — the follower crossed
    /// an epoch boundary before its η0 was supplied. Fail-closed and liveness-only: the
    /// block does not advance the tip, and a later append after the nonce is staged still
    /// succeeds. It has no single-epoch batch counterpart (the batch verifies one epoch
    /// under one supplied nonce), so [`AppendRefusal::as_stall_reason`] maps it to `None`.
    EpochNonceUnavailable,
}

impl AppendRefusal {
    /// The batch [`StallReason`] this refusal corresponds to, when one exists. A decode,
    /// link, or crypto refusal collapses to [`StallReason::BrokenSegment`] — exactly as
    /// [`crate::chain::verify_segment`] collapses a decode/link/opcert/VRF/KES failure —
    /// while a body-side refusal keeps its distinct reason. This is the pinned
    /// equivalence map: a refused append at block *i* corresponds to the batch stalling
    /// over the accepted prefix plus block *i*.
    ///
    /// Returns `None` for [`AppendRefusal::EpochNonceUnavailable`], which is follower-only:
    /// the batch [`crate::window::verify_watched_window`] verifies a single epoch under
    /// one caller-supplied nonce, so it cannot even be run across an epoch turn, and the
    /// equivalence relation does not extend to that refusal.
    pub fn as_stall_reason(self) -> Option<StallReason> {
        match self {
            AppendRefusal::Decode | AppendRefusal::BrokenLink | AppendRefusal::Crypto => {
                Some(StallReason::BrokenSegment)
            }
            AppendRefusal::NotContiguous => Some(StallReason::MissingBlock),
            AppendRefusal::BodyCommitmentMismatch => Some(StallReason::BodyCommitmentMismatch),
            AppendRefusal::MalformedBody => Some(StallReason::MalformedBody),
            AppendRefusal::EpochNonceUnavailable => None,
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
    /// Maps each appended block's slot to its epoch, so the follower selects that epoch's
    /// nonce from `nonces`.
    schedule: SlotSchedule,
    /// Epoch → η0. The verifying nonce for an appended block is looked up by the block's
    /// slot→epoch, never a mutable "current nonce": crossing a boundary is a map read, so
    /// a later rollback below the turn re-selects the earlier epoch's nonce with no
    /// re-staging. `append` only READS this map.
    nonces: BTreeMap<u64, [u8; 32]>,
    /// The last `ring_cap` accepted blocks' facts, oldest→newest. A rollback truncates
    /// this to the target and the window's non-final facts recompute from what survives;
    /// an evicted fact is finalized into the sticky aggregates below.
    ring: VecDeque<BlockFact>,
    /// The ring's capacity — [`RING_CAP`] in production, lowered only in tests to exercise
    /// eviction over the small committed window.
    ring_cap: usize,
    /// The follow base: the predecessor hash the first appended block linked to, pinned at
    /// the first append. It is a legitimate rollback target only while nothing has been
    /// evicted (then it sits exactly one below the oldest retained block); once eviction
    /// has begun it is below the retained region and rolling back to it is beyond-window.
    follow_base: Option<[u8; 32]>,
    /// Set the first time a fact is evicted. Distinguishes a legitimate follow-base
    /// rollback (nothing evicted, the base is one below the oldest retained fact) from a
    /// beyond-window one (eviction has begun, so the base is common-prefix-deep).
    has_evicted: bool,
    /// A creation finalized on eviction, retained forever: a block evicted below the ring
    /// is common-prefix-deep, so rollback never clears it.
    creation_final: Option<u64>,
    /// A spend finalized on eviction, retained forever (see `creation_final`).
    spend_final: Option<ObservedSpend>,
    /// The verified tip: the linkage parent for the next append and the point the verdict
    /// is answered as of. `None` before the first accepted block and after a rollback to
    /// the follow base.
    tip: Option<Tip>,
    /// Poisoned by a rollback deeper than the retained horizon: the verdict is then
    /// [`StallReason::RollbackBeyondWindow`] and the follower must be discarded and
    /// restarted from a fresh anchor.
    beyond_window: bool,
}

impl WindowFollower {
    /// Start following for a spend of `watch`, answered as of a verified tip at or above
    /// `require_through`, inside the Mithril-certified region `anchor`, with epochs laid
    /// out by `schedule`. Stage each epoch's nonce with [`WindowFollower::supply_next_eta0`]
    /// before appending its blocks; a block whose epoch nonce is not yet staged is refused
    /// [`AppendRefusal::EpochNonceUnavailable`].
    pub fn new(
        watch: OutPoint,
        anchor: &CertifiedTransactions,
        require_through: u64,
        schedule: SlotSchedule,
    ) -> Self {
        Self {
            watch,
            anchor_height: anchor.block_number,
            require_through,
            schedule,
            nonces: BTreeMap::new(),
            ring: VecDeque::new(),
            ring_cap: RING_CAP,
            follow_base: None,
            has_evicted: false,
            creation_final: None,
            spend_final: None,
            tip: None,
            beyond_window: false,
        }
    }

    /// Stage the epoch nonce η0 for `epoch`. The follower selects it for any appended
    /// block whose slot the schedule places in `epoch`. Overwritable (idempotent for the
    /// same bytes): a mis-fetched nonce can be corrected before a block is accepted under
    /// it. Overwriting cannot cause a false accept — the nonce is an INPUT to the
    /// leader-VRF check, never a verdict, so a wrong nonce only makes a block fail to
    /// verify (liveness), never verify falsely (safety).
    pub fn supply_next_eta0(&mut self, epoch: u64, eta0: [u8; 32]) {
        self.nonces.insert(epoch, eta0);
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
        match &self.tip {
            Some(prev) => {
                if view.prev_hash != Some(prev.block_hash) {
                    return Err(AppendRefusal::BrokenLink);
                }
                // Checked add: block_number is an attacker-chosen field inside the signed
                // header body, so a u64::MAX tip must refuse its successor fail-closed —
                // never an overflow panic (untrusted bytes never panic, crate-wide).
                if prev.block_number.checked_add(1) != Some(view.block_number) {
                    return Err(AppendRefusal::NotContiguous);
                }
            }
            // First block of the (re-)anchored window. If a follow base was pinned — the
            // follower base-rolled-back and is re-appending from the window start — the
            // re-appended first block MUST link to that base, so the follower cannot be
            // re-anchored onto a different fork. On the very first append there is no base
            // yet (trust starts at the first block), so no link is checked.
            None => {
                if let Some(base) = self.follow_base
                    && view.prev_hash != Some(base)
                {
                    return Err(AppendRefusal::BrokenLink);
                }
            }
        }
        // 3. Select this block's epoch nonce by its slot — a map lookup, never a mutated
        //    "current nonce" (which a rollback below an epoch turn would leave pointing at
        //    the wrong epoch). A missing staged nonce fails closed to a liveness-only
        //    refusal; it never advances the tip. Copy the nonce out so the immutable
        //    borrow of the map ends before the commit mutates `self`.
        let epoch = self.schedule.epoch_of(view.slot);
        let eta0 = *self
            .nonces
            .get(&epoch)
            .ok_or(AppendRefusal::EpochNonceUnavailable)?;
        // 4. Crypto: opcert -> leader-VRF (vs the epoch nonce) -> KES, the shared
        //    per-header unit. The batch collapses opcert/VRF/KES to BrokenSegment too, so
        //    the class, not the inner cause, is what a windowed verdict turns on.
        chain::verify_header(&view, &eta0).map_err(|_| AppendRefusal::Crypto)?;
        // 5. Bind the bodies to the header commitment and scan them, the shared per-block
        //    unit. Its decode cannot fail (step 1 already decoded), but map it fail-closed.
        let facts = scan_block_facts(block, &self.watch).map_err(|e| match e {
            ScanFailure::Decode => AppendRefusal::Decode,
            ScanFailure::BodyCommitmentMismatch => AppendRefusal::BodyCommitmentMismatch,
            ScanFailure::MalformedBody => AppendRefusal::MalformedBody,
        })?;

        // 6. Every check passed: commit. Nothing above mutated `self`, so the follower is
        //    untouched on any refusal. Pin the follow base on the first append (the
        //    predecessor the window hangs from), push this block's fact, and evict +
        //    finalize the oldest if the ring is over capacity.
        if self.follow_base.is_none() {
            self.follow_base = facts.view.prev_hash;
        }
        let fact = BlockFact {
            height: facts.view.block_number,
            slot: facts.view.slot,
            block_hash: facts.view.block_hash,
            created_here: facts.created_here,
            spending_txid: facts.spent_by,
        };
        self.ring.push_back(fact);
        if self.ring.len() > self.ring_cap {
            let evicted = self
                .ring
                .pop_front()
                .expect("a ring over capacity is non-empty");
            self.finalize(evicted);
        }
        self.tip = Some(Tip {
            block_number: fact.height,
            slot: fact.slot,
            block_hash: fact.block_hash,
        });
        Ok(Appended {
            block_number: fact.height,
        })
    }

    /// Fold an evicted fact into the sticky finalized aggregates. A fact evicted below the
    /// ring is `RING_CAP`-deep and common-prefix-immune, so its verdict contribution can
    /// never be rolled back — [`WindowFollower::rollback`] never clears these.
    fn finalize(&mut self, evicted: BlockFact) {
        self.has_evicted = true;
        if evicted.created_here {
            self.creation_final.get_or_insert(evicted.height);
        }
        if let Some(spending_txid) = evicted.spending_txid {
            self.spend_final.get_or_insert(ObservedSpend {
                at_height: evicted.height,
                at_slot: evicted.slot,
                spending_txid,
            });
        }
    }

    /// Roll the follower back to the point `(slot, hash)` — a chain-sync `RollBackward`.
    /// The 32-byte `hash` is the authoritative block identifier; `slot` accompanies it for
    /// chain-sync `Point` fidelity. Three arms (see [`Rollback`]): a target still in the
    /// fact ring truncates the accepted run to it; the follow base empties the window but
    /// keeps the follower anchored; anything deeper poisons the follower fail-closed. A
    /// rollback never clears the finalized aggregates or the nonce map.
    pub fn rollback(&mut self, _slot: u64, hash: &[u8; 32]) -> Rollback {
        // In-ring: truncate the accepted run to end at the target and restore the tip from
        // its retained fact. The survivors stay contiguous (a truncated prefix of a
        // contiguous run), so the window's facts recompute correctly from them + finals.
        if let Some(pos) = self.ring.iter().position(|f| &f.block_hash == hash) {
            self.ring.truncate(pos + 1);
            let tail = *self.ring.back().expect("the truncated ring is non-empty");
            self.tip = Some(Tip {
                block_number: tail.height,
                slot: tail.slot,
                block_hash: tail.block_hash,
            });
            return Rollback::Truncated {
                tip_height: tail.height,
            };
        }
        // The follow base — reachable only while nothing has been evicted (then it sits
        // exactly one below the oldest retained fact). Empty the window but stay anchored:
        // the finalized aggregates are kept (they are common-prefix-deep either way).
        if !self.has_evicted && self.follow_base == Some(*hash) {
            self.ring.clear();
            self.tip = None;
            return Rollback::ToBase;
        }
        // Deeper than retained: below the ring and not the base, i.e. deeper than the
        // common-prefix horizon the ring covers. The follower cannot reconstruct the
        // intervening facts — fail closed and require a restart.
        self.beyond_window = true;
        Rollback::BeyondWindow
    }

    /// The first observed spend across the finalized aggregate and the ring, if any. The
    /// finalized spend (if present) is deeper than every ring fact, so it is the earliest;
    /// otherwise the earliest ring fact carrying a spend. An outpoint is spent at most once
    /// on a chain, so there is never a conflicting pair.
    fn effective_spend(&self) -> Option<ObservedSpend> {
        if let Some(spend) = self.spend_final {
            return Some(spend);
        }
        self.ring.iter().find_map(|f| {
            f.spending_txid.map(|spending_txid| ObservedSpend {
                at_height: f.height,
                at_slot: f.slot,
                spending_txid,
            })
        })
    }

    /// Whether the watched outpoint's creation has been observed — finalized on eviction or
    /// still in the ring.
    fn effective_create_seen(&self) -> bool {
        self.creation_final.is_some() || self.ring.iter().any(|f| f.created_here)
    }

    /// The current three-valued windowed verdict, answered as of the verified tip under
    /// the caller's `freshness` bound. Mirrors the batch's terminal decision exactly: a
    /// recorded spend is a definite [`WatchVerdict::SpentObserved`]; otherwise the run
    /// must have observed the outpoint's creation, reached `require_through`, stayed at
    /// or below the certified anchor, and be fresh, or it is a distinct-reason
    /// [`WatchVerdict::Stalled`] — never a false [`WatchVerdict::Unspent`].
    pub fn verdict(&self, freshness: Freshness) -> WatchVerdict {
        // A beyond-window rollback poisons the follower: it can no longer reconstruct its
        // window, so it refuses fail-closed until the caller discards it. Checked first so
        // even a finalized spend cannot mask that the follower is unusable.
        if self.beyond_window {
            let verified_through = self.tip.map_or(0, |t| t.block_number);
            return stalled(verified_through, StallReason::RollbackBeyondWindow);
        }
        if let Some(spend) = self.effective_spend() {
            return WatchVerdict::SpentObserved {
                at_height: spend.at_height,
                at_slot: spend.at_slot,
                spending_txid: spend.spending_txid,
            };
        }
        let Some(tip) = self.tip else {
            // No verified tip to answer as of: a follower that base-rolled-back stays
            // anchored (a follow base is pinned) but has not re-observed creation, distinct
            // from a fresh follower that never appended (EmptyWindow).
            let reason = if self.follow_base.is_some() {
                StallReason::CreationNotObserved
            } else {
                StallReason::EmptyWindow
            };
            return stalled(0, reason);
        };
        // Contiguity is enforced per append (hash link + checked number+1) and preserved by
        // truncation (a prefix of a contiguous run is contiguous), so every accepted run
        // also satisfies the batch's terminal contiguity check.
        if !self.effective_create_seen() {
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

    /// Preprod Shelley slot schedule: epoch 300 begins at slot 127_958_400 and every
    /// epoch is 432_000 slots. Places every committed vector's slot in its real epoch.
    fn preprod_schedule() -> SlotSchedule {
        SlotSchedule {
            epoch: 300,
            epoch_first_slot: 127_958_400,
            epoch_length_slots: 432_000,
        }
    }

    /// The real epoch-300 Mithril-certified transactions anchor.
    fn anchor() -> CertifiedTransactions {
        CertifiedTransactions {
            merkle_root: String::new(),
            epoch: 300,
            block_number: 4_927_469,
        }
    }

    /// A watch outpoint the committed vectors never create or spend — these tests
    /// exercise contiguity and epoch-aware nonce selection, not the spend scan.
    fn dummy_watch() -> OutPoint {
        OutPoint {
            tx_id: [0u8; 32],
            index: 0,
        }
    }

    /// The transaction created in the preprod window's first block (4921916): its `#1`
    /// output is spent in block[1] (4921917).
    fn beaa9166() -> [u8; 32] {
        hex::decode("beaa9166c061e56457b5d84de4b3d15c9386b202d2585ff247f47af0dcd32a5e")
            .expect("hex")
            .try_into()
            .expect("32 bytes")
    }

    /// Load every `<prefix>-<slot>.block` with its `.eta0` sidecar, ordered by slot.
    fn load_run(prefix: &str) -> Vec<(u64, Vec<u8>, [u8; 32])> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
        let mut rows: Vec<(u64, Vec<u8>, [u8; 32])> = Vec::new();
        for entry in fs::read_dir(&dir).expect("read vectors dir") {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if !name.starts_with(prefix)
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
        rows
    }

    /// The two lowest preprod window blocks (4921916, 4921917) and their shared epoch-300
    /// nonce.
    fn first_two_blocks_and_eta0() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let rows = load_run("preprod-");
        let eta0 = rows[0].2;
        assert_eq!(rows[1].2, eta0, "one epoch, one nonce");
        (rows[0].1.clone(), rows[1].1.clone(), eta0)
    }

    /// A preprod-window follower (single epoch 300) with `eta0` staged for it.
    fn preprod_follower(watch: OutPoint, eta0: [u8; 32]) -> WindowFollower {
        let mut f = WindowFollower::new(watch, &anchor(), 4_921_937, preprod_schedule());
        f.supply_next_eta0(300, eta0);
        f
    }

    /// The schedule maps each slot to its epoch: the anchor's first slot is its epoch, one
    /// slot earlier is the previous epoch, and it is total (never panics) over all `u64`
    /// slots — a colluding leader can sign any slot inside the KES-signed header body.
    #[test]
    fn slot_schedule_maps_slots_to_epochs() {
        let s = preprod_schedule();
        assert_eq!(
            s.epoch_of(127_958_400),
            300,
            "the anchor's first slot is its epoch"
        );
        assert_eq!(
            s.epoch_of(127_958_399),
            299,
            "one slot before the anchor is the prior epoch"
        );
        assert_eq!(
            s.epoch_of(127_958_400 + 432_000 - 1),
            300,
            "the anchor epoch's last slot"
        );
        assert_eq!(
            s.epoch_of(127_958_400 + 432_000),
            301,
            "the next epoch's first slot"
        );
        assert_eq!(
            s.epoch_of(127_958_400 - 432_000),
            299,
            "the prior epoch's first slot"
        );
        assert_eq!(
            s.epoch_of(127_958_400 - 432_000 - 1),
            298,
            "two epochs back"
        );
        // Real vector slots: the boundary run's pre side is epoch 299, post side 300.
        assert_eq!(s.epoch_of(127_958_384), 299);
        assert_eq!(s.epoch_of(127_958_489), 300);
        // Totality: no panic at the u64 extremes, and a zero-length schedule never divides
        // by zero (it collapses to the anchor epoch).
        let _ = s.epoch_of(0);
        let _ = s.epoch_of(u64::MAX);
        let degenerate = SlotSchedule {
            epoch: 5,
            epoch_first_slot: 10,
            epoch_length_slots: 0,
        };
        assert_eq!(degenerate.epoch_of(u64::MAX), 5);
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
        let mut follower = preprod_follower(dummy_watch(), eta0);
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
            Some(StallReason::MissingBlock),
            "the refusal maps to the batch oracle's contiguity stall",
        );
    }

    /// The contiguity comparison at the numeric boundary: a colluding leader can sign a
    /// header carrying `block_number == u64::MAX` (the number is an attacker-chosen
    /// field inside the KES-signed header body), and the follower's next append must
    /// refuse it fail-CLOSED — never panic on the `+1` (untrusted bytes never panic,
    /// crate-wide) and never wrap to a comparison the batch oracle would not make.
    #[test]
    fn tip_at_u64_max_refuses_the_next_append_without_panicking() {
        let (b0, b1, eta0) = first_two_blocks_and_eta0();
        let mut follower = preprod_follower(dummy_watch(), eta0);
        follower.append(&b0).expect("the first block is accepted");
        follower
            .tip
            .as_mut()
            .expect("tip set after the first append")
            .block_number = u64::MAX;
        assert_eq!(
            follower.append(&b1),
            Err(AppendRefusal::NotContiguous),
            "a u64::MAX tip must refuse the successor fail-closed, not overflow",
        );
    }

    /// The F2 critique fix, end to end: the nonce map survives a rollback below an epoch
    /// turn, so re-appending the post-turn side needs NO re-staging. A mutated
    /// "current nonce" would be left pointing at the later epoch after the cross, so the
    /// re-appended post-turn blocks would still verify — but the pre-turn blocks would
    /// not; the map design keeps selection per-block (by slot), so a rollback cannot
    /// desynchronise it. `append` also never mutates the map (asserted here), so nonce
    /// state is independent of the block-tracking state a rollback truncates.
    ///
    /// The dummy watch is never created or spent in the run, so a rollback below the turn
    /// reduces to resetting the tip to the last pre-turn header (F3 adds the general
    /// fact-ring rollback); the property under test is the nonce map's durability.
    #[test]
    fn rollback_below_the_turn_re_appends_without_re_staging() {
        let run = load_run("boundary-");
        assert!(run.len() >= 4, "the run must straddle the turn");
        let schedule = preprod_schedule();
        let pre_epoch = schedule.epoch_of(run.first().unwrap().0);
        let post_epoch = pre_epoch + 1;

        let mut follower = WindowFollower::new(dummy_watch(), &anchor(), 0, schedule);
        for (slot, _, eta0) in &run {
            follower.supply_next_eta0(schedule.epoch_of(*slot), *eta0);
        }
        // Cross the boundary: every block accepted, each under its own epoch nonce.
        for (slot, bytes, _) in &run {
            follower
                .append(bytes)
                .unwrap_or_else(|e| panic!("block at slot {slot} accepted, got {e:?}"));
        }
        let nonces_after_cross = follower.nonces.clone();

        // Roll back below the turn to the last pre-turn block (still in the ring): a real
        // in-ring rollback, truncating the post-turn side off the accepted run.
        let last_pre = run
            .iter()
            .rev()
            .find(|(slot, _, _)| schedule.epoch_of(*slot) == pre_epoch)
            .expect("a pre-turn block exists");
        let last_pre_view = HeaderView::from_block_cbor(&last_pre.1).expect("decode");
        assert_eq!(
            follower.rollback(last_pre_view.slot, &last_pre_view.block_hash),
            Rollback::Truncated {
                tip_height: last_pre_view.block_number
            },
        );

        // Re-append every post-turn block with NO re-staging — selection is by slot, so
        // each still picks η0(post) and verifies.
        for (slot, bytes, _) in run
            .iter()
            .filter(|(s, _, _)| schedule.epoch_of(*s) == post_epoch)
        {
            follower
                .append(bytes)
                .unwrap_or_else(|e| panic!("post-turn block at slot {slot} re-appends, got {e:?}"));
        }
        assert_eq!(
            follower.nonces, nonces_after_cross,
            "rollback and append never mutated the nonce map across the cross or the re-append",
        );
    }

    /// Eviction IS finalization: with a tiny test-only ring cap, a spend observed early in
    /// the window is evicted below the cap as the window grows — and because a fact
    /// evicted `ring_cap`-deep is rollback-immune (Ouroboros common prefix), eviction
    /// folds it into the sticky `spend_final`/`creation_final` aggregates rollback never
    /// clears. So `SpentObserved` survives even though the spend's own fact is long gone
    /// from the ring. Watches beaa9166…#1 (created in block[0], spent in block[1]).
    #[test]
    fn eviction_finalizes_a_spend_that_survives_the_ring_cap() {
        let watch = OutPoint {
            tx_id: beaa9166(),
            index: 1,
        };
        let rows = load_run("preprod-");
        assert!(rows.len() >= 20, "expected the 22-block window");
        let eta0 = rows[0].2;
        let mut follower = WindowFollower::new(watch, &anchor(), 4_921_937, preprod_schedule());
        follower.supply_next_eta0(300, eta0);
        // Force eviction long before the 22-block window ends: block[1]'s spend fact is
        // evicted once four newer blocks have been appended over it.
        follower.ring_cap = 4;
        for (slot, bytes, _) in &rows {
            follower
                .append(bytes)
                .unwrap_or_else(|e| panic!("block at slot {slot} accepted, got {e:?}"));
        }

        // The spend (block[1]) and creation (block[0]) were finalized on eviction; their
        // facts have left the small ring entirely.
        assert_eq!(
            follower.creation_final,
            Some(4_921_916),
            "the creation was finalized when block[0] was evicted",
        );
        assert!(
            follower.spend_final.is_some(),
            "the spend was finalized when block[1] was evicted",
        );
        assert!(
            follower.ring.iter().all(|f| f.spending_txid.is_none()),
            "the spend fact is no longer in the ring — the verdict rests on the finalized aggregate",
        );

        let fresh = Freshness {
            slot_now: 128_046_016 + 60,
            max_lag: 100_000,
        };
        assert!(
            matches!(
                follower.verdict(fresh),
                WatchVerdict::SpentObserved {
                    at_height: 4_921_917,
                    ..
                }
            ),
            "SpentObserved survives eviction of the spending block's fact",
        );

        // Batch-equivalence holds even under eviction: the small-cap follower's terminal
        // verdict equals the batch (which never evicts — it re-scans the whole window).
        let blocks: Vec<Vec<u8>> = rows.iter().map(|(_, bytes, _)| bytes.clone()).collect();
        assert_eq!(
            follower.verdict(fresh),
            crate::window::verify_watched_window(
                watch,
                &anchor(),
                4_921_937,
                &blocks,
                &eta0,
                fresh
            ),
            "eviction-as-finalization preserves the batch equivalence",
        );
    }
}
