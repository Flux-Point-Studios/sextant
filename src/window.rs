//! Body-commitment binding for the read path.
//!
//! [`crate::chain::verify_segment`] authenticates block *headers*. The spend
//! signal a windowed-unspent verdict scans lives in the transaction *bodies*,
//! which a header does not itself carry — so a hostile provider could hand
//! authentic, hash-linked headers with SWAPPED bodies and a naive scan would read
//! a false verdict. This module closes that gap: it recomputes the header's
//! `block_body_hash` commitment from a block's four raw body segments and requires
//! it to match, binding the scanned bodies to the header-verified chain.
//!
//! ## The bytes are hashed verbatim
//! Cardano block CBOR is non-canonical, so the four segments are hashed exactly as
//! they appear on the wire (captured as byte ranges in [`crate::header::HeaderView::decode_block`]),
//! never re-encoded — the same discipline the header KES path follows for the
//! header body it signs.
//!
//! ## Windowed-unspent verdict ([`verify_watched_window`])
//! Cardano commits to no UTxO-set root, so *absolute* unspent is unprovable. The
//! honest read is *windowed*: no input spending the watched outpoint appears in any
//! body of a header-verified, hash-linked, gap-free, body-committed segment that
//! observed the outpoint's creation and reached the caller's required coverage height
//! — under Mithril-quorum + data-completeness, as of the verified tip.
//!
//! Two evasions a hostile provider can attempt, and how each is closed: (1) *drop a
//! block inside the window* — the hash chain breaks, so it collapses to
//! [`WatchVerdict::Stalled`]; (2) *truncate the window one block before the spend* —
//! nothing in the chain forbids a short window, so the caller MUST assert a hard lower
//! bound (`require_through`) on the tip it is answered as of; a window that does not
//! reach it is [`StallReason::WindowTooShort`], never a false [`WatchVerdict::Unspent`].
//! Freshness alone cannot close (2): the `max_lag` needed to admit the honestly
//! tip-trailing Mithril window also admits a spend hidden just under the tip.

use core::ops::Range;

use minicbor::Decoder;

use crate::chain::{self, ChainError};
use crate::hash::blake2b256;
use crate::header::{BlockBodySpans, DecodeError, HeaderView};
use crate::inclusion::verify_tx_inclusion;
use crate::utxo::{CertifiedTransactions, OutPoint, decode_spends, output_exists};

/// Why a block's transaction bodies did not bind to its header commitment.
/// Untrusted bytes make every failure an ordinary recoverable outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The block CBOR did not decode as a Praos block.
    Decode(DecodeError),
    /// The recomputed `hashAlonzoSegWits` did not equal the header's committed
    /// `block_body_hash`: the bodies were swapped, tampered, or truncated.
    BodyCommitmentMismatch,
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BindError::Decode(e) => write!(f, "{e}"),
            BindError::BodyCommitmentMismatch => {
                f.write_str("block body does not hash to its header commitment")
            }
        }
    }
}

impl std::error::Error for BindError {}

/// Verify that a block's transaction bodies are the ones its header commits to,
/// and return the decoded [`HeaderView`]. The recomputed body commitment must
/// equal header_body index 7; any mismatch — swapped or tampered bodies — is
/// rejected before the bodies are trusted for a spend scan.
///
/// This is the load-bearing bind for a windowed spend scan: only once a block's
/// bodies are bound to a header-verified, hash-linked chain is a
/// [`crate::utxo::decode_spends`] over those bodies trustworthy evidence.
pub fn verify_body_commitment(block_bytes: &[u8]) -> Result<HeaderView, BindError> {
    let (view, spans) = HeaderView::decode_block(block_bytes).map_err(BindError::Decode)?;
    if hash_alonzo_seg_wits(block_bytes, &spans) != view.block_body_hash {
        return Err(BindError::BodyCommitmentMismatch);
    }
    Ok(view)
}

/// Recompute the segregated-witness block body hash from the raw body spans, per
/// cardano-ledger's `hashAlonzoTxSeq`: the outer Blake2b-256 over the four inner
/// segment hashes concatenated in block order —
/// `blake2b256( blake2b256(tx_bodies) ‖ blake2b256(tx_witness_sets) ‖
/// blake2b256(auxiliary_data) ‖ blake2b256(invalid_transactions) )`.
pub(crate) fn hash_alonzo_seg_wits(block_bytes: &[u8], spans: &BlockBodySpans) -> [u8; 32] {
    let mut preimage = [0u8; 128];
    preimage[0..32].copy_from_slice(&blake2b256(&block_bytes[spans.tx_bodies.clone()]));
    preimage[32..64].copy_from_slice(&blake2b256(&block_bytes[spans.tx_witness_sets.clone()]));
    preimage[64..96].copy_from_slice(&blake2b256(&block_bytes[spans.auxiliary_data.clone()]));
    preimage[96..128].copy_from_slice(&blake2b256(
        &block_bytes[spans.invalid_transactions.clone()],
    ));
    blake2b256(&preimage)
}

/// The read-path facts a single block contributes to a windowed spend scan: its
/// decoded header, whether it created the watched outpoint, and — if it spent it —
/// the id of the spending transaction.
///
/// The shared per-block scan unit: the batch [`verify_watched_window`] and the
/// incremental [`crate::follow::WindowFollower`] both extract a block's facts through
/// [`scan_block_facts`], so the follower is a faithful incremental form of the frozen
/// batch oracle rather than a parallel re-implementation.
pub(crate) struct BlockFacts {
    /// The block's decoded, body-committed header view.
    pub view: HeaderView,
    /// Whether the watched outpoint's creating transaction, producing an output at the
    /// watched index, appears in this block.
    pub created_here: bool,
    /// The spending transaction id, if a transaction in this block consumes the
    /// watched outpoint.
    pub spent_by: Option<[u8; 32]>,
}

/// Why [`scan_block_facts`] could not extract a block's facts. These are the body-side
/// failures only; a header link/crypto failure is a separate concern the caller checks
/// via [`crate::chain::verify_header`].
pub(crate) enum ScanFailure {
    /// The block CBOR did not decode as a Praos block.
    Decode,
    /// The bodies did not hash to the header's `block_body_hash` commitment.
    BodyCommitmentMismatch,
    /// A body was not a decodable transaction — a producer cannot hide a spend behind
    /// a malformed body; the scan fails closed.
    MalformedBody,
}

/// Bind a block's bodies to its header commitment, then scan them for the watched
/// outpoint's creation and any spend of it. Returns the block's [`BlockFacts`] or the
/// body-side failure that stopped the scan; does no header link/crypto check.
pub(crate) fn scan_block_facts(block: &[u8], watch: &OutPoint) -> Result<BlockFacts, ScanFailure> {
    let (view, spans) = HeaderView::decode_block(block).map_err(|_| ScanFailure::Decode)?;
    if hash_alonzo_seg_wits(block, &spans) != view.block_body_hash {
        return Err(ScanFailure::BodyCommitmentMismatch);
    }
    let body_spans =
        tx_body_spans(block, &spans.tx_bodies).map_err(|()| ScanFailure::MalformedBody)?;
    let mut created_here = false;
    for body in body_spans {
        let tx = &block[body];
        let txid = blake2b256(tx);
        // Creation is observed only when the creating transaction actually produced an
        // output at the watched index — a phantom index is never read as created.
        if txid == watch.tx_id && output_exists(tx, watch.index as usize).unwrap_or(false) {
            created_here = true;
        }
        let spends = decode_spends(tx).map_err(|_| ScanFailure::MalformedBody)?;
        if spends.contains(watch) {
            return Ok(BlockFacts {
                view,
                created_here,
                spent_by: Some(txid),
            });
        }
    }
    Ok(BlockFacts {
        view,
        created_here,
        spent_by: None,
    })
}

/// The assumptions a windowed-unspent verdict rests on. Both are MANDATORY
/// (non-`Option`) data, not a docstring: an [`WatchVerdict::Unspent`] cannot be
/// constructed without stamping the scope it holds under, so a consumer always sees
/// the trust basis and a reviewer checks a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowAssumptions {
    /// The verified tip is at or below the certified anchor height, so the run lies in
    /// the region a Mithril quorum certified. This is an assumption Sextant SURFACES,
    /// not one it checks per block: it verifies each header's authorship (opcert +
    /// leader-VRF + KES), the hash links, and the height bound, but it does NOT bind
    /// each served block to the certified transaction root, and the read path holds no
    /// stake distribution to check leader eligibility against. So a provider colluding
    /// with a registered block producer could serve a valid-header chain that omits a
    /// spend, or stamps a recent slot on a stale run — and `as_of_slot` freshness rests
    /// on the same assumption. The cryptographic closure is per-block binding to the
    /// certified set (a Tier-2 UTxO-set commitment); until then this bit means only
    /// "trust the served chain is the certified one", surfaced so a consumer weighs it.
    pub mithril_quorum: bool,
    /// The scanned segment is a header-verified, hash-linked, gap-free, body-committed
    /// run — a complete body stream over the window with no admitted gap.
    pub data_complete: bool,
}

/// The trust basis an [`WatchVerdict::Unspent`] rests on. Today there is exactly one:
/// [`WatchBasis::WatchedWindow`], a header-verified, body-committed, gap-free window
/// under [`WindowAssumptions`]. `#[non_exhaustive]` so a future stronger WATCH basis
/// is additive and an external `match` can never silently read a new basis as a
/// windowed scan.
///
/// The full cross-operation trust-tier ladder (this windowed basis, then a
/// cryptographic ledger-state tier, then an economic attested tier) is documented in
/// ONE place — [`crate::utxo::SpendStatus`] — not re-enumerated here; a stronger tier,
/// when it exists, surfaces as a new variant there and (if it can be established over a
/// watch) as a new variant here, never as a silent coercion of `WatchedWindow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WatchBasis {
    /// No spend of the watched outpoint observed across a verified window, under the
    /// stamped assumptions.
    WatchedWindow(WindowAssumptions),
}

/// The verified tip a windowed verdict is *as of* — it travels with every `Unspent`
/// so no caller reads a windowed scan as current tip state. There is deliberately NO
/// `now` field: the read path has no notion of the present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedTip {
    /// The Mithril-certified height the window is anchored to (`certified_at`).
    pub anchor_height: u64,
    /// The verified tip's block number the verdict is stamped as of.
    pub as_of_height: u64,
    /// The verified tip's slot the verdict is stamped as of.
    pub as_of_slot: u64,
}

/// Why a windowed spend check is a NON-answer. Every non-ideal condition lands here,
/// so a gap or stall can never be mistaken for an [`WatchVerdict::Unspent`].
/// `#[non_exhaustive]` so new stall causes stay additive at the consumer boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StallReason {
    /// The window carried no blocks — no verified tip to answer as of.
    EmptyWindow,
    /// The header segment did not verify (broken link, crypto, or decode) — the
    /// withheld-block evasion collapses here.
    BrokenSegment,
    /// A block's bodies did not hash to its header's `block_body_hash` commitment:
    /// real headers with swapped or tampered bodies.
    BodyCommitmentMismatch,
    /// A block's body stream was not a decodable transaction sequence — a producer
    /// cannot hide a spend behind a malformed body; the scan fails closed.
    MalformedBody,
    /// The verified block numbers were not contiguous over the window
    /// (`tip − start + 1 ≠ len`).
    MissingBlock,
    /// The watched outpoint's creation was not observed inside the window — the
    /// "start the window after the spend" evasion.
    CreationNotObserved,
    /// The verified tip did not reach the caller's required coverage height — the
    /// "truncate the window one block before the spend" evasion. Freshness alone
    /// cannot close it: a loose enough `max_lag` to admit the honestly ~100-block-
    /// trailing Mithril window also admits a spend hidden just under the tip, so the
    /// caller MUST assert a hard lower bound on the tip it is answered as of.
    WindowTooShort,
    /// The window tip is above the certified anchor height: outside the
    /// Mithril-vouched region, so data-completeness is not quorum-backed.
    TipAboveAnchor,
    /// The verified tip is older than the caller's freshness bound.
    TipTooOld,
    /// An incremental follower ([`crate::follow::WindowFollower`]) was rolled back to a
    /// point deeper than the horizon it retains — neither a block still in its fact ring
    /// nor its follow base — so it cannot reconstruct the intervening state. Fail-closed:
    /// the follower must be discarded and restarted from a fresh anchor. The batch
    /// [`verify_watched_window`] never produces this (it re-verifies a whole window each
    /// call and never rolls back); it is a follower-only stall.
    RollbackBeyondWindow,
}

/// The caller's recency bound for a windowed verdict. Sextant proves "no spend through
/// the verified tip"; only the caller knows how stale is too stale for its economics,
/// so it supplies its own clock estimate and tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Freshness {
    /// The caller's current-slot estimate (from its own clock).
    pub slot_now: u64,
    /// The maximum slot lag the caller tolerates between `slot_now` and the tip.
    pub max_lag: u64,
}

/// Which trust region a spend of the watched outpoint was observed in — the two-region
/// honesty a definite [`WatchVerdict::SpentObserved`] carries.
///
/// A spend seen in a header-verified, hash-linked, body-committed window is
/// [`SpendRegion::HeaderVouched`] by default: the block's authorship (opcert +
/// leader-VRF + KES), its hash link, and its body commitment are all verified, but the
/// block is NOT bound to the Mithril-certified transaction set — so, exactly like the
/// [`WindowAssumptions::mithril_quorum`] a no-spend verdict rests on, a colluding
/// registered block producer could in principle have forged it. It becomes
/// [`SpendRegion::MithrilCertified`] ONLY when the spending transaction is proven a
/// member of the genesis-anchored certified set by a verified inclusion proof against
/// the certified Merkle root (see [`certify_spend_region`]).
///
/// Height NEVER upgrades a spend: a valid orphaned sibling block below the certified
/// anchor height is not the certified chain, so a spend's certified-region status is a
/// cryptographic fact about set membership, never a height comparison.
/// `#[non_exhaustive]` so a future region refinement stays additive at the consumer
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpendRegion {
    /// The spending transaction is proven a member of the genesis-anchored
    /// Mithril-certified transaction set (a verified inclusion proof recomputing to the
    /// certified Merkle root). Quorum-backed: unforgeable without breaking Mithril.
    MithrilCertified,
    /// The spend was observed in a header-verified, hash-linked, body-committed block
    /// that is NOT bound to the Mithril-certified set. Authoritative against the verified
    /// window, but rests on the surfaced `mithril_quorum` assumption — not quorum-backed.
    HeaderVouched,
}

/// The verdict of a windowed spend check. Three terminal shapes, and only one is
/// `Unspent`: collapsing `SpentObserved` (a definite refuse) into `Stalled` (a
/// non-answer), or either into `Unspent`, is the cardinal honesty failure this type
/// forbids by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchVerdict {
    /// No input spending the watched outpoint appeared in any body of the verified
    /// window, whose creation it observed — as of `as_of`, under `basis`. NOT absolute
    /// / eternal / tip-state unspent.
    Unspent {
        /// The verified tip this holds as of, and the certified anchor it rests on.
        as_of: WatchedTip,
        /// The trust basis, carrying the surfaced assumptions.
        basis: WatchBasis,
    },
    /// A verified, body-committed block in the window spends the watched outpoint — a
    /// definite refuse. Authoritative against the verified window regardless of
    /// freshness; whether that authority is Mithril-quorum-backed or merely
    /// header-vouched is carried in `region` (see [`SpendRegion`]). A `HeaderVouched`
    /// spend rests on the same `mithril_quorum` assumption a no-spend verdict does; only
    /// a `MithrilCertified` spend is authoritative independent of that assumption.
    SpentObserved {
        /// The block number the spend was observed in.
        at_height: u64,
        /// The slot the spend was observed at.
        at_slot: u64,
        /// The id of the transaction that consumed the outpoint.
        spending_txid: [u8; 32],
        /// Which trust region the spend was observed in.
        region: SpendRegion,
    },
    /// The window could not answer: a gap, a failed body-commitment, an unverified
    /// segment, an unobserved creation, or a stale tip. A non-answer is a REFUSE.
    Stalled {
        /// The highest block number the window verified through before stalling.
        verified_through: u64,
        /// Why the window could not answer.
        reason: StallReason,
    },
}

/// Verify whether `watch` is spent across a certified, header-verified window.
///
/// Composes the read path's proven primitives into one bytes-in / verdict-out flow:
/// [`chain::verify_segment`] (headers authentic, hash-linked, gap-free, one epoch) →
/// per-block [`verify_body_commitment`] (the scanned bodies bind to the verified
/// headers) → [`crate::utxo::decode_spends`] per transaction (the forward spend
/// signal). `anchor` is the Mithril-certified transactions commitment the window rests
/// on (its `block_number` is the certified height); `eta0` is the segment's epoch
/// nonce; `freshness` is the caller's recency bound.
///
/// `require_through` is the caller's HARD lower bound on the verified tip: the window's
/// tip block number MUST be at least this, or the verdict is [`StallReason::WindowTooShort`].
/// It closes the truncation evasion — a provider serving a valid window that simply ends
/// before the spend. The caller sets it to the height it needs no-spend coverage through
/// (e.g. a recent tip estimate, or the certified anchor height for a fully-quorum-backed
/// window); Sextant then proves "no spend through `as_of >= require_through`".
///
/// FAIL-CLOSED: any gap, broken link, body-commitment mismatch, unobserved creation, a tip
/// short of `require_through`, a tip above the anchor, or a stale tip yields
/// [`WatchVerdict::Stalled`], NEVER a false [`WatchVerdict::Unspent`]. A spend observed in
/// the window is a definite [`WatchVerdict::SpentObserved`], returned as soon as it is seen.
pub fn verify_watched_window(
    watch: OutPoint,
    anchor: &CertifiedTransactions,
    require_through: u64,
    blocks: &[impl AsRef<[u8]>],
    eta0: &[u8; 32],
    freshness: Freshness,
) -> WatchVerdict {
    if blocks.is_empty() {
        return stalled(0, StallReason::EmptyWindow);
    }

    // 1. Headers authentic, hash-linked, gap-free, single-epoch. A follower that
    //    cannot advance a verified tip past a withheld block lands here, never Unspent.
    if let Err(e) = chain::verify_segment(blocks, eta0) {
        let idx = match &e {
            ChainError::Decode { index, .. }
            | ChainError::BrokenLink { index }
            | ChainError::OpCert { index, .. }
            | ChainError::Vrf { index, .. }
            | ChainError::Kes { index, .. } => *index,
        };
        let verified_through = idx
            .checked_sub(1)
            .and_then(|j| blocks.get(j))
            .and_then(|b| HeaderView::from_block_cbor(b.as_ref()).ok())
            .map_or(0, |v| v.block_number);
        return stalled(verified_through, StallReason::BrokenSegment);
    }

    // 2. Per block, in order: bind the bodies to the header commitment, then scan the
    //    bound bodies for the outpoint's creation or a spend of it, through the same
    //    per-block unit the incremental follower uses.
    let mut start_number: Option<u64> = None;
    let mut verified_through: u64 = 0;
    let mut tip: Option<HeaderView> = None;
    let mut create_seen = false;

    for block in blocks {
        // verify_segment already decoded every header, so a decode failure here is
        // impossible; fail closed to BrokenSegment rather than panic on an impossible
        // re-decode, exactly as before.
        let facts = match scan_block_facts(block.as_ref(), &watch) {
            Ok(facts) => facts,
            Err(ScanFailure::Decode) => {
                return stalled(verified_through, StallReason::BrokenSegment);
            }
            Err(ScanFailure::BodyCommitmentMismatch) => {
                return stalled(verified_through, StallReason::BodyCommitmentMismatch);
            }
            Err(ScanFailure::MalformedBody) => {
                return stalled(verified_through, StallReason::MalformedBody);
            }
        };
        if facts.created_here {
            create_seen = true;
        }
        if let Some(spending_txid) = facts.spent_by {
            // The batch binds no served block to the certified transaction set, so it
            // never upgrades a spend past HeaderVouched; the follower does, on an
            // inclusion proof supplied at re-anchor (see [`certify_spend_region`]).
            return WatchVerdict::SpentObserved {
                at_height: facts.view.block_number,
                at_slot: facts.view.slot,
                spending_txid,
                region: SpendRegion::HeaderVouched,
            };
        }
        start_number.get_or_insert(facts.view.block_number);
        verified_through = facts.view.block_number;
        tip = Some(facts.view);
    }

    // 3. No spend observed. Require a gap-free run that observed the outpoint's
    //    creation, sits in the certified region, and is fresh — else a non-answer.
    let (Some(tip), Some(start_number)) = (tip, start_number) else {
        return stalled(verified_through, StallReason::EmptyWindow);
    };
    let contiguous =
        tip.block_number.checked_sub(start_number).map(|d| d + 1) == Some(blocks.len() as u64);
    if !contiguous {
        return stalled(verified_through, StallReason::MissingBlock);
    }
    if !create_seen {
        return stalled(verified_through, StallReason::CreationNotObserved);
    }
    // The tip must reach the caller's required coverage height — else a provider hides
    // a spend by ending the window just under it (freshness is a soft floor only).
    if tip.block_number < require_through {
        return stalled(verified_through, StallReason::WindowTooShort);
    }
    if tip.block_number > anchor.block_number {
        return stalled(verified_through, StallReason::TipAboveAnchor);
    }
    if freshness.slot_now.saturating_sub(tip.slot) > freshness.max_lag {
        return stalled(verified_through, StallReason::TipTooOld);
    }
    WatchVerdict::Unspent {
        as_of: WatchedTip {
            anchor_height: anchor.block_number,
            as_of_height: tip.block_number,
            as_of_slot: tip.slot,
        },
        basis: WatchBasis::WatchedWindow(WindowAssumptions {
            mithril_quorum: true,
            data_complete: true,
        }),
    }
}

/// Build a `Stalled` verdict — a non-answer carrying how far the window verified.
fn stalled(verified_through: u64, reason: StallReason) -> WatchVerdict {
    WatchVerdict::Stalled {
        verified_through,
        reason,
    }
}

/// Classify the trust region a spend belongs to. Returns [`SpendRegion::MithrilCertified`]
/// iff `proof_hex` is a valid Mithril inclusion proof of `spending_txid` that recomputes
/// to `anchor`'s certified transaction Merkle root — the ONLY thing that upgrades a spend
/// out of [`SpendRegion::HeaderVouched`]. Height is deliberately not an input: a spend's
/// certified-region status is set membership proven cryptographically, never a height
/// comparison (a valid orphaned sibling below the anchor height is not the certified
/// chain).
///
/// Fail-closed: a malformed proof, a proof for a different transaction, or one that does
/// not recompute to this anchor's root all leave the spend [`SpendRegion::HeaderVouched`]
/// — never a false certified claim.
pub fn certify_spend_region(
    spending_txid: &[u8; 32],
    anchor: &CertifiedTransactions,
    proof_hex: &[u8],
) -> SpendRegion {
    match anchor.merkle_root_bytes() {
        Some(root) if verify_tx_inclusion(proof_hex, spending_txid, &root).is_ok() => {
            SpendRegion::MithrilCertified
        }
        _ => SpendRegion::HeaderVouched,
    }
}

/// Split a `transaction_bodies` region (block index 1) into the raw byte span of each
/// transaction body, so the caller can hash each to its id and decode its spends.
///
/// Cardano block CBOR is NON-CANONICAL, so a `transaction_bodies` array is validly
/// encoded either DEFINITE (`0x8n` / `0x9b…` length) or INDEFINITE (`0x9f … 0xff`) —
/// real Conway preprod/mainnet blocks use both. Both split into the same per-body raw
/// spans and hash to the same raw region (the body-commitment bind is over the region
/// verbatim, breaks and all). An ill-formed region — a non-array, a body that does not
/// decode, or trailing bytes after the end — fails closed (`Err`), never silently
/// dropping a body (a dropped body is a spend a watcher would wrongly read as unspent).
pub(crate) fn tx_body_spans(block: &[u8], region: &Range<usize>) -> Result<Vec<Range<usize>>, ()> {
    let base = region.start;
    let mut d = Decoder::new(&block[region.clone()]);
    let mut spans = Vec::new();
    match d.array().map_err(|_| ())? {
        // Definite array: exactly `count` bodies, then the region must end.
        Some(count) => {
            // Each body is >= 1 byte, so the region length caps the true count; clamp the
            // pre-allocation so a hostile declared count cannot force a large alloc.
            spans.reserve(count.min(region.len() as u64) as usize);
            for _ in 0..count {
                let start = d.position();
                d.skip().map_err(|_| ())?;
                spans.push(base + start..base + d.position());
            }
            if d.position() != region.len() {
                return Err(());
            }
        }
        // Indefinite array: bodies until the break marker, which must be the region's
        // final byte. `datatype()` reports `Break` at the `0xff`; each body is skipped
        // (minicbor handles nested indefinite bodies with `alloc`).
        None => {
            while d.datatype().map_err(|_| ())? != minicbor::data::Type::Break {
                let start = d.position();
                d.skip().map_err(|_| ())?;
                spans.push(base + start..base + d.position());
            }
            // The break is a single `0xff` and must be the region's last byte.
            if block.get(base + d.position()) != Some(&0xff) || d.position() + 1 != region.len() {
                return Err(());
            }
        }
    }
    Ok(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the F6 live-run finding: a REAL preprod block (4927467) whose
    /// `transaction_bodies` is an INDEFINITE-length CBOR array (`0x9f … 0xff`) — the
    /// committed 22-block window is all definite, so the live follower was the first to
    /// hit one. `tx_body_spans` must split it byte-exactly; the differential against
    /// pallas proves no body is dropped, duplicated, or misaligned (a dropped body is a
    /// spend a watcher would wrongly read as unspent). The body-commitment bind holds
    /// over the raw region (breaks included).
    #[test]
    fn indefinite_tx_bodies_split_is_byte_exact_vs_pallas() {
        let hex_txt = std::fs::read_to_string("tests/vectors/indefinite-4927467.block")
            .expect("read the indefinite-array fixture");
        let block = hex::decode(hex_txt.trim()).expect("hex");
        let (view, spans) = HeaderView::decode_block(&block).expect("decode_block");
        assert_eq!(
            block[spans.tx_bodies.start], 0x9f,
            "the fixture must genuinely exercise the INDEFINITE tx_bodies path",
        );
        assert_eq!(
            hash_alonzo_seg_wits(&block, &spans),
            view.block_body_hash,
            "the body commitment binds over the raw indefinite region",
        );

        let body_spans =
            tx_body_spans(&block, &spans.tx_bodies).expect("split indefinite tx_bodies");
        let ours: Vec<String> = body_spans
            .iter()
            .map(|s| hex::encode(blake2b256(&block[s.clone()])))
            .collect();
        // pallas decodes the same block on an independent path; its per-tx hashes, in
        // order, must equal our raw-span txids.
        let pallas = pallas_traverse::MultiEraBlock::decode(&block).expect("pallas decode");
        let theirs: Vec<String> = pallas.txs().iter().map(|t| t.hash().to_string()).collect();
        assert!(
            ours.len() >= 30,
            "expected the full tx set, got {}",
            ours.len()
        );
        assert_eq!(
            ours, theirs,
            "the indefinite-array split must be byte-exact — no body dropped or misaligned",
        );

        // And every one of those bodies decodes its spends fail-closed (no MalformedBody):
        // the follower can process the block, not stall on it.
        for s in &body_spans {
            crate::utxo::decode_spends(&block[s.clone()]).expect("each body decodes its spends");
        }
    }

    /// A definite CBOR array of `items` (each already-encoded), prefixed by a
    /// definite-array header. Only small arrays (< 24) are needed here.
    fn array(items: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![0x80 | items.len() as u8];
        for i in items {
            v.extend_from_slice(i);
        }
        v
    }

    #[test]
    fn tx_body_spans_splits_a_definite_array_into_element_spans() {
        // Three distinct one-byte items: uint 1, uint 2, uint 3.
        let bodies = array(&[&[0x01], &[0x02], &[0x03]]);
        // Embed the region inside a larger buffer to prove spans are absolute.
        let mut block = vec![0xff, 0xff];
        let start = block.len();
        block.extend_from_slice(&bodies);
        let region = start..block.len();
        let spans = tx_body_spans(&block, &region).unwrap();
        assert_eq!(spans.len(), 3);
        assert_eq!(&block[spans[0].clone()], &[0x01]);
        assert_eq!(&block[spans[1].clone()], &[0x02]);
        assert_eq!(&block[spans[2].clone()], &[0x03]);
    }

    #[test]
    fn tx_body_spans_rejects_a_non_array_region() {
        // A map where an array is required — fail closed, never a silent empty scan.
        let block = vec![0xa0]; // empty map
        assert!(tx_body_spans(&block, &(0..block.len())).is_err());
    }

    #[test]
    fn tx_body_spans_splits_an_indefinite_array() {
        // 0x9f .. 0xff is an INDEFINITE array; real Conway blocks use it (see the
        // indefinite-4927467 fixture), so it splits the same as a definite one.
        let mut block = vec![0xff, 0xff]; // prefix to prove absolute spans
        let start = block.len();
        block.extend_from_slice(&[0x9f, 0x01, 0x02, 0x03, 0xff]);
        let region = start..block.len();
        let spans = tx_body_spans(&block, &region).unwrap();
        assert_eq!(spans.len(), 3);
        assert_eq!(&block[spans[0].clone()], &[0x01]);
        assert_eq!(&block[spans[1].clone()], &[0x02]);
        assert_eq!(&block[spans[2].clone()], &[0x03]);
    }

    #[test]
    fn tx_body_spans_rejects_an_indefinite_array_without_a_closing_break() {
        // The region ends before the break — fail closed rather than a truncated scan (a
        // dropped body is a spend a watcher would wrongly read as unspent).
        let block = vec![0x9f, 0x01, 0x02];
        assert!(tx_body_spans(&block, &(0..block.len())).is_err());
    }

    #[test]
    fn tx_body_spans_rejects_bytes_after_an_indefinite_break() {
        // A trailing byte after the break is inside the region — the break must be the
        // region's last byte, else a body could hide past it.
        let block = vec![0x9f, 0x01, 0xff, 0x02];
        assert!(tx_body_spans(&block, &(0..block.len())).is_err());
    }

    #[test]
    fn tx_body_spans_rejects_trailing_bytes_in_the_region() {
        // A one-element array followed by an extra byte inside the region.
        let mut block = array(&[&[0x01]]);
        block.push(0x02);
        assert!(tx_body_spans(&block, &(0..block.len())).is_err());
    }
}
