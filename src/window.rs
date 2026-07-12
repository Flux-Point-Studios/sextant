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
//! body of a header-verified, hash-linked, gap-free, body-committed segment from the
//! Mithril anchor to a verified tip — under Mithril-quorum + data-completeness, as of
//! that tip. The adversary's only evasion, withholding the spending block, cannot
//! advance the verified tip, so it collapses to [`WatchVerdict::Stalled`], never a
//! false [`WatchVerdict::Unspent`].

use core::ops::Range;

use minicbor::Decoder;

use crate::chain::{self, ChainError};
use crate::hash::blake2b256;
use crate::header::{BlockBodySpans, DecodeError, HeaderView};
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
fn hash_alonzo_seg_wits(block_bytes: &[u8], spans: &BlockBodySpans) -> [u8; 32] {
    let mut preimage = [0u8; 128];
    preimage[0..32].copy_from_slice(&blake2b256(&block_bytes[spans.tx_bodies.clone()]));
    preimage[32..64].copy_from_slice(&blake2b256(&block_bytes[spans.tx_witness_sets.clone()]));
    preimage[64..96].copy_from_slice(&blake2b256(&block_bytes[spans.auxiliary_data.clone()]));
    preimage[96..128].copy_from_slice(&blake2b256(
        &block_bytes[spans.invalid_transactions.clone()],
    ));
    blake2b256(&preimage)
}

/// The assumptions a windowed-unspent verdict rests on. Both are MANDATORY
/// (non-`Option`) data, not a docstring: an [`WatchVerdict::Unspent`] cannot be
/// constructed without stamping the scope it holds under, so a consumer always sees
/// the trust basis and a reviewer checks a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowAssumptions {
    /// The window sits inside a region a Mithril quorum certified (tip at or below
    /// the certified anchor height).
    pub mithril_quorum: bool,
    /// The scanned segment is a header-verified, hash-linked, gap-free, body-committed
    /// run — a complete body stream over the window with no admitted gap.
    pub data_complete: bool,
}

/// The trust basis an [`WatchVerdict::Unspent`] rests on — a forward-compatible ladder
/// mirroring [`crate::utxo::SpendStatus`]. `#[non_exhaustive]` so a future stronger
/// basis is additive and an external `match` can never silently read it as a windowed
/// scan:
/// * **Tier 1 — [`WatchBasis::WatchedWindow`] (today).** A header-verified,
///   body-committed, gap-free window under [`WindowAssumptions`].
/// * **Tier 2 — `CertifiedUnspent { epoch }` (reserved, CRYPTOGRAPHIC).** A future
///   Mithril ledger-state certificate of unspent-ness.
/// * **Tier 3 — `Attested { committee, at }` (reserved, ECONOMIC).** A committee
///   attestation, NEVER coercible into the cryptographic tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WatchBasis {
    /// No spend observed across a verified window under the stamped assumptions.
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
    /// The window tip is above the certified anchor height: outside the
    /// Mithril-vouched region, so data-completeness is not quorum-backed.
    TipAboveAnchor,
    /// The verified tip is older than the caller's freshness bound.
    TipTooOld,
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
    /// A verified, body-committed block in the window spends the watched outpoint —
    /// a definite refuse, authoritative regardless of freshness.
    SpentObserved {
        /// The block number the spend was observed in.
        at_height: u64,
        /// The slot the spend was observed at.
        at_slot: u64,
        /// The id of the transaction that consumed the outpoint.
        spending_txid: [u8; 32],
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
/// FAIL-CLOSED: any gap, broken link, body-commitment mismatch, unobserved creation,
/// tip above the anchor, or stale tip yields [`WatchVerdict::Stalled`], NEVER a false
/// [`WatchVerdict::Unspent`]. A spend observed in the window is a definite
/// [`WatchVerdict::SpentObserved`], returned as soon as it is seen.
pub fn verify_watched_window(
    watch: OutPoint,
    anchor: &CertifiedTransactions,
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
    //    bound bodies for the outpoint's creation or a spend of it.
    let mut start_number: Option<u64> = None;
    let mut verified_through: u64 = 0;
    let mut tip: Option<HeaderView> = None;
    let mut create_seen = false;

    for block in blocks {
        let block = block.as_ref();
        // verify_segment already decoded every header, so decode_block cannot fail
        // here; fail closed rather than panic on an impossible re-decode.
        let Ok((view, spans)) = HeaderView::decode_block(block) else {
            return stalled(verified_through, StallReason::BrokenSegment);
        };
        if hash_alonzo_seg_wits(block, &spans) != view.block_body_hash {
            return stalled(verified_through, StallReason::BodyCommitmentMismatch);
        }
        let Ok(body_spans) = tx_body_spans(block, &spans.tx_bodies) else {
            return stalled(verified_through, StallReason::MalformedBody);
        };
        for body in body_spans {
            let tx = &block[body];
            let txid = blake2b256(tx);
            // Creation is observed only when the creating transaction actually produced
            // an output at the watched index — a phantom index is never read as created.
            if txid == watch.tx_id && output_exists(tx, watch.index as usize).unwrap_or(false) {
                create_seen = true;
            }
            let Ok(spends) = decode_spends(tx) else {
                return stalled(verified_through, StallReason::MalformedBody);
            };
            if spends.contains(&watch) {
                return WatchVerdict::SpentObserved {
                    at_height: view.block_number,
                    at_slot: view.slot,
                    spending_txid: txid,
                };
            }
        }
        start_number.get_or_insert(view.block_number);
        verified_through = view.block_number;
        tip = Some(view);
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

/// Split a `transaction_bodies` region (block index 1) into the raw byte span of each
/// transaction body, so the caller can hash each to its id and decode its spends. A
/// Conway `transaction_bodies` is a definite array; an indefinite or ill-formed one
/// fails closed (`Err`) rather than silently dropping a body — a dropped body is a
/// spend a watcher would wrongly read as unspent.
fn tx_body_spans(block: &[u8], region: &Range<usize>) -> Result<Vec<Range<usize>>, ()> {
    let base = region.start;
    let mut d = Decoder::new(&block[region.clone()]);
    let count = d.array().map_err(|_| ())?.ok_or(())?;
    // Each element is >= 1 byte, so the region length caps the true element count;
    // clamp the pre-allocation so a hostile declared count cannot force a large alloc.
    let mut spans = Vec::with_capacity(count.min(region.len() as u64) as usize);
    for _ in 0..count {
        let start = d.position();
        d.skip().map_err(|_| ())?;
        spans.push(base + start..base + d.position());
    }
    if d.position() != region.len() {
        return Err(());
    }
    Ok(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn tx_body_spans_rejects_an_indefinite_array() {
        // 0x9f .. 0xff is an indefinite array; Sextant requires definite bodies.
        let block = vec![0x9f, 0x01, 0xff];
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
