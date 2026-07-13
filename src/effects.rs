//! Own-path block → UTxO-set effects extraction (BEYOND-DoD Tier-2, slice T2).
//!
//! [`extract_block_effects`] turns a raw block into the [`BlockEffects`] the Tier-2
//! [`crate::utxoset::UtxoSet`] applies: for every transaction, the outpoints it consumes and
//! the outpoints it creates, on Sextant's own decode path — no provider-supplied effect list.
//! It binds the bodies to the header commitment first (the same segregated-witness recompute
//! the windowed follower uses), so a provider cannot feed forged bodies past the header.
//!
//! Phase-2 validity is load-bearing and the reason [`crate::utxo::decode_spends`] is not enough
//! here: a phase-2-VALID transaction consumes its inputs (body key 0) and produces its outputs
//! (key 1); a phase-2-INVALID one (a Plutus script failed) consumes its COLLATERAL (key 13) and
//! produces only its collateral-return, its normal inputs staying unspent. Getting that wrong
//! flips a real outpoint's spent status. This slice extracts the valid path exactly (and binds
//! it byte-for-byte to pallas's independent `consumes`/`produces` across the committed vectors)
//! and, until the collateral path is vectored, FAILS CLOSED on any block carrying an invalid
//! transaction — an honest non-answer, never a wrong set delta.

use std::collections::BTreeSet;

use minicbor::Decoder;
use minicbor::data::Type;

use crate::hash::blake2b256;
use crate::header::HeaderView;
use crate::utxo::{OutPoint, inputs_at, output_count};
use crate::utxoset::{BlockEffects, TxEffect};
use crate::window::{hash_alonzo_seg_wits, tx_body_spans};

/// Why a block's effects could not be extracted. Every arm is a fail-closed non-answer: the
/// UTxO set is never advanced on a block whose effects are uncertain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The block CBOR did not decode as a Praos block.
    Decode,
    /// The bodies do not hash to the header's `block_body_hash` — forged or corrupt bodies.
    BodyCommitmentMismatch,
    /// A transaction body was not decodable (inputs/outputs), so its effect is unknown.
    MalformedBody,
    /// The block carries a phase-2-invalid transaction (index into the tx-bodies array). Its
    /// collateral-spend effect is not yet extracted on Sextant's own path, so the block is
    /// refused rather than have its set delta computed wrong. (Handled in the next slice.)
    PhaseTwoFailureUnsupported {
        /// The invalid transaction's index in the block's tx-bodies array.
        tx_index: usize,
    },
}

/// Extract the [`BlockEffects`] a verified block contributes to the UTxO set. Binds bodies to
/// the header, then, per transaction in on-chain order: its consumed inputs (key 0) and its
/// created outputs `(tx_id, 0..output_count)`, where `tx_id = Blake2b-256(tx_body)`.
pub fn extract_block_effects(block: &[u8]) -> Result<BlockEffects, ExtractError> {
    let (view, spans) = HeaderView::decode_block(block).map_err(|_| ExtractError::Decode)?;
    if hash_alonzo_seg_wits(block, &spans) != view.block_body_hash {
        return Err(ExtractError::BodyCommitmentMismatch);
    }

    let invalid = decode_invalid_transactions(&block[spans.invalid_transactions.clone()])
        .map_err(|_| ExtractError::Decode)?;

    let body_spans =
        tx_body_spans(block, &spans.tx_bodies).map_err(|()| ExtractError::MalformedBody)?;
    let mut txs = Vec::with_capacity(body_spans.len());
    for (i, span) in body_spans.iter().enumerate() {
        let tx = &block[span.clone()];
        if invalid.contains(&i) {
            return Err(ExtractError::PhaseTwoFailureUnsupported { tx_index: i });
        }
        let tx_id = blake2b256(tx);
        let spent = inputs_at(tx, 0).map_err(|_| ExtractError::MalformedBody)?;
        let n = output_count(tx).map_err(|_| ExtractError::MalformedBody)?;
        let mut created = Vec::with_capacity(n);
        for idx in 0..n {
            let index = u16::try_from(idx).map_err(|_| ExtractError::MalformedBody)?;
            created.push(OutPoint { tx_id, index });
        }
        txs.push(TxEffect { spent, created });
    }

    Ok(BlockEffects {
        number: view.block_number,
        hash: view.block_hash,
        // Genesis has no parent; a from-genesis replay's first apply is against a `None` tip,
        // which the engine accepts, so the null parent is inert.
        prev_hash: view.prev_hash.unwrap_or([0u8; 32]),
        txs,
    })
}

/// Decode the `invalid_transactions` block element — a `set` of `uint` transaction indices
/// (bare array or tag-258 wrapped) — into the set of phase-2-failed indices. An empty element
/// (the common case) yields an empty set.
fn decode_invalid_transactions(region: &[u8]) -> Result<BTreeSet<usize>, ()> {
    let mut d = Decoder::new(region);
    if d.datatype().map_err(|_| ())? == Type::Tag && d.tag().map_err(|_| ())?.as_u64() != 258 {
        return Err(());
    }
    let mut out = BTreeSet::new();
    // The element is a definite or indefinite array of indices.
    match d.array().map_err(|_| ())? {
        Some(count) => {
            for _ in 0..count {
                out.insert(usize::try_from(d.u64().map_err(|_| ())?).map_err(|_| ())?);
            }
        }
        None => loop {
            if d.datatype().map_err(|_| ())? == Type::Break {
                d.skip().map_err(|_| ())?;
                break;
            }
            out.insert(usize::try_from(d.u64().map_err(|_| ())?).map_err(|_| ())?);
        },
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_invalid_transactions_is_an_empty_set() {
        // The empty array `0x80` — the common case (no phase-2 failures in the block).
        assert_eq!(
            decode_invalid_transactions(&[0x80]).unwrap(),
            BTreeSet::new()
        );
    }

    #[test]
    fn decodes_invalid_transaction_indices_bare_and_tagged() {
        let s = BTreeSet::from([1usize, 3usize]);
        // Bare definite array [1, 3].
        assert_eq!(decode_invalid_transactions(&[0x82, 0x01, 0x03]).unwrap(), s);
        // tag-258 wrapped set with the same members.
        assert_eq!(
            decode_invalid_transactions(&[0xd9, 0x01, 0x02, 0x82, 0x01, 0x03]).unwrap(),
            s
        );
    }

    #[test]
    fn indefinite_invalid_transactions_array_decodes() {
        // 0x9f 01 03 ff — indefinite array [1, 3].
        assert_eq!(
            decode_invalid_transactions(&[0x9f, 0x01, 0x03, 0xff]).unwrap(),
            BTreeSet::from([1usize, 3usize])
        );
    }
}
