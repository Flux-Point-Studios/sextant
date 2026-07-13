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
//! produces only its collateral-return (key 16, at output index `|outputs|` — after the normal
//! outputs it did NOT produce), its normal inputs staying unspent. Getting that wrong flips a
//! real outpoint's spent status. Both deltas are extracted here and bound byte-for-byte to
//! pallas's independent `consumes`/`produces` across the committed vectors — including a real
//! mainnet phase-2 failure (`invalid-mainnet-13591743.block`, tx 7). The collateral-return rule
//! is Babbage-onward; a pre-Babbage (Alonzo) invalid transaction consumes all collateral with
//! no return, a delta this Conway-scoped path does not model, so it fails closed there.

use std::collections::BTreeSet;

use minicbor::Decoder;
use minicbor::data::Type;

use crate::hash::blake2b256;
use crate::header::HeaderView;
use crate::utxo::{OutPoint, has_body_key, inputs_at, output_count};
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
    /// A phase-2-invalid transaction declares a collateral return (key 16) but no outputs array
    /// (key 1) to place it after — a malformed shape whose collateral-return index is undefined.
    /// Fail closed rather than guess the index.
    CollateralReturnWithoutOutputs {
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
        let tx_id = blake2b256(tx);
        let effect = if invalid.contains(&i) {
            invalid_tx_effect(tx, tx_id, i)?
        } else {
            valid_tx_effect(tx, tx_id)?
        };
        txs.push(effect);
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

/// Collapse a consumed-input list to unique outpoints, in the order the UTxO set will remove
/// them. Collateral inputs (key 13) may LEGALLY list the same UTxO more than once — Conway's
/// `nonempty_set` and Babbage's array both preserve on-wire duplicates, and pallas `consumes()`
/// de-dups for the same reason. Left un-collapsed, a duplicate makes [`crate::utxoset::UtxoSet`]
/// remove the outpoint once, then fail `SpendOfUnknownOutput` on the repeat and reject the whole
/// (valid, on-chain) block — a permanent wedge. Normal inputs (key 0) are a ledger-enforced set,
/// but the same collapse is applied for defense in depth.
fn unique_spent(mut v: Vec<OutPoint>) -> Vec<OutPoint> {
    v.sort_unstable();
    v.dedup();
    v
}

/// A phase-2-VALID transaction: it consumes its inputs (body key 0) and produces its outputs
/// (key 1) as `(tx_id, 0..output_count)`.
fn valid_tx_effect(tx: &[u8], tx_id: [u8; 32]) -> Result<TxEffect, ExtractError> {
    let spent = unique_spent(inputs_at(tx, 0).map_err(|_| ExtractError::MalformedBody)?);
    let n = output_count(tx).map_err(|_| ExtractError::MalformedBody)?;
    let mut created = Vec::with_capacity(n);
    for idx in 0..n {
        let index = u16::try_from(idx).map_err(|_| ExtractError::MalformedBody)?;
        created.push(OutPoint { tx_id, index });
    }
    Ok(TxEffect { spent, created })
}

/// A phase-2-INVALID transaction: it consumes its COLLATERAL inputs (body key 13) — its normal
/// inputs stay unspent — and produces ONLY its collateral return (key 16), if present, at output
/// index `|outputs|` (the slot after the normal outputs it did not produce). Babbage-onward
/// semantics; a pre-Babbage invalid transaction has no collateral return and a different delta,
/// so it is caught by the [`ExtractError::CollateralReturnWithoutOutputs`] guard only when
/// key 16 is present without a key-1 outputs array (a shape the modelled eras never emit).
fn invalid_tx_effect(tx: &[u8], tx_id: [u8; 32], i: usize) -> Result<TxEffect, ExtractError> {
    let spent = unique_spent(inputs_at(tx, 13).map_err(|_| ExtractError::MalformedBody)?);
    let created = if has_body_key(tx, 16).map_err(|_| ExtractError::MalformedBody)? {
        let idx = output_count(tx)
            .map_err(|_| ExtractError::CollateralReturnWithoutOutputs { tx_index: i })?;
        let index = u16::try_from(idx).map_err(|_| ExtractError::MalformedBody)?;
        vec![OutPoint { tx_id, index }]
    } else {
        Vec::new()
    };
    Ok(TxEffect { spent, created })
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

    /// A minimal invalid-tx body `{13: [X, X], 1: []}` — collateral lists the same outpoint
    /// twice (legal: the ledger consumes it once). The extracted `spent` must be de-duplicated,
    /// else `UtxoSet::apply` removes X once then trips `SpendOfUnknownOutput` on the repeat and
    /// rejects the whole on-chain block, permanently wedging the follower.
    #[test]
    fn invalid_tx_dedups_duplicate_collateral() {
        let x_hash = [0xaa_u8; 32];
        // input X = [ h'aa..aa' (bytes .size 32), 0 ]  ->  82 5820 <32> 00
        let mut input_x = vec![0x82, 0x58, 0x20];
        input_x.extend_from_slice(&x_hash);
        input_x.push(0x00);
        // tx body = { 13: [X, X], 1: [] }  ->  a2 0d 82 X X 01 80
        let mut tx = vec![0xa2, 0x0d, 0x82];
        tx.extend_from_slice(&input_x);
        tx.extend_from_slice(&input_x);
        tx.extend_from_slice(&[0x01, 0x80]);

        // Raw decode preserves the on-wire duplicate (the bug source).
        assert_eq!(inputs_at(&tx, 13).unwrap().len(), 2);

        let effect = invalid_tx_effect(&tx, [0u8; 32], 0).unwrap();
        assert_eq!(
            effect.spent,
            vec![OutPoint {
                tx_id: x_hash,
                index: 0
            }],
            "duplicate collateral collapses to a single consumed outpoint",
        );
        assert!(
            effect.created.is_empty(),
            "no collateral return (no key 16)"
        );
    }
}
