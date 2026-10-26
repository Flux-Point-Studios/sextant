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
//! is Babbage-onward; a pre-Babbage (Alonzo) block does not decode on this path.
//!
//! [`verify_created_output`] reads one created output's content by the same rule, from a block
//! whose header hash the caller already trusts.

use alloc::vec::Vec;

use minicbor::Decoder;

use crate::hash::blake2b256;
use crate::header::{DecodeError, HeaderView};
use crate::utxo::{Datum, OutPoint, created_outputs, decode_single_output, inputs_at};
use crate::utxoset::{BlockEffects, TxEffect};
use crate::window::{hash_alonzo_seg_wits, phase2_valid_flags, tx_body_spans};

/// Why a block's effects could not be extracted. Every arm is a fail-closed non-answer: the
/// UTxO set is never advanced on a block whose effects are uncertain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The block CBOR did not decode as a Praos block, or its `invalid_transactions` was not
    /// a strictly ascending list of its transactions' indices.
    Decode,
    /// The bodies do not hash to the header's `block_body_hash` — forged or corrupt bodies.
    BodyCommitmentMismatch,
    /// A transaction body was not decodable (inputs/outputs), so its effect is unknown.
    MalformedBody,
}

/// Extract the [`BlockEffects`] a verified block contributes to the UTxO set. Binds bodies to
/// the header, then, per transaction in on-chain order and by its phase-2 outcome: the inputs
/// it consumes and the outpoints `(tx_id, index)` it creates, where
/// `tx_id = Blake2b-256(tx_body)`.
pub fn extract_block_effects(block: &[u8]) -> Result<BlockEffects, ExtractError> {
    let (view, spans) = HeaderView::decode_block(block).map_err(|_| ExtractError::Decode)?;
    if hash_alonzo_seg_wits(block, &spans) != view.block_body_hash {
        return Err(ExtractError::BodyCommitmentMismatch);
    }

    let body_spans =
        tx_body_spans(block, &spans.tx_bodies).map_err(|()| ExtractError::MalformedBody)?;
    let valid = phase2_valid_flags(&block[spans.invalid_transactions.clone()], body_spans.len())
        .map_err(|()| ExtractError::Decode)?;
    let mut txs = Vec::with_capacity(body_spans.len());
    for (span, phase2_valid) in body_spans.iter().zip(valid) {
        let tx = &block[span.clone()];
        txs.push(tx_effect(tx, blake2b256(tx), phase2_valid)?);
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

/// One transaction's effect under its phase-2 outcome. A phase-2-VALID transaction consumes
/// its inputs (body key 0) and creates its regular outputs; a phase-2-INVALID one consumes its
/// COLLATERAL inputs (body key 13) — its normal inputs stay unspent — and creates only its
/// collateral return, if any (see [`created_outputs`]).
fn tx_effect(tx: &[u8], tx_id: [u8; 32], phase2_valid: bool) -> Result<TxEffect, ExtractError> {
    let consumed = inputs_at(tx, if phase2_valid { 0 } else { 13 });
    let spent = unique_spent(consumed.map_err(|_| ExtractError::MalformedBody)?);
    let created = created_outputs(tx, phase2_valid)
        .map_err(|_| ExtractError::MalformedBody)?
        .into_iter()
        .map(|(index, _)| OutPoint { tx_id, index })
        .collect();
    Ok(TxEffect { spent, created })
}

/// An output a block created, with the block it was read from. Holds only within bytes that
/// hash to the expected block hash [`verify_created_output`] was given; the block's
/// membership in the canonical chain is the caller's to establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedOutput {
    /// The output's raw address bytes, as serialized on chain.
    pub address: Vec<u8>,
    /// The output's ADA amount in lovelace (the `coin` of its value).
    pub lovelace: u64,
    /// The output's datum, if any.
    pub datum: Option<Datum>,
    /// The header hash of the block the output was read from: the expected hash.
    pub block_hash: [u8; 32],
    /// That block's height.
    pub block_number: u64,
    /// That block's slot.
    pub slot: u64,
    /// The creating transaction's phase-2 outcome: `true` for one of its regular outputs,
    /// `false` for the collateral return of a phase-2-invalid transaction.
    pub phase2_valid: bool,
}

/// Why [`verify_created_output`] established no output. Every arm is a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreatedOutputError {
    /// The block CBOR did not decode as a Praos block.
    Decode(DecodeError),
    /// The block's header does not hash to the expected block hash.
    HeaderHashMismatch,
    /// The block's body segments do not hash to its header's `block_body_hash`.
    BodyCommitmentMismatch,
    /// The block's `invalid_transactions` is not a strictly ascending list of its
    /// transactions' indices.
    MalformedValidity,
    /// The block's transaction bodies do not split, or the creating body does not decode.
    MalformedBody,
    /// No transaction body in the block hashes to the transaction id.
    TransactionAbsent,
    /// More than one transaction body in the block hashes to the transaction id.
    TransactionRepeated,
    /// The transaction created no output at the index under its phase-2 outcome.
    NotCreated,
}

impl core::fmt::Display for CreatedOutputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CreatedOutputError::Decode(e) => write!(f, "{e}"),
            CreatedOutputError::HeaderHashMismatch => {
                f.write_str("block header does not hash to the expected block hash")
            }
            CreatedOutputError::BodyCommitmentMismatch => {
                f.write_str("block body does not hash to its header commitment")
            }
            CreatedOutputError::MalformedValidity => {
                f.write_str("block's invalid_transactions is not a strictly ascending index list")
            }
            CreatedOutputError::MalformedBody => f.write_str("malformed transaction body"),
            CreatedOutputError::TransactionAbsent => {
                f.write_str("no transaction in the block has the transaction id")
            }
            CreatedOutputError::TransactionRepeated => {
                f.write_str("the block carries the transaction more than once")
            }
            CreatedOutputError::NotCreated => {
                f.write_str("the transaction created no output at the index")
            }
        }
    }
}

impl core::error::Error for CreatedOutputError {}

/// Read output `out_index` of transaction `tx_id` as created by `block`, a ledger
/// `[era, block]` CBOR whose header must hash to `expected_block_hash`.
///
/// The header hash binds the bytes, the body commitment binds all four body segments to
/// the header, exactly one body must hash to `tx_id`, and the transaction's phase-2 outcome
/// comes from the block's `invalid_transactions`: a phase-2-valid transaction created its
/// regular outputs, an invalid one only its collateral return. No transaction bytes or
/// validity enter from the caller.
///
/// This proves creation within the bytes bound to `expected_block_hash`, and nothing about
/// that block's place in the chain. Canonical or anchor membership of the block is the
/// caller's to prove upstream; a hash read off the same untrusted bytes proves nothing, and
/// one from a header chain verified by [`crate::follow::WindowFollower`] carries that
/// chain's surfaced Mithril-quorum and leader-eligibility assumptions.
pub fn verify_created_output(
    block: &[u8],
    expected_block_hash: &[u8; 32],
    tx_id: &[u8; 32],
    out_index: u16,
) -> Result<CreatedOutput, CreatedOutputError> {
    let (view, spans) = HeaderView::decode_block(block).map_err(CreatedOutputError::Decode)?;
    if view.block_hash != *expected_block_hash {
        return Err(CreatedOutputError::HeaderHashMismatch);
    }
    if hash_alonzo_seg_wits(block, &spans) != view.block_body_hash {
        return Err(CreatedOutputError::BodyCommitmentMismatch);
    }
    let bodies =
        tx_body_spans(block, &spans.tx_bodies).map_err(|()| CreatedOutputError::MalformedBody)?;
    let mut matching = bodies
        .iter()
        .enumerate()
        .filter(|(_, span)| blake2b256(&block[(*span).clone()]) == *tx_id);
    let (position, span) = matching
        .next()
        .ok_or(CreatedOutputError::TransactionAbsent)?;
    if matching.next().is_some() {
        return Err(CreatedOutputError::TransactionRepeated);
    }
    let valid = phase2_valid_flags(&block[spans.invalid_transactions.clone()], bodies.len())
        .map_err(|()| CreatedOutputError::MalformedValidity)?;
    let tx = &block[span.clone()];
    let (_, output) = created_outputs(tx, valid[position])
        .map_err(|_| CreatedOutputError::MalformedBody)?
        .into_iter()
        .find(|(index, _)| *index == out_index)
        .ok_or(CreatedOutputError::NotCreated)?;
    let (address, lovelace, datum) = decode_single_output(&mut Decoder::new(&tx[output]))
        .map_err(|_| CreatedOutputError::MalformedBody)?;
    Ok(CreatedOutput {
        address,
        lovelace,
        datum,
        block_hash: view.block_hash,
        block_number: view.block_number,
        slot: view.slot,
        phase2_valid: valid[position],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::recommitted;

    /// Regression: a REAL preprod Conway block (#4933014) whose txs encode their outputs as
    /// INDEFINITE-length CBOR arrays. The live Tier-2 follow wedged here (`MalformedBody`) because
    /// the tx-body decoders assumed definite-length maps/arrays; extraction must now succeed and
    /// match pallas (the differential sweep in `tests/effects.rs` covers the outpoint equality).
    #[test]
    fn extracts_a_block_with_indefinite_length_tx_bodies() {
        let hex = include_str!("../tests/vectors/conway-indef-4933014.block");
        let block = crate::inclusion::decode_hex(hex.trim().as_bytes()).unwrap();
        let eff = extract_block_effects(&block).expect("indefinite-encoded outputs must extract");
        assert_eq!(eff.number, 4933014);
        let created: usize = eff.txs.iter().map(|t| t.created.len()).sum();
        // Every one of the 21 txs produces at least one output.
        assert!(
            created >= 21,
            "created {created} outputs across {} txs",
            eff.txs.len()
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

        let effect = tx_effect(&tx, [0u8; 32], false).unwrap();
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

    /// Each phase-2 outcome consumes one input set and creates by one rule. On
    /// `{0: [X], 13: [Y], 1: [o, o], 16: o}`: valid spends X and creates 0 and 1; invalid
    /// spends Y and creates the collateral return at 2. Without key 16 an invalid
    /// transaction creates nothing, and with no outputs its return sits at 0. A body
    /// without key 1 is malformed whatever its outcome.
    #[test]
    fn a_transaction_creates_by_its_phase_2_outcome() {
        let input = |byte: u8| [&[0x82, 0x58, 0x20][..], &[byte; 32], &[0x00]].concat();
        let o = [0x82, 0x41, 0x00, 0x07];
        let tx_id = [0x77; 32];
        let at = |index: u16| OutPoint { tx_id, index };
        let input_at = |byte: u8| OutPoint {
            tx_id: [byte; 32],
            index: 0,
        };
        let (x, y) = (input_at(0xaa), input_at(0xbb));
        let body = [
            &[0xa4, 0x00, 0x81][..],
            &input(0xaa),
            &[0x0d, 0x81],
            &input(0xbb),
            &[0x01, 0x82],
            &o,
            &o,
            &[0x10],
            &o,
        ]
        .concat();
        assert_eq!(
            tx_effect(&body, tx_id, true),
            Ok(TxEffect {
                spent: vec![x],
                created: vec![at(0), at(1)],
            })
        );
        assert_eq!(
            tx_effect(&body, tx_id, false),
            Ok(TxEffect {
                spent: vec![y],
                created: vec![at(2)],
            })
        );
        // {13: [Y], 1: [o]} creates nothing when invalid; {13: [Y], 1: [], 16: o} creates 0.
        let no_return = [&[0xa2, 0x0d, 0x81][..], &input(0xbb), &[0x01, 0x81], &o].concat();
        assert_eq!(
            tx_effect(&no_return, tx_id, false).map(|effect| effect.created),
            Ok(vec![])
        );
        let no_outputs = [
            &[0xa3, 0x0d, 0x81][..],
            &input(0xbb),
            &[0x01, 0x80, 0x10],
            &o,
        ]
        .concat();
        assert_eq!(
            tx_effect(&no_outputs, tx_id, false).map(|effect| effect.created),
            Ok(vec![at(0)])
        );
        // {13: [Y], 16: o}: no outputs key.
        let without_key_1 = [&[0xa2, 0x0d, 0x81][..], &input(0xbb), &[0x10], &o].concat();
        for phase2_valid in [true, false] {
            assert_eq!(
                tx_effect(&without_key_1, tx_id, phase2_valid),
                Err(ExtractError::MalformedBody)
            );
        }
    }

    /// Mainnet 13,591,743 under a forged phase-2 record its header re-commits to, one the
    /// ledger refuses: `[7, 7]` and `[8, 7]` do not ascend, and a tag-258 `[7]` is no list.
    /// The block's effects are unknown and nothing applies; its own record extracts.
    #[test]
    fn a_phase_2_record_the_ledger_refuses_refuses_the_block() {
        let hex = include_str!("../tests/vectors/invalid-mainnet-13591743.block");
        let block = crate::inclusion::decode_hex(hex.trim().as_bytes()).unwrap();
        assert!(extract_block_effects(&block).is_ok());
        let (_, spans) = HeaderView::decode_block(&block).unwrap();
        for record in [
            &[0x82, 0x07, 0x07][..],
            &[0x82, 0x08, 0x07],
            &[0xd9, 0x01, 0x02, 0x81, 0x07],
        ] {
            let forged = recommitted(&block, spans.invalid_transactions.clone(), record);
            assert_eq!(
                extract_block_effects(&forged).map(|_| ()),
                Err(ExtractError::Decode),
                "{record:02x?}"
            );
        }
    }
}
