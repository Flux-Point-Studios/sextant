//! UTxO read verification: prove an output's bytes are the authentic,
//! genesis-anchored on-chain bytes of a Mithril-certified transaction.
//!
//! This is the read path's terminal verdict. It composes the pure-Rust inclusion
//! verifier ([`crate::inclusion::verify_tx_inclusion`], default wasm-safe graph)
//! with a Conway transaction-output decoder on Sextant's own minicbor path.
//!
//! ## What a genuine `Ok` proves — and what it does NOT
//! Cardano commits to no UTxO-set state root (a Conway header carries only
//! `block_body_hash`, a per-block tx-merkle root — no ledger-state accumulator).
//! Mithril certifies *transactions* (`CardanoTransactionsMerkleRoot`, ~100 blocks
//! behind tip), not a UTxO set. So `Ok` proves exactly: the returned
//! `{address, lovelace, datum}` are the authentic on-chain bytes of output
//! `(H, out_index)`, and `H` is a member of the Mithril-certified transaction set
//! at `certified_at`, authenticated (when `certified_root` comes off a
//! [`crate::mithril::verify_chain_anchored`] cert) back to the network genesis key.
//!
//! It does **not** and **cannot** prove `(H, out_index)` is currently *unspent*:
//! transaction-set membership is a monotone "created" predicate, no Cardano
//! commitment exists to prove unspent against, and the verdict trails tip by ~100
//! blocks. Unspent is the ledger's to decide, atomically, at submission. That
//! honesty is enforced in the return type: [`SpendStatus`] carries today only
//! `NotEstablished` (a `#[non_exhaustive]` trust-tier ladder, uncoercible to a
//! positive-liveness claim), and every verdict carries `certified_at` so no caller
//! may read it as tip state.
//!
//! ## The bytes are hashed here, never trusted from a provider
//! `verify_utxo_read` hashes the *supplied* `tx_bytes` to obtain `H`
//! (`Blake2b-256`), never a provider-supplied hash. So a provider cannot pair one
//! transaction's proof with another transaction's bytes: substituted or tampered
//! bytes hash to a value that is not a leaf of the proof and are rejected as
//! not-included before any output is decoded.

use std::collections::BTreeSet;

use minicbor::Decoder;
use minicbor::data::Type;

use crate::hash::blake2b256;
use crate::inclusion::{InclusionError, verify_tx_inclusion};

/// A datum attached to a transaction output — the Cardano `datum_option`, or a
/// legacy Shelley/Alonzo output's trailing datum hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datum {
    /// A 32-byte datum hash; the plutus data lives off the output.
    Hash([u8; 32]),
    /// An inline datum: the raw CBOR of the plutus data item (the bytes carried
    /// inside the `#6.24(bytes)` wrapper), which a consumer decodes as it needs.
    Inline(Vec<u8>),
}

/// A transaction outpoint: a reference to output `index` of transaction `tx_id` —
/// the thing a spend consumes. `index` is a `u16` because a Conway
/// `transaction_input` encodes it as `uint .size 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    /// The 32-byte Blake2b-256 id of the transaction that created the output.
    pub tx_id: [u8; 32],
    /// The index of the output within that transaction.
    pub index: u16,
}

/// The set of outpoints a transaction consumes: its inputs (body key 0) together
/// with its collateral inputs (body key 13, drawn on only if the script phase
/// fails, but a spend either way). Reference inputs (key 18) are read, not
/// consumed, and are NOT members. A set, so a duplicated input collapses to one.
pub type SpendSet = BTreeSet<OutPoint>;

/// The Cardano-transactions commitment a certificate certifies: the Merkle root of
/// the signed transaction set at a certified `(epoch, block_number)`. Present only on
/// a `CardanoTransactions` certificate — a stake-distribution certificate commits to
/// no transaction set. This is the root a proof-based UTxO inclusion check recomputes
/// against (never trusting a provider-supplied root); when it comes off a
/// `verify_chain_anchored`-verified tip it is authenticated back to the genesis key.
/// `block_number` is the recency `certified_at` a caller must carry — the certified
/// set trails tip, so it proves creation, never unspent.
///
/// Pure data in the default (wasm-safe) graph so both the Mithril producer and the
/// windowed read-path consumer ([`crate::window::verify_watched_window`]) share one
/// anchor type; a certificate populates it under the `mithril` feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedTransactions {
    /// The `cardano_transactions_merkle_root` protocol-message part (hex).
    pub merkle_root: String,
    /// The epoch the transaction set is certified for.
    pub epoch: u64,
    /// The highest block number the certified transaction set covers.
    pub block_number: u64,
}

impl CertifiedTransactions {
    /// The certified transaction Merkle root as 32 raw bytes, ready to pass as the
    /// `certified_root` of a UTxO inclusion check. `None` when the hex root is not
    /// exactly 32 bytes — a malformed certificate, rejected fail-closed rather than
    /// yielding a partial or garbage root.
    pub fn merkle_root_bytes(&self) -> Option<[u8; 32]> {
        crate::inclusion::decode_hex(self.merkle_root.as_bytes())?
            .try_into()
            .ok()
    }
}

/// The spend verdict a read-path verifier can make. Deliberately has no `Unspent`
/// variant today: the read path CANNOT establish liveness (see the module docs), so
/// no code path can coerce a verdict into a positive-liveness claim.
///
/// `#[non_exhaustive]` marks this as a forward-compatible TRUST-TIER LADDER — a
/// future tier is additive (a new variant), never a layout break, and an external
/// `match` must carry a wildcard so a new tier can never be silently read as
/// `NotEstablished`:
/// * **Tier 1 — [`SpendStatus::NotEstablished`] (today).** Inclusion + provenance are
///   proven; liveness is not, and cannot be, established by this path.
/// * **Tier 2 — `CertifiedUnspent { epoch }` (reserved, CRYPTOGRAPHIC).** A future
///   Mithril ledger-state certificate + Merkle proof of unspent-ness as of `epoch`.
/// * **Tier 3 — `Attested { committee, at }` (reserved, ECONOMIC).** A Materios /
///   Witness-Network committee attestation of liveness.
///
/// LOAD-BEARING INVARIANT: an economic tier (3) is NEVER coercible into a
/// cryptographic one (2). A consumer must always see the trust basis and can never
/// mistake an attestation for a proof — which is why the tiers are distinct variants
/// (and, at the C ABI, distinct code bands), not a shared boolean. The future tiers
/// are documented, not defined: no empty variant exists until its proof does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpendStatus {
    /// Spend state is not established, and cannot be by this path (Tier 1).
    NotEstablished,
}

/// A verified transaction output: the authentic on-chain bytes of a
/// certified-transaction output, with the certified height it was attested at and
/// the honest, uncoercible spend verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOutput {
    /// The output's raw address bytes (Shelley address / Byron CBOR-address bytes,
    /// as serialized on chain).
    pub address: Vec<u8>,
    /// The output's ADA amount in lovelace (the `coin` of its value; any
    /// multi-asset bundle is not part of the read-path verdict).
    pub lovelace: u64,
    /// The output's datum, if any.
    pub datum: Option<Datum>,
    /// The Mithril-certified block height the transaction set was attested at.
    /// Travels with every verdict so no caller reads it as tip state.
    pub certified_at: u64,
    /// The spend verdict — always [`SpendStatus::NotEstablished`].
    pub spend_status: SpendStatus,
}

/// Why a UTxO read did not verify. Untrusted bytes and providers, so every variant
/// is an ordinary recoverable outcome — never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtxoError {
    /// The certified inclusion proof does not attest the supplied transaction
    /// bytes (tampered/substituted bytes, a missing leaf, or a root mismatch).
    Inclusion(InclusionError),
    /// The transaction bytes are not a decodable Conway transaction body, or the
    /// requested output is not a decodable Conway output.
    MalformedTx,
    /// `out_index` is past the end of the transaction's output list.
    OutputIndexOutOfRange,
}

impl core::fmt::Display for UtxoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UtxoError::Inclusion(e) => write!(f, "certified inclusion failed: {e}"),
            UtxoError::MalformedTx => f.write_str("malformed Conway transaction body or output"),
            UtxoError::OutputIndexOutOfRange => f.write_str("output index past end of transaction"),
        }
    }
}

impl std::error::Error for UtxoError {}

/// Verify that output `out_index` of the transaction whose body is `tx_bytes` is a
/// genesis-anchored, Mithril-certified on-chain output, and return its
/// `{address, lovelace, datum}` with the honest spend verdict.
///
/// `tx_bytes` is the raw transaction *body* CBOR (the `KeepRaw` body span, so
/// `Blake2b-256(tx_bytes)` is the transaction id). `proof_hex` is the aggregator's
/// HEX(JSON) `MKMapProof<BlockRange>` for that transaction. `certified_root` is the
/// certified transaction Merkle root — genesis-anchored only when obtained from a
/// [`crate::mithril::verify_chain_anchored`]-authenticated certificate.
/// `block_number` is the certified height, echoed as `certified_at`.
///
/// The supplied bytes are hashed here (never a provider-supplied hash) and their
/// certified inclusion is checked *before* the output is decoded, so tampered or
/// substituted bytes are rejected as not-included.
pub fn verify_utxo_read(
    tx_bytes: &[u8],
    out_index: usize,
    proof_hex: &[u8],
    certified_root: &[u8; 32],
    block_number: u64,
) -> Result<VerifiedOutput, UtxoError> {
    let h = blake2b256(tx_bytes);
    verify_tx_inclusion(proof_hex, &h, certified_root).map_err(UtxoError::Inclusion)?;

    let (address, lovelace, datum) = decode_output(tx_bytes, out_index)?;
    Ok(VerifiedOutput {
        address,
        lovelace,
        datum,
        certified_at: block_number,
        spend_status: SpendStatus::NotEstablished,
    })
}

/// Decode the set of outpoints a Conway transaction consumes — its inputs
/// (body key 0) and collateral inputs (key 13) — from the raw transaction-body
/// CBOR. This is the forward spend-scan signal: an outpoint's presence here, in a
/// body-committed block, is the on-chain evidence that it was spent.
///
/// A CBOR `set` is encoded either as a bare array or wrapped in tag 258
/// (`#6.258`); both forms are accepted and decode identically. Every deviation —
/// a non-map body, a malformed input, an output index wider than the protocol's
/// `uint .size 2` — fails closed to [`UtxoError::MalformedTx`], because a spend a
/// decoder silently drops is a spend a watcher would wrongly call unspent.
pub fn decode_spends(tx_bytes: &[u8]) -> Result<SpendSet, UtxoError> {
    let mut d = Decoder::new(tx_bytes);
    let entries = d
        .map()
        .map_err(|_| UtxoError::MalformedTx)?
        .ok_or(UtxoError::MalformedTx)?;
    let mut spends = SpendSet::new();
    for _ in 0..entries {
        match d.u64().map_err(|_| UtxoError::MalformedTx)? {
            // key 0 = inputs, key 13 = collateral inputs — both are spends.
            0 | 13 => decode_input_set(&mut d, &mut spends)?,
            // key 18 = reference inputs (read, not consumed) and every other
            // field are skipped.
            _ => d.skip().map_err(|_| UtxoError::MalformedTx)?,
        }
    }
    Ok(spends)
}

/// Decode a `set<transaction_input>` (bare array or tag-258 wrapped) into `spends`.
fn decode_input_set(d: &mut Decoder<'_>, spends: &mut SpendSet) -> Result<(), UtxoError> {
    if d.datatype().map_err(|_| UtxoError::MalformedTx)? == Type::Tag {
        let tag = d.tag().map_err(|_| UtxoError::MalformedTx)?;
        if tag.as_u64() != 258 {
            return Err(UtxoError::MalformedTx);
        }
    }
    let count = d
        .array()
        .map_err(|_| UtxoError::MalformedTx)?
        .ok_or(UtxoError::MalformedTx)?;
    for _ in 0..count {
        spends.insert(decode_outpoint(d)?);
    }
    Ok(())
}

/// Decode one Conway `transaction_input` = `[ transaction_id : $hash32,
/// index : uint .size 2 ]`. An index wider than `u16` is out of protocol range.
fn decode_outpoint(d: &mut Decoder<'_>) -> Result<OutPoint, UtxoError> {
    if d.array()
        .map_err(|_| UtxoError::MalformedTx)?
        .ok_or(UtxoError::MalformedTx)?
        != 2
    {
        return Err(UtxoError::MalformedTx);
    }
    let tx_id = read_hash32(d)?;
    let index = u16::try_from(d.u64().map_err(|_| UtxoError::MalformedTx)?)
        .map_err(|_| UtxoError::MalformedTx)?;
    Ok(OutPoint { tx_id, index })
}

/// Whether Conway transaction body `tx_bytes` produced an output at `out_index` — the
/// outputs array (key 1) has more than `out_index` entries. Binds a windowed "creation
/// observed" to the outpoint's ACTUAL existence (the creating transaction really made
/// an output at that index), not merely to the transaction's presence, so a phantom
/// index is never read as created. Fail-closed: a malformed body is `Err`, never a
/// phantom `Ok(true)`.
pub fn output_exists(tx_bytes: &[u8], out_index: usize) -> Result<bool, UtxoError> {
    match decode_output(tx_bytes, out_index) {
        Ok(_) => Ok(true),
        Err(UtxoError::OutputIndexOutOfRange) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Decode output `out_index` from a Conway transaction-body CBOR map (key 1 =
/// outputs). Untrusted CBOR, so a definite-map shape is required and every
/// deviation fails closed.
fn decode_output(tx_bytes: &[u8], out_index: usize) -> Result<Output, UtxoError> {
    let mut d = Decoder::new(tx_bytes);
    let entries = d
        .map()
        .map_err(|_| UtxoError::MalformedTx)?
        .ok_or(UtxoError::MalformedTx)?;
    for _ in 0..entries {
        let key = d.u64().map_err(|_| UtxoError::MalformedTx)?;
        if key == 1 {
            return decode_output_at(&mut d, out_index);
        }
        d.skip().map_err(|_| UtxoError::MalformedTx)?;
    }
    Err(UtxoError::MalformedTx)
}

/// The decoded read-path fields of a single output.
type Output = (Vec<u8>, u64, Option<Datum>);

fn decode_output_at(d: &mut Decoder<'_>, out_index: usize) -> Result<Output, UtxoError> {
    let count = d
        .array()
        .map_err(|_| UtxoError::MalformedTx)?
        .ok_or(UtxoError::MalformedTx)?;
    if out_index as u64 >= count {
        return Err(UtxoError::OutputIndexOutOfRange);
    }
    for _ in 0..out_index {
        d.skip().map_err(|_| UtxoError::MalformedTx)?;
    }
    decode_single_output(d)
}

/// A Conway output is a post-Alonzo map (`{0: address, 1: value, 2?: datum_option,
/// 3?: script_ref}`) or a legacy array (`[address, value]` or
/// `[address, value, datum_hash]`).
fn decode_single_output(d: &mut Decoder<'_>) -> Result<Output, UtxoError> {
    match d.datatype().map_err(|_| UtxoError::MalformedTx)? {
        Type::Map => decode_map_output(d),
        Type::Array => decode_legacy_output(d),
        _ => Err(UtxoError::MalformedTx),
    }
}

fn decode_map_output(d: &mut Decoder<'_>) -> Result<Output, UtxoError> {
    let entries = d
        .map()
        .map_err(|_| UtxoError::MalformedTx)?
        .ok_or(UtxoError::MalformedTx)?;
    let mut address: Option<Vec<u8>> = None;
    let mut lovelace: Option<u64> = None;
    let mut datum: Option<Datum> = None;
    for _ in 0..entries {
        match d.u64().map_err(|_| UtxoError::MalformedTx)? {
            0 => address = Some(read_bytes(d)?),
            1 => lovelace = Some(decode_value(d)?),
            2 => datum = Some(decode_datum_option(d)?),
            // 3 = script_ref (not part of the read-path verdict), or a future key.
            _ => d.skip().map_err(|_| UtxoError::MalformedTx)?,
        }
    }
    Ok((
        address.ok_or(UtxoError::MalformedTx)?,
        lovelace.ok_or(UtxoError::MalformedTx)?,
        datum,
    ))
}

fn decode_legacy_output(d: &mut Decoder<'_>) -> Result<Output, UtxoError> {
    let len = d
        .array()
        .map_err(|_| UtxoError::MalformedTx)?
        .ok_or(UtxoError::MalformedTx)?;
    if len != 2 && len != 3 {
        return Err(UtxoError::MalformedTx);
    }
    let address = read_bytes(d)?;
    let lovelace = decode_value(d)?;
    let datum = if len == 3 {
        Some(Datum::Hash(read_hash32(d)?))
    } else {
        None
    };
    Ok((address, lovelace, datum))
}

/// A Cardano value is a bare `coin` uint, or `[coin, multiasset]`. Only the coin is
/// part of the read-path verdict; the multi-asset bundle is skipped.
fn decode_value(d: &mut Decoder<'_>) -> Result<u64, UtxoError> {
    if d.datatype().map_err(|_| UtxoError::MalformedTx)? == Type::Array {
        let len = d
            .array()
            .map_err(|_| UtxoError::MalformedTx)?
            .ok_or(UtxoError::MalformedTx)?;
        if len != 2 {
            return Err(UtxoError::MalformedTx);
        }
        let coin = d.u64().map_err(|_| UtxoError::MalformedTx)?;
        d.skip().map_err(|_| UtxoError::MalformedTx)?; // multiasset map
        Ok(coin)
    } else {
        d.u64().map_err(|_| UtxoError::MalformedTx)
    }
}

/// A Conway `datum_option`: `[0, $hash32]` (a datum hash) or
/// `[1, #6.24(bytes .cbor plutus_data)]` (an inline datum).
fn decode_datum_option(d: &mut Decoder<'_>) -> Result<Datum, UtxoError> {
    if d.array()
        .map_err(|_| UtxoError::MalformedTx)?
        .ok_or(UtxoError::MalformedTx)?
        != 2
    {
        return Err(UtxoError::MalformedTx);
    }
    match d.u64().map_err(|_| UtxoError::MalformedTx)? {
        0 => Ok(Datum::Hash(read_hash32(d)?)),
        1 => {
            // The inline datum is a `#6.24` (encoded-CBOR) tag wrapping the plutus
            // data bytes; require the exact tag and return the wrapped bytes.
            if d.tag().map_err(|_| UtxoError::MalformedTx)?.as_u64() != 24 {
                return Err(UtxoError::MalformedTx);
            }
            Ok(Datum::Inline(read_bytes(d)?))
        }
        _ => Err(UtxoError::MalformedTx),
    }
}

/// Read a definite byte string.
fn read_bytes(d: &mut Decoder<'_>) -> Result<Vec<u8>, UtxoError> {
    if d.datatype().map_err(|_| UtxoError::MalformedTx)? != Type::Bytes {
        return Err(UtxoError::MalformedTx);
    }
    Ok(d.bytes().map_err(|_| UtxoError::MalformedTx)?.to_vec())
}

/// Read a definite 32-byte hash.
fn read_hash32(d: &mut Decoder<'_>) -> Result<[u8; 32], UtxoError> {
    if d.datatype().map_err(|_| UtxoError::MalformedTx)? != Type::Bytes {
        return Err(UtxoError::MalformedTx);
    }
    d.bytes()
        .map_err(|_| UtxoError::MalformedTx)?
        .try_into()
        .map_err(|_| UtxoError::MalformedTx)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time honesty tripwire: `SpendStatus` has exactly one inhabitant
    /// today. This same-crate exhaustive match (no wildcard) fails to compile the
    /// moment a liveness tier is added, forcing the author to consciously wire it
    /// and update the honest-scope docs — `#[non_exhaustive]` relaxes matching only
    /// for *external* crates, never here.
    #[test]
    fn spend_status_has_a_single_inhabitant_today() {
        match SpendStatus::NotEstablished {
            SpendStatus::NotEstablished => {}
        }
    }

    /// A minimal tx body `{1: [output]}` around a single output.
    fn body_with_output(output_cbor: &[u8]) -> Vec<u8> {
        let mut v = vec![0xa1, 0x01, 0x81];
        v.extend_from_slice(output_cbor);
        v
    }

    #[test]
    fn decodes_a_legacy_output_with_a_datum_hash() {
        // [address(1), coin 0, datum_hash(32)].
        let mut out = vec![0x83, 0x41, 0x00, 0x00, 0x58, 0x20];
        out.extend_from_slice(&[0x11u8; 32]);
        let (addr, lovelace, datum) = decode_output(&body_with_output(&out), 0).unwrap();
        assert_eq!(addr, vec![0x00]);
        assert_eq!(lovelace, 0);
        assert_eq!(datum, Some(Datum::Hash([0x11u8; 32])));
    }

    #[test]
    fn decodes_a_map_output_with_a_datum_hash_option() {
        // {0: address(1), 1: coin 7, 2: [0, datum_hash(32)]}.
        let mut out = vec![
            0xa3, 0x00, 0x41, 0x00, 0x01, 0x07, 0x02, 0x82, 0x00, 0x58, 0x20,
        ];
        out.extend_from_slice(&[0x22u8; 32]);
        let (addr, lovelace, datum) = decode_output(&body_with_output(&out), 0).unwrap();
        assert_eq!(addr, vec![0x00]);
        assert_eq!(lovelace, 7);
        assert_eq!(datum, Some(Datum::Hash([0x22u8; 32])));
    }

    #[test]
    fn rejects_a_non_map_transaction_body() {
        assert_eq!(decode_output(&[0x81, 0x00], 0), Err(UtxoError::MalformedTx));
    }

    #[test]
    fn rejects_a_body_with_no_outputs_field() {
        // {0: 0} — an inputs-only map, no key 1.
        assert_eq!(
            decode_output(&[0xa1, 0x00, 0x00], 0),
            Err(UtxoError::MalformedTx)
        );
    }

    #[test]
    fn rejects_an_output_that_is_neither_map_nor_array() {
        assert_eq!(
            decode_output(&body_with_output(&[0x00]), 0),
            Err(UtxoError::MalformedTx)
        );
    }

    #[test]
    fn rejects_a_map_output_missing_its_address() {
        // {1: coin 0} — no key 0.
        assert_eq!(
            decode_output(&body_with_output(&[0xa1, 0x01, 0x00]), 0),
            Err(UtxoError::MalformedTx)
        );
    }

    #[test]
    fn rejects_an_out_of_range_index() {
        let out = vec![0x82, 0x41, 0x00, 0x00]; // [address(1), coin 0]
        assert_eq!(
            decode_output(&body_with_output(&out), 1),
            Err(UtxoError::OutputIndexOutOfRange)
        );
    }

    // ---- decode_spends (the tx-INPUT decoder) ----

    /// A 32-byte transaction id filled with `b`.
    fn txid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// A Conway `transaction_input` = `[ $hash32, index ]`, `index` supplied as its
    /// raw CBOR so a test can encode an out-of-protocol-range index.
    fn input_cbor(id: &[u8; 32], index_cbor: &[u8]) -> Vec<u8> {
        let mut v = vec![0x82, 0x58, 0x20];
        v.extend_from_slice(id);
        v.extend_from_slice(index_cbor);
        v
    }

    /// A bare-array `set` of inputs: `[ input, .. ]`.
    fn bare_set(inputs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0x80 | inputs.len() as u8];
        for i in inputs {
            v.extend_from_slice(i);
        }
        v
    }

    /// A tag-258 wrapped `set` of inputs: `#6.258([ input, .. ])`.
    fn tagged_set(inputs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0xd9, 0x01, 0x02];
        v.extend_from_slice(&bare_set(inputs));
        v
    }

    /// A one-field tx body `{ key: value }`.
    fn body1(key: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![0xa1, key];
        v.extend_from_slice(value);
        v
    }

    /// A two-field tx body `{ k0: v0, k1: v1 }`.
    fn body2(k0: u8, v0: &[u8], k1: u8, v1: &[u8]) -> Vec<u8> {
        let mut v = vec![0xa2, k0];
        v.extend_from_slice(v0);
        v.push(k1);
        v.extend_from_slice(v1);
        v
    }

    #[test]
    fn tag258_and_bare_array_decode_to_the_same_outpoint() {
        let id = txid(0xab);
        let inp = input_cbor(&id, &[0x03]); // index 3
        let bare = decode_spends(&body1(0x00, &bare_set(std::slice::from_ref(&inp)))).unwrap();
        let tagged = decode_spends(&body1(0x00, &tagged_set(std::slice::from_ref(&inp)))).unwrap();
        let expected: SpendSet = [OutPoint {
            tx_id: id,
            index: 3,
        }]
        .into_iter()
        .collect();
        assert_eq!(bare, expected);
        assert_eq!(tagged, expected);
        assert_eq!(bare, tagged);
    }

    #[test]
    fn collateral_key13_is_a_spend() {
        let id = txid(0xcd);
        let body = body1(0x0d, &bare_set(&[input_cbor(&id, &[0x00])])); // key 13
        let expected: SpendSet = [OutPoint {
            tx_id: id,
            index: 0,
        }]
        .into_iter()
        .collect();
        assert_eq!(decode_spends(&body).unwrap(), expected);
    }

    #[test]
    fn reference_input_key18_is_not_a_spend() {
        let spent = txid(0x01);
        let referenced = txid(0x02);
        let body = body2(
            0x00,
            &bare_set(&[input_cbor(&spent, &[0x00])]),
            0x12, // key 18 = reference_inputs (read, not consumed)
            &bare_set(&[input_cbor(&referenced, &[0x00])]),
        );
        let spends = decode_spends(&body).unwrap();
        assert!(spends.contains(&OutPoint {
            tx_id: spent,
            index: 0
        }));
        assert!(!spends.contains(&OutPoint {
            tx_id: referenced,
            index: 0
        }));
        assert_eq!(spends.len(), 1);
    }

    #[test]
    fn malformed_input_body_is_malformed_tx() {
        // key 0's set element is a bare uint, not a `[ $hash32, index ]` pair.
        let body = body1(0x00, &[0x81, 0x00]);
        assert_eq!(decode_spends(&body), Err(UtxoError::MalformedTx));
    }

    #[test]
    fn overwide_index_is_malformed_tx() {
        let id = txid(0x07);
        // index 65536 = 0x1a 00 01 00 00, one past u16::MAX.
        let over = body1(
            0x00,
            &bare_set(&[input_cbor(&id, &[0x1a, 0x00, 0x01, 0x00, 0x00])]),
        );
        assert_eq!(decode_spends(&over), Err(UtxoError::MalformedTx));
        // The exact u16 boundary (65535 = 0x19 ff ff) is accepted.
        let max = body1(0x00, &bare_set(&[input_cbor(&id, &[0x19, 0xff, 0xff])]));
        let expected: SpendSet = [OutPoint {
            tx_id: id,
            index: u16::MAX,
        }]
        .into_iter()
        .collect();
        assert_eq!(decode_spends(&max).unwrap(), expected);
    }
}
