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
//! honesty is enforced in the return type: this single-tx read path yields only
//! [`SpendStatus::NotEstablished`], and every verdict carries `certified_at` so no
//! caller may read it as tip state. The stronger Tier-2 [`SpendStatus::CertifiedUnspent`]
//! (unspent across a verified window from a certified snapshot) comes from the
//! certified-state path ([`crate::utxoset::UtxoSet::certified_spend_status`]), not
//! this one — the ladder is `#[non_exhaustive]` and uncoercible to unconditional liveness.
//!
//! ## The bytes are hashed here, never trusted from a provider
//! `verify_utxo_read` hashes the *supplied* `tx_bytes` to obtain `H`
//! (`Blake2b-256`), never a provider-supplied hash. So a provider cannot pair one
//! transaction's proof with another transaction's bytes: substituted or tampered
//! bytes hash to a value that is not a leaf of the proof and are rejected as
//! not-included before any output is decoded.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

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

/// The trust class the certified snapshot state `UTxOSet(S)` rests on — the ONE distinction
/// between a stake-quorum recomputation and a single-key snapshot, made impossible to drop.
///
/// The immutable blocks are certified by Mithril's STM stake quorum; the cardano-database
/// *ancillary* (the ledger-state snapshot) is signed by a single IOG-operated Ed25519 key — a
/// weaker trust class. Bootstrapping `UTxOSet(S)` from the ancillary swaps the anchor's STATE onto
/// that single key while the chain above stays quorum-certified; a consumer must see that, banded
/// distinctly (as at the C ABI the spend-status tiers are), and never mistake it for the quorum.
///
/// [`AnchorBasis::AncillarySigned`] is DISCHARGEABLE to [`AnchorBasis::StmCertified`]: because the
/// blocks are STM-certified, the verified extraction path ([`crate::effects::extract_block_effects`]
/// applied through the UTxO engine) can recompute `UTxOSet(S)` from certified blocks INDEPENDENTLY
/// of the ancillary — a from-genesis audit once, then incremental audits reusing the same
/// primitive. After a matching audit's hash agrees, the same S is `StmCertified`, and the IOG key
/// is a bootstrap convenience rather than a standing safety dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorBasis {
    /// `UTxOSet(S)` recomputed from the STM-stake-quorum-certified immutable blocks via the
    /// verified extraction path — the same decentralized quorum the chain rests on.
    StmCertified,
    /// `UTxOSet(S)` taken from the Mithril cardano-database ancillary, signed by a single
    /// IOG-operated Ed25519 key — NOT the stake quorum. A bootstrap convenience, dischargeable
    /// to [`AnchorBasis::StmCertified`] by a matching extraction audit.
    AncillarySigned,
}

/// The spend verdict a read-path verifier can make. Deliberately has no unconditional `Unspent`:
/// the single-tx read path CANNOT establish liveness (see the module docs), so no code path can
/// coerce a verdict into a positive-liveness claim.
///
/// `#[non_exhaustive]` marks this as a forward-compatible TRUST-TIER LADDER — a future tier is
/// additive (a new variant), never a layout break, and an external `match` must carry a wildcard so
/// a new tier can never be silently read as `NotEstablished`. This is the ONE canonical home of the
/// ladder; the windowed read-path ([`crate::window::WatchBasis`]) mirrors Tier 1 over a watch and
/// defers here for the full enumeration rather than re-listing the tiers:
/// * **Tier 1 — [`SpendStatus::NotEstablished`] (single-tx read).** Inclusion + provenance are
///   proven; liveness is not, and cannot be, established by that path. The windowed watch path
///   establishes the stronger "no spend across a verified window" evidence and surfaces it as
///   [`crate::window::WatchBasis::WatchedWindow`].
/// * **Tier 2 — [`SpendStatus::CertifiedUnspent`] (DEFINED, CRYPTOGRAPHIC).** The Tier-2
///   certified-state ledger: the outpoint is a member of `UTxOSet(S)` (certified under an
///   [`AnchorBasis`]) and no spend was observed across the verified window `(S, tip]` — so it is
///   unspent *as of* `through_block`, scoped to that recency and labelled with the basis it rests
///   on. Never an unconditional-liveness claim: the ledger still decides atomically at submission.
/// * **Tier 3 — `Attested { committee, at }` (reserved, ECONOMIC).** A Materios / Witness-Network
///   committee attestation of liveness.
///
/// LOAD-BEARING INVARIANT: an economic tier (3) is NEVER coercible into a cryptographic one (2),
/// and within Tier 2 an [`AnchorBasis::AncillarySigned`] snapshot is never coercible into a
/// [`AnchorBasis::StmCertified`] one — the basis rides INSIDE the variant, so a consumer cannot read
/// a single-key snapshot as a stake-quorum one. A consumer must always see the trust basis and can
/// never mistake an attestation for a proof — which is why the tiers are distinct variants (and, at
/// the C ABI, distinct code bands), not a shared boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpendStatus {
    /// Spend state is not established, and cannot be by the single-tx path (Tier 1).
    NotEstablished,
    /// The outpoint is unspent as of `through_block`, in a set that descends from a certified
    /// snapshot S (of trust class `basis`) and was advanced only by header-verified, body-committed,
    /// contiguous blocks (Tier 2). This covers BOTH an outpoint carried in `UTxOSet(S)` and still
    /// unspent, AND one created within the verified window `(S, through_block]` and still unspent —
    /// the claim is "unspent in the certified-anchored, header-verified set", NOT "a member of
    /// `UTxOSet(S)`" specifically. Scoped to `through_block` and labelled with `basis`; never an
    /// unconditional-liveness claim (the ledger still decides at submission).
    CertifiedUnspent {
        /// The trust class of the ANCHOR S the set descends from (uncoercible: read the basis here,
        /// never assume the stronger one). Bound from the set's [`crate::utxoset::SnapshotAnchor`]
        /// at construction, never chosen at query time.
        basis: AnchorBasis,
        /// The tip block number through which the no-spend window was maintained — the recency the
        /// consumer must carry (the verdict ages as the chain advances past it).
        through_block: u64,
        /// Whether the WHOLE no-spend window `(S, through_block]` lies within the Mithril
        /// `CardanoTransactions`-certified region (`through_block <= the latest verified cert's
        /// block_number`). `true`: no-spend is backed by the STM stake quorum's transaction
        /// certification — a spend of the outpoint would be in the certified tx set. `false`:
        /// `through_block` is above the certified frontier, so the tail of the window is only
        /// HEADER-VOUCHED (honest-majority block authorship), not quorum-backed. This mirrors
        /// [`crate::window::WindowAssumptions::mithril_quorum`] / [`crate::window::SpendRegion`]
        /// exactly, so the window's trust is machine-readable here, never merely prose — a consumer
        /// can never read a header-vouched tail as quorum-certified.
        mithril_quorum: bool,
    },
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

impl core::error::Error for UtxoError {}

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
    let len = d.map().map_err(|_| UtxoError::MalformedTx)?;
    let mut spends = SpendSet::new();
    let mut i = 0;
    while seq_has_next(&mut d, len, i)? {
        match d.u64().map_err(|_| UtxoError::MalformedTx)? {
            // key 0 = inputs, key 13 = collateral inputs — both are spends.
            0 | 13 => decode_input_set(&mut d, &mut spends)?,
            // key 18 = reference inputs (read, not consumed) and every other
            // field are skipped.
            _ => skip_item(&mut d)?,
        }
        i += 1;
    }
    Ok(spends)
}

/// Whether a CBOR sequence (map or array) declared with header length `len` — `Some(n)` definite,
/// `None` indefinite — has another item before position `i`. On an indefinite sequence this
/// consumes the closing `Break` when the sequence ends. Cardano/Conway encodes body maps, input
/// sets, and output lists in EITHER length form (a real preprod block encodes outputs indefinitely),
/// so every tx-body navigator must accept both rather than rejecting the indefinite form.
pub(crate) fn seq_has_next(
    d: &mut Decoder<'_>,
    len: Option<u64>,
    i: u64,
) -> Result<bool, UtxoError> {
    match len {
        Some(n) => Ok(i < n),
        None => {
            if d.datatype().map_err(|_| UtxoError::MalformedTx)? == Type::Break {
                d.skip().map_err(|_| UtxoError::MalformedTx)?;
                Ok(false)
            } else {
                Ok(true)
            }
        }
    }
}

/// The outpoints in the transaction body's input set at CBOR map key `key`, in array order —
/// `0` = inputs (consumed by a phase-2-valid transaction), `13` = collateral inputs (consumed
/// by a phase-2-INVALID one). Empty if the key is absent (a transaction with no collateral).
/// Unlike [`decode_spends`], which unions both as "could be spent", this reads exactly ONE
/// set, so a UTxO-set apply consumes the inputs a valid transaction spends and the collateral
/// an invalid one spends — never both.
pub fn inputs_at(tx_bytes: &[u8], key: u64) -> Result<Vec<OutPoint>, UtxoError> {
    let mut d = Decoder::new(tx_bytes);
    let len = d.map().map_err(|_| UtxoError::MalformedTx)?;
    let mut i = 0;
    while seq_has_next(&mut d, len, i)? {
        if d.u64().map_err(|_| UtxoError::MalformedTx)? == key {
            return decode_input_vec(&mut d);
        }
        skip_item(&mut d)?;
        i += 1;
    }
    Ok(Vec::new())
}

/// Read the header of a `set<transaction_input>` (bare array or tag-258 wrapped), returning its
/// definite length or `None` for the indefinite form.
pub(crate) fn input_set_len(d: &mut Decoder<'_>) -> Result<Option<u64>, UtxoError> {
    if d.datatype().map_err(|_| UtxoError::MalformedTx)? == Type::Tag {
        let tag = d.tag().map_err(|_| UtxoError::MalformedTx)?;
        if tag.as_u64() != 258 {
            return Err(UtxoError::MalformedTx);
        }
    }
    d.array().map_err(|_| UtxoError::MalformedTx)
}

/// Decode a `set<transaction_input>` (bare array or tag-258 wrapped, definite or indefinite) into
/// an ordered `Vec`.
fn decode_input_vec(d: &mut Decoder<'_>) -> Result<Vec<OutPoint>, UtxoError> {
    let len = input_set_len(d)?;
    // Grow as elements decode rather than pre-allocating on the untrusted array count: a
    // direct caller of `inputs_at` with a body declaring a huge count would otherwise force a
    // capacity-overflow before any element is read. Each real element is bounds-checked by
    // `decode_outpoint`, so the vec never exceeds the wire bytes.
    let mut out = Vec::new();
    let mut i = 0;
    while seq_has_next(d, len, i)? {
        out.push(decode_outpoint(d)?);
        i += 1;
    }
    Ok(out)
}

/// Whether the transaction body carries CBOR map key `key` — used to detect a collateral
/// return (key 16), which a phase-2-invalid transaction produces at output index `|outputs|`.
pub fn has_body_key(tx_bytes: &[u8], key: u64) -> Result<bool, UtxoError> {
    let mut d = Decoder::new(tx_bytes);
    let len = d.map().map_err(|_| UtxoError::MalformedTx)?;
    let mut i = 0;
    while seq_has_next(&mut d, len, i)? {
        if d.u64().map_err(|_| UtxoError::MalformedTx)? == key {
            return Ok(true);
        }
        skip_item(&mut d)?;
        i += 1;
    }
    Ok(false)
}

/// The number of outputs a transaction body produces (the length of its key-1 outputs array) —
/// the count of created outpoints `(tx_id, 0..n)`. The outputs are walked in either length
/// form (a real preprod block encodes them indefinitely) and each must be an output, a map or
/// a legacy array, so a header can never count an item that is not there or is no output. The
/// body is walked to its end; one with no outputs key, or with two, is malformed.
pub fn output_count(tx_bytes: &[u8]) -> Result<usize, UtxoError> {
    let mut d = Decoder::new(tx_bytes);
    let len = d.map().map_err(|_| UtxoError::MalformedTx)?;
    let mut count = None;
    let mut i = 0;
    while seq_has_next(&mut d, len, i)? {
        if d.u64().map_err(|_| UtxoError::MalformedTx)? == 1 {
            let outputs = d.array().map_err(|_| UtxoError::MalformedTx)?;
            let mut n = 0;
            while seq_has_next(&mut d, outputs, n)? {
                if !matches!(
                    d.datatype().map_err(|_| UtxoError::MalformedTx)?,
                    Type::Map | Type::MapIndef | Type::Array | Type::ArrayIndef
                ) {
                    return Err(UtxoError::MalformedTx);
                }
                d.skip().map_err(|_| UtxoError::MalformedTx)?;
                n += 1;
            }
            if count.replace(n).is_some() {
                return Err(UtxoError::MalformedTx);
            }
        } else {
            skip_item(&mut d)?;
        }
        i += 1;
    }
    if d.position() != tx_bytes.len() {
        return Err(UtxoError::MalformedTx);
    }
    usize::try_from(count.ok_or(UtxoError::MalformedTx)?).map_err(|_| UtxoError::MalformedTx)
}

/// Decode a `set<transaction_input>` (bare array or tag-258 wrapped, definite or indefinite) into
/// `spends`.
fn decode_input_set(d: &mut Decoder<'_>, spends: &mut SpendSet) -> Result<(), UtxoError> {
    let len = input_set_len(d)?;
    let mut i = 0;
    while seq_has_next(d, len, i)? {
        spends.insert(decode_outpoint(d)?);
        i += 1;
    }
    Ok(())
}

/// Read the header of an array that must hold exactly `arity` items. A definite header of
/// another length is malformed; an indefinite one is held to `arity` by [`expect_end`].
fn array_of(d: &mut Decoder<'_>, arity: u64) -> Result<Option<u64>, UtxoError> {
    let len = d.array().map_err(|_| UtxoError::MalformedTx)?;
    if len.is_some_and(|n| n != arity) {
        return Err(UtxoError::MalformedTx);
    }
    Ok(len)
}

/// Require a sequence of header length `len` to end after `read` items. An indefinite one
/// must close with its break, which is consumed so the enclosing cursor sits past it.
fn expect_end(d: &mut Decoder<'_>, len: Option<u64>, read: u64) -> Result<(), UtxoError> {
    if seq_has_next(d, len, read)? {
        return Err(UtxoError::MalformedTx);
    }
    Ok(())
}

/// Skip one item where the shape requires one. minicbor's `skip` reads a break as an item,
/// which would let a container short of an item end on the break of the container around
/// it and read on into that container.
pub(crate) fn skip_item(d: &mut Decoder<'_>) -> Result<(), UtxoError> {
    if d.datatype().map_err(|_| UtxoError::MalformedTx)? == Type::Break {
        return Err(UtxoError::MalformedTx);
    }
    d.skip().map_err(|_| UtxoError::MalformedTx)
}

/// Decode one Conway `transaction_input` = `[ transaction_id : $hash32,
/// index : uint .size 2 ]`, in either length form. An index wider than `u16` is out of
/// protocol range.
pub(crate) fn decode_outpoint(d: &mut Decoder<'_>) -> Result<OutPoint, UtxoError> {
    let len = array_of(d, 2)?;
    let tx_id = read_hash32(d)?;
    let index = u16::try_from(d.u64().map_err(|_| UtxoError::MalformedTx)?)
        .map_err(|_| UtxoError::MalformedTx)?;
    expect_end(d, len, 2)?;
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
/// outputs). Every container is read in either length form, as the ledger reads it,
/// and the output's fields as [`decode_single_output`] reads them.
fn decode_output(tx_bytes: &[u8], out_index: usize) -> Result<Output, UtxoError> {
    let mut d = Decoder::new(tx_bytes);
    let len = d.map().map_err(|_| UtxoError::MalformedTx)?;
    let mut i = 0;
    while seq_has_next(&mut d, len, i)? {
        let key = d.u64().map_err(|_| UtxoError::MalformedTx)?;
        if key == 1 {
            return decode_output_at(&mut d, out_index);
        }
        skip_item(&mut d)?;
        i += 1;
    }
    Err(UtxoError::MalformedTx)
}

/// The decoded read-path fields of a single output.
type Output = (Vec<u8>, u64, Option<Datum>);

fn decode_output_at(d: &mut Decoder<'_>, out_index: usize) -> Result<Output, UtxoError> {
    // Walk the outputs array (definite or indefinite) to `out_index`; a target beyond the array is
    // out of range. This handles both length forms without pre-reading a count the indefinite form
    // does not carry.
    let len = d.array().map_err(|_| UtxoError::MalformedTx)?;
    let mut i = 0;
    while seq_has_next(d, len, i)? {
        if i as usize == out_index {
            return decode_single_output(d);
        }
        skip_item(d)?;
        i += 1;
    }
    Err(UtxoError::OutputIndexOutOfRange)
}

/// A Conway output is a post-Alonzo map (`{0: address, 1: value, 2?: datum_option,
/// 3?: script_ref}`) or a legacy array (`[address, value]` or
/// `[address, value, datum_hash]`). The address, coin and datum must decode, and a
/// repeated map key is refused; a key outside 0-2 is skipped unread. This reads the
/// output's read-path fields and validates nothing else in it.
pub(crate) fn decode_single_output(d: &mut Decoder<'_>) -> Result<Output, UtxoError> {
    match d.datatype().map_err(|_| UtxoError::MalformedTx)? {
        Type::Map | Type::MapIndef => decode_map_output(d),
        Type::Array | Type::ArrayIndef => decode_legacy_output(d),
        _ => Err(UtxoError::MalformedTx),
    }
}

fn decode_map_output(d: &mut Decoder<'_>) -> Result<Output, UtxoError> {
    let entries = d.map().map_err(|_| UtxoError::MalformedTx)?;
    let mut address: Option<Vec<u8>> = None;
    let mut lovelace: Option<u64> = None;
    let mut datum: Option<Datum> = None;
    let mut keys = BTreeSet::new();
    let mut i = 0;
    while seq_has_next(d, entries, i)? {
        let key = d.u64().map_err(|_| UtxoError::MalformedTx)?;
        // The ledger refuses a repeated key, which a last-wins read would hide.
        if !keys.insert(key) {
            return Err(UtxoError::MalformedTx);
        }
        match key {
            0 => address = Some(read_bytes(d)?),
            1 => lovelace = Some(decode_value(d)?),
            2 => datum = Some(decode_datum_option(d)?),
            // 3 = script_ref (not part of the read-path verdict), or a future key.
            _ => skip_item(d)?,
        }
        i += 1;
    }
    Ok((
        address.ok_or(UtxoError::MalformedTx)?,
        lovelace.ok_or(UtxoError::MalformedTx)?,
        datum,
    ))
}

fn decode_legacy_output(d: &mut Decoder<'_>) -> Result<Output, UtxoError> {
    let len = d.array().map_err(|_| UtxoError::MalformedTx)?;
    if len.is_some_and(|n| n != 2 && n != 3) {
        return Err(UtxoError::MalformedTx);
    }
    let address = read_bytes(d)?;
    let lovelace = decode_value(d)?;
    let datum = if seq_has_next(d, len, 2)? {
        let hash = read_hash32(d)?;
        expect_end(d, len, 3)?;
        Some(Datum::Hash(hash))
    } else {
        None
    };
    Ok((address, lovelace, datum))
}

/// A Cardano value is a bare `coin` uint, or `[coin, multiasset]` as a definite array:
/// the ledger refuses the indefinite pair. Only the coin is part of the read-path
/// verdict; the multi-asset bundle is skipped.
fn decode_value(d: &mut Decoder<'_>) -> Result<u64, UtxoError> {
    if d.datatype().map_err(|_| UtxoError::MalformedTx)? == Type::Array {
        if d.array().map_err(|_| UtxoError::MalformedTx)? != Some(2) {
            return Err(UtxoError::MalformedTx);
        }
        let coin = d.u64().map_err(|_| UtxoError::MalformedTx)?;
        skip_item(d)?; // multiasset map
        Ok(coin)
    } else {
        d.u64().map_err(|_| UtxoError::MalformedTx)
    }
}

/// A Conway `datum_option`: `[0, $hash32]` (a datum hash) or
/// `[1, #6.24(bytes .cbor plutus_data)]` (an inline datum).
fn decode_datum_option(d: &mut Decoder<'_>) -> Result<Datum, UtxoError> {
    let len = array_of(d, 2)?;
    let datum = match d.u64().map_err(|_| UtxoError::MalformedTx)? {
        0 => Datum::Hash(read_hash32(d)?),
        1 => {
            // The inline datum is a `#6.24` (encoded-CBOR) tag wrapping the plutus
            // data bytes; require the exact tag and return the wrapped bytes.
            if d.tag().map_err(|_| UtxoError::MalformedTx)?.as_u64() != 24 {
                return Err(UtxoError::MalformedTx);
            }
            Datum::Inline(read_bytes(d)?)
        }
        _ => return Err(UtxoError::MalformedTx),
    };
    expect_end(d, len, 2)?;
    Ok(datum)
}

/// Read a definite byte string.
pub(crate) fn read_bytes(d: &mut Decoder<'_>) -> Result<Vec<u8>, UtxoError> {
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

    /// Compile-time honesty tripwire: an exhaustive same-crate match (no wildcard) over every
    /// `SpendStatus` tier. It fails to compile the moment a NEW tier is added, forcing the author to
    /// consciously wire it and update the honest-scope docs — `#[non_exhaustive]` relaxes matching
    /// only for *external* crates, never here. Today: Tier 1 (`NotEstablished`) and the now-DEFINED
    /// Tier 2 (`CertifiedUnspent`, whose T3/T4 proof exists); Tier 3 (attested) stays undefined.
    #[test]
    fn spend_status_tiers_are_exhaustively_wired() {
        let tiers = [
            SpendStatus::NotEstablished,
            SpendStatus::CertifiedUnspent {
                basis: AnchorBasis::AncillarySigned,
                through_block: 1,
                mithril_quorum: false,
            },
        ];
        for tier in tiers {
            match tier {
                SpendStatus::NotEstablished => {}
                SpendStatus::CertifiedUnspent {
                    basis,
                    through_block,
                    mithril_quorum,
                } => {
                    // The basis rides INSIDE the variant — a consumer cannot read the verdict
                    // without seeing whether it is a single-key or stake-quorum snapshot — and the
                    // window's quorum trust is a machine-readable bit, not prose.
                    assert!(matches!(
                        basis,
                        AnchorBasis::AncillarySigned | AnchorBasis::StmCertified
                    ));
                    assert!(through_block > 0);
                    let _machine_readable_window_trust: bool = mithril_quorum;
                }
            }
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

    #[test]
    fn indefinite_output_containers_decode_like_their_definite_twins() {
        let hash = [0x22u8; 32];
        // {0: h'00', 1: [7, {}], 2: [0, hash]}, every container definite.
        let definite = [
            &[
                0xa3, 0x00, 0x41, 0x00, 0x01, 0x82, 0x07, 0xa0, 0x02, 0x82, 0x00, 0x58, 0x20,
            ][..],
            &hash,
        ]
        .concat();
        // The same output with the map and the datum_option indefinite: the map ends only
        // past the datum's break.
        let indefinite = [
            &[
                0xbf, 0x00, 0x41, 0x00, 0x01, 0x82, 0x07, 0xa0, 0x02, 0x9f, 0x00, 0x58, 0x20,
            ][..],
            &hash,
            &[0xff, 0xff],
        ]
        .concat();
        // [h'00', 7, hash], a legacy output, definite and indefinite.
        let legacy = [&[0x83, 0x41, 0x00, 0x07, 0x58, 0x20][..], &hash].concat();
        let legacy_indefinite =
            [&[0x9f, 0x41, 0x00, 0x07, 0x58, 0x20][..], &hash, &[0xff]].concat();
        for output in [definite, indefinite, legacy, legacy_indefinite] {
            assert_eq!(
                decode_output(&body_with_output(&output), 0),
                Ok((vec![0x00], 7, Some(Datum::Hash(hash)))),
                "{output:02x?}"
            );
        }
        // [h'00', 7] and [_ h'00', 7]: a legacy output of two elements carries no datum.
        for output in [
            &[0x82, 0x41, 0x00, 0x07][..],
            &[0x9f, 0x41, 0x00, 0x07, 0xff],
        ] {
            assert_eq!(
                decode_output(&body_with_output(output), 0),
                Ok((vec![0x00], 7, None)),
                "{output:02x?}"
            );
        }
    }

    #[test]
    fn definite_containers_keep_their_exact_arity() {
        // Each container is one element short, and the item after it would complete the
        // shape for a decoder that ignored the header's count.
        let short_input = [&[0x81, 0x58, 0x20][..], &txid(0x34), &[0x05]].concat();
        assert_eq!(
            decode_outpoint(&mut Decoder::new(&short_input)),
            Err(UtxoError::MalformedTx)
        );
        assert_eq!(
            decode_single_output(&mut Decoder::new(&[0x81, 0x41, 0x00, 0x07])),
            Err(UtxoError::MalformedTx)
        );
        assert_eq!(
            decode_value(&mut Decoder::new(&[0x81, 0x07, 0xa0])),
            Err(UtxoError::MalformedTx)
        );
        let short_datum = [&[0x81, 0x00, 0x58, 0x20][..], &[0x22; 32]].concat();
        assert_eq!(
            decode_datum_option(&mut Decoder::new(&short_datum)),
            Err(UtxoError::MalformedTx)
        );
    }

    #[test]
    fn an_indefinite_value_is_refused_as_the_ledger_refuses_it() {
        // [_ 7, {}]: cardano-cli 11.0 refuses the indefinite [coin, multiasset] pair
        // ("Excess terms"), in a map output and in a legacy one alike.
        for output in [
            vec![0xa2, 0x00, 0x41, 0x00, 0x01, 0x9f, 0x07, 0xa0, 0xff],
            vec![0x82, 0x41, 0x00, 0x9f, 0x07, 0xa0, 0xff],
        ] {
            assert_eq!(
                decode_output(&body_with_output(&output), 0),
                Err(UtxoError::MalformedTx),
                "{output:02x?}"
            );
        }
    }

    #[test]
    fn output_count_walks_the_outputs_it_counts() {
        // o = [h'00', 7], a legacy output.
        let o = [0x82, 0x41, 0x00, 0x07];
        let count =
            |outputs: &[&[u8]]| output_count(&[&[0xa1, 0x01][..], &outputs.concat()].concat());
        assert_eq!(count(&[&[0x82], &o, &o]), Ok(2));
        assert_eq!(count(&[&[0x9f], &o, &o, &[0xff]]), Ok(2));
        for outputs in [
            // Declared two, one present.
            &[&[0x82][..], &o][..],
            // Declared one, two present.
            &[&[0x81], &o, &o],
            // A break, and a number, where the second output is due.
            &[&[0x82], &o, &[0xff]],
            &[&[0x82], &o, &[0x05]],
            // The second output cut short.
            &[&[0x82], &o, &o[..3]],
        ] {
            assert_eq!(
                count(outputs),
                Err(UtxoError::MalformedTx),
                "{outputs:02x?}"
            );
        }
        // {1: [o], 1: [o]}: the outputs key repeated.
        let repeated = [&[0xa2, 0x01, 0x81][..], &o, &[0x01, 0x81], &o].concat();
        assert_eq!(output_count(&repeated), Err(UtxoError::MalformedTx));
    }

    #[test]
    fn indefinite_output_containers_keep_their_arity() {
        let hash = [0x22u8; 32];
        for output in [
            // A map output the body ends inside, before its break.
            vec![0xbf, 0x00, 0x41, 0x00, 0x01, 0x07],
            // A map output without its address.
            vec![0xbf, 0x01, 0x07, 0xff],
            // A legacy output of one element, and of four.
            vec![0x9f, 0x41, 0x00, 0xff],
            [
                &[0x9f, 0x41, 0x00, 0x07, 0x58, 0x20][..],
                &hash,
                &[0x00, 0xff],
            ]
            .concat(),
            // A value of one element, and of three.
            vec![0xa2, 0x00, 0x41, 0x00, 0x01, 0x9f, 0x07, 0xff],
            vec![0xa2, 0x00, 0x41, 0x00, 0x01, 0x9f, 0x07, 0xa0, 0x00, 0xff],
            // A datum_option of three elements.
            [
                &[
                    0xa3, 0x00, 0x41, 0x00, 0x01, 0x07, 0x02, 0x9f, 0x00, 0x58, 0x20,
                ][..],
                &hash,
                &[0x00, 0xff],
            ]
            .concat(),
        ] {
            assert_eq!(
                decode_output(&body_with_output(&output), 0),
                Err(UtxoError::MalformedTx),
                "{output:02x?}"
            );
        }
    }

    #[test]
    fn a_missing_item_cannot_borrow_the_enclosing_break() {
        // Each output lacks a required item and sits in an indefinite outputs array. A decoder
        // that read a break as the item would close the output on the next break up or, in
        // the first case, read on into the array and take h'bb' as the address.
        for outputs in [
            // [_ {_ 0: h'aa', 1: 7, 3: }, 0, h'bb']: key 3 without its value.
            vec![
                0x9f, 0xbf, 0x00, 0x41, 0xaa, 0x01, 0x07, 0x03, 0xff, 0x00, 0x41, 0xbb, 0xff,
            ],
            vec![0x9f, 0xbf, 0x00, 0x41, 0x00, 0x01, 0x07, 0x03, 0xff, 0xff],
            // [_ {_ 0: h'00', 1: [_ 7]}]: a value without its multiasset.
            vec![
                0x9f, 0xbf, 0x00, 0x41, 0x00, 0x01, 0x9f, 0x07, 0xff, 0xff, 0xff,
            ],
        ] {
            let body = [&[0xa1, 0x01][..], &outputs].concat();
            assert_eq!(
                decode_output(&body, 0),
                Err(UtxoError::MalformedTx),
                "{body:02x?}"
            );
        }
    }

    #[test]
    fn a_repeated_output_key_is_refused() {
        // The ledger refuses a repeated output-map key in either length form; a last-wins
        // read would bind one of several values.
        let hash = [0x22u8; 32];
        for output in [
            // {0: h'00', 0: h'01', 1: 7}
            vec![0xa3, 0x00, 0x41, 0x00, 0x00, 0x41, 0x01, 0x01, 0x07],
            // {0: h'00', 1: 7, 1: 8}
            vec![0xa3, 0x00, 0x41, 0x00, 0x01, 0x07, 0x01, 0x08],
            // {_ 0: h'00', 1: 7, 9: 0, 9: 0}
            vec![
                0xbf, 0x00, 0x41, 0x00, 0x01, 0x07, 0x09, 0x00, 0x09, 0x00, 0xff,
            ],
            // {0: h'00', 1: 7, 2: [0, hash], 2: [0, hash]}
            [
                &[
                    0xa4, 0x00, 0x41, 0x00, 0x01, 0x07, 0x02, 0x82, 0x00, 0x58, 0x20,
                ][..],
                &hash,
                &[0x02, 0x82, 0x00, 0x58, 0x20],
                &hash,
            ]
            .concat(),
        ] {
            assert_eq!(
                decode_output(&body_with_output(&output), 0),
                Err(UtxoError::MalformedTx),
                "{output:02x?}"
            );
        }
    }

    #[test]
    fn a_break_is_no_item_where_one_is_due() {
        // {5: break}: a definite body map whose value is a stray break.
        let stray = [0xa1, 0x05, 0xff];
        assert_eq!(decode_spends(&stray), Err(UtxoError::MalformedTx));
        assert_eq!(inputs_at(&stray, 0), Err(UtxoError::MalformedTx));
        assert_eq!(has_body_key(&stray, 16), Err(UtxoError::MalformedTx));
        // {5: break, 1: [[h'00', 7]]}
        let before_outputs = [0xa2, 0x05, 0xff, 0x01, 0x81, 0x82, 0x41, 0x00, 0x07];
        assert_eq!(output_count(&before_outputs), Err(UtxoError::MalformedTx));
        assert_eq!(
            decode_output(&before_outputs, 0),
            Err(UtxoError::MalformedTx)
        );
        // {1: [break, [h'00', 7]]}: a stray break before the output read.
        assert_eq!(
            decode_output(&[0xa1, 0x01, 0x82, 0xff, 0x82, 0x41, 0x00, 0x07], 1),
            Err(UtxoError::MalformedTx)
        );
        // {0: h'00', 1: 7, 3: break} and {0: h'00', 1: [7, break]}
        for output in [
            vec![0xa3, 0x00, 0x41, 0x00, 0x01, 0x07, 0x03, 0xff],
            vec![0xa2, 0x00, 0x41, 0x00, 0x01, 0x82, 0x07, 0xff],
        ] {
            assert_eq!(
                decode_output(&body_with_output(&output), 0),
                Err(UtxoError::MalformedTx),
                "{output:02x?}"
            );
        }
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

    /// `[_ $hash32, index ]`: a `transaction_input` as an indefinite array.
    fn indefinite_input_cbor(id: &[u8; 32], index_cbor: &[u8]) -> Vec<u8> {
        let mut v = input_cbor(id, index_cbor);
        v[0] = 0x9f;
        v.push(0xff);
        v
    }

    #[test]
    fn an_indefinite_input_decodes_like_its_definite_twin() {
        let (first, second) = (txid(0x31), txid(0x32));
        // The definite input after the indefinite one decodes only past its break.
        let indefinite = bare_set(&[
            indefinite_input_cbor(&first, &[0x02]),
            input_cbor(&second, &[0x00]),
        ]);
        let definite = bare_set(&[input_cbor(&first, &[0x02]), input_cbor(&second, &[0x00])]);
        let outpoints = vec![
            OutPoint {
                tx_id: first,
                index: 2,
            },
            OutPoint {
                tx_id: second,
                index: 0,
            },
        ];
        for key in [0x00, 0x0d] {
            assert_eq!(
                decode_spends(&body1(key, &indefinite)),
                Ok(outpoints.iter().copied().collect())
            );
            assert_eq!(
                inputs_at(&body1(key, &indefinite), u64::from(key)),
                inputs_at(&body1(key, &definite), u64::from(key))
            );
        }
        assert_eq!(inputs_at(&body1(0x00, &indefinite), 0), Ok(outpoints));
    }

    #[test]
    fn an_indefinite_input_keeps_its_arity_and_index_bound() {
        let id = txid(0x33);
        let mut unterminated = indefinite_input_cbor(&id, &[0x02]);
        unterminated.pop();
        for input in [
            unterminated,
            indefinite_input_cbor(&id, &[0x02, 0x00]),
            indefinite_input_cbor(&id, &[]),
            indefinite_input_cbor(&id, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        ] {
            assert_eq!(
                decode_spends(&body1(0x00, &bare_set(std::slice::from_ref(&input)))),
                Err(UtxoError::MalformedTx),
                "{input:02x?}"
            );
        }
        let max = body1(
            0x00,
            &bare_set(&[indefinite_input_cbor(&id, &[0x19, 0xff, 0xff])]),
        );
        assert_eq!(
            decode_spends(&max),
            Ok([OutPoint {
                tx_id: id,
                index: u16::MAX,
            }]
            .into_iter()
            .collect())
        );
    }
}
