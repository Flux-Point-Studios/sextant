//! UTxO read verification over a Mithril-certified transaction, and the Conway
//! transaction-output decoder the read paths share.
//!
//! [`verify_utxo_read`] composes the pure-Rust inclusion verifier
//! ([`crate::inclusion::verify_tx_inclusion`], default wasm-safe graph) with that decoder.
//!
//! ## Inclusion establishes no output
//! Cardano commits to no UTxO-set state root (a Conway header carries only
//! `block_body_hash`, a per-block tx-merkle root — no ledger-state accumulator).
//! Mithril certifies *transactions* (`CardanoTransactionsMerkleRoot`, ~100 blocks
//! behind tip), not a UTxO set. Membership of `H` in the certified set proves the
//! transaction is on chain; it does not prove what the transaction created. What a
//! transaction creates depends on its phase-2 outcome, which its block records in
//! `invalid_transactions` and its body does not carry: a phase-2-valid transaction
//! creates its regular outputs, an invalid one only its collateral return. A body and
//! an inclusion proof therefore establish no output, and [`verify_utxo_read`] refuses
//! every included body with [`UtxoError::ValidityNotEstablished`]. An output's creation
//! is read from its creating block by [`crate::effects::verify_created_output`].
//!
//! Neither path proves an output is currently *unspent*: no Cardano commitment exists
//! to prove unspent against, and unspent is the ledger's to decide, atomically, at
//! submission. The stronger Tier-2 [`SpendStatus::CertifiedUnspent`] (unspent across a
//! verified window from a certified snapshot) comes from the certified-state path
//! ([`crate::utxoset::UtxoSet::certified_spend_status`]) — the ladder is
//! `#[non_exhaustive]` and uncoercible to unconditional liveness.
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
use core::ops::Range;

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

/// The set of outpoints a transaction may consume: its inputs (body key 0), which a
/// phase-2-valid transaction consumes, together with its collateral inputs (body key 13),
/// which a phase-2-invalid one consumes. The union over-reads what the ledger consumed:
/// a watcher reading it refuses on every real spend, and may also refuse on an input the
/// ledger left unspent. Reference inputs (key 18) are read, not consumed, and are NOT
/// members. A set, so a duplicated input collapses to one.
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

/// The record [`verify_utxo_read`] is declared to return. It never returns one: an
/// included body establishes no output (see the module docs).
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
    /// The body is included and its output decodes, but nothing read establishes the
    /// transaction's phase-2 outcome, so the output is not established as created.
    ValidityNotEstablished,
}

impl core::fmt::Display for UtxoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UtxoError::Inclusion(e) => write!(f, "certified inclusion failed: {e}"),
            UtxoError::MalformedTx => f.write_str("malformed Conway transaction body or output"),
            UtxoError::OutputIndexOutOfRange => f.write_str("output index past end of transaction"),
            UtxoError::ValidityNotEstablished => {
                f.write_str("the transaction's phase-2 outcome is not established")
            }
        }
    }
}

impl core::error::Error for UtxoError {}

/// Check output `out_index` of the transaction whose body is `tx_bytes` against a
/// Mithril-certified transaction set. Every included body is refused with
/// [`UtxoError::ValidityNotEstablished`]: the body carries no phase-2 outcome, so no
/// output is established as created (see the module docs). The output is read from its
/// creating block by [`crate::effects::verify_created_output`].
///
/// `tx_bytes` is the raw transaction *body* CBOR (the `KeepRaw` body span, so
/// `Blake2b-256(tx_bytes)` is the transaction id). `proof_hex` is the aggregator's
/// HEX(JSON) `MKMapProof<BlockRange>` for that transaction. `certified_root` is the
/// certified transaction Merkle root. `_certified_height` is the certified height,
/// which a refusal does not consume.
///
/// The refusals come in this order: the supplied bytes are hashed here (never a
/// provider-supplied hash) and a body outside the certified set is
/// [`UtxoError::Inclusion`]; an output that does not decode is [`UtxoError::MalformedTx`];
/// an index past the outputs is [`UtxoError::OutputIndexOutOfRange`].
pub fn verify_utxo_read(
    tx_bytes: &[u8],
    out_index: usize,
    proof_hex: &[u8],
    certified_root: &[u8; 32],
    _certified_height: u64,
) -> Result<VerifiedOutput, UtxoError> {
    let h = blake2b256(tx_bytes);
    verify_tx_inclusion(proof_hex, &h, certified_root).map_err(UtxoError::Inclusion)?;
    decode_output(tx_bytes, out_index)?;
    Err(UtxoError::ValidityNotEstablished)
}

/// Decode the set of outpoints a Conway transaction may consume — its inputs
/// (body key 0) and collateral inputs (key 13) — from the raw transaction-body
/// CBOR: the forward spend-scan signal. An outpoint absent from every body of a
/// body-committed window was consumed by no transaction there; one present is only
/// listed, since a transaction consumes one of the two sets by its phase-2 outcome.
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
            // key 0 = inputs, key 13 = collateral inputs: one of the two is consumed.
            0 | 13 => decode_input_set(&mut d, &mut spends)?,
            // key 18 = reference inputs (read, not consumed) and every other
            // field are skipped.
            _ => d.skip().map_err(|_| UtxoError::MalformedTx)?,
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
        d.skip().map_err(|_| UtxoError::MalformedTx)?;
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

/// The outputs transaction body `tx_bytes` created, as `(index, span)` pairs with each span a
/// byte range of `tx_bytes`, under the phase-2 outcome its block records: a phase-2-valid
/// transaction creates its regular outputs (key 1) at `0..n`, and an invalid one only its
/// collateral return (key 16), at index `n`. The body is walked to its end in either length
/// form: key 1 must appear exactly once and key 16 at most once, and every output in either
/// must decode as the read path decodes one, so no index is created for an item no read
/// could return. `phase2_valid` is read from the block's body-committed
/// `invalid_transactions` (see [`crate::window`]), never taken from a caller.
pub(crate) fn created_outputs(
    tx_bytes: &[u8],
    phase2_valid: bool,
) -> Result<Vec<(u16, Range<usize>)>, UtxoError> {
    let mut d = Decoder::new(tx_bytes);
    let len = d.map().map_err(|_| UtxoError::MalformedTx)?;
    let mut regular: Option<Vec<Range<usize>>> = None;
    let mut collateral_return = None;
    let mut i = 0;
    while seq_has_next(&mut d, len, i)? {
        match d.u64().map_err(|_| UtxoError::MalformedTx)? {
            1 => {
                let outputs = d.array().map_err(|_| UtxoError::MalformedTx)?;
                let mut spans = Vec::new();
                let mut n = 0;
                while seq_has_next(&mut d, outputs, n)? {
                    spans.push(output_span(&mut d)?);
                    n += 1;
                }
                if regular.replace(spans).is_some() {
                    return Err(UtxoError::MalformedTx);
                }
            }
            16 => {
                if collateral_return.replace(output_span(&mut d)?).is_some() {
                    return Err(UtxoError::MalformedTx);
                }
            }
            _ => d.skip().map_err(|_| UtxoError::MalformedTx)?,
        }
        i += 1;
    }
    if d.position() != tx_bytes.len() {
        return Err(UtxoError::MalformedTx);
    }
    let regular = regular.ok_or(UtxoError::MalformedTx)?;
    let created: Vec<(usize, Range<usize>)> = if phase2_valid {
        regular.into_iter().enumerate().collect()
    } else {
        let after = regular.len();
        collateral_return
            .map(|span| (after, span))
            .into_iter()
            .collect()
    };
    created
        .into_iter()
        .map(|(index, span)| {
            let index = u16::try_from(index).map_err(|_| UtxoError::MalformedTx)?;
            Ok((index, span))
        })
        .collect()
}

/// Decode one output where the decoder stands and return the byte range it occupied.
fn output_span(d: &mut Decoder<'_>) -> Result<Range<usize>, UtxoError> {
    let start = d.position();
    decode_single_output(d)?;
    Ok(start..d.position())
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

/// Decode one Conway `transaction_input` = `[ transaction_id : $hash32,
/// index : uint .size 2 ]`. An index wider than `u16` is out of protocol range.
pub(crate) fn decode_outpoint(d: &mut Decoder<'_>) -> Result<OutPoint, UtxoError> {
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

/// Decode output `out_index` from a Conway transaction-body CBOR map (key 1 =
/// outputs). Untrusted CBOR, so a definite-map shape is required and every
/// deviation fails closed.
fn decode_output(tx_bytes: &[u8], out_index: usize) -> Result<Output, UtxoError> {
    let mut d = Decoder::new(tx_bytes);
    let len = d.map().map_err(|_| UtxoError::MalformedTx)?;
    let mut i = 0;
    while seq_has_next(&mut d, len, i)? {
        let key = d.u64().map_err(|_| UtxoError::MalformedTx)?;
        if key == 1 {
            return decode_output_at(&mut d, out_index);
        }
        d.skip().map_err(|_| UtxoError::MalformedTx)?;
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
        d.skip().map_err(|_| UtxoError::MalformedTx)?;
        i += 1;
    }
    Err(UtxoError::OutputIndexOutOfRange)
}

/// A Conway output is a post-Alonzo map (`{0: address, 1: value, 2?: datum_option,
/// 3?: script_ref}`) or a legacy array (`[address, value]` or
/// `[address, value, datum_hash]`).
pub(crate) fn decode_single_output(d: &mut Decoder<'_>) -> Result<Output, UtxoError> {
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

    /// The number of outputs a phase-2-valid body creates.
    fn output_count(tx_bytes: &[u8]) -> Result<usize, UtxoError> {
        created_outputs(tx_bytes, true).map(|created| created.len())
    }

    #[test]
    fn created_outputs_walks_the_outputs_it_creates() {
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
        // {1: [o]} and a byte after it: the body ends where its map does.
        let trailing = [&[0xa1, 0x01, 0x81][..], &o, &[0x00]].concat();
        for phase2_valid in [true, false] {
            assert_eq!(
                created_outputs(&trailing, phase2_valid),
                Err(UtxoError::MalformedTx)
            );
        }
    }

    #[test]
    fn a_body_without_outputs_creates_nothing_readable() {
        // {0: []} and {0: [], 16: o}: the ledger requires key 1, whatever the outcome.
        for body in [
            &[0xa1, 0x00, 0x80][..],
            &[0xa2, 0x00, 0x80, 0x10, 0x82, 0x41, 0x00, 0x07],
        ] {
            for phase2_valid in [true, false] {
                assert_eq!(
                    created_outputs(body, phase2_valid),
                    Err(UtxoError::MalformedTx),
                    "{body:02x?}"
                );
            }
        }
    }

    /// A valid transaction creates its regular outputs and an invalid one only its
    /// collateral return, after them; the return decodes, and appears once, either way.
    #[test]
    fn the_phase_2_outcome_picks_what_a_body_creates() {
        let o = [0x82, 0x41, 0x00, 0x07];
        let r = [0x82, 0x41, 0x01, 0x08];
        let indices = |body: &[u8], phase2_valid| {
            created_outputs(body, phase2_valid).map(|created| {
                created
                    .into_iter()
                    .map(|(index, span)| (index, body[span].to_vec()))
                    .collect::<Vec<_>>()
            })
        };
        // {1: [o, o], 16: r}
        let body = [&[0xa2, 0x01, 0x82][..], &o, &o, &[0x10], &r].concat();
        assert_eq!(
            indices(&body, true),
            Ok(vec![(0, o.to_vec()), (1, o.to_vec())])
        );
        assert_eq!(indices(&body, false), Ok(vec![(2, r.to_vec())]));
        // {1: [], 16: r} creates the return at 0; {1: [o]} creates nothing when invalid.
        let no_outputs = [&[0xa2, 0x01, 0x80, 0x10][..], &r].concat();
        assert_eq!(indices(&no_outputs, false), Ok(vec![(0, r.to_vec())]));
        assert_eq!(indices(&no_outputs, true), Ok(vec![]));
        let no_return = [&[0xa1, 0x01, 0x81][..], &o].concat();
        assert_eq!(indices(&no_return, false), Ok(vec![]));
        for body in [
            // {1: [o], 16: h'00'}: a return no read could return.
            [&[0xa2, 0x01, 0x81][..], &o, &[0x10, 0x41, 0x00]].concat(),
            // {1: [], 16: r, 16: r}: the return repeated.
            [&[0xa3, 0x01, 0x80, 0x10][..], &r, &[0x10], &r].concat(),
        ] {
            for phase2_valid in [true, false] {
                assert_eq!(
                    created_outputs(&body, phase2_valid),
                    Err(UtxoError::MalformedTx),
                    "{body:02x?}"
                );
            }
        }
    }

    /// Independent cross-decoder differential on the golden preprod order transaction
    /// (`tests/vectors/mithril-tx-body.cbor`): pallas's `MultiEraOutput` accessors are the
    /// oracle for `{address, lovelace, datum}` on every output, an inline-datum map output
    /// and a legacy array output among them.
    #[test]
    fn the_golden_outputs_decode_as_pallas_decodes_them() {
        use pallas_codec::minicbor;
        use pallas_primitives::conway::TransactionBody;
        use pallas_traverse::{Era, MultiEraOutput};

        let hex_text = std::fs::read_to_string("tests/vectors/mithril-tx-body.cbor").unwrap();
        let body_bytes = hex::decode(hex_text.trim()).unwrap();
        let body: TransactionBody = minicbor::decode(&body_bytes).unwrap();
        assert_eq!(body.outputs.len(), 2);
        for i in 0..body.outputs.len() {
            let out_bytes = minicbor::to_vec(&body.outputs[i]).unwrap();
            let oracle = MultiEraOutput::decode(Era::Conway, &out_bytes).unwrap();
            let (address, lovelace, datum) = decode_output(&body_bytes, i).unwrap();
            assert_eq!(address, oracle.address().unwrap().to_vec(), "{i}");
            assert_eq!(lovelace, oracle.value().coin(), "{i}");
            assert_eq!(datum.is_some(), oracle.datum().is_some(), "{i}");
        }
        assert!(matches!(
            decode_output(&body_bytes, 0),
            Ok((_, 5_000_000, Some(Datum::Inline(_))))
        ));
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
