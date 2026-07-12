//! Mithril certificate hashing on Sextant's own code path.
//!
//! A Mithril certificate commits to its content with a SHA-256 hash, and the
//! certificate chain is linked by that hash: each certificate's `previous_hash`
//! is its parent's content hash. This module recomputes a certificate's hash
//! from the aggregator's JSON, byte-for-byte as `mithril-common` does, so a
//! later slice can walk the chain to a genesis anchor without trusting the
//! aggregator's own `hash`/`previous_hash` fields.
//!
//! Byte-exactness is the whole game. The four nested hashes each fix an exact
//! field set, order, and integer encoding:
//!
//! * [`ProtocolParameters::compute_hash`] — `k` and `m` as big-endian `u64`,
//!   then `phi_f` as a `U8F24` fixed-point `u32` (round-to-nearest, ties to
//!   even — reproduced without the `fixed` crate).
//! * [`CertificateMetadata::compute_hash`] — network, protocol version, the
//!   parameters hash, both timestamps as big-endian `i64` nanoseconds (chrono),
//!   then each signer's `party_id ‖ BE(stake)` hash in list order.
//! * [`ProtocolMessage::compute_hash`] — each present part as
//!   `key_string ‖ value`, iterated in `ProtocolMessagePartKey` **enum order**
//!   (a `BTreeMap`), not JSON order.
//! * [`Certificate::compute_hash`] — `previous_hash`, big-endian `u64` epoch,
//!   the metadata and protocol-message hashes, the signed message, and the wire
//!   `aggregate_verification_key` / signature strings fed **directly** (never
//!   re-serialized). A standard certificate binds its signed entity type and
//!   multi-signature; a genesis certificate binds only its genesis signature.
//!
//! [`verify_chain`] composes those hashes into the chain of trust: it walks a
//! segment oldest→newest, checking each certificate's integrity, its `previous_hash`
//! linkage, and the **AVK binding** — each certificate's aggregate verification key
//! is the one its predecessor authorized (unchanged within an epoch, or the
//! `next_aggregate_verification_key` the predecessor committed one epoch earlier).
//!
//! [`verify_genesis`] terminates that chain of trust in its root. The oldest
//! certificate is a *genesis* certificate, signed not by an STM multi-signature
//! but by the network's genesis Ed25519 key over its `signed_message`. It verifies
//! on Sextant's own Ed25519 path ([`crate::ed25519`]) under a pinned genesis
//! verification key, after checking that `signed_message` binds the certificate's
//! protocol message (and thus the genesis AVK the chain rises from).
//!
//! [`verify_standard`] verifies the other root: every *standard* certificate is
//! authorized by an STM (stake-based threshold multi-signature) over its
//! `signed_message` under its own aggregate verification key. The BLS
//! aggregate / lottery-eligibility / Merkle-batch check is the composed
//! [`mithril_stm`] primitive; the wire deserialize, parameter assembly, and
//! message binding are Sextant's own path.
//!
//! [`verify_chain_anchored`] composes all three into the full chain of trust: a
//! genesis-anchored segment (oldest first) verifies iff its integrity, linkage and
//! AVK binding hold ([`verify_chain`]), its root is the network genesis anchor
//! ([`verify_genesis`]), and every certificate rising from that anchor rides a
//! valid STM multi-signature ([`verify_standard`]). It is the read path's trust
//! terminus — the certificate whose signed Cardano state a UTxO read is checked
//! against is only as trustworthy as its walk back to the genesis key.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mithril_stm::{
    AggregateSignature, AggregateVerificationKey, AggregateVerificationKeyForConcatenation,
    MithrilMembershipDigest, Parameters,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The membership digest mithril uses on its release networks — a Blake2b-256
/// Merkle commitment over the registered signer keys. It is the `D` type
/// parameter every STM structure ([`AggregateSignature`],
/// [`AggregateVerificationKey`], [`Parameters`]) is generic over.
type StmDigest = MithrilMembershipDigest;

/// A Mithril certificate as served by the aggregator (`GET /certificate/{hash}`).
/// Only the fields that feed [`Certificate::compute_hash`] (plus the chain-link
/// hashes) are modelled; any other wire fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct Certificate {
    /// The aggregator's committed content hash (hex). Recomputed by
    /// [`Certificate::compute_hash`] and compared, never trusted.
    pub hash: String,
    /// Parent certificate's content hash (hex) — the chain link.
    pub previous_hash: String,
    /// Cardano epoch this certificate is for.
    pub epoch: u64,
    /// What was signed; bound into the hash for standard certificates.
    pub signed_entity_type: SignedEntityType,
    /// Signer set and protocol parameters in force.
    pub metadata: CertificateMetadata,
    /// The structured message whose hash is the `signed_message`.
    pub protocol_message: ProtocolMessage,
    /// `H(MSG ‖ AVK)` — the STM signed message (hex), fed to the hash directly.
    pub signed_message: String,
    /// Wire aggregate verification key string, fed to the hash directly.
    pub aggregate_verification_key: String,
    /// Wire multi-signature string (empty on a genesis certificate).
    #[serde(default)]
    pub multi_signature: String,
    /// Wire genesis-signature string (empty on a standard certificate).
    #[serde(default)]
    pub genesis_signature: String,
}

impl Certificate {
    /// Parse an aggregator certificate from its JSON bytes on Sextant's own path.
    pub fn from_json(bytes: &[u8]) -> Result<Certificate, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Whether this is a *genesis* certificate — the chain's trust root, signed by
    /// the network genesis key rather than an STM multi-signature. Mithril keys the
    /// distinction on the presence of a genesis signature.
    pub fn is_genesis(&self) -> bool {
        !self.genesis_signature.is_empty()
    }

    /// Whether `signed_message` is the hash of `protocol_message`. This is the
    /// binding that makes a signature over `signed_message` transitively commit to
    /// the protocol message — and thus to the certificate's next-epoch AVK. Both
    /// the genesis and standard verifiers require it before trusting a signature.
    fn signed_message_binds_protocol_message(&self) -> bool {
        self.signed_message == self.protocol_message.compute_hash()
    }

    /// The Cardano-transactions commitment this certificate certifies, if it is a
    /// `CardanoTransactions` certificate: the `cardano_transactions_merkle_root`
    /// protocol-message part bound to the `(epoch, block_number)` its
    /// `signed_entity_type` names. `None` for any other signed entity — those
    /// commit to no transaction set. Both fields are read from the certificate's
    /// own hashed content, so on a verified certificate they cannot disagree with
    /// what it signed.
    pub fn certified_transactions(&self) -> Option<CertifiedTransactions> {
        let (epoch, block_number) = match self.signed_entity_type {
            SignedEntityType::CardanoTransactions(epoch, block_number) => (epoch, block_number),
            _ => return None,
        };
        let merkle_root = self
            .protocol_message
            .message_parts
            .get(&ProtocolMessagePartKey::CardanoTransactionsMerkleRoot)?
            .clone();
        Some(CertifiedTransactions {
            merkle_root,
            epoch,
            block_number,
        })
    }

    /// Recompute the certificate's content hash (lowercase hex), byte-identical
    /// to `mithril-common`'s `Certificate::compute_hash`.
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.metadata.compute_hash().as_bytes());
        hasher.update(self.protocol_message.compute_hash().as_bytes());
        hasher.update(self.signed_message.as_bytes());
        hasher.update(self.aggregate_verification_key.as_bytes());
        // mithril branches on an empty genesis signature: a standard certificate
        // binds {signed_entity_type, multi_signature}; a genesis one binds only
        // the genesis signature.
        if self.genesis_signature.is_empty() {
            self.signed_entity_type.feed_hash(&mut hasher);
            hasher.update(self.multi_signature.as_bytes());
        } else {
            hasher.update(self.genesis_signature.as_bytes());
        }
        hex_lower(hasher.finalize().as_slice())
    }
}

/// The Cardano-transactions commitment a certificate certifies: the Merkle root
/// of the signed transaction set at a certified `(epoch, block_number)`. Present
/// only on a `CardanoTransactions` certificate — a stake-distribution certificate
/// commits to no transaction set. This is the root a proof-based UTxO inclusion
/// check recomputes against (never trusting a provider-supplied root); when it
/// comes off a `verify_chain_anchored`-verified tip it is authenticated back to
/// the genesis key. `block_number` is the recency `certified_at` a caller must
/// carry — the certified set trails tip, so it proves creation, never unspent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedTransactions {
    /// The `cardano_transactions_merkle_root` protocol-message part (hex).
    pub merkle_root: String,
    /// The epoch the transaction set is certified for.
    pub epoch: u64,
    /// The highest block number the certified transaction set covers.
    pub block_number: u64,
}

/// A hash-linked, AVK-bound certificate chain segment verified on Sextant's own
/// path. Names the endpoints so a caller can anchor on the tip certificate hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// Content hash of the oldest certificate in the segment (its parent lies
    /// outside the segment — where the genesis anchor slice will terminate).
    pub root_hash: String,
    /// Content hash of the newest certificate in the segment.
    pub tip_hash: String,
    /// Number of certificates verified.
    pub length: usize,
    /// The tip certificate's Cardano-transactions commitment, when it certifies
    /// one — the genesis-authenticated Merkle root (and its certified height) a
    /// UTxO inclusion proof is recomputed against. `None` when the tip certifies a
    /// stake distribution rather than a transaction set.
    pub certified_transactions: Option<CertifiedTransactions>,
}

/// Why a certificate-chain segment failed to verify. Each variant carries the
/// 0-based index (oldest = 0) of the offending certificate. Untrusted aggregator
/// bytes make every failure an ordinary recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The segment held no certificates.
    Empty,
    /// The certificate at `index` does not hash to its committed `hash`.
    Hash { index: usize },
    /// The certificate at `index`'s `previous_hash` is not its predecessor's
    /// content hash — the segment is reordered, has a gap, or was spliced.
    BrokenLink { index: usize },
    /// The certificate at `index`'s aggregate verification key is not the one its
    /// predecessor authorized (same-epoch AVK, or the predecessor's committed
    /// next-epoch AVK) — a substituted signer set.
    AvkBinding { index: usize },
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::Empty => write!(f, "certificate chain segment is empty"),
            ChainError::Hash { index } => {
                write!(
                    f,
                    "certificate {index}: recomputed hash does not match the committed hash"
                )
            }
            ChainError::BrokenLink { index } => {
                write!(
                    f,
                    "certificate {index}: previous_hash does not link to its predecessor"
                )
            }
            ChainError::AvkBinding { index } => write!(
                f,
                "certificate {index}: aggregate verification key not authorized by its predecessor"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// Verify that `certs` — oldest first (`certs[0]` the segment root, the last its
/// tip) — form a hash-linked, AVK-bound Mithril certificate chain on Sextant's
/// own path. Returns the verified segment's endpoints, or the offending
/// certificate's index on the first failure.
///
/// Three composed guarantees, none of them the aggregator's own verdict:
/// * **integrity** — every certificate's [`Certificate::compute_hash`] equals its
///   committed `hash`;
/// * **linkage** — each certificate's `previous_hash` is its predecessor's content
///   hash, so no certificate can be reordered, dropped, or spliced;
/// * **AVK binding** — each certificate's aggregate verification key is the one its
///   predecessor authorized: unchanged within an epoch, or the
///   `next_aggregate_verification_key` the predecessor committed one epoch earlier.
///
/// The AVK binding is what stops a self-consistent forged child — one that links
/// correctly but carries an attacker's signer set — from being accepted; it is
/// the chain of trust the genesis anchor terminates and the multi-signature signs.
pub fn verify_chain(certs: &[Certificate]) -> Result<VerifiedChain, ChainError> {
    if certs.is_empty() {
        return Err(ChainError::Empty);
    }
    for (index, cert) in certs.iter().enumerate() {
        if cert.compute_hash() != cert.hash {
            return Err(ChainError::Hash { index });
        }
        if index == 0 {
            continue;
        }
        let parent = &certs[index - 1];
        if cert.previous_hash != parent.hash {
            return Err(ChainError::BrokenLink { index });
        }
        let authorized = if cert.epoch == parent.epoch {
            cert.aggregate_verification_key == parent.aggregate_verification_key
        } else if cert.epoch == parent.epoch + 1 {
            parent
                .protocol_message
                .message_parts
                .get(&ProtocolMessagePartKey::NextAggregateVerificationKey)
                .is_some_and(|next| *next == cert.aggregate_verification_key)
        } else {
            false
        };
        if !authorized {
            return Err(ChainError::AvkBinding { index });
        }
    }
    let tip = &certs[certs.len() - 1];
    Ok(VerifiedChain {
        root_hash: certs[0].hash.clone(),
        tip_hash: tip.hash.clone(),
        length: certs.len(),
        certified_transactions: tip.certified_transactions(),
    })
}

/// Why a genesis certificate failed to anchor the chain of trust. Untrusted
/// aggregator bytes make every failure a recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisError {
    /// The certificate carries no genesis signature — it is a standard certificate,
    /// not the chain's genesis root.
    NotGenesis,
    /// The `genesis_signature` field is not 64 bytes of hex.
    MalformedSignature,
    /// `signed_message` is not the hash of `protocol_message`: the signed content
    /// does not bind this certificate's protocol message (and its genesis AVK).
    MessageMismatch,
    /// The Ed25519 genesis signature does not verify under the network genesis
    /// verification key.
    InvalidSignature,
}

impl core::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GenesisError::NotGenesis => write!(f, "certificate is not a genesis certificate"),
            GenesisError::MalformedSignature => {
                write!(f, "genesis signature is not 64 bytes of hex")
            }
            GenesisError::MessageMismatch => {
                write!(f, "signed_message does not bind the protocol message")
            }
            GenesisError::InvalidSignature => {
                write!(f, "genesis signature does not verify under the genesis key")
            }
        }
    }
}

impl std::error::Error for GenesisError {}

/// Verify a Mithril *genesis* certificate against the pinned per-network genesis
/// verification key — the trust root the certificate chain terminates in.
///
/// A genesis certificate is signed not by an STM multi-signature but by the
/// network's genesis Ed25519 key. Accepting it requires, on Sextant's own path:
/// * the certificate is a genesis certificate (it carries a genesis signature);
/// * its `signed_message` is the hash of its `protocol_message`, so the signature
///   transitively commits to the genesis AVK the chain binds its first epoch to;
/// * the 64-byte Ed25519 signature verifies under `genesis_vkey` over
///   `signed_message.as_bytes()` — the ASCII hex of that protocol-message hash —
///   via [`crate::ed25519::verify`] (libsodium-strict, matching mithril's
///   `ed25519-dalek` `verify_strict`).
///
/// `genesis_vkey` is a caller-supplied trust root (pinned per network, reviewed
/// out of band), never an aggregator verdict.
pub fn verify_genesis(cert: &Certificate, genesis_vkey: &[u8; 32]) -> Result<(), GenesisError> {
    if !cert.is_genesis() {
        return Err(GenesisError::NotGenesis);
    }
    let sig = decode_hex_64(&cert.genesis_signature).ok_or(GenesisError::MalformedSignature)?;
    if !cert.signed_message_binds_protocol_message() {
        return Err(GenesisError::MessageMismatch);
    }
    if !crate::ed25519::verify(genesis_vkey, cert.signed_message.as_bytes(), &sig) {
        return Err(GenesisError::InvalidSignature);
    }
    Ok(())
}

/// Why a standard certificate failed to verify. Untrusted aggregator bytes make
/// every failure a recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardError {
    /// The certificate is not a standard certificate — it carries no STM
    /// multi-signature (it is a genesis certificate, or malformed).
    NotStandard,
    /// `signed_message` is not the hash of `protocol_message`: the signed content
    /// does not bind this certificate's protocol message (and its AVK).
    MessageMismatch,
    /// A degenerate threshold — `k == 0`, `m == 0`, or `phi_f` outside `(0, 1)` —
    /// under which a trivial multi-signature could clear the bar (`phi_f == 1`
    /// makes every claimed lottery win, so one signer alone reaches the quorum).
    WeakParameters,
    /// The aggregate verification key or multi-signature commits to a degenerate
    /// signer set — a leaf count outside `[1, MAX_AVK_LEAVES]`, a total stake below
    /// what a signature claims, or more signatures / lottery indices than
    /// `MAX_SINGLE_SIGS` / `MAX_LOTTERY_INDICES` — that would drive mithril-stm's
    /// Merkle / lottery verify into unbounded work on untrusted bytes.
    ImplausibleAvk,
    /// The `aggregate_verification_key` field is not hex-encoded STM AVK JSON.
    MalformedAvk,
    /// The `multi_signature` field is not hex-encoded STM signature JSON.
    MalformedSignature,
    /// The STM multi-signature does not verify under the certificate's aggregate
    /// verification key, message, and protocol parameters.
    InvalidMultiSignature,
}

impl core::fmt::Display for StandardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StandardError::NotStandard => write!(f, "certificate carries no STM multi-signature"),
            StandardError::MessageMismatch => {
                write!(f, "signed_message does not bind the protocol message")
            }
            StandardError::WeakParameters => {
                write!(f, "protocol parameters are a degenerate threshold")
            }
            StandardError::ImplausibleAvk => {
                write!(
                    f,
                    "aggregate verification key commits to a degenerate signer set"
                )
            }
            StandardError::MalformedAvk => {
                write!(f, "aggregate verification key is not valid STM AVK JSON")
            }
            StandardError::MalformedSignature => {
                write!(f, "multi_signature is not valid STM signature JSON")
            }
            StandardError::InvalidMultiSignature => {
                write!(f, "STM multi-signature does not verify")
            }
        }
    }
}

impl std::error::Error for StandardError {}

/// Verify a Mithril *standard* certificate's STM multi-signature — the authority
/// every non-genesis certificate rides on — on Sextant's own path.
///
/// A standard certificate is authorized not by the genesis key but by a
/// stake-based threshold multi-signature (STM): enough of the epoch's registered
/// signers, weighted by stake and each winning enough Praos-style lotteries,
/// jointly signed its `signed_message`. Accepting it requires:
/// * the certificate is a standard certificate (it carries a multi-signature);
/// * its `signed_message` is the hash of its `protocol_message`, so the signature
///   transitively commits to the certificate's next-epoch AVK (the chain link);
/// * the STM multi-signature verifies over `signed_message.as_bytes()` under the
///   certificate's own `aggregate_verification_key` and the protocol parameters in
///   its metadata.
///
/// The wire deserialize, parameter assembly, and message binding are Sextant's own
/// code; the BLS aggregate / lottery-eligibility / Merkle-batch check is the
/// composed [`mithril_stm`] primitive (as EC arithmetic is composed for the header
/// VRF). This proves the certificate is *self*-authorized; that its AVK is the one
/// its predecessor committed is [`verify_chain`]'s AVK binding, and that the chain
/// terminates in the genesis root is [`verify_genesis`]'s — the full chain of
/// trust is those three composed.
pub fn verify_standard(cert: &Certificate) -> Result<(), StandardError> {
    if cert.is_genesis() || cert.multi_signature.is_empty() {
        return Err(StandardError::NotStandard);
    }
    if !cert.signed_message_binds_protocol_message() {
        return Err(StandardError::MessageMismatch);
    }

    // Fail closed on a degenerate threshold before any curve work: `k == 0` /
    // `m == 0` / `phi_f ∉ (0, 1)` would let a trivial multi-signature clear the bar
    // (`phi_f == 1` makes every claimed lottery win, so a single signer reaches the
    // quorum, and it also unbounds the eligibility Taylor series). Standalone these
    // are attacker-controlled; in a chain walk [`verify_chain`]'s integrity check
    // independently pins them to the committed hash. (`phi_f` NaN fails both
    // comparisons, so it is rejected here too.)
    let p = &cert.metadata.protocol_parameters;
    if p.k == 0 || p.m == 0 || !(p.phi_f > 0.0 && p.phi_f < 1.0) {
        return Err(StandardError::WeakParameters);
    }

    // Cap the untrusted blob sizes before decoding: mithril-stm's own deserialize
    // and Sextant's `serde_json::Value` guard both allocate proportional to the
    // input, so an oversized AVK / multi-signature is a memory DoS.
    if cert.aggregate_verification_key.len() > MAX_STM_BLOB_HEX {
        return Err(StandardError::MalformedAvk);
    }
    if cert.multi_signature.len() > MAX_STM_BLOB_HEX {
        return Err(StandardError::MalformedSignature);
    }

    let avk_json =
        decode_hex(&cert.aggregate_verification_key).ok_or(StandardError::MalformedAvk)?;
    let sig_json = decode_hex(&cert.multi_signature).ok_or(StandardError::MalformedSignature)?;
    // Bound the AVK / signature stake, leaf count, and lottery work before the STM
    // verify: on untrusted bytes a leaf count near the u64 overflow, a signer
    // claiming more stake than the total, or an oversized signatures / indexes
    // array all drive mithril-stm into unbounded work.
    guard_stm_bounds(&avk_json, &sig_json)?;

    let concat_avk: AggregateVerificationKeyForConcatenation<StmDigest> =
        serde_json::from_slice(&avk_json).map_err(|_| StandardError::MalformedAvk)?;
    let avk = AggregateVerificationKey::new(concat_avk);

    let multi_sig: AggregateSignature<StmDigest> =
        serde_json::from_slice(&sig_json).map_err(|_| StandardError::MalformedSignature)?;

    let params = Parameters {
        m: p.m,
        k: p.k,
        phi_f: p.phi_f,
    };

    multi_sig
        .verify(cert.signed_message.as_bytes(), &avk, &params)
        .map_err(|_| StandardError::InvalidMultiSignature)
}

/// The largest registered-signer count Sextant will hand to the STM verifier. The
/// AVK's Merkle tree carries one leaf per registered stake pool; no Cardano network
/// has approached even 10⁴ pools, so 2²⁴ (≈16.8M) is enormous headroom while
/// keeping the leaf count far from the u64 arithmetic overflow that drives
/// mithril-stm's Merkle verify into unbounded work near `nr_leaves ≈ 2⁶⁴`.
const MAX_AVK_LEAVES: u64 = 1 << 24;

/// Cap on the hex length of an untrusted AVK / multi-signature blob (4 MiB). Real
/// certificates are kilobytes; both mithril-stm's deserialize and Sextant's own
/// `serde_json::Value` guard allocate proportional to this, so it bounds memory.
const MAX_STM_BLOB_HEX: usize = 1 << 22;

/// Cap on the number of single signatures in an aggregate (2¹⁶). A real quorum is
/// at most the registered pool count; this bounds the per-signature work.
const MAX_SINGLE_SIGS: usize = 1 << 16;

/// Cap on the total lottery indices across all single signatures (2¹⁸). A genuine
/// multi-signature carries `k` winning indices (thousands at most); mithril-stm
/// evaluates one lottery per index *before* checking the count against `k`, so an
/// oversized `indexes` array is a compute DoS this bound forecloses.
const MAX_LOTTERY_INDICES: usize = 1 << 18;

/// Reject an AVK / multi-signature whose committed stake, leaf count, or lottery
/// work would drive mithril-stm's Merkle / lottery verify into unbounded work on
/// untrusted bytes. Each bound is an invariant a genuine certificate satisfies
/// trivially:
/// * the AVK's `nr_leaves` is in `[1, MAX_AVK_LEAVES]` — a huge value overflows the
///   Merkle-tree arithmetic and never terminates;
/// * no single signature claims more stake than the AVK's `total_stake` — a signer
///   with `stake > total_stake` makes the eligibility Taylor series' exponent
///   exceed 1, so it never converges;
/// * there are at most `MAX_SINGLE_SIGS` signatures and `MAX_LOTTERY_INDICES` total
///   lottery indices — mithril-stm runs one lottery evaluation per index across all
///   signatures before the count is checked against `k`, so an oversized array is a
///   compute DoS.
///
/// Fields are read straight from the wire JSON (fail-closed on any missing or
/// out-of-range value), before the typed deserialize the STM verify consumes. In a
/// chain walk the AVK is additionally pinned by the AVK-binding to the genesis root.
fn guard_stm_bounds(avk_json: &[u8], sig_json: &[u8]) -> Result<(), StandardError> {
    let avk: serde_json::Value =
        serde_json::from_slice(avk_json).map_err(|_| StandardError::MalformedAvk)?;
    let total_stake = avk
        .get("total_stake")
        .and_then(serde_json::Value::as_u64)
        .ok_or(StandardError::MalformedAvk)?;
    let nr_leaves = avk
        .pointer("/mt_commitment/nr_leaves")
        .and_then(serde_json::Value::as_u64)
        .ok_or(StandardError::MalformedAvk)?;
    if nr_leaves == 0 || nr_leaves > MAX_AVK_LEAVES {
        return Err(StandardError::ImplausibleAvk);
    }

    let sig: serde_json::Value =
        serde_json::from_slice(sig_json).map_err(|_| StandardError::MalformedSignature)?;
    let signatures = sig
        .get("signatures")
        .and_then(serde_json::Value::as_array)
        .ok_or(StandardError::MalformedSignature)?;
    if signatures.len() > MAX_SINGLE_SIGS {
        return Err(StandardError::ImplausibleAvk);
    }
    let mut total_indices = 0usize;
    for entry in signatures {
        // Each signature is `[{sigma, indexes, ..}, [verification_key, stake]]`;
        // the signer's stake is `signatures[i][1][1]` and its lottery wins are
        // `signatures[i][0].indexes`.
        let stake = entry
            .pointer("/1/1")
            .and_then(serde_json::Value::as_u64)
            .ok_or(StandardError::MalformedSignature)?;
        if stake > total_stake {
            return Err(StandardError::ImplausibleAvk);
        }
        let indices = entry
            .pointer("/0/indexes")
            .and_then(serde_json::Value::as_array)
            .ok_or(StandardError::MalformedSignature)?;
        total_indices = total_indices.saturating_add(indices.len());
        if total_indices > MAX_LOTTERY_INDICES {
            return Err(StandardError::ImplausibleAvk);
        }
    }
    Ok(())
}

/// Why a genesis-anchored certificate chain failed to verify. Each variant names
/// where in the walk the failure lies; untrusted aggregator bytes make every
/// failure a recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchoredError {
    /// The segment's integrity, hash-linkage, or AVK-binding failed (the inner
    /// [`ChainError`] carries the offending certificate's index).
    Chain(ChainError),
    /// The segment's root is not a valid genesis anchor.
    Genesis(GenesisError),
    /// The standard certificate at `index` (1-based absolute segment position;
    /// the genesis root is index 0) is not authorized by a valid STM
    /// multi-signature.
    Standard {
        /// Position of the offending standard certificate in the segment.
        index: usize,
        /// Why its multi-signature was rejected.
        source: StandardError,
    },
}

impl core::fmt::Display for AnchoredError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnchoredError::Chain(e) => write!(f, "chain integrity: {e}"),
            AnchoredError::Genesis(e) => write!(f, "genesis anchor: {e}"),
            AnchoredError::Standard { index, source } => {
                write!(f, "certificate {index}: {source}")
            }
        }
    }
}

impl std::error::Error for AnchoredError {}

/// Verify a genesis-anchored Mithril certificate chain end-to-end on Sextant's own
/// path — the full chain of trust the read path depends on. `certs` is the segment
/// oldest first: `certs[0]` the genesis root, the last certificate its tip.
///
/// Composes the three verifiers built across the Mithril slices, none of them the
/// aggregator's own verdict:
/// * [`verify_chain`] — every certificate hashes to its committed `hash`
///   (integrity, which also pins each `k`/`m`/`phi_f` to that hash), each
///   `previous_hash` links to its predecessor (linkage), and each aggregate
///   verification key is the one its predecessor authorized (AVK binding);
/// * [`verify_genesis`] — the root is the network's genesis anchor, its
///   `genesis_signature` valid under the pinned `genesis_vkey`;
/// * [`verify_standard`] — every certificate rising from the anchor rides a valid
///   STM multi-signature over its own `signed_message` under its own AVK.
///
/// Because the integrity check runs first, a parameter-weakened forgery cannot
/// reach [`verify_standard`] with an attacker-chosen threshold. Returns the
/// verified segment's endpoints (root and tip hashes), or the offending
/// certificate's position on the first failure.
pub fn verify_chain_anchored(
    certs: &[Certificate],
    genesis_vkey: &[u8; 32],
) -> Result<VerifiedChain, AnchoredError> {
    let (root, rising) = certs
        .split_first()
        .ok_or(AnchoredError::Chain(ChainError::Empty))?;
    let verified = verify_chain(certs).map_err(AnchoredError::Chain)?;
    verify_genesis(root, genesis_vkey).map_err(AnchoredError::Genesis)?;
    for (i, cert) in rising.iter().enumerate() {
        verify_standard(cert).map_err(|source| AnchoredError::Standard {
            index: i + 1,
            source,
        })?;
    }
    Ok(verified)
}

/// Decode an even-length hex string — the aggregator's json-hex encoding of the
/// AVK and multi-signature — into its bytes, or `None` on an odd length or a
/// non-hex digit. The length-bounded input never forces an unbounded allocation.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Some(out)
}

/// Decode exactly 128 lowercase-or-uppercase hex chars into 64 bytes, or `None`
/// on any wrong length or non-hex digit. Alloc-free; the untrusted wire string
/// never forces an allocation before it is validated.
fn decode_hex_64(hex: &str) -> Option<[u8; 64]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (hex_val(bytes[2 * i])? << 4) | hex_val(bytes[2 * i + 1])?;
    }
    Some(out)
}

/// One hex digit's value, or `None` if the byte is not a hex digit.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// What a certificate signs. Only the variants present in real preprod vectors
/// are modelled; any other tag is a clean deserialization error (fail-closed),
/// to be added with its own vector by a later slice. Each numeric field is
/// hashed big-endian, matching `mithril-common`'s `feed_hash`.
#[derive(Debug, Clone, Deserialize)]
pub enum SignedEntityType {
    /// Stake distribution for the given epoch.
    MithrilStakeDistribution(u64),
    /// Cardano transactions up to `(epoch, block_number)`.
    CardanoTransactions(u64, u64),
}

impl SignedEntityType {
    fn feed_hash(&self, hasher: &mut Sha256) {
        match self {
            SignedEntityType::MithrilStakeDistribution(epoch) => {
                hasher.update(epoch.to_be_bytes());
            }
            SignedEntityType::CardanoTransactions(epoch, block_number) => {
                hasher.update(epoch.to_be_bytes());
                hasher.update(block_number.to_be_bytes());
            }
        }
    }
}

/// Certificate metadata: the signer set and protocol parameters in force.
#[derive(Debug, Clone, Deserialize)]
pub struct CertificateMetadata {
    /// Cardano network name (e.g. `preprod`).
    pub network: String,
    /// Mithril protocol version (semver); wire key `version`.
    #[serde(rename = "version")]
    pub protocol_version: String,
    /// STM protocol parameters; wire key `parameters`.
    #[serde(rename = "parameters")]
    pub protocol_parameters: ProtocolParameters,
    /// When single-signature registration opened.
    pub initiated_at: DateTime<Utc>,
    /// When the quorum was reached and the multi-signature aggregated.
    pub sealed_at: DateTime<Utc>,
    /// Active signers with their stake, in the order they are hashed.
    pub signers: Vec<Signer>,
}

impl CertificateMetadata {
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.network.as_bytes());
        hasher.update(self.protocol_version.as_bytes());
        hasher.update(self.protocol_parameters.compute_hash().as_bytes());
        hasher.update(timestamp_nanos(self.initiated_at).to_be_bytes());
        hasher.update(timestamp_nanos(self.sealed_at).to_be_bytes());
        for signer in &self.signers {
            hasher.update(signer.compute_hash().as_bytes());
        }
        hex_lower(hasher.finalize().as_slice())
    }
}

/// One stake-weighted party in a certificate's signer set.
#[derive(Debug, Clone, Deserialize)]
pub struct Signer {
    /// Pool identifier (bech32).
    pub party_id: String,
    /// Stake owned by the party (lovelace).
    pub stake: u64,
}

impl Signer {
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.party_id.as_bytes());
        hasher.update(self.stake.to_be_bytes());
        hex_lower(hasher.finalize().as_slice())
    }
}

/// STM protocol parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolParameters {
    /// Quorum parameter.
    pub k: u64,
    /// Number of lotteries.
    pub m: u64,
    /// Lottery win probability factor.
    pub phi_f: f64,
}

impl ProtocolParameters {
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.k.to_be_bytes());
        hasher.update(self.m.to_be_bytes());
        hasher.update(phi_f_fixed_bits(self.phi_f).to_be_bytes());
        hex_lower(hasher.finalize().as_slice())
    }
}

/// The structured message a certificate signs, keyed by part.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolMessage {
    /// Present parts, iterated in [`ProtocolMessagePartKey`] enum order for
    /// hashing (a `BTreeMap`, so wire/insertion order is irrelevant).
    pub message_parts: BTreeMap<ProtocolMessagePartKey, String>,
}

impl ProtocolMessage {
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for (key, value) in &self.message_parts {
            hasher.update(key.as_str().as_bytes());
            hasher.update(value.as_bytes());
        }
        hex_lower(hasher.finalize().as_slice())
    }
}

/// A protocol-message part key. Variant **declaration order is load-bearing**:
/// it is the `Ord` that fixes the hashing order (a `BTreeMap` key). Ordered as
/// in `mithril-common`'s enum; only the parts that appear in real preprod
/// certificates are modelled, so any other key is a clean deserialization
/// error. A later slice extends this set with its own vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum ProtocolMessagePartKey {
    /// Digest of the signed immutable-file snapshot.
    #[serde(rename = "snapshot_digest")]
    SnapshotDigest,
    /// Merkle root of the signed Cardano transactions.
    #[serde(rename = "cardano_transactions_merkle_root")]
    CardanoTransactionsMerkleRoot,
    /// Next epoch's aggregate verification key (the AVK-binding link).
    #[serde(rename = "next_aggregate_verification_key")]
    NextAggregateVerificationKey,
    /// Next epoch's protocol parameters.
    #[serde(rename = "next_protocol_parameters")]
    NextProtocolParameters,
    /// The current epoch.
    #[serde(rename = "current_epoch")]
    CurrentEpoch,
    /// Latest signed block number.
    #[serde(rename = "latest_block_number")]
    LatestBlockNumber,
}

impl ProtocolMessagePartKey {
    /// The canonical key string hashed into the protocol message (matching
    /// `mithril-common`'s `Display`).
    fn as_str(&self) -> &'static str {
        match self {
            ProtocolMessagePartKey::SnapshotDigest => "snapshot_digest",
            ProtocolMessagePartKey::CardanoTransactionsMerkleRoot => {
                "cardano_transactions_merkle_root"
            }
            ProtocolMessagePartKey::NextAggregateVerificationKey => {
                "next_aggregate_verification_key"
            }
            ProtocolMessagePartKey::NextProtocolParameters => "next_protocol_parameters",
            ProtocolMessagePartKey::CurrentEpoch => "current_epoch",
            ProtocolMessagePartKey::LatestBlockNumber => "latest_block_number",
        }
    }
}

/// `phi_f` as `mithril-common`'s `U8F24` fixed-point bits: round `phi_f · 2²⁴`
/// to the nearest integer, ties to even. Multiplying by the power of two `2²⁴`
/// is exact in `f64`, so this equals the `fixed` crate's conversion without the
/// dependency; the float→int cast saturates (never panics) on out-of-range input.
fn phi_f_fixed_bits(phi_f: f64) -> u32 {
    (phi_f * 16_777_216.0).round_ties_even() as u32
}

/// Nanoseconds since the Unix epoch, matching chrono's `timestamp_nanos_opt`
/// (mithril hashes `unwrap_or_default()`, i.e. 0 when out of representable range).
fn timestamp_nanos(dt: DateTime<Utc>) -> i64 {
    dt.timestamp_nanos_opt().unwrap_or_default()
}

/// Lowercase hex of `bytes`, matching `hex::encode` (mithril feeds each nested
/// hash to its parent as this ASCII hex string).
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `phi_f` fixed-point golden the spec calls out: `0.7 · 2²⁴` rounds to
    /// `11744051`. Guards the encoding independently of any full-hash vector.
    #[test]
    fn phi_f_fixed_point_golden() {
        assert_eq!(phi_f_fixed_bits(0.7), 11_744_051);
        // Ties-to-even example: 0.123 · 2²⁴ = 2063597.568 → 2063598.
        assert_eq!(phi_f_fixed_bits(0.123), 2_063_598);
    }

    /// mithril-common's own `ProtocolParameters::compute_hash` golden — pins the
    /// `u64` big-endian `k`/`m` and the `U8F24` `phi_f` encoding together.
    #[test]
    fn protocol_parameters_hash_matches_mithril_golden() {
        let params = ProtocolParameters {
            k: 1000,
            m: 100,
            phi_f: 0.123,
        };
        assert_eq!(
            params.compute_hash(),
            "ace019657cd995b0dfbb1ce8721a1092715972c4ae0171cc636ab4a44e6e4279",
        );
    }

    /// mithril-common's own `CertificateMetadata::compute_hash` golden — pins the
    /// field set/order, the chrono nanosecond timestamps, and the signer hashing.
    #[test]
    fn certificate_metadata_hash_matches_mithril_golden() {
        // initiated_at = 2024-02-12T13:11:47 with nanosecond 123043; sealed +100s.
        let initiated_at = DateTime::parse_from_rfc3339("2024-02-12T13:11:47.000123043Z")
            .unwrap()
            .with_timezone(&Utc);
        let sealed_at = DateTime::parse_from_rfc3339("2024-02-12T13:13:27.000123043Z")
            .unwrap()
            .with_timezone(&Utc);
        let metadata = CertificateMetadata {
            network: "devnet".to_string(),
            protocol_version: "0.1.0".to_string(),
            protocol_parameters: ProtocolParameters {
                k: 1000,
                m: 100,
                phi_f: 0.123,
            },
            initiated_at,
            sealed_at,
            signers: vec![
                Signer {
                    party_id: "1".to_string(),
                    stake: 10,
                },
                Signer {
                    party_id: "2".to_string(),
                    stake: 20,
                },
            ],
        };
        assert_eq!(
            metadata.compute_hash(),
            "f16631f048b33746aa0141cf607ee53ddb76308725e6912530cc41cc54834206",
        );
    }

    /// The protocol-message part keys hash under their canonical strings, and the
    /// enum `Ord` is the declaration order that fixes the hashing sequence.
    #[test]
    fn protocol_message_part_keys_are_canonical_and_ordered() {
        use ProtocolMessagePartKey::*;
        let declared = [
            (SnapshotDigest, "snapshot_digest"),
            (
                CardanoTransactionsMerkleRoot,
                "cardano_transactions_merkle_root",
            ),
            (
                NextAggregateVerificationKey,
                "next_aggregate_verification_key",
            ),
            (NextProtocolParameters, "next_protocol_parameters"),
            (CurrentEpoch, "current_epoch"),
            (LatestBlockNumber, "latest_block_number"),
        ];
        for (key, s) in declared {
            assert_eq!(key.as_str(), s);
        }
        for pair in declared.windows(2) {
            assert!(pair[0].0 < pair[1].0, "enum Ord must be declaration order");
        }
    }

    /// mithril-common's own `test_genesis_certificate_compute_hash` golden — the
    /// one certificate shape absent from the harvested vectors (all standard).
    /// Pins the genesis branch of [`Certificate::compute_hash`]: only the genesis
    /// signature is bound; the signed entity type and multi-signature are not.
    /// The fake AVK / genesis signature are mithril's own test doubles (verbatim,
    /// split at the source line boundaries), so this is an independent oracle.
    #[test]
    fn certificate_genesis_hash_matches_mithril_golden() {
        const AVK: &str = concat!(
            "7b226d745f636f6d6d69746d656e74223a7b22726f6f74223a5b37332c37342c3232392c3235302c3132322c32",
            "32362c38392c33372c3233312c3234352c3130362c3138332c3132372c332c39392c3137372c3231372c36352c3",
            "135322c3133352c33322c36372c3232332c33352c3134312c35312c342c3132352c3230332c33382c3139362c32",
            "31325d2c226e725f6c6561766573223a32342c22686173686572223a6e756c6c7d2c22746f74616c5f7374616b6",
            "5223a35323337353137363336353838327d",
        );
        const GENESIS_SIG: &str = concat!(
            "ebc0652ffe864970a2ba538eacf7d088e9840e3db883c96d13eb6c5b4c74cfc6e84932e4640ca9e3b5e3de2dd6",
            "15247a88c011405cc7508736abcf99cae2b10b",
        );

        let initiated_at = DateTime::parse_from_rfc3339("2024-02-12T13:11:47.0123043Z")
            .unwrap()
            .with_timezone(&Utc);
        let sealed_at = DateTime::parse_from_rfc3339("2024-02-12T13:13:27.0123043Z")
            .unwrap()
            .with_timezone(&Utc);

        let mut message_parts = BTreeMap::new();
        message_parts.insert(
            ProtocolMessagePartKey::SnapshotDigest,
            "snapshot-digest-123".to_string(),
        );
        message_parts.insert(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            AVK.to_string(),
        );
        let protocol_message = ProtocolMessage { message_parts };
        // mithril derives signed_message = protocol_message.compute_hash().
        let signed_message = protocol_message.compute_hash();

        let cert = Certificate {
            hash: String::new(),
            previous_hash: "previous_hash".to_string(),
            epoch: 10,
            // Not bound by the genesis branch; the value is irrelevant to the hash.
            signed_entity_type: SignedEntityType::MithrilStakeDistribution(10),
            metadata: CertificateMetadata {
                network: "testnet".to_string(),
                protocol_version: "0.1.0".to_string(),
                protocol_parameters: ProtocolParameters {
                    k: 1000,
                    m: 100,
                    phi_f: 0.123,
                },
                initiated_at,
                sealed_at,
                signers: vec![
                    Signer {
                        party_id: "1".to_string(),
                        stake: 10,
                    },
                    Signer {
                        party_id: "2".to_string(),
                        stake: 20,
                    },
                ],
            },
            protocol_message,
            signed_message,
            aggregate_verification_key: AVK.to_string(),
            multi_signature: String::new(),
            genesis_signature: GENESIS_SIG.to_string(),
        };
        assert_eq!(
            cert.compute_hash(),
            "6160fca853402c0ea89a0a9ceb5d97462ffd81c558c53feef01dcc0827f5bd19",
        );
    }
}
