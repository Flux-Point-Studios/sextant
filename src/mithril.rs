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
//! The genesis Ed25519 anchor and the STM multi-signature verify — the roots this
//! chain of trust terminates in and rides on — are the subsequent Mithril slices.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};

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
    Ok(VerifiedChain {
        root_hash: certs[0].hash.clone(),
        tip_hash: certs[certs.len() - 1].hash.clone(),
        length: certs.len(),
    })
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
