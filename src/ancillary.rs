//! Tier-2 T3-verify: verify the Mithril cardano-database **ancillary** manifest — the single
//! IOG Ed25519 signature that backs the [`AncillarySigned`] anchor basis. This is the one key the
//! certified-state bootstrap trusts until the extraction stack recomputes the set from
//! STM-certified blocks and discharges it to [`StmCertified`]; verifying it here makes that basis
//! *real* rather than asserted (the anchor-basis ruling).
//!
//! [`AncillarySigned`]: crate::utxoset::AnchorBasis::AncillarySigned
//! [`StmCertified`]: crate::utxoset::AnchorBasis::StmCertified
//!
//! The scheme is transcribed from mithril-client's `AncillaryVerifier` (cardano-node 11.x era):
//!
//! ```text
//! compute_hash = SHA-256( for each (path, hex_digest) in the manifest's SORTED map:
//!                             path.as_bytes() ‖ hex_digest.as_bytes() )
//! verify       = Ed25519 verify_strict( compute_hash, signature ) under the pinned ancillary vkey
//! ```
//!
//! Note the hash covers the **hex-string** digests exactly as they appear in the manifest (that is
//! what mithril signs), not the decoded bytes. A verified manifest then yields the trusted per-file
//! SHA-256 digest, against which the fetched `tables` blob is checked before it is parsed — so no
//! unverified bytes ever reach the UTxO set.

use alloc::collections::BTreeMap;
use alloc::string::String;

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Pinned ancillary verification keys — the raw 32-byte Ed25519 public keys decoded from
/// `mithril-infra/configuration/<network>/ancillary.vkey` (published as the hex of a JSON byte
/// array). A SINGLE IOG key: the `AncillarySigned` trust class, distinct from the stake-quorum
/// STM certification of the immutable blocks. Reviewed out of band, never an aggregator verdict.
pub const ANCILLARY_VKEY_PREPROD: [u8; 32] = [
    0xbd, 0xc0, 0xd8, 0x96, 0x72, 0xd8, 0xed, 0xd2, 0x2d, 0x12, 0x15, 0xc4, 0xd0, 0xf6, 0x92, 0x02,
    0xfc, 0xf3, 0xfb, 0xc5, 0x1c, 0x9d, 0xcc, 0x91, 0x1e, 0x0e, 0xe4, 0xa8, 0x81, 0x53, 0x88, 0x24,
];

/// The mainnet ancillary verification key. See [`ANCILLARY_VKEY_PREPROD`].
pub const ANCILLARY_VKEY_MAINNET: [u8; 32] = [
    0x17, 0x47, 0x60, 0x85, 0x2f, 0xfd, 0xe2, 0x88, 0xeb, 0x39, 0xa4, 0x6a, 0xba, 0x02, 0x15, 0x1d,
    0x78, 0xa3, 0x59, 0x79, 0xb1, 0x8a, 0xd0, 0x8a, 0xd6, 0x63, 0x3a, 0x16, 0x00, 0x3a, 0x03, 0x45,
];

#[derive(Deserialize)]
struct RawManifest {
    data: BTreeMap<String, String>,
    signature: String,
}

/// A manifest whose Ed25519 signature verified under a pinned ancillary key. It exposes the
/// trusted per-file SHA-256 digest — the commitment a fetched file must match before it is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAncillaryManifest {
    digests: BTreeMap<String, [u8; 32]>,
}

impl VerifiedAncillaryManifest {
    /// The trusted SHA-256 digest the manifest commits for `path`, or `None` if the manifest does
    /// not cover that file.
    pub fn digest_for(&self, path: &str) -> Option<[u8; 32]> {
        self.digests.get(path).copied()
    }

    /// The files this manifest commits, in sorted order.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.digests.keys().map(String::as_str)
    }
}

/// Why an ancillary manifest failed to verify. Untrusted provider bytes make every failure a
/// recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AncillaryError {
    /// The manifest is not the expected `{data, signature}` JSON.
    MalformedJson,
    /// A `data` value is not a 32-byte (64 hex char) SHA-256 digest.
    MalformedDigest,
    /// The `signature` field is not 64 bytes of hex.
    MalformedSignature,
    /// The Ed25519 signature does not verify under the pinned ancillary key.
    InvalidSignature,
}

impl core::fmt::Display for AncillaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AncillaryError::MalformedJson => {
                write!(f, "ancillary manifest is not {{data,signature}} JSON")
            }
            AncillaryError::MalformedDigest => {
                write!(f, "ancillary manifest digest is not a 32-byte hash")
            }
            AncillaryError::MalformedSignature => {
                write!(f, "ancillary manifest signature is not 64 bytes of hex")
            }
            AncillaryError::InvalidSignature => {
                write!(
                    f,
                    "ancillary manifest signature does not verify under the pinned ancillary key"
                )
            }
        }
    }
}

impl core::error::Error for AncillaryError {}

/// Verify a Mithril cardano-database ancillary manifest against a pinned ancillary verification
/// key. On success the returned [`VerifiedAncillaryManifest`] carries the trusted per-file SHA-256
/// digests; a fetched file is trusted only when its own SHA-256 matches the digest here.
///
/// `ancillary_vkey` is a caller-supplied trust root (pinned per network — [`ANCILLARY_VKEY_PREPROD`]
/// / [`ANCILLARY_VKEY_MAINNET`]), never a provider verdict.
pub fn verify_ancillary_manifest(
    manifest_json: &[u8],
    ancillary_vkey: &[u8; 32],
) -> Result<VerifiedAncillaryManifest, AncillaryError> {
    let manifest: RawManifest =
        serde_json::from_slice(manifest_json).map_err(|_| AncillaryError::MalformedJson)?;

    // The signed message is SHA-256 over each (path ‖ hex-digest) of the SORTED map — the hex
    // strings verbatim, since that is what mithril signs. A BTreeMap makes the order canonical
    // regardless of the JSON key order a hostile provider might present. Mithril sorts a
    // `BTreeMap<PathBuf,_>`; for the manifest's key space (`immutable/<f>`, `ledger/<slot>/<f>` —
    // all lowercase ASCII with no char below `/` at a component boundary) String order is
    // byte-identical to PathBuf order, and the `the_real_preprod_manifest_verifies` test pins that
    // against a signature IOG actually produced. A divergent future key would fail closed (a
    // false reject on an unverifiable message), never a false accept.
    let mut hasher = Sha256::new();
    for (path, hex_digest) in &manifest.data {
        hasher.update(path.as_bytes());
        hasher.update(hex_digest.as_bytes());
    }
    let signed_message: [u8; 32] = hasher.finalize().into();

    let signature =
        decode_hex_array::<64>(&manifest.signature).ok_or(AncillaryError::MalformedSignature)?;

    if !crate::ed25519::verify(ancillary_vkey, &signed_message, &signature) {
        return Err(AncillaryError::InvalidSignature);
    }

    // Only after the signature holds do we surface the trusted digests.
    let mut digests = BTreeMap::new();
    for (path, hex_digest) in manifest.data {
        let digest = decode_hex_array::<32>(&hex_digest).ok_or(AncillaryError::MalformedDigest)?;
        digests.insert(path, digest);
    }
    Ok(VerifiedAncillaryManifest { digests })
}

/// Decode exactly `2*N` hex chars into `N` bytes, or `None` on any wrong length or non-hex digit.
/// Alloc-free; the untrusted string never forces an allocation before it is validated.
fn decode_hex_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (hex_val(bytes[2 * i])? << 4) | hex_val(bytes[2 * i + 1])?;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The REAL preprod cardano-database ancillary manifest (committed fixture) must verify under
    /// the pinned preprod ancillary key. This is the definitive oracle: it exercises the exact
    /// `compute_hash` byte layout and key ordering against a signature IOG actually produced.
    #[test]
    fn the_real_preprod_manifest_verifies_under_the_pinned_key() {
        let manifest = include_bytes!("../tests/vectors/utxohd-ancillary-manifest.json");
        let verified = verify_ancillary_manifest(manifest, &ANCILLARY_VKEY_PREPROD)
            .expect("real preprod manifest must verify under the pinned preprod ancillary key");
        // The trusted digest for the newer snapshot's tables file is surfaced for the parse gate.
        let tables = verified
            .digest_for("ledger/128237957/tables")
            .expect("manifest commits the tables file");
        assert_eq!(
            hex_of(&tables),
            "d1d2288fdb89e125cefb82dc9274cb8b24b24c56777351637d2dacc85c37b23c"
        );
    }

    /// The wrong network's key must reject the same bytes — the signature is key-bound.
    #[test]
    fn the_real_manifest_is_rejected_under_the_mainnet_key() {
        let manifest = include_bytes!("../tests/vectors/utxohd-ancillary-manifest.json");
        assert_eq!(
            verify_ancillary_manifest(manifest, &ANCILLARY_VKEY_MAINNET),
            Err(AncillaryError::InvalidSignature)
        );
    }

    /// A single flipped digest byte breaks `compute_hash`, so the signature no longer verifies —
    /// the tamper the whole gate exists to catch.
    #[test]
    fn a_tampered_digest_fails_the_signature() {
        let original = include_str!("../tests/vectors/utxohd-ancillary-manifest.json");
        // Flip one hex char inside the first committed digest.
        let tampered = original.replacen("cf6ffe6f", "cf6ffe60", 1);
        assert_ne!(tampered, original);
        assert_eq!(
            verify_ancillary_manifest(tampered.as_bytes(), &ANCILLARY_VKEY_PREPROD),
            Err(AncillaryError::InvalidSignature)
        );
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        assert_eq!(
            verify_ancillary_manifest(b"not json", &ANCILLARY_VKEY_PREPROD),
            Err(AncillaryError::MalformedJson)
        );
        assert_eq!(
            verify_ancillary_manifest(br#"{"data":{},"signature":"xy"}"#, &ANCILLARY_VKEY_PREPROD),
            Err(AncillaryError::MalformedSignature)
        );
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
