//! Operational-certificate verification (and, in a later slice, KES signature
//! verification) for Praos block headers.
//!
//! A header's operational certificate binds an ephemeral hot KES key to the
//! pool's registered cold key: the cold key (the header's `issuer_vkey`)
//! Ed25519-signs `hot_vkey ‖ BE64(sequence_number) ‖ BE64(kes_period)`, matching
//! cardano-ledger's `OCertSignable`. Verifying it proves the pool's cold key
//! authorized this hot KES key — the cold→hot delegation only. It does not by
//! itself prove the block body was signed with that key; the header's KES
//! body-signature (a later slice) closes that. A spoofed header can copy a
//! genuine opcert, but without the hot KES secret it cannot produce the body
//! signature that this opcert's hot key must then verify.

use crate::ed25519;
use crate::header::OpCert;

/// Why an operational-certificate (or, later, KES) check failed. Untrusted
/// headers make every failure an ordinary recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KesError {
    /// The cold key's Ed25519 signature over the operational certificate did
    /// not verify — the hot key, sequence number, issue period, or signature
    /// was altered, or the cold key does not match the one that signed it.
    OpCertInvalidSignature,
}

impl core::fmt::Display for KesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KesError::OpCertInvalidSignature => {
                f.write_str("operational certificate signature did not verify")
            }
        }
    }
}

impl std::error::Error for KesError {}

/// The 48-byte message the cold key signs for an operational certificate:
/// `hot_vkey(32) ‖ BE64(sequence_number) ‖ BE64(kes_period)`, a raw
/// concatenation with no CBOR framing (cardano-ledger `OCertSignable`).
pub fn opcert_signable(opcert: &OpCert) -> [u8; 48] {
    let mut msg = [0u8; 48];
    msg[..32].copy_from_slice(&opcert.hot_vkey);
    msg[32..40].copy_from_slice(&opcert.sequence_number.to_be_bytes());
    msg[40..48].copy_from_slice(&opcert.kes_period.to_be_bytes());
    msg
}

/// Verify a header's operational certificate: the pool's `cold_vkey` (the
/// header's `issuer_vkey`) must have Ed25519-signed the hot KES key, sequence
/// number, and issue period carried in `opcert`.
pub fn verify_opcert(cold_vkey: &[u8; 32], opcert: &OpCert) -> Result<(), KesError> {
    if ed25519::verify(cold_vkey, &opcert_signable(opcert), &opcert.sigma) {
        Ok(())
    } else {
        Err(KesError::OpCertInvalidSignature)
    }
}
