//! Operational-certificate and KES body-signature verification for Praos block
//! headers.
//!
//! Two checks together authenticate a header's authorship, each on Sextant's own
//! code path:
//!
//! * The operational certificate binds the ephemeral hot KES key to the pool's
//!   registered cold key: the cold key (the header's `issuer_vkey`) Ed25519-signs
//!   `hot_vkey ‖ BE64(sequence_number) ‖ BE64(kes_period)`, matching
//!   cardano-ledger's `OCertSignable`. [`verify_opcert`] proves the cold→hot
//!   delegation.
//! * The body signature is a `Sum6Kes` signature by that hot key over the raw
//!   header_body CBOR, at the header's KES evolution period. [`verify_kes`]
//!   proves the block body was signed by the delegated hot key — closing what the
//!   opcert alone cannot: a spoofed header can copy a genuine opcert, but without
//!   the hot KES secret it cannot forge this signature.
//!
//! KES is Cardano's binary sum composition (MMM): a depth-6 tree of Ed25519
//! leaves under a Blake2b-256 verification-key hash tree, giving 64 forward-secure
//! evolution periods. Verification is Sextant's own recursion over
//! [`ed25519::verify`], differentially checked against pallas-crypto's independent
//! `Sum6Kes` verifier and against every real preprod header cardano-node accepted.

use crate::ed25519;
use crate::hash::blake2b256;
use crate::header::{HeaderView, OpCert};

/// Shelley-genesis `slotsPerKESPeriod` — the same constant on preprod, preview,
/// and mainnet. A header's absolute KES period is `slot / SLOTS_PER_KES_PERIOD`.
pub const SLOTS_PER_KES_PERIOD: u64 = 129_600;

/// Depth of the `Sum6Kes` tree.
const KES_DEPTH: u32 = 6;
/// One past the last valid evolution period for `Sum6Kes` (`2^6 = 64`).
const KES_PERIODS: u32 = 1 << KES_DEPTH;

/// Why an operational-certificate or KES check failed. Untrusted headers make
/// every failure an ordinary recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KesError {
    /// The cold key's Ed25519 signature over the operational certificate did
    /// not verify — the hot key, sequence number, issue period, or signature
    /// was altered, or the cold key does not match the one that signed it.
    OpCertInvalidSignature,
    /// The `Sum6Kes` body signature did not verify at the given period: a leaf
    /// Ed25519 signature, a Blake2b vk-tree node, or the root hot key mismatched.
    KesInvalidSignature,
    /// The KES evolution period is outside `0..64` — a header whose slot precedes
    /// its own operational certificate's issue period (an underflow), or a period
    /// past the tree's evolutions. Rejected rather than walking the wrong subtree.
    KesPeriodOutOfRange,
}

impl core::fmt::Display for KesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KesError::OpCertInvalidSignature => {
                f.write_str("operational certificate signature did not verify")
            }
            KesError::KesInvalidSignature => f.write_str("KES body signature did not verify"),
            KesError::KesPeriodOutOfRange => f.write_str("KES evolution period out of range"),
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

/// Verify a header's `Sum6Kes` body signature: the hot KES key rooted at
/// `root_vkey` (the operational certificate's `hot_vkey`) must have signed `msg`
/// (the raw header_body CBOR) at evolution `period`.
pub fn verify_kes(
    root_vkey: &[u8; 32],
    period: u32,
    msg: &[u8],
    sig: &[u8; 448],
) -> Result<(), KesError> {
    if period >= KES_PERIODS {
        return Err(KesError::KesPeriodOutOfRange);
    }
    if verify_sum(KES_DEPTH, period, root_vkey, msg, sig) {
        Ok(())
    } else {
        Err(KesError::KesInvalidSignature)
    }
}

/// Verify a decoded header's KES body signature at the evolution period the
/// header implies: `slot / SLOTS_PER_KES_PERIOD − opcert.kes_period`, the offset
/// from when the hot key's operational certificate was issued. A slot preceding
/// that issue period, or an offset past the tree's 64 evolutions, fails closed.
///
/// This proves only that the key rooted at `opcert.hot_vkey` signed the body; it
/// does not authorize that hot key. Pair it with [`verify_opcert`], which binds
/// the hot key to the pool's registered cold `issuer_vkey` — the two together
/// authenticate authorship (cold → hot delegation, then hot → body signature).
pub fn verify_header_kes(view: &HeaderView) -> Result<(), KesError> {
    let period = (view.slot / SLOTS_PER_KES_PERIOD)
        .checked_sub(view.opcert.kes_period)
        .and_then(|p| u32::try_from(p).ok())
        .ok_or(KesError::KesPeriodOutOfRange)?;
    verify_kes(
        &view.opcert.hot_vkey,
        period,
        &view.header_body,
        &view.body_signature,
    )
}

/// Recursive `SumKes` verification (cardano-crypto-class `Sum`). At depth `d`,
/// `sig = sigma(d−1) ‖ vk0(32) ‖ vk1(32)`: the node key must equal
/// `Blake2b256(vk0 ‖ vk1)`, and `period` selects the left subtree
/// (`period < 2^(d−1)`) or the right (`period − 2^(d−1)`). At depth 0 the
/// signature is a 64-byte Ed25519 signature over `msg` under the leaf key. Any
/// length or structural deviation fails closed rather than panicking.
fn verify_sum(depth: u32, period: u32, vk: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    if depth == 0 {
        return match <&[u8; 64]>::try_from(sig) {
            Ok(leaf) => ed25519::verify(vk, msg, leaf),
            Err(_) => false,
        };
    }

    let Some(split) = sig.len().checked_sub(64) else {
        return false;
    };
    let (sigma, vks) = sig.split_at(split);
    // vks = vk0 ‖ vk1; the node key commits to both children.
    if blake2b256(vks) != *vk {
        return false;
    }
    let (vk0, vk1) = vks.split_at(32);
    let (Ok(vk0), Ok(vk1)) = (<&[u8; 32]>::try_from(vk0), <&[u8; 32]>::try_from(vk1)) else {
        return false;
    };

    let half = 1u32 << (depth - 1);
    if period < half {
        verify_sum(depth - 1, period, vk0, msg, sigma)
    } else {
        verify_sum(depth - 1, period - half, vk1, msg, sigma)
    }
}
