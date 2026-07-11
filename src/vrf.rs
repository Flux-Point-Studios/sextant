//! Praos leader-election VRF (ECVRF-ED25519-SHA512-Elligator2, IETF draft-03 —
//! libsodium's `crypto_vrf_ietfdraft03`) on Sextant's own code path.
//!
//! Two verdicts live here, both computed by Sextant and differentially checked
//! against real chain data:
//!
//! * [`proof_to_hash`] recomputes the 64-byte VRF output (beta) from the
//!   80-byte proof. It is nonce-independent — beta depends only on the proof's
//!   Gamma point — so every block's committed `vrf_output` checks against it
//!   with no epoch nonce.
//! * [`verify`] runs the full draft-03 verification equation: it binds the
//!   proof to the public key and the input string, so only the key holder for
//!   this slot could have produced it. [`verify_praos_leader`] wraps it with
//!   the Praos input `alpha = Blake2b256(BE64(slot) || eta0)`, which is what a
//!   block header's leader proof actually commits to.
//!
//! The finite-field and curve arithmetic (Elligator2, point/scalar ops) comes
//! from Amaru's `curve25519-dalek` fork, whose `hash_from_bytes` carries the
//! libsodium-compatible sign-bit fix. The ECVRF protocol logic — decode, the
//! `U`/`V` equations, the challenge recomputation, the accept test — is
//! Sextant's own and is proven against real preprod leader proofs.

extern crate alloc;
use alloc::vec::Vec;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use sha2::{Digest, Sha512};

/// draft-03 suite string for ECVRF-ED25519-SHA512-Elligator2.
const SUITE: u8 = 0x04;
/// Domain-separation tag for `hash_to_curve` (draft-03 "ONE").
const ONE: u8 = 0x01;
/// Domain-separation tag for the challenge / `hash_points` (draft-03 "TWO").
const TWO: u8 = 0x02;
/// Domain-separation tag for `proof_to_hash` (draft-03 "THREE").
const THREE: u8 = 0x03;

/// Why a VRF operation failed. Byte providers are untrusted, so every malformed
/// proof or failed check is an ordinary recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VrfError {
    /// The proof's Gamma component is not a valid Edwards curve point.
    InvalidGamma,
    /// The public key is not a valid Edwards curve point.
    InvalidPublicKey,
    /// The public key lies in the small-order subgroup, so it cannot bind a
    /// unique proof — libsodium rejects it before the equation is even checked.
    SmallOrderPublicKey,
    /// The proof is well-formed but the draft-03 equation does not hold: the
    /// recomputed challenge differs from the one carried in the proof.
    VerificationFailed,
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VrfError::InvalidGamma => f.write_str("VRF proof Gamma is not a valid curve point"),
            VrfError::InvalidPublicKey => f.write_str("VRF public key is not a valid curve point"),
            VrfError::SmallOrderPublicKey => f.write_str("VRF public key is small-order"),
            VrfError::VerificationFailed => f.write_str("VRF proof failed the draft-03 equation"),
        }
    }
}

impl std::error::Error for VrfError {}

/// Recompute the 64-byte VRF output (beta) from an 80-byte draft-03 proof:
///
/// `beta = SHA-512( 0x04 || 0x03 || encode(8 * Gamma) )`
///
/// where `Gamma` is the first 32 bytes of the proof (a compressed Edwards
/// point) and `8 * Gamma` clears the cofactor. This is exactly libsodium's
/// `crypto_vrf_ietfdraft03_proof_to_hash`, so on a valid block the result
/// equals the `vrf_output` the producer committed on-chain. It does not by
/// itself prove the proof is valid — that is [`verify`]'s job.
pub fn proof_to_hash(proof: &[u8; 80]) -> Result<[u8; 64], VrfError> {
    let gamma = decode_point(&proof[..32]).ok_or(VrfError::InvalidGamma)?;
    Ok(gamma_to_hash(&gamma))
}

/// Full draft-03 verification: prove that `proof` was produced for `alpha` by
/// the holder of `vkey`, and return the certified 64-byte output on success.
///
/// Mirrors libsodium's `crypto_vrf_ietfdraft03_verify`:
/// 1. decode `pi = (Gamma, c, s)` and the public key `Y`;
/// 2. `H = hash_to_curve(Y, alpha)` (Elligator2, cofactor-cleared);
/// 3. `U = s·B − c·Y`, `V = s·H − c·Gamma`;
/// 4. `c' = SHA-512(0x04 || 0x02 || H || Gamma || U || V)[..16]`;
/// 5. accept iff `c' == c`, then return `proof_to_hash(pi)`.
pub fn verify(vkey: &[u8; 32], alpha: &[u8], proof: &[u8; 80]) -> Result<[u8; 64], VrfError> {
    let gamma = decode_point(&proof[..32]).ok_or(VrfError::InvalidGamma)?;
    let c = scalar_from_16(&proof[32..48]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&proof[48..80]);
    // Reject a non-canonical response scalar (`s ≥ L`) rather than silently
    // reducing it: a canonical producer's `s` is always `< L`, so this never
    // rejects a real proof, and it denies an adversary the malleated `s + L`
    // encoding that reduces to the same scalar.
    let s = Scalar::from_canonical_bytes(s_bytes).ok_or(VrfError::VerificationFailed)?;

    let y = decode_point(vkey).ok_or(VrfError::InvalidPublicKey)?;
    if y.is_small_order() {
        return Err(VrfError::SmallOrderPublicKey);
    }

    let h = hash_to_curve(vkey, alpha);
    let neg_c = -c;
    // U = s·B − c·Y and V = s·H − c·Gamma, the two announcements the prover
    // committed to. The same points, byte-identically compressed, feed the
    // challenge — how they are batched does not change the result.
    let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&neg_c, &y, &s);
    let v = EdwardsPoint::vartime_multiscalar_mul([s, neg_c], [h, gamma]);

    if hash_points(&h, &gamma, &u, &v) == proof[32..48] {
        Ok(gamma_to_hash(&gamma))
    } else {
        Err(VrfError::VerificationFailed)
    }
}

/// Verify a Praos block header's leader proof: build the VRF input the ledger
/// binds to this slot, `alpha = Blake2b256(BE64(slot) || eta0)`, then run the
/// full draft-03 [`verify`]. `eta0` is the 32-byte epoch nonce in force for the
/// block's epoch.
pub fn verify_praos_leader(
    vkey: &[u8; 32],
    slot: u64,
    eta0: &[u8; 32],
    proof: &[u8; 80],
) -> Result<[u8; 64], VrfError> {
    verify(vkey, &praos_vrf_input(slot, eta0), proof)
}

/// The Praos VRF input string: `Blake2b256(BE64(slot) || eta0)`, matching
/// cardano-ledger's `mkInputVRF`. This is the `alpha` a header's leader proof
/// commits to; exposed so a consumer (or a differential test) can reconstruct
/// it for the same slot and epoch nonce.
pub fn praos_vrf_input(slot: u64, eta0: &[u8; 32]) -> [u8; 32] {
    use blake2::VarBlake2b;
    use blake2::digest::{Update, VariableOutput};

    let mut h = VarBlake2b::new(32).expect("32 is a valid Blake2b output length");
    h.update(slot.to_be_bytes());
    h.update(eta0);
    let mut out = [0u8; 32];
    h.finalize_variable(|res| out.copy_from_slice(res));
    out
}

/// `hash_to_curve(Y, alpha) = 8 · Elligator2( SHA-512(0x04 || 0x01 || Y || alpha)[..32] )`.
/// The Elligator2 map with the libsodium sign-bit convention and the cofactor
/// clearing both live in `hash_from_bytes` on Amaru's dalek fork.
fn hash_to_curve(vkey: &[u8; 32], alpha: &[u8]) -> EdwardsPoint {
    let mut input = Vec::with_capacity(2 + 32 + alpha.len());
    input.extend_from_slice(&[SUITE, ONE]);
    input.extend_from_slice(vkey);
    input.extend_from_slice(alpha);
    EdwardsPoint::hash_from_bytes::<Sha512>(&input)
}

/// `hash_points`: the draft-03 challenge, the low 16 bytes of
/// `SHA-512(0x04 || 0x02 || H || Gamma || U || V)`. Returned as the raw 16-byte
/// proof encoding so it compares directly against the challenge in the proof.
fn hash_points(
    h: &EdwardsPoint,
    gamma: &EdwardsPoint,
    u: &EdwardsPoint,
    v: &EdwardsPoint,
) -> [u8; 16] {
    let hash = Sha512::new()
        .chain([SUITE, TWO])
        .chain(h.compress().as_bytes())
        .chain(gamma.compress().as_bytes())
        .chain(u.compress().as_bytes())
        .chain(v.compress().as_bytes())
        .finalize();
    let mut c = [0u8; 16];
    c.copy_from_slice(&hash[..16]);
    c
}

/// `beta = SHA-512(0x04 || 0x03 || encode(8 · Gamma))`.
fn gamma_to_hash(gamma: &EdwardsPoint) -> [u8; 64] {
    let hash = Sha512::new()
        .chain([SUITE, THREE])
        .chain(gamma.mul_by_cofactor().compress().as_bytes())
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&hash);
    out
}

/// Decode a compressed Edwards point, returning `None` for off-curve or
/// non-canonical encodings. libsodium's `ge25519_is_canonical` rejects a
/// y-coordinate `≥ p`, but dalek's `decompress` silently accepts it, so we
/// enforce canonicity by requiring the point to re-compress to the exact input
/// bytes. A canonical producer never emits a non-canonical encoding, so this
/// only ever rejects adversarial bytes, never a real block.
fn decode_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    let compressed = CompressedEdwardsY::from_slice(bytes);
    let point = compressed.decompress()?;
    (point.compress() == compressed).then_some(point)
}

/// The proof's 16-byte challenge `c`, widened into the low half of a 32-byte
/// little-endian scalar for the `s·B − c·Y` / `s·H − c·Gamma` equations; the
/// value is always well below the group order, so no reduction occurs.
fn scalar_from_16(bytes16: &[u8]) -> Scalar {
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(bytes16);
    Scalar::from_bits(buf)
}
