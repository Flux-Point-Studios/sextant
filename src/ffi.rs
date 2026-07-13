//! C-ABI boundary for the read-path verifier.
//!
//! This is the consumable surface the rest of the project calls: the verified core
//! (header decode → leader-VRF → operational cert → KES → chain link → Mithril
//! chain of trust) exposed as a minimal, allocation-free `extern "C"` API that also
//! compiles to `wasm32`. Every verdict is still computed by Sextant's own code path;
//! the FFI only marshals bytes in and a status code + a fixed out-struct back.
//!
//! Safety model:
//! * Every fallible export runs its body inside [`guard`] so a panic can never cross
//!   the `extern "C"` boundary (undefined behaviour on native, an uncatchable trap on
//!   wasm). Each export writes its out-params exactly once, on its terminal path, so
//!   catching a unwind leaves no half-written state.
//! * `eta0` and `genesis_vkey` are byte inputs, never trusted verdicts: a wrong value
//!   can only make a genuine proof *reject* (liveness), never make an invalid one
//!   *accept* (safety holds), exactly as in the in-process path.
//! * Status codes are banded so the same-named-but-distinct [`crate::chain::ChainError`]
//!   (200 band) and [`crate::mithril::ChainError`] (300 band) never collide.

use std::ptr;
use std::slice;

use crate::chain::{self, ChainError};
use crate::follow::{AppendRefusal, ReAnchor, Rollback, SlotSchedule, WindowFollower};
use crate::header::{DecodeError, HeaderView};
use crate::inclusion::InclusionError;
use crate::kes::KesError;
use crate::utxo::{self, CertifiedTransactions, Datum, OutPoint, UtxoError};
use crate::vrf::VrfError;
use crate::window::{self, Freshness, SpendRegion, StallReason, WatchBasis, WatchVerdict};

#[cfg(feature = "mithril")]
use crate::mithril::{
    self, AnchoredError, Certificate, ChainError as MithrilChainError, GenesisError, StandardError,
};

/// ABI contract version. A consumer asserts `sextant_abi_version() == SEXTANT_ABI_VERSION`
/// at load; cbindgen emits it into the header as a `#define`. Bumped 1→2 for the UTxO
/// read export and the certified-transactions out-params on the anchored verify; 2→3 for
/// the windowed watch-verdict export ([`sextant_verify_watched_window`]); 3→4 for the live
/// follower exports ([`sextant_follower_new`] …) and the reinterpretation of the
/// [`SextantWatchVerdict`] reserved byte as `spend_region`.
pub const SEXTANT_ABI_VERSION: u32 = 4;

/// The only defined `spend_status` value a verified read returns. The read path can
/// NEVER establish that an output is currently available to spend (see
/// [`SextantVerifiedOutput`]); no wire value means it is, and none is ever written.
///
/// `spend_status` is a BANDED code space: `0` = not established. A future
/// CRYPTOGRAPHIC band (a Mithril ledger-state proof) and a future ECONOMIC/attested
/// band (a committee attestation) are RESERVED and kept distinct, so a consumer
/// switching on the byte always sees the trust basis and can never read an
/// attestation as a proof. New tiers are additive (a new constant + an ABI-version
/// bump), never a layout break. cbindgen emits this as a `#define`.
pub const SEXTANT_SPEND_NOT_ESTABLISHED: u8 = 0;

/// Every verdict the boundary can return, as one flat `#[repr(i32)]` enum. All bands
/// are defined unconditionally (only the mithril *function* is feature-gated) so the
/// committed header and the numbering are identical across build configs. Negative =
/// a boundary/caller error; 0 = ok; positive bands mirror the internal verifiers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SextantStatus {
    Ok = 0,

    ErrNullPointer = -1,
    ErrEmptyInput = -2,
    /// Reserved: a caller-provided output buffer was too small (sizing protocol).
    ErrBufferTooSmall = -3,
    ErrPanic = -9,

    DecodeMalformedCbor = 100,
    DecodeUnsupportedEra = 101,
    DecodeBadHashLen = 102,
    DecodeTrailingBytes = 103,

    VrfInvalidGamma = 110,
    VrfInvalidPublicKey = 111,
    VrfSmallOrderPublicKey = 112,
    VrfVerificationFailed = 113,

    KesOpCertInvalidSignature = 120,
    KesInvalidSignature = 121,
    KesPeriodOutOfRange = 122,

    ChainDecode = 200,
    ChainBrokenLink = 201,
    ChainOpCert = 202,
    ChainVrf = 203,
    ChainKes = 204,

    MithrilChainEmpty = 300,
    MithrilChainHash = 301,
    MithrilChainBrokenLink = 302,
    MithrilChainAvkBinding = 303,

    MithrilGenesisNotGenesis = 310,
    MithrilGenesisMalformedSignature = 311,
    MithrilGenesisMessageMismatch = 312,
    MithrilGenesisInvalidSignature = 313,

    MithrilStdNotStandard = 320,
    MithrilStdMessageMismatch = 321,
    MithrilStdWeakParameters = 322,
    MithrilStdImplausibleAvk = 323,
    MithrilStdMalformedAvk = 324,
    MithrilStdMalformedSignature = 325,
    MithrilStdInvalidMultiSignature = 326,
    MithrilStdMalformedCertJson = 327,

    UtxoInclusionNotIncluded = 400,
    UtxoInclusionRootMismatch = 401,
    UtxoInclusionMalformedProof = 402,
    UtxoMalformedTx = 410,
    UtxoOutputIndexOutOfRange = 411,
}

/// Per-verdict detail carried alongside the status code, so a caller can point at the
/// offending certificate/block and recover the leaf reason. Caller-allocated, fixed
/// width, memcpy-safe. `index == -1` means "not applicable"; `detail == 0` means none.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SextantErrorDetail {
    /// 0-based position of the offending block/certificate, or `-1`.
    pub index: i64,
    /// The inner leaf status code, or a decode scalar (era/len), or `0`.
    pub detail: u64,
}

/// The read-path header fields, projected into a fixed `#[repr(C)]` struct. Only read
/// fields are exposed; the verification inputs (`header_body`, `vrf_proof`,
/// `body_signature`) are consumed by `verify_segment`, not surfaced — which keeps this
/// struct fixed-width (no owned buffer crosses the boundary).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SextantHeaderView {
    pub block_number: u64,
    pub slot: u64,
    pub opcert_sequence_number: u64,
    pub opcert_kes_period: u64,
    pub block_hash: [u8; 32],
    /// The parent block hash; all zero when `has_prev_hash == 0`.
    pub prev_hash: [u8; 32],
    pub issuer_vkey: [u8; 32],
    pub vrf_vkey: [u8; 32],
    pub vrf_output: [u8; 64],
    pub opcert_hot_vkey: [u8; 32],
    pub era: u8,
    /// `1` if `prev_hash` is present; `0` for a genesis header ([0;32] is a legal hash,
    /// so it cannot double as a sentinel).
    pub has_prev_hash: u8,
    /// Explicit tail padding; zeroed on write so the struct is fully deterministic.
    pub _reserved: [u8; 6],
}

/// A verified transaction output, projected into a caller-allocated fixed-width
/// `#[repr(C)]` struct. The scalars live here; the variable-length `address` and
/// `datum` bytes are delivered to the caller's `(buf, cap)` pairs, with the true
/// lengths reported here so a caller can size a retry (the sizing protocol).
///
/// ## Honest scope — read before gating on the result
/// A genuine `Ok` proves the returned `{address, lovelace, datum}` are the AUTHENTIC
/// on-chain bytes of a Mithril-certified output: its certified INCLUSION and its
/// provenance are anchored to the network genesis key as of `certified_at`, and
/// NOTHING MORE. It is NOT a claim that the output is currently available to spend —
/// Cardano commits to no UTxO-set accumulator, the verdict trails tip by ~100 blocks,
/// and the ledger decides availability atomically at submission. `spend_status` is
/// ALWAYS [`SEXTANT_SPEND_NOT_ESTABLISHED`]; never gate a spend on it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SextantVerifiedOutput {
    /// The output's ADA amount in lovelace (its `coin`; any multi-asset is excluded).
    pub lovelace: u64,
    /// The Mithril-certified block height the output was attested at — NOT tip state,
    /// NOT a liveness claim.
    pub certified_at: u64,
    /// The true length of the address bytes; may exceed `address_cap` (then retry).
    pub address_len: usize,
    /// The true length of the datum bytes: `0` = none, `32` = a datum hash, variable
    /// = an inline datum; may exceed `datum_cap` (then retry).
    pub datum_len: usize,
    /// `0` = no datum, `1` = a 32-byte datum hash in `datum_buf`, `2` = an inline
    /// datum (`datum_len` raw plutus-data CBOR bytes in `datum_buf`, `#6.24`-unwrapped
    /// — the caller decodes it).
    pub datum_kind: u8,
    /// Always [`SEXTANT_SPEND_NOT_ESTABLISHED`] (`0`) — the read path cannot establish
    /// liveness; never gate on it.
    pub spend_status: u8,
    /// Explicit tail padding; zeroed on write so the struct is fully deterministic.
    pub _reserved: [u8; 6],
}

/// Run a fallible boundary body so a panic becomes [`SextantStatus::ErrPanic`] instead
/// of unwinding across `extern "C"` (undefined behaviour). On `wasm32` (compiled
/// `panic = abort`) `catch_unwind` cannot catch, so a panic traps to a JS
/// `RuntimeError` — a safe liveness-only failure a verifier can never false-accept on.
#[cfg(not(target_arch = "wasm32"))]
#[inline]
fn guard(f: impl FnOnce() -> i32) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => SextantStatus::ErrPanic as i32,
    }
}

#[cfg(target_arch = "wasm32")]
#[inline]
fn guard(f: impl FnOnce() -> i32) -> i32 {
    f()
}

/// Write `{index, detail}` into a nullable out-param (no-op on null).
fn write_detail(out: *mut SextantErrorDetail, index: i64, detail: u64) {
    if !out.is_null() {
        // SAFETY: `out` is non-null and, by the export's contract, points to a writable
        // `SextantErrorDetail`. Written once on the terminal path.
        unsafe { *out = SextantErrorDetail { index, detail } };
    }
}

/// A header decode error's status code and its standalone-path scalar (era/len/0).
/// Two callers: the standalone `sextant_header_decode` (uses the scalar) and the chain
/// mapping (uses the code as the inner detail).
fn decode_status(e: &DecodeError) -> (i32, u64) {
    use SextantStatus as S;
    match e {
        DecodeError::MalformedCbor => (S::DecodeMalformedCbor as i32, 0),
        DecodeError::UnsupportedEra(era) => (S::DecodeUnsupportedEra as i32, *era as u64),
        DecodeError::BadHashLen(n) => (S::DecodeBadHashLen as i32, *n as u64),
        DecodeError::TrailingBytes => (S::DecodeTrailingBytes as i32, 0),
    }
}

/// A KES error's leaf status code. Two callers: the opcert and KES arms of the chain
/// mapping (both carry a [`KesError`]).
fn kes_code(e: &KesError) -> u64 {
    use SextantStatus as S;
    (match e {
        KesError::OpCertInvalidSignature => S::KesOpCertInvalidSignature as i32,
        KesError::KesInvalidSignature => S::KesInvalidSignature as i32,
        KesError::KesPeriodOutOfRange => S::KesPeriodOutOfRange as i32,
    }) as u64
}

/// Flatten a [`ChainError`] to `(status, index, detail)`: the 200 band, the offending
/// block index, and the inner leaf code (decode/vrf/kes) as the detail.
fn chain_status(e: &ChainError) -> (i32, i64, u64) {
    use SextantStatus as S;
    match e {
        ChainError::Decode { index, err } => {
            let (code, _) = decode_status(err);
            (S::ChainDecode as i32, *index as i64, code as u64)
        }
        ChainError::BrokenLink { index } => (S::ChainBrokenLink as i32, *index as i64, 0),
        ChainError::OpCert { index, err } => (S::ChainOpCert as i32, *index as i64, kes_code(err)),
        ChainError::Vrf { index, err } => {
            let leaf = match err {
                VrfError::InvalidGamma => S::VrfInvalidGamma as i32,
                VrfError::InvalidPublicKey => S::VrfInvalidPublicKey as i32,
                VrfError::SmallOrderPublicKey => S::VrfSmallOrderPublicKey as i32,
                VrfError::VerificationFailed => S::VrfVerificationFailed as i32,
            };
            (S::ChainVrf as i32, *index as i64, leaf as u64)
        }
        ChainError::Kes { index, err } => (S::ChainKes as i32, *index as i64, kes_code(err)),
    }
}

/// Project the decoded header into the fixed boundary struct, zeroing `prev_hash` for a
/// genesis header and always zeroing the tail padding.
fn project_header(h: &HeaderView) -> SextantHeaderView {
    let (has_prev_hash, prev_hash) = match h.prev_hash {
        Some(p) => (1, p),
        None => (0, [0u8; 32]),
    };
    SextantHeaderView {
        block_number: h.block_number,
        slot: h.slot,
        opcert_sequence_number: h.opcert.sequence_number,
        opcert_kes_period: h.opcert.kes_period,
        block_hash: h.block_hash,
        prev_hash,
        issuer_vkey: h.issuer_vkey,
        vrf_vkey: h.vrf_vkey,
        vrf_output: h.vrf_output,
        opcert_hot_vkey: h.opcert.hot_vkey,
        era: h.era,
        has_prev_hash,
        _reserved: [0u8; 6],
    }
}

/// The ABI version this build implements.
#[unsafe(no_mangle)]
pub extern "C" fn sextant_abi_version() -> u32 {
    SEXTANT_ABI_VERSION
}

/// Verify a block-chain segment (ledger `[era, block]` CBOR, on-chain order) against
/// the epoch nonce `eta0`, composing the full per-header crypto and the hash links.
///
/// Returns [`SextantStatus`] as `i32`: `0` on success (`out_detail = {index:-1,
/// detail:0}`), else the failure band with the offending block index and inner leaf
/// code in `out_detail`.
///
/// # Safety
/// `block_ptrs` and `block_lens` must each point to `count` readable entries; each
/// `block_ptrs[i]` to `block_lens[i]` readable bytes; `eta0` to 32 readable bytes;
/// `out_detail` must be null or point to a writable [`SextantErrorDetail`]. All borrows
/// live only for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_verify_segment(
    block_ptrs: *const *const u8,
    block_lens: *const usize,
    count: usize,
    eta0: *const u8,
    out_detail: *mut SextantErrorDetail,
) -> i32 {
    guard(|| {
        if block_ptrs.is_null() || block_lens.is_null() || eta0.is_null() {
            return SextantStatus::ErrNullPointer as i32;
        }
        if count == 0 {
            return SextantStatus::ErrEmptyInput as i32;
        }
        // SAFETY: `block_ptrs`/`block_lens` point to `count` valid entries (caller
        // contract); the borrows live only inside this closure.
        let ptrs = unsafe { slice::from_raw_parts(block_ptrs, count) };
        let lens = unsafe { slice::from_raw_parts(block_lens, count) };
        let mut blocks: Vec<&[u8]> = Vec::with_capacity(count);
        for i in 0..count {
            if ptrs[i].is_null() {
                return SextantStatus::ErrNullPointer as i32;
            }
            // SAFETY: `ptrs[i]` is non-null and points to `lens[i]` readable bytes.
            blocks.push(unsafe { slice::from_raw_parts(ptrs[i], lens[i]) });
        }
        // SAFETY: `eta0` is non-null and points to 32 readable bytes.
        let eta0 = unsafe { &*(eta0 as *const [u8; 32]) };
        match chain::verify_segment(&blocks, eta0) {
            Ok(()) => {
                write_detail(out_detail, -1, 0);
                SextantStatus::Ok as i32
            }
            Err(e) => {
                let (status, index, detail) = chain_status(&e);
                write_detail(out_detail, index, detail);
                status
            }
        }
    })
}

/// Decode a single block header's read fields into `out`.
///
/// Returns `0` on success (`out` filled, `out_detail = {index:-1, detail:0}`), else the
/// 100-band decode status; for an unsupported era / bad hash length `out_detail.detail`
/// carries the era/len scalar.
///
/// # Safety
/// `bytes` must point to `bytes_len` readable bytes; `out` must point to a writable
/// [`SextantHeaderView`]; `out_detail` must be null or point to a writable
/// [`SextantErrorDetail`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_header_decode(
    bytes: *const u8,
    bytes_len: usize,
    out: *mut SextantHeaderView,
    out_detail: *mut SextantErrorDetail,
) -> i32 {
    guard(|| {
        if bytes.is_null() || out.is_null() {
            return SextantStatus::ErrNullPointer as i32;
        }
        // SAFETY: `bytes` is non-null and points to `bytes_len` readable bytes.
        let input = unsafe { slice::from_raw_parts(bytes, bytes_len) };
        match HeaderView::from_block_cbor(input) {
            Ok(view) => {
                // SAFETY: `out` is non-null (checked); the whole struct is written once.
                unsafe { *out = project_header(&view) };
                write_detail(out_detail, -1, 0);
                SextantStatus::Ok as i32
            }
            Err(e) => {
                let (status, detail) = decode_status(&e);
                write_detail(out_detail, -1, detail);
                status
            }
        }
    })
}

/// Copy the static, human-readable message for a status code into `buf` (log-only,
/// never verdict-bearing). Returns the full message length in bytes; a null `buf` or
/// `cap == 0` is a sizing query that copies nothing.
///
/// # Safety
/// `buf` must be null, or point to `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_status_message(status: i32, buf: *mut u8, cap: usize) -> usize {
    let msg = status_message(status).as_bytes();
    if !buf.is_null() && cap > 0 {
        let n = msg.len().min(cap);
        // SAFETY: `buf` is non-null and points to `cap >= n` writable bytes; `msg` is a
        // distinct static string, so the ranges do not overlap.
        unsafe { ptr::copy_nonoverlapping(msg.as_ptr(), buf, n) };
    }
    msg.len()
}

/// The static message table — one entry per status, the single place a code maps to
/// prose. Also the referencing site that keeps every [`SextantStatus`] variant live.
const STATUS_MESSAGES: &[(SextantStatus, &str)] = {
    use SextantStatus as S;
    &[
        (S::Ok, "ok"),
        (S::ErrNullPointer, "null pointer argument"),
        (S::ErrEmptyInput, "empty input"),
        (S::ErrBufferTooSmall, "output buffer too small"),
        (S::ErrPanic, "internal panic caught at the FFI boundary"),
        (S::DecodeMalformedCbor, "header decode: malformed CBOR"),
        (S::DecodeUnsupportedEra, "header decode: unsupported era"),
        (S::DecodeBadHashLen, "header decode: wrong hash length"),
        (S::DecodeTrailingBytes, "header decode: trailing bytes"),
        (S::VrfInvalidGamma, "leader-VRF: gamma is not a curve point"),
        (
            S::VrfInvalidPublicKey,
            "leader-VRF: public key is not a curve point",
        ),
        (
            S::VrfSmallOrderPublicKey,
            "leader-VRF: small-order public key",
        ),
        (S::VrfVerificationFailed, "leader-VRF: verification failed"),
        (
            S::KesOpCertInvalidSignature,
            "operational certificate signature invalid",
        ),
        (S::KesInvalidSignature, "KES body signature invalid"),
        (S::KesPeriodOutOfRange, "KES period out of range"),
        (S::ChainDecode, "chain: block failed to decode"),
        (S::ChainBrokenLink, "chain: broken hash link"),
        (S::ChainOpCert, "chain: operational certificate failed"),
        (S::ChainVrf, "chain: leader-VRF failed"),
        (S::ChainKes, "chain: KES body signature failed"),
        (S::MithrilChainEmpty, "mithril: empty certificate segment"),
        (S::MithrilChainHash, "mithril: certificate hash mismatch"),
        (
            S::MithrilChainBrokenLink,
            "mithril: broken certificate link",
        ),
        (S::MithrilChainAvkBinding, "mithril: AVK binding mismatch"),
        (
            S::MithrilGenesisNotGenesis,
            "mithril: root is not a genesis certificate",
        ),
        (
            S::MithrilGenesisMalformedSignature,
            "mithril: malformed genesis signature",
        ),
        (
            S::MithrilGenesisMessageMismatch,
            "mithril: genesis signed-message mismatch",
        ),
        (
            S::MithrilGenesisInvalidSignature,
            "mithril: genesis signature invalid",
        ),
        (
            S::MithrilStdNotStandard,
            "mithril: certificate is not standard",
        ),
        (
            S::MithrilStdMessageMismatch,
            "mithril: standard signed-message mismatch",
        ),
        (
            S::MithrilStdWeakParameters,
            "mithril: degenerate protocol parameters",
        ),
        (
            S::MithrilStdImplausibleAvk,
            "mithril: implausible aggregate verification key",
        ),
        (
            S::MithrilStdMalformedAvk,
            "mithril: malformed aggregate verification key",
        ),
        (
            S::MithrilStdMalformedSignature,
            "mithril: malformed multi-signature",
        ),
        (
            S::MithrilStdInvalidMultiSignature,
            "mithril: multi-signature invalid",
        ),
        (
            S::MithrilStdMalformedCertJson,
            "mithril: malformed certificate JSON",
        ),
        (
            S::UtxoInclusionNotIncluded,
            "utxo read: transaction not included in the certified set",
        ),
        (
            S::UtxoInclusionRootMismatch,
            "utxo read: inclusion proof does not recompute the certified root",
        ),
        (
            S::UtxoInclusionMalformedProof,
            "utxo read: malformed inclusion proof",
        ),
        (S::UtxoMalformedTx, "utxo read: malformed transaction body"),
        (
            S::UtxoOutputIndexOutOfRange,
            "utxo read: output index past end of transaction",
        ),
    ]
};

fn status_message(status: i32) -> &'static str {
    STATUS_MESSAGES
        .iter()
        .find(|(s, _)| *s as i32 == status)
        .map_or("unknown status", |(_, msg)| *msg)
}

/// Flatten a [`UtxoError`] to its status band (UNGATED, beside [`chain_status`]).
/// `Inclusion` splits into the 400 band; a malformed tx / out-of-range index map to
/// the 410 band.
fn utxo_status(e: &UtxoError) -> i32 {
    use SextantStatus as S;
    (match e {
        UtxoError::Inclusion(InclusionError::NotIncluded) => S::UtxoInclusionNotIncluded,
        UtxoError::Inclusion(InclusionError::RootMismatch) => S::UtxoInclusionRootMismatch,
        UtxoError::Inclusion(InclusionError::MalformedProof) => S::UtxoInclusionMalformedProof,
        UtxoError::MalformedTx => S::UtxoMalformedTx,
        UtxoError::OutputIndexOutOfRange => S::UtxoOutputIndexOutOfRange,
    }) as i32
}

/// Copy `min(src.len(), cap)` bytes into `dst`, but only when `dst` is non-null and
/// the clamped count is non-zero. The variable-length marshalling contract: on the
/// `-3` sizing path the caller passes `cap == 0` (buf may be null) so nothing is
/// copied; on the `Ok` path `cap >= src.len()`, so the whole field is delivered. Two
/// callers: the address and datum buffers.
///
/// # Safety
/// When non-null, `dst` must point to at least `cap` writable bytes; `src` is a
/// distinct slice, so the ranges do not overlap.
unsafe fn copy_min(dst: *mut u8, cap: usize, src: &[u8]) {
    let n = src.len().min(cap);
    if dst.is_null() || n == 0 {
        return;
    }
    // SAFETY: `dst` is non-null with `cap >= n` writable bytes; `src` is distinct.
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst, n) };
}

/// Verify that output `out_index` of the transaction whose body is `tx_bytes` is a
/// genesis-anchored, Mithril-certified on-chain output, and marshal its
/// `{address, lovelace, datum}` back to the caller.
///
/// This is a CORE export — present in the default library and the wasm32 build (its
/// verifier composes only Blake2b/Blake2s + minicbor, no feature-gated crypto crate).
/// `certified_root` is
/// the 32-byte certified transaction Merkle root; obtain it ONLY from a
/// genesis-authenticated certificate (see the mithril anchored verify) so a provider
/// cannot inject one. The supplied `tx_bytes` are hashed here, never a
/// provider-supplied hash, so substituted/tampered bytes are rejected as not-included.
///
/// ## The sizing protocol (allocation-free; caller owns every buffer)
/// The fixed scalars land in `*out`; the variable-length `address` and `datum` bytes
/// go to `address_buf`/`datum_buf`, whose true lengths are reported in
/// `out.address_len`/`out.datum_len`. If EITHER buffer is too small the call writes
/// the full struct (true lengths, no variable bytes) and returns
/// [`SextantStatus::ErrBufferTooSmall`] (`-3`); the caller reads the lengths, resizes,
/// and retries (idempotent). A `(NULL, 0)` pair is a pure sizing probe. There is no
/// free function — on wasm no free callback can cross back in.
///
/// ## Honest scope
/// A genuine `Ok` proves authentic bytes + certified inclusion + provenance anchored
/// to genesis as of `certified_at`, NOTHING MORE; it is NOT a liveness claim, and
/// `out.spend_status` is always [`SEXTANT_SPEND_NOT_ESTABLISHED`]. Never gate on it.
///
/// # Safety
/// `tx_bytes` must point to `tx_bytes_len` readable bytes; `proof_hex` to
/// `proof_hex_len` readable bytes; `certified_root` to 32 readable bytes; `out` to a
/// writable [`SextantVerifiedOutput`]. `address_buf`/`datum_buf` must each be null
/// (permitted iff its cap is 0) or point to `address_cap`/`datum_cap` writable bytes.
/// `out_detail` must be null or point to a writable [`SextantErrorDetail`]. All
/// borrows live only for the duration of the call.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sextant_verify_utxo_read(
    tx_bytes: *const u8,
    tx_bytes_len: usize,
    out_index: usize,
    proof_hex: *const u8,
    proof_hex_len: usize,
    certified_root: *const u8,
    block_number: u64,
    out: *mut SextantVerifiedOutput,
    address_buf: *mut u8,
    address_cap: usize,
    datum_buf: *mut u8,
    datum_cap: usize,
    out_detail: *mut SextantErrorDetail,
) -> i32 {
    guard(|| {
        if tx_bytes.is_null() || proof_hex.is_null() || certified_root.is_null() || out.is_null() {
            return SextantStatus::ErrNullPointer as i32;
        }
        if tx_bytes_len == 0 {
            return SextantStatus::ErrEmptyInput as i32;
        }
        // SAFETY: each pointer is non-null (checked) and, by contract, points to the
        // stated number of readable bytes; the borrows live only inside this closure.
        let tx = unsafe { slice::from_raw_parts(tx_bytes, tx_bytes_len) };
        let proof = unsafe { slice::from_raw_parts(proof_hex, proof_hex_len) };
        let root = unsafe { &*(certified_root as *const [u8; 32]) };

        let v = match utxo::verify_utxo_read(tx, out_index, proof, root, block_number) {
            Ok(v) => v,
            Err(e) => {
                write_detail(out_detail, -1, 0);
                return utxo_status(&e);
            }
        };

        let address_len = v.address.len();
        let (datum_kind, datum_bytes): (u8, &[u8]) = match &v.datum {
            None => (0, &[]),
            Some(Datum::Hash(h)) => (1, h.as_slice()),
            Some(Datum::Inline(bytes)) => (2, bytes.as_slice()),
        };
        let datum_len = datum_bytes.len();
        let projected = SextantVerifiedOutput {
            lovelace: v.lovelace,
            certified_at: v.certified_at,
            address_len,
            datum_len,
            datum_kind,
            spend_status: SEXTANT_SPEND_NOT_ESTABLISHED,
            _reserved: [0u8; 6],
        };

        if address_cap < address_len || datum_cap < datum_len {
            // Sizing sub-result: publish the true lengths, copy no variable bytes.
            // SAFETY: `out` is non-null (checked); written once on this path.
            unsafe { *out = projected };
            write_detail(out_detail, -1, 0);
            return SextantStatus::ErrBufferTooSmall as i32;
        }

        // Both buffers fit: fill them, THEN commit the struct (the caller reads
        // `*_len`/`datum_kind` to interpret already-written buffers), THEN the detail.
        // SAFETY: caps are ≥ the true lengths, so `copy_min` writes the full fields.
        unsafe {
            copy_min(address_buf, address_cap, &v.address);
            copy_min(datum_buf, datum_cap, datum_bytes);
            *out = projected;
        }
        write_detail(out_detail, -1, 0);
        SextantStatus::Ok as i32
    })
}

// ---- Windowed watch-verdict boundary (BEYOND-DoD Tier1 slice 5) ----
//
// [`crate::window::verify_watched_window`] answers a THREE-valued question over a
// certified, header-verified, body-committed block window: was the watched outpoint
// spent, was NO spend of it observed, or could the window not answer. That verdict is
// surfaced here as a fixed-width `#[repr(C)]` out-struct whose `kind` the C consumer
// switches on — never collapsed to a single boolean, which would let a non-answer or a
// definite spend read as "safe to proceed".

/// `SextantWatchVerdict.kind`: NO spend of the watched outpoint was observed across the
/// verified window (the honest windowed verdict — read [`SextantWatchVerdict`]'s scope).
pub const SEXTANT_WATCH_NO_SPEND_OBSERVED: u8 = 1;
/// `SextantWatchVerdict.kind`: a verified, body-committed block in the window carries a
/// spend of the watched outpoint — a definite refuse. Authoritative against the verified
/// window regardless of freshness; whether that authority is Mithril-quorum-backed or
/// merely header-vouched is carried in `spend_region` (`SEXTANT_WATCH_REGION_*`). A
/// `HEADER_VOUCHED` spend rests on the same `mithril_quorum` assumption a no-spend answer
/// does; only a `MITHRIL_CERTIFIED` spend is authoritative independent of it.
pub const SEXTANT_WATCH_SPEND_OBSERVED: u8 = 2;
/// `SextantWatchVerdict.kind`: the window could not answer (a gap, a failed body
/// commitment, an unverified segment, an unobserved creation, a short or stale tip). A
/// non-answer is a REFUSE, never "probably fine".
pub const SEXTANT_WATCH_STALLED: u8 = 3;

/// `SextantWatchVerdict.basis` (meaningful only when `kind == SEXTANT_WATCH_NO_SPEND_OBSERVED`):
/// the trust basis, in the CRYPTOGRAPHIC-WITH-ASSUMPTIONS band `1..=9`. `WATCHED_WINDOW`
/// is the only tier today; a future ledger-state tier is reserved in this band's free
/// slots, and an ECONOMIC/attested tier is reserved numerically FAR (100+) so an
/// attestation can never be numerically mistaken for a cryptographic basis. This is the
/// ONE place the tier ladder lives at the C ABI. `0` for the other kinds.
pub const SEXTANT_WATCH_BASIS_WATCHED_WINDOW: u8 = 1;

/// `SextantWatchVerdict.assumptions` bit: the window sits inside a region a Mithril
/// quorum certified (the tip is at or below the caller-supplied certified anchor height).
/// SURFACED, not per-block verified: the read path binds no served block to the certified
/// transaction root, so this bit means "trust the served chain is the certified one", not
/// a proof of it — a consumer weighs it. When it is clear (an answer whose tip is above
/// the certified anchor), the region is header-verified but NOT quorum-backed.
pub const SEXTANT_WATCH_ASSUMPTION_MITHRIL_QUORUM: u8 = 1 << 0;
/// `SextantWatchVerdict.assumptions` bit: the scanned segment is a header-verified,
/// hash-linked, gap-free, body-committed run — a complete body stream over the window.
pub const SEXTANT_WATCH_ASSUMPTION_DATA_COMPLETE: u8 = 1 << 1;

/// `SextantWatchVerdict.stall_reason` (meaningful only when `kind == SEXTANT_WATCH_STALLED`):
/// the window carried no blocks.
pub const SEXTANT_WATCH_STALL_EMPTY_WINDOW: u8 = 1;
/// The header segment did not verify (broken link, crypto, or decode) — the withheld-block
/// evasion collapses here.
pub const SEXTANT_WATCH_STALL_BROKEN_SEGMENT: u8 = 2;
/// A block's bodies did not hash to its header commitment: real headers with swapped or
/// tampered bodies.
pub const SEXTANT_WATCH_STALL_BODY_COMMITMENT_MISMATCH: u8 = 3;
/// A block's body stream was not a decodable transaction sequence; the scan fails closed.
pub const SEXTANT_WATCH_STALL_MALFORMED_BODY: u8 = 4;
/// The verified block numbers were not contiguous over the window (a dropped block).
pub const SEXTANT_WATCH_STALL_MISSING_BLOCK: u8 = 5;
/// The watched outpoint's creation was not observed inside the window — the "start the
/// window after the spend" evasion.
pub const SEXTANT_WATCH_STALL_CREATION_NOT_OBSERVED: u8 = 6;
/// The verified tip did not reach the caller's `require_through` floor — the "truncate the
/// window before the spend" evasion. Freshness alone cannot close it, so the caller MUST
/// assert a hard lower bound on the tip it is answered as of.
pub const SEXTANT_WATCH_STALL_WINDOW_TOO_SHORT: u8 = 7;
/// The window tip is above the certified anchor height: outside the Mithril-vouched region.
pub const SEXTANT_WATCH_STALL_TIP_ABOVE_ANCHOR: u8 = 8;
/// The verified tip is older than the caller's freshness bound.
pub const SEXTANT_WATCH_STALL_TIP_TOO_OLD: u8 = 9;
/// An incremental follower ([`sextant_follower_new`]) was rolled back deeper than the
/// horizon it retains, so it can no longer reconstruct the window; discard and restart
/// from a fresh anchor. Produced by [`sextant_follower_verdict`] after a rollback returned
/// [`SEXTANT_FOLLOWER_ROLLBACK_BEYOND_WINDOW`]; the batch window verify never yields it.
pub const SEXTANT_WATCH_STALL_ROLLBACK_BEYOND_WINDOW: u8 = 10;
/// A follower [`sextant_follower_append`] crossed an epoch boundary before the epoch's η0
/// was staged via [`sextant_follower_supply_next_eta0`]. Fail-closed and liveness-only:
/// the block does not advance the tip, and appending it again after the nonce is staged
/// still succeeds. Follower-only — the single-epoch batch window verify has no counterpart.
pub const SEXTANT_WATCH_STALL_EPOCH_NONCE_UNAVAILABLE: u8 = 11;

/// `SextantWatchVerdict.spend_region` (meaningful only when `kind == SEXTANT_WATCH_SPEND_OBSERVED`):
/// the spending transaction is proven a member of the genesis-anchored Mithril-certified
/// transaction set — quorum-backed, authoritative independent of the `mithril_quorum`
/// assumption. `0` (n/a) for the other kinds.
pub const SEXTANT_WATCH_REGION_MITHRIL_CERTIFIED: u8 = 1;
/// `SextantWatchVerdict.spend_region`: the spend was observed in a header-verified,
/// hash-linked, body-committed block NOT bound to the certified set — authoritative
/// against the verified window, but resting on the same `mithril_quorum` assumption a
/// no-spend verdict does. Upgrades to [`SEXTANT_WATCH_REGION_MITHRIL_CERTIFIED`] only via
/// a [`sextant_follower_re_anchor`] inclusion proof of the spending tx (never height).
pub const SEXTANT_WATCH_REGION_HEADER_VOUCHED: u8 = 2;

/// [`sextant_follower_rollback`] outcome: the target was still in the fact ring; the
/// accepted run was truncated to end at it and `out_tip_height` carries the new tip. The
/// follower stays live — re-append the target's successors.
pub const SEXTANT_FOLLOWER_ROLLBACK_TRUNCATED: i32 = 1;
/// [`sextant_follower_rollback`] outcome: the target was the follow base; the window is
/// empty but the follower stays anchored (re-append from the first block).
pub const SEXTANT_FOLLOWER_ROLLBACK_TO_BASE: i32 = 2;
/// [`sextant_follower_rollback`] outcome: the target was deeper than the retained horizon;
/// the follower is poisoned and its verdict is now
/// [`SEXTANT_WATCH_STALL_ROLLBACK_BEYOND_WINDOW`]. Discard it and restart from a fresh anchor.
pub const SEXTANT_FOLLOWER_ROLLBACK_BEYOND_WINDOW: i32 = 3;

/// [`sextant_follower_re_anchor`] outcome: the new anchor's block number is below the
/// current anchor height; refused, so the certified region only ever grows. Untouched.
pub const SEXTANT_FOLLOWER_REANCHOR_NOT_MONOTONE: i32 = 1;
/// [`sextant_follower_re_anchor`] outcome: the certified anchor advanced (or held) but the
/// observed spend (if any) was not upgraded — no proof, or a proof that did not attest the
/// observed spend against the new anchor's certified root.
pub const SEXTANT_FOLLOWER_REANCHOR_ADVANCED: i32 = 2;
/// [`sextant_follower_re_anchor`] outcome: the anchor advanced (or held) AND the supplied
/// inclusion proof certified the observed spend — its region is now
/// [`SEXTANT_WATCH_REGION_MITHRIL_CERTIFIED`].
pub const SEXTANT_FOLLOWER_REANCHOR_ADVANCED_SPEND_CERTIFIED: i32 = 3;

/// The verdict of a windowed watch check, projected into a caller-allocated fixed-width
/// `#[repr(C)]` struct — no sizing protocol, no owned buffer crosses the boundary. The
/// consumer switches on `kind`; the fields carry the payload for that kind (all others
/// are zeroed).
///
/// ## Honest scope — read before gating on the result
/// `kind == SEXTANT_WATCH_NO_SPEND_OBSERVED` proves ONLY that no input consuming the
/// watched outpoint appears in any body of a header-verified, hash-linked, gap-free,
/// body-committed window that observed the outpoint's creation and reached the caller's
/// `require_through` height — under the surfaced `assumptions`, as of the verified tip
/// (`as_of_height`/`as_of_slot`). It is NOT absolute, NOT eternal, NOT tip-state, and NOT
/// a cryptographic proof of a negative; the window trails the live tip. The `assumptions`
/// bits and `as_of_*` travel with the verdict precisely so a consumer sees the scope and
/// never reads a windowed answer as current ledger state. `kind == SEXTANT_WATCH_STALLED`
/// (any gap/short/stale window) and `kind == SEXTANT_WATCH_SPEND_OBSERVED` are both a
/// REFUSE — only `NO_SPEND_OBSERVED`, with the caller's own freshness judgement over
/// `as_of_slot`, clears a gate.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SextantWatchVerdict {
    /// Which verdict: `SEXTANT_WATCH_NO_SPEND_OBSERVED` / `_SPEND_OBSERVED` / `_STALLED`.
    pub kind: u8,
    /// The trust basis, when `kind == NO_SPEND_OBSERVED`: `SEXTANT_WATCH_BASIS_WATCHED_WINDOW`.
    /// `0` otherwise.
    pub basis: u8,
    /// The surfaced assumptions bitset, when `kind == NO_SPEND_OBSERVED`
    /// (`SEXTANT_WATCH_ASSUMPTION_*`). `0` otherwise.
    pub assumptions: u8,
    /// Why the window could not answer, when `kind == STALLED` (`SEXTANT_WATCH_STALL_*`).
    /// `0` otherwise.
    pub stall_reason: u8,
    /// Which trust region a spend was observed in, when `kind == SPEND_OBSERVED`
    /// (`SEXTANT_WATCH_REGION_*`). `0` (n/a) for the other kinds. Occupies a byte that was
    /// reserved padding before ABI 4 — same layout, newly meaningful (hence the ABI bump).
    pub spend_region: u8,
    /// Explicit alignment padding; zeroed on write so the struct is fully deterministic.
    pub _reserved: [u8; 3],
    /// The Mithril-certified anchor height the window rests on, when `kind == NO_SPEND_OBSERVED`.
    pub anchor_height: u64,
    /// The verified tip block number the verdict holds as of, when `kind == NO_SPEND_OBSERVED`.
    pub as_of_height: u64,
    /// The verified tip slot the verdict holds as of, when `kind == NO_SPEND_OBSERVED` — the
    /// value the caller applies its OWN freshness bound to.
    pub as_of_slot: u64,
    /// The highest block number the window verified through before stalling, when
    /// `kind == STALLED`.
    pub verified_through: u64,
    /// The block number the spend was observed in, when `kind == SPEND_OBSERVED`.
    pub spend_at_height: u64,
    /// The slot the spend was observed at, when `kind == SPEND_OBSERVED`.
    pub spend_at_slot: u64,
    /// The id of the transaction that consumed the watched outpoint, when
    /// `kind == SPEND_OBSERVED`. Zeroed otherwise.
    pub spending_txid: [u8; 32],
}

/// Map a [`StallReason`] to its stable C code. Exhaustive (no wildcard): the
/// `#[non_exhaustive]` relaxation does not apply in-crate, so a new stall cause fails to
/// compile here until it is given a code — a tripwire, not a silent `0`.
fn stall_code(reason: StallReason) -> u8 {
    match reason {
        StallReason::EmptyWindow => SEXTANT_WATCH_STALL_EMPTY_WINDOW,
        StallReason::BrokenSegment => SEXTANT_WATCH_STALL_BROKEN_SEGMENT,
        StallReason::BodyCommitmentMismatch => SEXTANT_WATCH_STALL_BODY_COMMITMENT_MISMATCH,
        StallReason::MalformedBody => SEXTANT_WATCH_STALL_MALFORMED_BODY,
        StallReason::MissingBlock => SEXTANT_WATCH_STALL_MISSING_BLOCK,
        StallReason::CreationNotObserved => SEXTANT_WATCH_STALL_CREATION_NOT_OBSERVED,
        StallReason::WindowTooShort => SEXTANT_WATCH_STALL_WINDOW_TOO_SHORT,
        StallReason::TipAboveAnchor => SEXTANT_WATCH_STALL_TIP_ABOVE_ANCHOR,
        StallReason::TipTooOld => SEXTANT_WATCH_STALL_TIP_TOO_OLD,
        StallReason::RollbackBeyondWindow => SEXTANT_WATCH_STALL_ROLLBACK_BEYOND_WINDOW,
    }
}

/// Map a [`SpendRegion`] to its stable C code. Exhaustive (no wildcard): the
/// `#[non_exhaustive]` relaxation does not apply in-crate, so a new region fails to compile
/// here until it is given a code — a tripwire, not a silent `0`.
fn region_code(region: SpendRegion) -> u8 {
    match region {
        SpendRegion::MithrilCertified => SEXTANT_WATCH_REGION_MITHRIL_CERTIFIED,
        SpendRegion::HeaderVouched => SEXTANT_WATCH_REGION_HEADER_VOUCHED,
    }
}

/// The C stall/refusal code an [`AppendRefusal`] surfaces at [`sextant_follower_append`].
/// Reuses the batch-equivalence map [`AppendRefusal::as_stall_reason`] + [`stall_code`], so
/// the boundary reports the SAME reason the batch would over the refused prefix; the
/// follower-only [`AppendRefusal::EpochNonceUnavailable`] (which has no single-epoch batch
/// counterpart, hence `None`) gets the follower code [`SEXTANT_WATCH_STALL_EPOCH_NONCE_UNAVAILABLE`].
fn refusal_code(refusal: AppendRefusal) -> u8 {
    match refusal.as_stall_reason() {
        Some(reason) => stall_code(reason),
        None => SEXTANT_WATCH_STALL_EPOCH_NONCE_UNAVAILABLE,
    }
}

/// Map a [`Rollback`] to its `(return code, out_tip_height)`. Only `Truncated` carries a
/// tip height; the others report `0`.
fn rollback_outcome(r: Rollback) -> (i32, u64) {
    match r {
        Rollback::Truncated { tip_height } => (SEXTANT_FOLLOWER_ROLLBACK_TRUNCATED, tip_height),
        Rollback::ToBase => (SEXTANT_FOLLOWER_ROLLBACK_TO_BASE, 0),
        Rollback::BeyondWindow => (SEXTANT_FOLLOWER_ROLLBACK_BEYOND_WINDOW, 0),
    }
}

/// Map a [`ReAnchor`] to its stable C return code.
fn reanchor_outcome(r: ReAnchor) -> i32 {
    match r {
        ReAnchor::NotMonotone => SEXTANT_FOLLOWER_REANCHOR_NOT_MONOTONE,
        ReAnchor::Advanced => SEXTANT_FOLLOWER_REANCHOR_ADVANCED,
        ReAnchor::AdvancedSpendCertified => SEXTANT_FOLLOWER_REANCHOR_ADVANCED_SPEND_CERTIFIED,
    }
}

/// Encode 32 raw bytes as a 64-char lowercase-hex string, so a caller's raw certified root
/// (the `out_ct_root` of an anchored verify) populates the anchor whose `merkle_root`
/// [`crate::window::certify_spend_region`] hex-decodes. Kept local so `src` needs no hex dep.
fn hex_encode32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Project a [`WatchVerdict`] into the fixed boundary struct, zeroing every field not
/// carried by its kind. The `#[non_exhaustive]` `WatchBasis` matches exhaustively
/// in-crate, so a future basis is a compile error here until it is banded.
fn project_watch_verdict(v: WatchVerdict) -> SextantWatchVerdict {
    let mut out = SextantWatchVerdict {
        kind: 0,
        basis: 0,
        assumptions: 0,
        stall_reason: 0,
        spend_region: 0,
        _reserved: [0u8; 3],
        anchor_height: 0,
        as_of_height: 0,
        as_of_slot: 0,
        verified_through: 0,
        spend_at_height: 0,
        spend_at_slot: 0,
        spending_txid: [0u8; 32],
    };
    match v {
        WatchVerdict::Unspent { as_of, basis } => {
            let WatchBasis::WatchedWindow(a) = basis;
            out.kind = SEXTANT_WATCH_NO_SPEND_OBSERVED;
            out.basis = SEXTANT_WATCH_BASIS_WATCHED_WINDOW;
            out.assumptions = (if a.mithril_quorum {
                SEXTANT_WATCH_ASSUMPTION_MITHRIL_QUORUM
            } else {
                0
            }) | (if a.data_complete {
                SEXTANT_WATCH_ASSUMPTION_DATA_COMPLETE
            } else {
                0
            });
            out.anchor_height = as_of.anchor_height;
            out.as_of_height = as_of.as_of_height;
            out.as_of_slot = as_of.as_of_slot;
        }
        WatchVerdict::SpentObserved {
            at_height,
            at_slot,
            spending_txid,
            region,
        } => {
            out.kind = SEXTANT_WATCH_SPEND_OBSERVED;
            out.spend_at_height = at_height;
            out.spend_at_slot = at_slot;
            out.spending_txid = spending_txid;
            out.spend_region = region_code(region);
        }
        WatchVerdict::Stalled {
            verified_through,
            reason,
        } => {
            out.kind = SEXTANT_WATCH_STALLED;
            out.stall_reason = stall_code(reason);
            out.verified_through = verified_through;
        }
    }
    out
}

/// Run [`crate::window::verify_watched_window`] over a certified, header-verified block
/// window and marshal the three-valued watch verdict into `*out`.
///
/// This is a CORE export — present in the default library and the wasm32 build (the
/// window verifier composes only Blake2b + minicbor, no feature-gated crypto crate). The
/// window's cryptographic strength is the per-header crypto + hash links (`eta0`) and the
/// per-block body-commitment bind; `anchor_height` is a completeness BOUND, not a checked
/// input — it MUST be the `out_ct_block` of a prior
/// [`sextant_mithril_verify_chain_anchored`] so the caller cannot fabricate a certified
/// region. Passing an unauthenticated height forfeits the `mithril_quorum` assumption the
/// verdict surfaces, exactly as a wrong `eta0` forfeits a real verify — the boundary
/// cannot verify provenance, so it SURFACES the assumption instead of hiding it.
///
/// `require_through` is the caller's HARD lower bound on the verified tip: a window whose
/// tip is below it is `SEXTANT_WATCH_STALLED` with `SEXTANT_WATCH_STALL_WINDOW_TOO_SHORT`,
/// never a false no-spend — this closes the truncation evasion, which freshness alone
/// cannot. The caller sets it to the height it needs no-spend coverage through.
///
/// Returns `0` once the verdict is computed (branch on `out.kind` — a spend or a stall is
/// STILL `0`, the verdict is in the struct), or a negative [`SextantStatus`] for a
/// boundary/caller error (null pointer, zero `count`) with `*out` left untouched.
///
/// # Safety
/// `block_ptrs`/`block_lens` must each point to `count` readable entries, each
/// `block_ptrs[i]` to `block_lens[i]` readable bytes; `eta0` and `watched_txid` to 32
/// readable bytes each; `out` to a writable [`SextantWatchVerdict`]. All borrows live
/// only for the duration of the call.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sextant_verify_watched_window(
    block_ptrs: *const *const u8,
    block_lens: *const usize,
    count: usize,
    eta0: *const u8,
    anchor_height: u64,
    watched_txid: *const u8,
    watched_index: u16,
    require_through: u64,
    freshness_slot_now: u64,
    freshness_max_lag: u64,
    out: *mut SextantWatchVerdict,
) -> i32 {
    guard(|| {
        if block_ptrs.is_null()
            || block_lens.is_null()
            || eta0.is_null()
            || watched_txid.is_null()
            || out.is_null()
        {
            return SextantStatus::ErrNullPointer as i32;
        }
        if count == 0 {
            return SextantStatus::ErrEmptyInput as i32;
        }
        // SAFETY: `block_ptrs`/`block_lens` point to `count` valid entries (caller
        // contract); the borrows live only inside this closure.
        let ptrs = unsafe { slice::from_raw_parts(block_ptrs, count) };
        let lens = unsafe { slice::from_raw_parts(block_lens, count) };
        let mut blocks: Vec<&[u8]> = Vec::with_capacity(count);
        for i in 0..count {
            if ptrs[i].is_null() {
                return SextantStatus::ErrNullPointer as i32;
            }
            // SAFETY: `ptrs[i]` is non-null and points to `lens[i]` readable bytes.
            blocks.push(unsafe { slice::from_raw_parts(ptrs[i], lens[i]) });
        }
        // SAFETY: `eta0` and `watched_txid` are non-null and point to 32 readable bytes.
        let eta0 = unsafe { &*(eta0 as *const [u8; 32]) };
        let watch = OutPoint {
            tx_id: *unsafe { &*(watched_txid as *const [u8; 32]) },
            index: watched_index,
        };
        // The window path reads only the anchor's height (a completeness bound); its
        // merkle_root/epoch are not consumed, so a certified root is not marshalled here.
        let anchor = CertifiedTransactions {
            merkle_root: String::new(),
            epoch: 0,
            block_number: anchor_height,
        };
        let freshness = Freshness {
            slot_now: freshness_slot_now,
            max_lag: freshness_max_lag,
        };
        let verdict = window::verify_watched_window(
            watch,
            &anchor,
            require_through,
            &blocks,
            eta0,
            freshness,
        );
        // SAFETY: `out` is non-null (checked); the whole struct is written once.
        unsafe { *out = project_watch_verdict(verdict) };
        SextantStatus::Ok as i32
    })
}

// ---- The live window follower (F5) ----
//
// [`crate::follow::WindowFollower`] as an opaque C handle: create it, feed it one block
// at a time (a chain-sync `RollForward`), roll it back (a `RollBackward`), advance its
// certified anchor, and read the three-valued [`SextantWatchVerdict`] at any point. The
// handle owns a heap [`WindowFollower`]; the caller MUST pair every
// [`sextant_follower_new`] with exactly one [`sextant_follower_destroy`]. No lib-owned
// buffer crosses back out (the verdict projects into a caller struct), so the
// create/destroy pair is the only allocation the boundary owns — wasm-legal.
//
// Return convention (all mutation/read exports): a NEGATIVE `i32` is a boundary/caller
// error ([`SextantStatus`], incl. `ErrPanic`); `>= 0` is the domain outcome for that call
// (documented per export). `sextant_follower_new` returns the handle (or null on a null
// txid); `sextant_follower_destroy` returns nothing.

/// Opaque handle to a live [`WindowFollower`]. Its fields never cross the boundary
/// (cbindgen emits it as an opaque forward declaration); a caller holds only the pointer.
pub struct SextantFollower {
    inner: WindowFollower,
}

/// Start following for a spend of the outpoint `(watched_txid, watched_index)`, answered
/// as of a verified tip at or above `require_through`, inside the Mithril-certified region
/// bounded by `anchor_height`, with epochs laid out by the `schedule_*` triple
/// (`epoch`, its first slot, and the constant epoch length in slots). Stage each epoch's
/// nonce with [`sextant_follower_supply_next_eta0`] before appending its blocks.
///
/// Returns the heap-allocated handle, or null if `watched_txid` is null. Pair with exactly
/// one [`sextant_follower_destroy`].
///
/// # Safety
/// `watched_txid` must be null or point to 32 readable bytes. The returned pointer is owned
/// by the caller and valid until passed to [`sextant_follower_destroy`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_follower_new(
    watched_txid: *const u8,
    watched_index: u16,
    anchor_height: u64,
    require_through: u64,
    schedule_epoch: u64,
    schedule_epoch_first_slot: u64,
    schedule_epoch_length_slots: u64,
) -> *mut SextantFollower {
    if watched_txid.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `watched_txid` is non-null and points to 32 readable bytes (caller contract).
    let tx_id = *unsafe { &*(watched_txid as *const [u8; 32]) };
    let watch = OutPoint {
        tx_id,
        index: watched_index,
    };
    // `new` reads only the anchor's block_number (a completeness bound); its root/epoch are
    // not consumed here, so an empty root is honest — the certified root only matters at a
    // re-anchor that certifies a spend (see [`sextant_follower_re_anchor`]).
    let anchor = CertifiedTransactions {
        merkle_root: String::new(),
        epoch: 0,
        block_number: anchor_height,
    };
    let schedule = SlotSchedule {
        epoch: schedule_epoch,
        epoch_first_slot: schedule_epoch_first_slot,
        epoch_length_slots: schedule_epoch_length_slots,
    };
    let follower = WindowFollower::new(watch, &anchor, require_through, schedule);
    Box::into_raw(Box::new(SextantFollower { inner: follower }))
}

/// Free a follower handle produced by [`sextant_follower_new`]. A null handle is a no-op.
///
/// # Safety
/// `handle` must be null or a pointer returned by [`sextant_follower_new`] that has not
/// already been destroyed. After this call the pointer is dangling and must not be reused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_follower_destroy(handle: *mut SextantFollower) {
    if !handle.is_null() {
        // SAFETY: `handle` came from `Box::into_raw` in `sextant_follower_new` and is not
        // used after this call (caller contract); reclaim the box and drop it.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Stage the epoch nonce η0 for `epoch`. The follower selects it for any appended block
/// whose slot the schedule places in `epoch`. Overwritable: a mis-fetched nonce can be
/// corrected before a block is accepted under it (a wrong nonce only makes a block fail to
/// verify — liveness — never verify falsely).
///
/// Returns `0` on success, or [`SextantStatus::ErrNullPointer`] for a null handle/`eta0`.
///
/// # Safety
/// `handle` must be a live follower handle; `eta0` must point to 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_follower_supply_next_eta0(
    handle: *mut SextantFollower,
    epoch: u64,
    eta0: *const u8,
) -> i32 {
    guard(|| {
        if handle.is_null() || eta0.is_null() {
            return SextantStatus::ErrNullPointer as i32;
        }
        // SAFETY: `handle` is live; `eta0` points to 32 readable bytes (caller contract).
        let follower = unsafe { &mut (*handle).inner };
        let eta0 = *unsafe { &*(eta0 as *const [u8; 32]) };
        follower.supply_next_eta0(epoch, eta0);
        SextantStatus::Ok as i32
    })
}

/// Verify and fold one block (ledger `[era, block]` CBOR) into the follower. The block
/// must decode, link to the verified tip by hash with block-number `tip + 1`, have its
/// operational certificate / leader-VRF (against its epoch nonce) / KES verify, and have
/// its bodies bind to its header commitment; only then is it accepted.
///
/// Returns `0` on acceptance (`*out_block_number` = the new verified tip height), a
/// POSITIVE refusal code (`SEXTANT_WATCH_STALL_*`, incl.
/// [`SEXTANT_WATCH_STALL_EPOCH_NONCE_UNAVAILABLE`]) if the block did not extend the tip —
/// a refusal leaves the follower UNTOUCHED, so a later correct block still appends — or a
/// negative [`SextantStatus`] for a boundary error. `out_block_number` is untouched on a
/// non-zero return.
///
/// # Safety
/// `handle` must be a live follower handle; `block` must point to `block_len` readable
/// bytes; `out_block_number` must be null or point to a writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_follower_append(
    handle: *mut SextantFollower,
    block: *const u8,
    block_len: usize,
    out_block_number: *mut u64,
) -> i32 {
    guard(|| {
        if handle.is_null() || block.is_null() {
            return SextantStatus::ErrNullPointer as i32;
        }
        if block_len == 0 {
            return SextantStatus::ErrEmptyInput as i32;
        }
        // SAFETY: `handle` is live; `block` points to `block_len` readable bytes.
        let follower = unsafe { &mut (*handle).inner };
        let bytes = unsafe { slice::from_raw_parts(block, block_len) };
        match follower.append(bytes) {
            Ok(appended) => {
                if !out_block_number.is_null() {
                    // SAFETY: non-null, writable `u64` (caller contract).
                    unsafe { *out_block_number = appended.block_number };
                }
                SextantStatus::Ok as i32
            }
            Err(refusal) => refusal_code(refusal) as i32,
        }
    })
}

/// Roll the follower back to the point `(slot, hash)` — a chain-sync `RollBackward`. The
/// 32-byte `hash` is the authoritative block identifier; `slot` accompanies it for `Point`
/// fidelity.
///
/// Returns one of [`SEXTANT_FOLLOWER_ROLLBACK_TRUNCATED`] (in-ring; `*out_tip_height` = the
/// new verified tip), [`SEXTANT_FOLLOWER_ROLLBACK_TO_BASE`] (rolled back to the follow base;
/// `*out_tip_height` = 0), or [`SEXTANT_FOLLOWER_ROLLBACK_BEYOND_WINDOW`] (deeper than the
/// retained horizon — the follower is poisoned, discard it); or a negative [`SextantStatus`]
/// for a boundary error. `out_tip_height` is written on any non-negative return.
///
/// # Safety
/// `handle` must be a live follower handle; `hash` must point to 32 readable bytes;
/// `out_tip_height` must be null or point to a writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_follower_rollback(
    handle: *mut SextantFollower,
    slot: u64,
    hash: *const u8,
    out_tip_height: *mut u64,
) -> i32 {
    guard(|| {
        if handle.is_null() || hash.is_null() {
            return SextantStatus::ErrNullPointer as i32;
        }
        // SAFETY: `handle` is live; `hash` points to 32 readable bytes (caller contract).
        let follower = unsafe { &mut (*handle).inner };
        let hash = unsafe { &*(hash as *const [u8; 32]) };
        let (code, tip_height) = rollback_outcome(follower.rollback(slot, hash));
        if !out_tip_height.is_null() {
            // SAFETY: non-null, writable `u64` (caller contract).
            unsafe { *out_tip_height = tip_height };
        }
        code
    })
}

/// Advance the certified anchor to `(anchor_height, anchor_root)` — monotone in block
/// number, so a lower anchor is [`SEXTANT_FOLLOWER_REANCHOR_NOT_MONOTONE`] and the certified
/// region only grows. If `proof` is non-null AND the follower has observed a spend, the
/// spend's inclusion in the new anchor's certified transaction set is verified against
/// `anchor_root`; on success the spend's region upgrades to
/// [`SEXTANT_WATCH_REGION_MITHRIL_CERTIFIED`]. Height NEVER upgrades a spend — only a proof
/// that recomputes to the certified root does.
///
/// `anchor_root` MUST be the `out_ct_root` of a prior
/// [`sextant_mithril_verify_chain_anchored`]: the boundary cannot verify a caller-fabricated
/// root's provenance, so — exactly as the batch window verify does with `anchor_height` — it
/// surfaces the `mithril_quorum` assumption rather than checking it.
///
/// Returns one of [`SEXTANT_FOLLOWER_REANCHOR_NOT_MONOTONE`] /
/// [`SEXTANT_FOLLOWER_REANCHOR_ADVANCED`] / [`SEXTANT_FOLLOWER_REANCHOR_ADVANCED_SPEND_CERTIFIED`],
/// or a negative [`SextantStatus`] for a boundary error.
///
/// # Safety
/// `handle` must be a live follower handle; `anchor_root` must point to 32 readable bytes;
/// `proof` must be null (iff `proof_len` is 0) or point to `proof_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_follower_re_anchor(
    handle: *mut SextantFollower,
    anchor_height: u64,
    anchor_root: *const u8,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    guard(|| {
        if handle.is_null() || anchor_root.is_null() {
            return SextantStatus::ErrNullPointer as i32;
        }
        // SAFETY: `handle` is live; `anchor_root` points to 32 readable bytes.
        let follower = unsafe { &mut (*handle).inner };
        let root = unsafe { &*(anchor_root as *const [u8; 32]) };
        let anchor = CertifiedTransactions {
            merkle_root: hex_encode32(root),
            epoch: 0,
            block_number: anchor_height,
        };
        // A null (or empty) proof advances the anchor only; a non-null proof is the
        // spending-tx inclusion proof that can upgrade the observed spend.
        let spend_proof = if proof.is_null() || proof_len == 0 {
            None
        } else {
            // SAFETY: non-null, points to `proof_len` readable bytes (caller contract).
            Some(unsafe { slice::from_raw_parts(proof, proof_len) })
        };
        reanchor_outcome(follower.re_anchor(&anchor, spend_proof))
    })
}

/// Read the follower's current three-valued windowed verdict, answered as of the verified
/// tip under the caller's freshness bound (`freshness_slot_now` / `freshness_max_lag`), and
/// marshal it into `*out`. Branch on `out.kind` — a spend or a stall is STILL a `0` return
/// (the verdict is in the struct); only a null pointer is a negative [`SextantStatus`].
///
/// # Safety
/// `handle` must be a live follower handle; `out` must point to a writable
/// [`SextantWatchVerdict`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sextant_follower_verdict(
    handle: *mut SextantFollower,
    freshness_slot_now: u64,
    freshness_max_lag: u64,
    out: *mut SextantWatchVerdict,
) -> i32 {
    guard(|| {
        if handle.is_null() || out.is_null() {
            return SextantStatus::ErrNullPointer as i32;
        }
        // SAFETY: `handle` is live; `out` is writable (caller contract).
        let follower = unsafe { &(*handle).inner };
        let freshness = Freshness {
            slot_now: freshness_slot_now,
            max_lag: freshness_max_lag,
        };
        let verdict = follower.verdict(freshness);
        unsafe { *out = project_watch_verdict(verdict) };
        SextantStatus::Ok as i32
    })
}

/// Verify a genesis-anchored Mithril certificate chain (each entry the aggregator's
/// JSON, oldest first) under the pinned per-network `genesis_vkey`.
///
/// On success returns `0`, writes the 64-lowercase-hex root and tip certificate hashes
/// (no NUL) into `out_root_hex`/`out_tip_hex`, and the segment length into `out_length`.
/// A JSON that fails to parse returns [`SextantStatus::MithrilStdMalformedCertJson`]
/// with its index; any verification failure flattens `AnchoredError` to its leaf band +
/// offending certificate index.
///
/// The tip's certified transaction set (when the tip is a `CardanoTransactions`
/// certificate) is surfaced through `out_ct_root` (the 32 RAW bytes of the certified
/// Merkle root, ready to pass straight as the `certified_root` of
/// [`sextant_verify_utxo_read`]), `out_ct_block` (the certified height), and
/// `out_has_ct` (`1` present, `0` absent — root zeroed, block `0`). Because the root
/// is obtainable ONLY from this genesis-authenticated verify, a consumer is
/// physically unable to obtain a certified root without having anchored the chain to
/// genesis. A tip whose certified Merkle root is not 32-byte hex fails CLOSED to
/// [`SextantStatus::MithrilStdMalformedCertJson`] (never a partial `out_ct_root`).
///
/// # Safety
/// `cert_json_ptrs`/`cert_json_lens` must each point to `count` readable entries, each
/// pointer to its length in readable bytes; `genesis_vkey` to 32 readable bytes;
/// `out_root_hex` and `out_tip_hex` to 64 writable bytes each; `out_length` to a
/// writable `u64`; `out_ct_root` to 32 writable bytes; `out_ct_block` to a writable
/// `u64`; `out_has_ct` to a writable `u8`; `out_detail` must be null or point to a
/// writable [`SextantErrorDetail`].
#[cfg(feature = "mithril")]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sextant_mithril_verify_chain_anchored(
    cert_json_ptrs: *const *const u8,
    cert_json_lens: *const usize,
    count: usize,
    genesis_vkey: *const u8,
    out_root_hex: *mut u8,
    out_tip_hex: *mut u8,
    out_length: *mut u64,
    out_ct_root: *mut u8,
    out_ct_block: *mut u64,
    out_has_ct: *mut u8,
    out_detail: *mut SextantErrorDetail,
) -> i32 {
    guard(|| {
        if cert_json_ptrs.is_null()
            || cert_json_lens.is_null()
            || genesis_vkey.is_null()
            || out_root_hex.is_null()
            || out_tip_hex.is_null()
            || out_length.is_null()
            || out_ct_root.is_null()
            || out_ct_block.is_null()
            || out_has_ct.is_null()
        {
            return SextantStatus::ErrNullPointer as i32;
        }
        if count == 0 {
            return SextantStatus::ErrEmptyInput as i32;
        }
        // SAFETY: `cert_json_ptrs`/`cert_json_lens` point to `count` valid entries.
        let ptrs = unsafe { slice::from_raw_parts(cert_json_ptrs, count) };
        let lens = unsafe { slice::from_raw_parts(cert_json_lens, count) };
        let mut certs: Vec<Certificate> = Vec::with_capacity(count);
        for i in 0..count {
            if ptrs[i].is_null() {
                return SextantStatus::ErrNullPointer as i32;
            }
            // SAFETY: `ptrs[i]` is non-null and points to `lens[i]` readable bytes.
            let json = unsafe { slice::from_raw_parts(ptrs[i], lens[i]) };
            match Certificate::from_json(json) {
                Ok(c) => certs.push(c),
                Err(_) => {
                    write_detail(out_detail, i as i64, 0);
                    return SextantStatus::MithrilStdMalformedCertJson as i32;
                }
            }
        }
        // SAFETY: `genesis_vkey` is non-null and points to 32 readable bytes.
        let vkey = unsafe { &*(genesis_vkey as *const [u8; 32]) };
        match mithril::verify_chain_anchored(&certs, vkey) {
            Ok(v) => {
                // The certified transaction set from the AUTHENTICATED tip. A tip that
                // certifies a set with a non-32-byte-hex root is a malformed cert:
                // fail closed rather than surface a partial/garbage root with has_ct=1.
                let ct = match &v.certified_transactions {
                    Some(ct) => match ct.merkle_root_bytes() {
                        Some(root) => Some((root, ct.block_number)),
                        None => {
                            write_detail(out_detail, -1, 0);
                            return SextantStatus::MithrilStdMalformedCertJson as i32;
                        }
                    },
                    None => None,
                };
                // SAFETY: all out pointers are non-null (checked); the hex hashes are
                // exactly 64 chars, `out_ct_root` has ≥32 writable bytes. Written once.
                unsafe {
                    write_hex64(out_root_hex, &v.root_hash);
                    write_hex64(out_tip_hex, &v.tip_hash);
                    *out_length = v.length as u64;
                    match ct {
                        Some((root, block)) => {
                            ptr::copy_nonoverlapping(root.as_ptr(), out_ct_root, 32);
                            *out_ct_block = block;
                            *out_has_ct = 1;
                        }
                        None => {
                            ptr::write_bytes(out_ct_root, 0, 32);
                            *out_ct_block = 0;
                            *out_has_ct = 0;
                        }
                    }
                }
                write_detail(out_detail, -1, 0);
                SextantStatus::Ok as i32
            }
            Err(e) => {
                let (status, index, detail) = anchored_status(&e);
                write_detail(out_detail, index, detail);
                status
            }
        }
    })
}

/// Copy up to 64 bytes of a hex hash into a caller buffer (no NUL). Two callers: the
/// root and tip out-buffers.
///
/// # Safety
/// `dst` must point to at least 64 writable bytes.
#[cfg(feature = "mithril")]
unsafe fn write_hex64(dst: *mut u8, hex: &str) {
    let src = hex.as_bytes();
    let n = src.len().min(64);
    // SAFETY: `dst` points to ≥64 writable bytes; `n <= 64`; ranges are distinct.
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst, n) };
}

/// Flatten an [`AnchoredError`] to `(status, index, detail)` across its three arms: the
/// 300 chain band (with the cert index), the 310 genesis band (root), and the 320
/// standard band (with the rising cert's 1-based index).
#[cfg(feature = "mithril")]
fn anchored_status(e: &AnchoredError) -> (i32, i64, u64) {
    use SextantStatus as S;
    match e {
        AnchoredError::Chain(ce) => match ce {
            MithrilChainError::Empty => (S::MithrilChainEmpty as i32, -1, 0),
            MithrilChainError::Hash { index } => (S::MithrilChainHash as i32, *index as i64, 0),
            MithrilChainError::BrokenLink { index } => {
                (S::MithrilChainBrokenLink as i32, *index as i64, 0)
            }
            MithrilChainError::AvkBinding { index } => {
                (S::MithrilChainAvkBinding as i32, *index as i64, 0)
            }
        },
        AnchoredError::Genesis(ge) => {
            let code = match ge {
                GenesisError::NotGenesis => S::MithrilGenesisNotGenesis,
                GenesisError::MalformedSignature => S::MithrilGenesisMalformedSignature,
                GenesisError::MessageMismatch => S::MithrilGenesisMessageMismatch,
                GenesisError::InvalidSignature => S::MithrilGenesisInvalidSignature,
            };
            (code as i32, 0, 0)
        }
        AnchoredError::Standard { index, source } => {
            let code = match source {
                StandardError::NotStandard => S::MithrilStdNotStandard,
                StandardError::MessageMismatch => S::MithrilStdMessageMismatch,
                StandardError::WeakParameters => S::MithrilStdWeakParameters,
                StandardError::ImplausibleAvk => S::MithrilStdImplausibleAvk,
                StandardError::MalformedAvk => S::MithrilStdMalformedAvk,
                StandardError::MalformedSignature => S::MithrilStdMalformedSignature,
                StandardError::InvalidMultiSignature => S::MithrilStdInvalidMultiSignature,
            };
            (code as i32, *index as i64, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::OpCert;

    /// The guard converts a panic in the boundary body into `ErrPanic`, never a native
    /// abort or an unwind across `extern "C"`.
    #[test]
    fn guard_converts_panic_to_err_panic() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // keep the harness output clean
        let rc = guard(|| panic!("boundary body panicked"));
        std::panic::set_hook(prev);
        assert_eq!(rc, SextantStatus::ErrPanic as i32);
    }

    #[test]
    fn guard_passes_through_the_ok_code() {
        assert_eq!(guard(|| SextantStatus::Ok as i32), 0);
    }

    /// A header with no parent projects to `has_prev_hash == 0` and a zeroed
    /// `prev_hash` (there is no genesis vector, so this exercises the branch directly).
    #[test]
    fn project_header_genesis_has_no_prev_hash() {
        let view = HeaderView {
            era: 7,
            block_number: 1,
            slot: 2,
            prev_hash: None,
            block_hash: [3u8; 32],
            issuer_vkey: [4u8; 32],
            vrf_vkey: [5u8; 32],
            vrf_output: [6u8; 64],
            vrf_proof: [7u8; 80],
            block_body_hash: [12u8; 32],
            opcert: OpCert {
                hot_vkey: [8u8; 32],
                sequence_number: 9,
                kes_period: 10,
                sigma: [11u8; 64],
            },
            header_body: Vec::new(),
            body_signature: [0u8; 448],
        };
        let p = project_header(&view);
        assert_eq!(p.has_prev_hash, 0);
        assert_eq!(p.prev_hash, [0u8; 32]);
        assert_eq!(p.block_number, 1);
        assert_eq!(p.opcert_hot_vkey, [8u8; 32]);
        assert_eq!(p._reserved, [0u8; 6]);
    }

    /// The two spend regions project to their distinct ABI-4 codes (the `HeaderVouched`
    /// case is also covered end-to-end at the C boundary; `MithrilCertified` cannot be
    /// reached through the committed fixtures' window spend, so it is pinned here).
    #[test]
    fn project_watch_verdict_maps_the_spend_region() {
        let base = WatchVerdict::SpentObserved {
            at_height: 42,
            at_slot: 7,
            spending_txid: [9u8; 32],
            region: SpendRegion::MithrilCertified,
        };
        let certified = project_watch_verdict(base);
        assert_eq!(certified.kind, SEXTANT_WATCH_SPEND_OBSERVED);
        assert_eq!(
            certified.spend_region,
            SEXTANT_WATCH_REGION_MITHRIL_CERTIFIED
        );
        assert_eq!(certified._reserved, [0u8; 3]);

        let vouched = project_watch_verdict(WatchVerdict::SpentObserved {
            at_height: 42,
            at_slot: 7,
            spending_txid: [9u8; 32],
            region: SpendRegion::HeaderVouched,
        });
        assert_eq!(vouched.spend_region, SEXTANT_WATCH_REGION_HEADER_VOUCHED);
    }

    #[test]
    fn status_message_is_defined_for_every_code_and_unknowns() {
        for (s, msg) in STATUS_MESSAGES {
            assert_eq!(status_message(*s as i32), *msg);
            assert!(!msg.is_empty());
        }
        assert_eq!(status_message(9999), "unknown status");
    }
}
