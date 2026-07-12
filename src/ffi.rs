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
use crate::header::{DecodeError, HeaderView};
use crate::kes::KesError;
use crate::vrf::VrfError;

#[cfg(feature = "mithril")]
use crate::mithril::{
    self, AnchoredError, Certificate, ChainError as MithrilChainError, GenesisError, StandardError,
};

/// ABI contract version. A consumer asserts `sextant_abi_version() == SEXTANT_ABI_VERSION`
/// at load; cbindgen emits it into the header as a `#define`.
pub const SEXTANT_ABI_VERSION: u32 = 1;

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
    ]
};

fn status_message(status: i32) -> &'static str {
    STATUS_MESSAGES
        .iter()
        .find(|(s, _)| *s as i32 == status)
        .map_or("unknown status", |(_, msg)| *msg)
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
/// # Safety
/// `cert_json_ptrs`/`cert_json_lens` must each point to `count` readable entries, each
/// pointer to its length in readable bytes; `genesis_vkey` to 32 readable bytes;
/// `out_root_hex` and `out_tip_hex` to 64 writable bytes each; `out_length` to a
/// writable `u64`; `out_detail` must be null or point to a writable [`SextantErrorDetail`].
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
    out_detail: *mut SextantErrorDetail,
) -> i32 {
    guard(|| {
        if cert_json_ptrs.is_null()
            || cert_json_lens.is_null()
            || genesis_vkey.is_null()
            || out_root_hex.is_null()
            || out_tip_hex.is_null()
            || out_length.is_null()
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
                // SAFETY: both out buffers are caller-allocated with ≥64 bytes; each
                // hash is exactly 64 lowercase hex chars.
                unsafe {
                    write_hex64(out_root_hex, &v.root_hash);
                    write_hex64(out_tip_hex, &v.tip_hash);
                    *out_length = v.length as u64;
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

    #[test]
    fn status_message_is_defined_for_every_code_and_unknowns() {
        for (s, msg) in STATUS_MESSAGES {
            assert_eq!(status_message(*s as i32), *msg);
            assert!(!msg.is_empty());
        }
        assert_eq!(status_message(9999), "unknown status");
    }
}
