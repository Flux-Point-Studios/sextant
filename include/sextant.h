#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * ABI contract version. A consumer asserts `sextant_abi_version() == SEXTANT_ABI_VERSION`
 * at load; cbindgen emits it into the header as a `#define`.
 */
#define SEXTANT_ABI_VERSION 1

/**
 * Every verdict the boundary can return, as one flat `#[repr(i32)]` enum. All bands
 * are defined unconditionally (only the mithril *function* is feature-gated) so the
 * committed header and the numbering are identical across build configs. Negative =
 * a boundary/caller error; 0 = ok; positive bands mirror the internal verifiers.
 */
enum SextantStatus
#ifdef __cplusplus
  : int32_t
#endif // __cplusplus
 {
  Ok = 0,
  ErrNullPointer = -1,
  ErrEmptyInput = -2,
  /**
   * Reserved: a caller-provided output buffer was too small (sizing protocol).
   */
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
};
#ifndef __cplusplus
typedef int32_t SextantStatus;
#endif // __cplusplus

/**
 * Per-verdict detail carried alongside the status code, so a caller can point at the
 * offending certificate/block and recover the leaf reason. Caller-allocated, fixed
 * width, memcpy-safe. `index == -1` means "not applicable"; `detail == 0` means none.
 */
typedef struct {
  /**
   * 0-based position of the offending block/certificate, or `-1`.
   */
  int64_t index;
  /**
   * The inner leaf status code, or a decode scalar (era/len), or `0`.
   */
  uint64_t detail;
} SextantErrorDetail;

/**
 * The read-path header fields, projected into a fixed `#[repr(C)]` struct. Only read
 * fields are exposed; the verification inputs (`header_body`, `vrf_proof`,
 * `body_signature`) are consumed by `verify_segment`, not surfaced — which keeps this
 * struct fixed-width (no owned buffer crosses the boundary).
 */
typedef struct {
  uint64_t block_number;
  uint64_t slot;
  uint64_t opcert_sequence_number;
  uint64_t opcert_kes_period;
  uint8_t block_hash[32];
  /**
   * The parent block hash; all zero when `has_prev_hash == 0`.
   */
  uint8_t prev_hash[32];
  uint8_t issuer_vkey[32];
  uint8_t vrf_vkey[32];
  uint8_t vrf_output[64];
  uint8_t opcert_hot_vkey[32];
  uint8_t era;
  /**
   * `1` if `prev_hash` is present; `0` for a genesis header ([0;32] is a legal hash,
   * so it cannot double as a sentinel).
   */
  uint8_t has_prev_hash;
  /**
   * Explicit tail padding; zeroed on write so the struct is fully deterministic.
   */
  uint8_t _reserved[6];
} SextantHeaderView;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * The ABI version this build implements.
 */
uint32_t sextant_abi_version(void);

/**
 * Verify a block-chain segment (ledger `[era, block]` CBOR, on-chain order) against
 * the epoch nonce `eta0`, composing the full per-header crypto and the hash links.
 *
 * Returns [`SextantStatus`] as `i32`: `0` on success (`out_detail = {index:-1,
 * detail:0}`), else the failure band with the offending block index and inner leaf
 * code in `out_detail`.
 *
 * # Safety
 * `block_ptrs` and `block_lens` must each point to `count` readable entries; each
 * `block_ptrs[i]` to `block_lens[i]` readable bytes; `eta0` to 32 readable bytes;
 * `out_detail` must be null or point to a writable [`SextantErrorDetail`]. All borrows
 * live only for the duration of the call.
 */
int32_t sextant_verify_segment(const uint8_t *const *block_ptrs,
                               const uintptr_t *block_lens,
                               uintptr_t count,
                               const uint8_t *eta0,
                               SextantErrorDetail *out_detail);

/**
 * Decode a single block header's read fields into `out`.
 *
 * Returns `0` on success (`out` filled, `out_detail = {index:-1, detail:0}`), else the
 * 100-band decode status; for an unsupported era / bad hash length `out_detail.detail`
 * carries the era/len scalar.
 *
 * # Safety
 * `bytes` must point to `bytes_len` readable bytes; `out` must point to a writable
 * [`SextantHeaderView`]; `out_detail` must be null or point to a writable
 * [`SextantErrorDetail`].
 */
int32_t sextant_header_decode(const uint8_t *bytes,
                              uintptr_t bytes_len,
                              SextantHeaderView *out,
                              SextantErrorDetail *out_detail);

/**
 * Copy the static, human-readable message for a status code into `buf` (log-only,
 * never verdict-bearing). Returns the full message length in bytes; a null `buf` or
 * `cap == 0` is a sizing query that copies nothing.
 *
 * # Safety
 * `buf` must be null, or point to `cap` writable bytes.
 */
uintptr_t sextant_status_message(int32_t status, uint8_t *buf, uintptr_t cap);

#if defined(SEXTANT_MITHRIL)
/**
 * Verify a genesis-anchored Mithril certificate chain (each entry the aggregator's
 * JSON, oldest first) under the pinned per-network `genesis_vkey`.
 *
 * On success returns `0`, writes the 64-lowercase-hex root and tip certificate hashes
 * (no NUL) into `out_root_hex`/`out_tip_hex`, and the segment length into `out_length`.
 * A JSON that fails to parse returns [`SextantStatus::MithrilStdMalformedCertJson`]
 * with its index; any verification failure flattens `AnchoredError` to its leaf band +
 * offending certificate index.
 *
 * # Safety
 * `cert_json_ptrs`/`cert_json_lens` must each point to `count` readable entries, each
 * pointer to its length in readable bytes; `genesis_vkey` to 32 readable bytes;
 * `out_root_hex` and `out_tip_hex` to 64 writable bytes each; `out_length` to a
 * writable `u64`; `out_detail` must be null or point to a writable [`SextantErrorDetail`].
 */
int32_t sextant_mithril_verify_chain_anchored(const uint8_t *const *cert_json_ptrs,
                                              const uintptr_t *cert_json_lens,
                                              uintptr_t count,
                                              const uint8_t *genesis_vkey,
                                              uint8_t *out_root_hex,
                                              uint8_t *out_tip_hex,
                                              uint64_t *out_length,
                                              SextantErrorDetail *out_detail);
#endif

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
