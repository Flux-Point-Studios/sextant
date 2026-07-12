#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * ABI contract version. A consumer asserts `sextant_abi_version() == SEXTANT_ABI_VERSION`
 * at load; cbindgen emits it into the header as a `#define`. Bumped 1→2 for the UTxO
 * read export and the certified-transactions out-params on the anchored verify.
 */
#define SEXTANT_ABI_VERSION 2

/**
 * The only defined `spend_status` value a verified read returns. The read path can
 * NEVER establish that an output is currently available to spend (see
 * [`SextantVerifiedOutput`]); no wire value means it is, and none is ever written.
 *
 * `spend_status` is a BANDED code space: `0` = not established. A future
 * CRYPTOGRAPHIC band (a Mithril ledger-state proof) and a future ECONOMIC/attested
 * band (a committee attestation) are RESERVED and kept distinct, so a consumer
 * switching on the byte always sees the trust basis and can never read an
 * attestation as a proof. New tiers are additive (a new constant + an ABI-version
 * bump), never a layout break. cbindgen emits this as a `#define`.
 */
#define SEXTANT_SPEND_NOT_ESTABLISHED 0

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
  UtxoInclusionNotIncluded = 400,
  UtxoInclusionRootMismatch = 401,
  UtxoInclusionMalformedProof = 402,
  UtxoMalformedTx = 410,
  UtxoOutputIndexOutOfRange = 411,
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

/**
 * A verified transaction output, projected into a caller-allocated fixed-width
 * `#[repr(C)]` struct. The scalars live here; the variable-length `address` and
 * `datum` bytes are delivered to the caller's `(buf, cap)` pairs, with the true
 * lengths reported here so a caller can size a retry (the sizing protocol).
 *
 * ## Honest scope — read before gating on the result
 * A genuine `Ok` proves the returned `{address, lovelace, datum}` are the AUTHENTIC
 * on-chain bytes of a Mithril-certified output: its certified INCLUSION and its
 * provenance are anchored to the network genesis key as of `certified_at`, and
 * NOTHING MORE. It is NOT a claim that the output is currently available to spend —
 * Cardano commits to no UTxO-set accumulator, the verdict trails tip by ~100 blocks,
 * and the ledger decides availability atomically at submission. `spend_status` is
 * ALWAYS [`SEXTANT_SPEND_NOT_ESTABLISHED`]; never gate a spend on it.
 */
typedef struct {
  /**
   * The output's ADA amount in lovelace (its `coin`; any multi-asset is excluded).
   */
  uint64_t lovelace;
  /**
   * The Mithril-certified block height the output was attested at — NOT tip state,
   * NOT a liveness claim.
   */
  uint64_t certified_at;
  /**
   * The true length of the address bytes; may exceed `address_cap` (then retry).
   */
  uintptr_t address_len;
  /**
   * The true length of the datum bytes: `0` = none, `32` = a datum hash, variable
   * = an inline datum; may exceed `datum_cap` (then retry).
   */
  uintptr_t datum_len;
  /**
   * `0` = no datum, `1` = a 32-byte datum hash in `datum_buf`, `2` = an inline
   * datum (`datum_len` raw plutus-data CBOR bytes in `datum_buf`, `#6.24`-unwrapped
   * — the caller decodes it).
   */
  uint8_t datum_kind;
  /**
   * Always [`SEXTANT_SPEND_NOT_ESTABLISHED`] (`0`) — the read path cannot establish
   * liveness; never gate on it.
   */
  uint8_t spend_status;
  /**
   * Explicit tail padding; zeroed on write so the struct is fully deterministic.
   */
  uint8_t _reserved[6];
} SextantVerifiedOutput;

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

/**
 * Verify that output `out_index` of the transaction whose body is `tx_bytes` is a
 * genesis-anchored, Mithril-certified on-chain output, and marshal its
 * `{address, lovelace, datum}` back to the caller.
 *
 * This is a CORE export — present in the default library and the wasm32 build (its
 * verifier composes only Blake2b/Blake2s + minicbor, no feature-gated crypto crate).
 * `certified_root` is
 * the 32-byte certified transaction Merkle root; obtain it ONLY from a
 * genesis-authenticated certificate (see the mithril anchored verify) so a provider
 * cannot inject one. The supplied `tx_bytes` are hashed here, never a
 * provider-supplied hash, so substituted/tampered bytes are rejected as not-included.
 *
 * ## The sizing protocol (allocation-free; caller owns every buffer)
 * The fixed scalars land in `*out`; the variable-length `address` and `datum` bytes
 * go to `address_buf`/`datum_buf`, whose true lengths are reported in
 * `out.address_len`/`out.datum_len`. If EITHER buffer is too small the call writes
 * the full struct (true lengths, no variable bytes) and returns
 * [`SextantStatus::ErrBufferTooSmall`] (`-3`); the caller reads the lengths, resizes,
 * and retries (idempotent). A `(NULL, 0)` pair is a pure sizing probe. There is no
 * free function — on wasm no free callback can cross back in.
 *
 * ## Honest scope
 * A genuine `Ok` proves authentic bytes + certified inclusion + provenance anchored
 * to genesis as of `certified_at`, NOTHING MORE; it is NOT a liveness claim, and
 * `out.spend_status` is always [`SEXTANT_SPEND_NOT_ESTABLISHED`]. Never gate on it.
 *
 * # Safety
 * `tx_bytes` must point to `tx_bytes_len` readable bytes; `proof_hex` to
 * `proof_hex_len` readable bytes; `certified_root` to 32 readable bytes; `out` to a
 * writable [`SextantVerifiedOutput`]. `address_buf`/`datum_buf` must each be null
 * (permitted iff its cap is 0) or point to `address_cap`/`datum_cap` writable bytes.
 * `out_detail` must be null or point to a writable [`SextantErrorDetail`]. All
 * borrows live only for the duration of the call.
 */
int32_t sextant_verify_utxo_read(const uint8_t *tx_bytes,
                                 uintptr_t tx_bytes_len,
                                 uintptr_t out_index,
                                 const uint8_t *proof_hex,
                                 uintptr_t proof_hex_len,
                                 const uint8_t *certified_root,
                                 uint64_t block_number,
                                 SextantVerifiedOutput *out,
                                 uint8_t *address_buf,
                                 uintptr_t address_cap,
                                 uint8_t *datum_buf,
                                 uintptr_t datum_cap,
                                 SextantErrorDetail *out_detail);

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
 * The tip's certified transaction set (when the tip is a `CardanoTransactions`
 * certificate) is surfaced through `out_ct_root` (the 32 RAW bytes of the certified
 * Merkle root, ready to pass straight as the `certified_root` of
 * [`sextant_verify_utxo_read`]), `out_ct_block` (the certified height), and
 * `out_has_ct` (`1` present, `0` absent — root zeroed, block `0`). Because the root
 * is obtainable ONLY from this genesis-authenticated verify, a consumer is
 * physically unable to obtain a certified root without having anchored the chain to
 * genesis. A tip whose certified Merkle root is not 32-byte hex fails CLOSED to
 * [`SextantStatus::MithrilStdMalformedCertJson`] (never a partial `out_ct_root`).
 *
 * # Safety
 * `cert_json_ptrs`/`cert_json_lens` must each point to `count` readable entries, each
 * pointer to its length in readable bytes; `genesis_vkey` to 32 readable bytes;
 * `out_root_hex` and `out_tip_hex` to 64 writable bytes each; `out_length` to a
 * writable `u64`; `out_ct_root` to 32 writable bytes; `out_ct_block` to a writable
 * `u64`; `out_has_ct` to a writable `u8`; `out_detail` must be null or point to a
 * writable [`SextantErrorDetail`].
 */
int32_t sextant_mithril_verify_chain_anchored(const uint8_t *const *cert_json_ptrs,
                                              const uintptr_t *cert_json_lens,
                                              uintptr_t count,
                                              const uint8_t *genesis_vkey,
                                              uint8_t *out_root_hex,
                                              uint8_t *out_tip_hex,
                                              uint64_t *out_length,
                                              uint8_t *out_ct_root,
                                              uint64_t *out_ct_block,
                                              uint8_t *out_has_ct,
                                              SextantErrorDetail *out_detail);
#endif

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
