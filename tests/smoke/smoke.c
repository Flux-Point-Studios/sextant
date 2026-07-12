/* CI-only C smoke test: link the shipped static library through the committed C
 * header and drive the boundary. It proves, on the Linux artifact target, that
 * (a) libsextant.a links, (b) the exported #[no_mangle] symbols survived linker
 * dead-strip (a stripped symbol becomes a link error here, not a silent gap),
 * (c) the header matches the linked ABI, and (d) the negative path returns a
 * status code plus the offending block index across a real C boundary.
 *
 * Compiled without -DSEXTANT_MITHRIL, so it also proves the default static
 * library needs no mithril/blst symbol. Built and run in .woodpecker/artifacts.yml
 * — never the local harness, because a Windows-MSVC toolchain emits sextant.lib
 * (not libsextant.a) and cannot link it with cc.
 *
 * CHECK (not assert) so the test holds even if compiled with -DNDEBUG. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sextant.h"
#include "utxo_fixture.h"

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "smoke: FAILED: %s\n", #cond);                     \
            return 1;                                                          \
        }                                                                      \
    } while (0)

int main(void) {
    /* The header the consumer compiled against must match the linked ABI. */
    CHECK(sextant_abi_version() == SEXTANT_ABI_VERSION);

    /* A deliberately invalid two-block segment (two garbage blobs). The verifier
     * must reject with a non-zero status and name the offending block — never
     * falsely accept. */
    const uint8_t b0[] = {0x82, 0x00, 0x01, 0x02};
    const uint8_t b1[] = {0x00};
    const uint8_t *ptrs[2] = {b0, b1};
    const size_t lens[2] = {sizeof b0, sizeof b1};
    uint8_t eta0[32];
    memset(eta0, 0, sizeof eta0);

    SextantErrorDetail detail = {0, 0};
    int32_t rc = sextant_verify_segment(ptrs, lens, 2, eta0, &detail);
    CHECK(rc != 0);           /* garbage must not be accepted */
    CHECK(detail.index >= 0); /* the offending block must be identified */

    /* The null-pointer contract returns the boundary error, not a crash. */
    CHECK(sextant_verify_segment(NULL, lens, 2, eta0, &detail) == ErrNullPointer);

    /* Link-reference the remaining core exports so a dead-stripped symbol is a
     * link error here rather than a silent gap. */
    SextantHeaderView view;
    int32_t rc_hdr = sextant_header_decode(b0, sizeof b0, &view, &detail);
    CHECK(rc_hdr != 0); /* garbage is not a valid header */

    char msg[64];
    size_t n = sextant_status_message(rc, (uint8_t *)msg, sizeof msg);
    CHECK(n > 0);

    /* ---- The core UTxO-read consumer: the C analogue of the Rust
     * examples/verified_read_gate, over the same real preprod order. Compiled
     * WITHOUT -DSEXTANT_MITHRIL, so it exercises the core export against the default
     * no-blst static library. The certified root is a committed fixture here; the
     * mithril compose that DERIVES it from a genesis-anchored verify is proven in
     * tests/ffi.rs under --all-features (smoke.c can't include the mithril proto). */
    SextantVerifiedOutput vout;
    SextantErrorDetail vdetail = {0, 0};

    /* Sizing probe: NULL buffers, caps 0 -> ErrBufferTooSmall with the true lengths
     * (and nothing copied). */
    int32_t rc_size = sextant_verify_utxo_read(
        UTXO_TX_BODY, sizeof UTXO_TX_BODY, 0, UTXO_PROOF_HEX, sizeof UTXO_PROOF_HEX,
        UTXO_CERTIFIED_ROOT, UTXO_BLOCK_NUMBER, &vout, NULL, 0, NULL, 0, &vdetail);
    CHECK(rc_size == ErrBufferTooSmall);
    CHECK(vout.address_len > 0);
    CHECK(vout.datum_len == sizeof UTXO_EXPECTED_DATUM);

    /* Resize to the reported lengths and retry -> Ok, with the authentic fields. */
    uint8_t addr_buf[128];
    uint8_t datum_buf[256];
    CHECK(vout.address_len <= sizeof addr_buf);
    CHECK(vout.datum_len <= sizeof datum_buf);
    int32_t rc_ok = sextant_verify_utxo_read(
        UTXO_TX_BODY, sizeof UTXO_TX_BODY, 0, UTXO_PROOF_HEX, sizeof UTXO_PROOF_HEX,
        UTXO_CERTIFIED_ROOT, UTXO_BLOCK_NUMBER, &vout, addr_buf, sizeof addr_buf,
        datum_buf, sizeof datum_buf, &vdetail);
    CHECK(rc_ok == Ok);
    CHECK(vout.lovelace >= UTXO_EXPECTED_LOVELACE);
    CHECK(vout.certified_at == UTXO_BLOCK_NUMBER);
    CHECK(vout.datum_kind == 2); /* an inline datum */
    CHECK(vout.datum_len == sizeof UTXO_EXPECTED_DATUM);
    CHECK(memcmp(datum_buf, UTXO_EXPECTED_DATUM, vout.datum_len) == 0);
    CHECK(vout.spend_status == SEXTANT_SPEND_NOT_ESTABLISHED);

    /* Spoof-refuse: flip output 0's coin byte so the body no longer hashes to the
     * certified leaf -> rejected as not-included (400), never a false accept. */
    uint8_t spoof[sizeof UTXO_TX_BODY];
    memcpy(spoof, UTXO_TX_BODY, sizeof UTXO_TX_BODY);
    spoof[UTXO_TAMPER_COIN_OFFSET] ^= 0x01;
    int32_t rc_spoof = sextant_verify_utxo_read(
        spoof, sizeof spoof, 0, UTXO_PROOF_HEX, sizeof UTXO_PROOF_HEX,
        UTXO_CERTIFIED_ROOT, UTXO_BLOCK_NUMBER, &vout, addr_buf, sizeof addr_buf,
        datum_buf, sizeof datum_buf, &vdetail);
    CHECK(rc_spoof == UtxoInclusionNotIncluded);

    /* Null guard: a null tx pointer is a caller error, not a crash. */
    CHECK(sextant_verify_utxo_read(NULL, sizeof UTXO_TX_BODY, 0, UTXO_PROOF_HEX,
                                   sizeof UTXO_PROOF_HEX, UTXO_CERTIFIED_ROOT,
                                   UTXO_BLOCK_NUMBER, &vout, addr_buf, sizeof addr_buf,
                                   datum_buf, sizeof datum_buf, &vdetail) == ErrNullPointer);

    /* ---- The windowed watch-verdict export: garbage in must yield a STALLED
     * non-answer across the C boundary, NEVER a false no-spend, and the fixed
     * SextantWatchVerdict crosses the boundary. The authentic no-spend /
     * spend-observed / window-too-short paths are proven in tests/window.rs's FFI
     * module (they load the 22-block preprod window, too large to embed here). */
    uint8_t wtxid[32];
    memset(wtxid, 0, sizeof wtxid);
    SextantWatchVerdict wv;
    memset(&wv, 0, sizeof wv);
    const uint8_t *wptrs[1] = {b0};
    const size_t wlens[1] = {sizeof b0};

    /* One garbage block: the header segment fails to verify -> STALLED, never a
     * no-spend. rc is Ok because the verdict lives in the struct, not the code. */
    int32_t rc_w = sextant_verify_watched_window(wptrs, wlens, 1, eta0, 4927469, wtxid, 0,
                                                 4921937, 0, 100000, &wv);
    CHECK(rc_w == Ok);
    CHECK(wv.kind == SEXTANT_WATCH_STALLED);
    CHECK(wv.kind != SEXTANT_WATCH_NO_SPEND_OBSERVED);

    /* Boundary guards: zero count is empty input; a null out or null block list is a
     * caller error, not a crash. */
    CHECK(sextant_verify_watched_window(wptrs, wlens, 0, eta0, 0, wtxid, 0, 0, 0, 0, &wv) ==
          ErrEmptyInput);
    CHECK(sextant_verify_watched_window(wptrs, wlens, 1, eta0, 0, wtxid, 0, 0, 0, 0, NULL) ==
          ErrNullPointer);
    CHECK(sextant_verify_watched_window(NULL, wlens, 1, eta0, 0, wtxid, 0, 0, 0, 0, &wv) ==
          ErrNullPointer);

    printf("smoke: ok (abi=%u verify_segment rc=%d index=%lld header rc=%d msg=\"%s\" "
           "utxo lovelace=%llu datum_len=%zu spoof_rc=%d watch_kind=%u)\n",
           sextant_abi_version(), rc, (long long)detail.index, rc_hdr, msg,
           (unsigned long long)vout.lovelace, vout.datum_len, rc_spoof, wv.kind);
    return 0;
}
