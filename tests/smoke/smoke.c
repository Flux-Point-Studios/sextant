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

/* Whether every one of the `n` bytes at `p` is `value`: a sentinel survives a call. */
static int all_bytes_are(const uint8_t *p, size_t n, uint8_t value) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != value) {
            return 0;
        }
    }
    return 1;
}

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

    /* ---- The core UTxO-read export, over the real preprod order the Rust
     * examples/verified_read_gate reads. Compiled WITHOUT -DSEXTANT_MITHRIL, so it
     * exercises the core export against the default no-blst static library. The order
     * is included in the certified set and still refused: an included body establishes
     * no output (412), so nothing is marshalled - the sentinel bytes in the struct and
     * both buffers survive, a sizing probe included. */
    SextantVerifiedOutput vout;
    SextantErrorDetail vdetail = {0, 0};
    uint8_t addr_buf[128];
    uint8_t datum_buf[256];
    memset(&vout, 0x5a, sizeof vout);
    memset(addr_buf, 0xaa, sizeof addr_buf);
    memset(datum_buf, 0xaa, sizeof datum_buf);

    int32_t rc_size = sextant_verify_utxo_read(
        UTXO_TX_BODY, sizeof UTXO_TX_BODY, 0, UTXO_PROOF_HEX, sizeof UTXO_PROOF_HEX,
        UTXO_CERTIFIED_ROOT, UTXO_BLOCK_NUMBER, &vout, NULL, 0, NULL, 0, &vdetail);
    CHECK(rc_size == UtxoValidityNotEstablished);
    int32_t rc_read = sextant_verify_utxo_read(
        UTXO_TX_BODY, sizeof UTXO_TX_BODY, 0, UTXO_PROOF_HEX, sizeof UTXO_PROOF_HEX,
        UTXO_CERTIFIED_ROOT, UTXO_BLOCK_NUMBER, &vout, addr_buf, sizeof addr_buf,
        datum_buf, sizeof datum_buf, &vdetail);
    CHECK(rc_read == UtxoValidityNotEstablished);
    CHECK(vdetail.index == -1 && vdetail.detail == 0);
    CHECK(all_bytes_are((const uint8_t *)&vout, sizeof vout, 0x5a));
    CHECK(all_bytes_are(addr_buf, sizeof addr_buf, 0xaa));
    CHECK(all_bytes_are(datum_buf, sizeof datum_buf, 0xaa));

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
    CHECK(all_bytes_are((const uint8_t *)&vout, sizeof vout, 0x5a));

    /* ---- The block-bound created-output export: a garbage block refuses in the 420
     * band, its decode leaf in the detail, with the struct and buffers untouched; null
     * and empty inputs are caller errors. The authentic reads over a real mainnet block
     * are proven in tests/created_output.rs's FFI module (the block is too large to
     * embed here). */
    SextantCreatedOutput cout;
    SextantErrorDetail cdetail = {0, 0};
    uint8_t expected_hash[32];
    memset(expected_hash, 0, sizeof expected_hash);
    memset(&cout, 0x5a, sizeof cout);
    int32_t rc_created =
        sextant_verify_created_output(b0, sizeof b0, expected_hash, expected_hash, 0, &cout,
                                      addr_buf, sizeof addr_buf, datum_buf,
                                      sizeof datum_buf, &cdetail);
    CHECK(rc_created == CreatedDecode);
    CHECK(cdetail.index == -1 && cdetail.detail == DecodeUnsupportedEra);
    CHECK(all_bytes_are((const uint8_t *)&cout, sizeof cout, 0x5a));
    CHECK(all_bytes_are(addr_buf, sizeof addr_buf, 0xaa));
    CHECK(sextant_verify_created_output(NULL, sizeof b0, expected_hash, expected_hash, 0,
                                        &cout, NULL, 0, NULL, 0, &cdetail) == ErrNullPointer);
    CHECK(sextant_verify_created_output(b0, sizeof b0, expected_hash, expected_hash, 0, NULL,
                                        NULL, 0, NULL, 0, &cdetail) == ErrNullPointer);
    CHECK(sextant_verify_created_output(b0, 0, expected_hash, expected_hash, 0, &cout, NULL,
                                        0, NULL, 0, &cdetail) == ErrEmptyInput);

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

    /* ---- The live follower (F5): link-reference every opaque-handle export so a
     * dead-stripped symbol is a link error here, and drive the boundary contract on
     * a fresh handle (the full 22-block replay is proven in tests/follower_ffi.rs).
     * A garbage block is refused (never accepted), the empty follower stalls (never a
     * no-spend), and the handle is destroyed. */
    SextantFollower *f =
        sextant_follower_new(wtxid, 0, 4927469, 4921937, 300, 127958400, 432000);
    CHECK(f != NULL);
    CHECK(sextant_follower_new(NULL, 0, 0, 0, 0, 0, 0) == NULL);
    CHECK(sextant_follower_supply_next_eta0(f, 300, eta0) == Ok);

    /* A garbage block does not decode -> a POSITIVE refusal code, never accepted (0)
     * and never a boundary error (<0). */
    uint64_t appended_at = 0;
    int32_t rc_a = sextant_follower_append(f, b0, sizeof b0, &appended_at);
    CHECK(rc_a == SEXTANT_WATCH_STALL_BROKEN_SEGMENT);

    /* An empty follower cannot answer -> STALLED, never a false no-spend. */
    SextantWatchVerdict fv;
    memset(&fv, 0, sizeof fv);
    CHECK(sextant_follower_verdict(f, 0, 100000, &fv) == Ok);
    CHECK(fv.kind == SEXTANT_WATCH_STALLED);
    CHECK(fv.kind != SEXTANT_WATCH_NO_SPEND_OBSERVED);

    /* Re-anchor holding the certified height advances (no proof, no observed spend). */
    uint8_t root[32];
    memset(root, 0, sizeof root);
    CHECK(sextant_follower_re_anchor(f, 4927469, root, NULL, 0) ==
          SEXTANT_FOLLOWER_REANCHOR_ADVANCED);

    /* A rollback to an unretained point poisons the follower fail-closed. */
    uint64_t rb_tip = 0;
    CHECK(sextant_follower_rollback(f, 0, wtxid, &rb_tip) ==
          SEXTANT_FOLLOWER_ROLLBACK_BEYOND_WINDOW);

    /* Null guards, then destroy (and a null destroy is a no-op). */
    CHECK(sextant_follower_append(NULL, b0, sizeof b0, &appended_at) == ErrNullPointer);
    CHECK(sextant_follower_verdict(f, 0, 0, NULL) == ErrNullPointer);
    sextant_follower_destroy(f);
    sextant_follower_destroy(NULL);

    printf("smoke: ok (abi=%u verify_segment rc=%d index=%lld header rc=%d msg=\"%s\" "
           "utxo_rc=%d spoof_rc=%d created_rc=%d watch_kind=%u follow_rc=%d)\n",
           sextant_abi_version(), rc, (long long)detail.index, rc_hdr, msg, rc_read,
           rc_spoof, rc_created, wv.kind, rc_a);
    return 0;
}
