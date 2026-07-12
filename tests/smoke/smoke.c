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

    printf("smoke: ok (abi=%u verify_segment rc=%d index=%lld header rc=%d msg=\"%s\")\n",
           sextant_abi_version(), rc, (long long)detail.index, rc_hdr, msg);
    return 0;
}
