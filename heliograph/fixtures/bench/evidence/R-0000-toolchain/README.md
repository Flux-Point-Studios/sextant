# R-0000-toolchain — shared build/identity evidence for the M0 RISC Zero executor rows

Shared evidence for run rows R-0001…R-0008 (executor tier, no proving).
Produced by `spikes/risc0-mithril/run-m0.sh` (extends spike S-0001).

- Build container: `risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3`
  (risc0-build v3.0.5 `DEFAULT_DOCKER_TAG`), linux/amd64, Docker Desktop on
  Windows 11 (server 29.1.3), 4 vCPU / 11 GiB VM. NOT `BENCH_HARDWARE` —
  executor-tier context rows only, never threshold-bearing.
- Guest builds: `cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf
  --features mithril` (rustc 1.88.0-dev toolchain `risc0`), twice:
  - `guest-vanilla.elf` — vanilla crates.io `blst` (portable C via
    riscv32-unknown-elf-gcc 13.2.0): the unaccelerated control (§6.2 branch 2).
  - `guest-accel.elf` — `[patch.crates-io]` `risc0/blst` tag
    `v0.3.16-risczero.0` via `risc0-blst-patch.toml`: the accelerated path
    (§6.2 branch 1).
- Host binaries (x86-64, rustc 1.88.0 stable, same container):
  - `hg-m0-runner` — `risc0-zkvm =3.0.5` (`prove` feature) local executor,
    execution only; wraps the user ELF with the v1compat kernel exactly as
    risc0-build v3.0.5 does and records user/total cycles, segments, wall
    time, and the journal.
  - `hg-m0-native` — the native differential (BENCH.md §2.2): sextant
    `90b2672a` `features=["mithril"]` (mithril-stm 0.10.5 + crates.io blst,
    x86 native), same pipeline, same verdict mapping.
- Verdict mapping (journal u32, LE): 0 accepted; 1 JSON parse failure;
  2 NotStandard; 3 MessageMismatch; 4 WeakParameters; 5 ImplausibleAvk;
  6 MalformedAvk; 7 MalformedSignature; 8 InvalidMultiSignature;
  9 content-hash mismatch (BENCH.md §2.1 step 2).
- Files here: `versions.txt` (exact toolchain identities), `elf-identity.txt`
  (ELF SHA-256s + image IDs for both flavors), `fixture-sha256.txt`,
  `tamper-manifest.txt` (single-byte tamper offsets), build logs.

Caveat (ADR-004 D1, same as S-0001): guests built via plain `cargo +risc0
build` inside the canonical builder image, not host-side `cargo risczero
build`; image IDs here are evidence, not canonical registry identities.
