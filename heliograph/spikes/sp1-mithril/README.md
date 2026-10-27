# S-0002 — SP1 guest compile bisect (Sextant `mithril` leg)

The SP1 arm of the M0 compile question (BENCH.md §6.1, ADR-001 context): does
Sextant's Mithril standard-certificate verification **compile** to an SP1 guest
ELF? The guest (`src/main.rs`) reads certificate JSON via `sp1_zkvm::io`, runs
`sextant::mithril::Certificate::from_json` → content-hash recompute →
`verify_standard`, and commits a `u32` verdict. `cargo prove build` producing
the ELF is the win condition; nothing is proven or executed here.

## Reproduction

`./build.sh` from Git Bash on the Windows host (Docker Desktop running). It
reuses the named container `hg-sp1-spike` (`rust:1.93-bookworm`) with named
volumes for the cargo registry and `/root/.sp1`, installs the SP1 toolchain via
`sp1up` and Debian's `gcc-riscv64-unknown-elf`, then runs the three bisect
layers (purging blst's build cache between mithril layers so the compiler
choice is exercised, not replayed). Logs land in `logs/` (untracked); curated
evidence is committed at `fixtures/bench/evidence/S-0002/`.

## Outcome (2026-07-14) — mithril guest ELF COMPILES

| layer | configuration | result |
|---|---|---|
| 1 | sextant `default-features = false` | **compiles** (30 s cold); ELF sha256 `0db3a6e3…7435977` |
| 2 | + `mithril`, stock toolchain | **fails in `blst 0.3.16`'s build script**: cc-rs finds no compiler for `riscv64im-succinct-zkvm-elf`, falls back to host x86-64 `cc` with `-march=rv64im -mabi=lp64 … -D__BLST_NO_ASM__ -D__BLST_PORTABLE__` → `cc: error: unrecognized argument in option '-mabi=lp64'`. The **only** failing crate — rayon-core, crossbeam, subtle, getrandom 0.2.17, num-bigint, ff, chrono all compile for the SP1 std target |
| 3 | + `mithril`, `CC_riscv64im_succinct_zkvm_elf=riscv64-unknown-elf-gcc` (Debian gcc 12.2.0) | **compiles and links**: ELF sha256 `6aae24ad…6a0a671` (1.4 MB, 39 `blst_*` text symbols); vkey `0x004c3360d58ac7e46b33b44095f81524c3aada3eb4433235dc8b693cd98f5f7d`; rebuild after cache purge → identical sha256 |

The recon's expected hard wall (sp1.md §2: blst "cannot ride SP1's patch
mechanism", pure-Rust backend seam required) is narrower than predicted: the
wall is *only* the missing C cross-compiler, and a stock Debian bare-metal
RISC-V gcc clears it. mithril-stm's rayon does not block compilation.

## M0 executor extension (2026-07-14)

The guest now carries SP1 `cycle-tracker-report` markers around the three
stages (`read-input`, `parse-content-hash`, `verify-standard`) and commits the
documented verdict mapping: `0` accepted, `1` parse error, `2` content-hash
mismatch, `3` `verify_standard` rejection. `runner/` is the host-side (x86,
in-container) executor harness: `sp1-sdk`'s `ProverClient::from_env()` +
`client.execute(elf, stdin)` — execution only, no proving — which reports
`total_instruction_count` plus the cycle-tracker spans, and differentials the
guest verdict against native Sextant (`mithril-stm` 0.10.5 + `blst`) computed
in the same process with the same mapping:

```
sp1-mithril-runner <elf> <fixture.json> golden|tampered <out-dir>
```

`tampered` flips one byte inside the `multi_signature` hex value (16 bytes
past its opening quote, remapped to a different hex digit) — Sextant's
`compute_hash` covers the `multi_signature` string (mithril.rs:184), so the
expected journaled rejection is verdict `2`, on guest and native alike.
Executor evidence: `fixtures/bench/evidence/R-SP1-E{1..4}/`.

### Executor outcome (2026-07-15) — all four rows differential-green

| run | fixture | variant | guest == native | RV64IM instructions | exec wall |
|---|---|---|---|---|---|
| R-SP1-E1 | F-PP1 | golden | 0 == 0 | 182,937,047 | 5.4 s |
| R-SP1-E2 | F-PP1 | tampered @2438 | 2 == 2 | 480,102 | 0.4 s |
| R-SP1-E3 | F-MN1 | golden | 0 == 0 | 2,374,163,854 | 44.9 s |
| R-SP1-E4 | F-MN1 | tampered @13724 | 2 == 2 | 8,860,600 | 0.4 s |

Stage split (profiled portable executor; identical instruction totals and
public values as the native-child executor): F-MN1 golden = read-input 363 /
parse-content-hash 8,823,919 / verify-standard 2,365,302,455 / other ~37k.

Two runtime walls, both cleared: (1) SP1 v6's native child executor lives in
`/dev/shm` — Docker's default 64 MB shm SIGBUSes it; the container needs
`--shm-size` of several GB. (2) blst's Rust bindings build a `threadpool`
`ThreadPool` inside `verify_standard`; SP1 std's `thread::spawn` returns
`Unsupported`, so the guest panicked (exit code 1, empty public values) until
blst's `no-threads` feature was enabled via graph unification. rayon —
mithril-stm's unconditional dependency — never spawned: 0.10.5 uses rayon in
doc examples only, so its runtime thread behavior was never exercised.

## What compiling does NOT establish (M0-proper work)

- **Runs/proves.** Untested here: rayon will try to spawn std threads and
  `blst` C runs as plain RV64IM guest code (zero SP1 syscall acceleration —
  the software-pairing cycle count is exactly what M0 measures). First
  execution may still fail at runtime; that is a run question, not a compile
  question.
- **Canonical identity.** This is a container build, not
  `cargo prove build --docker` (ADR-004 D1 non-canonical). The pinned SP1
  build image must be checked for — and, if absent, extended with — a RISC-V C
  cross-compiler before a citable vkey exists; the cross-gcc version then
  becomes a `build-recipe.toml` pin (it shapes the ELF bytes).
- **Semantics of gcc-compiled C under the prover.** The `-march=rv64im
  -mabi=lp64` flags match the target, but vendor-blessed support for foreign
  C objects in guests should be confirmed upstream before this path carries a
  threshold-bearing row (vs. the sp1-patches/bls12_381 pure-Rust seam, which
  remains the vendor-documented primary).
