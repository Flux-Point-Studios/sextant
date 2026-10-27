# S-0001 — RISC Zero × Sextant mithril compile spike

**Question (BENCH.md §6.2, §8.6; ADR-001 "the crux"):** does Sextant's Mithril
STM leg — `mithril-stm` 0.10.5 → `blst` 0.3.16 C + `rayon` — compile for the
RISC Zero guest target `riscv32im-risc0-zkvm-elf`, and does the vendor's
accelerated blst fork (`v0.3.16-risczero.0`) slot in via a single
`[patch.crates-io]` line with zero Sextant changes?

**Answer: YES — all three bisect layers compile and link.** Compile-only spike;
no proving, no host run (BENCH.md branches 1–2 of §6.2 are both *buildable*;
runtime behavior is M0 proper).

## Outcome per bisect layer

Guest: `guest/` — `env::read()`s certificate JSON bytes, runs
`sextant::mithril::Certificate::from_json` + `verify_standard`, `env::commit()`s
a `u32` verdict code (codes documented in `guest/src/main.rs`). Sextant consumed
as the pinned git dependency `90b2672aa3ee7a957ecaee0e33026337825efafa`, never
vendored (HANDOFF §0).

| layer | configuration | result | user ELF bytes |
|---|---|---|---|
| 1 | `sextant` `default-features = false` only | **compiles** (52s cold) | 341,596 |
| 2 | + `features = ["mithril"]` — vanilla `blst` 0.3.16 `portable` C, cross-compiled by `riscv32-unknown-elf-gcc` 13.2.0 | **compiles + links** — the *unaccelerated control* (BENCH.md §6.2 branch 2) is buildable | 1,288,828 |
| 3 | + `[patch.crates-io] blst = risc0/blst tag v0.3.16-risczero.0` (via `--config risc0-blst-patch.toml`) | **compiles + links** — the *accelerated path* (branch 1); pulls `risc0-bigint2` 1.4.13; ELF shrinks vs layer 2 (C field arithmetic remapped onto bigint2 384-bit ops) | 1,199,904 |

`rayon` 1.12.0 / `rayon-core` 1.13.0 (mithril-stm's unconditional dep) and
`chrono` 0.4.45 compile **and link** for the target — the risc0 toolchain ships
`std` for the guest, so `rayon`'s thread machinery type-checks and links. No
rayon-shedding feature was needed at compile time. Whether mithril-stm's
*verify* path spawns threads at runtime (a single-threaded guest would trap) is
deliberately out of scope here and is the first M0-proper question.

## Layer-3 identity (the M0-relevant configuration)

Derived exactly as risc0-build v3.0.5 does (`imageid/`: user ELF + v1compat
kernel → `ProgramBinary` → `compute_image_id`):

| artifact | value |
|---|---|
| user ELF SHA-256 | `15735607ba22a2cfad3478ddf4bb954471e7e5143c63948a1ba55b8a9d573329` |
| combined (user+kernel) SHA-256 | `975382e8314f445d35bbd4c9a400b9b65ca4ed0e56cd5bc13e3517f36b9ee99f` |
| image ID | `5515edd69e5077b4044cd432a54d39833b52a2a270da2ab2b65181ba990e3080` |

Two independent fresh-container runs (`build.sh`, clean target dirs) produced
**byte-identical user ELF, combined binary, and image ID** — a same-host
reproducibility check (ADR-004 T-A6-1 proper needs divergent-OS/arch runners;
this is necessary-not-sufficient evidence).

**Canonicality caveat (ADR-004 D1):** builds ran *inside* the vendor's own
guest-builder container (docker-in-docker is unavailable), replicating
risc0-build v3.0.5's exact environment (`cargo_command_internal` +
`encode_rust_flags`: `CARGO_ENCODED_RUSTFLAGS`, `CC_riscv32im_risc0_zkvm_elf`,
`CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib"`,
`RISC0_FEATURE_bigint2`). This is compile evidence, not a canonical registry
image ID — M0 proper re-derives identity via host-side `cargo risczero build`
(the docker pipeline) per ADR-004.

## Version pins (ADR-004 record)

| component | pin |
|---|---|
| build container | `risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3` (Ubuntu 20.04.6; risc0-build v3.0.5 `DEFAULT_DOCKER_TAG`) |
| guest rustc / cargo | `rustc 1.88.0-dev (de85b1d3d 2025-06-26)` / `cargo 1.88.0-dev (873a06493)` (rustup toolchain `risc0`) |
| C cross-compiler | `riscv32-unknown-elf-gcc (gc891d8dc23e) 13.2.0` |
| `risc0-zkvm` (guest dep) | `=3.0.5`, `default-features = false, features = ["std"]` |
| `risc0-bigint2` | 1.4.13 (pulled by the blst fork) |
| `blst` (layer 3) | `git+https://github.com/risc0/blst?tag=v0.3.16-risczero.0#7d1fc3e6d8cf0d52a291f52455233bf8d6432ed2` |
| `mithril-stm` | 0.10.5 (`default-features = false, features = ["num-integer-backend"]`, via sextant) |
| `sextant` | `git rev 90b2672aa3ee7a957ecaee0e33026337825efafa`, `default-features = false` (+`mithril` in layers 2–3) |
| key transitives | rayon 1.12.0, rayon-core 1.13.0, chrono 0.4.45, serde_json 1.0.150, subtle 2.6.1, getrandom 0.2.17, num-bigint 0.4.8 |
| imageid helper | `risc0-binfmt =3.0.4`, `risc0-zkos-v1compat =2.2.2` |
| host | Windows 11 / Docker Desktop, server 29.1.3, linux/amd64 |

`guest/Cargo.lock` (committed) is the layer-3 resolution — the M0-relevant
configuration. Layers 1–2 re-resolve from the same manifest without the patch
config.

## The one obstacle hit, and its fix

Fresh resolution against the pinned toolchain trips **MSRV bitrot**, not any
risc0/blst/rayon incompatibility: latest `enum-ordinalize` 4.4.1 requires
rustc 1.89 and `ruint` 1.19.0 requires 1.90, vs the toolchain's 1.88.0-dev.
Fixed with `rust-version = "1.88.0"` + `resolver = "3"` in both crates
(MSRV-aware resolution) — no `--precise` pin chain, no version overrides.

## Reproduce

```
./build.sh   # from this directory; Docker required (linux/amd64)
```

Runs all three layers plus the image-ID derivation in a fresh pull of the
digest-pinned builder container.

---

# M0 executor tier (extends S-0001; run rows R-0001…R-0008)

`run-m0.sh` drives the execution-only matrix {F-PP1, F-MN1} ×
{blst-vanilla, blst-risczero-fork} × {golden, tampered} in the same pinned
container: instrumented guest (per-stage `env::cycle_count()` split on stderr,
journal = u32 verdict code), host executor runner (`runner/`,
`risc0-zkvm =3.0.5` `prove`-feature local `ExecutorImpl` — the engine
`default_executor()`'s LocalProver wraps, called directly because
`SessionInfo` drops `total_cycles`), and the native differential (`native/`,
sextant `90b2672` `features=["mithril"]`, identical pipeline + verdict
mapping). Verdict codes: 0 accept; 1 JSON parse failure; 2–8 `StandardError`
variants in declaration order; 9 content-hash mismatch (BENCH.md §2.1 step 2).
Evidence: `fixtures/bench/evidence/R-000{1..8}/` + shared
`R-0000-toolchain/` (versions, ELF identities, tamper manifest, row summary).

**Runtime finding (the S-0001 open question).** mithril-stm 0.10.5 never
calls rayon in library code — its `src/` mentions `par_iter` only inside
doc-comment examples, so rayon-core never initializes in-guest. The thread
machinery that *does* run on the verify path is `blst`'s Rust-binding worker
pool: `std::thread::Builder::spawn` is `Unsupported` on
`riscv32im-risc0-zkvm-elf`, surfacing first as a disabled `sys_getenv`
(std reads `RUST_MIN_STACK` inside `spawn`) and then as `threadpool-1.8.1`'s
`unwrap` panic. Two additive guest-manifest features fix it with zero
Sextant/mithril-stm changes: `risc0-zkvm-platform` `sys-getenv` and `blst`
`no-threads` (blst's documented wasm/serial path). No upstream ask needed.

**Headline executor numbers** (full table in
`fixtures/bench/evidence/R-0000-toolchain/rows-summary.txt`): F-MN1 golden
accepts at 930.2M user cycles (accelerated fork, 965 segments, 22.6 s
executor wall) vs 2,533.6M (vanilla portable C) — a 2.77× verify-stage delta;
F-PP1 51.7M vs 197.2M (3.88×). All eight rows differential-match native, and
both tamper rows journal verdict 9 at the content-hash gate
(`compute_hash` covers `multi_signature`, so the signature tamper flips the
hash before `verify_standard` runs — matching native exactly).
