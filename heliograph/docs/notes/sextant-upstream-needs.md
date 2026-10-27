# Sextant upstream need: a `no_std + alloc` build of the default graph

Status: **RESOLVED IN-HOUSE — implemented as Sextant PR #60** (2026-07-14;
Sextant is our own org repo under the delegated build→red-team→merge loop, so
no §9 gate applied). The ask below was drafted for filing and is preserved as
the design record; what landed matches §2a/§3(iii)/§4/§5 verbatim, plus one
finding the draft missed: **the manifest's multi-crate-type lib
(`["lib","cdylib","staticlib"]`) breaks ANY bare-metal dependency build**
(cdylib/staticlib are built even for dependency builds and demand a panic
handler + allocator) — fixed by an rlib-only manifest with the artifacts
pipeline requesting linkables via `cargo rustc --crate-type`. Probe result for
§3: `--features mithril` without std stops at `subtle` (dep graph, not Sextant
source); both zkVM targets ship std in-guest, so the mithril leg rides vendor
std targets (M0 confirms). The ONLY remaining external ask is the
mithril-stm backend seam (§3 option ii — an ask on IOG's Mithril repo, §9-gated,
and possibly moot if blst-C compiles under the vendor toolchains at M0).

All file:line cites verified against sextant @ `a0729fd` (2026-07-14).
Companion analysis: heliograph `docs/notes/sextant-legs.md`.

## 1. Context

Heliograph produces succinct zero-knowledge proofs of Sextant verification
runs: Sextant's verify legs (Mithril certificate chain, Praos header segments,
tx/UTxO inclusion, windowed no-spend, Tier-2 certified set) compiled into a
RISC-V zkVM guest (RISC Zero `riscv32im-risc0-zkvm-elf` or SP1
`riscv64im-succinct-zkvm-elf`), executing over untrusted input bytes and
committing the verdict to a public journal that any chain or auditor can check
for cents. Sextant is consumed as a pinned upstream dependency — never a fork,
never a vendored copy. Sextant's sans-io constitution (no sockets, threads, or
clock in `src/`; bytes in, verdict out, every trust anchor an explicit input —
README.md:58-66) is already exactly the shape a guest needs. The only gap
between the default graph and a guest target is `std`, and the gap is small.

## 2. The ask: gate `std`, make the default graph `no_std + alloc`

This is the entire code ask. Mechanical, zero verify-path logic change:
`default = ["std"]`, `#![cfg_attr(not(feature = "std"), no_std)]`,
`extern crate alloc`. The complete blocker list (grep-verified, `src/` @
`a0729fd`):

1. **`impl std::error::Error` → `impl core::error::Error`.**
   `core::error::Error` is stable since Rust 1.81 and the crate is edition
   2024 (Cargo.toml:4), so no MSRV concern. Sites: chain.rs:62,
   header.rs:133, vrf.rs:69, kes.rs:66, inclusion.rs:73, utxo.rs:237,
   window.rs:65, setfollow.rs:58, ancillary.rs:105, mithril.rs:259, :356,
   :445, :645.
2. **`use std::collections::…` → `alloc::collections`.** Sites: utxo.rs:36
   (BTreeSet), utxoset.rs:37 (BTreeSet, VecDeque), inclusion.rs:27 (VecDeque),
   effects.rs:20 (BTreeSet), follow.rs:84 (BTreeMap, VecDeque), ancillary.rs:23
   (BTreeMap), mithril.rs:56 (BTreeMap).
3. **Gate `pub mod ffi` (lib.rs:11) behind the `std` feature.** `std::ptr` /
   `std::slice` (ffi.rs:20-21) are core-swappable, but the panic guard
   (`std::panic::catch_unwind`, ffi.rs:279-292) genuinely needs std unwinding
   — and a guest never builds the FFI at all: the zkVM journal replaces the
   C ABI as the verdict marshalling surface. The module already cfg-degrades
   for `wasm32` (ffi.rs:288-292), so this is one gate, not a redesign.
4. **Nothing else.** Remaining `String`/`Vec`/`format!` use is
   alloc-satisfiable (the one verify-path formatting is the MMR range-leaf key
   `format!` at inclusion.rs:335 — deterministic, alloc-only). `std::fs`
   appears only inside `#[cfg(test)]` modules (window.rs:570,
   setfollow.rs:91-119, follow.rs:688).

The dependency graph is already configured for this (Cargo.toml:46-67):
`minicbor` (alloc), `amaru-curve25519-dalek` (`default-features = false,
u64_backend, alloc`), `sha2`/`blake2` 0.9 (`default-features = false`),
`serde`/`serde_json` (`default-features = false, alloc`), `chrono`
(mithril-only, `default-features = false, serde, alloc`).

Result: the default graph — header/VRF/opcert/KES/nonce, inclusion, UTxO read,
windowed watch, Tier-2 certified set — builds for bare-metal RISC-V with zero
algorithmic change.

## 3. The `mithril` feature: status report, not a code ask

`mithril = ["dep:chrono", "dep:mithril-stm"]` (Cargo.toml:41). `mithril-stm`
0.10.5 resolves `blst` 0.3.16 (C, built via `cc`) and `rayon` 1.12
unconditionally (Cargo.lock:180-182, :1182-1184, :1556-1558) — neither builds
for a bare no_std RISC-V target. The realistic paths, none of which need
Sextant changes beyond §2:

- **(i) Vendor-patched blst — works today on the RISC Zero path, zero Sextant
  changes.** `mithril-stm` pins `blst` 0.3.16 (`portable`); RISC Zero ships
  fork tag `v0.3.16-risczero.0` — an exact version match. A single
  `[patch.crates-io]` entry in heliograph's guest workspace substitutes the
  accelerated fork; heliograph owns that integration and its residual risks
  (rayon-in-guest behavior, `portable`-feature interplay). Nothing lands in
  Sextant's tree.
- **(ii) A pure-Rust STM backend upstream in mithril-stm** (zkcrypto
  `bls12_381`: pure Rust, no_std, accelerated forks exist on both zkVMs).
  Required for the SP1 path (SP1 patches pure-Rust crates only; no C).
  This is an ask on `input-output-hk/mithril`, not on Sextant — heliograph
  will raise it in its Mithril-consumer note.
- **(iii) Sextant-side — verified: nothing in `src/mithril.rs` itself blocks
  no_std.** Its own std surface is exactly the BTreeMap import (mithril.rs:56)
  and the four `std::error::Error` impls (mithril.rs:259, :356, :445, :645),
  both covered by §2. Content hashing, the chain walk, AVK binding, genesis
  Ed25519 (Sextant's own `src/ed25519.rs`), and the DoS bounds
  (`guard_stm_bounds`, mithril.rs:564-610) are pure Rust. `chrono` in the
  configured build (`default-features = false, serde, alloc` — `clock` off)
  is documented no_std; only RFC3339 deserialize and `timestamp_nanos_opt`
  are consumed (mithril.rs:58, :762-776, :896-899). So the day a
  guest-capable `mithril-stm` exists via (i) or (ii), `--features mithril`
  should build in-guest with no further Sextant work.

If (ii) stalls upstream: the entire mithril-stm surface Sextant touches is
four types and one verify call (mithril.rs:59-62, :507-522), so a Sextant-side
backend seam would be a small, separate, differentially-tested PR — explicitly
NOT part of this ask.

## 4. Deterministic inputs and no clock — already true; stating for the record

- **Input encoding: no ask.** Every entry point takes raw bytes (block CBOR,
  certificate JSON, hex(JSON) proofs) with compiled-in DoS caps
  (`MAX_PROOF_HEX` inclusion.rs:36; `guard_stm_bounds` mithril.rs:564-610).
  Guests will journal Sextant's own commitments (certificate `compute_hash`,
  `certified_root`, `eta0`, the Tier-2 set `fingerprint`).
- **serde_json on the cert/proof parse paths** (mithril.rs:104-105, :565-580)
  is the no_std configuration, pure Rust, deterministic with a compiled-in
  recursion bound — fine in-guest; no replacement requested.
- **No clock.** A grep for `std::time` across `src/` @ `a0729fd` returns
  nothing; freshness is caller-supplied data by design (window.rs carries
  deliberately no `now`), matching the sans-io claim in
  `docs/notes/sextant-legs.md` §2.1 and README.md:58-66. Confirmed; no ask.

## 5. Proposed acceptance test

One harness leg beside the existing wasm32 leg (.woodpecker/harness.yml:9):

```sh
rustup target add riscv32im-unknown-none-elf
cargo build --release --no-default-features --target riscv32im-unknown-none-elf
```

Green means the default graph is guest-clean, vendor-neutrally: both vendor
targets (`riscv32im-risc0-zkvm-elf`, `riscv64im-succinct-zkvm-elf`) require
vendor toolchains, and the bare tier-2 rustc target is the neutral proxy that
catches every future std regression. `--features mithril` stays out of this
leg until §3(i)/(ii) resolves the mithril-stm dependency story.

## 6. Explicitly NOT asked

- No vendored or forked copies of Sextant — heliograph consumes a pinned
  upstream dependency.
- No public API changes: same functions, types, verdicts, error enums — only
  import paths and feature gating move.
- No trust-model or verdict-semantics changes; no new claim semantics.
- No zkVM vendor dependencies in Sextant's tree (`[patch.crates-io]` lives in
  heliograph's guest workspace).
- No mithril-stm replacement inside Sextant (§3(ii) belongs to Mithril;
  §3(iii) is a verification statement, not a change).
