# Sextant

**A read-path verifying client for Cardano — a trust-minimized substrate that checks the chain's cryptography on its own code path, in Rust, with C-ABI and WebAssembly targets.**

Sextant answers questions about Cardano state — *is this header a valid Praos block? does this Mithril certificate chain back to the network genesis key? is this UTxO's inclusion certified? has this outpoint been spent?* — by **recomputing the cryptography itself**, never by trusting a provider's answer. A block explorer, RPC endpoint, or aggregator supplies **bytes**; Sextant supplies the **verdict**.

It is deliberately small, dependency-lean, and honest about what it can and cannot prove.

---

## Why

Most applications read Cardano through a trusted intermediary (Blockfrost, Koios, a Dolos/ogmios node, an indexer). That intermediary can lie, and the application has no way to tell. Sextant closes that gap for the **read path**: it is a light-client verification core that a wallet, keeper, bridge, oracle, or on-device app can embed to check what it is told against the network's own signatures and commitments.

Two principles run through the whole codebase:

- **A provider supplies bytes, never a verdict.** Every value Sextant returns is computed by its own verifier over untrusted input. A wrong or hostile input can only make a genuine proof *fail* (a liveness cost), never make an invalid one *succeed* (safety holds). The single trusted input is the pinned per-network **genesis verification key**.
- **Honest scope, enforced mechanically.** Sextant never claims a property its cryptography cannot back. Cardano commits to no UTxO-set accumulator, so *absolute* "is this unspent?" is unprovable — and the code says so, in the type system and at the C ABI. A CI gate greps the generated C header for any liveness vocabulary and fails the build if it appears. What Sextant proves, it proves; what it assumes, it surfaces as data the caller must weigh.

---

## What it verifies

Each capability is implemented on Sextant's own code path and **differentially tested** against an independent implementation on the same inputs (so a bug shows up as a byte-level disagreement, not a silent wrong answer).

| Capability | What is checked | Independent oracle |
|---|---|---|
| **Header decode** | Conway/Babbage Praos block headers → `{block_number, slot, issuer, VRF, opcert, KES, prev_hash}` | `pallas-traverse` |
| **Leader VRF** | ECVRF-ED25519-SHA512-Elligator2 (IETF draft-03): the proof verifies against the epoch nonce and yields the committed output | `cardano-crypto` |
| **Operational certificate** | The cold key delegated to the hot key: strict libsodium-compatible Ed25519 over `hot_vkey ‖ seq ‖ kes_period` | `pallas-crypto` (cryptoxide backend) |
| **KES body signature** | `Sum6Kes` signature over the header body | `pallas-crypto` (`kes` feature) |
| **Chain following** | Hash-linked, gap-free segments across an **epoch boundary**, including Praos nonce evolution (η0) | `pallas` rolling-nonce |
| **Mithril** | A **genesis-anchored** certificate chain: genesis Ed25519 root, STM stake-threshold multi-signatures, AVK binding across epochs, byte-exact content hashing | `mithril-stm` |
| **UTxO read** | A transaction's certified **inclusion** in the Mithril `CardanoTransactions` set (BLAKE2s MMR / `MKMapProof` recompute), then a Conway output decode | `ckb-merkle-mountain-range`, `pallas-primitives` |
| **Windowed-unspent** | No input spending a watched outpoint appears in a header-verified, body-committed, gap-free window from a certified anchor to a verified tip | the batch verifier is the frozen oracle for the incremental follower |

The test corpus includes **61 real block vectors** harvested from Cardano preprod and mainnet, plus adversarial mutation vectors (tampered VRF proofs, swapped bodies, forged commitments, non-canonical encodings) proving each check is non-vacuous.

---

## The honest-scope model: the trust-tier ladder

"Is this outpoint currently unspent?" has **no absolute cryptographic answer** on Cardano — the ledger decides spendability atomically at submission, and there is no state commitment to prove a negative against. Sextant refuses to fake one. Instead it exposes a **ladder of distinct trust bases**, each naming what it rests on, none coercible into a stronger one:

- **Tier 0 — `NotEstablished`.** A single-transaction inclusion read proves an output was *created* and certified as of a block height. Liveness is not established, and cannot be, by this path.
- **Tier 1 — Windowed (`WatchedWindow`).** *Shipped.* A Mithril certificate anchors the outpoint's existence; a follower re-verifies every block body from the anchor to a tip and scans inputs for a spend. No spend observed + follower live ⇒ *no spend through the verified tip*, **as of** that tip, under two **surfaced assumptions** (Mithril quorum, data completeness). Not absolute, not eternal, not tip-state — and it says so. Withholding the spending block cannot advance the tip, so it collapses to a *stall*, never a false "unspent".
- **Tier 2 — `CertifiedUnspent` (cryptographic, reserved).** A future Mithril ledger-state (UTxO-set) commitment + membership proof. Membership at a snapshot re-bases the Tier-1 window to *snapshot→tip* (bounded), covering any outpoint of any age. See [`docs/mithril-utxo-commitment-note.md`](docs/mithril-utxo-commitment-note.md).
- **Tier 3 — `Attested` (economic, reserved).** A committee (e.g. a witness network) attesting an observation — a second opinion, **never** coercible into the cryptographic tier.

The ladder is enforced in the type system (`#[non_exhaustive]` with compile-time tripwires) and banded at the C ABI (cryptographic-with-assumptions `1..=9`, economic `100+`), so a consumer can never mistake an assumption for a proof, or an attestation for a certificate.

---

## Architecture

Sextant is **sans-io**: it verifies bytes it is handed and holds no sockets, threads, or clock. Transport (fetching blocks and certificates) lives outside the trust substrate.

- **Default graph — wasm-safe, lean.** Header/VRF/opcert/KES/nonce, UTxO inclusion, and the windowed follower compose only BLAKE2 + `minicbor` + an [Amaru fork of `curve25519-dalek`](https://crates.io/crates/amaru-curve25519-dalek) (the Elligator2 hash-to-curve that matches libsodium byte-for-byte, as the Amaru node itself runs). **No `blst`, no async, no network.** This graph compiles to `wasm32-unknown-unknown`.
- **`mithril` feature (off by default).** Adds STM multi-signature verification (`mithril-stm`, riding `blst`) for the certificate chain. Kept behind a feature so the default library and the WASM artifact stay small; a CI gate proves no `blst`/`mithril-stm` symbol leaks into the default build or the C header.
- **The verifier core owns the orchestration.** Third-party crates (`curve25519-dalek`, `mithril-stm`) are composed only for primitive arithmetic; the ECVRF equations, the KES ladder, the STM signed-message assembly and AVK-chain binding, the CBOR decoders, and the MMR recompute are all Sextant's own code, differentially checked.

### Consumable surfaces

- **Rust** — `sextant` as a library crate.
- **C ABI** — a stable, `cbindgen`-generated header ([`include/sextant.h`](include/sextant.h), `SEXTANT_ABI_VERSION 4`) over a `cdylib`/`staticlib`. Every export runs its body inside a panic guard so a panic can never unwind across the FFI boundary; the header is drift-gated (the committed header must byte-match a fresh `cbindgen` run).
- **WebAssembly** — the default graph builds to `wasm32-unknown-unknown` for in-browser / on-device verification.

The C ABI exposes: `sextant_verify_segment`, `sextant_header_decode`, `sextant_verify_utxo_read`, `sextant_mithril_verify_chain_anchored` *(mithril feature)*, `sextant_verify_watched_window`, the incremental follower handle (`sextant_follower_new` / `_append` / `_supply_next_eta0` / `_rollback` / `_re_anchor` / `_verdict` / `_destroy`), plus `sextant_abi_version` and `sextant_status_message`.

---

## Build & test

Requires a recent stable Rust toolchain and the `wasm32-unknown-unknown` target.

```sh
# Default (wasm-safe) library, cdylib, and staticlib
cargo build --release

# WebAssembly module
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown

# Full test suite, including the mithril feature and every differential oracle
cargo test --all-features

# Regenerate the committed C header after changing the FFI surface
make header   # cbindgen --config cbindgen.toml --crate sextant --lang c --output include/sextant.h
```

The single source of "done" is the project harness, which runs formatting, `clippy -D warnings`, the release build, `cargo test --all-features`, the `wasm32` build, and the C-header gates (drift, no-feature-leak, honest-scope):

```sh
scripts/harness.sh --full
```

### Examples

Two runnable consumer examples (both use the `mithril` feature to authenticate the chain to genesis first):

```sh
# A single verified UTxO read → spend gate, then a spoofed-response refusal
cargo run --example verified_read_gate --features mithril

# The windowed watch gate: PROCEED only on no-spend (naming basis, anchor, as-of, lag,
# assumptions), REFUSE fail-closed on a spend, a gap, and a truncated window
cargo run --example windowed_spend_gate --features mithril
```

Their stdout is the honest service-log excerpt: a `PROCEED` line always names the trust basis and the surfaced assumptions — there is no bare "proceed".

---

## Status

- **Read-path verification core — complete.** Header VRF/KES/opcert, chain-following with nonce evolution across an epoch boundary, genesis-anchored Mithril certificate chains, and certified UTxO inclusion with a tampered-claim rejection test — all differentially byte-identical to independent oracles on real preprod + mainnet vectors.
- **C-ABI / WASM trust substrate — shipped.** A stable, drift-gated C header (ABI v4) and a wasm-safe build, with a CI leg that links the static library and runs a C smoke test.
- **Windowed-unspent (Tier 1) — shipped end-to-end.** The batch verifier, the incremental `WindowFollower` (append-one-block-at-a-time, epoch-crossing, rollback with eviction-as-finalization, two-region spend honesty), the C-ABI follower handle, and consumer examples.
- **Deferred, by design (not diluted):** a live relay-follower transport, the Tier-2 Mithril ledger-state commitment (a proposal note is committed for the Mithril team), and the Tier-3 economic attestation tier.

This is early software (`v0.1.0`). The verification claims are backed by tests; the API is not yet stable.

---

## Repository layout

```
src/            the verifier core (header, vrf, kes, ed25519, curve, chain, nonce,
                mithril, inclusion, utxo, window, follow, hash, ffi)
include/        the committed, drift-gated C ABI header (sextant.h)
tests/          integration + differential test suites and the real block/cert vectors
examples/       runnable consumer gates
docs/           the Mithril UTxO-set commitment proposal note
tools/harvest/  a workspace member that fetches real vectors (not part of the trust core)
```

---

## Trust model, precisely

A genuine success from Sextant proves exactly what its documentation says and **nothing more**:

- A verified **header segment** proves each block's authorship (opcert + leader-VRF + KES) and the hash links — *not* that the segment is the canonical chain (that rests on the Mithril anchor, a surfaced assumption).
- A verified **UTxO read** proves authentic on-chain bytes + certified inclusion + provenance anchored to genesis *as of a certified height ~100 blocks behind tip* — *not* current spendability.
- A **windowed no-spend** proves no spend through a verified tip under the Mithril-quorum and data-completeness assumptions — *not* absolute or tip-state unspent.

The one trusted input is the pinned genesis verification key. Everything else is checked. Where a property cannot be checked (e.g. that the served chain is the certified one, absent a per-block ledger-state commitment), Sextant **surfaces it as an assumption** the consumer must weigh — it never fakes the check.

---

## License

No license is declared yet. Copyright © Flux Point Studios. Please contact the maintainers before use in a derived work.
