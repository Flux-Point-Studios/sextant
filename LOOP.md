# LOOP: Sextant — read-path verifying Cardano client (Rust core, C-ABI/WASM trust substrate)

STATUS: ACTIVE

## Definition of Done
Every line must be provably true, with the proof named. The Stop gate and
the outer loop only trust `scripts/harness.sh --full`; everything else
needs a row in Evidence.

- [ ] `scripts/harness.sh --full` exits 0
- [ ] Header validation: decodes current-era headers and verifies leader
      VRF + KES against ≥20 golden vectors pulled from preview and
      mainnet, byte-identical verdicts to pallas on the same inputs —
      proof: named differential test run in harness output
- [ ] Chain following: validates a stored preview header sequence across
      an epoch boundary, including nonce evolution — proof: test run
      naming the epoch and the evolved nonce value
- [ ] Mithril: verifies a genesis-anchored certificate chain fetched from
      the network aggregator — proof: test naming the certificate hash
- [ ] UTxO verification for the read path designed and
      implemented (snapshot-anchored or proof-based — decide in a design
      slice first), with a negative test proving a tampered UTxO claim is
      rejected — proof: named test
- [ ] Artifacts: single static lib + C header via cbindgen, and a wasm32
      build, both produced in CI — proof: release workflow run link
- [ ] Live: the first downstream consumer's execution path performs one
      verified UTxO read on preview against a real order before a spend
      decision, and rejects a spoofed RPC response in the same test —
      proof: service log excerpt + the UTxO ref
- [ ] Diff carries no single-caller abstractions and no dead code

## Plan
- [ ] Failing test: decode one preview header from a checked-in CBOR
      vector; assert slot, block number, issuer vkey
- [ ] Vector harvester script: pull N headers from Dolos/Blockfrost into
      tests/vectors/ (vectors are inputs to verify, never trusted state)
- [ ] Failing test: leader VRF verification on vector 1; implement;
      differential-check against pallas
- [ ] KES + operational certificate verification, same pattern
- [ ] <derive the next slice from the Definition of Done, one at a time>

## Constraints
- Read-path only. No transaction building, no interface layer — that
  belongs to the separate write-path layer this library sits under.
- Rust core. pallas crates permitted as dependencies, but every verdict
  this library returns must be computed by its own code path and
  differentially tested — never delegated to an RPC.
- No trusted oracle in the verify path: Dolos/Blockfrost may supply
  bytes, never verdicts.
- Targets: static lib + C ABI (cbindgen), wasm32. Keep the core no_std-friendly where feasible.
- Zig embedding layer is out of scope until the Rust core's DoD is green.

## Merge policy
- Auto-merge: yes. Merge requires all of: CI harness check green,
  red-team VERDICT: SHIP, no unresolved review threads.
- Method: squash; delete branch on merge; sync default branch after.
- Merge-triggers-deploy repos: n/a (library; releases tag manually until
  the Live line is close).
- Standing authorizations: starting scripts/loop.sh for Plan items in
  this file needs no further approval.

## Evidence
| When (UTC) | Claim | Proof |
|---|---|---|
| 2026-07-10 20:17 UTC | Repo onboarded onto fluxpoint-loop; harness gates the DoD | `scripts/harness.sh --full` exits 0 — `cargo fmt --check`, `clippy -D warnings`, release build (lib+cdylib+staticlib), `cargo test` (1 passed), `wasm32-unknown-unknown` release build |

## Notes for the next iteration
Onboarding state (2026-07-10): fluxpoint-loop scaffold in place —
scripts/harness.sh (Rust read-path stack: fmt, clippy -D warnings, release
build, cargo test, wasm32 build), scripts/loop.sh, LOOP_PROMPT.md,
.claude/settings.json. Public repo + Woodpecker pipeline
(.woodpecker/harness.yml) wired; the CI harness check is the merge gate.
Crate is still the cargo-init stub (`add()`) with no verifier code. Deps to
add as the first slices land: a CBOR decoder + blake2/VRF/KES/ed25519
primitives for header validation, and pallas as a differential
dev-dependency (never in the verdict path). Harness ratchet points not yet
gated: cbindgen C-header generation and the preview-net Live UTxO exercise
— each turns on when its DoD slice ships. Attacking next: the first Plan
slice — a failing test decoding one preview header CBOR vector, asserting
slot, block number, issuer vkey.