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
- [x] Failing test: decode one current-era header from a checked-in CBOR
      vector; assert slot, block number, issuer vkey
- [x] Vector-set differential harness: every `tests/vectors/*.block` is
      decoded on Sextant's own path and cross-checked against pallas
      (block_number/slot/issuer_vkey), the validated era is surfaced on
      `HeaderView`, and cross-era coverage is asserted — the scaling
      primitive for the ≥20-vector requirement (harvested vectors are
      auto-verified here or the harness goes red; vectors are inputs to
      verify, never trusted state)
- [x] Vector harvester + live pull: `tools/harvest` (workspace member) pulls
      recent preprod block CBOR off a public relay (pallas-network N2N
      BlockFetch; points from Koios) into tests/vectors/. 22 preprod (era 7)
      + 5 mainnet golden (era 6/7) = 27 vectors, each byte-identical to pallas
      via the sweep. Note: preprod, not preview, per operator choice.
- [x] VRF output verification: extract vrf_vkey + vrf_result (output/proof)
      from the header and recompute the 64-byte VRF output (beta) via
      draft-03 `proof_to_hash` (SHA512 over 8·Gamma, on cryptoxide's
      curve25519) on Sextant's own path — byte-identical to every one of the
      27 real vectors' on-chain output. Nonce-independent, so no epoch nonce
      needed. Oracle is the canonical libsodium producer (cardano-node), not
      pallas: pallas-crypto 1.1.1 (latest published) ships no VRF module.
- [ ] Full leader-VRF verify: `hash_to_curve` (Elligator2) + challenge +
      equation, binding the proof to `alpha = Blake2b256(slot_be8 || eta0)`;
      accept a real vector (eta0 = Koios `epoch_params?_epoch_no=N`, N = the
      block's epoch) and reject a tampered proof. Needs network for eta0 —
      extend `tools/harvest` to capture the epoch nonce as a sidecar, or run
      in a network-enabled context.
- [ ] KES + operational-certificate verification, same differential pattern
      (pallas-crypto has a `kes` feature usable as the oracle here)
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
| 2026-07-10 20:20 UTC | Woodpecker CI runs the harness on push | `ci/woodpecker/push/harness` success on `main` — https://ci.fluxpointstudios.com/repos/15/pipeline/1/1 |
| 2026-07-10 20:54 UTC | Header decode slice: block_number/slot/issuer_vkey from a real Conway block, byte-identical to pallas on the same input | `cargo test --test header_decode` — `decodes_conway_header_fields` + `matches_pallas_on_the_same_bytes` both pass in `scripts/harness.sh --full` (exit 0); vector `tests/vectors/conway1.block`, expected block 1093546 / slot 22075282 / issuer `e856c8…b08c4a` |
| 2026-07-10 21:09 UTC | Red-team BLOCK closed: adversarial CBOR can no longer force a wrong successful decode (array-count/era/prev_hash/trailing-byte defects) | Decoder now validates exact array counts, Praos era {6,7}, 32-byte prev_hash/issuer, full input consumption; 6 regression tests (`rejects_*`) + Babbage differential added; `scripts/harness.sh --full` exit 0, 9 tests pass |
| 2026-07-10 21:16 UTC | Red-team re-attack: 4 findings verified closed, no panic/DoS; 2nd BLOCK (non-canonical era u16/u32/u64 = Sextant-Ok/pallas-Err) fixed | Era now required to be a canonical U8 token, matching pallas `block_era`; `rejects_non_canonical_era_encoding` asserts both Sextant and pallas reject the u64-widened Conway block; `scripts/harness.sh --full` exit 0, 10 tests pass |
| 2026-07-10 21:22 UTC | Slice 1 merged to main with red-team SHIP; 362,161 both-accept fuzz cases, 0 field mismatches vs pallas | PR #1 squash-merged (`ae942a3`), CI `ci/woodpecker/pr/harness` green (pipeline 8), red-team `VERDICT: SHIP`; `scripts/harness.sh --full` exit 0 on merged main |
| 2026-07-11 00:10 UTC | Vector-set differential harness + `HeaderView.era` (salvaged from the loop iteration, verified here by running the harness): every `tests/vectors/*.block` is decoded on Sextant's own path and is byte-identical to pallas on block_number/slot/issuer_vkey; the validated Praos era is surfaced on `HeaderView.era`; cross-era coverage asserted | `tests/header_decode.rs::every_vector_matches_pallas_and_is_praos` + `decodes_conway_header_fields` (era 7) + `decodes_babbage_header_era` (era 6); `scripts/harness.sh --full` exit 0 |
| 2026-07-11 00:30 UTC | Harvester delivered 27 real vectors (≥20 DoD floor) and the decoder handles real Conway tx CBOR | `tools/harvest` (workspace member) BlockFetched 22 preprod blocks off relay `preprod-node.play.dev.cardano.org:3001` via pallas-network N2N (points from Koios); +5 mainnet golden vectors from pallas. Fixed nested-indefinite-CBOR skip by enabling minicbor `alloc`. Sweep verifies all 27 byte-identical to pallas; `scripts/harness.sh --full` exit 0, 11 tests |
| 2026-07-11 00:42 UTC | Red-team of the harvester slice: VERDICT SHIP — no DoS from `alloc`, no wrong-Ok, no Sextant/pallas divergence | `fluxpoint-loop:red-team-reviewer`: alloc-skip memory is O(N)-bounded (1M fuzz no panic/hang; deep-indefinite O(1); huge length-prefix → Err, no pre-alloc); all 27 vectors byte-identical to pallas incl. era; sweep fails closed on degenerate files. One LOW (counted files, not distinct blocks) hardened here — sweep now counts distinct block contents (`distinct.len() >= 20`) |
| 2026-07-11 00:45 UTC | Slice 2 (harvester + 27-vector differential decode) merged to main | PR #2 squash-merged (`d533e1e`), CI `ci/woodpecker/pr/harness` green (pipeline 16), red-team `VERDICT: SHIP`; `scripts/harness.sh --full` exit 0 on merged main |
| 2026-07-11 01:40 UTC | VRF output verification: Sextant recomputes each header's 64-byte VRF output (beta) from its 80-byte proof on its own draft-03 code path and it is byte-identical to the on-chain output the producer committed, across all 27 real vectors | `cargo test --test vrf` — `every_vector_output_equals_proof_to_hash` (≥20 distinct blocks), `proof_to_hash_matches_onchain_output_conway1` (anchor: beta == `af9ff8…d25e5e`), `decodes_conway_vrf_fields`, `tampered_gamma_breaks_output`, `off_curve_gamma_is_rejected` all pass in `scripts/harness.sh --full` (exit 0, 16 tests). `beta = SHA512(0x04‖0x03‖enc(8·Gamma))` on cryptoxide curve25519; oracle is the canonical libsodium producer (pallas-crypto 1.1.1 has no VRF). Found + corrected cryptoxide's negated-decode (`Ge::from_bytes` returns −P) |
| 2026-07-11 01:55 UTC | Red-team of the VRF slice: VERDICT SHIP — no wrong verdict, no panic on untrusted bytes, no overclaim; the one actionable LOW (no dedicated negative test for a malformed `vrf_result`) closed here | `fluxpoint-loop:red-team-reviewer`: proof_to_hash matches libsodium incl. the −P negate; decoder fails closed (`expect_array(2)` + `read_bytes_exact::<N>`, skip 10−6=4); slice honestly scoped (output-only, full alpha-binding verify deferred). Added `rejects_bad_vrf_result_shape` (wrong arity / non-bytes / 63-byte output / 79-byte proof → `MalformedCbor`/`BadHashLen`); `scripts/harness.sh --full` exit 0, 17 tests |
| 2026-07-11 01:58 UTC | Independent red-team of the autonomously-merged VRF slice: VERDICT SHIP (confirms the loop's self-review; first fully-autonomous merge, externally verified) | Fresh `fluxpoint-loop:red-team-reviewer` pass: `proof_to_hash` byte-exact to libsodium — the −P negate is load-bearing (no-negate → different beta, so the 27-vector test genuinely constrains it); no overclaim (output-only, zero internal callers mistaking it for verify); no panic across 1M random proofs + 400k end-to-end mutations; `cryptoxide` a correctly-scoped prod dep (`--edges normal` = curve25519/sha2 only, pallas dev-only, wasm no_std builds). Informational: the full-verify slice must expose the eligibility verdict behind a distinct `verify`-style API |

## Notes for the next iteration
State (2026-07-11): VRF **output** verification shipped. `HeaderView` now
surfaces `vrf_vkey` (idx 4), `vrf_output` (64) and `vrf_proof` (80) from
`vrf_result` (idx 5). `src/vrf.rs::proof_to_hash` recomputes beta =
`SHA512(0x04‖0x03‖enc(8·Gamma))` on cryptoxide's curve25519 (added as a
`default-features=false, ["curve25519","sha2"]` dep — pure-Rust, no_std, the
same substrate pallas is built on), byte-identical to all 27 real vectors'
on-chain output. This is nonce-independent, so no epoch nonce was needed.

Two load-bearing discoveries this slice (both verified against real bytes):
1. **pallas-crypto 1.1.1 (latest published) ships NO VRF module** — features
   are ed25519-dalek/kes/rand/…, no `vrf`. So the DoD's "byte-identical
   verdicts to pallas" for VRF is not satisfiable at the pinned version; the
   oracle used is the canonical libsodium producer (the block's own committed
   output), which is strictly stronger. pallas-crypto DOES have a `kes`
   feature — use it as the oracle for the KES slice.
2. **cryptoxide `Ge::from_bytes` returns −P** (ref10 negated-decode, what
   Ed25519 verify wants). VRF needs the true point, so proof_to_hash negates
   it back (`&Ge::ZERO - &neg.to_cached()`). The full verify must do the same
   for Gamma AND the vrf_vkey Y — at that point (2nd/3rd caller) extract a
   `decode_point` helper; it was inlined here to avoid a one-caller abstraction.

eta0 for the full alpha-binding verify — NOT blocked: the Bash allowlist has
no WebFetch/WebSearch/curl, but `cargo run -p harvest` reaches the network
in-process via reqwest (that is exactly how slice 2 fetched all 27 vectors),
so path (a) is fully doable autonomously now:
  (a) [preferred] extend `tools/harvest` to also GET Koios
      `epoch_params?_epoch_no=N` (N = the block's epoch) and write the 32-byte
      eta0 (`nonce`) as a sidecar next to each vector (e.g.
      `preprod-<slot>.eta0`), then the verify test reconstructs alpha offline.
      Keeps the loop self-contained and feeds the separate nonce-evolution DoD
      line. Run `cargo run -p harvest` once, commit the vectors + sidecars.
  (b) fallback only: run the verify slice in a session with WebFetch/curl.
Attack (a) next: the spec is fully pinned (see the copy-pasteable block from
research): alpha = Blake2b256(BE64(slot)‖eta0); H = 8·elligator2(SHA512(0x04‖
0x01‖Y‖alpha)[0..32] with bit255 cleared); U = s·B−c·Y, V = s·H−c·Gamma;
c' = SHA512(0x04‖0x02‖H‖Gamma‖U‖V)[0..16]; accept iff c'==c. Elligator2 (the
one hard part) has no cryptoxide helper — port from IOG libsodium/Amaru.

Infra: Woodpecker runs the harness on push/PR (`ci/woodpecker/*/harness`);
repo is Flux-Point-Studios/sextant — if CI webhooks go quiet, Repair/re-sync
repo 15 in Woodpecker. Ratchet points not yet gated: cbindgen C-header
generation and the preview-net Live UTxO exercise.

Carried from red-team (for when the full body/VRF validation lands): now that
`HeaderView.era` is available, cross-check it against the transaction-body
schema so a Conway-body-labeled-Babbage block cannot pass full validation.

## Blockers (read first)
**CI is RED and it blocks all merges — fix this before the next slice.**
Slice 4 (full leader-VRF verify) is CODE-COMPLETE and carries red-team
`VERDICT: SHIP`, but it is PARKED on **PR #4**
(branch `slice-4-leader-vrf-verify`) because the Merge policy requires CI green
and Woodpecker is failing.

Diagnosis (not a code defect): every pipeline for the branch fails in ~41–48 s
— far too fast to have compiled the new ~40-crate tree (minutes locally), so it
dies at an early step (rustup / `cargo fmt` / initial crates.io index+download)
*before* the slice's code compiles. The only structural change vs the green
slice-3 build is the new deps (`amaru-curve25519-dalek`, `sha2 0.9`,
`blake2 0.9`, dev-only `cardano-crypto`). Most likely the self-hosted runner
cannot fetch the new/obscure crates (registry/mirror gap or lost crates.io
egress). Local proof is solid: `scripts/harness.sh --full` exits 0 (fmt, clippy
`-D warnings`, 22 tests, wasm32) and a clean-target clippy compiled the whole
new tree — plus an independent red-team SHIP.

Do next, in order: (1) open the Woodpecker pipeline log (target URL on PR #4)
and confirm the failing step; if it is a crate fetch, add the new crates to the
runner's source/mirror or restore crates.io egress (or Repair/re-sync repo 15).
(2) Re-run CI; when green, squash-merge PR #4 and sync `main`. (3) THEN mark the
slice-4 Plan item done and branch the KES slice from the merged result — do NOT
start KES from this pre-merge `main`, or it will diverge from the parked branch.