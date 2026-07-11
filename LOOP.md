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
- [x] Full leader-VRF verify: `hash_to_curve` (Elligator2) + challenge +
      equation, binding the proof to `alpha = Blake2b256(slot_be8 || eta0)`;
      accept a real vector (eta0 = Koios `epoch_params?_epoch_no=N`, N = the
      block's epoch) and reject a tampered proof. Done: eta0 backfilled as
      `.eta0` sidecars via `cargo run -p harvest eta0`; `vrf::verify` composes
      Amaru's elligator-fixed `curve25519-dalek` fork on Sextant's own draft-03
      orchestration; all 22 real preprod proofs verify, verdict cross-checked
      against the independent non-dalek `cardano-crypto` oracle, tampered
      slot/nonce/key/scalar all rejected.
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
| 2026-07-11 04:40 UTC | eta0 sidecars backfilled for all 22 preprod vectors (epoch 300 active nonce, Koios), no vector churn | `cargo run -p harvest eta0` — new `harvest eta0` mode decodes each `preprod-*.block` with pallas, resolves its epoch via Koios `block_info`, fetches `epoch_params?_epoch_no=300&select=nonce`, writes `preprod-<slot>.eta0` (eta0 `aa845533…4eeb6c30`). 22 sidecars written |
| 2026-07-11 04:40 UTC | Full leader-VRF verify on Sextant's own draft-03 code path: 22 real preprod leader proofs accept and yield the committed output, verdict byte-identical to an independent non-dalek oracle; tampered slot/nonce/key/scalar all reject | `cargo test --test vrf` — `real_preprod_leader_proofs_verify` (≥20 cases, `verify_praos_leader` binds `alpha = Blake2b256(BE64(slot)‖eta0)`), `verdict_matches_independent_oracle` (vs `cardano-crypto` `VrfDraft03::verify` on the same alpha), `tampered_leader_proof_is_rejected`; hash-to-curve = Amaru's elligator-sign-fixed `curve25519-dalek` fork, ECVRF orchestration is Sextant's own. All 8 vrf + 12 header tests green in `scripts/harness.sh --full` (exit 0) |
| 2026-07-11 04:40 UTC | Substrate migrated cryptoxide → Amaru `curve25519-dalek` fork; `proof_to_hash` regression-free on all 27 vectors; wasm32 artifact still builds | `scripts/harness.sh --full` exit 0 — `proof_to_hash` now `gamma.mul_by_cofactor()` on the fork (drops cryptoxide's −P negate hack), `every_vector_output_equals_proof_to_hash` still byte-identical; `cargo build --release --target wasm32-unknown-unknown` green with the dalek fork (`default-features=false, ["u64_backend","alloc"]`) + sha2 0.9 + blake2 0.9 |
| 2026-07-11 05:05 UTC | Red-team of the verify slice returned BLOCK on the canonicity boundary (a false-accept class the dalek-based oracle could not catch); closed by tightening to match libsodium's canonical-only decode | `fluxpoint-loop:red-team-reviewer` VERDICT BLOCK: `verify` reduced a non-canonical `s` (`from_bytes_mod_order`) and `decode_point` tolerated non-canonical point encodings. Fixed: `s` now `Scalar::from_canonical_bytes(..)` (reject `s ≥ L`), `decode_point` requires a compress round-trip (reject y `≥ p`, matching libsodium `ge25519_is_canonical`). Both reject only adversarial encodings a canonical producer never emits — all 22 real proofs still verify. New oracle-independent negatives `non_canonical_scalar_is_rejected` (s+L → `VerificationFailed`) and `non_canonical_point_is_rejected` (Gamma=p → `InvalidGamma`); `scripts/harness.sh --full` exit 0, 22 tests (12 header + 10 vrf) |
| 2026-07-11 05:49 UTC | Slice 4 (full leader-VRF verify) merged to main; operator caught a flaky test that a single green run and the red-team both missed | PR #4 squash-merged (`44365a8`), CI green (pipeline 40). Independent `fluxpoint-loop:red-team-reviewer` SHIP — `verify` binds vkey+alpha (real-Gamma+garbage-`c‖s` forgery rejected, 80×9 single-byte tamper → 0 accepted, all 22 real leader proofs verify vs on-chain truth), Elligator2 byte-exact, deps sound (Amaru fork = 1 auditable line). Flaky test fixed: `leader_cases` sorted by slot, tampered test now finds a distinct-vkey case (`fs::read_dir` order made it pass/fail non-deterministically); `scripts/harness.sh --full` exit 0 on merged main |

## Notes for the next iteration
State (2026-07-11): full leader-VRF **verify** shipped, on Sextant's own
draft-03 code path. `src/vrf.rs` now exposes `verify(vkey, alpha, proof)`,
`verify_praos_leader(vkey, slot, eta0, proof)` (builds `alpha =
Blake2b256(BE64(slot)‖eta0)` via `praos_vrf_input`, also public) and the
migrated `proof_to_hash`. All 22 preprod vectors carry a committed
`preprod-<slot>.eta0` sidecar (epoch-300 nonce), and every real leader proof
verifies + matches the independent `cardano-crypto` oracle; tampered
slot/nonce/key/scalar reject.

**Substrate migrated cryptoxide → Amaru `curve25519-dalek` fork**
(`package = "amaru-curve25519-dalek"`, aliased `curve25519-dalek`,
`default-features=false, ["u64_backend","alloc"]`) + `sha2 0.9` + `blake2 0.9`.
Why: Elligator2 hash-to-curve must match libsodium byte-for-byte, and cryptoxide
exposes neither its field ops (mul/sq/from_bytes are private) nor a general
variable-base Edwards mul, so it cannot host the map or the `U`/`V` equations.
Upstream dalek's `hash_from_bytes` uses the wrong sign bit; Amaru's fork is a
single-commit fix (`sign_bit = 0`) and is what the Amaru node itself runs.
cryptoxide is fully removed — `proof_to_hash` is now `gamma.mul_by_cofactor()`
(no more −P negate hack), still byte-identical on all 27 vectors. wasm32 build
confirmed green with the fork.

Trust note for the red-team / Live slice: **eta0 is a byte input, not a trusted
verdict.** A wrong eta0 changes alpha, so it can only make a genuine proof
*reject* (liveness), never make an invalid proof *accept* (safety holds). In the
tests eta0 is self-authenticating — the 22 real proofs verifying is proof the
Koios nonce was correct. For a live consumer, the trust-minimal source of eta0
is to **compute** it from the chain (the separate nonce-evolution DoD line):
eta0 evolves deterministically from block VRF outputs. That slice makes the
whole leader-VRF path oracle-free.

Attack next — **KES + operational certificate verify** (DoD "verifies … KES",
same differential pattern). Unlike VRF, **pallas-crypto 1.1.1 HAS a `kes`
feature** — use it as the differential oracle (add `pallas-crypto` dev-dep with
`features=["kes"]`). The header's `body_signature` (index 1 of the header
`[header_body, body_signature]`) is the KES signature over the header body; the
operational cert lives in the header_body tail we currently `skip()` (fields
after `vrf_result`: op-cert = [hot_vkey, seq_no, kes_period, sigma], then
protocol version). Surface those on `HeaderView`, verify (a) the cold-key
Ed25519 signature over the op-cert, and (b) the KES signature over the body at
the header's KES period, against ≥20 real vectors, byte-identical verdict to
pallas-crypto's kes. cardano-crypto also ships a `kes` feature as a second
oracle. No new network input needed (KES is self-contained in the header).

Infra: Woodpecker runs the harness on push/PR (`ci/woodpecker/*/harness`);
repo is Flux-Point-Studios/sextant — if CI webhooks go quiet, Repair/re-sync
repo 15 in Woodpecker. Ratchet points not yet gated: cbindgen C-header
generation and the preview-net Live UTxO exercise.

Carried from red-team (for when the full body/VRF validation lands): now that
`HeaderView.era` is available, cross-check it against the transaction-body
schema so a Conway-body-labeled-Babbage block cannot pass full validation.

## Attacking next
KES + operational-certificate verification (Plan item 5 — the second half of
DoD line 2). pallas-crypto 1.1.1 ships a `kes` feature usable as the
differential oracle here (unlike VRF, which it lacks). Branch from the merged
`main` (slice 4 is in).

Concrete shape (two independent checks per header):
1. Operational certificate: the pool's COLD key (`issuer_vkey`, header_body
   idx 3) Ed25519-signs `hot_kes_vkey ‖ BE64(sequence_number) ‖ BE64(kes_period)`.
   The opcert lives at header_body idx 8 = `[hot_vkey(32), seq(uint),
   kes_period(uint), sigma(64)]`. Ed25519 verify is already available (amaru
   dalek fork).
2. KES signature: `body_signature` (header idx 1) is a Cardano `Sum6Kes`
   signature (binary Merkle sum of Ed25519, depth 6 = 64 periods) over the
   header_body bytes, at period `slot_kes_period = (slot - opcert.kes_period·..)`
   — get the exact period math from pallas-crypto/cardano-node.
PREFER implementing Sum6Kes verification on the EXISTING substrate (amaru
dalek Ed25519 + blake2, both already deps) over adding another obscure KES
crate — keeps the trust substrate minimal (Constraint) and avoids the slice-4
CI dep-fetch pain. Differentially check the verdict against pallas-crypto's
`kes` on the same header bytes; anchor on the 27 real vectors.

The slice-4 CI blocker (runner couldn't fetch obscure crates) is resolved —
pipeline 40 green; if CI fails-fast on fetch again, the fix is the runner
(crates.io egress / mirror), not the code.