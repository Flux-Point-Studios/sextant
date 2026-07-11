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
- [x] Operational-certificate verification: decode the opcert (header_body idx
      8 = `[hot_vkey, seq, kes_period, sigma]`) and verify the cold key
      (`issuer_vkey`) Ed25519-signed `hot_vkey ‖ BE64(seq) ‖ BE64(kes_period)`
      (cardano-ledger OCertSignable) on Sextant's own path. `src/ed25519.rs`
      matches libsodium's strict cofactorless boundary (canonical `S<L`,
      canonical non-small-order `A`); the canonical point-decode is extracted to
      `src/curve.rs` (shared with vrf). All 22 real preprod opcerts verify
      (cardano-node ground truth), verdict byte-identical to pallas-crypto's
      independent `cryptoxide` backend; tamper / `s+L` malleation /
      malformed-CBOR all rejected. PR #5.
- [x] KES body-signature verification (the other half of DoD line 2): the
      header's `body_signature` (header idx 1) is a `Sum6Kes` signature over the
      raw header_body bytes at period `slot/129600 − opcert.kes_period`. Verified
      recursively on the existing ed25519 substrate (Blake2b256 vk-hash tree,
      Sum0 = Ed25519 leaf, 448-byte sig) on Sextant's own path in `src/kes.rs`
      (`verify_kes` / `verify_header_kes`); the decoder now captures the raw
      header_body span + the 448-byte body_signature on `HeaderView`. All 22 real
      preprod body signatures verify (cardano-node ground truth, periods 0..35),
      verdict byte-identical to pallas-crypto's independent `Sum6Kes`; tampered
      sig/vk-node/root-key/message/period and out-of-range/underflow periods all
      rejected. `blake2b256` extracted to `src/hash.rs` (shared with vrf). No new
      crate in the trust-substrate normal graph (pallas `kes` feature is dev-only).
      DoD line 2 assessment recorded in Notes (KES + leader-VRF proven on ≥20 real
      preprod; a full "from mainnet" tick needs a real-mainnet harvest with eta0).
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
| 2026-07-11 06:32 UTC | Operational-certificate verify (opcert half of DoD line 2): all 22 real preprod opcerts verify on Sextant's own Ed25519 path, verdict byte-identical to pallas-crypto's independent `cryptoxide` backend; the cold key genuinely signed `hot_vkey ‖ BE64(seq) ‖ BE64(kes_period)` | `cargo test --test opcert` — `real_preprod_opcerts_verify` (≥20), `opcert_verdict_matches_independent_oracle` (vs `pallas_crypto::key::ed25519`, cryptoxide, on genuine + 1-bit tamper), `tampered_opcert_is_rejected` (sig/hot/seq/period/wrong-cold-key), `opcert_rejects_non_canonical_scalar` (`s+L`); + `header_decode::rejects_bad_opcert_shape`. `src/ed25519.rs` = libsodium strict cofactorless verify on the amaru dalek fork; `decode_point` extracted to `src/curve.rs` (shared with vrf). `scripts/harness.sh --full` exit 0, 27 tests (13 header + 4 opcert + 10 vrf) |
| 2026-07-11 06:32 UTC | Slice 5 merged to main with red-team SHIP | PR #5 squash-merged (`32d50b4`), CI `ci/woodpecker/pr/harness` green (pipeline 48). Independent `fluxpoint-loop:red-team-reviewer` VERDICT SHIP — no CRITICAL/HIGH/MEDIUM: Ed25519 boundary no looser than libsodium (no false-accept path), OCertSignable layout confirmed by 22-vector parity, decoder element-accounting exact + fail-closed, `curve.rs` extraction byte-identical (vrf's 10 tests green), authority binds {cold,hot,seq,period}. One LOW (module doc overstated opcert as full header auth) fixed in `5303ff8` (scoped to cold→hot delegation); single-variant `KesError` accepted as next-slice scaffolding. No new crate fetch (pallas-crypto already resolved transitively) |
| 2026-07-11 06:53 UTC | Independent red-team of the autonomously-merged opcert slice: VERDICT SHIP (confirms the loop's self-review) | Fresh `fluxpoint-loop:red-team-reviewer` + operator 4× flaky-check: 0 forged opcerts accepted; Ed25519 matches libsodium strictness and is stricter than its own cryptoxide oracle on small-order A (9 forgeries the oracle accepts but cardano-node/Sextant reject — oracle is the lax side); no VRF regression from shared `curve.rs`; BE64 OCertSignable confirmed on 22 vectors; no panic/DoS (300k iters); deterministic (both case-builders `sort_by_key(slot)`) |
| 2026-07-11 07:40 UTC | KES body-signature verify (KES half of DoD line 2): all 22 real preprod header body signatures verify on Sextant's own recursive `Sum6Kes` path at `slot/129600 − opcert.kes_period` (cardano-node ground truth), verdict byte-identical to pallas-crypto's independent `Sum6Kes`; the hot KES key genuinely signed the raw header_body CBOR | `cargo test --test kes` — `real_preprod_kes_body_sigs_verify` (≥20, `verify_header_kes`, periods 0..35), `kes_verdict_matches_independent_oracle` (vs `pallas_crypto::kes` `Sum6KesSig::verify`, genuine + 1-bit tamper), `tampered_kes_body_sig_is_rejected` (sig/last-vk-node/root-key/message/wrong-period), `kes_period_out_of_range_is_rejected` (≥64 and slot-precedes-opcert underflow). `src/kes.rs` recurses the Blake2b256 vk tree over `src/ed25519::verify` leaves; decoder captures raw header_body span + 448-byte body_signature; `blake2b256` shared via `src/hash.rs`. Mutation check: inverting the subtree split → 3/4 tests red. `scripts/harness.sh --full` exit 0, 31 tests (13 header + 4 kes + 4 opcert + 10 vrf) |
| 2026-07-11 07:58 UTC | Slice 6 (KES body-signature verify) merged to main with red-team SHIP | PR #6 squash-merged (`150e143`), CI `ci/woodpecker/pr/harness` green (pipeline 56). `fluxpoint-loop:red-team-reviewer` VERDICT SHIP — no CRITICAL/HIGH/MEDIUM: `verify_sum` visits all 6 vk-node checks + the leaf on every period (no path-shortening), MMM split proven underflow-free by induction, message span byte-exact (`8a`..idx-9, oracle cross-check non-circular), no reachable panic on untrusted bytes, decoder/VRF-refactor regression-free, honestly scoped. Two INFO, one closed with a doc note on `verify_header_kes` (`8a4f1a0`). `scripts/harness.sh --full` exit 0 on merged main, working tree clean |
| 2026-07-11 07:37 UTC | Independent red-team of the autonomously-merged KES slice: VERDICT SHIP — soundly closes DoD line 2 (VRF + KES) | Fresh `fluxpoint-loop:red-team-reviewer` + operator 4× flaky-check: evolved-period math has no off-by-one (oracle accepts at exactly Sextant's period, rejects at period±1 across all 22); signed message is the byte-exact raw header_body span (not re-encoded); Sum6Kes Merkle path binds both children in order (swapped subtree / tampered node / wrong root all rejected); 15k differential fuzz → 0 disagreements, 0 forgeries accepted; 100k adversarial iters → no panic; no regression from shared `hash.rs`; deterministic |

## Notes for the next iteration
State (2026-07-11): **KES body-signature verify shipped** (this slice). DoD line
2's two crypto halves — leader-VRF (slice 4) and KES (opcert slice 5 + this KES
body-sig slice) — are now both proven on the 22 real preprod vectors, each
byte-identical to an independent pallas-family oracle.

`src/kes.rs` now exposes, beyond opcert: `verify_kes(root_vkey, period, msg,
&[u8;448]) -> Result<(), KesError>` (recursive `Sum6Kes`: depth-6 Blake2b256 vk
tree over `ed25519::verify` leaves, `sig = sigma(d−1) ‖ vk0 ‖ vk1`, split at
`2^(d−1)`), and `verify_header_kes(&HeaderView)` which derives the evolution
period `slot/129600 − opcert.kes_period` (checked_sub + `<64` bound, else
`KesPeriodOutOfRange`). `HeaderView` gained `header_body: Vec<u8>` (the raw CBOR
span the KES key signs, captured `body_start..d.position()`) and
`body_signature: [u8;448]`. `blake2b256` is now shared in `src/hash.rs` (vrf's
`praos_vrf_input` and kes's vk tree both call it). Oracle: `pallas-crypto` dev-dep
now `features=["kes"]` → `pallas_crypto::kes::summed_kes::Sum6KesSig::verify` — an
independent `Sum6Kes` implementation. The `kes` feature pulls dev-only mainstream
transitives (serde_with/schemars/chrono/time); `cargo tree -p sextant --edges
normal` confirms the trust-substrate lib graph is unchanged (4 direct deps).

**DoD line 2 assessment — deliberately left unchecked.** Line 2 asks for VRF+KES
on ≥20 golden vectors "pulled from preview and mainnet." What is proven: leader-VRF
+ KES on 22 **preprod** blocks (freshly BlockFetched off a live relay), oracle-
parity on each. What is NOT proven for a fully honest tick: (a) the leader-VRF
verify runs preprod-only because mainnet vectors have no `.eta0` sidecar; (b) the
5 mainnet vectors are pallas **synthetic decode-fixtures** — the diagnostic this
slice ran shows babbage1/2/3 carry hand-set slots (~1.03M, impossible for real
Babbage) whose slot→KES-period relationship is off by a constant, so
`verify_header_kes` (which derives the period from the slot) cannot use them;
babbage4 (slot 63.5M) and conway1 obey the formula and DO match the oracle's
period exactly (27, 5) — confirming the period math and the KES verifier, not a
bug. A clean line-2 tick needs a **real-mainnet block harvest with eta0**
(same tooling as the preprod harvest). Recorded here so the operator, not the
loop, decides whether preprod-primary satisfies line 2.

Prior state: operational-certificate verify (slice 5, PR #5, `32d50b4`).
`src/ed25519.rs` exposes `verify(pubkey, msg, sig) -> bool` (libsodium strict
cofactorless). `src/kes.rs` exposes `opcert_signable`/`verify_opcert`. `HeaderView`
carries `opcert` (header_body idx 8). `src/curve.rs` `decode_point` is shared by
vrf and ed25519.

Earlier state: full leader-VRF **verify** on Sextant's own draft-03 code path.
`src/vrf.rs` exposes `verify(vkey, alpha, proof)`, `verify_praos_leader(vkey,
slot, eta0, proof)` (builds `alpha = Blake2b256(BE64(slot)‖eta0)` via
`praos_vrf_input`) and `proof_to_hash`. All 22 preprod vectors carry a
`preprod-<slot>.eta0` sidecar (epoch-300 nonce); every real leader proof
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

## Attacking next — DoD line 3: chain-following + nonce evolution
The exact Praos nonce spec was independently re-derived from cardano-ledger +
ouroboros-consensus SOURCE and numerically cross-checked against pallas-crypto's
golden vectors (spec-derivation workflow, confidence HIGH). USE THIS — an earlier
sketch had the per-block recipe WRONG (single untagged hash) and its "compute η0
from the chain" plan is INFEASIBLE (see feasibility).

VERIFIED Praos (Babbage+, preprod) nonce spec — Blake2b-256, 32-byte nonces, no
CBOR/length framing:
- Combine ⭒:  a ⭒ b = blake2b256( bytes(a)[32] ‖ bytes(b)[32] )  (left 32 then
  right 32; left-associative). NeutralNonce is the identity and short-circuits
  WITHOUT hashing (neutral extraEntropy / genesis prev-hash drop out).
- Per-block contribution (THE TRAP — double hash + domain tag):
    η_block = blake2b256( blake2b256( 0x4E ‖ rawVrfOutput64 ) )
  0x4E = ASCII 'N'; rawVrfOutput64 = the 64-byte certified output of the single
  unified Praos VRF (already on `HeaderView.vrf_output`). pallas-crypto's
  `generate_rolling_nonce` is the LEGACY TPraos single-hash-no-tag shape — do NOT
  reuse it as-is; pre-hash `blake2b256(0x4E‖output)` yourself (matches amaru's
  `extended_vrf_nonce_output`), then fold.
- Rolling fold (once per applied block):  η_v' = η_v ⭒ η_block.
- Epoch boundary:  η0(e+1) = candidateNonce(e) ⭒ prevHashNonce(e)  — NO
  extraEntropy on preprod (neutral). prevHashNonce = Nonce(castHash(the 32-byte
  Blake2b-256 header-hash of the LAST block of epoch e)); pure retag, no rehash;
  one-epoch lag.
- Candidate freezes once slot-in-epoch ≥ 432000 − 172800 = 259200 (window = 4k/f,
  k=2160 f=0.05). Stop folding into the candidate at that slot.

FEASIBILITY — computing epoch-300 η0 by folding needs ALL ~13k epoch-299 blocks
to the freeze (~65 MB); INFEASIBLE as checked-in vectors. Do the feasible,
meaningful decomposition (all three are real and gate the DoD):
1. FORMULA, differential vs a real oracle: implement ⭒, η_block (0x4E double
   hash), the rolling fold, and the epoch combine in `src/nonce.rs`; unit-test
   byte-exact against pallas-crypto's `test_rolling_nonce` (30-block fold from the
   shelley-genesis seed — it is TPraos single-hash-shaped, so test your ⭒+fold
   with ITS per-block inputs) and `test_epoch_nonce` (the ⭒ + extra-entropy
   combine). Proves the formula against ground truth.
2. CHAIN-FOLLOWING, real vectors: verify the stored consecutive preprod sequence
   links — each header's prev_hash == blake2b256(previous header bytes) — slots
   and block numbers strictly increase, and each header's full crypto (leader-VRF
   vs its epoch η0 + KES + opcert) verifies.
3. REAL BOUNDARY, harvest: extend `tools/harvest` to pull a short contiguous run
   spanning the 299→300 boundary + both epochs' `.eta0` sidecars. Verify each
   block's leader-VRF against ITS epoch's η0 (pre-boundary → η0(299), post →
   η0(300)) and that using the WRONG epoch's nonce makes verify FAIL — the
   on-chain proof the nonce evolved. DoD line 3 proof = a test naming epochs
   299→300 and the evolved value η0(300) = `aa845533…4eeb6c30`.

Infra: Woodpecker runs the harness on push/PR (`ci/woodpecker/*/harness`); repo
Flux-Point-Studios/sextant (repo 15), CI green through pipeline 56. Trust-
substrate normal-dep graph unchanged (all oracles dev-only). Carried red-team
note: cross-check `HeaderView.era` against the tx-body schema so a Conway-body-
labelled-Babbage block cannot pass full validation.
