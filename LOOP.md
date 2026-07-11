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
- [x] Chain following: validates a stored preview header sequence across
      an epoch boundary, including nonce evolution — proof: test run
      naming the epoch and the evolved nonce value
      (PROVEN on preprod — the operator-chosen testnet for this whole client,
      per Plan; `tests/boundary.rs::boundary_run_crosses_epoch_299_to_300_and_
      the_nonce_evolved` follows a stored contiguous run across the 299→300 turn
      and names the evolved η0(300) = `aa845533…4eeb6c30`, with each side's
      leader-VRF bound to its own epoch nonce and rejecting the other's)
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
- [x] Nonce-evolution FORMULA (DoD line 3, part 1 of 3): `src/nonce.rs`
      implements the Praos `⭒` combine (`Blake2b256(a‖b)`), the per-block
      contribution `Blake2b256(Blake2b256(0x4E ‖ vrf_output))` (double hash +
      domain tag — the Praos trap the legacy TPraos rolling nonce omits), the
      rolling fold `η_v' = η_v ⭒ contribution`, and the epoch-boundary combine
      `η0 = candidate ⭒ prevHashNonce (⭒ extraEntropy)` on Sextant's own path.
      Differentially proven byte-exact against pallas-crypto's independent
      implementation: the `test_epoch_nonce` golden pins `epoch_nonce`/`⭒`, the
      `test_rolling_nonce` golden (30-block shelley-seed fold) pins `⭒` + fold
      chaining, and on all 22 real preprod VRF outputs `evolve` matches pallas's
      `generate_rolling_nonce` oracle (fed the test-assembled extended input, so
      non-circular). Formula only — the prevHashNonce header-hash retag, the
      candidate-freeze window, and folding a real epoch are chain-data slices
      (parts 2 + 3), deliberately not claimed here.
- [x] Chain-following over the stored contiguous preprod run (DoD line 3,
      part 2 of 3): `src/chain.rs` `verify_segment(blocks, eta0)` composes the
      Blake2b256 header link (`prev_hash == parent.block_hash`) with the full
      per-header crypto (opcert → leader-VRF vs the epoch nonce → KES) already
      proven per-vector. The 22 preprod vectors were BlockFetched as one range,
      so they are one unbroken epoch-300 segment (block numbers 4921916..=4921937);
      `HeaderView` now surfaces `prev_hash` + `block_hash`, both byte-identical to
      pallas. Positive: the stored run verifies end-to-end against its named nonce
      and Sextant's decoded fields witness +1 block numbers / strictly-increasing
      slots. Negative: reorder / drop / splice → `BrokenLink`; per-field tamper →
      the matching opcert/VRF/KES failure at that block; wrong epoch nonce →
      leader-VRF rejects block 0; malformed block → `Decode` at its index. No
      harvest needed — the harvested range was already contiguous.
- [x] REAL BOUNDARY (DoD line 3, part 3 of 3 — closes the DoD line): `tools/harvest
      boundary` BlockFetched a contiguous 10-block preprod run across the 299→300
      turn (slots 127958330..=127958607; turn at 127958489) into `boundary-*.block`
      + per-epoch `.eta0` sidecars. `tests/boundary.rs` splits the run at its single
      nonce switch and, reusing `chain::verify_segment` once per side, verifies each
      block's leader-VRF against ITS epoch η0 (pre → η0(299) `9adf4f5b…f4e0b2`, post
      → η0(300) `aa845533…4eeb6c30`), proves the boundary links by hash (last-299
      `block_hash` == first-300 `prev_hash`, +1 height) and that swapping in the
      WRONG epoch's nonce makes leader-VRF reject at block 0 on BOTH sides — the
      on-chain proof η0 evolved. No lib change: the per-epoch nonce switch is a
      test-level composition of the existing primitive. `boundary-` prefix keeps
      these out of part 2's single-epoch preprod sweep; the all-`*.block`
      decode/VRF sweeps auto-verify them against pallas.
- [x] Mithril certificate hashing (DoD line 4, part 1 of N): `src/mithril.rs`
      (behind an OFF-by-default `mithril` cargo feature so the wasm/default lib
      graph stays lean) defines the certificate entity structs and the byte-exact
      SHA-256 `compute_hash` fns (ProtocolParameters U8F24 `phi_f`, metadata
      RFC3339-nanos, ProtocolMessage in enum order, Certificate feeding the wire
      avk/multi_sig strings directly). Harvest a real preprod certificate segment
      (`tools/harvest mithril`, aggregator `release-preprod`) as JSON vectors;
      prove `Certificate::compute_hash` == the aggregator's own `hash` on every
      vector and that each cert's `previous_hash` == its parent vector's computed
      hash (self-authenticating chain links), plus the golden `phi_f=0.7 ->
      11744051`, verdict byte-identical to `mithril-common`'s hasher. Signature
      verification (genesis Ed25519 anchor, STM multi-sig, AVK binding, full
      chain-walk to genesis) are the subsequent Mithril slices.
- [x] Mithril chain-linking + AVK binding (DoD line 4, part 2 of N, PR #11):
      `src/mithril.rs::verify_chain` walks a cert segment oldest→newest checking
      each cert's integrity (`compute_hash == hash`), `previous_hash` linkage, and
      the AVK binding (child AVK == the `next_aggregate_verification_key` the parent
      committed one epoch earlier). Non-vacuous negatives (broken link / reorder /
      splice / tamper / AVK-substitution); feature-gate clean (0 blst in default+wasm).
- [x] Mithril GENESIS ANCHOR (DoD line 4, part 3 of N): the trust root the chain
      terminates in. `src/mithril.rs::verify_genesis(cert, genesis_vkey)` requires
      the cert be a genesis cert (carries a genesis signature), that its
      `signed_message` binds its protocol message (`signed_message ==
      protocol_message.compute_hash()`, so the signature transitively commits the
      genesis AVK), and that the 64-byte Ed25519 `genesis_signature` verifies under
      the pinned per-network genesis vkey over `signed_message.as_bytes()` (the ASCII
      hex) on Sextant's own libsodium-strict `ed25519::verify`. New `tools/harvest
      mithril-genesis` walks tip→genesis (release-preprod re-genesis is at epoch 196,
      105 hops), checking in ONLY the genesis cert (`mithril-genesis-cert.json` hash
      `69bc3bdf…af7ad59`), its immediate child (`mithril-genesis-child.json`), and the
      decoded genesis vkey (`mithril-genesis.vkey` = `7f497ca1…cd27eb2c`). Proven: the
      real genesis cert verifies, verdict byte-identical to pallas-crypto's
      independent (cryptoxide) Ed25519 on the same (vkey, msg, sig); the message
      format was empirically pinned (only `signed_message.as_bytes()` verifies, not
      the 32 raw bytes); tampered sig / wrong vkey / swapped protocol message / a
      standard cert / malformed sig each reject with a distinct verdict; and
      `verify_chain([genesis, child])` accepts — the genesis root authorizes the next
      epoch's signer set (one hop of the chain of trust). No new crate (reuses
      `ed25519`); Cargo.lock adds 0; mithril feature keeps it out of default+wasm.
      STM multi-sig verify + the full tip→genesis walk close the DoD line.
- [x] Mithril STANDARD-cert STM multi-signature verify (DoD line 4, part 4 of N):
      `src/mithril.rs::verify_standard(cert)` authorizes a *standard* certificate by
      its stake-based threshold multi-signature. Sextant owns the wire path — hex→JSON
      deserialize of `aggregate_verification_key`
      (`AggregateVerificationKeyForConcatenation` → `AggregateVerificationKey::new`) and
      `multi_signature` (`AggregateSignature`), `Parameters{m,k,phi_f}` assembly from the
      cert metadata, and the `signed_message == protocol_message.compute_hash()` binding
      (the shared guard, now factored and reused by `verify_genesis`) — and COMPOSES
      `mithril-stm` 0.10.5 (`num-integer-backend`, off wasm) for the BLS aggregate /
      lottery-eligibility / Merkle-batch verify over `signed_message.as_bytes()`, exactly
      as `curve25519-dalek` is composed for the header VRF. All 12 real preprod standard
      multi-signatures verify; wrong message / wrong AVK → `InvalidMultiSignature`, swapped
      protocol message → `MessageMismatch`, genesis cert → `NotStandard`, malformed blobs →
      `MalformedAvk`/`MalformedSignature`. mithril-stm is the sole STM implementation, so
      the oracle is the real on-chain multi-signatures themselves (unforgeable threshold
      BLS), not a second library. Feature-gated: `cargo tree -e normal` shows 0
      blst/mithril-stm in default+wasm. The full tip→genesis walk (`verify_chain_anchored`)
      composing genesis + AVK-binding + per-cert `verify_standard` is part 5 (closes DoD line 4).

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
| 2026-07-11 14:55 UTC | Nonce-evolution FORMULA (DoD line 3, part 1): Sextant's own `src/nonce.rs` (`⭒` combine, `Blake2b256(Blake2b256(0x4E‖vrf))` per-block contribution, rolling fold, epoch combine) is byte-exact to pallas-crypto's independent nonce implementation and its golden vectors | `cargo test --test nonce` — `epoch_nonce_matches_pallas_test_epoch_nonce` (golden + live `generate_epoch_nonce`), `combine_and_fold_match_pallas_test_rolling_nonce` (30-block shelley-seed golden), `praos_evolve_matches_pallas_rolling_on_real_preprod_vectors` (≥20 real preprod VRF outputs vs `generate_rolling_nonce`, fed the test-assembled `Blake2b256(0x4E‖vrf)`; also pins the double-hash decomposition), `block_contribution_is_praos_double_hash_with_tag` (≠ single hash, ≠ inner-only, ≠ wrong tag), `combine_is_order_sensitive_and_extra_entropy_is_optional`. `scripts/harness.sh --full` exit 0, 36 tests (13 header + 4 kes + 5 nonce + 4 opcert + 10 vrf) |
| 2026-07-11 15:05 UTC | Slice 7 (Praos nonce-evolution formula) merged to main with red-team SHIP | PR #7 squash-merged (`6d5a435`), CI `ci/woodpecker/pr/harness` green (pipeline 63). `fluxpoint-loop:red-team-reviewer` VERDICT SHIP — no CRITICAL/HIGH/MEDIUM/LOW: `combine` byte layout `left32‖right32` (order load-bearing, pinned by golden + order-sensitivity test); `0x4E` tag correct/prepended and a genuine double hash (≠ TPraos single, ≠ inner-only, ≠ wrong tag); differential oracle non-circular (the extended input `Blake2b256(0x4E‖vrf)` is assembled with pallas's own hasher, so a wrong tag/order/hash-count in the code under test diverges — green assertion on 22 real vectors transitively pins pallas's `generate_rolling_nonce` shape); golden vectors match pallas 1.1.1 live; no panic/DoS (all fixed-width buffers, no lib-path unwrap); no overclaim (FORMULA-only, parts 2+3 deferred); alloc-free, clippy clean |
| 2026-07-11 15:18 UTC | Independent red-team of the autonomously-merged nonce formula: VERDICT SHIP — validates the pre-loop spec workflow | Fresh `fluxpoint-loop:red-team-reviewer` + operator 3× flaky-check: `0x4E` double-hash byte-exact vs a THIRD independent impl (raw `blake2` crate, bypassing both `hash.rs` and pallas) — all four wrong shapes diverge (tag + double-hash both load-bearing); differential oracle non-circular (real pallas golden constants, independent Blake2b, trap workaround proven constraining); combine order/commutativity/neutral correct; no regression; 500k ops no panic; honestly scoped. The workflow's `0x4E` correction prevented a wrong single-hash formula from shipping |
| 2026-07-11 15:33 UTC | Chain-following (DoD line 3, part 2): the stored 22-block preprod run is a hash-linked, fully crypto-verified epoch-300 segment on Sextant's own path (block numbers 4921916..=4921937); `HeaderView.block_hash`/`prev_hash` byte-identical to pallas | `cargo test --test chain` — `preprod_run_is_a_contiguous_verified_chain` (≥20 blocks; `chain::verify_segment` composes the Blake2b256 link + opcert + leader-VRF vs eta0 + KES; Sextant's decoded fields witness +1 block numbers / strictly-increasing slots; verified against named η0(300) `aa845533…4eeb6c30`), `block_hash_and_prev_hash_match_pallas`, `reordered_segment_is_rejected` + `dropped_block_breaks_the_chain` (`BrokenLink`), `tampered_block_in_segment_is_rejected` (opcert-sigma→`OpCert`, vrf_proof→`Vrf`, body_signature→`Kes`, each at the tampered index), `wrong_epoch_nonce_rejects_the_segment` (`Vrf` at block 0), `malformed_block_is_reported_at_its_index` (`Decode`). `scripts/harness.sh --full` exit 0, 43 tests (7 chain + 13 header + 4 kes + 5 nonce + 4 opcert + 10 vrf) |
| 2026-07-11 15:40 UTC | Slice 8 (chain-following) merged to main with red-team SHIP | PR #8 squash-merged (`5ca3618`), CI `ci/woodpecker/pr/harness` green (pipeline 69). `fluxpoint-loop:red-team-reviewer` VERDICT SHIP — no CRITICAL/HIGH/MEDIUM/LOW: `block_hash` span is byte-exact `HashHeader` (array-2 token + full body_signature, no off-by-one; pallas-parity on all 22), reorder/gap/splice all break `BrokenLink` and the link transitively pins block_number+slot (test-only monotonicity assertion is honest, not a gap), every block incl. index 0 runs opcert→VRF→KES, `eta0` is a byte-input (safety-preserving), no reachable panic/unwrap/unsafe and O(1) memory, all 5 `ChainError` variants reachable+tested, DoD line 3 correctly left UNCHECKED. Two INFO, both out of scope (vrf_output↔proof identity is KES-covered / needed only in part 3; first-block anchoring is the Mithril slice). `scripts/harness.sh --full` exit 0 on merged main |
| 2026-07-11 15:49 UTC | Independent red-team of the autonomously-merged chain-following slice: VERDICT SHIP | Fresh `fluxpoint-loop:red-team-reviewer` + operator 3× flaky-check: `block_hash` byte-identical to pallas's real header hash on all 22 (hashes the `[header_body, body_signature]` span, not `[era,block]`); no block (incl. index 0) escapes opcert+VRF+KES; negatives non-vacuous (reorder/drop/splice→BrokenLink, per-field tamper→matching error, wrong eta0→`Vrf{0}`); no regression, 2000 mutations no panic, deterministic, honest scope (eta0 is input) |
| 2026-07-11 16:40 UTC | REAL BOUNDARY (DoD line 3, part 3 — closes line 3): a stored contiguous preprod run across the epoch 299→300 turn proves η0 evolved; each side's leader-VRF is bound to its own epoch nonce and rejects the other's | `cargo run -p harvest boundary` BlockFetched 10 blocks (slots 127958330..=127958607, turn at 127958489) → `boundary-<slot>.block` + `.eta0`; last-299 slot 127958384 carries η0(299) `9adf4f5b…f4e0b2`, first-300 slot 127958489 carries η0(300) `aa845533…4eeb6c30`. `cargo test --test boundary` — `boundary_run_crosses_epoch_299_to_300_and_the_nonce_evolved` (verify_segment(pre, η0(299)) Ok, verify_segment(post, η0(300)) Ok, boundary links by hash + `+1` height + slot advance, names evolved η0(300)), `each_side_rejects_the_other_epochs_nonce` (verify_segment(pre, η0(300)) and verify_segment(post, η0(299)) both `Vrf{index:0}`). `scripts/harness.sh --full` exit 0, 45 tests (2 boundary + 7 chain + 13 header + 4 kes + 5 nonce + 4 opcert + 10 vrf); the all-`*.block` decode + VRF-output sweeps auto-verify the 10 new vectors against pallas. No `src/` change — the per-epoch nonce switch is a test-level composition of `chain::verify_segment` |
| 2026-07-11 16:21 UTC | Slice 9 (real 299→300 boundary) merged to main with red-team SHIP — DoD line 3 CLOSED | PR #9 squash-merged (`3268daa`), CI `ci/woodpecker/pr/harness` green (pipeline 75). `fluxpoint-loop:red-team-reviewer` VERDICT SHIP — no CRITICAL/HIGH/MEDIUM/LOW: split clean 5/5 monotone (`[A,B,A,B]` trips "spans more than two epochs", both sides guarded non-empty); rejection is specifically leader-VRF at index 0 (opcert+KES nonce-independent, so correct-nonce Ok proves opcert passes → swapped η0 fails only VRF → `Vrf{0}` guaranteed, not an artifact); mis-tag-proof (a wrong sidecar η0 or `slot>=turn_slot` off-by-one fails its own `verify_segment.expect`, so the crypto subordinates the untrusted harvest; turn block 127958489 correctly epoch-300); η0 is a pinned input, wrong η0 only rejects (liveness) never false-accepts (safety); boundary is a real link (prev_hash==block_hash, +1 height) and the all-`*.block` VRF sweep independently confirms all 10 are genuine preprod headers; trust substrate untouched (zero `src/`/`Cargo` diff, `harvest` is `publish=false`, `boundary-` prefix isolates the `preprod-`-scoped sweeps). `scripts/harness.sh --full` exit 0 on merged main, working tree clean |
| 2026-07-11 16:29 UTC | Independent red-team of the autonomously-merged real-boundary slice: VERDICT SHIP — DoD line 3 soundly closed | Fresh `fluxpoint-loop:red-team-reviewer` + operator 3× flaky-check: genuine cryptographic mutual rejection (epoch-300 block's leader-VRF returns Err under η0(299) via real `alpha` divergence — NOT a nonce-inequality shortcut); real boundary at `firstSlotOf(300)=127,958,400` (Byron offset accounted); contiguous hash-linked run; no overclaim (Koios η0 is input); no regression, deterministic. Consensus-verification core (DoD lines 2+3) now complete |
| 2026-07-11 18:05 UTC | Mithril certificate hashing (DoD line 4, part 1): Sextant's own `Certificate::compute_hash` (`src/mithril.rs`, `mithril` feature) reproduces the preprod aggregator's committed `hash` byte-exactly on 12 real certificates, and each `previous_hash` is the parent's recomputed content hash | `cargo test --features mithril` — `tests/mithril.rs::certificate_hash_matches_aggregator` (12 certs: 11 `MithrilStakeDistribution` + 1 `CardanoTransactions`), `previous_hash_links_to_parent_content` (≥10 in-segment links), `tampered_certificate_breaks_the_hash`; module unit goldens vs mithril-common's own test vectors: `protocol_parameters_hash_matches_mithril_golden` (`ace019…`), `certificate_metadata_hash_matches_mithril_golden` (`f16631…`), `phi_f_fixed_point_golden` (0.7→11744051). Vectors harvested by new `cargo run -p harvest mithril` (aggregator `release-preprod`). `scripts/harness.sh --full` exit 0, 52 tests; the wasm build is a cached no-op (mithril feature OFF by default → no serde/chrono/json in the default+wasm graph; Cargo.lock adds 0 crates) |
| 2026-07-11 18:11 UTC | Part 1 (Mithril cert hashing) merged; independent red-team VERDICT SHIP | PR #10 squash-merged (`fbbf947`), CI green (pipeline 84). Independent `fluxpoint-loop:red-team-reviewer` + operator 3× flaky-check: a from-scratch THIRD reimplementation of the cert hash equals both the aggregator's committed `hash` AND Sextant's `compute_hash` on all 12 real certs (both entity types), `phi_f` U8F24 golden reproduced; oracle non-tautological (3 independent computations agree); feature-gate clean (0 mithril/serde/chrono/blst in default+wasm graph); 200k fuzz no panic; honest scope (hashing only). The loop opened + self-red-teamed the PR but ran out of turns before merging — merged here. Next: part 2 = genesis-anchored chain-walk + STM multi-sig (blst enters, feature-gate keeps it off wasm) |
| 2026-07-11 18:35 UTC | Part 2 (Mithril chain-linking + AVK binding) merged; independent red-team SHIP | PR #11 squash-merged (`a95cfd6`), CI green (pipeline 89). `src/mithril.rs::verify_chain` walks a cert segment recomputing each content hash and checking `previous_hash == parent.compute_hash()` (transitive: the integrity check runs per-cert first, so a parent lying about its own hash is caught before it can link — red-team proved → `Err(Hash{5})`), plus AVK binding (child AVK == parent's committed `next_aggregate_verification_key`). Non-vacuous negatives (broken link/reorder/splice/tamper/AVK-sub); feature-gate clean (0 blst in default+wasm); 50k mutations no panic. Genesis Ed25519 anchor + STM multi-sig are parts 3+4. Carried: link check could be `!= parent.compute_hash()` directly for a local (order-independent) guarantee |
| 2026-07-11 19:35 UTC | Mithril GENESIS ANCHOR (DoD line 4, part 3): the real preprod genesis certificate (the trust root) verifies on Sextant's own libsodium-strict Ed25519 path under the pinned network genesis vkey; verdict byte-identical to pallas-crypto's independent cryptoxide backend | `cargo test --test mithril --all-features` — `real_preprod_genesis_certificate_verifies` (names hash `69bc3bdfff0bb134675396e83b301f43e763d576d4b85856f6b3cb806af7ad59`, epoch-196 re-genesis; asserts self-hash + empty `previous_hash` + `is_genesis`), `genesis_verdict_matches_independent_oracle` (Sextant `ed25519::verify` == `pallas_crypto` `PublicKey::verify` on genuine + 1-bit-flip), `tampered_genesis_certificate_is_rejected` (sig-flip/wrong-vkey → `InvalidSignature`, swapped protocol message → `MessageMismatch`, standard cert → `NotGenesis`, malformed hex → `MalformedSignature`), `genesis_anchors_its_child` (`verify_chain([genesis, child])` Ok, tip == child hash `fc979366…`). Message format empirically pinned (only `signed_message.as_bytes()` verifies, 32 raw bytes do not). `verify_genesis` composes existing `ed25519::verify` + `protocol_message.compute_hash()` binding; `tools/harvest mithril-genesis` walked tip→genesis (105 hops) to pin the anchor. `scripts/harness.sh --full` exit 0, 63 tests; Cargo.lock adds 0 crates (mithril feature keeps it out of default+wasm) |
| 2026-07-11 19:50 UTC | Slice 11 (Mithril genesis anchor) merged to main with red-team SHIP | PR #12 squash-merged (`5eac799`), CI `ci/woodpecker/pr/harness` green (pipeline 94). `fluxpoint-loop:red-team-reviewer` VERDICT SHIP — no CRITICAL/HIGH/MEDIUM/LOW: the `signed_message == protocol_message.compute_hash()` guard pins the genuine protocol message (hence NextAVK) by SHA-256 second-preimage, so a detach/AVK-swap keeping the genuine signature is rejected `MessageMismatch`; Sextant's `ed25519::verify` ⊇ dalek `verify_strict` on every adversary-reachable encoding (the one gap — small-order-R — is keyholder-only, i.e. the genesis key itself), so no forged-cert false-accept; `decode_hex_64` guards `len!=128` before indexing and returns `MalformedSignature` on odd/non-hex/huge, zero panic/unwrap/unsafe in the production genesis path; a 1-bit-flipped vkey rejects (no self-authentication circularity); scope honest (STM multi-sig + full walk deferred, DoD line 4 UNCHECKED). 3 INFO carried: (1) optional small-order-R fixture to pin the divergence direction, (2) factor the shared `signed_message`↔`protocol_message` guard when part 4 lands, (3) confirm mithril-common's genesis-verify strictness. `scripts/harness.sh --full` exit 0 on merged main |
| 2026-07-11 21:14 UTC | Mithril STANDARD-cert STM multi-signature verify (DoD line 4, part 4): all 12 real preprod standard certificates are authorized by a valid STM multi-signature verified on Sextant's own path; every tamper rejects with a distinct verdict | `cargo test --features mithril --test mithril` — `real_preprod_multi_signatures_verify` (12 standard certs; `verify_standard` composes hex→JSON AVK/sig deserialize + `Parameters{m,k,phi_f}` + the `signed_message==protocol_message.compute_hash()` binding + `mithril_stm::AggregateSignature::verify` over `signed_message.as_bytes()`), `multi_signature_binds_message_and_avk` (A's sig over B's message → `InvalidMultiSignature`; A's sig under B's AVK → `InvalidMultiSignature`), `tampered_standard_certificate_is_rejected` (genesis→`NotStandard`, swapped proto-msg→`MessageMismatch`, malformed hex→`MalformedSignature`/`MalformedAvk`). `mithril-stm` 0.10.5 (`num-integer-backend`) composed for the BLS/lottery/Merkle-batch check; `cargo tree -e normal` = 0 blst in default graph, present only under `--features mithril`. `scripts/harness.sh --full` exit 0 (fmt, clippy --all-features, release build, all tests incl. 10 mithril, wasm32 build). D = `MithrilMembershipDigest` (Blake2b-256 Merkle commitment); message format empirically pinned to `signed_message.as_bytes()` (the 12 real sigs verify only under it) |
| 2026-07-11 21:35 UTC | Slice 12 (Mithril standard-cert STM multi-signature verify) merged to main with red-team SHIP | PR #13 squash-merged (`2912ddf`), CI `ci/woodpecker/pr/harness` green (pipeline 100; push pipeline 99 also green — CI compiled blst under `--all-features`, so no CI toolchain change was needed). `fluxpoint-loop:red-team-reviewer` VERDICT SHIP — no CRITICAL/HIGH/MEDIUM/LOW across all 8 attack areas: the `signed_message==protocol_message.compute_hash()` guard is load-bearing and correctly ordered (before curve work), so a NextAVK swap keeping the genuine signature is rejected `MessageMismatch`; message format validated by unforgeable ground truth (12 real threshold-BLS sigs verify only under `signed_message.as_bytes()`); dual genesis+multi cert fails closed `NotStandard`; no reachable panic/DoS (`decode_hex` bounded, `verify` returns Result, zero production callers yet); negatives non-vacuous (would fail if `verify_standard` returned Ok); feature-gate clean (0 blst/mithril-stm in default+wasm, `num-integer-backend` avoids GMP); deterministic tests, shared guard has two callers (not single-caller), no dead code. 2 INFO carried to part 5: (1) `verify_chain_anchored` must run the `compute_hash()==hash` integrity check before/with `verify_standard` (pins attacker-chosen `k/m/phi_f`) OR `verify_standard` reject `k==0`/`m==0`/`phi_f∉(0,1]`; (2) add adversarial-input tests for the mithril-stm serde path (invalid curve points, mismatched array lengths, oversized arrays) when the untrusted caller lands. `scripts/harness.sh --full` exit 0 on merged main, working tree clean |
| 2026-07-11 20:10 UTC | Independent red-team of the autonomously-merged genesis anchor: VERDICT SHIP — trust root genuinely pinned | Fresh `fluxpoint-loop:red-team-reviewer` + operator 3× flaky-check: genesis vkey pinned from the OFFICIAL IOG repo (`7f497ca1…` `release-preprod/genesis.vkey`, NOT the aggregator) — real re-genesis cert (epoch 196) verifies only under it, not hollow; real strict Ed25519 (256 vkey bit-flips + tamper/non-genesis/malformed all reject, matches pallas); `signed_message` binds the genesis AVK; 30k fuzz no panic; honest scope. **Part 4 roadmap (from red-team): (a) STM multi-sig verify via mithril-stm (feature-gated, keeps blst off wasm); (b) `verify_chain_anchored(certs, vkey)` requiring `certs[0]` to be a verified genesis + each standard cert's STM multi-sig; (c) pin the genesis vkey as a lib constant, not just a test vector** |

## Notes for the next iteration
State (2026-07-11): **Mithril STANDARD-cert STM multi-signature verify shipped**
(DoD line 4, part 4 of N). `src/mithril.rs::verify_standard(cert)` authorizes a
standard certificate by its STM (stake-based threshold multi-signature): it requires
the cert be standard (has a `multi_signature`, not a genesis cert), that
`signed_message == protocol_message.compute_hash()` (the **shared guard**, now factored
onto `Certificate::signed_message_binds_protocol_message` and reused by `verify_genesis`),
and that `mithril_stm::AggregateSignature::verify(signed_message.as_bytes(), &avk, &params)`
succeeds. Sextant owns the wire path: hex→JSON deserialize of the AVK
(`AggregateVerificationKeyForConcatenation<D>` → `AggregateVerificationKey::new`) and the
multi-signature (`AggregateSignature<D>`), and `Parameters{m,k,phi_f}` assembly from
`metadata.parameters`. `D = MithrilMembershipDigest` (Blake2b-256 Merkle commitment).
The BLS aggregate / lottery / Merkle-batch check is the **composed** `mithril-stm` 0.10.5
primitive (`num-integer-backend`, NEVER rug/snark), exactly as curve25519-dalek is composed
for the header VRF. **mithril-stm is the sole STM implementation in existence**, so unlike
VRF/KES/Ed25519 there is no independent second-impl oracle — the oracle is the 12 real
on-chain multi-signatures themselves (a threshold BLS signature no adversary can forge),
plus non-vacuous tamper rejection. **Feature-gated**: `cargo tree -e normal` shows 0
blst/mithril-stm in the default+wasm graph; only `--features mithril` (host clippy/test)
pulls blst. Cargo.lock added 17 crates (blst, num-bigint/integer/rational, rayon, etc.),
all under the mithril feature. The message format was empirically pinned:
`signed_message.as_bytes()` (ASCII hex) is what verifies, matching the genesis path.

**Attacking next — DoD line 4, part 5: the full tip→genesis walk (`verify_chain_anchored`)
that CLOSES the line.** Compose the three verifiers already built into one bytes-in/
verdict-out control flow: given a certificate segment (tip→…→genesis) and the pinned
genesis vkey, walk oldest→newest requiring `certs[0]` be a verified genesis
(`verify_genesis`), each subsequent standard cert's STM multi-sig (`verify_standard`), and
the hash-link + AVK-binding between adjacent certs (`verify_chain`'s logic). DoD line 4
proof = a test that verifies a real preprod chain terminating in the genesis anchor and
NAMES the tip certificate hash; negatives (a broken link / substituted AVK / tampered
multi-sig / wrong genesis vkey anywhere in the walk) each reject. The harvester already
proved the full walk is tractable (release-preprod re-genesis at epoch 196, 105 hops);
part 5 can either (a) check in a longer contiguous segment via a new
`tools/harvest mithril-chain <depth>` mode, or (b) compose over the existing 12 standard
`mithril-cert-*.json` (epochs 290–300, already hash-linked) plus the genesis cert+child —
decide in the slice. NOTE: the 12 standard vectors are one contiguous epoch-290→300 run
but do NOT reach genesis; option (a) (a real tip→genesis segment) is the honest close.

**Two hardening items the part-4 red-team carried into part 5 (do BOTH in the walk slice):**
1. **Parameter integrity.** `verify_standard` trusts the cert's own `k/m/phi_f` as-is; standalone
   that lets an attacker-chosen `k=0`/`phi_f=1.0` weaken the threshold. Closed only because
   `verify_chain`'s `compute_hash()==hash` check pins those params to the aggregator's committed
   hash. So `verify_chain_anchored` MUST run the integrity check (`compute_hash()==hash`) before or
   alongside `verify_standard` for every cert — OR add a fail-closed guard in `verify_standard`
   rejecting `k==0`/`m==0`/`phi_f∉(0,1]`. Do not wire an untrusted caller without one of these.
2. **Adversarial serde-input coverage.** The part-4 negatives cover malformed hex / wrong message /
   wrong AVK / swapped protocol message / genesis+dual shapes, but NOT valid-JSON-invalid-curve-points,
   mismatched STM array lengths, or oversized `indexes`/`signatures` arrays. Add these hostile-input
   tests against `verify_standard` (assert clean `Err`, no panic/hang/unbounded alloc) when part 5
   introduces the untrusted-bytes entry point.

Prior state (2026-07-11): **Mithril GENESIS ANCHOR shipped** (DoD line 4, part 3 of N).
`src/mithril.rs::verify_genesis(cert, &genesis_vkey)` verifies the chain's trust
root: it requires the cert be a genesis cert (`is_genesis` = non-empty
`genesis_signature`), that `signed_message == protocol_message.compute_hash()` (so
the signature transitively commits the genesis AVK — a swapped protocol message is
rejected `MessageMismatch`), and that the 64-byte Ed25519 `genesis_signature`
verifies under the pinned per-network genesis vkey over `signed_message.as_bytes()`
(the ASCII hex, NOT the 32 raw bytes — empirically pinned) on Sextant's own
libsodium-strict `ed25519::verify`. Reuses the existing ed25519 substrate — **no
new crate, Cargo.lock adds 0**, all under the `mithril` feature (out of default +
wasm). `tools/harvest mithril-genesis` walked tip→genesis (release-preprod
**re-genesis is at epoch 196**, 105 hops) and checked in only the genesis cert
(`mithril-genesis-cert.json`, hash `69bc3bdf…af7ad59`), its immediate child
(`mithril-genesis-child.json`), and the decoded genesis vkey (`mithril-genesis.vkey`
= `7f497ca1…cd27eb2c`, the mithril-repo published key, reviewed in-PR). Proven on
the real cert: verifies, verdict byte-identical to pallas-crypto's independent
cryptoxide Ed25519; five distinct rejections; and `verify_chain([genesis, child])`
Ok — the genesis root authorizes the next epoch's signer set (one hop). Message
binding is included defensively (matches mithril intent: `signed_message` IS the
protocol-message hash); a red-team should confirm mithril-common's genesis verify
is no stricter.

**Attacking next — DoD line 4, part 4: STM multi-signature verify** (then part 5:
the full tip→genesis walk that closes the line). The genesis anchor is the root for
*genesis* certs; every *standard* cert rides on an STM multi-signature over its
`signed_message` under its AVK. Compose `mithril-stm` (see the "Attacking next"
block below for the exact feature flags — `num-integer-backend`, NEVER `rug`/`snark`;
blst `portable`), implement `verify_standard` (multi-sig verify + AVK-binding +
`signed_message == protocol_message.compute_hash()`), oracle = `mithril-common`'s
`ProtocolMultiSignature::verify`. Keep it under the `mithril` feature so blst stays
out of wasm. NOTE: the `verify_genesis` message-binding check is exactly the
standard-cert `signed_message`↔`protocol_message` check — factor the shared guard
when part 4 lands (avoid a second copy). The 12 `mithril-cert-*.json` standard-cert
vectors already carry real `multi_signature` blobs to verify against.

Prior state (2026-07-11): **Mithril certificate HASHING shipped** (DoD line 4, part 1
of N). `src/mithril.rs` (behind the OFF-by-default `mithril` cargo feature)
decodes an aggregator certificate on Sextant's own path and recomputes its
content hash byte-exactly to `mithril-common`: the four nested SHA-256 hashes
(`ProtocolParameters` with `k`/`m` BE-u64 + `phi_f` as a `U8F24` round-ties-even
`u32`; `CertificateMetadata` with chrono BE-i64 nanosecond timestamps + per-signer
`party_id‖BE(stake)`; `ProtocolMessage` iterated in `ProtocolMessagePartKey`
**enum order**, not JSON order; `Certificate` feeding the wire avk/multi_sig/
genesis_sig strings directly, standard-cert path binding `signed_entity_type`).
Proven on 12 real preprod certs (`cargo run -p harvest mithril`, aggregator
`release-preprod`) — all match the aggregator's own committed `hash`, and each
`previous_hash` is the parent's recomputed hash — plus mithril-common's own unit
goldens (`ace019…`, `f16631…`, phi_f 0.7→11744051). Feature-gated so the default
+ wasm graph is unchanged (**Cargo.lock adds 0 crates**; serde/serde_json/chrono
were already resolved via existing dev-deps).

**Design point (a) — tip→genesis walk depth — RESOLVED by the part-3 harvest.**
The walk is NOT hundreds of hops: release-preprod **re-genesised at epoch 196**, so
genesis is reached in 105 hops from the current tip (not near epoch 0). `tools/harvest
mithril-genesis` does the full walk once, checking in only the genesis cert + child +
vkey; the aggregator retains the chain that far, no pruning hit. So the full-walk path
(not the bounded-segment alternative) is what part 5 composes — the harvest tool
already proves it's tractable. **Design point (b) — STM multi-sig — still open** (part
4): pulls `mithril-stm`+blst, keep under the `mithril` feature (off in wasm); add
`apt-get install -y clang` to CI only if Mithril-in-wasm is later wanted.
`SignedEntityType` / `ProtocolMessagePartKey` model only the variants seen in real
vectors — a cert with another tag is a clean deserialize error, extend with its own
vector then.

Prior state (2026-07-11): **REAL BOUNDARY shipped — DoD line 3 is CLOSED** (slice
9, part 3 of 3). `cargo run -p harvest boundary` (new mode in `tools/harvest`)
BlockFetched a contiguous 10-block preprod run across the epoch 299→300 turn
(slots 127958330..=127958607, turn at 127958489) into `boundary-<slot>.block` +
per-epoch `.eta0` sidecars: the last epoch-299 block (127958384) carries η0(299)
`9adf4f5b…f4e0b2`, the first epoch-300 block (127958489) carries η0(300)
`aa845533…4eeb6c30` — the same evolved value part 2 pinned. `tests/boundary.rs`
splits the run at its single nonce switch and, reusing `chain::verify_segment`
once per side, proves: each side verifies against ITS epoch nonce; the boundary
links by hash (last-299 `block_hash` == first-300 `prev_hash`, `+1` height, slot
advances); and swapping in the WRONG epoch's nonce makes leader-VRF reject at
block 0 on BOTH sides. **No `src/` change** — the per-epoch nonce switch is a
test-level composition of the existing primitive, so no single-caller abstraction
was added. The `boundary-` prefix isolates these from part 2's single-epoch
preprod sweep, while the all-`*.block` decode + VRF-output sweeps auto-verify them
against pallas.

**DoD line 3 (Chain following across an epoch boundary, incl. nonce evolution) is
now checked**, PROVEN on preprod — the operator-chosen testnet for this whole
client (Plan line 46). The "preview" wording in line 3 is the documented
preprod substitution, not an unmet requirement; the evolved η0(300) is named in
the test. DoD line 3 parts 1 (formula, `src/nonce.rs`) + 2 (single-epoch chain,
`src/chain.rs`) + 3 (this real boundary) are all shipped.

Prior state (2026-07-11): **Nonce-evolution FORMULA shipped** (DoD line 3
part 1). `src/nonce.rs` exposes `combine(a,b)` (`⭒` = `Blake2b256(a‖b)`),
`block_nonce_contribution(&[u8;64])` (`Blake2b256(Blake2b256(0x4E‖vrf))`),
`evolve(&eta_v, &vrf_output)` (rolling fold) and `epoch_nonce(candidate,
prevHashNonce, Option<&[u8;32]> extra_entropy)` (epoch combine). All alloc-free
fixed-buffer over the shared `hash::blake2b256`; `pallas-crypto`'s `nonce` module
is the dev-only oracle (its `generate_epoch_nonce` IS `⭒`; its
`generate_rolling_nonce(prev,x)=Blake2b256(prev‖Blake2b256(x))` reproduces the
Praos fold when fed `Blake2b256(0x4E‖vrf)`). Trust-substrate normal-dep graph
unchanged. **Formula only** — no chain data consumed yet; the prevHashNonce
retag, candidate-freeze window, and a real epoch fold are parts 2 + 3.

Prior state (2026-07-11): KES body-signature verify shipped. DoD line 2's two
crypto halves — leader-VRF (slice 4) and KES (opcert slice 5 + KES body-sig slice
6) — are both proven on the 22 real preprod vectors, each byte-identical to an
independent pallas-family oracle.

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

## Attacking next — DoD line 4: Mithril genesis-anchored certificate-chain verify
Protocol independently derived from the mithril source (mithril-common 0.6.67 +
mithril-stm 0.10.5) and validated against a LIVE preprod certificate
(spec-derivation workflow, confidence HIGH). USE THIS.

COMPOSE the STM primitive, IMPLEMENT the chain-walk yourself (bytes-in/verdict-out):
- Compose `mithril-stm = { version = "0.10.5", default-features = false,
  features = ["num-integer-backend"] }` for the multi-sig verify only. NEVER
  enable `rug-backend` or `future_snark` (rug = GMP, breaks wasm). It rides blst
  `portable` (off-x86 OK). Differential oracle: `mithril-common` (dev-only) —
  its `CertificateVerifier::verify_certificate_chain`.
- Implement in `src/mithril.rs`: entity structs (Certificate, CertificateMetadata,
  ProtocolMessage = ordered map keyed by a ProtocolMessagePartKey enum,
  ProtocolParameters{k,m,phi_f}, CertificateSignature{ Genesis(hex) |
  Multi(SignedEntityType, json-hex) }); the 4 byte-exact SHA-256 hash fns
  (ProtocolParameters.compute_hash uses a U8F24 fixed-point `phi_f =
  round(phi_f*2^24) as u32-BE` — inline ~5 lines, do NOT pull `fixed`; golden
  check phi_f=0.7 -> 11744051; metadata: chrono RFC3339 nanoseconds as i64-BE;
  ProtocolMessage iterates in enum order; Certificate.compute_hash feeds the wire
  avk/multi_sig strings DIRECTLY, no re-serialize); the chain-walk (tip -> genesis
  via `previous_hash`) as Sextant control flow with an injected
  `get_certificate(prev_hash)` retriever (lib stays offline/sync; harvester/test
  supplies fetched bytes).
- GENESIS ANCHORING (the trust root, the crux): the walk terminates at a GENESIS
  cert whose `genesis_signature` is Ed25519 by the per-network GENESIS
  VERIFICATION KEY over the genesis AVK. Reuse `src/ed25519.rs` (gate to match
  mithril verify_strict). Fetch the preprod genesis vkey, pin it as a vector.
- AVK BINDING (chain of trust): each cert's protocol_message carries
  `NextAggregateVerificationKey` = next epoch's AVK; verify the CHILD cert's own
  `aggregate_verification_key` == what the PARENT signed, recursively to the
  genesis AVK. Plus previous_hash / epoch chaining as pure comparisons.
- STANDARD cert = STM multi-sig verify (`ProtocolMultiSignature::verify(
  signed_message, avk, params)` via mithril-stm) + AVK-binding + linking. GENESIS
  cert = Ed25519 genesis-sig. Follow 0.6.67 verify_standard (10 steps) /
  verify_genesis (5 steps) ordering.

WASM (harness gates `cargo build --target wasm32` — must stay green):
RECOMMENDED — put the Mithril verifier + `mithril-stm` behind a cargo feature
(`mithril`, OFF by default). `cargo test/clippy --all-features` exercise it on the
host (with the mithril-common oracle); the default lib build + the wasm build
EXCLUDE it, so the wasm artifact stays lean and dodges blst's wasm C-toolchain
(clang) need entirely. The harness already uses `--all-features` for test/clippy
and plain for the wasm build, so this composes cleanly. (Alt if you want Mithril
IN wasm: add `apt-get install -y clang` to `.woodpecker/harness.yml` + under
`cfg(target_family="wasm")` set `getrandom = {version="0.2", features=["js"]}` —
IOG's mithril-client-wasm proves blst->wasm works with clang.)

HARVEST + DoD proof: extend `tools/harvest` to fetch a real preprod certificate
CHAIN from the aggregator (base `https://aggregator.pre-release-preview.api.
mithril.network/aggregator` — CONFIRM; GET /certificates, /certificate/{hash},
walk `previous_hash` to a genesis cert) + the preprod genesis vkey; check them in
as JSON vectors. DoD line 4 proof = a test that verifies the chain to genesis and
NAMES the certificate hash; negatives (tampered multi-sig / broken previous_hash /
wrong genesis vkey / mismatched NextAVK) each reject; verdict byte-identical to
mithril-common's verifier.

Infra: Woodpecker CI green through pipeline 75; trust-substrate normal-dep graph
otherwise unchanged (feature-gate keeps mithril-stm out of the default/wasm graph).
