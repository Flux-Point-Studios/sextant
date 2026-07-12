# LOOP: Sextant — read-path verifying Cardano client (Rust core, C-ABI/WASM trust substrate)

STATUS: ACTIVE

## Definition of Done
Every line must be provably true, with the proof named. The Stop gate and
the outer loop only trust `scripts/harness.sh --full`; everything else
needs a row in Evidence.

- [ ] `scripts/harness.sh --full` exits 0
- [x] Header validation: decodes current-era headers and verifies leader
      VRF + KES against ≥20 golden vectors pulled from preview and
      mainnet, byte-identical verdicts to pallas on the same inputs —
      proof: named differential test run in harness output
      (PROVEN on merged main `3fb7d6a` — leader-VRF + opcert + KES verify
      byte-identical to the independent oracles on ≥20 real PREPROD (operator-chosen
      for preview, per Plan) AND 24 real MAINNET blocks (epoch 642, slots 192261567..
      192262175): `tests/{vrf,kes,opcert}.rs::real_{preprod,mainnet}_*_verify` +
      `*_verdict_matches_independent_oracle` + the all-`*.block` decode/output sweeps,
      all under `scripts/harness.sh --full`. VRF oracle = `cardano-crypto` (pallas
      ships no VRF); KES/opcert oracle = `pallas` Sum6Kes / cryptoxide Ed25519)
- [x] Chain following: validates a stored preview header sequence across
      an epoch boundary, including nonce evolution — proof: test run
      naming the epoch and the evolved nonce value
      (PROVEN on preprod — the operator-chosen testnet for this whole client,
      per Plan; `tests/boundary.rs::boundary_run_crosses_epoch_299_to_300_and_
      the_nonce_evolved` follows a stored contiguous run across the 299→300 turn
      and names the evolved η0(300) = `aa845533…4eeb6c30`, with each side's
      leader-VRF bound to its own epoch nonce and rejecting the other's)
- [x] Mithril: verifies a genesis-anchored certificate chain fetched from
      the network aggregator — proof: test naming the certificate hash
      (PROVEN on release-preprod; `tests/mithril.rs::real_preprod_genesis_anchored_
      chain_verifies` runs `mithril::verify_chain_anchored` over the real segment
      rooted in the epoch-196 re-genesis, naming the tip cert hash
      `fc979366…f2d56b72` and the genesis root `69bc3bdf…af7ad59`; the composed
      verifier requires the root be a genesis-key-signed anchor, each rising cert's
      STM multi-signature, and the hash-link + AVK-binding + integrity between them)
- [ ] UTxO verification for the read path designed and
      implemented (snapshot-anchored or proof-based — decide in a design
      slice first), with a negative test proving a tampered UTxO claim is
      rejected — proof: named test
- [x] Artifacts: single static lib + C header via cbindgen, and a wasm32
      build, both produced in CI — proof: release workflow run link
      (PROVEN on merged main `d743d9a` — `.woodpecker/artifacts.yml` builds
      `libsextant.a` + `include/sextant.h` (cbindgen, drift-gated by the harness)
      + `sextant.wasm`, and a CI-only C smoke test links the real static lib
      through the committed header on Linux; all Woodpecker contexts green, run
      https://ci.fluxpointstudios.com/repos/15/pipeline/122/1)
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
- [x] Mithril GENESIS-ANCHORED WALK (DoD line 4, part 5 of 5 — CLOSES the line):
      `src/mithril.rs::verify_chain_anchored(certs, genesis_vkey)` composes the three
      verifiers built across parts 2–4 into one bytes-in/verdict-out control flow — the
      segment's integrity + hash-linkage + AVK-binding (`verify_chain`), the root as the
      network genesis anchor (`verify_genesis`), and every rising cert's STM multi-signature
      (`verify_standard`) — returning the verified root/tip hashes or the offending cert's
      index (`AnchoredError::{Chain,Genesis,Standard}`). Proven on the real preprod segment
      rooted in the epoch-196 re-genesis (`[genesis, child]`, tip hash `fc979366…f2d56b72`);
      negatives (empty / wrong genesis vkey / non-genesis root / broken link / naive-integrity
      tamper / substituted AVK / tampered authority) each reject at the right layer + index.
      Integrity runs first, so a parameter-weakened forgery can't reach the multi-sig verify.
      Two part-4 red-team hardening items landed in `verify_standard`: (1) a degenerate-threshold
      guard (`k==0`/`m==0`/`phi_f∉(0,1]` → `WeakParameters`); (2) `guard_stm_bounds` closing
      TWO real mithril-stm DoS vectors the hostile-input tests surfaced — a signer claiming
      more stake than `total_stake` (eligibility Taylor series never converges) and `nr_leaves`
      near the u64 overflow (Merkle verify never terminates), both → `ImplausibleAvk` promptly.
      No new crate (composes existing ed25519/mithril-stm); mithril feature keeps it out of
      default+wasm.
- [x] Artifacts part 1 of 2 — C-ABI FFI surface + cbindgen header (DoD line 6):
      `src/ffi.rs` exposes the read-path verdicts over a minimal, allocation-free
      `extern "C"` surface — `sextant_abi_version`, `sextant_verify_segment` (the
      composed block-chain verdict), `sextant_header_decode` (fills a fixed
      `#[repr(C)] SextantHeaderView`), `sextant_status_message`, and (feature
      `mithril`) `sextant_mithril_verify_chain_anchored` — every fallible body
      wrapped in a cfg-split `guard()` (native `catch_unwind`, wasm no-op) so no
      panic crosses the boundary. A single flat `#[repr(i32)] SextantStatus` (all
      bands defined UNCONDITIONALLY so the header + numbering are feature-invariant;
      only the mithril FN is `#[cfg]`-gated) + a nullable
      `SextantErrorDetail{index,detail}` out-param carry every verdict + offending
      index with zero allocation. `cbindgen.toml` + committed `include/sextant.h`
      (mithril proto under `#if defined(SEXTANT_MITHRIL)`); harness gains a header
      drift-check (regenerate + `git diff --exit-code`) and a feature-leak grep (no
      `blst`/`mithril_stm` token in the header). `tests/ffi.rs` exercises every
      export from Rust on real vectors: good + tampered → right status+index, null/
      empty guards, header fields incl. genesis `has_prev_hash==0`, panic→`ErrPanic`,
      mithril good/tampered/bad-json. See the "## Attacking next" spec for the pinned
      signatures, the `SextantStatus` enum, and the struct layouts.
- [x] Artifacts part 2 of 2 — CI artifact production (CLOSES DoD line 6):
      `.woodpecker` builds and retains the three artifacts (`libsextant.a`,
      `include/sextant.h`, `sextant.wasm`) into `dist/` with a listing, so a green
      pipeline run link is the "produced in CI" proof; plus a CI-only C smoke test
      (`tests/smoke/smoke.c`) that compiles against `sextant.h`, links
      `libsextant.a`, and calls through the boundary (abi_version match + a tampered
      segment → nonzero code + `out_detail.index>=0`), proving external C linkage +
      symbol retention on the Linux artifact target. A durable downloadable release
      (plugin-release / `gh release`) needs a CI secret — deferred to the operator.
- [x] UTxO part 1a of 3 — SURFACE the certified transaction root (DoD line 5,
      proof-based certified-inclusion; operator-ratified). `mithril::verify_chain_anchored`
      / `VerifiedChain` (src/mithril.rs) already verify the tip cert but only returned
      `{root_hash,tip_hash,length}`; now `VerifiedChain` also carries
      `certified_transactions: Option<CertifiedTransactions{merkle_root, epoch, block_number}>`,
      surfaced from the tip cert's own hashed content (`CardanoTransactions(epoch,block)`
      signed-entity + the `cardano_transactions_merkle_root` protocol-message part) via a
      new `Certificate::certified_transactions()`. The tip of the already-verified 12-cert
      preprod chain (`tests/mithril_chain.rs`) IS a real `CardanoTransactions` cert
      (`96602b8f…869795`, STM-verified per part 4), so the surfaced root is pinned to a real
      in-tree, genesis-authenticatable value — no fresh harvest needed for the surfacing.
      RED→GREEN: `verified_chain_surfaces_the_certified_transaction_root` (root
      `4409e1c7…c319b5`, epoch 300, block 4924499) + `surfaced_root_comes_from_the_tip_
      certificates_hashed_content` + `stake_distribution_certificate_surfaces_no_transaction_
      root` (→ `None`). The spec's `73d8885a…`/block 4926569 was the live-artifact sample;
      pinned to the real in-tree cert instead (loop honesty — pin to what is proven).
- [x] UTxO part 1b of 3 — harvest done (proof + cert; raw tx CBOR deferred to part 3).
      Operator ran the aggregator egress (parked for the non-interactive loop) and committed
      the golden fixtures: `tests/vectors/mithril-txproof.json` (a real `CardanoTransactionsProofs`
      for tx `242f2037…a636`, `non_certified_transactions` empty) + `tests/vectors/
      mithril-txproof-cert.json` (its certifying cert `b3582978c8ae855f…deea` =
      `CardanoTransactions(300, 4927469)`, `cardano_transactions_merkle_root`
      `83c012fdc3e756fb…5d774129`; `cert.hash == proof.certificate_hash`; a real STM *standard*
      cert, `verify_standard`-authenticatable, NOT matching the `mithril-cert-*` 12-cert glob).
      The raw tx CBOR (part 3's `TxOut` decode) is a separate BlockFetch+pallas harvest, deferred
      to part 3.
- [x] UTxO part 2 of 3 — the MKMap/MMR inclusion verify (the crypto core, wasm-safe
      default build). Implement, in the DEFAULT (non-`mithril`, no-blst, wasm-safe) graph,
      a ~200-LOC pure-Rust BLAKE2s-256 Merkle-Mountain-Range verifier reproducing Mithril's
      `MKMapProof<BlockRange>` verify: decode the hex→JSON proof
      (`{master_proof: MKProof{inner_root,inner_leaves,inner_proof_size,inner_proof_items},
      sub_proofs}`), verify each per-range sub-proof (tx-hash leaf → range-root) + the
      master MMR proof (range-root → master root), recompute the root via `compute_root()`
      (NEVER trust the input `inner_root`), and `contains(tx_hash)`. `verify_tx_inclusion(
      proof_bytes, tx_hash, certified_root) -> Result<(), InclusionError>` asserts the
      recomputed root == `certified_root`. Oracle (fixtures now committed by part 1b): the golden
      vector `tests/vectors/mithril-txproof.json` — its `certified_transactions[0].proof`
      (hex→JSON `MKMapProof`) must recompute to
      `83c012fdc3e756fb5230d1a6554fbf743ccea171b37d536a64350c4f5d774129`, which ==
      `Certificate::from_json(mithril-txproof-cert.json).certified_transactions().unwrap().merkle_root`
      (compose `verify_standard` on that cert to STM-authenticate the root before trusting it) —
      so the positive test is `verify_tx_inclusion(proof, 242f2037…a636, that_root) == Ok`; plus a
      dev-only differential vs `ckb-merkle-mountain-range` (the crate mithril rides). Negatives: a
      mutated proof-path node → `RootMismatch`; a tx-hash not in the proof → `NotIncluded`.
- [ ] UTxO part 3 of 3 — `verify_utxo_read` + the honest verdict (CLOSES DoD line 5).
      HARVEST DONE (operator, network seam): `tools/harvest tx-cbor <txhash>` (new mode) pulled
      the raw transaction BODY CBOR for the golden tx `242f2037…a636` into
      `tests/vectors/mithril-tx-body.cbor` (561 bytes) — the exact pallas `KeepRaw` body span, so
      `blake2b256(body) == 242f2037…a636` (the certified txid; VERIFIED). `tx_bytes` IS this body
      CBOR, so H is computed with NO span isolation: `H = hash::blake2b256(tx_bytes)`.
      `verify_utxo_read(tx_bytes, out_index, proof_bytes, certified_root, block_number) ->
      Result<VerifiedOutput, _>`: hash the SUPPLIED `tx_bytes` → H (NEVER a provider-supplied H),
      `verify_tx_inclusion(H, proof_bytes, certified_root)`, then decode `TxOut[out_index]` from
      the body map (Conway tx body = CBOR map; key 1 = outputs array; a Conway `TxOut` is a map
      `{0: address_bytes, 1: value(coin uint | [coin, multiasset]), 2: datum_option?, 3:
      script_ref?}`). Return `VerifiedOutput { address, lovelace, datum: Option<..>, certified_at:
      block_number, spend_status: SpendStatus::NotEstablished }` — `spend_status` is the honesty
      enforced in the TYPE (uncoercible to "unspent"; NO code path may narrow it; add an
      honesty-guard test asserting the API never yields a positive-liveness value). The golden
      fixture's outputs (for the positive test): idx 0 = a script address + `5_000_000` lovelace +
      an inline datum; idx 1 = a payment address + `4_867_657_971` lovelace, no datum. `certified_at`
      = the cert's `block_number` 4927469 (== proof `latest_block_number`). NAMED negative (the DoD
      proof) `tampered_utxo_claim_is_rejected`: flip one lovelace/datum byte in `tx_bytes` → H
      changes → H not among the proof's attested leaves → `Err(InclusionError::NotIncluded)` (the
      hash-binding catches it BEFORE any root work — the honest variant, not `RootMismatch`);
      variant: pass a DIFFERENT tx's body under this proof → same `NotIncluded`. `SpendStatus` +
      `VerifiedOutput` live in the DEFAULT wasm-safe graph (no blst); the Conway TxOut decode is
      Sextant's own minicbor path. See the "## Attacking next" spec for the honest-scope statement
      (proves authentic-bytes + certified-inclusion + provenance, NOT unspent/liveness).

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
| 2026-07-11 21:49 UTC | Independent red-team of the autonomously-merged STM multi-sig slice: VERDICT SHIP | Fresh `fluxpoint-loop:red-team-reviewer` + operator 3× flaky-check: `verify_standard` genuinely calls `mithril_stm::verify` (all 12 real preprod multi-sigs verify; bit-flip → 0 accepted; mutated message/AVK/genesis-as-standard reject); threshold bound (k-lowered cert caught by `verify_chain` integrity `Err(Hash)`, foreign AVK by AVK-binding); feature-gate clean (0 blst in default+wasm); 5k fuzz no panic; deterministic. **Confirmed NO combined `verify_chain_anchored` yet → DoD line 4 correctly UNCHECKED. PART 5 (closes line 4): compose the tip→genesis walk — `verify_chain_anchored(certs, genesis_vkey)` requiring the root to be a verified genesis + `verify_chain` (link+AVK) + `verify_standard` (STM) per standard cert + the `compute_hash==hash` integrity check to pin `k/m/phi_f`; end-to-end test on the real preprod chain naming the cert hash** |
| 2026-07-11 22:20 UTC | Mithril GENESIS-ANCHORED WALK (DoD line 4, part 5 — CLOSES line 4): the real preprod genesis-anchored certificate chain verifies end-to-end on Sextant's own composed path, naming the tip cert hash | `cargo test --features mithril --test mithril` (14 tests) — `real_preprod_genesis_anchored_chain_verifies`: `mithril::verify_chain_anchored(&[genesis, child], &genesis_vkey)` Ok, names root `69bc3bdf…af7ad59` (epoch-196 re-genesis) + tip `fc979366ab86682b08901ad69c4de5c9cce503684fba038807d44c59f2d56b72` (epoch-197 child), length 2; composes `verify_chain` (integrity+link+AVK-binding, integrity FIRST so params pinned) + `verify_genesis` (root) + `verify_standard` (each rising STM). `chain_anchored_rejects_forgeries`: empty→`Chain(Empty)`, wrong vkey→`Genesis(InvalidSignature)`, non-genesis root→`Genesis(NotGenesis)`, broken link (resealed)→`Chain(BrokenLink{1})`, naive tamper→`Chain(Hash{1})`, substituted AVK (resealed)→`Chain(AvkBinding{1})`, swapped authority→`Standard{index:1}`. `scripts/harness.sh --full` exit 0 (fmt, clippy --all-features, release, all tests incl. wasm32). No new crate |
| 2026-07-11 22:20 UTC | Part-4 red-team hardening + adversarial DoS closure: the hostile-input tests surfaced real mithril-stm DoS vectors; `verify_standard` fails closed on ALL of them | `verify_standard` guards: (1) degenerate threshold `k==0`/`m==0`/`phi_f∉(0,1)` → `WeakParameters` — **phi_f=1.0 is REJECTED** (makes every claimed lottery win → a lone signer clears the quorum); (2) `guard_stm_bounds` → `ImplausibleAvk` for `stake>total_stake` (eligibility Taylor exponent >1 diverges), `nr_leaves∉[1,2²⁴]` (Merkle arithmetic overflows near 2⁶⁴), `signatures.len()>2¹⁶`, and total lottery `indexes>2¹⁸` (mithril-stm evaluates one lottery/index BEFORE the k-count check); (3) blob-hex length caps at 4 MiB → `MalformedAvk`/`MalformedSignature` (bounds `serde_json` allocation). A thread-timeout probe CONFIRMED stock mithril-stm hangs on total_stake=1 and nr_leaves=u64::MAX (>12s; guarded <20ms). `verify_standard_rejects_hostile_stm_inputs` (bounded-time worker thread → regression fails clean, not a stuck suite) + `verify_standard_rejects_weak_parameters`. `scripts/harness.sh --full` exit 0, 70 tests |
| 2026-07-11 22:40 UTC | Red-team of the part-5 diff returned VERDICT BLOCK (HIGH + MEDIUM); both closed, re-verified green | `fluxpoint-loop:red-team-reviewer` (read the vendored mithril-stm 0.10.5 verify path): NO false-accept in `verify_chain_anchored`, but standalone `verify_standard` was still hangable/OOM-able — HIGH: unbounded `indexes`/`signatures` array or `m` drives `check_indices` before the k-count check; MEDIUM: `phi_f==1.0` → unconditional lottery win (lone-signer forge). Fixes: `guard_stm_bounds` now caps `signatures.len()`/total `indexes`/blob size, and the threshold guard rejects `phi_f>=1.0` — real preprod certs (phi_f=0.65, kilobyte blobs, k winning indices) unaffected; new hostile tests (oversized blobs, 400k-element `indexes`) assert prompt `Err` in bounded time. Red-team also confirmed `MAX_AVK_LEAVES=2²⁴` provably below the overflow and `stake≤total_stake` keeps the eligibility exponent ≤1; length-2 genesis→child segment a defensible close. `scripts/harness.sh --full` exit 0 |
| 2026-07-11 23:27 UTC | Independent red-team of the autonomously-merged genesis-anchored chain verify: VERDICT SHIP — DoD line 4 CLOSED | Fresh `fluxpoint-loop:red-team-reviewer` + operator 3× flaky-check: `verify_chain_anchored` requires a verified genesis root (un-anchored/omitted/tampered-genesis chains reject `Genesis(...)`), runs `verify_chain` integrity BEFORE STM (attacker-lowered k/m/phi_f caught by hash mismatch; degenerate thresholds → `WeakParameters`), enforces link/AVK/STM per cert, closes mithril-stm DoS paths (`guard_stm_bounds`), verifies the real preprod chain end-to-end naming tip `fc979366…`. No regression, feature-gate clean (0 blst in default+wasm), 3k fuzz no panic. **Trust-establishment core complete: DoD lines 3 + 4 checked, line 2 substantive; 14 slices incl. a 5-part Mithril epic** |
| 2026-07-12 00:40 UTC | Artifacts part 1 (DoD line 6): the verified core is exposed over a minimal, allocation-free C ABI (`src/ffi.rs`) whose in-process verdicts equal the Rust path on real vectors, with a committed cbindgen header the harness drift-gates | `scripts/harness.sh --full` exit 0 — 4 core exports (`sextant_abi_version`/`_verify_segment`/`_header_decode`/`_status_message`) + `#[cfg(mithril)] sextant_mithril_verify_chain_anchored`; `tests/ffi.rs` (14) + `src/ffi.rs` unit (4): good preprod segment → `Ok{index:-1}`; dropped block → `ChainBrokenLink(201)`+index; tampered VRF → `ChainVrf(203)`+index+`detail∈110..=113`; null eta0 → `ErrNullPointer`; count==0 → `ErrEmptyInput`; header fields byte-match `HeaderView`; malformed→`100`, era→`101`+`detail==era`; mithril anchor good → `0`+64-hex root `69bc3bdf…`/tip `fc979366…`+len 2, bad-json@i → `327`+`index==i`, wrong vkey → `313`, resealed broken-link → `302`+idx1, resealed tampered-sig → 320-band+idx1; `guard` unit test panic→`ErrPanic(-9)`, genesis projection `has_prev_hash==0`. Header drift-gate (`cbindgen` regen + `diff`) clean, `#if defined(SEXTANT_MITHRIL)` present, 0 `blst`/`mithril_stm` tokens; `cargo tree -e normal` = 0 blst/mithril-stm in default+wasm; wasm32 build green (guard is a no-op trap there). No new crate (ffi adds no dep); no `panic="abort"` (grep-guarded) |
| 2026-07-12 00:55 UTC | Red-team of the part-1 diff: VERDICT SHIP — no false-accept at the boundary, no memory/panic/feature-leak hole; the one actionable MEDIUM (panic=abort guard missed the single-quoted TOML form) closed + proven | `fluxpoint-loop:red-team-reviewer` across 7 attack surfaces: `Ok`(0) emitted only inside `Ok` arms (success writes strictly gated), bands disjoint from 0; every `from_raw_parts`/`&*` null-checked incl. each `block_ptrs[i]`/`cert_json_ptrs[i]` + `count==0` guard, `write_hex64`/`status_message` clamp `.min(64)`/`.min(cap)`; `guard` on all fallible exports, `AssertUnwindSafe` sound (writes only after the verifier, on the terminal arm); `cargo tree -e normal` (default + wasm) = 0 blst/mithril-stm; drift gate proven RED-on-change. MEDIUM fix: `header_gate` panic-abort grep now matches `['\"]abort['\"]` (both TOML string forms) — proven old regex matched 1/2 fixture lines (missed `panic = 'abort'`), new matches 2/2; `scripts/harness.sh --full` exit 0 after the fix. LOWs (index→i64 wrap unreachable; `ErrBufferTooSmall` reserved for part-2 sizing) documented, non-blocking |
| 2026-07-12 01:20 UTC | Independent verification of the autonomously-merged FFI part-1 (DoD line 6, part 1): VERDICT SHIP — safe C-ABI boundary, honest ABI header, deterministic | Fresh `fluxpoint-loop:red-team-reviewer` (7 attack surfaces) + operator drift/flaky checks: every fallible export `guard`-wrapped (`AssertUnwindSafe` sound — out-params written once on the terminal arm, so a caught unwind → `ErrPanic(-9)`, never a half-written verdict); no false-accept (`Ok(0)` only inside `Ok` arms, bands disjoint from 0); every raw-ptr marshalling null-checked incl. per-element + `count==0`; taxonomy exhaustive with chain(200)/mithril(300) bands disjoint. Independent header regen = byte-identical to committed `include/sextant.h` (the drift gate is not hollow); `cargo test --all-features` ×3 = 88/88 deterministic; `cargo tree -e normal` default+wasm = 0 blst/mithril-stm; header 0-leak + `#if defined(SEXTANT_MITHRIL)`-guarded. One LOW closed here: `AnchoredError::Standard.index` doc said "0-based, oldest=root" but the value is `i+1` (1-based absolute; genesis root = index 0) — `src/mithril.rs` doc corrected to match the code + the already-correct FFI comment. Symbol-retention through linker dead-strip is deferred to part-2's CI C-smoke-test (pinned). Merged PR branch cleaned; remote = origin/main only |
| 2026-07-12 02:10 UTC | Artifacts part 2 (CLOSES DoD line 6): the three artifacts are produced in CI and a C smoke test links the real static lib through the committed header on the Linux target | PR #16 squash-merged to main (`d743d9a`); `.woodpecker/artifacts.yml` runs `cargo build --release` (→ lean `libsextant.a`, no blst) + `cargo build --release --target wasm32` (→ `sextant.wasm`), then `cc -I include tests/smoke/smoke.c target/release/libsextant.a -lpthread -ldl -lm && ./smoke` (asserts `abi_version()==SEXTANT_ABI_VERSION`; garbage 2-block segment → non-zero `ChainDecode`+`index≥0`; null eta0 → `ErrNullPointer`; all 4 core exports link-referenced so a dead-stripped `#[no_mangle]` symbol is a LINK error), then assembles + lists `dist/{libsextant.a,sextant.h,sextant.wasm}`. All 4 Woodpecker contexts green on the PR (pipeline 122) AND on merged main `d743d9a` (`push/artifacts` + `push/harness` success). Independent `fluxpoint-loop:red-team-reviewer` VERDICT SHIP, 0 findings: proof non-vacuous (`CHECK` macro not `assert`; garbage genuinely decodes to `UnsupportedEra(0)`; a false-accept regression would turn smoke red), lean artifact (no `default=[mithril]`), fail-fast pipeline gates `./smoke`'s exit code. Durable downloadable release (publish secret) deferred to the operator. Run link: https://ci.fluxpointstudios.com/repos/15/pipeline/122/1 |
| 2026-07-12 11:20 UTC | UTxO part 1a (DoD line 5): the verified certificate chain surfaces the tip cert's genesis-authenticatable Cardano-transactions Merkle root — the value a proof-based UTxO inclusion check recomputes against — from the tip's own hashed content, pinned to a real in-tree cert | `cargo test --features mithril` — `tests/mithril_chain.rs::verified_chain_surfaces_the_certified_transaction_root` (`verify_chain` over the 12-cert epoch-290→300 preprod segment; tip `96602b8f…869795` is a real STM-verified `CardanoTransactions(300,4924499)` cert; surfaced `VerifiedChain.certified_transactions == Some{merkle_root: 4409e1c7bb2e9fc6507d16393842daba385bb03a2d7c2b09f5bcede9b4c319b5, epoch: 300, block_number: 4924499}`), `surfaced_root_comes_from_the_tip_certificates_hashed_content` (surfaced == `tip.certified_transactions()`, so it cannot disagree with what the cert signed), `stake_distribution_certificate_surfaces_no_transaction_root` (a `MithrilStakeDistribution` cert → `None`, the honest absence a UTxO read must not read as an empty root). New `mithril::CertifiedTransactions` + `Certificate::certified_transactions()`; `VerifiedChain` gains `certified_transactions: Option<CertifiedTransactions>` populated from the tip in `verify_chain` (so `verify_chain_anchored` surfaces it genesis-authenticated). No new crate; mithril-feature-only (0 change to default+wasm graph); FFI untouched (reads only root/tip hashes). `scripts/harness.sh --full` exit 0 (HARNESS_GREEN) — fmt, clippy --all-features, release, all tests incl. wasm32 + header drift-gate. `fluxpoint-loop:red-team-reviewer` VERDICT SHIP (anchored path cryptographically sound — `compute_hash` folds the whole protocol-message BTreeMap incl. the merkle-root part + the standard-cert `signed_entity_type` (epoch/block BE), and STM multi-sig is over `H(protocol_message)`, so a resealed-hash forgery is rejected by `verify_standard`; panic-free `match`/`.get()?`; 0 blst/mithril-stm in default+wasm). One MEDIUM (doc-only overclaim — the `VerifiedChain` field doc said "genesis-authenticated" unconditionally, but the struct is also returned by integrity-only `verify_chain`) closed: field + `verify_chain` fn docs now scope genesis-authentication to `verify_chain_anchored`, plus a 4th non-vacuous test `plain_verify_chain_does_not_genesis_authenticate_the_surfaced_root` (a self-consistent resealed-hash cert with a forged root passes plain `verify_chain` and surfaces the FORGED root — pins the honesty boundary). Part 1b (harvest the real tx-proof + tx CBOR fixtures for parts 2/3) is network-gated and parked |
| 2026-07-12 12:40 UTC | UTxO part 2 (DoD line 5): the pure-Rust BLAKE2s-256 MMR inclusion verifier recomputes the real preprod certified transaction root on Sextant's own path (never the proof's stated `inner_root`) and binds the transaction to it; tampering is rejected | `cargo test --features mithril --test inclusion` (7) + `cargo test --lib inclusion` (2) — `real_preprod_proof_recomputes_the_certified_root_and_includes_the_tx` (`verify_tx_inclusion` over the real `mithril-txproof.json` `MKMapProof<BlockRange>` for tx `242f2037…a636` recomputes the master MMR root to `83c012fd…5d774129` == the STM-authenticated cert `cardano_transactions_merkle_root`), `the_certified_root_is_stm_authenticated_and_the_proof_binds_to_it` (composes `verify_standard` on cert `b3582978…deea` → `certified_transactions().merkle_root` → the verifier's `certified_root`, block 4927469), `a_mutated_master_path_node_is_rejected_as_root_mismatch` + `a_mutated_sub_tree_path_node_is_rejected` (→ `RootMismatch`), `a_transaction_not_in_the_proof_is_not_included` (→ `NotIncluded`), `the_wrong_certified_root_is_rejected` (→ `RootMismatch`), `malformed_proof_bytes_are_rejected_without_panicking` (non-hex/empty/odd/non-JSON → `MalformedProof`); `calculate_root_matches_ckb_across_shapes` (differential vs `ckb-merkle-mountain-range` on 1/2/3/5/7/8/11/16/100-leaf trees, every leaf proven) + `a_mutated_ckb_proof_item_diverges_from_the_true_root`. New `src/inclusion.rs` (default graph, no blst) + `blake2s256` in `src/hash.rs`; serde/serde_json promoted to normal deps (0 new lock crates; ckb is the only new crate, dev-only). `cargo tree -e normal` default+wasm = 0 blst/mithril-stm; wasm32 build includes the verifier. `scripts/harness.sh --full` exit 0 (HARNESS_GREEN) — fmt, clippy --all-features, release, all tests, wasm32, header drift-gate |
| 2026-07-12 14:30 UTC | Independent red-team of UTxO part 2 returned VERDICT BLOCK (CRITICAL false-accept); closed + regression-guarded + re-verified green | The loop opened PR #19 but ran out of turns before self-red-teaming, so the independent pass was PRIMARY. `fluxpoint-loop:red-team-reviewer` (built a `ckb-merkle-mountain-range` differential harness) found a CRITICAL: the MMR port dropped four ckb anti-malleability guards, so a proof carrying a **duplicate/unconsumed leaf** in a genuine single-tx block range smuggles an arbitrary tx `X` past membership — `calculate_peak_root` returns at `pos==peak_pos` and silently DROPS `X`, the root still recomputes to the real STM-authenticated `certified_root`, and `collect_leaves` reports `X` present → `verify_tx_inclusion(proof, X, root) == Ok`. Reproduced end-to-end (X=`0xEE..`, real 8-range master root). The golden vector + the ckb differential both missed it (they exercise only well-formed proofs). FIX: restored the four ckb recompute guards — queue-empty-at-peak (G1, the essential one — alone closes the whole false-accept family), `parent_pos<=peak_pos` (G2), reject internal-node leaf positions (G3), reject duplicate leaf positions (G4). Two non-vacuous regression tests added (`a_smuggled_tx_in_a_single_tx_block_range_is_rejected`, `a_residual_leaf_at_a_peak_return_is_rejected`): operator VERIFIED both return `Ok` (FAIL) on the pre-fix verifier and `Err`/pass with the guards — genuinely guarding the CRITICAL (test 1 catches removing {G1,G4}, test 2 catches removing G1 alone). Post-fix independent VERDICT SHIP. `scripts/harness.sh --full` exit 0 (fmt, clippy --all-features, release, all inclusion tests + 2 new, wasm32, header drift-gate); feature-gate still clean (0 blst/mithril-stm in default+wasm) |
| 2026-07-12 03:30 UTC | DoD line 2 "from mainnet" CLOSED: leader-VRF + opcert + KES verify on 24 real mainnet blocks, byte-identical to the independent oracles | PR #17 squash-merged to main (`3fb7d6a`). `tools/harvest` (now `Network`-parameterized) BlockFetched 24 contiguous real mainnet blocks (epoch 642, slots 192261567..192262175) off the CF backbone relay (magic 764824073) + their eta0 (`593225d2…5bf8159c`) from Koios mainnet. `real_mainnet_leader_proofs_verify` (24 leader proofs verify + reproduce the committed output + agree with `cardano-crypto` VrfDraft03), `real_mainnet_kes_body_sigs_verify` (24 KES body sigs verify + `pallas` Sum6Kes oracle parity), `real_mainnet_opcerts_verify` (24 opcerts verify + `pallas` cryptoxide Ed25519 parity) — the full cold→hot→body chain + leader-VRF on mainnet. Case-builders generalized by prefix (KES/opcert require the `.eta0` sidecar, excluding the 5 synthetic decode-fixtures whose hand-set slots break the KES-period rule); the all-`*.block` decode + VRF-output sweeps auto-verify the 24 mainnet vectors against pallas. Independent `fluxpoint-loop:red-team-reviewer` VERDICT SHIP: proof non-vacuous (≥20 asserted, real verifiers called, genuinely-independent oracles); blocks confirmed real (decoded era-7 Conway; a 1-bit `eta0` flip makes leader-VRF FAIL, so `eta0` + proof are genuine); one LOW (opcert mainnet coverage) closed in the same PR (`78d6dcc`). All Woodpecker contexts green (PR pipeline 127). `scripts/harness.sh --full` exit 0. DoD line 2 now spans preprod (preview substitute) + mainnet, ≥20 each |

## Notes for the next iteration
State (2026-07-12): **UTxO part 2 shipped — the pure-Rust BLAKE2s-256 MMR inclusion
verifier** (DoD line 5, the load-bearing crypto core). `src/inclusion.rs` (DEFAULT
non-`mithril`, no-blst, wasm-safe graph) reproduces mithril's `MKMapProof<BlockRange>` verify on
Sextant's own path — a verbatim port of `ckb-merkle-mountain-range`'s `calculate_root` (peak walk
+ per-peak recompute + right-to-left bagging) over the `MergeMKTreeNode` merge
`BLAKE2s-256(left‖right)`, with checked arithmetic + a `MAX_MMR_SIZE = 2⁴⁰` cap + a 8 MiB proof
cap so untrusted `inner_proof_size`/positions never overflow, underflow, or diverge, and serde's
compiled-in recursion limit bounds the nesting. `verify_tx_inclusion(proof_hex, tx_hash,
certified_root)`: hex→JSON decode, assert the tx's 64-byte lowercase-hex ASCII leaf is present
(`NotIncluded` else), recompute every sub-tree root and require it bind into its parent master
tree as `merge("{start}-{end}", sub_root)` (the empirically-pinned MKMap master-leaf transform),
recompute the master root (NEVER the proof's stated `inner_root`), and assert it == the supplied
`certified_root` (`RootMismatch` else). Proven on the REAL preprod `mithril-txproof.json` (tx
`242f2037…a636` recomputes master root `83c012fd…5d774129`), tied to the STM-authenticated cert
`b3582978…deea` root via `verify_standard` + `certified_transactions()`, plus a
`ckb-merkle-mountain-range` differential across 1..100-leaf shapes and the tamper/absent/wrong-root
negatives. serde/serde_json promoted to normal deps (0 new lock crates; ckb dev-only). DoD line 5
stays UNCHECKED (part 3 remains — the honest verdict type).

**Attacking next — UTxO part 3 of 3 (CLOSES DoD line 5): `verify_utxo_read` + the honest
verdict.** The design is pinned in the "## Attacking next — DoD line 5" spec below. Compose the
shipped `verify_tx_inclusion` into `verify_utxo_read(tx_bytes, out_index, proof_bytes,
certified_root, block_number) -> VerifiedOutput{addr,value,datum,certified_at,spend_status:
SpendStatus::NotEstablished}`: hash the SUPPLIED `tx_bytes` → H (Blake2b-256, NEVER a
provider-supplied H — the substituted-bytes guard), `verify_tx_inclusion(H)`, then decode
`TxOut[out_index]` from the certified `tx_bytes` (CBOR, the minicbor path already in
`src/header.rs`), and return the output with an uncoercible `SpendStatus::NotEstablished` (the
type-level honesty — proves provenance/inclusion, NOT unspent). NAMED DoD negative
`tampered_utxo_claim_is_rejected`: flip one lovelace/datum byte in the `TxOut` → H changes →
`verify_tx_inclusion` → `NotIncluded`/`RootMismatch`; variant: tx-B's bytes under tx-A's proof →
rejected. Likely also the FFI export (`sextant_verify_utxo_read`) + `smoke.c` reference (the
red-team "every export gains a smoke reference" rule) + cbindgen header regen.

**BLOCKER for part 3 — the raw tx CBOR fixture is a fresh network harvest** (BlockFetch the block
carrying tx `242f2037…a636` off a relay + decode its `TxOut` with pallas), and network egress is
permission-gated in this non-interactive loop (a plain `curl`/`cargo run -p harvest` is denied).
Two paths: **(A)** build part 3's `verify_utxo_read` + `SpendStatus` type + the honest-scope
harness against a SYNTHETIC `TxOut` fixture whose Blake2b-256 hash is inserted as a constructed
MKMap leaf (self-contained, no network — proves the tx-bytes→H binding + the tampered-claim
negative + the uncoercible spend_status without the real block), and pin the REAL-tx-CBOR golden
when an operator harvest lands — RECOMMENDED, closes the DoD crypto with the named negative now;
**(B)** park part 3 until an operator harvest session. Attack (A) next: the DoD proof
(`tampered_utxo_claim_is_rejected`) is a crypto property that a synthetic-but-real-shaped `TxOut`
+ constructed proof proves as rigorously as a harvested block.

**DoD line 6 remains CLOSED — the C-ABI/WASM artifacts primitive shipped
(parts 1 + 2 of 2, PRs #15 + #16).** Part 1 (`src/ffi.rs`) turns the verified core into
the consumable primitive: 4 core `extern "C"` exports (`sextant_abi_version`,
`sextant_verify_segment`, `sextant_header_decode`, `sextant_status_message`) + a
`#[cfg(feature="mithril")] sextant_mithril_verify_chain_anchored`, each fallible body in a
cfg-split `guard()` (native `catch_unwind`, wasm no-op) so no panic crosses the boundary.
One flat `#[repr(i32)] SextantStatus` (all bands defined unconditionally — feature-invariant
numbering; only the mithril FN is `#[cfg]`-gated) + a nullable `SextantErrorDetail{index,detail}`
carry every verdict + offending index with zero allocation; two caller-allocated `#[repr(C)]`
structs (`SextantErrorDetail`, `SextantHeaderView`) and hex out-buffers carry the results —
no owned buffer / RustBuffer / two-call-sizing crosses the boundary. `tests/ffi.rs` (14) +
`src/ffi.rs` unit (4) exercise every export on real vectors; the harness gained the header
drift-gate (regen + `diff`), the `#if defined(SEXTANT_MITHRIL)` + no-`blst`/`mithril_stm`
leak grep, and a no-`panic="abort"` grep. `cbindgen 0.28` on stable (no nightly/parse.expand)
maps the cfg fn to `#if defined(SEXTANT_MITHRIL)` via `[defines]`; `[export] include` forces
the enum (no fn signature references it) and `exclude` drops the leaked `SLOTS_PER_KES_PERIOD`.
No new crate (ffi adds no dep); feature-gate keeps mithril-stm/blst out of default+wasm.

**DoD line 6 CLOSED (parts 1 + 2 shipped).** Part 2 (PR #16, `d743d9a`): `.woodpecker/
artifacts.yml` builds + lists `dist/{libsextant.a, sextant.h, sextant.wasm}` (green run link =
"produced in CI" proof) and a CI-only C smoke test links the real static lib through the
committed header on Linux (external C linkage + `#[no_mangle]` symbol retention; Windows-MSVC
local link is fragile, so CI-only by design + a merge gate). Independent red-team SHIP (0
findings); all Woodpecker contexts green on the PR and on merged main. A durable downloadable
release (plugin-release / `gh release`) needs a CI publish secret — DEFERRED to the operator.
RULE (red-team-flagged): every new export must gain a `smoke.c` reference or it is not proven
retained.

**Attacking next — OPERATOR-STEERED (do NOT auto-derive).** The consensus core (leader-VRF +
opcert + KES on preprod AND mainnet), chain-following + nonce, the Mithril trust root, AND the
consumable C-ABI/WASM primitive are all done — **DoD lines 2, 3, 4, 6 CLOSED**. Remaining DoD is a
different character and needs an operator decision: line 5 (UTxO — a DESIGN slice first:
snapshot-anchored vs proof-based, anchored to the now-verified Mithril snapshot; see the deferred
UTxO note above) and line 7 (Live — needs a downstream consumer). Checkpoint the operator before
attacking either. (2026-07-12: DoD line 2 closed by the mainnet harvest — `tools/harvest` gained a
`Network`-parameterized `mainnet`/`mainnet-eta0` mode; 24 real epoch-642 mainnet blocks verify
leader-VRF + opcert + KES byte-identical to the independent oracles.)

**Carried notes (the part-2 red-team returned 0 findings):** (1) the drift gate installs
`cbindgen ^0.28` via `cargo install` if missing — a future 0.28.x formatting change could
spuriously fail the gate; fix is `make header` + recommit (fail-closed, never a false-accept).
(2) `SextantStatus::ErrBufferTooSmall(-3)` is reserved ABI (in the message table, never
produced by a part-1 export) — a real producer arrives with a sizing-buffer export or it can be
dropped. (3) `chain_status`/`anchored_status`/`project_header` are single-call-site ABI-mapping
helpers (like `chain::verify_header`) kept separate to keep the unsafe exports short and the
write-once-last invariant auditable; `decode_status`/`kes_code`/`write_detail`/`write_hex64`/
`guard` all have genuine fan-in.

Prior state (2026-07-11): **Mithril GENESIS-ANCHORED WALK shipped — DoD line 4 is CLOSED**
(part 5 of 5). `src/mithril.rs::verify_chain_anchored(certs, genesis_vkey)` is the read
path's trust terminus: given a genesis-anchored segment (oldest first), it composes the
three verifiers built across parts 2–4 into one bytes-in/verdict-out control flow —
`verify_chain` (integrity + hash-linkage + AVK-binding over the whole segment, run FIRST
so each cert's `k/m/phi_f`/AVK is pinned to its committed hash before any signature work),
`verify_genesis` (the root is the network genesis anchor), and `verify_standard` per rising
cert (its STM multi-signature). Returns the verified root/tip hashes or the offending cert's
position (`AnchoredError::{Chain(ChainError), Genesis(GenesisError), Standard{index,source}}`).
Proven on the real preprod segment `[genesis(196), child(197)]` (tip hash `fc979366…f2d56b72`);
every negative rejects at the right layer + index. **The genesis-anchored segment is length 2**
(the epoch-196 re-genesis + its epoch-197 child) — a genuine, contiguous, aggregator-fetched
chain terminating in the genesis root; the at-scale multi-cert machinery is proven separately
(part 2 `verify_chain` over the 12-cert epoch-290→300 run in `tests/mithril_chain.rs`; part 4
`verify_standard` over 12 standard STM sigs). A longer contiguous genesis→…→tip harvest
(`tools/harvest mithril-chain`) is a strengthening the operator can run when the aggregator is
reachable, NOT a DoD gap. No new crate (composes existing `ed25519` + `mithril-stm`); mithril
feature keeps it out of default+wasm.

**Both part-4 red-team hardening items landed in `verify_standard` — and the hostile-input
tests SURFACED REAL mithril-stm DoS vectors (a first red-team pass returned BLOCK; now closed):**
1. **Parameter integrity** — a fail-closed `k==0`/`m==0`/`phi_f∉(0,1)` guard → `WeakParameters`.
   `phi_f=1.0` is REJECTED (the first red-team's MEDIUM): it makes every claimed lottery win, so a
   lone signer clears the k-quorum. Independent of `verify_chain`'s integrity check, which also
   pins the params.
2. **Adversarial serde-input** — `guard_stm_bounds(avk_json, sig_json)` + blob-size caps close
   every way hostile AVK/sig bytes drive stock mithril-stm into unbounded work (a thread-timeout
   probe CONFIRMED the hangs >12s; guarded, <20ms) → `ImplausibleAvk`/`Malformed*`: a signer
   claiming `stake > total_stake` (eligibility Taylor exponent >1 diverges), `nr_leaves ∉ [1,2²⁴]`
   (Merkle arithmetic overflows near 2⁶⁴), `signatures.len() > 2¹⁶`, total lottery `indexes > 2¹⁸`
   (the first red-team's HIGH — mithril-stm evaluates one lottery per index BEFORE checking the
   count against `k`), and AVK/sig hex blobs > 4 MiB (bounds `serde_json` allocation). All bounds
   are ~10²–10³× any real Cardano certificate. `verify_standard_rejects_hostile_stm_inputs` asserts
   each is a prompt clean `Err` via a 10s-bounded worker thread, so a guard regression fails cleanly
   instead of hanging the suite. In a chain walk the AVK is additionally pinned by AVK-binding; the
   guard makes standalone `verify_standard` safe on fully-untrusted bytes.

**Carried LOW (re-red-team, non-blocking):** `MAX_STM_BLOB_HEX = 4 MiB` has the thinnest
headroom of the four DoS caps vs a large mainnet `CardanoTransactions` aggregate (~1–2 MB
observed). It is fail-closed (a bigger genuine cert → `MalformedSignature`, never a
false-accept/panic/hang), and the target here is preprod (kilobyte certs). When a mainnet cert
harvest lands (same tooling as the block harvest, needs network), measure the largest genuine sig
blob and raise the constant to a few × above it (8–16 MiB).

**Attacking next — DoD line 6: Artifacts (C-ABI FFI + cbindgen + wasm/CI).** Operator chose
this next after the trust-establishment core closed. The full pinned design is in the
"## Attacking next — DoD line 6" section below (spec-workflow-derived, reconciled to source);
it lands as two Plan sub-slices (FFI surface + cbindgen header; then CI artifact production).
This is the compounding-leverage payoff — the verified core (header→VRF→opcert→KES→nonce→
chain→Mithril) becomes the consumable C-ABI/WASM primitive every downstream consumer calls.

**Deferred — DoD line 5: UTxO verification (design slice first).** Not dropped, just sequenced
after Artifacts per operator choice. When it comes up: decide snapshot-anchored vs proof-based
in a design slice, then implement with a tampered-claim negative. The Mithril chain of trust is
the natural anchor — a snapshot certificate's `protocol_message` commits (via `SnapshotDigest` /
`CardanoTransactionsMerkleRoot`) to signed Cardano state, and `verify_chain_anchored` now
authenticates that certificate back to the genesis key, so a snapshot-anchored UTxO proof =
(a Merkle/inclusion proof a UTxO is in the committed set) + (the committing cert verified by
`verify_chain_anchored`). Header VRF/KES from-mainnet (DoD line 2) is a separate open tick —
it needs a real-mainnet block harvest with eta0 (see the DoD line 2 assessment below).

Prior state (2026-07-11): **Mithril STANDARD-cert STM multi-signature verify shipped**
(DoD line 4, part 4). `src/mithril.rs::verify_standard(cert)` authorizes a standard certificate
by its STM (stake-based threshold multi-signature): the cert must be standard, `signed_message
== protocol_message.compute_hash()` (the **shared guard** `signed_message_binds_protocol_message`,
reused by `verify_genesis`), and `mithril_stm::AggregateSignature::verify` succeeds over
`signed_message.as_bytes()`. Sextant owns the wire path (hex→JSON AVK/sig deserialize +
`Parameters{m,k,phi_f}` assembly); the BLS aggregate/lottery/Merkle-batch check is the composed
`mithril-stm` 0.10.5 primitive (`num-integer-backend`, NEVER rug/snark), `D = MithrilMembershipDigest`.
**mithril-stm is the sole STM implementation**, so the oracle is the 12 real on-chain multi-sigs
themselves. Feature-gated: `cargo tree -e normal` shows 0 blst/mithril-stm in default+wasm.

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

## Attacking next — DoD line 5: UTxO read verification (proof-based certified-inclusion)
Design derived by a spec workflow (Mithril-source + Cardano-CDDL research, cursed-problem reframing,
adversarial synthesis) and OPERATOR-RATIFIED. The real aggregator vector is confirmed live. USE THIS.

### The honest scope (state it plainly, ENFORCE it in the type)
Cardano commits to NO UTxO-set state root (the Conway header carries only `block_body_hash`, a
per-block tx-merkle root — no ledger-state hash / accumulator). Mithril certifies TRANSACTIONS
(`CardanoTransactionsMerkleRoot`, ~100 blocks behind tip) and immutable-file digests — NOT a UTxO
set. So this slice PROVES: the bytes of output `(H, i)` = {addr, value, datum} are the authentic
on-chain bytes of tx `H`, and `H` is a member of the Mithril-certified transaction set at certified
height X, authenticated end-to-end back to the genesis key. It DOES NOT and CANNOT prove `(H,i)` is
currently UNSPENT (tx-set membership is a monotone "created" predicate; no Cardano commitment exists
to prove unspent against; the verdict trails tip ~100 blocks). Unspent is deferred to the ledger,
which atomically rejects a double-spend at submission — NEVER launder that into a "verified unspent"
claim. Enforce the honesty in the return type: `spend_status: SpendStatus::NotEstablished`,
uncoercible to "unspent", and `certified_at: block_number` travels with every verdict.

### The primitive (confirmed live on release-preprod)
Aggregator `https://aggregator.release-preprod.api.mithril.network/aggregator` — CardanoTransactions
IS enabled. `GET /artifact/cardano-transactions` -> `{merkle_root, epoch, block_number, hash,
certificate_hash}` (sample: root `73d8885a…67a8b2`, block 4926569, epoch 300, cert `b91da12f…857e53`).
`GET /proof/cardano-transaction?transaction_hashes=<h>` -> `CardanoTransactionsProofs
{certificate_hash, certified_transactions:[{transactions_hashes, proof}], non_certified_transactions,
latest_block_number}`. The `proof` field is HEX(JSON) of `MKMapProof<BlockRange>` =
`{master_proof: MKProof, sub_proofs}` where `MKProof = {inner_root:{hash:[32 u8]}, inner_leaves:
[[block_range,{hash}]], inner_proof_size:<MMR node count>, inner_proof_items:[{hash},...]}`. Node
merge = BLAKE2s-256(left‖right); leaf = tx-hash bytes; MMR semantics = `ckb-merkle-mountain-range`.
A real sample is captured in the session scratchpad (tx `242f2037…a636`, block 4925999, cert
`b91da12f…857e53`, recompute target `73d8885a…67a8b2`, inner_proof_size 629099, 12 proof items).

### COMPOSE the existing trust root; compute the verdict on Sextant's own path
- The cert (`certificate_hash`) is authenticated by the EXISTING `verify_chain_anchored` (genesis
  anchor + AVK-binding + STM multi-sig). The provider is trusted for proof BYTES ONLY, never a verdict.
- Recompute the Merkle-forest root from the proof (`compute_root()`, NEVER trust the input
  `inner_root`) and assert it == the cert's certified `CardanoTransactionsMerkleRoot` part (the
  `match_message` trust-join, on Sextant's own code) — that binds inclusion to the genesis key.

### Build (3 Plan sub-slices; the checklist is in the Plan section above)
- Part 1: harvest the real proof + its anchoring cert chain + the raw tx CBOR into fixtures; surface
  the tip cert's certified root + `(epoch, block_number)` on `VerifiedChain` (verified today, not
  returned) — RED against the fixture's known root `73d8885a…67a8b2` / block 4926569.
- Part 2: the pure-Rust BLAKE2s-256 + MMR `MKMapProof<BlockRange>` verify in the DEFAULT wasm-safe
  graph (NO blst — blst stays behind the `mithril` feature for STM cert-auth only);
  `verify_tx_inclusion(proof, tx_hash, certified_root)`; oracle = the golden vector (recomputed root
  == cert `merkle_root`) + a dev differential vs `ckb-merkle-mountain-range`; negatives (mutated node
  -> `RootMismatch`, tx not in proof -> `NotIncluded`).
- Part 3: `verify_utxo_read(tx_bytes, out_index, proof, certified_root, block_number) ->
  VerifiedOutput{addr,value,datum,certified_at,spend_status: NotEstablished}` (hash the SUPPLIED tx
  bytes -> H, NEVER a provider-supplied H); the named `tampered_utxo_claim_is_rejected` negative
  (flip a lovelace/datum byte -> `RootMismatch`) + a substituted-bytes variant. CLOSES DoD line 5.

### Feature-gate / wasm (HARD constraint)
The inclusion verifier is pure BLAKE2s + MMR — it MUST live in the default build and compile to
wasm32 (no blst, no mithril-stm). The blst-bearing STM cert-auth stays behind the existing `mithril`
feature; the verified certified-root is passed INTO the wasm-safe verifier as an input. The harness
`cargo build --release --target wasm32-unknown-unknown` (mithril OFF) must include the verifier.

### Open risks for the red-team
(1) THE UNSPENT GAP — a proven output since spent still verifies; `SpendStatus::NotEstablished` must
be uncoercible (no code path narrows it to a positive claim) — add an honesty-guard test. (2) RECENCY
— every verdict carries `certified_at`; no caller may read it as tip state. (3) LEAF/NODE
DOMAIN-SEPARATION FIDELITY — the reimplemented BLAKE2s+MMR merge / leaf / peak-bagging MUST match
mithril-merkle-tree byte-for-byte or a valid proof falsely rejects or a tampered one falsely passes;
pin with the real golden vector + the ckb-merkle differential. (4) TX-BYTES->H BINDING — hash the
supplied bytes, never a provider H, else tx-A's proof pairs with tx-B's bytes (guard with the
substituted-bytes negative). (5) PROVIDER availability (censorship) is a liveness risk, not soundness
(the root is recomputed + genesis-bound).

Infra: Woodpecker CI green through DoD lines 2/3/4/6; the `mithril` feature keeps blst out of
default+wasm and the inclusion verifier MUST preserve that.
