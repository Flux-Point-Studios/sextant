# LOOP: Sextant — read-path verifying Cardano client (Rust core, C-ABI/WASM trust substrate)

STATUS: DONE

## Definition of Done
Every line must be provably true, with the proof named. The Stop gate and
the outer loop only trust `scripts/harness.sh --full`; everything else
needs a row in Evidence.

- [x] `scripts/harness.sh --full` exits 0
      (PROVEN on merged main `28d112c` — fmt, clippy `--all-targets --all-features
      -D warnings`, release build, `cargo test --all-features` (all suites incl.
      `tests/consumer.rs`=4), wasm32 build, cbindgen header drift-gate; all four
      Woodpecker contexts green on the PR + merged main, pipeline 158/159)
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
- [x] UTxO verification for the read path designed and
      implemented (snapshot-anchored or proof-based — decide in a design
      slice first), with a negative test proving a tampered UTxO claim is
      rejected — proof: named test
      (PROVEN — proof-based certified-inclusion, operator-ratified. `src/utxo.rs`
      `verify_utxo_read(tx_bytes, out_index, proof_hex, certified_root, block_number)`
      hashes the SUPPLIED tx body to H (Blake2b-256, never a provider-supplied H),
      composes the shipped `inclusion::verify_tx_inclusion(H, …)` (recomputes the MMR
      root, never the proof's stated `inner_root`), then decodes the Conway `TxOut` on
      Sextant's own minicbor path, returning `{address, lovelace, datum, certified_at,
      spend_status: NotEstablished}`. The honesty is TYPE-level: `SpendStatus` has the
      single inhabitant `NotEstablished` — the read path CANNOT and does not claim
      unspent (no Cardano UTxO-set commitment exists; the certified set trails tip ~100
      blocks). NAMED negative `tests/utxo.rs::tampered_utxo_claim_is_rejected` flips an
      output lovelace byte → H changes → `Err(Inclusion(NotIncluded))` before any
      decode; `a_different_transactions_bytes_are_rejected_under_this_proof` is the
      substituted-bytes variant. Positive test decodes both real golden outputs (idx 0
      = script addr + 5 ADA + inline datum; idx 1 = base addr + 4_867_657_971 lovelace,
      no datum), and the mithril-gated `the_output_is_read_against_an_stm_authenticated_
      certified_root` binds the read to a `verify_standard`-authenticated cert root
      (genesis-anchorable via `verify_chain_anchored`). All under `scripts/harness.sh
      --full`. Default wasm-safe graph (no blst); FFI export is a follow-up slice)
- [x] Artifacts: single static lib + C header via cbindgen, and a wasm32
      build, both produced in CI — proof: release workflow run link
      (PROVEN on merged main `d743d9a` — `.woodpecker/artifacts.yml` builds
      `libsextant.a` + `include/sextant.h` (cbindgen, drift-gated by the harness)
      + `sextant.wasm`, and a CI-only C smoke test links the real static lib
      through the committed header on Linux; all Woodpecker contexts green, run
      https://ci.fluxpointstudios.com/repos/15/pipeline/122/1)
- [x] Live: the first downstream consumer's execution path performs one
      verified UTxO read on preview against a real order before a spend
      decision, and rejects a spoofed RPC response in the same test —
      proof: service log excerpt + the UTxO ref
      (PROVEN on merged main `28d112c`, PR #22. The `examples/verified_read_gate`
      example binary (a keeper/batcher stand-in shared with `tests/consumer.rs` via
      `#[path]`) runs ONE control flow over UNTRUSTED bytes: `serde_json` parse the
      106-cert `mithril-anchor-chain.json` → `verify_chain_anchored(&certs,
      &genesis_vkey)` (genesis-anchored, tip `b3582978…deea`) → root+height taken
      ONLY from the AUTHENTICATED tip (`Request` has no root field — provider-root
      injection is type-impossible) → `verify_utxo_read(mithril-tx-body.cbor, 0,
      mithril-txproof.json proof, &root, 4927469)` → boolean gate `lovelace >=
      5_000_000 && datum == Inline(d8799f…4417ff)`. SERVICE LOG EXCERPT (both paths,
      one run): `INFO read.verify utxo=242f2037…a636#0 certified_at=4927469
      anchored=genesis lovelace=5000000 datum=inline` / `… -> PROCEED  note=
      spend_status=NotEstablished (authenticity+inclusion proven; unspent deferred
      to the ledger at submission)` / `WARN read.verify …#0 provider=spoofed
      reason=NotIncluded` / `… -> REFUSE (no verified output; spend not submitted)`.
      UTxO REF `242f2037b427ff20ef97a076a7d845c74530be4e5a97b59bb18a519fcfa7a636#0`.
      Named tests (preview = the operator-chosen preprod, per Plan): `consumer_
      proceeds_on_the_authentic_certified_order`, `consumer_refuses_a_spoofed_
      tampered_utxo` (SAME test: authentic PROCEED then a flipped output-coin byte →
      the SAME gate → `Inclusion(NotIncluded)` → REFUSE), `consumer_refuses_an_
      unanchored_cert_chain` (wrong genesis vkey → `AnchoredError::Genesis`),
      `the_example_runs_both_paths_and_exits_zero`. Honest scope enforced in the gate
      (never branches on `spend_status`) + the PROCEED note + module docs: proves
      authentic genesis-certified INCLUSION + provenance as of certified_at (~100
      blocks behind tip), NOT unspent/liveness. Independent `fluxpoint-loop:red-team-
      reviewer` VERDICT SHIP (0 CRITICAL/HIGH/MEDIUM/LOW; all 7 pinned risks —
      unspent-gap, provider-root residue, spoof-through-`evaluate`, non-vacuous
      negatives, fail-closed no-panic, no-overclaim, feature-gate — verified closed).
      No `src/` change (composes only); no FFI change (header drift-gate clean);
      default+wasm graph untouched (example `required-features=["mithril"]`))
- [x] Diff carries no single-caller abstractions and no dead code
      (PROVEN — the Live diff's shared helpers all have genuine fan-in: `refuse`
      (4 callers), the fixture loaders + `tamper_output0_coin` (example + tests),
      `evaluate`/`run_demo`/`expected_datum` (both `#[path]` includers); the three
      one-shot match-to-reason helpers were inlined before merge, and `run_demo`
      reads every `Outcome` field so neither includer carries dead code. Enforced by
      `clippy --all-targets --all-features -D warnings` in the green harness + CI.
      Red-team confirmed no dead code / no single-caller abstraction)

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
- [x] UTxO part 3 of 3 — `verify_utxo_read` + the honest verdict (CLOSES DoD line 5).
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
- [x] Live — first-consumer genesis-anchored verified read + spoof-reject (CLOSES DoD line 7,
      the LAST line). SHIPPED: `examples/verified_read_gate/{main.rs,gate.rs}` (a keeper/batcher
      stand-in) + `tests/consumer.rs` compose the shipped verify path over UNTRUSTED bytes —
      `serde_json` parse the 106-cert chain → `verify_chain_anchored(&certs, &genesis_vkey)` →
      `certified_transactions{merkle_root,block_number}` from the AUTHENTICATED tip (NEVER a
      provider root; `Request` carries no root field) → `verify_utxo_read(tx_body, 0, proof, root,
      block)` → a boolean spend gate `lovelace>=5_000_000 && datum==Inline(EXPECTED)`. Named tests
      GREEN: `consumer_proceeds_on_the_authentic_certified_order` (PROCEED on `242f2037…a636#0`,
      certified_at=4927469 + the NotEstablished note), `consumer_refuses_a_spoofed_tampered_utxo`
      (SAME test: authentic PROCEED then a flipped output-coin byte → the SAME gate →
      `Inclusion(NotIncluded)` → REFUSE, fail-closed), `consumer_refuses_an_unanchored_cert_chain`
      (wrong genesis vkey → `AnchoredError::Genesis` → REFUSE), `the_example_runs_both_paths_and_
      exits_zero`. The example stdout IS the DoD service-log excerpt (both PROCEED + spoofed-REFUSE
      from one run). No `src/` change (composes only); no FFI change (header drift-gate clean);
      default+wasm graph untouched (example is `required-features=["mithril"]`). C-ABI
      `sextant_verify_utxo_read` export is a deliberate follow-on slice (NOT this one). Original
      spec + harvest note preserved below.
      HARVEST DONE (operator, network seam): `tools/harvest mithril-anchor-chain`
      walked the tx cert `b3582978…` (epoch 300) down `previous_hash` to the genesis anchor
      (epoch 196) and committed the whole 106-cert contiguous chain, oldest-first, as one array
      `tests/vectors/mithril-anchor-chain.json` (630 KB); PROVEN `verify_chain_anchored(&certs,
      &genesis_vkey)` Ok over it (105 AVK-bindings + STM multi-sigs), tip `b3582978…`,
      `certified_transactions.merkle_root == 83c012fd…`, block 4927469. Build a Rust consumer
      (an example binary `examples/verified_read_gate.rs` + a `tests/consumer.rs` integration test —
      a keeper/batcher stand-in for the out-of-scope write-path) that runs, from UNTRUSTED provider
      bytes, ONE control flow: parse the 106-cert chain + the pinned genesis vkey → `verify_chain_
      anchored` → `VerifiedChain.certified_transactions` (root+height from the AUTHENTICATED cert,
      NEVER a provider root) → `hex::decode` the root → `verify_utxo_read(mithril-tx-body.cbor, 0,
      mithril-txproof.json proof, &certified_root, block_number)` → `VerifiedOutput` → a boolean
      SPEND GATE `proceed = out.lovelace >= 5_000_000 && out.datum == Some(Datum::Inline(EXPECTED))`.
      Named tests: `consumer_proceeds_on_the_authentic_certified_order` (PROCEED on tx `242f2037…`#0,
      the log line carries `certified_at=4927469` + the mandatory NotEstablished note) +
      `consumer_refuses_a_spoofed_tampered_utxo` (SAME run: flip an output coin byte → the SAME
      consumer gate → `verify_utxo_read` → `Err(Inclusion(NotIncluded))` → REFUSE, fail-closed) +
      `consumer_refuses_an_unanchored_cert_chain` (swap the genesis vkey → `AnchoredError::Genesis`
      → REFUSE). The DoD proof = the example binary's stdout showing BOTH the PROCEED and the
      spoofed-REFUSE paths from one run + the UTxO ref `242f2037…a636#0`. HONEST SCOPE (enforced in
      the gate + the log + docs): proves authentic genesis-certified transaction INCLUSION +
      provenance; the gate MUST NOT read `spend_status` as unspent and MUST NOT claim PROCEED means
      the spend will succeed — unspent is the ledger's to decide atomically at submission. See the
      "## Attacking next" spec for the full pinned design. Then set `STATUS: DONE` (every DoD line
      checked). NEXT (a follow-on slice, NOT part of this): export `sextant_verify_utxo_read` in
      `src/ffi.rs` (+ `SextantVerifiedOutput` `#[repr(C)]`, a UtxoError status band, cbindgen header,
      smoke.c) so a C/WASM consumer proves the C-ABI primitive end-to-end (closes the deferred FFI
      export too).
- [x] BEYOND-DoD — C-ABI `sextant_verify_utxo_read` export + end-to-end C consumer (proves the
      C-ABI/WASM primitive is genuinely consumable; closes the deferred FFI export). The DoD is
      already DONE (STATUS: DONE stays); this is a beyond-DoD primitive slice. Design pinned by a
      spec workflow (FFI-inventory survey + variable-length-output-marshalling research + adversarial
      synthesis) — USE the full "## Attacking next" spec below. In brief: export a CORE (ungated,
      no-blst, wasm-safe) `sextant_verify_utxo_read` marshalling `VerifiedOutput` via the RESERVED
      `ErrBufferTooSmall=-3` caller-sizing protocol (fixed scalars in a `#[repr(C)]
      SextantVerifiedOutput`; variable `address` + `datum` bytes to caller `(buf,cap)` pairs, true
      lengths in the struct, NO free fn); add status bands 400-402 (flattened inclusion) + 410-411
      (utxo), appended after 327 with NO renumbering; EXTEND `sextant_mithril_verify_chain_anchored`
      with `out_ct_root[32]`/`out_ct_block`/`out_has_ct` (the certified root obtainable ONLY from the
      genesis-authenticated verify — honest by construction) and bump `SEXTANT_ABI_VERSION` 1→2;
      `spend_status: u8` ALWAYS `0 == SEXTANT_SPEND_NOT_ESTABLISHED` (the ONLY defined constant — no
      "unspent"/"spent" value exists at the ABI) + the tier-banding forward-compat below; regenerate
      `include/sextant.h` (`make header`, drift + leak gates); a CORE-only `tests/smoke/smoke.c`
      end-to-end consumer (sizing-probe → -3 → resize → Ok accept; tamper coin byte → 400 spoof-refuse)
      + a `#[cfg(mithril)]` Rust FFI end-to-end compose test (anchored verify → `out_ct_root` →
      `verify_utxo_read`). All under `scripts/harness.sh --full` + CI. Red-team the variable-length
      marshalling (write-once-last, no partial copy on -3), the honest-scope constant (no "unspent"
      token in the header), and the feature-gate (core export pulls NO blst). See the full spec below.
      SHIPPED (harness-green locally; CI pending on the PR): CORE ungated `sextant_verify_utxo_read`
      (present in default lib + wasm32) marshals `VerifiedOutput` via the `-3`/`ErrBufferTooSmall`
      caller-sizing protocol — fixed scalars in `#[repr(C)] SextantVerifiedOutput`, variable
      `address`+`datum` to caller `(buf,cap)` pairs, true lengths in the struct, write-once-last, no
      free fn; status bands 400/401/402 (flattened inclusion) + 410/411 (utxo) appended with NO
      renumbering; `sextant_mithril_verify_chain_anchored` EXTENDED with `out_ct_root[32]`/
      `out_ct_block`/`out_has_ct` (certified root obtainable ONLY from the genesis-authenticated
      verify — honest by construction), `SEXTANT_ABI_VERSION` 1→2; `spend_status: u8` ALWAYS
      `SEXTANT_SPEND_NOT_ESTABLISHED (0)` (only defined constant; NO unspent/spent token anywhere in
      the header — new harness gate greps it); `utxo::SpendStatus` now `#[non_exhaustive]` with the
      Tier-1/2/3 ladder documented (compile-time single-inhabitant tripwire moved to a same-crate
      unit test). `include/sextant.h` regenerated (drift + leak + honest-scope gates green). Tests:
      `tests/ffi.rs` +9 (ungated utxo_ffi: good/sizing-probe/exact+partial-`-3`/tampered-400/oob-411/
      null+empty/const=0; mithril: has_ct surface + end-to-end anchored→ct_root→verify_utxo_read
      compose + spoof-400); `tests/smoke/smoke.c` gains the core C consumer (sizing-probe→`-3`→resize→
      Ok→accept; tamper coin byte→400 spoof-refuse; null guard; abi 2) over committed
      `tests/smoke/utxo_fixture.h` (real golden order, datum 74B not the spec's 79 — pinned to the
      proven value). `gate.rs` uses the new `CertifiedTransactions::merkle_root_bytes()` (2nd caller).
      No `.woodpecker` change (rides the existing cc+./smoke line). All under `scripts/harness.sh
      --full` exit 0.
- [ ] BEYOND-DoD v0.2 flagship — Windowed-unspent Tier 1 (`Unspent{WatchedWindow}`), operator-ratified,
      BUILD SLICE-BY-SLICE (red-team gate each). Design pinned by a spec workflow (see the full
      "## Attacking next" spec). The honest verdict: no input spending a watched outpoint appears in
      any block body of a header-verified, hash-linked, GAP-FREE, BODY-COMMITTED segment from the
      Mithril anchor to a verified tip, under (a) Mithril-quorum + (b) data-completeness assumptions,
      follower live — NEVER absolute/eternal/tip-state. The adversary's only evasion (withhold the
      spending block) STRUCTURALLY collapses to `Stalled` (can't advance the tip), never a false
      `Unspent`. Build core over committed fixtures; DEFER the live relay follower (transport, a
      provider-of-bytes never a verdict). Slices:
  - [x] Tier1 slice 1 — `decode_spends` (tx-INPUT decoder). In `src/utxo.rs`, sibling of
        `decode_output`: decode Conway tx body key 0 (`set<transaction_input>`, each `[tx_id:hash32,
        index:uint]`) AND key 13 (collateral) into a `SpendSet`; handle the TAG-258 DUALITY
        (`#6.258([..])` OR bare array — accept both), reject an index wider than u16, fail closed to
        `MalformedTx` on any deviation. Tests: `tag258_and_bare_array_decode_to_the_same_outpoint`,
        `collateral_key13_is_a_spend`, `reference_input_key18_is_NOT_a_spend`,
        `malformed_input_body_is_MalformedTx`, `overwide_index_is_MalformedTx`. No harvest (synthetic
        CBOR + existing fixtures).
        SHIPPED (harness-green locally; CI pending on the PR): `pub struct OutPoint{tx_id:[u8;32],
        index:u16}` + `pub type SpendSet = BTreeSet<OutPoint>` + `pub fn decode_spends(tx_bytes) ->
        Result<SpendSet, UtxoError>` in the DEFAULT wasm-safe graph (0 blst, 0 new deps; reuses
        `read_hash32`). Scans the definite body map; key 0 ∪ key 13 → `decode_input_set` (peeks
        `Type::Tag`==258 or a bare array, both decode identically) → `decode_outpoint` (`u16::try_from`
        rejects an index wider than `uint .size 2`); key 18 (reference_inputs) and every other field
        are `d.skip()`ped — a reference input is read, not consumed. Every deviation fails closed to
        `MalformedTx`. The 5 named unit tests (uppercase in `NOT`/`MalformedTx` normalized to
        snake_case for the `-D warnings` `non_snake_case` lint; intent unchanged) are GREEN, PLUS an
        added real-fixture differential `tests/utxo.rs::decode_spends_matches_pallas_inputs_on_the_
        golden_tx` — the golden `mithril-tx-body.cbor`'s consumed outpoints match pallas's own
        `inputs`+`collateral` sets byte-for-byte (the same cross-decoder oracle discipline
        `decode_output` carries; closes open-risk #3 tag-258/collateral → missed-spend on REAL bytes).
        No FFI change (header drift-gate clean). Next: slice 2 (body-commitment bind).
  - [ ] Tier1 slice 2 — body-commitment BIND. In `src/header.rs`: stop `d.skip()`-ing header_body
        idx 7 (`block_body_hash`), capture its 32 bytes + the RAW spans of block[1..4]. New bind
        (in `src/window.rs` or `src/chain.rs`): recompute `hashAlonzoSegWits =
        blake2b256(blake2b256(raw tx_bodies) ‖ blake2b256(raw witness_sets) ‖ blake2b256(raw aux) ‖
        blake2b256(raw invalid_txs))` and require `== header idx 7` — binding the scanned bodies to
        the verified chain (hash the RAW block[1..4] spans VERBATIM, never a re-encode; Cardano CBOR
        is non-canonical). Tests: `authentic_block_body_binds_to_its_header_commitment`,
        `swapped_body_fails_the_bind`. Uses existing committed preprod block fixtures.
  - [ ] Tier1 slice 3 — the verdict types + `verify_watched_window` (the core). New `src/window.rs`:
        `WatchVerdict = Unspent{as_of: WatchedTip, basis: WatchedWindow(WindowAssumptions)} |
        SpentObserved{at, spending_txid} | Stalled{verified_through, reason: StallReason}`;
        `WatchedTip{anchor_height, as_of_height, as_of_slot}` (NO `now` field); `WindowAssumptions
        {mithril_quorum, data_complete}` (MANDATORY non-Option — unconstructable without them).
        `verify_watched_window(watch, anchor: CertifiedTransactions, blocks, eta0, freshness{slot_now,
        max_lag}) -> WatchVerdict` composes `chain::verify_segment` (headers authentic + linked +
        gap-free) → per-block body-bind (slice 2) → `decode_spends` (slice 1) → membership test →
        the CHECKED invariant `tip.n − start.n + 1 == len` + creation-of-H observed at/above start →
        freshness lag. FAIL-CLOSED: any gap/broken-link/body-mismatch/stale-tip → `Stalled`, NEVER
        `Unspent`. HARVEST (operator, network seam): a contiguous preprod segment with a real
        create+spend of one outpoint + a not-spent outpoint, committed as fixtures. Named tests:
        `unspent_outpoint_in_verified_window_yields_Unspent_as_of_tip`,
        `spending_block_in_window_yields_SpentObserved_at_block`,
        `dropped_spending_block_yields_Stalled_never_Unspent`,
        `window_starting_after_the_spend_yields_Stalled` (the "start after the spend" evasion),
        `stale_tip_yields_Stalled_TipTooOld`.
  - [ ] Tier1 slice 4 — `SpendStatus::Unspent{as_of, basis}` variant + the `#[non_exhaustive]`
        tripwire update, wiring the WatchVerdict into the ladder; honest-scope doc.
  - [ ] Tier1 slice 5 — C-ABI additive: `SextantWatchVerdict` (sibling struct) + banded constants
        (`SEXTANT_SPEND_UNSPENT_WATCHED_WINDOW=1` cryptographic-with-assumptions band; `SEXTANT_WATCH_
        SPENT_OBSERVED=2`/`_STALLED=3`; stall-reason codes; economic ATTESTED band reserved far at
        100+) + `sextant_verify_watched_window` export + `SEXTANT_ABI_VERSION` 2→3 + header regen +
        a C smoke leg. NO absolute/eternal/unqualified-unspent constant ever defined. A honest gate
        example (`examples/windowed_spend_gate`) whose PROCEED line names basis+anchor+as_of+lag+
        assumptions. See the "## Attacking next" spec for the full pinned design.

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
| 2026-07-12 15:40 UTC | UTxO part 3 (CLOSES DoD line 5): `verify_utxo_read` proves an output's bytes are the authentic, genesis-anchorable on-chain bytes of a Mithril-certified transaction and carries the honest, uncoercible spend verdict; a tampered UTxO claim is rejected | `cargo test --all-features` — `tests/utxo.rs` (6) + `src/utxo.rs` unit (7). `verify_utxo_read(tx_bytes, out_index, proof_hex, certified_root, block_number)` hashes the SUPPLIED body → H (`hash::blake2b256`, never a provider H), composes shipped `inclusion::verify_tx_inclusion(H, …)` (root recomputed, never the proof's `inner_root`), then decodes the Conway `TxOut` (map form `{0:addr,1:value,2:datum_option,3:script_ref}` + legacy array `[addr,value(,datum_hash)]`; value = bare coin OR `[coin,multiasset]`; inline datum = `[1,#6.24(bytes)]`) on Sextant's own minicbor path. `verify_utxo_read_yields_the_certified_output_bytes` decodes both real golden outputs of tx `242f2037…a636` (idx 0 = script addr `7015e93b…3699` + 5_000_000 lovelace + inline datum `d8799f…4417ff`; idx 1 = base addr `007dedab…ddf05` + 4_867_657_971 lovelace, no datum), `certified_at`=4_927_469, `spend_status`=`NotEstablished`. NAMED negative `tampered_utxo_claim_is_rejected` (flip an output lovelace byte → H changes → `Err(Inclusion(NotIncluded))` before any decode) + `a_different_transactions_bytes_are_rejected_under_this_proof` (substituted-bytes variant). Honesty guard `the_verdict_never_claims_liveness` (exhaustive match on the single `SpendStatus::NotEstablished`). `the_output_is_read_against_an_stm_authenticated_certified_root` (mithril-gated) composes `verify_standard` on cert `b3582978…deea` → `certified_transactions().merkle_root` → `verify_utxo_read`, so the read is genesis-anchorable via `verify_chain_anchored`. Lib unit tests cover both `Datum` variants + all `UtxoError` variants (`MalformedTx`/`OutputIndexOutOfRange`). Default wasm-safe graph (no blst; 0 new deps); no FFI change (header drift-gate clean). `scripts/harness.sh --full` exit 0 (HARNESS_GREEN) — fmt, clippy --all-features, release, all tests, wasm32, header drift-gate |
| 2026-07-12 16:20 UTC | Independent red-team of UTxO part 3: VERDICT SHIP; one LOW (no in-code TxOut-decode differential) closed | Independent `fluxpoint-loop:red-team-reviewer` on merged `26328ae` + operator flaky/CI checks: NO false-accept (H = `blake2b256(supplied tx_bytes)` computed BEFORE `decode_output`, propagated with `?`; 5 hand-built laundering proof shapes all rejected; part-2 CRITICAL confirmed closed with standing regressions), decode panic-free under 3M+700k hostile inputs (guarded `.unwrap()`s, `.skip()` iterative, `MAX_PROOF_HEX`/`MAX_MMR_SIZE` bounds), `SpendStatus` single-inhabitant + uncoercible + `certified_at` on every Ok, tampered-negative PROVEN non-vacuous (a forged self-consistent proof for the tampered hash decodes to Ok with the CHANGED lovelace, so the real `NotIncluded` is the hash-binding), positive test pins the real values, feature-gate clean (0 blst in default+wasm; `verify_utxo_read` ungated). CI green on merged `26328ae`; `--test utxo --test inclusion` ×3 = 15 tests deterministic. The one LOW closed here: `utxo_output_decode_matches_pallas_on_every_output` — an INDEPENDENT cross-decoder differential (decode the golden body with `pallas-primitives`, cross-check `{address, lovelace, datum-presence}` per output via pallas's `MultiEraOutput` vs Sextant's `decode_output`), so the TxOut decode now carries the same independent-oracle discipline as every other verdict (pallas/cardano-crypto/ckb). `scripts/harness.sh --full` exit 0 |
| 2026-07-12 18:10 UTC | Live (DoD line 7): the first downstream consumer performs one genesis-anchored verified UTxO read before a spend decision and refuses a spoofed provider response in the same run — the example stdout is the service-log excerpt | `cargo test --features mithril --test consumer` (4) + `examples/verified_read_gate` binary. RED first (stub `evaluate`→Refuse: all 4 red for the right reason), then GREEN. The consumer (`examples/verified_read_gate/gate.rs`, shared by the binary + `tests/consumer.rs` via `#[path]`) composes SHIPPED functions over UNTRUSTED bytes: `serde_json` parse the 106-cert `mithril-anchor-chain.json` → `verify_chain_anchored(&certs, &genesis_vkey)` → `VerifiedChain.certified_transactions{merkle_root 83c012fd…, block 4927469}` from the AUTHENTICATED tip `b3582978…deea` (NEVER a provider root — `Request` has no root field) → `hex::decode_to_slice` the root → `verify_utxo_read(mithril-tx-body.cbor, 0, mithril-txproof.json proof, &root, 4927469)` → boolean gate `lovelace>=5_000_000 && datum==Inline(d8799f…4417ff)`. Tests: `consumer_proceeds_on_the_authentic_certified_order` (Proceed, certified_at=4927469, read line carries the height + PROCEED line the NotEstablished note, ref `242f2037…a636#0`); `consumer_refuses_a_spoofed_tampered_utxo` (SAME test — authentic Proceed, then a flipped output-0 coin byte through the SAME gate → `Inclusion(NotIncluded)` → Refuse, fail-closed, WARN names provider=spoofed reason=NotIncluded); `consumer_refuses_an_unanchored_cert_chain` (wrong genesis vkey → `AnchoredError::Genesis` → Refuse); `the_example_runs_both_paths_and_exits_zero`. Example stdout (DoD proof, both paths from one run): `INFO read.verify utxo=242f2037…a636#0 certified_at=4927469 anchored=genesis lovelace=5000000 datum=inline` / `INFO spend.gate …#0 -> PROCEED  note=spend_status=NotEstablished (authenticity+inclusion proven; unspent deferred to the ledger at submission)` / `WARN read.verify …#0 provider=spoofed reason=NotIncluded` / `INFO spend.gate …#0 -> REFUSE (no verified output; spend not submitted)`. No `src/` change (composes only); no FFI change (header drift-gate clean); default+wasm graph untouched (example `required-features=["mithril"]`). `scripts/harness.sh --full` exit 0 (HARNESS_GREEN — fmt, clippy --all-targets --all-features, release, all tests incl. `consumer` (4), wasm32, header drift-gate). Honest scope: proves authentic genesis-certified INCLUSION + provenance as of certified_at (~100 blocks behind tip), NOT unspent/liveness — the gate never branches on `spend_status`. UTxO ref `242f2037b427ff20ef97a076a7d845c74530be4e5a97b59bb18a519fcfa7a636#0`. PR #22 squash-merged to main (`28d112c`); all four Woodpecker contexts green (pipeline 158/159). Independent `fluxpoint-loop:red-team-reviewer` VERDICT SHIP — 0 CRITICAL/HIGH/MEDIUM/LOW, all 7 pinned risks verified closed (unspent-gap guarded, provider-root injection type-impossible, spoof driven through `evaluate`, negatives non-vacuous, fail-closed no-panic on untrusted `Request` bytes, no overclaim beyond ADA-coin inclusion, feature-gate clean). **DoD line 7 CLOSED — every DoD line now checked; STATUS: DONE.** |
| 2026-07-12 18:40 UTC | Independent verification of the STATUS: DONE / DoD-line-7 close — VERDICT SHIP, 0 findings; the whole project is legitimately DONE | Separate independent `fluxpoint-loop:red-team-reviewer` pass on merged `28d112c` + operator flaky/example checks (the loop's own red-team was ALSO SHIP; this is a second, independent pass — the discipline held on every autonomous merge). No overclaim (the gate's only decision is `lovelace>=min && datum==expected`; `spend_status` appears ONLY in a comment + the honest note string, never a branch; SpendStatus single-inhabitant never read as liveness; docs state "a Proceed never means the spend will succeed"). Provider-root injection TYPE-IMPOSSIBLE (`Request` has no `certified_root` field; the root is only `verify_chain_anchored(...).certified_transactions.merkle_root`; `genesis_vkey` the sole trusted input). Spoof driven THROUGH `evaluate()` (not just the primitive) and NON-VACUOUS (the reviewer traced the tamper to body offset 116, coin 5_000_000→21_777_216 which would STILL pass the `>=` predicate, so the `NotIncluded` refusal is the crypto hash-binding, not a predicate miss). No false-accept (every spoof vector → Refuse; root recompute load-bearing; the 106-cert chain genuinely authenticates genesis(196)→tip(300)). STATUS: DONE legitimate: all 8 checkboxes `[x]`, line-7 proof reproduced (operator ran the example → exit 0, the honest 4-line log excerpt), line 8 clean vs the diff, line 1 harness green. Operator flaky check: `--test consumer --test utxo --test inclusion --test mithril` ×3 = 34 tests deterministic; example binary reproduced the PROCEED-with-NotEstablished-note + spoofed-REFUSE(NotIncluded) log. All four Woodpecker contexts green on merged main. **The full read-path verifying Cardano client is DONE: DoD lines 1–8 all checked.** |
| 2026-07-12 03:30 UTC | DoD line 2 "from mainnet" CLOSED: leader-VRF + opcert + KES verify on 24 real mainnet blocks, byte-identical to the independent oracles | PR #17 squash-merged to main (`3fb7d6a`). `tools/harvest` (now `Network`-parameterized) BlockFetched 24 contiguous real mainnet blocks (epoch 642, slots 192261567..192262175) off the CF backbone relay (magic 764824073) + their eta0 (`593225d2…5bf8159c`) from Koios mainnet. `real_mainnet_leader_proofs_verify` (24 leader proofs verify + reproduce the committed output + agree with `cardano-crypto` VrfDraft03), `real_mainnet_kes_body_sigs_verify` (24 KES body sigs verify + `pallas` Sum6Kes oracle parity), `real_mainnet_opcerts_verify` (24 opcerts verify + `pallas` cryptoxide Ed25519 parity) — the full cold→hot→body chain + leader-VRF on mainnet. Case-builders generalized by prefix (KES/opcert require the `.eta0` sidecar, excluding the 5 synthetic decode-fixtures whose hand-set slots break the KES-period rule); the all-`*.block` decode + VRF-output sweeps auto-verify the 24 mainnet vectors against pallas. Independent `fluxpoint-loop:red-team-reviewer` VERDICT SHIP: proof non-vacuous (≥20 asserted, real verifiers called, genuinely-independent oracles); blocks confirmed real (decoded era-7 Conway; a 1-bit `eta0` flip makes leader-VRF FAIL, so `eta0` + proof are genuine); one LOW (opcert mainnet coverage) closed in the same PR (`78d6dcc`). All Woodpecker contexts green (PR pipeline 127). `scripts/harness.sh --full` exit 0. DoD line 2 now spans preprod (preview substitute) + mainnet, ≥20 each |

| 2026-07-12 19:40 UTC | BEYOND-DoD (DoD stays DONE): the C-ABI/WASM `sextant_verify_utxo_read` export + the extended anchored verify + an end-to-end C consumer make the verified read the primitive a non-Rust downstream calls — closes the deferred FFI export | `scripts/harness.sh --full` exit 0 (HARNESS_GREEN — fmt, clippy `--all-targets --all-features -D warnings`, release, `cargo test --all-features` incl. `tests/ffi.rs` (32, +9 new), wasm32 build, header drift-gate + blst/mithril_stm leak grep + NEW honest-scope `\b(un)?spent\b` grep). CORE ungated `sextant_verify_utxo_read` (in default lib AND wasm32; verifier = blake2b/blake2s + minicbor, 0 blst) marshals `VerifiedOutput` via the caller-sizing `-3`/`ErrBufferTooSmall` protocol (first live producer of `-3`): fixed scalars in `#[repr(C)] SextantVerifiedOutput`, variable `address`+`datum` to caller `(buf,cap)` pairs, TRUE lengths in the struct, write-once-last (struct+detail strictly last, no partial copy on `-3`), no free fn. Status bands 400/401/402 (flattened `InclusionError`) + 410/411 (`UtxoError`) appended after 327 with NO renumbering. `sextant_mithril_verify_chain_anchored` EXTENDED (not a sibling) with `out_ct_root[32]`/`out_ct_block`/`out_has_ct` (32 RAW bytes of the STM-authenticated `certified_transactions.merkle_root`, obtainable ONLY from the genesis-authenticated verify — a C consumer is physically unable to get a certified root without anchoring to genesis; malformed root fails CLOSED to 327), `SEXTANT_ABI_VERSION` 1→2. Honest scope at the ABI: `spend_status: u8` ALWAYS `SEXTANT_SPEND_NOT_ESTABLISHED (0)` — the ONLY defined constant, NO `unspent`/`spent` token anywhere in `include/sextant.h` (grep-gated in the harness); `utxo::SpendStatus` is now `#[non_exhaustive]` with the documented Tier-1 `NotEstablished` / Tier-2 `CertifiedUnspent` (cryptographic, reserved) / Tier-3 `Attested` (economic, reserved) ladder + the load-bearing "economic never coercible into cryptographic" invariant; the compile-time single-inhabitant tripwire moved to a same-crate unit test (external `tests/utxo.rs` now asserts equality). Named ffi tests: `utxo_ffi::{good_read_fills_struct_and_buffers, sizing_query_null_bufs, buffer_too_small_reports_true_lengths (exact→Ok + address-fits/datum-short→`-3` with NO partial copy), tampered_bytes_not_included (400), out_of_range_index (411), null_and_empty_guards, spend_status_constant_is_zero}`; `mithril_ffi::{anchored_surfaces_the_certified_transaction_root (has_ct=1, ct_block 4927469, ct_root 83c012fd…774129), anchored_root_feeds_a_verified_utxo_read (end-to-end: anchored verify→ct_root→`sextant_verify_utxo_read`→order predicate PROCEED, then spoofed body→400), anchored_good_names_root_and_tip (None branch: stake-dist tip→has_ct=0)}`. `tests/smoke/smoke.c` (CI-only, WITHOUT `-DSEXTANT_MITHRIL`) gains the core C consumer over committed `tests/smoke/utxo_fixture.h` (real golden order tx `242f2037…a636#0`; the inline datum is 74 B — the spec's "79" was wrong, pinned to the proven value; tamper offset 116 = the coin `1a 00 4c 4b 40`): sizing-probe→`-3`→resize→Ok (lovelace 5_000_000, datum_kind 2, spend_status 0, certified_at 4927469)→tamper coin byte→400 spoof-refuse→null guard; abi check 2. `gate.rs` now uses the new `CertifiedTransactions::merkle_root_bytes()` (2nd caller — DRY). No `.woodpecker` change (rides the existing `cc -I include tests/smoke/smoke.c … && ./smoke` line). CI (Woodpecker artifacts + harness) verifies the C linkage/consumer on the Linux target — PENDING on the PR |

| 2026-07-12 20:05 UTC | Independent red-team of the beyond-DoD FFI export (PR #23): VERDICT SHIP; one MEDIUM (defense-in-depth harness-grep gap) fixed + proven in the same push | Independent `fluxpoint-loop:red-team-reviewer` on `git diff main...HEAD`: all six pinned invariants verified sound — (1) marshalling/memory-safety: `copy_min` never derefs a null/cap-0 buffer and never copies a partial prefix on `-3`; struct written strictly LAST on Ok, once on `-3`; (2) honest-scope: `spend_status` hardcoded `SEXTANT_SPEND_NOT_ESTABLISHED` on every path, no positive-liveness constant, header 0 `unspent`/`spent` tokens, `SpendStatus` `#[non_exhaustive]` + same-crate exhaustive-match tripwire; (3) certified-root provenance: only one Mithril export, authenticates to genesis before surfacing `out_ct_root`, `merkle_root_bytes()` fails closed (→327, `has_ct` never set) — no sibling injection path; (4) null/empty/panic guards incl. empty-proof→402 (not pre-rejected) + the 3 new mithril out-ptrs; (5) feature-gate: core export ungated + wasm-clean, 0 blst/mithril_stm in the header, ABI 1→2 threaded; (6) status bands exhaustive 400–411 with non-empty messages. Only finding — MEDIUM, no reachable false-accept (type-system tripwire + hardcoded constant are the primary guarantee): the honest-scope grep `\b(un)?spent\b` could not catch a `_`-joined `#define SEXTANT_SPEND_UNSPENT`/`_SPENT` (regex `_` is a word char, so no `\b` fires before `UNSPENT`) — the exact leak the gate exists to catch. FIXED: widened to a bare-substring `(un)?spent` match; PROVEN false-positive-free (0 matches on the clean header; the 10 legit `spend`/`SEXTANT_SPEND_*` tokens contain no `spent` substring) AND that it now FIRES (2 matches) on an injected `SEXTANT_SPEND_UNSPENT`/`_SPENT` header — the gate catches what it exists to catch. `scripts/harness.sh --full` exit 0 after the fix. VERDICT SHIP. |
| 2026-07-12 20:35 UTC | Independent verification of the autonomously-merged C-ABI export (PR #23, `17b270b`): VERDICT SHIP — safe variable-length marshalling, honest scope survives the C boundary, blst-free, deterministic | A SECOND independent `fluxpoint-loop:red-team-reviewer` (the loop's own was also SHIP) with EMPIRICAL checks: `nm` on the default-build `libsextant.a`/`.lib` shows `sextant_verify_utxo_read` present + ZERO `blst`/`mithril_stm`/`sextant_mithril_*` symbols; `cargo build --release --target wasm32` clean with the core export + 0 blst; `include/sextant.h` byte-identical to a fresh `make header` (drift gate real); header has 0 `(un)?spent` substrings + only `SEXTANT_SPEND_NOT_ESTABLISHED=0`; the widened harness grep fires on an injected `SEXTANT_SPEND_UNSPENT`/`_SPENT`. Marshalling traced: `copy_min` guards null/cap-0 + copies NOTHING (not a truncated prefix) on `-3`, `*out`+detail written LAST on every terminal path, no reachable OOB; honest scope holds (single constructor hardcodes `NotEstablished`, `#[non_exhaustive]` compile-tripwire, no positive-liveness constant); certified root honest-by-construction (only from the genesis-authenticated verify; malformed→327 before any out-write; None→has_ct=0). Operator flaky check: `--test ffi --test utxo --test inclusion` ×3 = 39 tests deterministic; 134 tests all-features. One LOW (the pre-existing `sextant_status_message` copies a truncated prefix on an undersized cap — the correct strlcpy-style contract for a LOG string, never verdict-bearing) → no fix needed. All four Woodpecker contexts green on merged main. **The C-ABI/WASM primitive is genuinely consumable end-to-end (a non-Rust consumer runs the verified read); the deferred FFI export is closed.** |

| 2026-07-12 20:05 UTC | BEYOND-DoD v0.2 Tier1 slice 1 (DoD stays DONE): `decode_spends` — the tx-INPUT decoder, the forward spend-scan signal — decodes a Conway body's consumed outpoints (key 0 inputs ∪ key 13 collateral, excluding key 18 reference inputs) on Sextant's own minicbor path, tag-258/bare-array duality handled, fail-closed | TDD: added the 5 named unit tests referencing not-yet-existing `decode_spends`/`OutPoint`/`SpendSet` → RED (`cargo test --lib utxo`: `cannot find type SpendSet` / `cannot find struct OutPoint`), then the minimum impl → GREEN. `pub struct OutPoint{tx_id:[u8;32], index:u16}` + `pub type SpendSet=BTreeSet<OutPoint>` + `pub fn decode_spends(&[u8])->Result<SpendSet,UtxoError>` in `src/utxo.rs`, DEFAULT wasm-safe graph (0 blst, 0 new deps, reuses `read_hash32`): scans the definite body map, key 0∪13 → `decode_input_set` (peeks `Type::Tag`==258 OR a bare array, both decode identically) → `decode_outpoint` (`u16::try_from` rejects an index wider than `uint .size 2`); key 18 + every other field `d.skip()`ped. Unit tests GREEN: `tag258_and_bare_array_decode_to_the_same_outpoint`, `collateral_key13_is_a_spend`, `reference_input_key18_is_not_a_spend` (only the spent input, not the referenced one), `malformed_input_body_is_malformed_tx` (a bare-uint set element), `overwide_index_is_malformed_tx` (65536→`MalformedTx`, 65535→Ok at `u16::MAX`) — the spec's uppercase `NOT`/`MalformedTx` normalized to snake_case for the `-D warnings` `non_snake_case` lint, intent unchanged. PLUS an added real-fixture differential `tests/utxo.rs::decode_spends_matches_pallas_inputs_on_the_golden_tx`: the golden `mithril-tx-body.cbor`'s consumed outpoints equal pallas's own decoded `inputs`+`collateral` sets byte-for-byte (non-empty; the same cross-decoder oracle every sibling decoder in this file carries — closes open-risk #3 tag-258/collateral → missed-spend on REAL bytes, the cardinal false-Unspent source). `scripts/harness.sh --full` exit 0 (HARNESS_GREEN — fmt, clippy `--all-targets --all-features -D warnings`, release, `cargo test --all-features` = 15 suites incl. `utxo`=8 (+1) and lib `utxo::tests`=13 (+5), wasm32 build, header drift-gate + leak/honest-scope greps; 0 failure markers). One clippy fix (`cloned_ref_to_slice_refs` → `std::slice::from_ref`). No FFI/`Cargo`/`.woodpecker`/header change (drift-gate clean); default+wasm graph untouched. PR + red-team next |
| 2026-07-12 20:05 UTC | Independent red-team of Tier1 slice 1 (PR #TBD): VERDICT TBD | pending `fluxpoint-loop:red-team-reviewer` on the diff |

## Notes for the next iteration
State (2026-07-12, latest — beyond-DoD Tier1 slice 1 `decode_spends` shipped): **STATUS: DONE holds.**
This iteration shipped the first build slice of the operator-ratified BEYOND-DoD v0.2 flagship
(Windowed-unspent Tier 1): `decode_spends`, the tx-INPUT decoder, in the default wasm-safe graph.
It decodes a Conway tx body's consumed outpoints — key 0 inputs ∪ key 13 collateral, EXCLUDING key 18
reference inputs (read, not consumed) — handling the CBOR set tag-258/bare-array duality and rejecting
an index wider than `u16`, failing closed to `MalformedTx` on any deviation. This is the forward
spend-scan primitive slice 3 (`verify_watched_window`) will compose: an outpoint's presence here, in a
body-committed block, is the on-chain evidence it was spent. Proven by 5 synthetic-CBOR unit tests +
a pallas differential over the real golden tx body (closes the cardinal "missed-spend → false Unspent"
risk on real bytes). Harness green locally; the C smoke leg is unchanged (no FFI touched this slice).
**Next slice = Tier1 slice 2 — the body-commitment BIND** (the CRUX / main red-team surface): stop
`d.skip()`-ing header_body idx 7 (`block_body_hash`), capture it + the RAW block[1..4] spans, and
require `blake2b256(blake2b256(raw tx_bodies) ‖ blake2b256(raw witness_sets) ‖ blake2b256(raw aux) ‖
blake2b256(raw invalid_txs)) == header idx 7` — binding the scanned bodies to the header-verified chain
(hash the RAW spans VERBATIM, never a re-encode; Cardano CBOR is non-canonical). Uses the existing
committed preprod block fixtures; tests `authentic_block_body_binds_to_its_header_commitment` +
`swapped_body_fails_the_bind`. See the "## Attacking next" spec for the full pinned design.

State (2026-07-12, earlier — beyond-DoD FFI export shipped): **STATUS: DONE holds.** This iteration
shipped the last open Plan item — the beyond-DoD C-ABI `sextant_verify_utxo_read` export + the
extended anchored verify (`out_ct_root`/`out_ct_block`/`out_has_ct`) + an end-to-end C consumer in
`tests/smoke/smoke.c` — closing the deferred FFI export. The verified read is now the primitive a
C/WASM downstream calls end-to-end (the compounding-leverage payoff): a consumer authenticates the
Mithril chain to genesis through `sextant_mithril_verify_chain_anchored`, takes the certified root
from the AUTHENTICATED tip (obtainable NO other way — honest by construction), and feeds it straight
into `sextant_verify_utxo_read`. `SEXTANT_ABI_VERSION` is now 2. **Plan is now empty; the DoD (lines
1–8) remains fully checked.** `scripts/harness.sh --full` is green locally (fmt, clippy
--all-targets --all-features -D warnings, release, `cargo test --all-features`, wasm32, header
drift + blst/mithril_stm leak + NEW `\b(un)?spent\b` honest-scope grep).
**ONE proof is CI-only-outstanding:** the C smoke consumer (`tests/smoke/smoke.c` + committed
`tests/smoke/utxo_fixture.h`) links `libsextant.a` through the committed header and is exercised
ONLY in Woodpecker (Windows-MSVC emits `sextant.lib`, not `libsextant.a`, so it cannot link with
`cc` locally). The local harness proves everything EXCEPT the real external C-linkage of the new
export; that lands green on the PR's `push/artifacts` context. Ship path: open the PR, wait for all
Woodpecker contexts green, red-team the diff, merge per policy. If a future iteration is requested
with NO operator-directed slice, there is no derivable DoD work left — the read-path client is
complete. Compounding follow-ons (operator's call, do NOT auto-derive): (a) a durable downloadable
release artifact (needs a CI publish secret — deferred); (b) Tier-2 `CertifiedUnspent` spend-status
when a Mithril ledger-state commitment ships (the `#[non_exhaustive]` ladder + the reserved ABI
bands are already shaped for it — additive, never a layout break); (c) the Zig embedding layer (was
out of scope until the Rust DoD; the C-ABI it targets is now complete incl. the UTxO read).

State (2026-07-12): **STATUS: DONE — every Definition-of-Done line is checked with proof recorded.**
DoD line 7 (Live) shipped as PR #22 (`28d112c`, red-team SHIP, all four Woodpecker contexts green):
`examples/verified_read_gate/{main.rs,gate.rs}` (a keeper/batcher stand-in for the out-of-scope
write-path) + `tests/consumer.rs` (which shares `gate.rs` via `#[path]`) run ONE control flow over
UNTRUSTED provider bytes: parse the 106-cert `mithril-anchor-chain.json` → `verify_chain_anchored`
(genesis-anchored, tip `b3582978…deea`) → take root+height ONLY from the AUTHENTICATED tip
(`Request` carries no root field — provider-root injection is type-impossible) → `verify_utxo_read`
→ a boolean spend gate. Both the authentic PROCEED and the spoofed-REFUSE paths run from ONE example
invocation (stdout = the DoD service-log excerpt) and are mirrored by the four `consumer` tests.
Fail-closed: every spoof (`tampered UTxO` → `Inclusion(NotIncluded)`, `wrong genesis vkey` →
`AnchoredError::Genesis`) makes a `verify_*` return Err BEFORE a VerifiedOutput exists, so the gate
is never reached. The gate NEVER branches on `spend_status`; the PROCEED note states the honest
scope verbatim.

**The read-path DoD is complete (all 8 lines).** The verify core (header VRF/opcert/KES on preprod
AND mainnet, chain-following + nonce across a real epoch boundary, the Mithril genesis-anchored trust
root, the proof-based certified UTxO read), the consumable C-ABI/WASM artifacts primitive, AND a
live downstream consumer that fail-closed-refuses a spoofed provider are all shipped and
red-teamed. **The one remaining follow-on (a NEW slice, NOT a DoD gap, operator's call whether to
pursue): the C-ABI `sextant_verify_utxo_read` export + `smoke.c` reference + cbindgen header regen**
— the caller-allocated-buffer ABI for `VerifiedOutput`'s variable-length address/optional inline
datum (`addr_buf`/`addr_cap` + `datum_buf`/`datum_cap` + out-lengths; `SpendStatus` → a fixed
`#[repr(i32)]`; `certified_at` a `u64` out-param), so a C/WASM consumer proves the read primitive
end-to-end over the boundary (the red-team "every export gains a `smoke.c` reference or it is not
proven retained" rule applies). This turns the verified read into the primitive a non-Rust
downstream calls — the compounding-leverage payoff. **DoD lines 2, 3, 4, 5, 6 are all CLOSED.** The
UTxO epic proved the loop's value AND the independent-red-team gate's: part 2's MMR verifier hid a
CRITICAL false-accept behind a green harness + green CI + a green ckb differential (a duplicate/
unconsumed leaf smuggled an arbitrary tx past membership under a real STM-authenticated root); only
adversarial malleability testing caught it. Every autonomous crypto merge still needs the
independent red-team + flaky check before it can be trusted. `src/utxo.rs` `verify_utxo_read(tx_bytes, out_index, proof_hex, certified_root,
block_number) -> Result<VerifiedOutput, UtxoError>` is the read path's terminal verdict, in the
DEFAULT wasm-safe graph (0 blst, 0 new deps): it hashes the SUPPLIED body → H
(`hash::blake2b256`, NEVER a provider-supplied H), composes the shipped
`inclusion::verify_tx_inclusion(H, …)` (root recomputed, never the proof's `inner_root`), then
decodes the Conway `TxOut` at `out_index` on Sextant's own minicbor path — map form
`{0:addr,1:value,2:datum_option,3:script_ref}` + legacy array `[addr,value(,datum_hash)]`; value =
bare coin OR `[coin,multiasset]` (lovelace only, multiasset skipped); inline datum
`[1,#6.24(bytes)]` and datum-hash options → `Datum::{Inline,Hash}`. Returns `{address, lovelace,
datum, certified_at, spend_status}`. The honesty is TYPE-level: `SpendStatus` has the single
inhabitant `NotEstablished` — the read path CANNOT and does not claim unspent (Cardano commits to
no UTxO-set accumulator; the certified transaction set trails tip ~100 blocks). Proven on the real
golden tx `242f2037…a636`: both outputs decode (idx 0 = script addr + 5 ADA + inline datum; idx 1
= base addr + 4_867_657_971 lovelace, no datum); NAMED negative `tampered_utxo_claim_is_rejected`
(flip an output lovelace byte → H changes → `Err(Inclusion(NotIncluded))` before any decode) +
substituted-bytes variant + exhaustive honesty guard + a mithril-gated end-to-end test binding the
read to a `verify_standard`-authenticated (genesis-anchorable via `verify_chain_anchored`) root.
Independent red-team VERDICT SHIP (0 findings); all 4 Woodpecker contexts green (pipeline 148).

**Attacking next — OPERATOR-STEERED (do NOT auto-derive): DoD line 7 (Live) is the only
remaining DoD line.** The verify core is COMPLETE — consensus (leader-VRF + opcert + KES on
preprod AND mainnet), chain-following + nonce, the Mithril genesis-anchored trust root, the
proof-based certified UTxO read, AND the consumable C-ABI/WASM artifacts primitive: **DoD lines 2,
3, 4, 5, 6 all CLOSED.** Line 7 is a different character and needs an operator decision — it
requires *a downstream consumer*: "the first downstream consumer's execution path performs one
verified UTxO read on preview against a real order before a spend decision, and rejects a spoofed
RPC response in the same test." Checkpoint the operator before attacking it.

**Prerequisite sub-slice for line 7 (the compounding-leverage payoff): the FFI export
`sextant_verify_utxo_read` + `smoke.c` reference + cbindgen header regen.** Deliberately deferred
from part 3 (which did NOT touch the C-ABI — header drift-gate stayed clean). Unlike the existing
allocation-free exports, `VerifiedOutput` carries a variable-length `address` and an optional
variable-length inline `datum`, so the export needs the caller-allocated-buffer ABI pattern
(caller passes `addr_buf`/`addr_cap` + `datum_buf`/`datum_cap` + out-lengths; `SpendStatus` maps
to a fixed `#[repr(i32)]`; `certified_at` is a `u64` out-param). The red-team "every export gains
a smoke.c reference or it is not proven retained" rule applies. This is the natural first step of
line 7: it turns the verified read into the primitive the downstream consumer calls through
C-ABI/WASM, then line 7 wires a real preview order + a spoofed-RPC-rejection test on top.

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

**[CLOSED 2026-07-12 — historical] DoD line 5: UTxO verification (design slice first).** Was
sequenced after Artifacts per operator choice; closed proof-based (parts 1–3, PRs #18–#20). The
design rationale, recorded here as history: decide snapshot-anchored vs proof-based in a design
slice, then implement with a tampered-claim negative. The Mithril chain of trust is
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

## Attacking next — BEYOND-DoD v0.2: Windowed-unspent Tier 1 (Unspent{WatchedWindow})
Design pinned by a spec workflow (follower-mechanism research + verdict/consumer/C-ABI research +
adversarial synthesis), OPERATOR-RATIFIED, build SLICE-BY-SLICE (red-team gate each). The Plan
lists the 5 slices; THIS is the shared design + the load-bearing invariants every slice must hold.
CURRENT slice = Tier1 slice 1 (`decode_spends`, the tx-INPUT decoder). The DoD stays DONE.

### The honest verdict (enforced by TYPE, not comment)
`WatchVerdict` has THREE terminal shapes and only ONE is Unspent — collapsing SpentObserved vs
Stalled is the cardinal honesty sin:
- `Unspent { as_of: WatchedTip, basis: WatchedWindow(WindowAssumptions) }` — no input spending the
  watched outpoint appears in any block body of a header-verified, hash-linked, GAP-FREE,
  BODY-COMMITTED segment from the Mithril anchor to a verified tip, under (a) Mithril-quorum +
  (b) data-completeness, follower live. `WatchedTip{anchor_height, as_of_height, as_of_slot}` — NO
  `now` field (the read path has no notion of current). `WindowAssumptions{mithril_quorum,
  data_complete}` are MANDATORY non-Option data (an Unspent is unconstructable without stamping its
  scope — a red-team asserting "assumptions surfaced" checks a field, not a docstring).
- `SpentObserved { at_height, at_slot, spending_txid }` — a DEFINITE refuse: a verified,
  body-committed block in the window carries a `transaction_input == the watched outpoint`.
- `Stalled { verified_through, reason }` — the NON-ANSWER; EVERY non-ideal condition lands here:
  `MissingBlock` (gap), `BodyCommitmentMismatch` (a body didn't hash to its header commitment),
  `BrokenSegment` (verify_segment BrokenLink), `TipTooOld` (tip older than the caller's lag bound).

### The cursed move (why it's honest)
Reframe the impossible "prove eternal-unspent" into "scan tx INPUTS forward over a cryptographically-
bound gap-free window." The adversary's only evasion — withhold the spending block — STRUCTURALLY
collapses to `Stalled`: withholding cannot advance the verified tip, and a non-advancing tip is
exactly what stall detection catches. There is NO code path by which withholding yields a fresher
`Unspent`. `verified_through`/`as_of` travels with every verdict (like `certified_at`) so no caller
reads a stale window as current.

### The anchor (existence at anchor)
Existence rests on CERTIFIED CREATION via inclusion (`verify_utxo_read` — a monotone "created"
predicate pinning the outpoint's BIRTH), NOT a ledger-state snapshot (that's Tier 2, needs a
full-ledger replay + a Mithril ledger-state cert that does not exist). The window START = the
creating block, identified INSIDE the verified body stream as the first block whose tx_bodies
contains a tx hashing to H; `create_seen` is a POSITIVE precondition (the window is valid only once
creation is observed inside it) — this closes the "start the window AFTER the spend" evasion.

### THE CRUX / the load-bearing new crypto (slice 2 — the main red-team surface)
`chain::verify_segment` authenticates HEADERS only; the spend signal is in the tx BODIES, and
`src/header.rs` currently `d.skip()`s header_body idx 7 (`block_body_hash`). A hostile provider could
hand real headers + SWAPPED bodies → a false Unspent. THE BIND: recompute `block_body_hash =
hashAlonzoSegWits = blake2b256( blake2b256(raw tx_bodies) ‖ blake2b256(raw witness_sets) ‖
blake2b256(raw aux_data) ‖ blake2b256(raw invalid_txs) )` over the RAW block[1..4] spans VERBATIM
(never a re-encode — Cardano CBOR is non-canonical; same "hash the exact bytes" rule the header_body
KES path follows) and require `== header idx 7`. Contiguity/gap is FREE from verify_segment
(BrokenLink on any reorder/gap/splice — Blake2b256 collision-resistance). Both endpoints PINNED:
anchor-end = the segment's low block reaches the creation + creation observed inside; tip-end = the
segment chains up to/through `certified_at` (below = Mithril+header agree; above, toward live tip
~100 blocks, only the header chain vouches and `as_of` says so). CHECKED invariant: `tip.n −
start.n + 1 == segment.len()` AND `verify_segment == Ok` AND creation observed at/above start.

### The consumer contract (Masumi escrow / ADAM spend-gate)
A three-clause AND, and clause C is the one naive impls forget: PROCEED iff (A) escrow funded at the
certified anchor [inclusion Ok]; AND (B) no spend through the verified tip [`Unspent{as_of,
WatchedWindow}`]; AND (C) the tip is recent enough FOR THE CALLER [`now_slot_estimate − as_of_slot ≤
max_lag`, enforced BY THE CONSUMER — Sextant proves "no spend through as_of", only the consumer knows
how stale is too stale for ITS economics]. MUST NOT: read `Unspent{as_of}` as tip-state or eternal;
fold `Stalled` into "probably fine" (a non-answer is a REFUSE); `SpentObserved` → definite refuse.
The honest gate (`examples/windowed_spend_gate`, slice 5) prints basis+anchor+as_of+lag+assumptions
on the SAME line as PROCEED — no bare `-> PROCEED` for a windowed verdict.

### C-ABI additive (slice 5) — the ladder banding
Additive only: new banded constant `SEXTANT_SPEND_UNSPENT_WATCHED_WINDOW=1` (the CRYPTOGRAPHIC-WITH-
ASSUMPTIONS band 1..=9; Tier-2 ledger-state reserved in the same band's free slots), outcome codes
`SEXTANT_WATCH_SPENT_OBSERVED=2`/`_STALLED=3` + stall-reason codes, a SIBLING `SextantWatchVerdict`
struct (never mutating `SextantVerifiedOutput` — its spend_status stays always 0), a
`sextant_verify_watched_window` export, `SEXTANT_ABI_VERSION` 2→3, header regen. The economic
ATTESTED band stays RESERVED + numerically FAR (100+), so an attestation can never be numerically
mistaken for a proof. NEVER define `SEXTANT_SPEND_UNSPENT` (unqualified) / `_ABSOLUTE` / `_ETERNAL`.

### Honest scope (the plain statement the tier carries)
`Unspent{WatchedWindow}` proves ONLY "no input spending the watched outpoint appears in any body of a
header-verified, hash-linked, gap-free, body-committed segment from the certified anchor to a
verified tip, under Mithril-quorum + data-completeness, as of the VERIFIED TIP." It is NOT absolute /
eternal / tip-state unspent, NOT a cryptographic proof of the negative, NOT a `CertifiedUnspent`
(Tier 2). The SPV lesson made precise: absence is only provable RELATIVE to a verified complete data
window under an availability assumption — Tier 1 SURFACES that assumption (as data + `as_of`) instead
of hiding it. Any gap / failed body-commitment / broken link / stale tip → `Stalled`, NEVER a false
`Unspent`.

### Buildable-now vs deferred
The ENTIRE verify core is buildable now over committed preprod fixtures, no network: body-bind +
input-decode + forward spend-scan + the fail-closed verdict. DEFERRED (explicitly, not diluted):
the live relay follower — the TRANSPORT that sources the contiguous body stream from the anchor to
the LIVE tip in real time (a chain-sync client / provider feed — a provider of BYTES, never a
verdict; Sextant re-verifies every block) + real-time `slot_now` from a clock + long-window
streaming performance.

### Open risks (per-slice red-team)
(1) A GAP/STALL BECOMING A FALSE UNSPENT — the cardinal failure. Adversarial tests: a window missing
block h+1 → `Stalled{MissingBlock}`; a window that STARTS AFTER the spend → `Stalled` (the Goodhart
evasion), never `Unspent`. (2) BODY NOT BOUND — without slice 2's `hashAlonzoSegWits` bind, real
headers + swapped bodies → false Unspent; test: swap a body → `Stalled{BodyCommitmentMismatch}`.
Watch the raw-span-vs-re-encode subtlety. (3) TAG-258 DUALITY / COLLATERAL — a decoder accepting one
set-encoding, or omitting key 13, misses a spend → false Unspent; decode both forms + key0∪key13.
(4) WATCHEDWINDOW COERCED INTO CERTIFIEDUNSPENT/ABSOLUTE — distinct variant + basis-as-value +
`#[non_exhaustive]` + no absolute/eternal constant + bands numerically apart; grep for any
Unspent construction omitting `WindowAssumptions`. (5) ASSUMPTIONS HIDDEN — mandatory data + named
on the PROCEED line. (6) WASM/FEATURE-GATE — the window core stays default+wasm32 (Blake2b + minicbor
only, no feature-gated crypto); the panic guard wraps the new export.

Infra: Woodpecker CI green through the whole DoD + the C-ABI export; the window core must stay
blst-free in default+wasm and the committed header drift-free.
