# Mithril recursion watch

**Decides:** ADR-005 (swappable checkpoint source), the M0 bakeoff spec (in-guest workload sizing), ADR-002 (recursion economics), and the ship-checklist Mithril-consumer note.
**Recon date:** 2026-07-14. Live-network numbers below were measured that day against the release aggregators and are reproducible with `GET /certificates` + a `previous_hash` walk.

---

## 1. What one certificate-chain verification costs (the M0 guest workload)

Sextant is the authority on the certificate formats and verification semantics — `D:/fluxPoint/sextant/src/mithril.rs` transcribes `mithril-common`'s hashing byte-for-byte (golden-tested against mithril's own vectors) and composes the full chain of trust in `verify_chain_anchored` = `verify_chain` (integrity + linkage + AVK binding) ∘ `verify_genesis` (Ed25519 root) ∘ `verify_standard` (STM multi-signature per rising certificate). Nothing here is re-derived; this section only *prices* what Sextant already settled.

Per **standard certificate** the guest executes:

1. **JSON parse + content-hash recompute** (`Certificate::compute_hash`): ~4 structural SHA-256 hashes plus one per listed signer (~114 on the mainnet tip cert), all over small buffers. Includes the `U8F24` `phi_f` fixed-point and chrono nanosecond timestamp encodings — already reproduced dependency-free in Sextant. Cheap.
2. **STM multi-signature verify** (`mithril_stm::AggregateSignature::verify`, concatenation proof system, per `ConcatenationProof::verify` in mithril-stm 0.10.5 `src/proof_system/concatenation/proof.rs`):
   - *Deserialize + validate*: one G1 point (48 B, `sig_validate` subgroup check) per single signature and one G2 verification key (96 B) per signer — mainnet median **59 single signatures** per certificate.
   - *Lottery eligibility* (`check_indices` → `evaluate_dense_mapping` → `is_lottery_won`): per lottery index, one **Blake2b-512** hash over `"map" ‖ msgp ‖ index ‖ σ` (~160 B input) plus a **num-bigint rational Taylor-series comparison** (bounded at 1000 iterations, early-exit; `src/proof_system/concatenation/eligibility.rs`). Mainnet median **2,434 indices** per certificate (k = 1,944). This is the dominant *non-curve* cost and is pure bignum arithmetic — likely a large cycle sink in a zkVM; measure it separately in M0.
   - *AVK membership*: one Merkle **batch path** verification (Blake2b-256) covering all ~59 contributing signers against the 244-leaf registered-signer tree (~59 leaf hashes + ~53 sibling nodes on the tip cert).
   - *BLS aggregate check* (`BlsSignature::verify_aggregate`, blst `min_sig`: signatures G1, vks G2): scalars derived by hashing all signatures (Blake2b), then a **~59-point G1 MSM + ~59-point G2 MSM** (128-bit scalars, random-linear-combination aggregation), one **hash-to-curve into G1**, and **one pairing equation** (2 Miller loops + final exponentiation).
3. **Genesis certificate** (chain root, once per chain): one strict **Ed25519** verify under the pinned per-network genesis vkey — Sextant's own `ed25519` path.

Per-certificate wire size: mainnet median **~126 KB** JSON (multi_signature ~49 KB binary); preprod median **~5.5 KB** (k=5, m=100, phi_f=0.7, 1 single sig, ~11 indices, 25-leaf AVK). Mainnet parameters: **k=1,944, m=16,948, phi_f=0.2**, AVK 244 leaves, total ~114 listed signers (55–81 contributing single signatures observed across the current chain).

**Load-bearing build finding:** mithril-stm hardcodes `blst` (`[dependencies.blst]` in its Cargo.toml — C + assembly, no backend feature). Sextant consumes `mithril-stm = 0.10.5, default-features = false, features = ["num-integer-backend"]` (no GMP, wasm-safe; `future_snark` OFF, so no Midnight dependencies enter the graph). For a zkVM guest, blst must cross-compile as portable C to the vendor's RISC-V target **without** any precompile acceleration — SP1's and RISC Zero's BLS12-381 accelerations patch pure-Rust crates (`bls12_381`-family), not blst's C. The pairing + 2 MSMs per certificate in un-accelerated portable C is plausibly the whole M0 bill. This must be resolved in the bakeoff spec: either (a) prove blst-portable-C compiles and eat the cycles, or (b) a `mithril-stm` BLS-backend swap (see asks, §4). Option (b) touches upstream, not a Sextant fork — consistent with "Sextant is upstream, never a fork."

---

## 2. THE WATCH ITEM (ADR-005): upstream SNARK-friendly / recursive certificates

**Status: prototype essentially complete and running on an internal test network; not productized, no announced activation date for release networks.**

### Code reality (verifiable locally — mithril-stm 0.10.5 on crates.io, the exact version Sextant pins)

Behind the `future_snark` feature (off by default), the crate already ships the entire SNARK track:

- `proof_system/halo2_snark/` — a **second proof system** alongside concatenation: single signatures become **unique Schnorr signatures over JubJub**, the AVK becomes a **Poseidon-hashed Merkle commitment**, and the aggregate is a **Halo2/KZG SNARK proof** (`SnarkProof`) proving: every witness signature valid, every lottery index winning/unique, every leaf's Merkle path valid, ≥ k indices (doc comment on `SnarkProof::verify`, `src/proof_system/halo2_snark/proof.rs`).
- `circuits/halo2/` — the STM circuit (lottery, merkle-path, comparison, unique-Schnorr gadgets), golden-tested.
- `circuits/halo2_ivc/` — **the recursion**: module doc says it is "the landing zone for the recursive SNARK / IVC prototype... moved from the standalone recursive prototype... until the recursive circuit is wired into STM." Its IVC `State` (`src/circuits/halo2_ivc/state.rs`) is `{counter, msg, merkle_root, next_merkle_root, protocol_params, next_protocol_params, current_epoch}` — i.e. **exactly the per-epoch checkpoint state heliograph's ADR-002 plans to carry** (AVK, next-AVK, params, epoch). The convergence is near 1:1.
- `AggregateSignature` is now an enum: `Snark(Box<SnarkProof>)` behind `future_snark`, with `Concatenation` kept `#[serde(untagged)]` for backward compatibility (`src/protocol/aggregate_signature/signature.rs`) — old clients keep parsing concatenation certificates unchanged.
- Dual registration entries (`snark_registration_entry.rs` + `concatenation_registration_entry.rs`): signers register both key types; concatenation proofs strip SNARK fields to avoid breaking existing clients.
- The proving stack is **Midnight's** (`midnight-circuits`, `midnight-curves`, `midnight-proofs`, `midnight-zk-stdlib`): Halo2-style PLONK over **BLS12-381 KZG** (blstrs emulation), JubJub native curve, Poseidon hashing.
- **Caveat in the code itself:** `SnarkProof::verify` regenerates its `SnarkSetup` (SRS) inside the function — commented as temporary "until the circuit is stable and the srs is stored and available." The trusted setup is not yet a pinned, distributed artifact.

### Issue/milestone trail (github.com/input-output-hk/mithril)

- Milestone **"05 - Succinct Mithril Proofs"**, due **2026-06-30**, shown **84% complete (16/19 issues)** as of this recon. Core epics all closed between Dec 2025 and Jun 2026: #2551 (prepare SNARK-friendly STM), #2791 (STM refactor for SNARK-friendliness), #2792 (pre-aggregation primitives Phase 1), #2796 (Halo2 circuit MVP), **#2807 (Recursive SNARK PoC)**, #2820/#2890 (SNARK-friendly STM MVP Phases 1–2), **#2886 (recursive Halo2 circuit MVP)**, #2892 (SNARK-friendly Mithril nodes), #2818/#2891 (Bitcoin DeFi use-case feasibility Phases 1–2 — note the driving consumer is a Bitcoin bridge/DeFi story, i.e. exactly heliograph's "portable verdict" shape pointed at another chain).
- Weekly-update work items: #2811 (adapt certificate chain to support SNARK AVK), #2915 (authenticated signer registration for SNARK), #2993 (hash-to-curve CPU/circuit discrepancy — closed), #3138 (prepare prover input), #3140 (verify SNARK proof), **#3141 (wire SNARK proof in aggregate signature — done)**, **#3142 (recursive SNARK e2e tests — done)**, **#3147 (adapt certificate chain to support recursive SNARK — done)**; open: **#3300 (refactor the *unsafe SNARK setup*)**, **#3319 (refactor prover input preparation)**.
- Intersect updates: 2026-07-01 — recursive SNARK proof **wired into the aggregate signature, integrated in e2e tests, and deployed on a test network**; 2026-06-17 — "adapted the certificate chain to support recursive SNARKs," **Midnight ZK library audit** in progress; June 2026 weekly reports — **SNARK-friendly genesis certificate** and **dual-signature genesis certificate** implementation.
- Parallel track still open: **#2552 "ALBA for Concatenation proof system - MVP"** — an ALBA-based compression of the concatenation proof, a different (non-SNARK) certificate-compression endgame. Watch it too; it would shrink certificate bytes without changing the verifier class.

### What a native recursive certificate would replace in heliograph's checkpoint leg

Today heliograph's ADR-002 plan is: prove the genesis→tip walk once (105 STM verifies in-guest, §3), then extend by one certificate per proof composition. A native recursive Mithril certificate collapses that entire leg: the guest would verify **one Halo2/KZG proof** whose public state binds `(epoch, AVK root, next-AVK root, params, msg)` — the same state heliograph's checkpoint journal carries — instead of re-executing the STM walk. Heliograph's own recursion then remains only for composing header-segment and inclusion legs onto the checkpoint. That is precisely the ADR-005 trait boundary: `checkpoint source = {proven-STM-walk | native-recursive-certificate}` with identical claim semantics and tier, differing only in the verification workload and in *whose* proof system is trusted (heliograph's zkVM vendor vs. Midnight's audited Halo2/KZG + its SRS). Note the trust surface does not vanish — it moves: image ID → circuit VK + SRS provenance.

**Timeline read (honest):** primitives done, e2e running on an internal test network, but productization gates remain — unsafe-setup refactor (#3300), Midnight ZK audit, aggregator wire format, dual-signature genesis rollout, signer re-registration with Schnorr keys, and (by precedent) an era switch + possible re-genesis to activate. The Pythagoras era switch took months from primitives to mainnet. No public date for release-preprod/mainnet activation exists. **ADR-005's trait stays; do not block v0.1 on this.**

---

## 3. Certificate-chain economics (measured 2026-07-14)

**Chain-link structure** (matches Sextant's `verify_chain` AVK-binding rule and the Mithril certificates doc): every certificate in an epoch carries the **same** `previous_hash` — all 20 tip-epoch certs on both networks pointed at one parent. The docs confirm: "it is sufficient to link to only one certificate from the previous epoch"; verification checks the current AVK "is part of the message signed by the multi-signature of the previous certificate." **The walk is one hop per epoch**, regardless of how many certificates the epoch emits.

Measured by walking `previous_hash` from tip to genesis on the live aggregators:

| | preprod | mainnet |
|---|---|---|
| Tip epoch (2026-07-14) | 300 | 643 |
| Genesis cert epoch | **196** (sealed 2025-02-09) | **539** (sealed 2025-02-13) |
| Certificates tip→genesis | **106** (105 hops, no gaps) | **106** (105 hops, no gaps) |
| Total wire bytes, full chain | **0.63 MB** (median cert 5.5 KB) | **13.24 MB** (median cert 126 KB) |
| Params (k / m / phi_f) | 5 / 100 / 0.7 | 1,944 / 16,948 / 0.2 |
| Single sigs per cert (min/med/max) | 1 / 1 / 3 | 48 / 59 / 81 |
| Lottery indices per cert (min/med/max) | 5 / 11 / 37 | 1,944 / 2,434 / 2,484 |
| AVK leaves (registered signers) | 25 | 244 |

Both chains are ~105 hops because both were **re-genesised in February 2025** (mainnet: Pythagoras era switch at epoch 539 + the certificate-chain client security advisory of 2025-02-14 / GHSA-724h-fpm5-4qvr). Re-genesis is a real, recurring event: it resets chain length and **rotates heliograph's chain root** — the pinned genesis vkey/cert must be a versioned input of the checkpoint claim, not a constant baked into the image.

**Certificate emission vs. chain depth:** mainnet emits a CardanoTransactions certificate roughly every **9–10 minutes** (~765/epoch), but chain depth grows **one per 5-day epoch (~73/year)**. Tip freshness for a `CardanoTransactions` claim advances every ~10 minutes at the cost of one certificate verify against the already-proven epoch state.

**The numbers ADR-002 rests on:**
- **Full-chain re-verify (mainnet, today):** 1 Ed25519 + **105 STM verifies** ≈ 105 pairing checks + 210 MSMs (~59 points each) + ~256k lottery evaluations (Blake2b-512 + bignum Taylor each) + ~13.2 MB of guest input.
- **Extend-by-one:** hash/link/AVK-bind checks + **1 STM verify** ≈ 1 pairing check + 2 MSMs + ~2.4k lottery evals + ~126 KB input. Same cost whether advancing the tip within an epoch (links to the already-proven per-epoch parent) or crossing an epoch boundary (AVK binding to the parent's committed next-AVK).
- **Amortization ratio ≈ 105× today, growing ~73/year** until the next re-genesis resets it. Recursion is not optional at mainnet scale: at plausible zkVM costs the full walk is minutes-to-hours of proving, while extend-by-one is the {{MAX_PROOF_TIME}}-shaped unit the bakeoff must price.
- Preprod is ~20× cheaper per certificate on every axis — right for CI and fixtures, **wrong for cost extrapolation**; M0 must bench a *mainnet-read-only* fixture too (k=1,944 vs k=5 changes the lottery-eval count by 200–400×).

---

## 4. What heliograph should ask of Mithril upstream (ranked by leverage)

1. **A pluggable BLS backend in mithril-stm** (feature or trait over the `blst` dependency), so zkVM-accelerated pure-Rust BLS12-381 implementations can substitute in guest builds. Unblocks M0/M1 *now*, independent of the SNARK track, benefits every constrained consumer (wasm, mobile, enclave), and keeps Sextant unforked. This is the highest-leverage ask because it is small, immediately actionable upstream, and heliograph's whole checkpoint leg rides on it.
2. **Pinned, documented SRS + circuit-VK provenance for the recursive certificate** (the #3300 "unsafe setup" refactor done right): whose KZG ceremony, how distributed, how versioned, and a stable versioned `SnarkProof` serialization with golden vectors. Heliograph treats a circuit VK the way it treats an image ID — a trust anchor whose rotation is a governed event. Without this, ADR-005's swap can never clear heliograph's fail-closed bar.
3. **An embeddable verifier with published cost:** keep `AggregateSignature::Snark` verification pure-Rust / `no_std`-friendly / wasm-compilable, and publish verifier-side numbers. Note for our own planning: KZG verification is still BLS12-381 pairings — inside a zkVM guest the precompile question (and ask #1's shape) returns at the SNARK layer.
4. **Fail-closed wire-format guarantees + activation plan:** confirm unknown `AggregateSignature` variants surface as parse errors to existing clients (the untagged-serde arrangement suggests yes — make it a stated guarantee with a vector), and state whether recursive-certificate activation implies an era switch / re-genesis / signer re-registration, with lead time. Consumers pin genesis anchors; re-genesis is a trust-anchor rotation on our side.
5. **Golden vectors for the SNARK-friendly protocol message and dual-signature genesis certificate** as soon as they stabilize — Sextant transcribed the current formats byte-for-byte from vectors; the same discipline needs the same inputs to arm test suites before the format freezes (the exact play from Sextant's UTxO-commitment note §5.8, which upstream has already seen).
6. **Publish the Midnight ZK library audit** (referenced in the 2026-06-17 update) when complete — it goes verbatim into heliograph's THREAT_MODEL vendor-trust surface alongside the zkVM vendor's own audit lineage.
7. **Access to the recursive-SNARK test network / fixtures** (per the 2026-07-01 update one exists): heliograph offers to be the first external verifying consumer of recursive certificates — the same first-consumer commitment Sextant made for the UTxO commitment, which is the relationship this note's ship-checklist item exists to build.

---

## 5. Honest unknowns

- **No public activation date or commitment** for recursive certificates on release-preprod/release-mainnet; "deployed in a test network" (2026-07-01) names no network and we found no public endpoint for it.
- **Coexistence vs. replacement** of concatenation and SNARK certificates on release networks is unstated (dual registration + untagged serde suggest long coexistence, but that is inference, not a source).
- **SRS provenance** (whose ceremony backs the KZG setup) is undocumented; the code regenerates setup in-function today.
- **Verifier-side cost of `SnarkProof::verify`** is unpublished; we did not benchmark it (needs `future_snark` + the Midnight stack, out of scope for this recon).
- **The ALBA track (#2552)** could produce a different compressed-certificate endgame; its verifier class (hash-based, likely zkVM-friendlier than pairings) is unassessed here.
- **Milestone counts** differed slightly between GitHub views during recon (84%, 16/19 vs. an issue listing showing 10 closed/1 open); treat percentages as approximate, the issue trail as authoritative.
- **Native STM verify wall-time** for a mainnet certificate was not measured here (Sextant's harness runs preprod fixtures); M0 must establish the native baseline alongside the in-guest numbers.
- The per-epoch hop certificates are whatever the aggregator emitted first that epoch (typically MithrilStakeDistribution); a `CardanoTransactions` claim additionally needs its tip certificate to be of that entity type — Sextant's `certified_transactions()` accessor already enforces reading only signed protocol-message parts (its doc comment records the forged-`signed_entity_type` pitfall; carry that verbatim into CLAIMS.md).

## Sources

- **Sextant (authority on formats/semantics):** `D:/fluxPoint/sextant/src/mithril.rs` (module docs, `verify_chain_anchored`, DoS bounds, `certified_transactions` signed-parts rule); `D:/fluxPoint/sextant/docs/mithril-utxo-commitment-note.md` (§2 SNARK-track reading, upstream contact precedent); `D:/fluxPoint/sextant/tests/vectors/mithril-cert-*.json` (preprod golden certs); `Cargo.toml` pin `mithril-stm = 0.10.5, default-features = false`.
- **mithril-stm 0.10.5 source (crates.io, local registry):** `src/proof_system/concatenation/{proof.rs,eligibility.rs,single_signature.rs}`, `src/signature_scheme/bls_multi_signature/signature.rs` (blst `min_sig`, RLC aggregation, `evaluate_dense_mapping`), `src/proof_system/halo2_snark/proof.rs` (SnarkProof + unsafe-setup comment), `src/circuits/halo2_ivc/{mod.rs,state.rs}` (IVC prototype + State), `src/protocol/aggregate_signature/signature.rs` (`Snark` variant, untagged back-compat), `Cargo.toml` (`future_snark` → midnight-* deps; hardcoded `blst`).
- **Mithril docs:** https://mithril.network/doc/mithril/advanced/mithril-protocol/certificates (chain structure, one-link-per-epoch, genesis anchor); https://mithril.network/doc/dev-blog/2025/02/14/client-security-advisory/ + GHSA-724h-fpm5-4qvr (Feb 2025 advisory, mainnet re-genesis at epoch 539, Pythagoras era switch).
- **Mithril repo:** milestone "05 - Succinct Mithril Proofs" (due 2026-06-30); issues #2551, #2552 (ALBA, open), #2791, #2792, #2796, #2807, #2811, #2818, #2820, #2886, #2890, #2891, #2892, #2915, #2993, #3138, #3140, #3141, #3142, #3147, #3300 (open), #3319 (open) — https://github.com/input-output-hk/mithril.
- **Intersect Mithril updates:** https://updates.cardano.intersectmbo.org/2026-07-01-mithril/ (SNARK proof wired into aggregate signature, e2e, test-network deployment); .../2026-06-17-mithril/ (cert chain adapted for recursive SNARKs, Midnight ZK audit); .../2026-06-03-mithril/ and cardano.org weekly reports 2026-06-12/06-19 (SNARK-friendly + dual-signature genesis certificate); .../2026-02-18-mithril/ (SNARK AVK, signer registration, hash-to-curve fix).
- **Live measurements (2026-07-14):** `https://aggregator.release-{mainnet,preprod}.api.mithril.network/aggregator/{certificates,certificate/{hash}}` — tip-to-genesis walks (106 certs each), per-cert multi-signature decodes (sig/index counts), byte totals. Method: follow `previous_hash` from tip until `genesis_signature` non-empty.
- **STM paper:** Chaidos & Kiayias et al., "Mithril: Stake-based Threshold Multisignatures," https://eprint.iacr.org/2021/916 (cited by mithril-stm as the protocol reference; concatenation = §4.3).
