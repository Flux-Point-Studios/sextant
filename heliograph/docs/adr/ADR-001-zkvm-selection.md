# ADR-001 — zkVM vendor selection (SP1 vs RISC Zero)

## Status

**SKELETON — decision deferred.** The DECISION section is a HANDOFF §9 human
gate (gate 2: "zkVM vendor selection sign-off (ADR-001)"). It is filled by the
M0 bakeoff numbers (BENCH.md Part II) against the signed §12 thresholds, and
requires human sign-off. This document freezes the **criteria** and the
**recording obligations** now; it does not — and must not — pick a vendor.

Phase: 1 (DESIGN). Blocks: nothing in Phase 1. Blocked by: M0 execution
(Phase 2) for its DECISION only.

## Context

Heliograph compiles Sextant's verification legs to a zkVM guest (HANDOFF §1).
Two vendors are in scope, both consumed as pinned, unmodified dependencies
(HANDOFF §2, §6): **SP1** (Succinct Labs, v6 "Hypercube" line) and **RISC Zero**
(v3.0.5 / risc0-ethereum v3.0.1). No third candidate is considered: the survey
of the light-client corpus (docs/notes/lightclient-patterns.md) found the
production ZK-light-client field is these two zkVM families plus custom
circuits, and custom circuits are forbidden without a §9 gate (HANDOFF §0
"No custom circuits", §9 gate 5, default answer no).

### The crux: BLS12-381 pairing, in-guest

The decision is dominated by one workload. Sextant's Mithril checkpoint leg
(claim `0x0001`, CLAIMS.md §3.1) terminates in an STM aggregate-signature
verification whose cost is a BLS12-381 pairing equation plus two ~N-point MSMs,
a hash-to-G1, per-index lottery evaluation, and AVK Merkle-path checks
(BENCH.md §2.1, mithril-recursion-watch §1). **Neither vendor ships a
BLS12-381 pairing precompile, a G2 precompile, or an MSM precompile.** The
pairing runs as guest software on both. This is the single fact that makes M0 a
real bakeoff rather than a formality — the vendors differ in *how* the software
pairing is accelerated, and that difference is unmeasured until M0:

- **SP1** (docs/notes/sp1.md §2): syscall registry exposes only BLS12-381 **G1
  add/double/decompress + Fp/Fp2 modular arithmetic** (`BLS12381_ADD` 0x1E,
  `BLS12381_DOUBLE` 0x1F, `BLS12381_DECOMPRESS` 0x1C, `BLS12381_FP_*` 0x20-0x22,
  `BLS12381_FP2_*` 0x23-0x25). No pairing, no G2 ops, no MSM. The
  vendor-maintained patched crate `sp1-patches/bls12_381`
  (tag `patch-0.8.0-sp1-6.0.0`, fork of zkcrypto `bls12_381` 0.8.0) routes
  base-field and Fp2 arithmetic through those syscalls, so G2 and the Fp12
  pairing tower are *partially* accelerated. `mithril-stm` 0.10.5's hardcoded
  `blst` (C + asm) **cannot** ride SP1's patch mechanism — SP1 patches pure-Rust
  crates only (docs/notes/sp1.md §2, BENCH.md §6.1). The SP1 path therefore
  **requires a pure-Rust STM backend seam** (Sextant upstream `guest` feature /
  mithril-stm backend swap — docs/notes/sextant-upstream-needs.md). Vendor
  planning prior, not a result: `kzg-rs` `verify_kzg_proof` = 9,390,640 cycles
  (≈ one 2-pairing product + G1/G2 mults on the patched crate), order-of-
  magnitude "a few million cycles per pairing" (docs/notes/sp1.md §2). No
  vendor cycle count exists for an STM verify.

- **RISC Zero** (docs/notes/risc0.md §2): likewise **no pairing precompile and
  no G2 precompile**. What the rv32im v2 circuit provides via `risc0-bigint2`:
  384-bit Fp `modmul/modinv/modadd/modsub`, 384-bit **Fp2** ops
  (`extfield_deg2_*_384`, `extfield_xxone_mul_384`), and 384-bit G1
  `ec_add`/`ec_double`. The pairing runs as guest software over those
  accelerated ops. **Decisive vendor asymmetry:** RISC Zero ships an
  **accelerated `blst` fork** at tag **`v0.3.16-risczero.0`**, which
  **matches `mithril-stm` 0.10.5's exact `blst = 0.3.16` pin** (docs/notes/
  risc0.md §1-2 "Mithril seam"). The fork remaps blst's field arithmetic onto
  `risc0_bigint_modmul_384`/`modinv_384`/`extfield_xxone_mul_384` and blst's
  SHA-256 onto `sys_sha_buffer`; the Miller loop, final exponentiation, G2, and
  hash-to-curve remain compiled C over accelerated limbs. This raises the
  possibility of accelerated STM verification in-guest via a single
  `[patch.crates-io]` line and **zero Sextant changes** (STATUS.md; docs/notes/
  sextant-upstream-needs.md), where the SP1 path needs the pure-Rust backend
  seam. That possibility is **unproven** — it is the first M0 experiment
  (BENCH.md §6.2, spike S-0001), with three documented outcome branches
  (accelerated blst compiles/runs; unaccelerated control; compile fails →
  fall back to the pure-Rust `risc0/zkcrypto-bls12_381` seam, same backend
  class as SP1). RISC Zero also has no vendor cycle count for a pairing or STM
  verify (docs/notes/risc0.md §2).

The two paths are not comparable on paper. SP1's cycle unit is RV64IM, RISC
Zero's is RV32IM; the costing models differ and **cycle counts are not
cross-vendor comparable** (BENCH.md §4.1). Comparison happens only on wall
time, dollars, proof bytes, and gas. That is why the decision is deferred to
measured numbers.

### Secondary factors, all recorded but subordinate to the crux

These are inputs to the writeup, not tie-breakers that override the threshold
gate. They are captured here so the M0 decision memo weighs them explicitly:

- **Recursion / composition** (ADR-002 dependency). Both support verify-inside-
  guest: SP1 `verify_sp1_proof` (deferred, compressed proofs only —
  docs/notes/sp1.md §6); RISC Zero `env::verify` + `resolve` (assumption-based,
  ~zero guest cycles for the inner verify — docs/notes/risc0.md §6). Both have
  the same *self*-recursion caveat (a guest cannot embed its own image ID as a
  compile-time constant; the inner ID becomes a journaled input — CLAIMS.md §2.3,
  §3.2). The RISC Zero self-recursion inner-ID pattern is vendor-undocumented
  and is an M1 spike before ADR-002 freeze (docs/notes/risc0.md §7.4).
- **On-chain verifier + admin surface.** Both ship audited Groth16 verifiers
  deployed on Base Sepolia (the signed `EVM_TESTNET`): SP1 gateway
  `0x397A5f7f...4448dA9B` (docs/notes/sp1.md §4); RISC Zero router
  `0x0b144e07...a86fb711` + verifier `0x2a098988...49Fa84D` (docs/notes/
  risc0.md §4). RISC Zero's governance is more fully documented (router owned
  by `TimelockController`, tombstoned selectors, permissionless proof-of-
  unsoundness circuit breaker — docs/notes/risc0.md §4); **SP1 gateway
  ownership is undocumented on the fetched pages and must be resolved before M4**
  (docs/notes/sp1.md open item 5; THREAT_MODEL A8 residual risk).
- **Reproducible builds** (ADR-004 dependency). Both require a pinned Docker
  toolchain for a canonical image ID; non-docker builds are non-reproducible on
  both (docs/notes/sp1.md §1, docs/notes/risc0.md §1). No differentiator.
- **Trusted-setup provenance of the wrap circuit** (THREAT_MODEL A7). SP1
  Groth16 = circuit-specific ceremony (18 named participants); RISC Zero
  Groth16 = PSE-coordinated, **independently re-verifiable** ceremony (pinned
  `stark_verify.r1cs` SHA-256, documented `snarkjs zkey verify`). RISC Zero is
  the stronger provenance story of the two (docs/notes/risc0.md §3,
  docs/notes/sp1.md §3). Documented, not a threshold.
- **Licensing** (HANDOFF §6, Apache-2.0/MIT only). Both permissive. One
  SP1-path flag: `sp1-contracts` has no root LICENSE file (SPDX-per-file MIT) —
  confirm before vendoring the verifier byte-identical (docs/notes/sp1.md §5).
  No copyleft on either dependency surface.
- **Guest ergonomics.** SP1's `succinct` toolchain builds std for the guest
  (RV64IM); RISC Zero targets RV32IM and supports both std and no_std. Sextant's
  default graph is already ~`no_std + alloc`-clean; the one blocker is the
  `mithril` leg's blst + rayon (STATUS.md; docs/notes/sextant-upstream-needs.md).
  Ergonomics do not decide the gate.

### What "identical guest workload" pins (so the numbers are commensurable)

M0 is judged fairly only if both vendors prove the *same thing*. BENCH.md §2.2
fixes this: identical input bytes (the pinned fixtures F-PP1, F-MN1), identical
verification semantics (the same Sextant code at commit `3a68b2f`), and
**byte-identical journals** equal to the committed golden journal. What is
allowed to differ per vendor is exactly what M0 prices — the BLS12-381 / STM
backend under `AggregateSignature::verify` (BENCH.md §2.2, §6). Every backend
configuration must pass the differential check (guest verdict == native Sextant
verdict) on both the golden fixture and the tamper control (BENCH.md §2.4).

## Decision

**DEFERRED — filled by M0, human sign-off required.**

No vendor is selected in this ADR. The selection is HANDOFF §9 gate 2 and is
made by applying the criteria below to the BENCH.md Part II run ledger after M0
executes. When the numbers exist and the human has signed off, this section is
replaced with: the chosen vendor, the exact stack pin (stack-registry ID), the
W-MN1 end-to-end wall time and cost that cleared the thresholds, the loser's
same numbers, and the sign-off record. Until then the answer is DEFERRED, in
these words, by design.

If the M0 go/no-go gate returns **no-go** (the better vendor exceeds a
threshold), this ADR is *not* resolved by picking the less-bad vendor: the gate
escalates per §12 (below) and vendor selection waits on that escalation's
outcome.

## Decision criteria (frozen now; binding at M0)

The criteria are wired to the **signed** BENCH.md §5 thresholds (human
greenlight 2026-07-14). All are measured on `BENCH_HARDWARE = AWS g6e.xlarge`
(1× NVIDIA L40S 48 GB, x86-64 host — the SKU is signed and satisfies both
vendors' hard constraints, including RISC Zero's x86-only Groth16 wrap —
BENCH.md §5).

### C1 — Threshold gate (necessary; a vendor that fails it cannot be selected)

The threshold-bearing result is the **better vendor's W-MN1 end-to-end** (the
mainnet-read-only certificate F-MN1, fixture bytes in → Groth16 proof out) on
the pinned SKU, with the differential check and validity controls green
(BENCH.md §5):

- **`MAX_PROOF_TIME` ≤ 10 min per checkpoint-update.** W-MN1 is the checkpoint-
  update proxy (BENCH.md §2.1: extend-by-one at mainnet scale ≈ hash/link/AVK-
  bind + exactly one `verify_standard`; the link/bind overhead is hashing noise
  next to the STM verify).
- **`MAX_PROOF_COST` ≤ $1 per update**, computed per BENCH.md §4.4
  (`cost_usd = e2e proving wall time × pinned-SKU on-demand list price`; no spot
  pricing, no amortization, source URL + retrieval date recorded).

F-MN1 is **mandatory**: preprod (F-PP1) under-exercises mainnet parameters by
orders of magnitude (k=5 vs k=1,944; ~37 vs ~2,434 lottery indices; 1 vs ~59
single signatures — BENCH.md §3.3, mithril-recursion-watch §3). A bakeoff
without F-MN1 cannot be judged against the thresholds and does not satisfy the
M0 gate (BENCH.md §3.2). A vendor whose W-MN1 exceeds either threshold is
disqualified from selection, full stop — there is no "close enough."

### C2 — Validity gate (necessary; proves the numbers are not vacuous)

A vendor's numbers are eligible for comparison only if, for both fixtures:

- **Differential check green** (BENCH.md §2.2, §2.4): guest verdict == native
  Sextant (`mithril-stm` 0.10.5 + `blst`) verdict on the same fixture bytes,
  for the golden fixture AND the single-flipped-byte tamper control (the tamper
  control must run on the **patched/accelerated** configuration specifically —
  BENCH.md §2.4, §6.1).
- **Determinism check green** (BENCH.md §2.4): each threshold-bearing
  configuration runs twice; journal bytes identical across runs and across
  vendors (== golden). This is where SP1's hint/unconstrained nondeterminism
  surface would show (docs/notes/sp1.md §1, open item 2; THREAT_MODEL A1).
- **Byte-identical golden journal** emitted by both vendors' guests
  (BENCH.md §2.3).
- **Reproducible image ID demonstrated** for that vendor before its numbers may
  be cited: two independent builds → identical vkey/image ID via the pinned
  Docker toolchain (BENCH.md §4.5; ADR-004 preview). A vendor whose measured
  binary is not reproducibly identified is not citable in this ADR.

### C3 — Ranking among vendors that pass C1 + C2 (sufficient, in order)

If both vendors clear C1 and C2, rank on the measured numbers in this
precedence, all from the BENCH.md ledger, all on F-MN1:

1. **End-to-end proving wall time** (the `MAX_PROOF_TIME`-shaped number).
2. **Proving cost USD** (the `MAX_PROOF_COST`-shaped number).
3. **On-chain verify gas** — measured in a local Foundry fork test against the
   vendor's audited verifier, never a folk number (BENCH.md §4.2 item 9;
   RISC Zero has no citable vendor gas figure — docs/notes/risc0.md §4).
4. **Wrapped proof bytes** (SP1 Groth16 ~260 B; RISC Zero Groth16Receipt is a
   small validity proof — recorded, not assumed).
5. **Secondary factors from Context**, as documented tie-breakers only: admin-
   surface clarity (SP1 gateway ownership must be resolved — docs/notes/sp1.md
   open item 5), wrap-ceremony re-verifiability (RISC Zero's edge — A7), and the
   integration cost differential (RISC Zero's blst-fork path plausibly needs
   zero Sextant changes vs SP1's required pure-Rust backend seam — STATUS.md,
   docs/notes/sextant-upstream-needs.md). These break a tie; they never
   override C1.

### C4 — Recording obligation (both vendors, win or lose)

Per HANDOFF §4 ("Record the loser's numbers too") and BENCH.md §7, the M0
resolution of this ADR records, for **both** vendors, whether selected or not:
every §4.2 metric on both fixtures, the stage-split cycles on F-MN1 (parse+hash
/ lottery / MSM+pairing / other — BENCH.md §4.2 item 11, §8.5), the native
baseline rows (BENCH.md §4.3), the spike outcomes (BENCH.md §8.6, incl. S-0001
the RISC Zero blst-patch compile spike), and the backend actually linked (a
mandatory per-row annotation — BENCH.md §2.2). The loser's numbers are part of
the permanent record because the revisit trigger (below) and any future re-
bakeoff read against them. A selection that discards the loser's numbers is
not a valid resolution of this ADR.

## Consequences

- **Positive.** The decision is made on numbers against pre-signed thresholds,
  not vendor marketing — Goodhart-resistant by construction (the threshold is
  set before the measurement, by a human, in BENCH.md §5). The loser's full
  ledger stays available, so a later vendor re-selection is a re-read of
  recorded numbers, not a fresh investigation. Both vendors' verifiers already
  live on Base Sepolia, so the M4 path is open whichever way the gate falls.
- **Negative / accepted.** The vendor choice is a **trust-anchor commitment**:
  the selected vendor's image ID is heliograph's trust anchor (ADR-004), and its
  proof system + wrap ceremony are load-bearing, documented-not-verified trust
  (THREAT_MODEL §3 vendor-trust table, A7). Switching vendors later rotates
  every image ID — a governed event (below). Until M0 runs, downstream ADRs
  that touch vendor specifics (ADR-002 recursion mechanism, ADR-004 image-ID
  construction) carry a vendor-conditional branch and cannot fully freeze their
  vendor-specific wording; they name both paths and resolve on this ADR's
  DECISION.
- **Liveness of this ADR.** This skeleton unblocks all of Phase 1 (nothing in
  Phase 1 needs the vendor picked). It blocks only its own DECISION, which is a
  Phase-2 event. No Phase-1 gate waits on it.

## Revisit trigger

This ADR is re-opened — a new dated decision memo appended, human sign-off re-
required — on any of:

1. **Native recursive Mithril certificates become viable (ADR-005).** Upstream
   Mithril is wiring a Halo2/KZG recursive-SNARK certificate (unique-Schnorr-
   over-JubJub signatures, Poseidon AVK commitment, `SnarkProof` aggregate —
   docs/notes/mithril-recursion-watch §2; as of 2026-07-01 wired into the
   aggregate signature, integrated in e2e tests, deployed on an unnamed test
   network — §4, §5). If ADR-005's swappable checkpoint source replaces the
   proven STM walk with native recursive certificates, the in-guest workload
   that dominates this bakeoff (the BLS12-381 software pairing) **changes
   entirely**, and the trust surface **moves rather than vanishes**: image ID →
   Midnight Halo2/KZG circuit VK + SRS provenance (THREAT_MODEL §3 watch row).
   The swap cannot clear heliograph's fail-closed bar until that VK/SRS
   provenance is pinned and the Midnight ZK library audit is published
   (mithril-recursion-watch §2, §4 asks 2 and 6). When it can, the vendor
   bakeoff is re-run against the *new* workload — a different M0, a fresh
   DECISION.
2. **A zkVM vendor/version bump that rotates image IDs.** Any change to the
   selected vendor's zkVM crates, patched-crate tags, Docker toolchain tag, or
   wrap circuit that changes the vkey/image ID is a HANDOFF §9 gate 2 event
   (image-ID rotation = trust-anchor rotation, HANDOFF §6). Re-pin the vendor-
   trust table (THREAT_MODEL §3, "re-pinned at every vendor bump"), re-run
   T-A7-1/T-A7-2 (wrap-artifact digest pins; RISC Zero ceremony re-verification),
   and re-confirm the thresholds still hold on the new stack. A version bump is
   not automatically a re-selection, but it is a gated re-validation.
3. **A threshold amendment.** Any change to the signed BENCH.md §5 thresholds
   is a new dated spec revision requiring the same human sign-off (BENCH.md §5),
   and invalidates a prior selection made against the old thresholds.

Absent a trigger, the M0 DECISION stands.

## Alternatives considered

- **Pick a vendor now, on paper.** Rejected: the crux (in-guest BLS12-381
  pairing cost on real STM certificates) has **no vendor-published cycle count
  on either side** (docs/notes/sp1.md open item 1, docs/notes/risc0.md §7 item
  1); the closest prior (`kzg-rs` 9.39M cycles/KZG check) is a proxy, not an
  STM-verify measurement. Selecting on marketing or folk numbers is exactly the
  "vibes" HANDOFF §4 forbids. The whole point of M0 is that this number does not
  yet exist.
- **Assume RISC Zero on the strength of the blst-fork match.** Tempting — the
  `v0.3.16-risczero.0` fork matches `mithril-stm` 0.10.5's exact pin and hints
  at zero Sextant changes (STATUS.md, docs/notes/risc0.md §2). Rejected as a
  *decision*: the accelerated path is **unproven** until the S-0001 compile
  spike runs (blst `portable` feature × the risc0 C build path; mithril-stm's
  unconditional `rayon`; blst APIs outside the fork's accelerated surface —
  BENCH.md §6.2). It is a strong prior that shapes the *expected* outcome, not a
  substitute for the wall-time and cost numbers the thresholds are written
  against. Recorded as a factor (C3.5), not a verdict.

  > **S-0001/S-0002 resolved (2026-07-14, BENCH.md §8.6): BOTH arms compile,
  > zero Sextant changes.** RISC Zero: vanilla blst C *and* the accelerated
  > fork both build+link (the §6.2 control pair is obtainable); rayon
  > compiles/links under guest std (runtime behavior an M0 item); image ID
  > derived, same-host reproducible. SP1: blocks stock at the blst cc wall as
  > predicted, but a Debian riscv cross-gcc unblocks it (vendor-unblessed,
  > unaccelerated — the `sp1-patches/bls12_381` pure-Rust seam stays the
  > documented primary for threshold-bearing rows). Consequence: the bakeoff
  > proceeds with BOTH arms measurable; the compile question no longer
  > discriminates. The DECISION remains deferred to M0 *numbers* per this
  > ADR's criteria — nothing here picks a vendor.
- **Run both vendors in production (no selection).** Rejected for v0.1: two
  vendors means two image-ID trust anchors, two wrap ceremonies, two verifier
  admin surfaces, and doubled reproducible-build and audit-scoping obligations
  (THREAT_MODEL A3, A6, A7, A8) — multiplicative trust-surface cost for no
  product gain, since a proof from either verifies the same Cardano fact.
  Multi-prover is a designed-for future (N independent provers of the *same*
  guest — HANDOFF §2), not multi-vendor. The proofs being permissionlessly
  verifiable keeps the option open without paying for it now.
- **Custom BLS12-381 pairing circuit (bypass both zkVMs' software pairing).**
  Rejected by policy: custom circuits are a HANDOFF §9 gate 5 with a default
  answer of no, and v0.1 is zkVM-only (HANDOFF §0 "No custom circuits"). Named
  here only to record that the pairing-cost crux does *not* license circuit
  work as a workaround; the escalation path for a failed threshold is BENCH.md
  §5's three options (wait for native recursive certs; narrower claims; hybrid
  models), not a bespoke circuit.
- **A third zkVM (Jolt, Nexus, Valida, etc.).** Not evaluated: outside the
  recon scope (HANDOFF §8 names SP1 and RISC Zero), none surfaced in the
  production light-client corpus (docs/notes/lightclient-patterns.md), and
  adding a candidate is new recon work, not a Phase-1 design choice. Recorded as
  deliberately out of scope, not overlooked.
