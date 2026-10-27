# BENCH.md — proving benchmarks: M0 bakeoff spec + append-only ledger

**Status: SPEC SIGNED (Phase 0, revision 1 — thresholds human-signed
2026-07-14, §5). No measurement rows exist yet.**

This file is two things and stays two things:

- **Part I** — the M0 bakeoff specification: the identical guest workload, the
  pinned fixtures, what is measured, the thresholds, and the go/no-go rule.
  Part I is versioned prose; amendments before M0 execution are ordinary
  edits, amendments after any run row exists are appended as dated spec
  revisions (§7 rule 6).
- **Part II** — the append-only measurement ledger. Per HANDOFF §10, verbatim:
  "`BENCH.md` is append-only history, never overwritten — cost claims must be
  reconstructible."

Authority: HANDOFF §4 (Phase 0 bakeoff-spec deliverable; Phase 2 M0), §7
(benchmark doctrine), §10 (ledger), §12 (threshold placeholders);
`docs/notes/sextant-legs.md` (the workload, Sextant file:line);
`docs/notes/mithril-recursion-watch.md` (workload sizing, chain economics);
`docs/notes/sp1.md` + `docs/notes/risc0.md` (vendor pipelines, pins);
`docs/CLAIMS.md` v0 (journal header). Sextant is upstream and authoritative
for all verification semantics (HANDOFF §0, §8); nothing here re-derives them.

---

# Part I — M0 bakeoff specification

## 1. Purpose

M0 answers one question with numbers: **on which zkVM is Sextant's Mithril STM
certificate verification cheap enough to ship, and is it cheap enough at
all?** The output feeds ADR-001 (vendor selection — "decided by M0 numbers
against §12 thresholds, not vibes"; the loser's numbers are recorded too) and
the M0 human go/no-go gate (§5).

M0 is a benchmark, not a product. Non-goals: no recursion or proof
composition, no `verify_genesis`, no chain walk (`verify_chain` /
`verify_chain_anchored`), no header-segment or inclusion legs, no public
deployment of anything (HANDOFF §9 gate 1 untouched — verify gas is measured
in local fork tests), no prover-network dependency (network rows are optional
and non-threshold-bearing, §4.4).

## 2. The workload — identical across vendors

### 2.1 What one run computes

One run = **one real STM certificate verification via Sextant's `mithril`
path**, over exact fixture bytes supplied as untrusted guest input:

1. **Parse:** `Certificate::from_json` (Sextant `src/mithril.rs:104`) —
   Sextant's own strict deserialization; unknown signed-entity / part-key tags
   fail closed (mithril.rs:727, :846).
2. **Content hash:** recompute the certificate content hash
   (`Certificate::compute_hash`, byte-exact to `mithril-common`: `U8F24`
   `phi_f` fixed-point mithril.rs:892-894, chrono nanosecond timestamps
   :898-900, `ProtocolMessagePartKey` enum-order hashing :847-867) and assert
   it equals the committed `hash` field — the integrity check of
   `verify_chain` (mithril.rs:288) applied to the single fixture certificate.
3. **`verify_standard(cert)`** (mithril.rs:468): `signed_message ==
   H(protocol_message)` binding; degenerate-threshold refusal (`k==0 || m==0
   || phi_f ∉ (0,1)`, mithril.rs:484); DoS caps via `guard_stm_bounds`
   (mithril.rs:530-610); then the composed STM primitive
   `AggregateSignature::<MithrilMembershipDigest>::verify(signed_message.as_bytes(),
   &avk, &params)` (mithril.rs:507-522) — per certificate: single-signature
   G1/G2 deserialize + subgroup checks, per-index lottery evaluation
   (Blake2b-512 + big-rational Taylor comparison), AVK Merkle batch-path
   verification (Blake2b-256), and one aggregated BLS check (two ~N-point
   MSMs, one hash-to-G1, one pairing equation)
   (mithril-recursion-watch §1).
4. **Journal commit** (§2.3). Accepted or rejected, the outcome is a journaled
   verdict, never a bare panic (HANDOFF §5 standing rules).

The AVK used is the certificate's own committed
`aggregate_verification_key`; its *authorization* (parent-chain AVK binding)
is deliberately out of scope for M0 — that is the chain walk, priced in M1.
This is why the M0 journal is DRAFT-only and can never be accepted by any
production verifier (§2.3).

This workload is the **checkpoint-update proxy**: extend-by-one at mainnet
scale ≈ hash/link/AVK-bind checks + exactly one `verify_standard`
(mithril-recursion-watch §3, "the {{MAX_PROOF_TIME}}-shaped unit the bakeoff
must price"). The link/bind overhead is hashing noise next to the STM verify,
so W-MN1 (§3) is the number judged against the thresholds.

### 2.2 The identity rule

"Identical guest workload" (HANDOFF Phase 0) means, precisely:

- **Identical input bytes:** the pinned fixture file, byte-for-byte (§3).
- **Identical verification semantics:** the same Sextant code at the same
  pinned commit performs steps 1–3. Sextant is consumed as a pinned git
  dependency, never vendored or forked (HANDOFF §0).
- **Identical journal bytes:** both vendors' guests must emit byte-identical
  journals equal to the committed golden journal (§2.3).

What is *allowed* to differ per vendor — because it is exactly what M0
benchmarks — is the **BLS12-381 / STM backend** underneath
`AggregateSignature::verify` (each vendor's best available path, §6). Every
backend configuration must pass the **differential check**: guest verdict ==
native Sextant (`mithril-stm` 0.10.5 + `blst`) verdict on the same fixture
bytes, for both the golden fixture and the tamper control (§2.4). The backend
actually linked is a mandatory per-row annotation (§8.2); a row that does not
name its backend is invalid.

### 2.3 The M0 bench journal (claim_version 0 — DRAFT)

The bench journal reuses the CLAIMS.md v0 common header (CLAIMS.md §2) with
`claim_version = 0` (**DRAFT — rejected unconditionally by every production
verifier path**, CLAIMS.md §1 rule 3) and a bench-reserved claim type. Byte
layout below is **bench-local and dies with M0**; the production codec is
ADR-003.

Fixed-width big-endian concatenation, 78 bytes total:

| # | field | type | value for M0 |
|---|-------|------|--------------|
| H1 | `claim_version` | `u16` | `0` (DRAFT) |
| H2 | `claim_type` | `u16` | `0x0F01` — bench-only. Band `0x0F00–0x0FFF` is hereby reserved for benchmark claim types; CLAIMS.md §2.1 must mirror this reservation. |
| H3 | `network_id` | `u32` | Cardano network magic per CLAIMS.md H3: preprod `1`, mainnet `764824073` |
| H4 | `genesis_vkey` | `[u8;32]` | all zeroes — the M0 claim is anchor-free (no genesis verification is performed, §2.1); a zero anchor is one more reason no production verifier can accept it |
| H5 | `verdict` | `u16` | `0` accepted / nonzero = journaled rejection |
| H6 | `reject_index` | `u32` | `0` (single-certificate workload) |
| B1 | `cert_hash` | `[u8;32]` | the recomputed certificate content hash (== the fixture's committed `hash` field on the accept path) |

Golden journal for W-PP1 (accept path), as hex:

```
0000 0f01 00000001
0000000000000000000000000000000000000000000000000000000000000000
0000 00000000
489d87708a169ac6ebdff3f6f4fd389f16e9a96425c01a83fcb8b8d92f31117e
```

Golden journal bytes are committed at
`fixtures/bench/m0/golden-journal-<fixture>.bin` before the first run row for
that fixture; runs assert byte equality (`journal_ok` column, §8.4).

### 2.4 Validity controls (non-threshold-bearing, mandatory)

To prove we are not benchmarking a vacuous accept:

1. **Tamper control:** one run per (vendor × fixture) over the fixture with a
   single flipped byte inside `multi_signature`. Required outcome: journaled
   rejection (`verdict != 0`), differential-matched against native Sextant on
   the same tampered bytes. Recorded as a run row flagged `control`.
2. **Determinism check:** each threshold-bearing configuration runs twice;
   journal bytes must be identical across runs and across vendors (== golden);
   guest cycle counts recorded for both runs (variance noted — SP1's
   hint/unconstrained mechanism and any allocator nondeterminism would show
   here; sp1.md §1 flags determinism as structural, not vendor-stated).

## 3. Fixtures — pinned inputs

Fixture files live at `fixtures/bench/m0/` and are pinned by SHA-256 of the
file bytes in the fixture registry (§8.3). A measurement row referencing an
unregistered fixture is invalid. Per HANDOFF §5, fixtures reuse Sextant
vectors where they exist.

### 3.1 F-PP1 — preprod certificate (pinned now)

Real release-preprod standard certificate, harvested by Sextant and committed
as a golden vector.

| pin | value |
|---|---|
| source | Sextant `tests/vectors/mithril-cert-489d…117e.json` (Sextant @ `3a68b2f`) |
| destination | `fixtures/bench/m0/preprod-cert-489d…117e.json` (byte-identical copy; commit before first run) |
| file SHA-256 | `e181255a5721a0d5e7005109aabefe47000f838492d36b746b52e2c3e2a116b0` |
| size | 5,155 bytes |
| Mithril content hash | `489d87708a169ac6ebdff3f6f4fd389f16e9a96425c01a83fcb8b8d92f31117e` |
| network / epoch | preprod / 290 |
| signed entity | `MithrilStakeDistribution(290)` |
| params k / m / phi_f | 5 / 100 / 0.7 |
| single signatures | 1 |
| lottery indices | 37 (preprod chain median is 11, max 37 — this fixture sits at the heavy end for its network) |
| AVK leaves | 24 (9 listed signers in metadata) |

### 3.2 F-MN1 — mainnet-read-only certificate (harvest procedure; REQUIRED)

**The mainnet fixture is mandatory.** Preprod k=5 vs mainnet k=1,944 changes
the lottery-evaluation count by 200–400× and the single-signature count by
~59×; preprod numbers are "right for CI and fixtures, wrong for cost
extrapolation" (mithril-recursion-watch §3). A bakeoff without F-MN1 cannot be
judged against the thresholds and does not satisfy the M0 gate.

"Mainnet-read-only" per HANDOFF §5: the fixture is bytes read from the public
mainnet aggregator, committed to the repo. It implies no mainnet deployment,
no mainnet anchors in shipped configs, and touches no §9 gate.

Harvest procedure (append the pin row to §8.3 before any run references it):

1. `GET https://aggregator.release-mainnet.api.mithril.network/aggregator/certificates`,
   pick a recent **standard** certificate (`genesis_signature` empty,
   `multi_signature` non-empty), preferring a `CardanoTransactions` entity
   near the chain medians (~126 KB JSON, ~59 single sigs, ~2.4k lottery
   indices; k=1,944 / m=16,948 / phi_f=0.2 — mithril-recursion-watch §3). STM
   verify cost is entity-agnostic; `CardanoTransactions` is preferred only
   because it is the product-shaped certificate.
2. `GET …/certificate/{hash}`, save the exact response bytes to
   `fixtures/bench/m0/mainnet-cert-<hash>.json`. No reformatting, no
   pretty-printing — the file bytes are the pin.
3. Record in §8.3: file SHA-256, size, content hash, epoch, entity, k/m/phi_f,
   single-sig count, lottery-index count, AVK leaves, harvest date + URL.
4. Verify natively (Sextant `verify_standard`) before first guest run; commit
   the golden journal (network_id `764824073`).

### 3.3 Why both — the sizing gulf

| axis | F-PP1 (preprod) | F-MN1 (mainnet, expected) | gulf |
|---|---|---|---|
| k (quorum) | 5 | 1,944 | ~389× |
| lottery evaluations | 37 | ~2,434 | ~66× (chain medians: 11 vs 2,434 ⇒ 200–400× band) |
| single signatures (G1+G2 deserialize, MSM points) | 1 | ~59 | ~59× |
| input bytes | 5,155 | ~126 KB | ~24× |
| AVK leaves | 24 | 244 | ~10× |

The lottery evaluations (Blake2b-512 + num-bigint rational Taylor comparison
per index) are the dominant non-curve cost and are expected to be a large
zkVM cycle sink; M0 measures them separately (§4.2, stage split).

## 4. What is measured

### 4.1 Pipeline stages per vendor

Every vendor pipeline stage is timed separately; stage names map as follows
(sp1.md §3, risc0.md §3):

| stage | SP1 (v6 Hypercube) | RISC Zero (v3.0.x) |
|---|---|---|
| execute (no proving) | executor run, total cycles (RV64IM) | executor run, total cycles + segment count (RV32IM) |
| first proof | Core (STARK shards) | composite (per-segment STARK) |
| succinct/compressed | Compressed (constant-size STARK) | lift + join → SuccinctReceipt (~200 kB) |
| on-chain wrap | Groth16 wrap (~260 B; PLONK optional row, ~868 B) | identity_p254 + compress → Groth16Receipt |
| on-chain verify | `ISP1Verifier.verifyProof` fork test | `IRiscZeroVerifier.verify` fork test |

**Cycle counts are NOT cross-vendor comparable** (RV64IM vs RV32IM, different
costing models). Cross-vendor comparison happens on wall time, dollars, proof
bytes, and gas only. Cycles are recorded per vendor for regression tracking
and workload decomposition.

### 4.2 Metrics — the row schema

Per (vendor × fixture × backend configuration), one ledger row (§8.4) with:

1. **total guest cycles** (vendor's own unit; RISC Zero also records segments)
2. **execution wall time** (no proving)
3. **proving wall time to first proof** (Core / composite)
4. **compressed/succinct proof wall time**
5. **Groth16 wrap wall time** (PLONK as an optional separate row for SP1)
6. **end-to-end wall time** (fixture bytes in → Groth16 proof out)
7. **proving cost, USD** (§4.4)
8. **proof sizes** (bytes, per stage retained)
9. **on-chain verify gas** — measured in a local Foundry fork test against the
   vendor's audited verifier (vendored byte-identical or at its published
   address; sp1.md §4, risc0.md §4). Vendor-documented figures (SP1 ~270k
   Groth16 / ~300k PLONK) are recorded as context, never substituted for
   measurement; RISC Zero has **no** authoritative vendor gas figure and folk
   numbers are not citable (risc0.md §4).
10. **peak host RAM / GPU VRAM** during proving
11. **stage-split guest cycles** (separate sub-table §8.5): parse+content-hash
    / lottery evaluations / MSM+pairing / other — via vendor cycle-tracking
    instrumentation (SP1 cycle-tracker annotations; RISC Zero
    `env::cycle_count()` deltas). Best-effort granularity, but the lottery vs
    pairing split is required on F-MN1 (it decides where optimization and
    upstream asks aim — mithril-recursion-watch §1, §4.1).

**Every row is hardware- and version-annotated** (HANDOFF §7: "BENCH.md is a
ledger (hardware, versions, numbers)"): each row references a hardware
registry entry (§8.1) and a stack registry entry (§8.2) carrying exact
toolchain versions, patched-crate tags, docker image tags, guest commit, ELF
hash, and vkey/image ID. A row with an unpinned reference is invalid and is
superseded, never edited.

### 4.3 Native baseline (required context rows)

Sextant native `verify_standard` (`mithril-stm` 0.10.5 + `blst`, exactly as
Sextant pins it) on both fixtures, on the bench machine's CPU: wall time,
recorded as `native` rows. This establishes the zkVM overhead factor and the
mainnet native wall time that no existing harness has measured
(mithril-recursion-watch §5).

### 4.4 Cost accounting rule (reconstructibility)

A cost claim must be recomputable by a stranger from the row alone:

- **Local proving:** `cost_usd = e2e proving wall time × pinned SKU
  on-demand list price ($/hr)`. The list price, its source URL, and the
  retrieval date live in the hardware registry row. No spot pricing, no
  negotiated rates, no amortization assumptions.
- **Prover network / marketplace** (Succinct Prover Network, Boundless):
  optional, non-threshold-bearing rows; cost = the actual receipt (auction
  price, tx reference), attached as evidence. Both vendors' network pricing is
  market-dependent with no vendor price sheet (sp1.md §3, risc0.md §3).
- Raw evidence per run — prover logs, cycle-tracker output, receipt JSON, gas
  report — committed under `fixtures/bench/evidence/<run_id>/` and referenced
  from the row.

### 4.5 Toolchain identity (pre-requisites for threshold-bearing rows)

Before a row may be judged against thresholds:

- The stack registry entry records: all zkVM crate versions, docker toolchain
  image tag, patched-crate git tags, BLS backend crate + exact tag, Sextant
  commit, guest crate commit, ELF SHA-256, and the **vkey bytes32 (SP1)** /
  **image ID (RISC Zero)** of the exact binary measured.
- **Two independent builds → identical vkey/image ID** (HANDOFF §3;
  ADR-004 preview) is demonstrated per vendor before ADR-001 may cite that
  vendor's numbers: SP1 via `cargo prove build --docker --tag <pinned>` + ELF
  SHA-512 comparison (sp1.md §1); RISC Zero via the docker toolchain
  (`cargo risczero build`) — non-docker builds are explicitly non-canonical
  (risc0.md §1). Recorded as spike rows (§8.6).

## 5. Thresholds and the go/no-go rule

> **SIGNED OFF — human greenlight, 2026-07-14** (spec revision 1; the
> PROVISIONAL banner this replaces is preserved in git history). The values
> below are binding for the M0 gate. Amending any of them is a new dated spec
> revision requiring the same sign-off.

| threshold | SIGNED value | notes |
|---|---|---|
| `MAX_PROOF_TIME` | **≤ 10 min per checkpoint-update** on `BENCH_HARDWARE` | judged on W-MN1 end-to-end (fixture → Groth16), per §2.1's checkpoint-update proxy argument |
| `MAX_PROOF_COST` | **≤ $1 per update** | computed per §4.4 on the pinned SKU |
| `BENCH_HARDWARE` | **AWS `g6e.xlarge`** (1× NVIDIA L40S 48 GB, x86-64 host, 4 vCPU / 32 GiB) | satisfies the hard constraints: x86-64 host (RISC Zero Groth16 wrap is x86-only, even under Docker — risc0.md §3); CUDA compute capability ≥ 8.6, ≥ 24 GB VRAM recommended (SP1 CUDA prover — sp1.md §3); ≥ 16 GB RAM + Docker (both vendors' wrap pipelines) |
| `REGRESSION_PCT` (HANDOFF §7) | **> 10 %** proving-time regression flagged by CI | ledger-adjacent; signed in the same conversation |

Threshold-bearing result = the **better vendor's** W-MN1 end-to-end proving
wall time and cost, on the pinned SKU, with the differential check and
validity controls green.

The go/no-go rule, **verbatim from HANDOFF §4 (Phase 2, M0):**

> **Human go/no-go:** if the better result exceeds {{MAX_PROOF_TIME}} /
> {{MAX_PROOF_COST}}, stop and escalate with options (wait for native
> recursive certs; narrower claims; hybrid models) — do not grind past the
> threshold.

Escalation is a stop, not a detour: no optimization campaigns, no threshold
re-litigation from the agent side, no "one more experiment" past the gate.
The three named options map to: ADR-005's native recursive-certificate path
(mithril-recursion-watch §2), a reduced claim scope (CLAIMS.md §2.1 registry
subset), and hybrid trust models (documented, not invented — a §9
conversation).

## 6. Per-vendor measurement notes

### 6.1 SP1

- **Pinning:** exact `sp1-zkvm` / `sp1-sdk` / `sp1-contracts` versions,
  `SP1_CIRCUIT_VERSION`, docker image `ghcr.io/succinctlabs/sp1:<tag>`; vkey
  via `cargo prove vkey --elf <path>` recorded as bytes32 (sp1.md §1). Recon
  was against the v6 "Hypercube" line (v6.3.1 repo / 6.1.0 docs
  recommendation); re-pin exact versions at M0 execution and record in §8.2.
- **BLS12-381 reality:** **no pairing precompile, no G2 ops, no MSM** — only
  G1 add/double/decompress + Fp/Fp2 syscalls (syscall registry, sp1.md §2).
  The pairing runs as guest software. `mithril-stm`'s hardcoded `blst`
  (C + asm) cannot ride SP1's patch mechanism — SP1 patches pure-Rust crates
  only. Therefore the SP1 path **requires the pure-Rust STM backend seam**
  (Sextant upstream `guest` feature / mithril-stm backend swap —
  sextant-legs §3.2, mithril-recursion-watch §4.1).
- **Record WHICH pure-Rust path is linked** — this is a mandatory stack-registry
  field, one of:
  (a) vanilla zkcrypto `bls12_381` 0.8.0 (unaccelerated), or
  (b) `sp1-patches/bls12_381` tag `patch-0.8.0-sp1-6.0.0` (or `-v2`; Fp/Fp2
  routed through syscalls, partially accelerating G2 and the pairing tower).
  If both are obtainable, they are **separate rows, never merged**; the
  patched path is the expected primary.
- **Planning prior, not a result:** vendor-published `kzg-rs`
  `verify_kzg_proof` = 9,390,640 cycles (≈ one 2-pairing product + G1/G2
  mults on the patched crate) — order-of-magnitude "a few million cycles per
  pairing" (sp1.md §2). No vendor number exists for an STM verify; that is
  M0's job.
- **Hints caveat:** patched crates use SP1's unconstrained/hint mechanism
  internally; hinted data is not constrained by the proof. The tamper control
  (§2.4) must run on the **patched** configuration specifically, and the
  hint surface goes to the THREAT_MODEL unbound-input zoo (sp1.md §1).
- Cycle unit is RV64IM (v6) — record but never compare against RISC Zero
  cycles (sp1.md open item 3).

### 6.2 RISC Zero

- **Pinning:** `risc0-zkvm` (recon pin v3.0.5), `r0vm`, `risc0-ethereum`
  contracts (v3.0.1), docker toolchain; image ID = SHA-256-based
  `compute_image_id` over the combined user+kernel ELF (risc0.md §1).
  Non-docker builds are non-canonical for identity purposes.
- **THE FIRST EXPERIMENT — the blst patch compile spike.** Before any proving
  or any backend work, attempt:
  `[patch.crates-io] blst = { git = "https://github.com/risc0/blst", tag = "v0.3.16-risczero.0" }`
  under `mithril-stm` 0.10.5 (`default-features = false,
  features = ["num-integer-backend"]`) for target
  `riscv32im-risc0-zkvm-elf`. The fork tag matches mithril-stm's `blst =
  0.3.16` pin exactly (risc0.md §2, "Mithril seam"). The spike resolves, and
  its §8.6 row records: (a) whether blst's `portable` feature interacts sanely
  with the risc0 C build path (`riscv32-unknown-elf-gcc -march=rv32im`);
  (b) whether mithril-stm's unconditional `rayon` dependency builds/links for
  the guest target (rayon-core needs std threads — sextant-legs §2.2);
  (c) whether mithril-stm uses blst APIs outside the fork's accelerated
  surface. Outcome branches:
  1. **Compiles and runs** → the accelerated path: blst field arithmetic
     remapped onto bigint2 384-bit ops + `sys_sha_buffer`; Miller loop, final
     exponentiation, G2, hash-to-curve remain C over accelerated limbs
     (risc0.md §2). Proceed to full measurement rows.
  2. **Also obtainable: the unaccelerated control** — vanilla
     `supranational/blst` as portable C cross-compiled to the guest. If it
     builds, record **accelerated and unaccelerated as separate rows, never
     merged** — the delta is the value of the vendor's acceleration and
     directly informs the upstream pluggable-backend ask
     (mithril-recursion-watch §4.1). Do not sink more than a timeboxed effort
     into the unaccelerated control if it fights back; it is informative, not
     threshold-bearing.
  3. **Compile fails** → fall back to the same pure-Rust backend seam as SP1,
     using the vendor fork `risc0/zkcrypto-bls12_381` tag
     `bls12_381/v0.8.0-risczero.1` (risc0.md version table); note in the
     comparison that both vendors then run the same backend class.
- **Groth16 wrap is x86-only** (Apple Silicon unsupported even under Docker) —
  constrains `{{BENCH_HARDWARE}}` and any local dev runs (risc0.md §3).
- **Gas:** no authoritative vendor figure exists; measure in the fork test;
  do not cite folk numbers (risc0.md §4).
- Cycle unit is RV32IM total cycles + segment count.

## 7. Reporting procedure

1. Register hardware (§8.1), stack (§8.2), and fixture (§8.3) rows first; a
   run row referencing an unregistered ID is invalid.
2. Append run rows (§8.4) as runs complete — including failed, aborted, and
   control runs (a failed run is data; HANDOFF doctrine). Never batch-rewrite.
3. Evidence lands in `fixtures/bench/evidence/<run_id>/` in the same commit
   as the row.
4. Corrections: a wrong row is never edited; append a superseding row with
   `supersedes: <run_id>` and a reason, and strike nothing.
5. Spikes (compile experiments, reproducibility checks) get S-rows (§8.6) —
   outcomes recorded whatever they are.
6. Spec revisions after the first run row: append to §9 (dated), never rewrite
   Part I silently.

---

# Part II — Append-only ledger

**Rules (HANDOFF §10, verbatim):** "`BENCH.md` is append-only history, never
overwritten — cost claims must be reconstructible." Every row is hardware- and
version-annotated by reference (hw_id, stack_id, fixture_id). Unknown or
not-obtained values are `—` with a footnote, never blank, never guessed.

## 8.1 Hardware registry (HW-…)

| hw_id | date (UTC) | description (cloud SKU / GPU / CPU / RAM / region / driver, CUDA) | $/hr on-demand list (source URL, retrieval date) |
|---|---|---|---|
| HW-DEV0 | 2026-07-15 | Windows 11 workstation, Docker Desktop WSL2 VM: 4 vCPU, 11.68 GiB RAM, no GPU. **Executor-tier context ONLY — not `BENCH_HARDWARE`; wall times on this row are never threshold-bearing.** | — (owned hardware; $0 marginal) |

## 8.2 Stack registry (ST-…)

| stack_id | date (UTC) | vendor | zkVM crates + versions | toolchain / docker tag | patched crates (exact tags) | BLS/STM backend (crate + tag) | Sextant commit | guest commit | ELF SHA-256 | vkey bytes32 / image ID |
|---|---|---|---|---|---|---|---|---|---|---|
| ST-0001 | 2026-07-15 | RISC Zero | risc0-zkvm =3.0.5 (std), risc0-zkvm-platform =2.2.2 (+`sys-getenv`) | `risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71b…` (guest rustc 1.88.0-dev, riscv32 gcc 13.2.0); host executor risc0-zkvm =3.0.5 `prove` | none | blst 0.3.16 crates.io `portable` + **`no-threads`** (serial — the documented wasm path; required, see R-0001 note) via mithril-stm 0.10.5 | `90b2672a` | `spikes/risc0-mithril` (instrumented) | `fffac3a1…70cbe8e` | image ID `68251e01…082b3324` |
| ST-0002 | 2026-07-15 | RISC Zero | same as ST-0001 | same | `[patch.crates-io]` blst = `risc0/blst` tag `v0.3.16-risczero.0` `#7d1fc3e6` (+risc0-bigint2 1.4.13) | risc0 accelerated blst fork + `no-threads` | `90b2672a` | same | `563d55fc…a0ded07` | image ID `dab6d60d…777021f0` |
| ST-0003 | 2026-07-15 | SP1 | sp1-zkvm 6.3.1, sp1-sdk 6.3.1 (host, `SP1_PROVER=cpu`, execute-only) | cargo-prove v6.3.1 (`8252c29`), succinct rustc 1.94.0-dev, `rust:1.93-bookworm@sha256:7c4ae649…` (+`--shm-size=8g`); **NON-CANONICAL per ADR-004 D1** (cross-gcc absent from the pinned `--docker` image — recipe gap) | none | blst 0.3.16 `portable` + **`no-threads`**, C via Debian `riscv64-unknown-elf-gcc` 12.2.0 (`CC_riscv64im_succinct_zkvm_elf`) | `90b2672a` | `spikes/sp1-mithril` (instrumented) | `739216d2…c1975685` | vkey `0x009bda93…accd4aca` |

## 8.3 Fixture registry (F-…)

| fixture_id | status | network | file (`fixtures/bench/m0/`) | file SHA-256 | size (bytes) | cert content hash | epoch / entity | k / m / phi_f | sigs / indices / AVK leaves | provenance |
|---|---|---|---|---|---|---|---|---|---|---|
| F-PP1 | **pinned** (committed 2026-07-14) | preprod (magic 1) | `F-PP1.json` | `e181255a5721a0d5e7005109aabefe47000f838492d36b746b52e2c3e2a116b0` | 5,155 | `489d8770…f31117e`† | 290 / MithrilStakeDistribution | 5 / 100 / 0.7 | 1 / 37 / 24 | release-preprod aggregator by hash, 2026-07-14; **byte-identical** to the Sextant golden vector (Sextant @ `3a68b2f`) and to this spec's §3.1 pin — aggregator bytes == committed bytes verified |
| F-MN1 | **pinned** (committed 2026-07-14) | mainnet (magic 764824073) | `F-MN1.json` | `2b00e86a10affd1f8092bf307c9f3cfef533772d2ac3b60bb8adffd2c360922e` | 113,553 | `f4ca8ecc…8beea55c` | 643 / CardanoTransactions(643, block 13678859) | 1944 / 16948 / 0.2 | 59 / 1,971 / 244 | release-mainnet aggregator, verbatim HTTP body, 2026-07-14 (chain-median sig count per §3.2) |

† full hash: `489d87708a169ac6ebdff3f6f4fd389f16e9a96425c01a83fcb8b8d92f31117e`.

## 8.4 Run ledger (R-…) — M0 rows land here

**Executor-tier rows (2026-07-15).** Kind `exec` = execution only, NO proving —
cycle-count + validity-control rows; every proving column is `—` by
construction. Verdict differential (guest journal verdict == native Sextant on
identical bytes) held on ALL 12 rows. `journal == golden` is `n/a·spike`: these
guests journal a bare u32 verdict (documented mapping in each spike README),
not the §2.3 78-byte bench journal — wiring `hg-claims` into the guests is a
proving-tier prerequisite. Cycle-count caveat (both vendors): blst draws random
blinding scalars via host entropy, so user-cycle counts vary ~10²/run;
**journal bytes are byte-identical across runs** — §2.4's determinism check
compares journals, never cycles.

| run_id | date (UTC) | fixture | vendor | stack_id | hw_id | kind (bench / native / control / network) | guest cycles | segments/shards | exec (s) | first proof (s) | succinct (s) | Groth16 wrap (s) | e2e (s) | peak RAM/VRAM | cost USD | proof bytes (succinct / wrapped) | verify gas | journal == golden | evidence | supersedes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R-0001 | 2026-07-15 | F-PP1 | RISC Zero | ST-0001 | HW-DEV0 | exec | 197,220,545 user / 207,093,760 total | 198 | 3.32 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 0 == native) | `evidence/R-0001/` | — |
| R-0002 | 2026-07-15 | F-PP1 | RISC Zero | ST-0001 | HW-DEV0 | control (tamper) | 1,258,520 user | 2 | 0.04 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 9 == native) | `evidence/R-0002/` | — |
| R-0003 | 2026-07-15 | F-PP1 | RISC Zero | ST-0002 | HW-DEV0 | exec | 51,717,002 user / 56,098,816 total | 54 | 1.24 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 0 == native) | `evidence/R-0003/` | — |
| R-0004 | 2026-07-15 | F-PP1 | RISC Zero | ST-0002 | HW-DEV0 | control (tamper) | 1,258,520 user | 2 | 0.04 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 9 == native) | `evidence/R-0004/` | — |
| R-0005 | 2026-07-15 | F-MN1 | RISC Zero | ST-0001 | HW-DEV0 | exec | 2,533,598,396 user / 2,674,917,376 total | 2,551 | 45.16 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 0 == native) | `evidence/R-0005/` | — |
| R-0006 | 2026-07-15 | F-MN1 | RISC Zero | ST-0001 | HW-DEV0 | control (tamper) | 26,082,075 user | 27 | 0.77 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 9 == native) | `evidence/R-0006/` | — |
| R-0007 | 2026-07-15 | F-MN1 | RISC Zero | ST-0002 | HW-DEV0 | exec | **930,175,201 user** / 1,011,875,840 total | 965 | 22.63 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 0 == native) | `evidence/R-0007/` | — |
| R-0008 | 2026-07-15 | F-MN1 | RISC Zero | ST-0002 | HW-DEV0 | control (tamper) | 26,082,075 user | 27 | 0.88 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 9 == native) | `evidence/R-0008/` | — |
| R-SP1-E1 | 2026-07-15 | F-PP1 | SP1 | ST-0003 | HW-DEV0 | exec | 182,937,047 | — | 5.41 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 0 == native) | `evidence/R-SP1-E1/` | — |
| R-SP1-E2 | 2026-07-15 | F-PP1 | SP1 | ST-0003 | HW-DEV0 | control (tamper) | 480,102 | — | 0.44 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 2 == native) | `evidence/R-SP1-E2/` | — |
| R-SP1-E3 | 2026-07-15 | F-MN1 | SP1 | ST-0003 | HW-DEV0 | exec | **2,374,163,854** | — | 44.87 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 0 == native) | `evidence/R-SP1-E3/` | — |
| R-SP1-E4 | 2026-07-15 | F-MN1 | SP1 | ST-0003 | HW-DEV0 | control (tamper) | 8,860,600 | — | 0.44 | — | — | — | — | — | 0 | — | — | n/a·spike (verdict 2 == native) | `evidence/R-SP1-E4/` | — |

Row notes: (1) The tamper controls (§2.4) reject at the **content-hash gate**
(Sextant `compute_hash` covers `multi_signature` on standard certs), matching
native exactly — spec-conformant, but the STM-crypto rejection path itself is
therefore unexercised by this control; a crypto-layer control (mutate a field
the content hash does not cover, or re-seal the hash) is a proving-tier
follow-up. (2) The §6.2 acceleration delta on the verify stage: **3.88×**
(F-PP1) and **2.77×** (F-MN1) user cycles — the backend-independent lottery
evaluations (Blake2b + num-bigint rational compare) dilute the curve speedup
at mainnet k=1944. (3) `no-threads` on blst was REQUIRED on both vendors:
mithril-stm never calls rayon at runtime (doc-comments only — the S-0001/S-0002
compile-graph worry was an artifact); the real spawner was blst's own
`da_pool()` threadpool, which panics on both single-threaded guest stds.
Guest-manifest-only fix; zero Sextant/mithril-stm changes.

## 8.5 Stage-split sub-ledger (cycles; required on F-MN1 rows)

Instrumentation splits at Sextant API boundaries (read input /
`Certificate::from_json` / `compute_hash`+integrity / `verify_standard`); the
lottery-vs-MSM split *inside* `verify_standard` needs mithril-stm-internal
cycle marks or differential-ELF experiments — a proving-tier follow-up, so
those two columns are merged under `verify_standard` below.

| run_id | parse + content hash | lottery evaluations | MSM + pairing | other | instrumentation notes |
|---|---|---|---|---|---|
| R-0005 | 1,137,529 + 8,244,323 | (merged →) | verify_standard = 2,507,515,790 | read_input = 16,692,605 | risc0 `env::cycle_count()` per stage |
| R-0007 | 1,137,529 + 8,244,323 | (merged →) | verify_standard = 904,092,623 | read_input = 16,692,605 | risc0 `env::cycle_count()` per stage |
| R-SP1-E3 | 8,823,919 (parse+hash combined) | (merged →) | verify_standard = 2,365,302,455 | read_input = 363; ~37,117 misc | SP1 cycle-tracker (portable executor + `profiling`; the native child executor drops tracker spans — vendor bug noted in evidence) |

## 8.6 Spike log (S-…)

| spike_id | date (UTC) | question | outcome | evidence |
|---|---|---|---|---|
| S-0001 | 2026-07-14 | Does the Sextant `mithril` leg compile to a RISC Zero guest, and does the accelerated blst fork (`v0.3.16-risczero.0`) resolve against mithril-stm 0.10.5's exact `^0.3.16` pin (§6.2)? Sextant @ `90b2672a`, risc0-zkvm =3.0.5, builder container `risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71b…` (risc0-build v3.0.5's own DEFAULT_DOCKER_TAG, exact env replicated), guest rustc 1.88.0-dev, riscv32-unknown-elf-gcc 13.2.0. | **COMPILES — all three layers, zero Sextant changes.** (1) default graph clean (341,596 B ELF); (2) + `mithril` with VANILLA blst 0.3.16 `portable` C: cross-compiles AND links (1,288,828 B) — the §6.2 unaccelerated control is buildable, no patch required; rayon 1.12.0/rayon-core 1.13.0 compile+link (risc0 guest std; runtime thread behavior deliberately unmeasured — compile-only); chrono/subtle/getrandom all fine; (3) `[patch.crates-io]` blst = `risc0/blst` tag `v0.3.16-risczero.0` (`#7d1fc3e6`) resolves cleanly, pulls risc0-bigint2 1.4.13, ELF shrinks to 1,199,904 B. Image ID (risc0-build v3.0.5 derivation + v1compat kernel): `5515edd69e5077b4044cd432a54d39833b52a2a270da2ab2b65181ba990e3080`; user-ELF sha256 `15735607…d573329`; two fresh-container runs byte-identical (same-host only — T-A6-1 proper needs divergent runners). Only failure encountered: crates.io MSRV bitrot vs the pinned 1.88.0 toolchain (enum-ordinalize/ruint via risc0-zkvm's own graph) — fixed structurally with `rust-version="1.88.0"` + resolver 3 MSRV-aware resolution. Caveat: built via plain `cargo +risc0 build` inside the canonical builder image (docker-in-docker unavailable), not host-side `cargo risczero build` — the registry image ID re-derivation is an M0-proper item. Repro: `spikes/risc0-mithril/build.sh`. | `spikes/risc0-mithril/` (guest + imageid crates, lockfiles, README) |
| S-0002 | 2026-07-14 | Does the Sextant `mithril` leg (mithril-stm 0.10.5 → blst 0.3.16 C + rayon) compile to an SP1 guest ELF (`cargo prove build`, target `riscv64im-succinct-zkvm-elf`)? Sextant @ `90b2672a`, sp1-zkvm 6.3.1, cargo-prove `8252c29` (v6.3.1), succinct rustc 1.94.0-dev, container `rust:1.93-bookworm@sha256:7c4ae649…`. | **COMPILES.** Bisect: (1) default graph clean; (2) + `mithril` stock → sole failure = blst build script, cc-rs falls back to host x86-64 `cc` with `-march=rv64im -mabi=lp64` (no C cross-compiler in the succinct toolchain; rayon/subtle/getrandom all compile); (3) + `CC_riscv64im_succinct_zkvm_elf=riscv64-unknown-elf-gcc` (Debian gcc 12.2.0, blst portable/no-asm C) → ELF links, 39 `blst_*` symbols, sha256 `6aae24ad…6a0a671`, vkey `0x004c3360…d98f5f7d`, cache-purge rebuild hash-identical. blst is unconditionally in-graph (no pure-Rust fallback in mithril-stm 0.10.5 — crates.io index: blst non-optional). Compile-only: run/prove untested; build non-canonical per ADR-004 D1 (`--docker` image lacks the cross-gcc — recipe gap); gcc-compiled C in SP1 guests is vendor-unblessed (zero syscall acceleration — the pure-Rust `sp1-patches/bls12_381` seam remains the documented primary). Repro: `spikes/sp1-mithril/build.sh`. | `fixtures/bench/evidence/S-0002/` |

## 9. Spec revisions (dated, append-only after first run row)

| date (UTC) | revision | reason | signed |
|---|---|---|---|
| _none — Part I is in DRAFT and may still be edited normally_ | | | |
