# STATUS

**Parked as of 2026-10-27**, in the Sextant repository at `heliograph/`.
Resume only for the first consumer that needs a Cardano fact verified on a
chain that cannot run Sextant natively: an EVM state oracle, or a bridge to a
chain without a Cardano client. The codec gate stays active while parked;
guest/prover development and paid proving remain deferred.

`spikes/` is the frozen experiment record cited by [`docs/BENCH.md`](docs/BENCH.md).
Its Sextant git pins at `90b2672aa3ee7a957ecaee0e33026337825efafa` predate the
[GHSA-qp53-rvq4-5wwm / C-1 fix](https://github.com/Flux-Point-Studios/sextant/security/advisories/GHSA-qp53-rvq4-5wwm).
The spikes are excluded from CI and keep those pins for reproducibility.
A revived guest must build against the in-repo Sextant via a path dependency,
which carries that fix, and revalidate its claims against the current
phase-2-aware verification semantics before producing consumer proofs.

Run `scripts/gate.sh` from this directory: fmt, clippy `-D warnings`, all-feature
`hg-claims` tests (61), and the coverage-ledger check. This workspace and its
lockfile are independent of the Sextant root workspace; no zkVM toolchain is
needed for the gate.

## Recorded progress before parking

- **Phase reached:** 2 — BUILD; M0 executor complete, proving tier pending.
  **Phase-1 exit gate PASSED 2026-07-14**, tagged `heliograph/phase-1`
  (Phase-0 also passed + tagged `heliograph/phase-0`).
- **Milestone:** Phase 1 complete — ADR-000..005 + 3 design sketches, earned
  through an adversarial consistency review (1 blocker + 5 majors + 3 minors
  found and fixed before tagging). Phase 0: recon, CLAIMS v0, THREAT_MODEL v1
  (14 adversaries), BENCH (thresholds signed).
- **Gate:** fmt, clippy, 61 codec tests, and the coverage-ledger check.

## Done this phase

- **Recon** (`docs/notes/`): sextant-legs (the claims inventory + guest-safety:
  default graph ≈ no_std+alloc already; the ONE blocker is `mithril` →
  mithril-stm 0.10.5 → blst 0.3.16 C + rayon), sp1 (NO BLS12-381 pairing
  precompile; ~M cycles/pairing in software), risc0 (no pairing precompile
  either, BUT vendor ships an accelerated blst fork at **v0.3.16-risczero.0 —
  mithril-stm's exact pin**; plausibly a one-line `[patch.crates-io]`),
  mithril-recursion-watch (mainnet chain = 106 certs post Feb-2025 re-genesis;
  extend-by-one = 1 STM verify; upstream halo2_ivc is real and far along;
  **re-genesis recurs → genesis anchor is a versioned claim input, never an
  image constant**), lightclient-patterns (production LCs chain contract-side;
  the sp1-helios PR #54 under-constrained-journal incident; freshness is always
  consumer policy).
- **`docs/CLAIMS.md` v0** — claim types 0x0001–0x0005 (checkpoint,
  checkpoint-extension, header-segment, tx-inclusion, utxo-read) + deferred
  Tier-1/Tier-2 types; common journal header (claim_version, claim_type,
  network_id, genesis_vkey, verdict); journaled rejections; every field seeded
  for the mutant zoo. Byte layout deferred to ADR-003.
- **`docs/THREAT_MODEL.md` v1** — 14-adversary catalog (A1 under-constrained
  journals … A14 deployment-init), vendor-trust table, out-of-scope. Both
  audit PDFs read in full and harvested: Zellic sp1-helios (findings 3.1–3.5;
  the meta-finding — guest in scope, zero guest findings, missed the PR #54
  hole — folded into A1) and Veridise blobstream0 (V-BLOB-VUL-001..004). New:
  A14 (deploy-init, from the constructor key-domain bug), the load-bearing-
  checks ledger (A10), host-bindings-from-ABI + no-silent-canonicalization
  (A4), error-selector coverage (A8), mandatory minimum-progress + front-run
  race (A13). Pre-red-team (v2 lands after Phase 3).

All five Phase-0 deliverables are now DRAFTED (see also `docs/BENCH.md` — the
M0 bakeoff spec with PROVISIONAL thresholds + the append-only ledger skeleton,
including the mandatory mainnet-read-only fixture and tamper/determinism
controls — and `docs/notes/sextant-upstream-needs.md`, the paste-ready guest
feature ask: the RISC Zero path needs ZERO Sextant changes via the
v0.3.16-risczero.0 blst fork; the real asks are the no_std default graph and
the SP1-path pairing story).

## Recorded design decisions

**Phase 1 — DESIGN.** ADRs + sketches DRAFTED (`docs/adr/`, `docs/design/`):

- **ADR-000 Naming** — Accepted. Live sweep: `heliograph` free at the GitHub
  org/repo and (decisively) across Cardano/ZK — no project carries the name.
  Crates `hg-*` all free; npm scope `@fluxpoint` (‑ `@heliograph` couples to an
  unrelated existing npm user). Bare `heliograph` on crates.io/npm are dormant
  unrelated packages, deliberately not contested.
- **ADR-002 Recursion** — Accepted. Three-layer hybrid: `0x0001` base case,
  `0x0002` extend-by-one via in-guest composition (inner image-ID journaled =
  the A3 defense), router chains checkpoints CONTRACT-SIDE (A10). Priced: ≈105×
  amortization today. RISC Zero self-recursion wiring provisional pending the
  M1 spike (fallback recorded).
- **ADR-003 Journal codec** — Accepted. Big-endian flat fixed-width, one
  encoding per value, one buffer feeds digest+parse (A4/T-A4-5). Rules frozen;
  `claim_version=1` assigned at the CLAIMS v1 freeze (Phase 2).
- **ADR-004 Reproducible builds** — Accepted. Docker-pinned per vendor; image
  ID publicly recomputable; two-independent-builds CI (T-A6-1). Vendor-neutral.
- **ADR-005 Checkpoint source** — Accepted. `CheckpointSource` trait; native
  recursive-cert path is a future §9-gated swap (upstream unsafe-setup +
  in-flight audit gates not yet cleared).
- **ADR-001 zkVM selection** — SKELETON. DECISION section literally "DEFERRED —
  filled by M0, human sign-off required" (§9 gate 2). Criteria wired to the
  signed BENCH thresholds; loser's numbers to be recorded too.
- **Sketches** (`docs/design/`): `hg-claims` API (1055 lines, no_std codec),
  contract interface (857 lines, thin router over untouched vendor verifier),
  test strategy (625 lines, all 40 ledger rows wired to gate/CI/release).

### Phase-1 exit gate — PASSED (2026-07-14), tagged `heliograph/phase-1`

ADRs ✓ / `hg-claims` API sketch ✓ / contract interface sketch ✓ / test
strategy ✓. Earned via an adversarial 4-lens consistency review (not
self-declared) — found 1 blocker + 5 majors + 3 minors, all fixed before the tag:

- **BLOCKER** — the router's strict-monotonic-`tip_epoch` extension rule would
  reject ~765 of every 766 legitimate same-epoch extensions (mainnet emits ~765
  CardanoTransactions certs/epoch, ~1 boundary crossing), breaking the ~10-min
  tip-freshness path ADR-002 exists to serve. Fix: `chain_length`+1 is the sole
  strict-progress key (monotone by construction, both shapes); `tip_epoch`
  NON-DECREASING; `minProgress` keyed on `ctx_block_number`, not epoch/slot.
- Majors: rejection journals could be stored as live checkpoints (added the
  `verdict==0` storing gate + `RejectedCheckpointNotStorable`); §7 wasn't the
  "complete" error set it claimed (added `ZeroMinProgress`/`ZeroTimelockDelay`/
  `UnsupportedNetwork`); ADR-005 "byte-identical" vs ADR-003 D5's STM-specific
  AVK preimage (resolved: S5 is the source-invariant Mithril-protocol AVK root);
  `verifyClaim` NatSpec "reverts on R8" (R8 never reverts — rejections return);
  phantom `slot` in the checkpoint progress rule (struck — no slot field).
- Minors: 154→209 byte heading; R6 uniform-on-rejection clarity; nr_leaves
  justification.

Phase 2 then opened the **M0 bakeoff**, with both SP1 and RISC Zero arms;
ADR-001 remains undecided pending the proving-tier measurements below.

## Phase 2 — done so far

- **Sextant guest unblock (PR #60, MERGED @ 90b2672):** default graph
  no_std+alloc; `tools/guest-canary` harness gate on rv32im; the crate-type fix
  (rlib-only manifest — multi-crate-type libs build ALL types even as a
  dependency, breaking bare-metal builds); mithril additivity pinned
  (`cargo check --no-default-features --features mithril`). Red-teamed
  (1 HIGH fixed + pinned), 4/4 CI green, squash-merged per the delegated loop.
- **`crates/hg-claims` (the codec):** no_std+alloc, zero runtime deps, 61
  tests. Golden-first TDD (vectors derived independently from the ADR-003
  tables BEFORE the encoder existed); every-byte mutation zoo over all 10
  goldens (T-A4-3/T-A1-1 seed); full fail-closed suite; adversarial review
  verdict SHIP (3 minors, all closed: normative gate-precedence documented in
  `decode.rs`; `docs/journal-coverage.md` ledger created with a gate check
  that FAILS on statusless rows, proven both directions; the CLAIMS §4.2
  rejection-population obligation carried below).
- Gate grew: fmt + clippy `-D warnings` + tests + the coverage-ledger check.
- **M0 compile spikes S-0001/S-0002 (BENCH §8.6): BOTH ARMS COMPILE, zero
  Sextant changes.** RISC Zero: all three layers (default graph; vanilla blst C
  — the unaccelerated control builds; the `v0.3.16-risczero.0` accelerated fork
  patches cleanly, image ID `5515edd6…990e3080`, same-host reproducible ×2).
  SP1: blocks stock at the blst cc wall exactly as recon predicted, unblocked
  by a Debian riscv cross-gcc (vendor-unblessed; `sp1-patches/bls12_381` stays
  the documented primary). Evidence committed: `spikes/{risc0,sp1}-mithril/`
  with reproducing build.sh per arm. The compile question NO LONGER
  discriminates ADR-001 — M0 numbers will.
- **Fixtures harvested + pinned (BENCH §8.3):** F-PP1 (preprod, byte-identical
  to the Sextant golden vector AND the §3.1 pin — the identity chain verified)
  and F-MN1 (mainnet epoch 643, CardanoTransactions, k=1944, 59 sigs / 1,971
  indices / 244 AVK leaves — chain-median class), verbatim aggregator bytes.

## M0 — executor phase DONE (2026-07-15; BENCH §8.4 R-0001..R-0008 + R-SP1-E1..E4)

**12/12 rows green: guest verdict == native Sextant on every row, tamper
controls journal the same rejection as native, both fixtures, both vendors.**

- **The thread question is fully resolved, zero upstream changes:** rayon was
  never real (doc-comments only in mithril-stm; never called at runtime). The
  actual spawner was **blst's own `da_pool()` threadpool** — panics on both
  vendors' single-threaded guest stds; fixed guest-manifest-only with blst
  `no-threads` (its documented serial path) + risc0 `sys-getenv`.
- **First-ever STM-verify-in-zkVM cycle numbers** (F-MN1 mainnet, k=1944):
  RISC Zero accelerated **930.2M** user cycles (vanilla 2,533.6M — the §6.2
  delta is 2.77× at mainnet scale, diluted by backend-independent lottery
  math); SP1 unaccelerated gcc-blst 2,374.2M.
- Cycle counts vary ~10²/run (blst random blinding via host entropy); journal
  bytes are byte-identical — §2.4 determinism compares journals, never cycles.
- Tamper rejects at the content-hash gate (native-matching, spec-conformant);
  a crypto-layer control is a proving-tier follow-up.

## On resumption: M0 proving tier

1. Wire `hg-claims` into the guests (the §2.3 78-byte bench journal replaces
   the spike u32) + commit `golden-journal-<fixture>.bin`.
2. Host-side `cargo risczero build` for the canonical registry image ID +
   a true two-runner T-A6-1; close the SP1 `--docker` cross-gcc recipe gap.
3. Crypto-layer tamper control (mutate below the content hash).
4. **GPU proving on `g6e.xlarge`** — the threshold-bearing rows. First PAID
   step: **blocked on {{PROVER_BUDGET}}** (§9 gate 4). Note (estimate, NOT a
   threshold judgment): at vendor-typical GPU proving throughput, 0.93–2.4B
   cycles is minutes-scale — the ≤10 min gate looks plausible on the
   accelerated arm, but only the pinned-SKU measurement decides.

### Carried obligations (explicit, so they cannot evaporate)

- **hg-guest MUST populate rejection journals** (identity/anchor fields from
  the guest's own verification state; only unreached payload zeroed — CLAIMS
  §4.2). The codec demonstrates but cannot enforce this; the pin is the
  T-A12-1 equality invariant (guest journal == native Sextant verdict) at M1.
- **M4 mirrors MUST replicate the decode gate precedence** documented in
  `hg-claims::decode_structural` (type → length → version), with a
  cross-surface unknown-version+unknown-type fixture.
- S5/S6 preimage BYTES lock at M1 (formula frozen in ADR-003 D5).

### Human touchpoints (not blocking)

- ~~Upstream note filing~~ **RESOLVED IN-HOUSE**: Sextant is our own org repo
  (no §9 gate) — the `guest` no_std feature landed as **Sextant PR #60**
  (default graph no_std+alloc; rv32im guest-canary harness gate; the
  crate-type fix that unblocks ANY guest dependency build). The only remaining
  external ask is the mithril-stm backend seam on IOG's Mithril repo —
  §9-gated, deferred until M0 says it's needed (both zkVM targets ship std
  in-guest, so likely moot).
- **`{{PROVER_BUDGET}}`** — required only before any PAID proving run
  (§9 gate 4). M0 can open on local/CI hardware.

## HANDOFF §12 items — status after the 2026-07-14 human greenlight

| Item | Value | Status |
|---|---|---|
| `MAX_PROOF_TIME` | ≤ 10 min / checkpoint-update | **SIGNED** (BENCH.md §5 rev 1) |
| `MAX_PROOF_COST` | ≤ $1 / update | **SIGNED** |
| `BENCH_HARDWARE` | AWS `g6e.xlarge` (1× L40S) | **SIGNED** |
| `REGRESSION_PCT` | > 10 % CI flag | **SIGNED** |
| `EVM_TESTNET` | Base Sepolia | **SIGNED** (M4 target) |
| v0.1 claim scope | inclusion + UTxO-read (both; types 0x0001–0x0005) | **SIGNED** |
| License | Apache-2.0 | **CONFIRMED** |
| `PROJECT_NAME` / `GITHUB_ORG` | heliograph / Flux-Point-Studios | resolved 2026-07-14 |
| `{{PROVER_BUDGET}}` | — | **STILL OPEN** — required before any PAID proving
  run (§9 gate 4); local/CPU/owned-GPU runs are unblocked without it |
| Security disclosure contact | proposed: GitHub Private Vulnerability
  Reporting on this repo | **PROPOSED** — needed by Phase-3 SECURITY.md;
  adopt-or-amend before then |

ADR-000 still owes the crates.io / npm / ecosystem availability sweep
(Phase 1).

## Pending §9 gates

- None in flight. (Repo publication was §9-gate-1, satisfied by direct human
  instruction 2026-07-14.)
