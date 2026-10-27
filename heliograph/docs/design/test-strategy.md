# Test strategy — instantiating HANDOFF §7

- **Status:** Design-frozen (2026-07-14). Phase 1 (DESIGN) deliverable — the
  "test strategy written (§7 instantiated)" line of HANDOFF §4 Phase 1 exit gate.
- **Scope:** how the verification doctrine (HANDOFF §7) becomes concrete test
  suites, which gate each runs at, the fixture strategy, and the merge rule that
  keeps the doctrine permanent as claim types are added.
- **Relation to specs:** this document *wires* what is already specified. The
  40-row test ledger (THREAT_MODEL.md §5) is the authority on which test kills
  which adversary; the claim schema and its mutant obligations are CLAIMS.md and
  ADR-003; the reproducibility discipline is ADR-004; the bakeoff/differential
  discipline is BENCH.md. This file does not restate those rows — it references
  them by test ID and says *where they live and when they run*.

Precedence, per HANDOFF §0: Sextant semantics are never re-derived here — they
are cited (HANDOFF §0, §8). Every load-bearing claim below carries its source.

---

## 0. The doctrine, in one paragraph

Prove the prover the same way Sextant proved the verifier (HANDOFF §7). The
prover is untrusted infrastructure (HANDOFF §1); the only load-bearing objects
are the pinned guest image ID and the Cardano trust anchors. Therefore the test
suite exists to guarantee exactly two things and their contrapositives:

1. **The guest computes what Sextant computes** — for *every* fixture, golden
   AND mutant, accept AND reject (the equality invariant, T-A12-1).
2. **Nothing verdict-relevant escapes the journal** — every input byte-range
   and every journal field either provably changes the journal/verdict under
   mutation, or carries a filed, reviewed verdict-irrelevance argument (the
   unbound-input zoo, T-A1-1).

Everything else in this strategy is one of these two invariants pushed to a
specific layer (codec, contract, SDK, CLI, build), or a fixture/gating
discipline that keeps them honest.

---

## 1. The layered test map

Seven suites. Each is named, located per the HANDOFF §5 layout, mapped to its
ledger rows, and assigned a gate (§2). The two soundness-core suites (zoo +
equality invariant) are `make gate`-blocking and can never be waived
(THREAT_MODEL A1: "never waivable on audit grounds"; HANDOFF §7).

### 1.1 The unbound-input zoo — `T-A1-1`, the soundness core

**What it asserts.** For every guest input byte-range and every journal field,
a mutant demonstrating either (a) mutation changes the journal/verdict, or
(b) a filed, reviewed written argument for verdict-irrelevance
(THREAT_MODEL A1 pinning tests; CLAIMS.md §1.7 item 7 "every journal field must
earn a mutant"; HANDOFF §7). Any input that silently changes a verdict without a
journal change is **P0, stop-the-line** (HANDOFF Phase 3; THREAT_MODEL A1).

**Where it lives.** Guest test crates (`hg-guest` tests) + the coverage ledger
`docs/journal-coverage.md` (THREAT_MODEL §5 row T-A1-1; HANDOFF §7). The ledger
is the gate-blocking artifact: one row per (claim type × input byte-range) and
per (claim type × journal field), each row either pointing at its killing mutant
or citing its filed verdict-irrelevance argument. **`make gate` fails on any gap
or any uncovered row** (HANDOFF §7 "`make gate` fails on gaps").

**Zoo classes it must carry** (each earns its own mutants, per the schema):

- **Header fields** H1–H5 (CLAIMS.md §2): `claim_version` flip ⇒ reject
  everywhere (CLAIMS.md H1); `claim_type`, `network_id`, `genesis_vkey`,
  `verdict`, `reject_index` each mutation-sensitive (ADR-003 D2 offsets).
- **Per-claim body fields** — every S/P/U field of every claim type
  (`CheckpointState` S1–S13, header-segment P-fields, inclusion/utxo U-fields;
  CLAIMS.md §3.1–3.5, ADR-003 per-claim offset tables). Fields that commit
  inputs verbatim satisfy the zoo trivially (CLAIMS.md §1.7 note; ADR-003 §7),
  but the row still exists and cites *why*.
- **Degenerate-path mutants — `T-A1-2`, an explicit class.** Empty certificate
  list, zero-certificate extension, empty block window, absent optional fields
  — the sp1-helios PR #54 shape (THREAT_MODEL A1 real-world instance:
  prover-supplied committee committed on the empty-`updates` path). One
  degenerate mutant per claim type per optional/list input (THREAT_MODEL §5 row
  T-A1-2).
- **Codec-specific mutant classes — from ADR-003 §7 (the "mutant zoo"
  obligations the codec newly creates):** endianness (BE assertion — flipping
  byte order changes the journal), presence-flag flip (each `u8` optional flag —
  `has_certified_transactions` → S11–S13, `datum_kind` → U11 — earns a mutant
  proving MUST-NOT-consume when the flag is 0), verdict-table (every reachable
  verdict code has a fixture, equality-invariant checked), commitment-preimage
  (mutating an `avk_commitment` / `address_hash` / `datum_commitment` preimage
  input changes the committed bytes), no-silent-canonicalization, and the
  length-gate (over-/under-length input rejected at R1). These are ADR-003's
  "necessity-by-mutant" transfer — the codec fixes bytes, so CLAIMS.md §1.7
  obligations transfer directly and the codec *adds* these classes.
- **SP1 hint/unconstrained sub-class** (THREAT_MODEL A1 mitigations;
  docs/notes/sp1.md §1 "Determinism"): `ENTER_UNCONSTRAINED` / `HINT_READ`
  inputs are not constrained by the proof and are treated as a first-class
  unbound-input class on the SP1 path — patched-crate internals that use hints
  are auditable only to the depth of the patched-crate diff, so the row records
  that residual explicitly.

**Coverage-ledger mechanics.** `docs/journal-coverage.md` is a checked-in table.
A CI/`make gate` step parses it and asserts: (1) every journal field named in
`hg-claims` for every claim type has a ledger row; (2) every ledger row resolves
to either a test function name (a live mutant) or a filed argument ID; (3) no
row is `TODO`/unfilled. A field present in the codec with no ledger row is a
gate failure — this is the "gaps fail the gate" rule made mechanical.

### 1.2 The golden-journal corpus — byte-exact, per claim type

**What it asserts.** For each claim type (0x0001–0x0005), a committed,
byte-exact expected journal is the normative encoding; the codec round-trips to
it exactly and the guest emits it exactly (HANDOFF §7 "golden journals:
byte-exact expected journals committed per claim type"; ADR-003 D8 "golden
vectors declared normative over the prose"). Ledger rows: **T-A2-2**
(`network_id` golden + mutant), **T-A4-3** (golden-encoding canonicality),
**T-A5-1** (as-of fields golden + mutant), **T-A2-3** cross-layer consumers of
the same goldens.

**Where it lives.** `hg-claims` golden tests + `/fixtures` (HANDOFF §5:
`/fixtures` holds "proofs, journals, golden encodings"). One golden journal file
per claim type, checked in, with the frozen `LEN_*` from ADR-003 D2/per-claim
tables (checkpoint 0x0001 LEN=255; checkpoint-extension 0x0002 LEN=328;
header-segment 0x0003 LEN=170; tx-inclusion 0x0004 LEN=191; utxo-read 0x0005
LEN=269 — ADR-003). A byte diff against the golden is a test failure.

**Why byte-exact and not structural.** The journal is the ABI of truth
(HANDOFF §0, §11 "the journal is a legal document"). A structural (field-value)
comparison would pass a codec that silently re-orders or re-pads bytes — exactly
the ABI-drift class A4 attacks. Byte-exactness is what makes the Solidity mirror
(ADR-003 D8: `hg-claims` mirrored constant-for-constant) verifiable: the same
golden bytes are the fixture for the contract-side decoder.

**Freeze caveat carried from ADR-003:** the S5/S6 preimage *formulas*
(`avk_commitment`, `next_avk_commitment`) are frozen now; their *bytes* lock at
M1 pending the mithril-stm 0.10.5 AVK wire-order transcription (ADR-003 D5;
docs/notes/sextant-legs.md §4). Until M1 the golden for those fields is marked
provisional in `/fixtures` and the equality invariant (§1.3) is the backstop.

### 1.3 The equality invariant — `T-A12-1`, CI-blocking

**What it asserts.** For every fixture in the Sextant corpus — golden AND mutant
— the guest verdict == native Sextant verdict, **and the journal
tier/assumptions match the native metadata** (HANDOFF §7 "Equality invariant
(CI-blocking)"; THREAT_MODEL A12 T-A12-1). Rejection parity is as important as
acceptance parity (HANDOFF §7; A12).

**Where it lives.** A harness over the full Sextant corpus, CI-blocking, run
inside `make gate` (THREAT_MODEL §5: T-A12-1 gate = `make gate`). The harness
runs each fixture through two paths and asserts equality:

- **Native path:** Sextant `verify_*` at the pinned commit (`3a68b2f`), the
  reference (`mithril-stm` 0.10.5 + `blst`; docs/notes/sextant-legs.md).
- **Guest path:** the `hg-guest` program executed (executor mode for CI speed;
  a real proof for the nightly smoke, §2). The comparison object is the
  byte-identical journal (ADR-003) plus the tier/assumption metadata
  (THREAT_MODEL A12: assumption bits `mithril_quorum`/`data_complete`, tier
  byte, anchor-basis byte cross verbatim from Sextant's ABI structs).

**This is the trait acceptance test (ADR-005 D1).** The `CheckpointSource`
trait's contract is a *postcondition on the produced `CheckpointState`*, not a
procedure: an implementation is correct iff, for every corpus fixture, its
`CheckpointState`/journaled-rejection is byte-identical to native Sextant's
(ADR-005 D1). The equality invariant *is* that acceptance test — so when
`NativeRecursiveSource` is one day built, it clears this same harness or it is
rejected (ADR-005 D3 requirement 3).

**Backend-differential is a sub-mode, not a separate suite** (§1.6): the same
harness, run with the guest built against different BLS backends, is how the M0
bakeoff proves both vendors prove the *same thing* (BENCH.md §2.2, §2.4).

### 1.4 Rejection parity — expected rejections are journaled verdicts, not panics

**What it asserts.** Every *expected* rejection (a malformed or adversarial but
in-bounds input Sextant rejects) is emitted by the guest as a **journaled
verdict** (`verdict != 0`, `reject_index` set), never a guest panic
(HANDOFF §5 "every expected rejection must be a *journaled verdict*, not a
panic"; CLAIMS.md §4; ADR-003 D6 verdict codes). A panic = no proof (CLAIMS.md
§4.4) — so a rejection that panics is a *coverage hole*, because the rejection
path then produces no journal to test.

**Where it lives.** This is a *property of the equality-invariant corpus*
(§1.3), not a separate suite: the corpus includes every mutant Sextant rejects,
and the assertion is "guest journals the same rejection verdict Sextant returns,
at the same `reject_index`." Two ledger rows make it explicit:

- **T-A9-3** — withholding → Stalled parity: truncated/gapped input sets produce
  the same `Stalled`/rejection verdict natively and in-guest, journaled
  (THREAT_MODEL A9; gate `make gate`).
- **T-A12-2** — tier-laundering negative: the codec *rejects* any encoding of a
  Tier-1 verdict lacking its assumption bits or carrying an upgraded tier byte
  (THREAT_MODEL A12; gate `make gate`) — the "a proven verdict keeps its tier"
  non-negotiable made a schema violation, not a judgment call (HANDOFF §0).

**Why it is doctrine, not hygiene.** Every surveyed vendor light client shipped
with "a single test case" covering only "the sunny-day behavior"
(THREAT_MODEL A1 corroboration, Veridise blobstream0 Exec Summary;
docs/notes/lightclient-patterns.md §4.6). Rejection parity is the discipline
that closes exactly that gap: the reject paths are first-class tested surface.

### 1.5 Reproducible-image-ID — `T-A6-1`, two independent builds

**What it asserts.** Two builds on independent runners (different host OS/arch),
each through the pinned vendor Docker toolchain, produce byte-identical ELF
(SHA-512) and identical image ID/vkey; any drift fails (THREAT_MODEL A6 T-A6-1;
ADR-004 D5; HANDOFF §3 Definition-of-Shipped line). The image ID *is* the trust
anchor (ADR-004 D1; HANDOFF §0 "the image ID is a signature on [the journal]"),
so this is the test that the anchor is *falsifiable* — a stranger with the
recipe reaches the same ID (ADR-004 D2, D6).

**Where it lives.** CI job `reproducible-image-id` (THREAT_MODEL §5 T-A6-1),
**CI-blocking from M1 onward** (not `make gate` — it needs two independent
runners and a container build, which a single dev checkout cannot provide).
Vendor-parameterized by the `build-recipe.toml` `vendor` field (ADR-004 D5): the
same job matrix runs the SP1 arm (`cargo prove build --docker` → `cargo prove
vkey`) and/or the RISC Zero arm (`cargo risczero build` → `compute_image_id`);
during the M0 bakeoff both arms run, and after ADR-001 the losing arm is dropped
without touching the job structure (ADR-004 D5).

**Companion release-gate test:** **T-A6-2** — clean-room rebuild audit: a
from-scratch machine following *only* the published `build-recipe.toml`
reproduces the shipped image ID (THREAT_MODEL A6 T-A6-2; ADR-004 D6). Runs at
the **release gate** and per-release, not per-commit.

### 1.6 The differential BLS-backend check — `T-A1-3` + BENCH.md wiring

**What it asserts.** The fixture corpus, run against guests built **with and
without** the vendor patched crates (accelerated vs pure-Rust BLS backend),
produces **identical journals** (THREAT_MODEL A1 T-A1-3; docs/notes/sp1.md §1
vendor requirement; BENCH.md §2.4). This is the guard that vendor crypto
acceleration is *only* an acceleration and never changes the verdict — the
Goodhart-resistant core of the M0 bakeoff (BENCH.md §2.2 "identical guest
workload", §2.4 differential + tamper controls).

**Where it lives.** A CI matrix job on the SP1 path (T-A1-3, gate CI) plus the
BENCH.md Part II run ledger for M0. The M0-specific obligations (BENCH.md §5,
§6, §7):

- **Differential check green** (BENCH.md §2.4): guest verdict == native Sextant
  verdict on the golden fixture AND the single-flipped-byte tamper control; the
  tamper control must run on the **patched/accelerated** configuration
  specifically (BENCH.md §2.4, §6.1).
- **Determinism check green** (BENCH.md §2.4): each threshold-bearing config
  runs twice; journal bytes identical across runs and vendors (== golden). This
  is where SP1's hint/unconstrained nondeterminism surface would show
  (docs/notes/sp1.md §1; THREAT_MODEL A1).
- **Per-row backend annotation** (BENCH.md §2.2): every recorded row names the
  backend actually linked — mandatory, so a number is never attributed to the
  wrong backend.

This suite feeds ADR-001's C2 validity gate (a vendor's numbers are eligible for
comparison only if its differential + determinism checks are green). It is
therefore *both* a soundness test (T-A1-3) and the input to the vendor-selection
gate — recorded once, read by both.

### 1.7 Contract & cross-layer suites — Foundry fork tests + binding checks

The on-chain and cross-layer surface. All live under `contracts/test` (Foundry),
`examples/`, and the SDK/CLI test crates (HANDOFF §5). Grouped by adversary:

**Router acceptance / rejection (fork tests against the deployed vendor
verifier on Base Sepolia — the signed `EVM_TESTNET`):**

- **T-A2-1** wrong-network revert (preprod journal → mainnet-configured router
  reverts with the specific wrong-network error). Gate CI.
- **T-A3-1** foreign-image rejection (valid proof from a foreign guest image,
  byte-identical journal, rejected by registry lookup / verifier). Gate CI.
- **T-A3-2** recursion inner-ID chain: an extension proof whose journaled inner
  image ID differs from the registry-pinned ID rejected by router, SDK, and CLI;
  and the zoo proves the inner-ID field is mutation-sensitive. Gate
  `make gate` + CI (the zoo half is `make gate`, the fork-test half is CI).
- **T-A10-1** old-checkpoint regression (a valid proof extending a superseded
  checkpoint is rejected by the router's monotonicity rule). Gate CI.
- **T-A11-1 / T-A11-2** re-genesis fixture pair + anchor-rotation drill (chains
  rooted at pre- and post-re-genesis anchors; the full governed rotation walked
  in a fork test — the genesis anchor is a *journaled input*, so one image
  serves both eras; ADR-004 D4, CLAIMS.md H4). Gate CI.

**Registry / admin governance (A8):**

- **T-A8-1** no-state-rewrite ABI surface: the router exposes **no**
  `adminSetTrustedState`-equivalent (ADR-002 D4; A8). Gate CI.
- **T-A8-2** timelock delay + event: registry add/remove of an image ID or
  network config only takes effect after the timelock and emits the governance
  event. Gate CI.
- **T-A8-3** registry state-machine fuzz (add/remove/propose/cancel) — Foundry
  fuzz. Gate CI.
- **T-A8-4** error-selector + revert-branch coverage (Zellic 3.1 + 3.5): every
  custom error selector and revert branch is exercised. Gate CI.

**Griefing / front-run / deploy-init (A13, A14):**

- **T-A13-1** minimum-progress rule **+ front-run race**: a below-minimum valid
  update is rejected; and in the race scenario an adversarial minimal valid
  extension lands while an honest proof is pending — assert the below-minimum
  update is rejected and the honest path recovers within a bounded number of
  re-proves (V-BLOB-VUL-001). Gate CI.
- **T-A13-2** DoS-cap bounds **incl. heliograph-introduced lists**: inputs at
  and just over each cap (Sextant's `guard_stm_bounds` caps *and* every
  heliograph-introduced input list — cert-chain hop count, block-window length,
  batch size); over-cap = journaled rejection at bounded cycles, panic = test
  failure. Gate `make gate` (guest tests) + `/fixtures`.
- **T-A14-1 / T-A14-2 / T-A14-3** golden deployment, first-interaction works,
  deploy-params round-trip (the sp1-helios constructor key-domain bug class —
  heliograph carries ≥3 height domains: slot, block height, epoch). Gate CI.

**Cross-layer binding — the ABI-drift defenses (A4):**

- **T-A4-1** unknown-version rejection (fuzz): fuzzed version bytes rejected at
  router (Foundry fuzz), guest/host (cargo fuzz), and SDK. Gate CI.
- **T-A4-2** downgrade fixture: a committed pre-freeze (v0) encoding is rejected
  by every verifier layer. Gate CI.
- **T-A4-4 — bindings-match-ABI** (Zellic 3.3): CI regenerates host/SDK Solidity
  bindings from the compiled contract ABI artifact and diffs against the checked
  -in copy; a drift fails. **Bindings are generated, never hand-written**
  (ADR-003 D8; THREAT_MODEL A4 — the sp1-helios `getCurrentSlot`/`getStorageSlot`
  drift). Gate CI.
- **T-A4-5 — no silent canonicalization** (Veridise V-BLOB-VUL-004): a fork test
  proving one buffer feeds *both* the vendor-verifier digest and field parsing —
  no decode→re-encode→hash round-trip (ADR-003 D8). Gate CI.

**Cross-layer agreement — the four-way equivalence (HANDOFF §7):**

- **T-A2-3** cross-layer network agreement: SDK and CLI verifiers reject the
  same wrong-network artifact the router rejects. Gate CI.
- **T-A5-2** router-accepts / consumer-rejects: `examples/evm-oracle` fork test
  where an old-but-valid proof is **accepted by the router** and **rejected by
  the example consumer's max-age policy** — proving both halves (router does not
  enforce recency; the consumer must; THREAT_MODEL A5, the largest documentation
  obligation in the product). Gate CI.
- **T-A9-1** offline portable verdict: `examples/portable-verdict` verifies a
  self-contained proof file with the network disabled — contract-accept ⇔
  SDK-verify ⇔ host-verify ⇔ native-verdict (HANDOFF §7 cross-layer agreement).
  Gate M3 gate → CI.
- **T-A9-2** permissionless update: an arbitrary unprivileged caller can submit
  a valid proof (no allowlist on submission; A9). Gate CI.

**Phase-3 permanent scenarios (become CI tests, never one-off):**

- **T-A5-3** stale-selection honesty, **T-A10-2 / T-A10-3** minority-fork
  journal visibility + malicious-prover selection-games suite. Gate CI (kept
  permanent after Phase 3, per §4). **T-A7-1** wrap-artifact digest pins
  (CI pin check against `build-recipe.toml` `wrap_circuit_version`; ADR-004 D3)
  and **T-A7-2** ceremony re-verification (per vendor bump, §9 gate 2 checklist).

---

## 2. Gate assignment — where each suite runs

Three gates, matching the ledger `Gate` column exactly (THREAT_MODEL §5). The
rule of assignment: **soundness-core and codec invariants that a single dev
checkout can run go in `make gate`; anything needing independent runners,
container builds, a testnet, or a release ceremony runs at CI or the release
gate.** `make gate` never shrinks (scripts/gate.sh header) — it grows these rows
in as the crates land.

### 2.1 `make gate` (local + the innermost CI job; HANDOFF §7 definition)

`make gate` = fmt + clippy -D warnings + tests + **equality invariant + journal
zoo + golden journals** + (nightly) a full proving smoke on one fixture per leg
(HANDOFF §7). scripts/gate.sh is the single source of truth `make gate` and CI
both run; it grows from the current phase-0 scaffold check as the workspace
lands. Rows that run here (ledger `Gate` = `make gate`):

| Ledger row | Suite (§1) |
|---|---|
| T-A1-1 unbound-input zoo | 1.1 (zoo + `docs/journal-coverage.md` parse) |
| T-A1-2 degenerate-path mutants | 1.1 (zoo class) |
| T-A2-2 network_id golden + mutant | 1.1 / 1.2 |
| T-A3-2 recursion inner-ID (zoo half) | 1.1 |
| T-A4-3 golden-encoding canonicality | 1.2 |
| T-A5-1 as-of fields golden + mutant | 1.2 |
| T-A9-3 withholding → Stalled parity | 1.4 (rejection parity) |
| T-A10-2 minority-fork journal visibility (zoo half) | 1.1 |
| T-A12-1 equality invariant | 1.3 (CI-blocking, run here) |
| T-A12-2 tier-laundering negative | 1.4 |
| T-A13-2 DoS-cap bounds (guest tests) | 1.7 |

The nightly proving-smoke (one real proof per leg) is a `make gate` mode that
CI runs on a schedule, not per-commit — a real proof is minutes (HANDOFF §2), so
per-commit uses executor/dev-mode for the equality invariant and the nightly job
is the one that exercises a genuine wrapped proof end-to-end.

### 2.2 CI (per-PR, not runnable on a bare dev checkout)

Needs Foundry + a Base Sepolia fork, two independent runners, container builds,
or fuzzing budget. Rows (ledger `Gate` = `CI` or `CI-blocking from M1`):

| Ledger row | Why not `make gate` |
|---|---|
| T-A1-3 patched-vs-original crates | CI matrix (two build configs) |
| T-A2-1 / T-A2-3 network revert + agreement | Foundry fork + SDK/CLI |
| T-A3-1 foreign-image rejection | Foundry fork |
| T-A4-1 unknown-version (fuzz) | Foundry fuzz + cargo fuzz |
| T-A4-2 downgrade fixture | all verifier layers |
| T-A4-4 bindings-match-ABI | CI codegen + diff |
| T-A4-5 no silent canonicalization | Foundry fork |
| T-A5-2 router-accepts / consumer-rejects | `examples/evm-oracle` fork |
| T-A6-1 two-independent-builds | two runners + container (CI-blocking from M1) |
| T-A7-1 wrap-artifact digest pins | CI pin check |
| T-A8-1..4 registry / admin / fuzz | Foundry fork + fuzz |
| T-A9-1 offline portable verdict | `examples/portable-verdict` (M3 gate → CI) |
| T-A9-2 permissionless update | Foundry fork |
| T-A10-1 old-checkpoint regression | Foundry fork |
| T-A11-1 / T-A11-2 re-genesis + rotation drill | Foundry fork |
| T-A12-3 mainnet-fixture corpus gate | corpus-composition check (§3) |
| T-A13-1 minimum-progress + front-run race | Foundry fork |
| T-A14-1..3 deploy-init suite | Foundry fork + deploy scripts |
| T-A5-3 / T-A10-3 Phase-3 scenarios | kept permanent post-Phase-3 |

### 2.3 Release gate + §9-gate-2 checklist

| Ledger row | Gate |
|---|---|
| T-A6-2 clean-room rebuild audit | release gate + per-release checklist |
| T-A7-2 ceremony re-verification | per vendor bump (§9 gate 2 checklist) |

T-A6-2 and T-A7-2 fire at ship and at every image-ID rotation (a vendor/version
bump; ADR-004 D4, THREAT_MODEL A6/A7). They are not per-PR because they audit a
*released* artifact against its published recipe.

---

## 3. Fixture strategy

Three sources, one non-negotiable, and a reuse rule.

### 3.1 Reuse Sextant fixtures wherever possible

The Sextant repository *is* the authority on Cardano verification semantics and
ships the fixture + mutant corpus (HANDOFF §8: "SPEC, trust model, fixtures,
mutant corpus"; §5: `/fixtures` "reuses Sextant vectors"). Heliograph
re-derives nothing (HANDOFF §0). The equality-invariant corpus (§1.3) is, by
construction, the Sextant corpus run through the guest — so every Sextant golden
and every Sextant mutant is already a heliograph fixture. Heliograph *adds*
fixtures only where it introduces surface Sextant does not have: the journal
byte-layout goldens (ADR-003), the recursion inner-ID chain (ADR-002), the
contract-side deploy/registry fixtures (A8/A14), and its own input-list bounds
(A13, heliograph-introduced lists).

### 3.2 Preprod for CI

Preprod fixtures are the per-PR corpus: cheap to prove, fast in the executor,
and they exercise the full leg logic. Every leg's equality invariant, zoo, and
golden suites run on preprod fixtures in `make gate`/CI (HANDOFF §5: "preprod →
mainnet-read-only fixtures for proving benchmarks").

### 3.3 Mainnet-read-only is MANDATORY for cost/bounds — `T-A12-3`

**This is the load-bearing fixture rule.** Preprod under-exercises mainnet
parameters by orders of magnitude: **k=5 vs mainnet k=1,944** lottery quorum;
~37 vs ~2,434 lottery indices; 1 vs ~59 single signatures per certificate
(THREAT_MODEL A12 residual; BENCH.md §3.3; docs/notes/mithril-recursion-watch.md
§3). A cost, bounds, or assumption path tested only on preprod is *under-tested*
(THREAT_MODEL A12 residual risk). Therefore:

- **T-A12-3 — corpus composition gate (CI):** the fixture set includes
  mainnet-read-only certificates and mutants **at mainnet parameters**; CI fails
  if any claim type's corpus is preprod-only (THREAT_MODEL §5 T-A12-3).
- **F-MN1 (the mainnet-read-only certificate) is mandatory for the M0 bakeoff
  and the threshold gate** (BENCH.md §3.2, §5; ADR-001 C1): a bakeoff without
  F-MN1 cannot be judged against `MAX_PROOF_TIME` ≤ 10 min / `MAX_PROOF_COST` ≤
  $1 and does not satisfy the M0 gate. "Read-only" = the fixture is a real
  mainnet certificate consumed for verification; heliograph never *writes* to
  mainnet without a §9 gate 7 (HANDOFF §5, §9).
- The DoS-cap bounds fixtures (T-A13-2) at mainnet parameters are where the
  over-cap journaled-rejection behavior is actually stressed — preprod caps are
  too small to exercise the real bound.

### 3.4 The tamper/determinism controls (BENCH.md)

Two synthetic fixtures ride every threshold-bearing run: the single-flipped-byte
**tamper control** (must flip the verdict, on the accelerated backend
specifically — BENCH.md §2.4, §6.1) and the **determinism** re-run (identical
journal bytes across two runs and across vendors — BENCH.md §2.4). These are not
Cardano fixtures; they are the controls that prove the corpus numbers are not
vacuous (§1.6; ADR-001 C2).

---

## 4. The permanence rule — every mitigation has a permanent test

HANDOFF §7 makes the suites a *permanent* maintained corpus, not a one-time
pass; THREAT_MODEL §5 states all 40 rows are "planned at v1" and the Phase-3
exit gate makes them "permanent tests" (HANDOFF Phase 3 exit: "zoo green;
scenarios permanent tests"). Two mechanical rules keep this true.

### 4.1 A mitigation without a permanent test is not a mitigation

Every adversary A1–A14 in THREAT_MODEL.md carries a **Pinning tests** subsection,
and every pinning test is a row in the §5 ledger with a gate. The rule: **no
threat-model mitigation may be claimed as "current" unless its pinning test
exists and runs at its assigned gate.** A Phase-3 red-team scenario that finds a
new hole is not closed by a fix — it is closed by a fix *plus* a permanent test
added to the ledger and wired to a gate (HANDOFF Phase 3: scenarios become
permanent tests; THREAT_MODEL §5 is the cross-reference "for wiring into
`make gate` and `docs/journal-coverage.md`"). The ledger is the checklist; a
mitigation whose row is unwired is a gate failure waiting to be filed.

This is the harness-decides-done doctrine (CLAUDE.md cursed-problems §"The
harness decides done"): the external check (the ledger + `make gate` + CI), not
the engineer's self-report, judges whether a threat is handled.

### 4.2 A new claim type ships its zoo + golden + equality rows *before* merge

When a claim type is added (the deferred 0x0006–0x0008, or any future type),
the merge is blocked until **all** of the following exist and are green
(HANDOFF §7; CLAIMS.md §1.7; ADR-003 §7):

1. **Zoo rows** — every new journal field and every new input byte-range has a
   `docs/journal-coverage.md` row resolving to a killing mutant or a filed
   verdict-irrelevance argument (T-A1-1). No unfilled row.
2. **Golden journal** — a byte-exact committed golden for the new claim type at
   its frozen `LEN_*` (T-A4-3; ADR-003 declares golden vectors normative).
3. **Equality-invariant rows** — the new type's fixtures (preprod AND
   mainnet-read-only, §3.3) run through the guest==native harness, accept AND
   reject (T-A12-1, T-A12-3).
4. **Rejection-parity rows** — every rejection path of the new type journals a
   verdict, never panics (§1.4; ADR-003 D6 verdict-code table extended with the
   new type's reachable codes).
5. **Any codec-specific mutant classes** the new type introduces (new presence
   flags, new commitment preimages) earn their ADR-003 §7 mutants.

ADR-003's HANDOFF note already fixes the compatibility half: deferred
0x0006–0x0008 bodies **do not re-layout** 0x0001–0x0005, so adding a type is
additive, and its test rows are additive to the ledger — never a rewrite of
existing goldens. `make gate`'s coverage-ledger parse (§1.1) enforces (1)
mechanically: a new field in `hg-claims` with no ledger row fails the gate, so
the "before merge" rule cannot be forgotten.

---

## 5. What this strategy deliberately defers

- **Exact test-function names and file paths** land with the crates (Phase 2
  M1+). This document fixes *which suite, which gate, which ledger row* — the
  Phase-1 obligation — not the Rust module tree.
- **The `docs/journal-coverage.md` initial rows** are authored at M1 when
  `hg-claims` fields become concrete bytes (ADR-003 S5/S6 lock at M1); the
  schema (one row per field per claim type, resolving to mutant-or-argument) is
  fixed here.
- **Vendor-specific CI arms** (which of SP1/RISC Zero the `reproducible-image-id`
  and `T-A1-3` matrices keep) resolve at ADR-001's M0 decision; the matrix
  structure runs both until then (ADR-004 D5) and is unchanged by the selection.
- **The nightly proving-smoke fixture selection** (one per leg) is fixed at M1
  when the legs exist; the gate rule (HANDOFF §7) is fixed here.

---

## Citations

- **HANDOFF.md** §0 (fail-closed; journal is the ABI of truth; a proven verdict
  keeps its tier; Sextant not re-derived), §1 (prover untrusted; only image ID +
  anchors load-bearing), §2 (proof latency minutes; no new claim semantics),
  §3 (Definition of Shipped: reproducible image ID; equality test over the
  entire corpus incl. mutants; three demos), §4 (phase gates; Phase-1 exit "test
  strategy written (§7 instantiated)"; Phase-3 zoo + permanent scenarios), §5
  (crate/dir layout; `/fixtures` reuses Sextant vectors; preprod → mainnet-read-
  only; every expected rejection is a journaled verdict not a panic), §7 (the
  verification doctrine — equality invariant CI-blocking, unbound-input zoo with
  `docs/journal-coverage.md`, golden journals, cross-layer agreement, benchmark
  regressions, the `make gate` definition), §8 (Sextant is the fixture/mutant
  authority; primary sources), §9 (gates: 1 publish, 2 vendor/image-ID rotation,
  7 mainnet).
- **docs/THREAT_MODEL.md** — §5 the 40-row test ledger (T-A1-1 … T-A14-3 with
  the `Gate` column this strategy matches), A1 (unbound-input zoo, degenerate
  paths, hint sub-class, never-waivable-on-audit-grounds), A4 (ABI-drift;
  bindings-from-ABI T-A4-4; no-silent-canonicalization T-A4-5), A5 (as-of
  staleness; router-accepts/consumer-rejects), A6 (reproducible image ID T-A6-1/
  T-A6-2), A7 (wrap-ceremony pins T-A7-1/T-A7-2), A8 (registry governance), A9
  (permissionless + withholding parity), A10 (old-checkpoint / selection games),
  A11 (re-genesis rotation), A12 (equality invariant; tier-laundering; mainnet-
  corpus gate T-A12-3; preprod k=5 vs mainnet k=1,944), A13 (front-run race +
  heliograph-introduced bounds), A14 (deploy-init).
- **docs/CLAIMS.md** — §1.7 item 7 (every journal field earns a mutant or a
  verdict-irrelevance argument; verbatim-input fields satisfy the zoo trivially),
  §2 (common header H1–H5), §3.1–3.5 (claim types 0x0001–0x0005; `CheckpointState`
  S1–S13), §4 (journaled rejections, not panics; a panic = no proof).
- **docs/adr/ADR-002** — recursion inner-image-ID chaining (T-A3-2), contract-
  side chaining + no `adminSetTrustedState` (T-A8-1), minimum-progress rule
  (T-A13-1).
- **docs/adr/ADR-003** — D2 (46-byte header offsets), D6 (verdict-code table),
  D8 (single-buffer / bindings-from-ABI / golden vectors normative), §7 (the
  codec-specific mutant classes: endianness, presence-flag, verdict-table,
  commitment-preimage, no-silent-canonicalization, length-gate); per-claim
  `LEN_*` (255/328/170/191/269); S5/S6 bytes lock at M1.
- **docs/adr/ADR-004** — D1 (image ID is the trust anchor; docker-pinned build),
  D5 (`reproducible-image-id` CI job, two independent builds, vendor-matrix),
  D6 (clean-room rebuild per release), D3 (`build-recipe.toml` incl.
  `wrap_circuit_version` for T-A7-1).
- **docs/adr/ADR-005** — D1 (the `CheckpointSource` trait postcondition == the
  equality invariant; byte-identical `CheckpointState`), D3 (a native swap
  clears the same equality harness).
- **docs/BENCH.md** — §2.2 (identical guest workload; commensurable numbers),
  §2.4 (differential + tamper + determinism controls), §3.2/§3.3 (F-MN1
  mandatory; preprod under-exercises mainnet), §5 (signed thresholds), §6.1
  (tamper control on the accelerated backend), §7 (record the loser's numbers).
- **docs/notes/** — sextant-legs.md (the leg inventory + guest-safety; §4 AVK
  wire-order; the STM backend seam), mithril-recursion-watch.md §3 (mainnet vs
  preprod parameters; 106-hop chains; re-genesis), sp1.md §1 (determinism;
  hints; reproducible-build path), lightclient-patterns.md §4.6 (every vendor
  shipped sunny-day-only tests — the gap rejection parity closes).

## HANDOFF — for the BUILD phase (M1+)

- **This document is the §7 instantiation** the Phase-1 exit gate requires
  (HANDOFF §4). It fixes suites → gates → ledger rows → fixtures → the merge
  rule. It does not author test code (Phase 2).
- **First BUILD obligations it creates:**
  1. **Author `docs/journal-coverage.md`** at M1 (one row per field per claim
     type; resolves to mutant-or-argument) and wire its parse into
     `scripts/gate.sh` (the coverage-ledger gate, §1.1) — `make gate`-blocking.
  2. **Stand up the equality-invariant harness** (§1.3) as the first
     `make gate` addition beyond the phase-0 scaffold — it is the trait
     acceptance test (ADR-005 D1) and gates every leg.
  3. **Commit the golden journals** per claim type at their frozen `LEN_*`
     (§1.2); mark S5/S6 provisional until the M1 AVK wire-order lock.
  4. **Stand up `reproducible-image-id`** CI-blocking from M1 (§1.5;
     THREAT_MODEL A6 T-A6-1; ADR-004 D5) with the vendor matrix.
  5. **Grow `scripts/gate.sh`** from the phase-0 scaffold to the full HANDOFF §7
     definition (fmt + clippy -D + tests + equality invariant + zoo + goldens +
     nightly smoke) as the crates land — it never shrinks.
- **The 40-row ledger is the checklist.** Every row has a home (suite §1) and a
  gate (§2) here; BUILD wires each to a live test at its milestone (T-A1-*/
  T-A12-* at M1–M2, T-A6-1 from M1, contract rows at M4, T-A6-2/T-A7-2 at
  release). No row is left unwired at ship (HANDOFF §3 Definition of Shipped).
- **The merge rule (§4.2) is binding from the first new claim type.** 0x0006–
  0x0008 (deferred) and any future type ship zoo + golden + equality + rejection
  -parity rows before merge; `make gate`'s coverage parse enforces it.
