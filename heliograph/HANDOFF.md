# HANDOFF: `heliograph` — Portable ZK Verdicts for Cardano

**Operating contract for Claude Code. Five phases: SPEC → DESIGN → BUILD → RED TEAM → SHIP.**
**Thesis: Sextant made Cardano verification embeddable. Heliograph makes verdicts portable — succinct proofs of Sextant's verification, checkable by any chain, contract, or auditor.**

---

## 0. Agent bootstrap — read this first, every session

You are the sole senior engineer. This document is your contract.

Precedence: (1) live human instruction, (2) this document, (3) the Sextant
repository's SPEC and trust model (protocol truth already lives there — do not
re-derive it), (4) primary sources (§8), (5) your priors.

Session ritual: read `STATUS.md` → run `make gate` on a clean tree → continue
from "Next actions."

Non-negotiables:
- **Fail-closed, inherited and extended.** Sextant's rule — never claim what
  cryptography can't back — now applies to proofs: the on-chain verifier
  rejects unknown guest image IDs, unknown claim versions, and wrong network
  IDs. A proof that can't be fully bound is a rejected proof.
- **The journal is the ABI of truth.** Anything a verdict depends on MUST be
  bound in the guest's public output (journal) or committed via the image ID.
  An input that can change the verdict without changing the journal is a
  soundness bug of the highest severity.
- **A proven verdict keeps its tier.** Heliograph adds *proven computation*,
  not stronger claims: a proof of a Tier-1 windowed verdict is still Tier-1,
  with its assumptions carried verbatim into the journal. Laundering a tier
  through a proof is forbidden.
- **No custom circuits.** v0.1 is zkVM-only (guest programs in Rust). Writing
  or modifying arithmetic circuits is a §9 human gate — assume the answer is no.
- **Sextant is upstream, never a fork.** Consume it as a pinned dependency.
  Changes it needs (a `guest` feature) are upstreamed via PR to the Sextant
  repo, not vendored copies.

---

## 1. Mission

Build **heliograph** (working name — ADR-000): a system that produces and
verifies succinct zero-knowledge proofs of Sextant verification runs.

Concretely:
1. **Guest programs** — Sextant's verification legs (Mithril certificate
   chain, Praos header segments, tx/UTxO inclusion) compiled to a zkVM
   (SP1 or RISC Zero — selected by benchmark, ADR-001), executing over
   untrusted input bytes and committing a structured **journal**: the claim.
2. **A prover host** — CLI + daemon that fetches inputs (untrusted, as
   always), runs the guest, produces proofs, and wraps them (Groth16/PLONK
   per vendor pipeline) for cheap on-chain verification.
3. **An on-chain verifier** — EVM first: the vendor's audited verifier
   contract plus a thin claim-router that checks image ID, network ID, claim
   version, and exposes verified Cardano facts to consumer contracts.
4. **The claim schema** — `CLAIMS.md` + a shared `hg-claims` crate: the
   versioned, canonical encoding of what a proof asserts. This schema is the
   product's public interface; treat changes as breaking.

North star: **any contract, chain, or auditor can verify a fact about Cardano
for cents, without trusting the prover.** The prover is untrusted
infrastructure; only the pinned guest image and the Cardano trust anchors are
load-bearing.

Flagship demos (`/examples`):
- `evm-oracle/` — a public-testnet EVM contract that accepts a proof of a real
  Cardano preprod transaction inclusion and exposes it to other contracts.
- `portable-verdict/` — a CLI that emits a self-contained proof file; anyone
  verifies it locally with no chain access ("a Cardano fact in an email
  attachment").
- `checkpoint-update/` — the recursion loop: extend a proven Mithril
  checkpoint by one certificate and re-verify, demonstrating amortized cost.

---

## 2. Non-goals — hard boundaries

- No asset-transfer bridge product: heliograph is the **state oracle layer**;
  bridges are consumers of it. No custody, no wrapped assets, no token.
- No inbound leg in v0.1 (Plutus verifying foreign proofs via CIP-381 /
  Halo2-Plutus). Document the two-way vision in one page; build outbound only.
- No custom circuits, no modifications to vendor proof systems.
- No realtime promises. Proof latency is minutes; consumers needing seconds
  are out of scope and the docs say so.
- No prover-decentralization protocol in v0.1. Design so N independent provers
  can exist (proofs are permissionlessly verifiable); operate one.
- No new claim semantics beyond what Sextant already verifies. If Sextant
  can't verify it, heliograph can't prove it.

---

## 3. Definition of shipped (v0.1.0)

- [ ] `CLAIMS.md` v1 frozen: journal schema with image ID binding, network ID,
      anchor basis (carrying Sextant's `StmCertified` / ancillary distinction),
      trust tier, as-of slots, claim payload; golden-tested canonical encoding
- [ ] Guest crates build reproducibly: two independent builds → identical
      image ID, documented procedure
- [ ] M0 bakeoff published: proving cost/time for real preprod STM certificate
      verification on both candidate zkVMs, hardware-annotated (`BENCH.md`)
- [ ] Mithril checkpoint leg + recursion (extend-by-one-cert) proven end-to-end
      on preprod and preprod-mainnet fixtures
- [ ] Header-segment and inclusion legs composing a proven checkpoint
- [ ] CI equality test: guest verdict == native Sextant verdict over the
      entire Sextant fixture corpus (including every mutant — proofs of
      *rejection* paths must also agree)
- [ ] EVM verifier + TS SDK deployed to a public testnet (human gate), with
      accept ⇔ local-verify ⇔ native-verdict agreement tests
- [ ] Unbound-input zoo green (§7); THREAT_MODEL v2 post-red-team; SECURITY.md
- [ ] Three demos run from a fresh clone; benchmark page published
- [ ] Mithril-consumer note (what heliograph needs from native recursive
      certificates) written and shared upstream
- [ ] All §9 gates signed off

---

## 4. Phase gates

Tag at each gate. Do not start a phase before the prior gate passes.

### Phase 0 — RECONNAISSANCE & SPEC
- Read: Sextant SPEC + trust model (authoritative for Cardano semantics);
  Mithril certificate formats; both zkVM vendors' docs, precompile lists
  (BLS12-381 pairing coverage is decisive), licensing, and Groth16-wrap
  pipelines; the vendor verifier contracts.
- Write `CLAIMS.md` v0: every claim type as (inputs, journal fields, what is
  proven, what is assumed, tier). The Mithril anchor-basis distinction from
  Sextant carries through verbatim.
- Write `THREAT_MODEL.md` v1. Minimum adversary catalog: under-constrained
  journals; cross-network and cross-image replay; stale-but-valid data
  selection by a malicious prover; image-ID supply chain (non-reproducible
  builds); trusted-setup provenance of the vendor's wrapping circuit;
  verifier-contract admin-key compromise; data withholding (liveness).
- Write the **bakeoff spec**: identical guest workload (one real preprod STM
  certificate verification via Sextant's `mithril` path), measured on
  {{BENCH_HARDWARE}}; record cycles, wall time, proving cost, wrap time, gas.
- Write the Sextant upstream-needs note (proposed `guest` feature: `no_std +
  alloc` entrypoints, deterministic input encoding, no `std::time`).
- **Exit gate:** claims specified with sources; threat model reviewed; bakeoff
  spec approved with human-set thresholds (§12); go/no-go criteria explicit.

### Phase 1 — DESIGN
ADRs, minimum set:
- **ADR-000 Naming** — availability sweep (crates.io, npm, GitHub, Cardano
  ecosystem collisions); register continuity with Sextant encouraged.
- **ADR-001 zkVM selection** — decided by M0 numbers against §12 thresholds,
  not vibes. Record the loser's numbers too; revisit trigger defined.
- **ADR-002 Recursion architecture** — prove the certificate chain once from
  the pinned genesis vkey → cache the proven checkpoint → each update proves
  exactly one new certificate against the prior proof (composition). Header
  and inclusion claims compose the latest checkpoint proof rather than
  re-proving the chain.
- **ADR-003 Journal-as-ABI** — canonical, versioned encoding in `hg-claims`
  (shared by guest, host, SDK, and mirrored in the contract); every field's
  necessity is proven by a mutant (§7); unknown versions rejected everywhere.
- **ADR-004 Reproducible guest builds** — pinned toolchain container; image ID
  publicly recomputable; release artifacts carry the build recipe. Mandatory:
  the image ID *is* the trust anchor.
- **ADR-005 Swappable checkpoint source** — the Mithril STM leg sits behind a
  trait so native recursive Mithril certificates (in flight upstream) can
  replace it without touching claim semantics.
- Verifier contract design: vendor's audited verifier untouched; thin router
  above it; allowed-image-ID registry behind a timelocked admin (key custody
  is a §9 gate); events designed for indexer consumption.
- **Exit gate:** ADRs done; `hg-claims` API sketch; contract interface sketch;
  test strategy written (§7 instantiated).

### Phase 2 — BUILD
- **M0 — Bakeoff.** Both zkVMs, identical Sextant-derived guest, real fixture.
  Publish `BENCH.md`. **Human go/no-go:** if the better result exceeds
  {{MAX_PROOF_TIME}} / {{MAX_PROOF_COST}}, stop and escalate with options
  (wait for native recursive certs; narrower claims; hybrid models) — do not
  grind past the threshold.
- **M1 — Checkpoint leg.** Mithril chain verification in-guest from pinned
  genesis vkey; recursion per ADR-002. Gate: extend-by-one on real preprod
  certs; forged/spliced/replayed mutants rejected *in-guest* with journal
  evidence; reproducible image ID.
- **M2 — Chain + inclusion legs.** Header segments and tx/UTxO-read claims
  composing the checkpoint proof. Gate: full-corpus equality test vs native
  Sextant (accepts AND rejects); tier + assumptions present in every journal.
- **M3 — Host prover.** CLI + daemon; input fetching stays outside the guest;
  proof artifact format (self-contained: proof + journal + image ID + claim
  version). Gate: `portable-verdict` demo works offline end-to-end.
- **M4 — EVM verifier + SDK.** Foundry project; router + registry; TS SDK.
  Gate: testnet deployment (human gate first); accept ⇔ local-verify ⇔ native
  agreement in CI via fork tests; gas numbers in `BENCH.md`.
- **M5 — Demos + benchmarks.** All three flagship demos from fresh clone;
  benchmark page drafted for publication.

### Phase 3 — RED TEAM
Switch personas. Minimum program:
- **Unbound-input zoo** (the soundness core): for every guest input byte-range
  and every journal field, a mutant demonstrating either (a) mutation changes
  the journal/verdict, or (b) a written argument for why it is verdict-
  irrelevant, reviewed and filed. Any input that silently changes a verdict
  without journal change = P0, stop-the-line.
- Cross-network replay (preprod proof against mainnet-configured router);
  cross-image replay; claim-version downgrade; router admin abuse under
  timelock; stale-data honesty (as-of slot binding vs consumer recency
  checks — document the consumer's obligation explicitly).
- Malicious-prover games: valid proofs over adversarially *selected* inputs
  (old checkpoints, minority forks pre-anchor) — verify the anchor binding
  makes these visible in the journal.
- Fuzz the router and journal decoders; fork-test the deployed contract;
  reproducibility audit by clean-room rebuild.
- Document (not fix) vendor-trust surface: proving system assumptions,
  trusted setup lineage, verifier-contract audit provenance.
- **Exit gate:** zoo green; scenarios permanent tests; THREAT_MODEL v2 with
  residual risks; SECURITY.md with disclosure contact.

### Phase 4 — SHIP
- Docs: "What a proof proves, precisely" (mirror of Sextant's trust-model
  section, one page, brutal); integrator quickstarts (EVM consumer, CLI
  verifier); benchmark page; claim-schema reference.
- Release engineering: reproducible-build recipe published; signed artifacts;
  CI matrix incl. guest builds; `make gate` in CI.
- Publish the Mithril-consumer note upstream.
- v0.1.0 tag after §3 checklist and §9 sign-offs.

---

## 5. Architecture directives

```
/crates
  hg-claims        claim schema: types + canonical codec (no_std; shared)
  hg-guest         zkVM guest: sextant legs behind claim dispatch
  hg-host          prover CLI/daemon; fetch adapters; proof artifact I/O
  hg-sdk-ts        TypeScript verification + contract bindings
/contracts         Foundry: vendor verifier (vendored, unmodified) + router
/fixtures          proofs, journals, golden encodings; reuses Sextant vectors
/examples          evm-oracle/  portable-verdict/  checkpoint-update/
/docs              CLAIMS.md THREAT_MODEL.md BENCH.md adr/ notes/
```

Standing rules:
- Sextant = pinned git dependency (`guest` feature). Version bumps are
  deliberate commits with changelog reading, never floating.
- Guest: no I/O, no clock, no randomness beyond committed inputs; checked
  arithmetic; panics inside the guest are proof failures, not UB — but every
  expected rejection must be a *journaled verdict*, not a panic.
- Host fetch adapters follow Sextant's pattern: untrusted sources, bytes only.
- `hg-claims` codec: canonical (one encoding per value), versioned, golden-
  tested; mirrored constant-for-constant in the Solidity router.
- Networks: preprod → mainnet-read-only fixtures for proving benchmarks;
  contract deployments: {{EVM_TESTNET}} first; any mainnet (either side) is a
  §9 gate.

---

## 6. Dependency policy

zkVM vendor crates and verifier contracts pinned by exact version + hash;
upgrades are ADR-worthy events (image IDs change — that's a trust-anchor
rotation, handle it as one). Groth16/wrap verifier contracts are consumed
from the vendor's audited releases, byte-identical, never modified. Licenses:
Apache-2.0/MIT-compatible only; `cargo deny` enforces; deviations are §9.

---

## 7. Verification doctrine

Prove the prover the same way Sextant proved the verifier:
- **Equality invariant (CI-blocking):** for every fixture in the Sextant
  corpus — golden AND mutant — guest verdict == native Sextant verdict, and
  journal tier/assumptions match the native metadata. Rejection parity is as
  important as acceptance parity.
- **Unbound-input zoo** per §Phase-3, maintained as a permanent suite with
  coverage tracked in `docs/journal-coverage.md`; `make gate` fails on gaps.
- **Golden journals:** byte-exact expected journals committed per claim type.
- **Cross-layer agreement:** contract-accept ⇔ SDK-verify ⇔ host-verify ⇔
  native-verdict, exercised in fork tests.
- **Benchmark regressions:** `BENCH.md` is a ledger (hardware, versions,
  numbers); CI flags >{{REGRESSION_PCT}}% proving-time regressions.
- `make gate` = fmt + clippy -D warnings + tests + equality invariant +
  journal zoo + golden journals + (nightly) a full proving smoke on one
  fixture per leg.

---

## 8. Primary sources

- **Sextant repository** — SPEC, trust model, fixtures, mutant corpus: the
  authority on Cardano verification semantics. Heliograph re-derives nothing.
- **Mithril docs + repository** — certificate/artifact formats; the upstream
  SNARK/recursive-certificate workstream (watch item, ADR-005).
- **zkVM vendor documentation** (SP1, RISC Zero) — guest toolchains,
  precompiles, wrapping pipelines, verifier contracts, audits.
- **CIP-381 / Halo2-Plutus verifier** — for the two-way-vision note only.
- Cross-check code: vendor example light clients (e.g. Tendermint-in-SP1
  patterns) — read for architecture, never copy trust decisions.

Blog posts and model memory are not sources. When vendor docs and vendor code
disagree, file it in `docs/notes/upstream-issues.md` and trust the code.

---

## 9. Human gates — stop and ask before

1. Publishing anything public (crates, npm, contract deployments to ANY
   public network, docs domains, the Mithril note)
2. zkVM vendor selection sign-off (ADR-001) and any later vendor/version bump
   that rotates image IDs
3. Router admin / registry key custody decisions; any timelock parameter
4. Proving-infrastructure spend beyond {{PROVER_BUDGET}}
5. Custom circuit work of any kind (default answer: no)
6. Claim-schema changes after v1 freeze (breaking-change review)
7. Mainnet anything — Cardano mainnet anchors in shipped configs, EVM mainnet
   deployment
8. License deviations from Apache-2.0

If blocked and it's not on this list: most reversible option, provisional ADR,
continue.

---

## 10. Session mechanics

`STATUS.md` as in Sextant (phase, milestone, last green commit, next 3
actions, blockers with options + recommendation, pending gates), plus:
- `BENCH.md` is append-only history, never overwritten — cost claims must be
  reconstructible.
- Guest changes note their image-ID impact in the commit message.
- Conventional commits; tags at milestones; smallest testable increment;
  never mark done without `make gate` on a clean checkout.

---

## 11. Tone of the artifact

A proof is a promise made to strangers. The journal is a legal document; the
image ID is a signature on it. Boring, explicit, canonical, versioned —
clever encodings and implicit context are how oracles get people rekt.

---

## 12. Open items for the human — fill before or during Phase 0

- `{{PROJECT_NAME}}` (working: heliograph — signaling verified truth over
  distance; ADR-000 sweeps availability) and `{{GITHUB_ORG}}`
- Bakeoff thresholds: {{MAX_PROOF_TIME}} (suggest: ≤10 min/checkpoint-update
  on {{BENCH_HARDWARE}}), {{MAX_PROOF_COST}} (suggest: ≤$1/update),
  {{BENCH_HARDWARE}} (suggest: one pinned GPU cloud SKU)
- {{EVM_TESTNET}} for the M4 deployment (suggest: Base Sepolia)
- {{PROVER_BUDGET}} for Phase 2–3 proving spend
- v0.1 claim scope: inclusion-only, or inclusion + UTxO-read? (suggest: both —
  UTxO-read is where consumers live)
- Security disclosure contact; license confirmation (default Apache-2.0)
