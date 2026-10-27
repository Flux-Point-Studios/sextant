# ADR-000 Naming

- **Status:** Accepted (2026-07-14)
- **Phase:** 1 — DESIGN (HANDOFF.md §4 Phase 1: "ADR-000 Naming — availability
  sweep (crates.io, npm, GitHub, Cardano ecosystem collisions); register
  continuity with Sextant encouraged").
- **Deciders:** sole senior engineer; the `PROJECT_NAME`/`GITHUB_ORG`
  resolution (`heliograph` / `Flux-Point-Studios`) was a human item, greenlit
  2026-07-14 (STATUS.md §"HANDOFF §12 items").
- **Supersedes / superseded by:** none.

---

## Context

HANDOFF.md §1 names the system `heliograph` as a *working name* and makes
ADR-000 the availability sweep that either ratifies it or replaces it, and
fixes the crate namespace and npm scope the workspace publishes under
(HANDOFF §5 layout: `hg-claims`, `hg-guest`, `hg-host`, `hg-sdk-ts`). Two
constraints frame the decision:

1. **The name is a public-interface commitment.** Crate names, the npm scope,
   and the GitHub repo are the identifiers integrators pin. HANDOFF §9 gate 1
   makes *publishing* any of them a human gate; this ADR does the sweep so the
   publish, when it happens, lands on names that are free, uncontested in our
   domain, and continuous with Sextant (`github.com/Flux-Point-Studios/sextant`,
   README.md:4).
2. **Sextant is upstream continuity, not a fork** (HANDOFF §0). The naming must
   read as "the same studio's next layer": same GitHub org, a crate-prefix
   discipline that mirrors how Sextant itself avoids the contested bare name
   (`sextant` on crates.io is an unrelated navigation crate —
   `github.com/linuskmr/sextant-rs`, updated 2024-10 — so upstream already does
   not publish under the bare identifier).

The sweep below was run 2026-07-14 against the live registries (crates.io API,
npm registry, GitHub API) and web/ecosystem search. Each row records what the
check *returned*, per the HANDOFF §8 discipline (primary sources, not memory).

### Sweep results

**crates.io** (`GET https://crates.io/api/v1/crates/<name>`; 200 = taken,
404 = free):

| name | result | detail |
|---|---|---|
| `heliograph` | **TAKEN (dormant)** | "Medium-level bindings to System V semaphores", `standard-ai/heliograph`, one version `0.1.0`, last updated 2021-01-05, 7 recent downloads, not archived. Occupies the bare name; unrelated domain. |
| `hg` | **TAKEN** | occupied; not a target name. |
| `hg-core` | **TAKEN** | occupied; not a target name. |
| `hg-claims` | **FREE** | 404 — target. |
| `hg-guest` | **FREE** | 404 — target. |
| `hg-host` | **FREE** | 404 — target. |
| `hg-sdk` | **FREE** | 404. |
| `hg-sdk-ts` | **FREE** | 404 — target (HANDOFF §5). |
| `hg-verifier` / `hg-verify` / `hg-fixtures` | **FREE** | 404 — reserved for later crates. |
| `heliograph-claims` / `-guest` / `-host` / `-sdk` | **FREE** | 404 — the long-form fallback prefix, all free. |

**npm** (`GET https://registry.npmjs.org/<name>`; 200 = taken, 404 = free):

| name | result | detail |
|---|---|---|
| `heliograph` (unscoped) | **TAKEN** | "Tools to support message passing via async iterators", maintainer `vinsonchuong`, 55 versions (to 7.0.0), created 2018, last modified 2023-03. Live, unrelated domain. |
| `@heliograph/*` (scope) | **not reliably claimable** | scope names 404 (unpublished), BUT an npm scope matches an existing user/org name (npm docs, "About scopes"): the `heliograph` *username* is held by `vinsonchuong`, so the `@heliograph` org scope is coupled to that account and cannot be assumed available to us. |
| `@fluxpoint/*` | **FREE** | `@fluxpoint/hg-sdk` → 404; no package occupies the scope. |
| `@flux-point-studios/*` / `@fluxpointstudios/*` | **FREE** | 404 — org-continuous alternatives, both free. |

**GitHub** (`api.github.com`):

| target | result | detail |
|---|---|---|
| org `heliograph` | **FREE** (404) | no organization holds the handle. |
| user `heliograph` | **TAKEN** (200) | dormant personal account since 2010, 2 repos, last active 2015 — not an org, no namespace overlap with our domain. |
| repo `Flux-Point-Studios/heliograph` | **EXISTS** (200) | our target, already created (HANDOFF §9 gate-1 satisfied 2026-07-14). |
| repo `Flux-Point-Studios/sextant` | **EXISTS** (200) | continuity anchor; org has 46 public repos, created 2024-06. |
| repo search `heliograph` | 40 repos, **no collision** | top hit is a 10★ Objective-C reflection library (2016); rest are a VoIP lib, the abandoned semaphore crate, and tiny personal projects. **None is ZK, Cardano, blockchain, or oracle/bridge.** |

**Cardano / ZK ecosystem** (the decisive dimension):

| check | result |
|---|---|
| GitHub `heliograph cardano` | **1 repo: ours only.** |
| GitHub `heliograph zk` | **1 repo: ours only.** |
| `eryxcoop/zk-bridge` (recon: the only Cardano ZK bridge, docs/notes/lightclient-patterns.md) | real (3★, active 2026-06), named "zk-bridge" — **no "heliograph" clash**; and it is a *bridge* (inbound-verification consumer), a different product category from heliograph's outbound state-oracle layer (HANDOFF §2 non-goals). |
| Web search "heliograph Cardano zero-knowledge" | **no project named Heliograph.** Named Cardano ZK efforts — the [Halo2-Plutus verifier](https://iohk.io/en/blog/posts/2025/08/26/unlocking-zero-knowledge-proofs-for-cardano-the-halo2-plutus-verifier/), a [Hydra+ZK-SNARK framework](https://projectcatalyst.io/funds/10/development-and-infrastructure/a-zero-knowledge-proof-framework-for-cardano-based-on-hydra-and-zk-snarks), a [Semaphore privacy-layer port](https://projectcatalyst.io/funds/11/cardano-use-cases-concept/cardano-privacy-layer-zero-knowledge-proof-based-membership-verification-and-anonymous-voting-and-signaling-poc), Proof-of-Innocence — **none named Heliograph, none a naming clash.** The Halo2-Plutus verifier is exactly the CIP-381 inbound-leg primitive HANDOFF §2 defers, so it is a future *consumer*, not a competitor for the name. |

---

## Decision

**1. Project name: `heliograph`.** Ratified as the permanent name, not just a
working one. It is free at the level that matters — the GitHub org/repo
(`Flux-Point-Studios/heliograph`, already created) and, decisively, the Cardano
and ZK ecosystems, where no other project carries it. A heliograph signals
verified truth over distance by reflected light; the metaphor is the product
(HANDOFF §12). The bare-name collisions on crates.io and npm are dormant,
unrelated-domain packages and do not block the strategy below, which never
publishes a bare `heliograph` package.

**2. Crate namespace: `hg-*`** (HANDOFF §5 layout, ratified). The published
Rust crates are:

| crate | role (HANDOFF §5) | crates.io |
|---|---|---|
| `hg-claims` | claim schema: types + canonical codec (`no_std`; shared) | free |
| `hg-guest` | zkVM guest: Sextant legs behind claim dispatch | free |
| `hg-host` | prover CLI/daemon; fetch adapters; proof artifact I/O | free |
| `hg-sdk-ts` | (npm package, not a crate — see scope below) | n/a |

Reserved for later crates as they land (all confirmed free 2026-07-14):
`hg-sdk` (a Rust verification SDK if one is split out), `hg-verifier`,
`hg-fixtures`. The `hg-` prefix is the namespace; new crates take it without a
further sweep.

**3. npm scope: `@fluxpoint`.** The TypeScript SDK publishes as
`@fluxpoint/hg-sdk-ts` (and future JS/TS packages as `@fluxpoint/hg-*`). The
scope is free and is *org-continuous* with Flux Point Studios, which is the
right signal: it groups heliograph with any sibling Flux Point packages rather
than implying a standalone `heliograph` org. `@heliograph` is **rejected as the
scope** because an npm scope binds to a same-named user/org account and the
`heliograph` username is already held by an unrelated maintainer (npm docs,
"About scopes"), so the scope is not reliably ours to claim. `@flux-point-studios`
is a spelled-out fallback if `@fluxpoint` is unavailable at claim time (both
were free on the sweep).

**4. Continuity with Sextant.** Same GitHub org (`Flux-Point-Studios`); the
README already links Sextant as upstream (README.md:4). The `hg-` prefix
mirrors Sextant's own reality that the bare studio-project name is contested on
the package registries, so both projects live under the org on GitHub and under
short, free prefixes on the registries. Heliograph consumes Sextant as a pinned
git dependency, never a fork (HANDOFF §0) — the naming reflects a layer, not a
sibling.

---

## Consequences

- **Publishing is unblocked on names.** When HANDOFF §9 gate 1 is exercised,
  the crate names (`hg-claims`, `hg-guest`, `hg-host`), the npm package
  (`@fluxpoint/hg-sdk-ts`), and the repo are all confirmed-free or
  already-ours. No rename risk from a registry collision.
- **The bare `heliograph` package names stay unclaimed by us — deliberately.**
  We do not squat or contest the dormant crates.io/npm holders. The product's
  identity lives on GitHub and in the Cardano/ZK ecosystem, where it is
  uncontested; the registries carry only the prefixed/scoped names. This is the
  same posture Sextant takes.
- **One residual to resolve at publish time (npm scope claim).** `@fluxpoint`
  was free on the sweep but is claimed on first publish; if it has been taken in
  the interim, fall back to `@flux-point-studios` (also free on the sweep) — a
  one-line change in the SDK `package.json`, no code impact. Recorded as an open
  question, not a blocker.
- **New crates inherit the decision.** Any crate added under `hg-*` and any npm
  package under `@fluxpoint/*` is covered by this ADR; no per-crate sweep is
  required unless a name is later found taken.
- **No ecosystem confusion.** Because no Cardano/ZK project shares the name,
  integrators searching "heliograph cardano" / "heliograph zk" find only this
  project — the naming does its job as a locator (A2 cross-network legibility
  has a real-world cousin here: a self-describing, uncontested name reduces the
  chance a consumer pins the wrong artifact).

---

## Alternatives considered

- **Publish a bare `heliograph` crate / npm package.** Rejected: both are taken
  by dormant, unrelated-domain packages (crates.io System V semaphore bindings;
  npm async-iterator messaging lib). Contesting or requesting a transfer is
  cost with no benefit — the `hg-*` prefix and `@fluxpoint` scope give clean,
  free namespaces immediately, and the GitHub repo already carries the flagship
  name where it matters.
- **npm scope `@heliograph`.** Rejected: an npm scope binds to a same-named
  user/org, and `heliograph` the *username* is held by an unrelated maintainer,
  so the scope is not reliably claimable. `@fluxpoint` is both free and more
  honestly continuous with the studio.
- **Long-form crate prefix `heliograph-*`** (e.g. `heliograph-claims`).
  Confirmed free, but rejected in favor of `hg-*`: HANDOFF §5 fixes the short
  prefix, it is what the docs and Makefile already reference, and shorter
  import paths (`hg_claims::…`) read better in guest/host code. `heliograph-*`
  is held in reserve as a fallback only if an `hg-*` name is ever found taken.
- **Rename the project** (drop `heliograph`). Rejected: no ecosystem collision
  forces it; the name is free where the product lives (GitHub org/repo, Cardano
  and ZK search), the metaphor is apt (signaling verified truth over distance),
  and the human resolved `PROJECT_NAME = heliograph` on 2026-07-14. A sweep that
  finds the flagship dimensions clear is a ratification, not a trigger to
  rename.

---

## Sources

- **HANDOFF.md** §0 (Sextant upstream, not a fork), §1 (mission, working name),
  §4 Phase 1 (ADR-000 mandate), §5 (`hg-*` crate layout + `hg-sdk-ts`), §9
  gate 1 (publishing is a human gate). **STATUS.md** §"HANDOFF §12 items"
  (`PROJECT_NAME`/`GITHUB_ORG` resolved). **README.md**:4 (Sextant upstream
  link).
- **docs/notes/lightclient-patterns.md** — the recon that identified
  `eryxcoop/zk-bridge` as the only Cardano ZK bridge (checked here: no name
  clash, different product category).
- **Live registry checks, 2026-07-14** (this sweep): crates.io API
  (`heliograph` = `standard-ai/heliograph` dormant; `hg-claims`/`hg-guest`/
  `hg-host`/`hg-sdk-ts` free; `hg`/`hg-core` taken); npm registry
  (`heliograph` = `vinsonchuong` async-iterator lib, live; `@heliograph`
  scope coupled to that username; `@fluxpoint` free); GitHub API (org
  `heliograph` free, user taken/dormant, `Flux-Point-Studios/heliograph` and
  `…/sextant` exist; 40 unrelated `heliograph` repos, none ZK/Cardano);
  `github.com/linuskmr/sextant-rs` (bare `sextant` crate, unrelated — upstream
  precedent for prefix discipline).
- **npm scope semantics:** [About scopes | npm Docs](https://docs.npmjs.com/about-scopes/)
  — a scope matches a user/org name; only its owner publishes into it.
- **Cardano ZK ecosystem (no name clash):**
  [Halo2-Plutus verifier | IOG](https://iohk.io/en/blog/posts/2025/08/26/unlocking-zero-knowledge-proofs-for-cardano-the-halo2-plutus-verifier/),
  [Hydra + ZK-SNARK framework | Catalyst](https://projectcatalyst.io/funds/10/development-and-infrastructure/a-zero-knowledge-proof-framework-for-cardano-based-on-hydra-and-zk-snarks),
  [Cardano Semaphore privacy-layer port | Catalyst](https://projectcatalyst.io/funds/11/cardano-use-cases-concept/cardano-privacy-layer-zero-knowledge-proof-based-membership-verification-and-anonymous-voting-and-signaling-poc).

---

## HANDOFF

- **Decision is final for build.** Workspace crates are created under `hg-*`
  (`hg-claims`, `hg-guest`, `hg-host`); the SDK npm package is
  `@fluxpoint/hg-sdk-ts`; the repo is `Flux-Point-Studios/heliograph`. No
  further naming sweep is needed to start Phase 2 scaffolding.
- **CLAIMS / THREAT_MODEL impact: none.** This ADR fixes identifiers only; it
  does not touch claim semantics (CLAIMS.md), the journal ABI, or any adversary
  in THREAT_MODEL.md. The `hg-claims` crate that ADR-003 specifies is the one
  named here.
- **Blocks nothing; unblocks the workspace `Cargo.toml` package names.** The
  one deferred action — claiming the `@fluxpoint` npm scope and the crate names
  on first publish — is gated behind HANDOFF §9 gate 1 (human) and is a Phase-2
  event, not a Phase-1 one.
- **Open question carried forward:** confirm `@fluxpoint` is still free at the
  moment of first npm publish; fall back to `@flux-point-studios` if not (both
  free on this sweep). Tracked in STATUS.md next-actions when M4 (SDK) lands.
