# ADR-004 Reproducible guest builds

- **Status:** Accepted (2026-07-14)
- **Phase:** 1 — DESIGN
- **Deciders:** sole senior engineer (HANDOFF §0)
- **Depends on / relates to:** ADR-001 (zkVM selection — DEFERRED; this ADR is
  vendor-neutral by construction), ADR-002 (recursion — the inner-image-ID
  chain this build discipline anchors), ADR-003 (`hg-claims` codec — the vkey
  chain is a journal field), ADR-005 (checkpoint-source swap — a future
  image-ID rotation this recipe must handle unchanged).
- **Governs:** THREAT_MODEL A6 (image-ID supply chain), tests T-A6-1
  (two-independent-builds) and T-A6-2 (clean-room rebuild); Definition of
  Shipped item "Guest crates build reproducibly: two independent builds →
  identical image ID, documented procedure" (HANDOFF §3).

---

## Context

The image ID *is* the trust anchor. HANDOFF §5 (architecture directives) and
§0 ("the image ID is a signature on [the journal]") make the guest program's
identity — SP1's program verifying key `bytes32`, RISC Zero's image ID — the
single load-bearing binding between a proof and the verification logic that
produced it. Every downstream defense assumes it: the on-chain verifier takes
it as a verify-call parameter (`verifyProof(programVKey, …)` /
`verify(seal, imageId, journalDigest)`; docs/notes/sp1.md §4,
docs/notes/risc0.md §4), the router's timelocked registry allowlists it
(HANDOFF Phase 1), the portable-verdict CLI pins it, and recursion journals the
inner image ID as an ABI field (CLAIMS.md §2.3; docs/notes/lightclient-patterns.md
§3). THREAT_MODEL §1.1 lists the pinned guest image ID as the first
load-bearing element in the entire system.

That anchor is only as trustworthy as the claim "this published image ID
corresponds to this published guest source." THREAT_MODEL A6 states the attack:
a compromised toolchain, a poisoned build environment, or a merely
non-reproducible build lets a backdoored guest hide behind a legitimate-looking
ID — verifiers pin the ID, nobody can independently recompute it, and every
downstream binding (A3, cross-image replay) then binds to attacker logic. A6's
"what it achieves" is "the trust anchor itself is forged." This is the highest
class of supply-chain failure available in the system, because it defeats the
allowlist that every other layer relies on.

Both vendors compute the anchor deterministically from the built guest binary,
and both state that only their Docker-pinned toolchain produces that binary
reproducibly:

- **SP1.** The program vkey is derived deterministically from the ELF
  (`vk.bytes32()` from `client.setup(ELF)`, or offline via
  `cargo prove vkey --elf <path>`); reproducible ELF ⇒ reproducible vkey
  (docs/notes/sp1.md §1). The vendor warns that plain `cargo prove build` "may
  not generate a reproducible ELF"; the reproducible path is
  `cargo prove build --docker [--tag vX.Y.Z]`, which produces "a reproducible
  ELF that will be identical across all platforms," verified by SHA-512 of the
  ELF. The container is `ghcr.io/succinctlabs/sp1`; the default tag is the
  `sp1-build` crate version (docs/notes/sp1.md §1).
- **RISC Zero.** The image ID is `SystemState{ pc: 0, merkle_root }.digest()`
  under SHA-256, where `merkle_root` is the Merkle root over the initial memory
  image of the combined user+kernel ELF (`compute_image_id`,
  `binfmt/src/elf.rs:394`; docs/notes/risc0.md §1). The supported reproducible
  path is the Docker toolchain (`cargo risczero build` / `risc0-build`
  `use_docker`); the vendor FAQ states "These ImageIDs will stay consistent
  across all builds due to a containerized process," and a code comment in
  `risc0/zkvm/Cargo.toml` states that without Docker "the rust build system
  will generate binaries that [are] not identical across all architectures"
  (docs/notes/risc0.md §1).

Two facts force this ADR now, in Phase 1, ahead of ADR-001:

1. **The build recipe is part of the claim schema surface, not an
   implementation detail.** The image ID it produces is pinned in the router
   registry, in consumer contracts, and in the portable-verdict artifact; it is
   journaled as an inner image ID under recursion. A build procedure that
   cannot be independently reproduced makes all of those pins unfalsifiable.

2. **ADR-001 is deferred, so the layout must not assume the vendor.** The
   guest workspace, the recipe format, and the CI reproducibility check must be
   defined so that either vendor — or, transitionally, both in the M0 bakeoff —
   slots in without redesign. Both vendors expose the same three primitives
   (a pinned toolchain container, a deterministic binary→anchor derivation, and
   a documented recompute command), so a vendor-neutral abstraction is
   available (docs/notes/sp1.md §1,§6; docs/notes/risc0.md §1,§6;
   docs/notes/sextant-upstream-needs.md §5 already defines a vendor-neutral
   guest-clean build proxy).

Non-reproducible builds are not merely discouraged here; per both vendors they
are **non-canonical**. THREAT_MODEL A6 mitigation makes this explicit: "Non-
container builds are treated as non-canonical, full stop."

---

## Decision

**The image ID is the trust anchor, and its provenance is established by a
docker-pinned, per-vendor, publicly recomputable build. Every release artifact
carries a build recipe sufficient for any third party to recompute the image ID
from source, and CI fails on any image-ID drift.**

Six binding rules.

### D1. The pinned toolchain container is the build's root of trust

Guest binaries that produce a canonical image ID are built **only** inside the
vendor's pinned toolchain container, identified by an **immutable content
digest** (`@sha256:…`), never by a floating tag alone:

- **SP1 path:** `cargo prove build --docker --tag <vX.Y.Z>` against
  `ghcr.io/succinctlabs/sp1`, with the resolved image digest recorded
  (docs/notes/sp1.md §1). The `--tag` is human-legible; the recorded
  `@sha256:` digest is what the recipe and CI pin.
- **RISC Zero path:** the Docker toolchain (`cargo risczero build` /
  `risc0-build use_docker`) against the pinned `risc0/risc0` guest-build
  container digest (docs/notes/risc0.md §1).

Non-docker builds (`cargo prove build` without `--docker`, or a non-Docker
`risc0-build`) are permitted **only** for local development iteration and are
**never** the source of a published image ID, a registry entry, a golden
fixture, or a release artifact. This is the vendor-stated rule
(docs/notes/sp1.md §1: non-docker "may not generate a reproducible ELF";
docs/notes/risc0.md §1: non-docker binaries "not identical across all
architectures") adopted verbatim as THREAT_MODEL A6's "non-container builds are
non-canonical, full stop." CI enforces it by building canonical artifacts only
via the container path (D5) and by rejecting any locally-built ELF from the
release path.

The toolchain container digest is itself a trust dependency heliograph takes
rather than verifies (THREAT_MODEL A6 residual risk: "reproducibility pins
source→ID; it does not audit the vendor's toolchain container itself"). Pinning
it by immutable digest is what makes that dependency *stated and stable* rather
than silently floating; a container-digest change is a governed vendor bump
(HANDOFF §6, §9 gate 2), handled exactly like a version bump because it can
rotate the image ID.

### D2. The image ID must be publicly recomputable, offline, from source

For every published guest image, the recompute must be reproducible by a third
party holding only (a) the pinned source commit and (b) the recipe (D3), using
only vendor-documented commands:

- **SP1:** rebuild the ELF via the pinned container, then `cargo prove vkey
  --elf <path>` to derive the `bytes32` program vkey; assert the ELF SHA-512
  and the vkey both match the recipe (docs/notes/sp1.md §1).
- **RISC Zero:** rebuild via the pinned container, then
  `risc0_zkvm::compute_image_id(&elf)` over the combined binary to derive the
  image-ID digest; assert it matches the recipe (docs/notes/risc0.md §1).

"Publicly recomputable" is a hard requirement: the recompute uses no
heliograph-private inputs, no network fetch of unpinned artifacts, and no
non-container build step. The clean-room audit (T-A6-2) is the periodic proof
that this holds (D6).

### D3. Release artifacts carry the full build recipe

Every released guest image ships a machine-readable recipe (`build-recipe.toml`
committed under the artifact and reproduced in release notes) that pins, per
guest image:

| Recipe field | Binds | Vendor source |
|---|---|---|
| `vendor` | Which pipeline produced it (`sp1` \| `risc0`) | ADR-001 (deferred); both supported |
| `toolchain_container` | Immutable `image@sha256:…` of the build container | docs/notes/sp1.md §1; docs/notes/risc0.md §1 |
| `toolchain_tag` | Human-legible tag (`vX.Y.Z`) for legibility only | docs/notes/sp1.md §1 |
| `guest_source_commit` | The pinned `hg-guest` commit (and Sextant pinned dependency commit) | HANDOFF §5, §6; docs/notes/sextant-upstream-needs.md |
| `sextant_pin` | Sextant git rev consumed as the pinned dependency | HANDOFF §5 (Sextant = pinned git dependency, never a fork) |
| `patch_crates` | Any `[patch.crates-io]` guest substitutions (e.g. the accelerated `blst`/`bls12_381` fork tags) | docs/notes/risc0.md §2; docs/notes/sp1.md §2; docs/notes/sextant-upstream-needs.md §3 |
| `elf_sha512` | SHA-512 of the built guest ELF (the vendor's own reproducibility check unit) | docs/notes/sp1.md §1 |
| `image_id` | The resulting trust anchor: SP1 program vkey `bytes32` / RISC Zero image-ID digest | docs/notes/sp1.md §1; docs/notes/risc0.md §1 |
| `wrap_circuit_version` | Wrap-artifact identifiers (`SP1_CIRCUIT_VERSION` / RISC Zero `stark_verify.r1cs` hash + zkey ids) — pinned here so A7's digest check has a home | docs/notes/sp1.md §3; docs/notes/risc0.md §3; THREAT_MODEL A7 (T-A7-1) |

The recipe is the reproducible-build recipe HANDOFF Phase 4 requires published,
and the object the clean-room rebuild (T-A6-2) is executed against. Because the
`patch_crates` line names the guest's substituted crypto backends — the largest
single item in the Sextant `guest`-feature integration
(docs/notes/sextant-upstream-needs.md §3; docs/notes/sp1.md §2 BLS12-381
software-pairing path) — a change to a patched-crate tag is a recipe change and
therefore an image-ID-affecting, governed event.

### D4. Image-ID rotation is a governed trust-anchor event

Any input to the recipe that changes the image ID — guest source change, zkVM
vendor/version bump, toolchain-container digest change, or a `[patch.crates-io]`
tag change — is a **trust-anchor rotation**, not a routine build:

- The commit that changes a guest binary MUST note its image-ID impact in the
  commit message (HANDOFF §10).
- The rotation is a §9 gate 2 human sign-off (vendor/version bump that rotates
  image IDs) and flows through the router's timelocked registry as a governed
  add/remove (THREAT_MODEL A6 mitigation; A8 registry governance; A11
  re-genesis is the same rotation shape at the anchor level).
- The old image ID is not silently dropped: registry semantics keep already-
  accepted proofs verifiable while future proofs move to the new anchor
  (THREAT_MODEL A8 discussion; A11-2 anchor-rotation drill).

This rule is why the genesis anchor is a **journaled input, not a guest
constant** (CLAIMS.md H4; docs/notes/mithril-recursion-watch.md §3): re-genesis
is a real, recurring event (both networks re-genesised February 2025), and a
guest-const anchor would force an image-ID rotation per network and per
re-genesis. Keeping network/era binding in the journal and out of the image
means one image serves all networks and all genesis eras, so image-ID rotations
are reserved for *logic* changes — which is exactly what makes D4's governance
tractable (docs/notes/lightclient-patterns.md §2a, §6.1). The const-vs-input
decision itself is ratified in ADR-002/CLAIMS.md §6.3; this ADR records only its
consequence for build reproducibility: **the image ID commits to logic, not to
network configuration.**

### D5. CI runs the two-independent-builds check and fails on drift (T-A6-1)

A CI job `reproducible-image-id`, CI-blocking from M1 onward (THREAT_MODEL A6
T-A6-1; HANDOFF §3), builds each guest image on **two independent runners**
(different host OS/arch) through the pinned container and asserts:

1. byte-identical ELF (SHA-512 match across runners and against the recipe
   `elf_sha512`), and
2. identical image ID / vkey across runners and against the recipe `image_id`.

Any drift fails the gate. The check is vendor-parameterized (D-vendor-neutral):
the same job matrix runs the SP1 arm (`cargo prove build --docker` →
`cargo prove vkey`) and/or the RISC Zero arm (`cargo risczero build` →
`compute_image_id`) selected by the recipe `vendor` field, so during the M0
bakeoff both arms run and after ADR-001 the losing arm is dropped without
touching the job's structure. This job is the machine enforcement of D1–D3:
it proves the container path is deterministic and that the recipe's recorded
hashes are the ones the build actually produces.

Independence is deliberate: the vendor's own reproducibility guarantee is
"identical across all platforms" (SP1) / "consistent across all builds" (RISC
Zero); running on divergent host OS/arch is the test that the guarantee holds
in *our* build, not just the vendor's, and catches any accidental leak of host
state into the guest binary.

### D6. Clean-room rebuild is a per-release audit (T-A6-2)

At every release, and as the Phase-3 reproducibility audit, a from-scratch
machine following **only** the published recipe (D3) reproduces the shipped
image ID (THREAT_MODEL A6 T-A6-2; HANDOFF Phase 3 "reproducibility audit by
clean-room rebuild"). This is the human-executed counterpart to D5's automated
check: D5 proves reproducibility across two of *our* runners continuously; D6
proves a stranger with only public inputs reaches the same anchor. Together
they close A6 from both sides — internal drift and external unrecomputability.

---

## Consequences

### Positive

- **The trust anchor becomes falsifiable.** Anyone can take the recipe and the
  source commit and recompute the image ID; a mismatch is a public, mechanical
  proof of tampering. This is what lets the router registry, consumer pins, and
  portable-verdict allowlists mean something (THREAT_MODEL A3, A6).
- **Vendor-neutral by construction.** The layout (guest workspace + recipe +
  `reproducible-image-id` job matrix) is defined against the primitives both
  vendors share, so ADR-001 selects a vendor without reopening this ADR, and
  the M0 bakeoff runs both arms under one CI structure
  (docs/notes/sp1.md §1,§6; docs/notes/risc0.md §1,§6).
- **Image-ID rotations are legible and governed.** D4 routes every anchor-
  affecting change through commit-message impact notes, §9 gate 2, and the
  timelocked registry, so a rotation is a deliberate, delayed, observable event
  — never a silent swap (THREAT_MODEL A6, A8, A11).
- **The recipe gives A7 a home.** Wrap-circuit artifact identifiers ride in the
  recipe, so the A7 trusted-setup pin check (T-A7-1) has a committed source of
  truth to diff against on every build (THREAT_MODEL A7).
- **Reuse of the vendors' own units.** Reproducibility is checked at the SHA-512
  ELF granularity the vendors themselves publish, so heliograph's check inherits
  the vendors' reproducibility engineering rather than reinventing it
  (docs/notes/sp1.md §1).

### Negative / costs

- **Docker is mandatory for canonical builds**, including local production-shaped
  builds. SP1 local Groth16/PLONK proving already requires Docker + ≥16 GB RAM
  (docs/notes/sp1.md §3); RISC Zero's Groth16 wrap is x86-only, "Apple Silicon
  … unsupported (even via Docker)" (docs/notes/risc0.md §3). Consequence: the
  reproducible-build and wrap paths constrain developer hardware and
  {{BENCH_HARDWARE}} (AWS g6e.xlarge, x86 — compatible). Recorded, not fixed.
- **A second, slower build path.** Container builds are slower than plain
  `cargo build`; the `reproducible-image-id` job runs two of them per guest on
  independent runners. Accepted: the anchor's falsifiability is worth the CI
  minutes, and non-canonical fast builds remain available for inner-loop dev.
- **The toolchain container itself is unaudited trust.** Pinning by digest makes
  it stated and stable but does not remove it; a compromise of the vendor's
  published container is inside the vendor-trust surface (THREAT_MODEL §3),
  documented, not fixed here (HANDOFF §9 gate 5: no custom circuits / no
  reimplementing the vendor stack).
- **Recipe maintenance is now load-bearing.** A stale recipe (wrong digest,
  missing `patch_crates` line) would either fail D5/D6 (good) or, if the recipe
  and build drift together, mask a change — mitigated by D5 asserting the recipe
  hashes against freshly-built hashes on every CI run, so the recipe cannot
  silently diverge from what the pinned inputs actually produce.

### Neutral / follow-ups

- **Shared-image vs image-per-leg is left open** (CLAIMS.md §6.4;
  docs/notes/lightclient-patterns.md §3): whether all claim legs share one guest
  image (claim dispatch, `claim_type` as the first journal field, HANDOFF §5) or
  each leg gets its own image ID is an ADR-003/ADR-001 decision. This ADR is
  agnostic: the recipe (D3) and CI matrix (D5) enumerate *N* image IDs whether
  N = 1 or N = one-per-leg, with no structural change.
- **Recursion inner image IDs inherit this recipe.** The extend-by-one
  checkpoint guest's own image ID is produced and pinned by exactly this
  procedure; because the inner image ID is a journal field (CLAIMS.md §2.3,
  ADR-002), the recipe's `image_id` is what the router/CLI checks the journaled
  inner ID against (THREAT_MODEL A3 T-A3-2).
- **ADR-005 swap is a future rotation, not an exception.** If the STM leg is
  replaced by native recursive Mithril certificates, the guest source changes
  and the image ID rotates through D4 like any other logic change; the trust
  surface moves (image ID → Midnight Halo2/KZG circuit VK + SRS provenance,
  THREAT_MODEL §3 watch row) but the build-reproducibility discipline is
  unchanged.

---

## Alternatives considered

### Alt-1 — Non-docker builds, pin only the resulting hash

Build the guest with plain `cargo prove build` / non-Docker `risc0-build`, then
publish and pin whatever image ID results. **Rejected:** both vendors state
non-docker builds are non-reproducible — SP1 "may not generate a reproducible
ELF" (docs/notes/sp1.md §1), RISC Zero non-docker binaries are "not identical
across all architectures" (docs/notes/risc0.md §1). A pin over a
non-reproducible build is unfalsifiable: no third party can recompute it, so it
provides no defense against THREAT_MODEL A6 (the pin *is* the forgery surface).
This is precisely the "non-container builds are non-canonical, full stop" rule.

### Alt-2 — Bake the genesis/network anchor into the guest as a constant, letting the image ID carry network binding

Make the image ID the network binding by compiling the genesis vkey in as a
const (preprod and mainnet then get different image IDs; fail-closed by
construction). **Rejected for the build layer** (the semantic decision is
ADR-002/CLAIMS.md §6.3; recorded here for its reproducibility consequence): a
const anchor forces an image-ID rotation per network *and* per re-genesis, and
re-genesis is a real recurring event (both networks re-genesised February 2025;
docs/notes/mithril-recursion-watch.md §3). That multiplies D4 governed
rotations by the number of networks × genesis eras and makes the
`reproducible-image-id` matrix combinatorial. Keeping network/era in the
journal (CLAIMS.md H4) and out of the image means the image ID commits to logic
only, so rotations are reserved for actual logic changes — the surveyed
production light clients all pass the anchor as committed input for this reason
(docs/notes/lightclient-patterns.md §2a, §6.1).

### Alt-3 — Vendor-specific build tooling with no shared recipe/CI abstraction

Write the SP1 build/CI and (later) RISC Zero build/CI as independent,
purpose-built pipelines. **Rejected:** ADR-001 is deferred and the M0 bakeoff
runs both vendors over an identical guest workload (HANDOFF Phase 2 M0), so a
non-neutral layout would either block M0 or require a rewrite at vendor
selection. Both vendors expose the same three primitives (pinned container,
deterministic binary→anchor derivation, documented recompute command), so a
single recipe schema (D3) and a single vendor-parameterized CI matrix (D5) cover
both with no duplication — satisfying the code-hygiene rule against parallel
copies of the same logic.

### Alt-4 — Trust the vendor's Docker guarantee; skip the two-independent-builds CI check

Rely on the vendor's stated "identical across all platforms" / "consistent
across all builds" guarantee and pin a single build's output without CI
re-verification. **Rejected:** the guarantee is about the vendor's builds; A6
is about *heliograph's* build environment (a poisoned CI runner, an accidental
host-state leak into the guest binary). T-A6-1 running on two independent
OS/arch runners is the test that the guarantee holds in our pipeline, and HANDOFF
§3 makes "two independent builds → identical image ID" a Definition-of-Shipped
line item, not an optional check. A vendor guarantee is a claim to verify, not a
substitute for verification (HANDOFF §8: when vendor docs and reality disagree,
trust what you can check).

### Alt-5 — Reproducibility audited only once, at ship

Run the clean-room rebuild (T-A6-2) a single time before v0.1.0 and never
again. **Rejected:** every image-ID rotation (D4) — vendor bump, toolchain-
container digest change, patched-crate tag change, ADR-005 swap — produces a
new anchor whose reproducibility is unproven until re-audited. T-A6-2 is
therefore specified as **per-release** (THREAT_MODEL A6: "repeated at every
release"), with the continuous T-A6-1 CI check catching drift between releases.

---

## Citations

- **HANDOFF.md** §0 (image ID is a signature on the journal; fail-closed on
  unknown image IDs), §3 (Definition of Shipped: two independent builds →
  identical image ID; reproducible-build recipe published), §5 (architecture:
  the image ID is the trust anchor; guest crate layout; Sextant = pinned git
  dependency), §6 (dependency policy: exact version+hash pins; image-ID change
  is a trust-anchor rotation), §9 gates 2 & 5, §10 (guest changes note image-ID
  impact), Phase 3 (clean-room rebuild), Phase 4 (reproducible-build recipe
  published).
- **docs/notes/sp1.md** §1 (`cargo prove build --docker --tag`,
  `ghcr.io/succinctlabs/sp1`, ELF SHA-512, `cargo prove vkey`, reproducible-ELF
  ⇒ reproducible vkey; non-docker non-reproducible), §2 (BLS12-381 no pairing
  precompile → patched-crate software pairing; `patch_crates` significance), §3
  (wrap-circuit versioning `SP1_CIRCUIT_VERSION`; Docker+16 GB for wrap), §4
  (`verifyProof(programVKey, …)`), §6 (recursion: inner vkey as journaled
  input).
- **docs/notes/risc0.md** §1 (image ID = SHA-256 of `SystemState`;
  `compute_image_id`; docker toolchain the only canonical path; non-docker
  binaries differ across architectures), §2 (no BLS12-381 pairing/G2 precompile
  → software pairing over accelerated ops; blst/bls12_381 fork tags), §3
  (Groth16 wrap x86-only; `stark_verify.r1cs` hash for A7), §4 (`verify(seal,
  imageId, journalDigest)`), §6 (composition/recursion inner-ID as runtime
  input).
- **docs/notes/lightclient-patterns.md** §2a (const-in-guest vs committed-input
  anchor; image-ID-as-network-binding tradeoff), §3 (inner image ID as
  journaled input; shared-image needs claim-type-first), §6.1 (genesis-anchor
  placement is heliograph's to decide).
- **docs/notes/mithril-recursion-watch.md** §3 (both networks re-genesised
  February 2025; genesis vkey must be a versioned input, not an image constant).
- **docs/notes/sextant-upstream-needs.md** §3 (`[patch.crates-io]` guest
  crypto backends live in heliograph's guest workspace), §5 (vendor-neutral
  guest-clean build proxy).
- **THREAT_MODEL.md** A6 (image-ID supply chain / non-reproducible builds;
  T-A6-1 two-independent-builds, T-A6-2 clean-room rebuild; "non-container
  builds are non-canonical, full stop"; residual: toolchain container unaudited),
  A3 (cross-image replay — the binding A6 protects), A7 (wrap-circuit digest
  pins T-A7-1), A8 (registry governance of anchor rotation), A11 (re-genesis as
  anchor rotation), §1.1 (image ID first load-bearing element), §3 (vendor-trust
  surface; ADR-005 watch row).
- **CLAIMS.md** §1.2 (claim identity = image ID + journal; inner image IDs are
  journal fields), §2 H4 (`genesis_vkey` a versioned input, never an image
  constant), §2.3 (`anchor_mode` / `inner_image_id`), §6.3 (genesis-anchor
  placement ratification deferred to ADR-002), §6.4 (shared-image vs
  image-per-leg open).

---

## HANDOFF — for the next session

- **Status:** ADR-004 **Accepted**. Vendor-neutral by construction; nothing in
  it is blocked on ADR-001 (zkVM selection). Safe to build against.
- **What is now fixed:** the image ID is the trust anchor; canonical guest
  builds are docker-pinned per vendor by immutable container digest (D1);
  the image ID must be publicly recomputable offline from source (D2); every
  release carries a `build-recipe.toml` (D3, schema fixed); image-ID rotation
  is a governed §9-gate-2 event routed through the timelocked registry (D4);
  CI `reproducible-image-id` runs two-independent-builds and fails on drift
  (D5, T-A6-1, CI-blocking from M1); clean-room rebuild is per-release
  (D6, T-A6-2).
- **What this ADR deliberately does NOT decide** (owned elsewhere):
  1. **Vendor selection** — ADR-001, decided by M0 numbers. The recipe/CI matrix
     runs both arms until then.
  2. **Genesis-anchor placement (const vs input)** — semantically ratified in
     ADR-002/CLAIMS.md §6.3. ADR-004 only records the consequence (image ID
     commits to logic, not network config) and assumes the journaled-input
     design (CLAIMS.md H4).
  3. **Shared-image vs image-per-leg** — ADR-003/ADR-001; the recipe enumerates
     N image IDs for any N.
- **Build-time obligations this ADR creates for BUILD phase (M1+):**
  - Stand up the `reproducible-image-id` CI job (D5) as CI-blocking from M1;
    it is a Definition-of-Shipped line (HANDOFF §3).
  - Author `build-recipe.toml` per guest image (D3); wire the wrap-circuit
    identifiers so THREAT_MODEL T-A7-1's pin check reads from it.
  - Record the resolved toolchain container `@sha256:` digest at M0 for each
    vendor arm and pin it (D1); a digest change is a governed bump.
  - Confirm at M0 whether the guest binds `blst` (C, unusable in the SP1 guest)
    or a pure-Rust `bls12_381` backend, and record the `patch_crates` line
    accordingly (docs/notes/sp1.md §2; docs/notes/sextant-upstream-needs.md §3).
- **Open questions carried forward:** see `open_questions` in the structured
  output.
