# Architecture Decision Records

Numbered, immutable-once-accepted decision records for heliograph (HANDOFF §4
Phase 1). Each ADR states Context → Decision → Consequences → Alternatives, and
cites the recon notes (`docs/notes/`), `docs/CLAIMS.md`, and
`docs/THREAT_MODEL.md` rather than re-deriving Sextant semantics (HANDOFF §0).

| ADR | Title | Status |
|---|---|---|
| [000](ADR-000-naming.md) | Naming — crates.io / npm / GitHub / Cardano-ecosystem availability sweep | Accepted (`heliograph`, `hg-*` crates, `@fluxpoint` npm scope) |
| [001](ADR-001-zkvm-selection.md) | zkVM vendor selection (SP1 vs RISC Zero) | **Skeleton** — DECISION deferred to M0 numbers + §9 gate 2 human sign-off |
| [002](ADR-002-recursion-architecture.md) | Recursion architecture | Accepted (RISC Zero composed-path guest wiring provisional pending the M1 self-recursion spike) |
| [003](ADR-003-journal-as-abi-canonical-codec.md) | Journal-as-ABI: the canonical `hg-claims` codec | Accepted (codec rules frozen; `claim_version=1` assigned at the CLAIMS v1 freeze, Phase 2) |
| [004](ADR-004-reproducible-guest-builds.md) | Reproducible guest builds (image ID is the trust anchor) | Accepted |
| [005](ADR-005-swappable-checkpoint-source.md) | Swappable checkpoint source (native recursive-cert path behind a trait) | Accepted (native path is a future §9-gated swap) |

The Phase-1 design sketches these ADRs feed live in [`../design/`](../design/):
the `hg-claims` API sketch, the verifier-router contract interface, and the
test strategy (HANDOFF §7 instantiated).
