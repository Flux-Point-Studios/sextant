# ADR-005 Swappable checkpoint source

- **Status:** Accepted. The `CheckpointSource` trait boundary is adopted now
  (v0.1). The native-recursive-certificate implementation behind it is a
  future, §9-gated trust-anchor swap that is **NOT** approved for v0.1 and
  today cannot clear the fail-closed bar.
- **Date:** 2026-07-14
- **Deciders:** sole senior engineer (HANDOFF §0), pending §9 sign-off for any
  future native-path activation (gate 2, gate 7).
- **Supersedes / relates:** ADR-001 (zkVM selection — decides the STM-walk
  proof system), ADR-002 (recursion architecture — the extend-by-one economics
  this trait preserves), ADR-003 (`hg-claims` codec — the journal this trait's
  output must satisfy byte-for-byte), ADR-004 (reproducible guest builds — the
  image-ID trust anchor the native path would *replace*, not extend).

---

## Context

Heliograph's checkpoint claim (`claim_type 0x0001`, CLAIMS §3.1) is the trust
terminus: every Mithril-anchored verdict cites it. Today the only way to
discharge it is to execute Sextant's `verify_chain_anchored`
(`D:/fluxPoint/sextant/src/mithril.rs:666`, via docs/notes/sextant-legs.md
Leg 2) **inside the zkVM guest** — the full genesis→tip STM certificate walk:
integrity + linkage + AVK-binding + genesis Ed25519 + one STM multi-signature
per rising certificate (105 hops on both networks today,
docs/notes/mithril-recursion-watch.md §3). The proven output is a
`CheckpointState` (CLAIMS §2.4) that a proof carries into the journal.

Two facts create the design pressure this ADR resolves:

1. **The in-guest STM verify is the dominant cost and the hard build risk.**
   mithril-stm 0.10.5 hardcodes `blst` (C + assembly) and pulls `rayon`
   (std threads); neither zkVM vendor's BLS12-381 acceleration patches blst's
   C path, they patch pure-Rust `bls12_381`-family crates
   (docs/notes/mithril-recursion-watch.md §1 "load-bearing build finding";
   docs/notes/sextant-legs.md §2.2). The pairing + 2 MSMs per certificate in
   un-accelerated portable C is "plausibly the whole M0 bill." The checkpoint
   leg is where heliograph is most exposed.

2. **Upstream is building the exact primitive that collapses this leg.**
   mithril-stm 0.10.5 *already ships* — behind the default-off `future_snark`
   feature — a second proof system (`proof_system/halo2_snark/`) and the
   recursion prototype (`circuits/halo2_ivc/`). Critically, the upstream IVC
   `State` (`src/circuits/halo2_ivc/state.rs`) is
   `{counter, msg, merkle_root, next_merkle_root, protocol_params,
   next_protocol_params, current_epoch}` — a **near-1:1 match** to
   heliograph's planned `CheckpointState` (CLAIMS §2.4 was deliberately
   modelled on it). A native recursive Mithril certificate would let the guest
   verify **one Halo2/KZG proof** whose public state binds
   `(epoch, AVK root, next-AVK root, params, msg)` instead of re-executing the
   STM walk (docs/notes/mithril-recursion-watch.md §2 "What a native recursive
   certificate would replace").

The temptation is to design the checkpoint leg around whichever path we expect
to win. That is a trap: the two paths differ enormously in verification
workload and in *whose cryptography is trusted*, but they must be
**identical in what the claim asserts** — a proven checkpoint is a proven
checkpoint regardless of how the STM math was discharged (HANDOFF §0: "A proven
verdict keeps its tier"; the proof upgrades nothing, CLAIMS §3.1 TIER). If the
claim semantics were entangled with the discharge method, swapping the method
would silently be a new claim — a soundness event disguised as an optimization.

This ADR fixes the boundary now, while it is cheap, so that the swap — when and
if upstream productizes — is an isolated, governed, ADR-worthy event and not a
rewrite of the claim schema.

---

## Decision

### D1. The Mithril STM verification leg sits behind a `CheckpointSource` trait.

The guest's checkpoint claim (`0x0001`) and extension claim (`0x0002`) are
written against a trait boundary, not against `verify_chain_anchored` directly.
The trait is the seam at which the STM math is discharged; everything above it
(journal construction, header dispatch, the `hg-claims` codec, the router, the
SDK, the CLI) is method-agnostic.

**The trait boundary — what it consumes and what it produces:**

```text
CheckpointSource
  consumes (untrusted bytes + committed anchors):
    - certificate material: the aggregator artifact(s) for the walk
      · STM path:    cert JSON, oldest-first (Sextant Certificate::from_json)
      · native path: one recursive SnarkProof + its bound public state
    - genesis_vkey: [u8;32]  (committed input, journaled as header H4;
                              a VERSIONED claim input, never an image
                              constant — re-genesis is real, CLAIMS §H4,
                              mithril-recursion-watch §3)
  produces (on success):
    - a verified CheckpointState (CLAIMS §2.4, fields S1..S13) —
      {root_hash, tip_hash, tip_epoch, chain_length, avk_commitment,
       next_avk_commitment, stm_k, stm_m, stm_phi_f_fixed,
       has_certified_transactions, ctx_merkle_root, ctx_epoch,
       ctx_block_number}
  produces (on expected failure):
    - a journaled rejection (verdict != 0, reject_index = offending
      certificate index) — NOT a panic (CLAIMS §4; HANDOFF §5)
```

The contract of the trait is a **postcondition on the produced
`CheckpointState`, not a procedure**: an implementation is correct iff, for
every certificate corpus (golden and mutant), the `CheckpointState` (or
journaled rejection) it produces is byte-identical to the one native Sextant
`verify_chain_anchored` yields for the same bytes and `genesis_vkey`. This is
exactly the existing equality invariant (HANDOFF §7; THREAT_MODEL T-A12-1),
now stated as the trait's acceptance test rather than a leg-specific one.

**Two implementations, one contract:**

| impl | how STM is discharged | trusted for soundness | status |
|---|---|---|---|
| `StmWalkSource` (v0.1) | Sextant's `verify_chain_anchored` executed in-guest; the pure-Rust guest BLS backend (sextant-legs §3 "STM backend seam") does the pairing/MSM/lottery math | pinned **image ID** (ADR-004) + Mithril's stake-threshold assumption | **built** |
| `NativeRecursiveSource` (future) | verify one upstream recursive Mithril `SnarkProof`; read its bound IVC public state into `CheckpointState` | Midnight Halo2/KZG **circuit VK + SRS provenance** + Mithril's stake-threshold assumption | **gated, not built** (D3) |

### D2. A swap does not touch claim semantics, and MUST NOT.

The journal produced under either implementation is bit-for-bit the same
`CheckpointState` under the same `hg-claims` codec. Concretely, swapping the
implementation:

- **Does not** change any CLAIMS field, field order, type, verdict code, tier,
  or as-of scoping (CLAIMS §2.4, §3.1). The claim version (`claim_version`,
  CLAIMS §H1) does not increment on a swap, because the ABI of truth is
  unchanged.
- **Does not** relax any fail-closed check the verifier performs:
  `network_id`, `genesis_vkey`-against-pin, `claim_version`, `claim_type`,
  and anchor binding (CLAIMS §1.4) all sit *above* the trait and are
  unaffected.
- **Does** change the guest's *image ID* (the guest program is different), and
  therefore is a governed image-ID rotation on its own (ADR-004; HANDOFF §6,
  §9 gate 2) — see D3.

This is the whole point of the boundary: "a proven checkpoint is a proven
checkpoint regardless of how the STM math was discharged." The tier is
preserved verbatim (CLAIMS §3.1 TIER: "The proof upgrades nothing"); laundering
a tier or a basis through a change of discharge method is forbidden
(CLAIMS §1.5, §5.5).

### D3. A swap to the native path is an ADR-worthy **trust-anchor** event, and today it CANNOT clear heliograph's fail-closed bar.

The native path is **not a free optimization** — it moves the trust surface, it
does not shrink it (docs/notes/mithril-recursion-watch.md §2: "the trust
surface does not vanish — it moves: image ID → circuit VK + SRS provenance").

Under `StmWalkSource`, soundness rests on: (a) the pinned **image ID** (the
guest logic is what it says it is — ADR-004, reproducibly built), plus
(b) Mithril's stake-threshold assumption carried verbatim (CLAIMS §3.1
ASSUMES). Under `NativeRecursiveSource`, (a) is **replaced** by: the Midnight
Halo2/KZG **recursive circuit's verifying key**, its **SRS provenance** (whose
KZG ceremony, how distributed, how versioned), and a stable, versioned
`SnarkProof` serialization with golden vectors. Heliograph must treat a circuit
VK exactly as it treats an image ID — a trust anchor whose rotation is a
governed event (docs/notes/mithril-recursion-watch.md §4 ask 2).

Therefore a future swap is a full ADR of its own (call it ADR-005a when
proposed), and it must clear the **same fail-closed bar** the image-ID anchor
clears today (ADR-004; THREAT_MODEL A6 "image-ID supply chain", A7
"trusted-setup provenance"). It must, at minimum:

1. Pin the circuit VK and SRS by exact hash, with documented, re-verifiable
   provenance (the analogue of the two-independent-builds requirement for the
   image ID; THREAT_MODEL A6/A7 pinning tests).
2. Publish a stable, versioned `SnarkProof` wire format with golden vectors,
   so the guest's decode is canonical and differentially testable against
   upstream (the Sextant transcription discipline,
   docs/notes/mithril-recursion-watch.md §4 asks 2 and 5).
3. Pass the equality invariant against the STM-walk source over the full corpus
   (D1 postcondition) — the native `CheckpointState` must be **semantically
   equivalent** to the STM-walk `CheckpointState` for the same anchor, produced
   over a **source-invariant `avk_commitment` preimage**: S5/S6 are defined over
   the Mithril-protocol AVK root (`mt_root ‖ total_stake`, ADR-003 D5), which
   every checkpoint source must expose, so the two sources yield byte-identical
   S5/S6 without either passing through its own proof-system-internal hash. If
   the native path cannot surface the protocol `mt_root`, that is an ADR-003
   codec-revision trigger before the `claim_version=1` freeze, not a swap that
   silently changes the commitment.
4. Carry the Midnight ZK library audit into THREAT_MODEL §3 as a documented
   vendor-trust row, exactly as the zkVM vendors' audit lineage is
   (THREAT_MODEL §3 vendor-trust surface; watch row).

**Today it fails this bar and the swap is blocked**, per
docs/notes/mithril-recursion-watch.md §2 and THREAT_MODEL §3 watch row:

- **The SRS is unsafe.** `SnarkProof::verify` regenerates its `SnarkSetup`
  (SRS) *in-function*, commented in upstream as temporary "until the circuit is
  stable and the srs is stored and available." The trusted setup is not yet a
  pinned, distributed artifact. Upstream #3300 ("refactor the unsafe SNARK
  setup") is **open** (mithril-recursion-watch §2). Requirement 1 cannot be
  met.
- **The audit is in flight.** The Midnight ZK library audit is in progress
  (Intersect update 2026-06-17), not published. Requirement 4 cannot be met.
- **There is no activation date.** Primitives are done and running on an
  internal test network (Intersect 2026-07-01), but productization gates
  remain — unsafe-setup refactor, audit, aggregator wire format,
  dual-signature genesis rollout, Schnorr signer re-registration, and by
  precedent an era switch + possible re-genesis. No public
  release-preprod/mainnet activation date exists
  (mithril-recursion-watch §2 "Timeline read (honest)", §5 "Honest unknowns").

### D4. The trait stays; v0.1 does not block on the native path.

The `CheckpointSource` boundary is adopted in v0.1 regardless of upstream
timing, because it is cheap now (it is where Sextant already draws its own
backend seam — sextant-legs §3.2, "the entire mithril-stm surface Sextant
touches is four types + one call") and expensive to retrofit later. v0.1 ships
`StmWalkSource` only. `NativeRecursiveSource` is left as an
unimplemented, documented target behind the trait, activated only when D3's bar
is met and a §9 gate 2 (vendor/anchor rotation) — and, because activation
plausibly rides a re-genesis, §9 gate 7 (mainnet/anchor) — signs it off.

Heliograph additionally commits to be the **first external verifying consumer**
of recursive certificates when they stabilize (the ship-checklist
Mithril-consumer note, HANDOFF §3; mithril-recursion-watch §4 ask 7). That is a
relationship-building deliverable, not a v0.1 dependency.

---

## Consequences

**Positive.**

- The most expensive and highest-build-risk leg (the in-guest STM walk,
  Context fact 1) has a pre-planned replacement path that is a **pure trust-and-
  cost swap**, not a schema change. When upstream productizes, heliograph
  captures the ~105× amortization collapse (mithril-recursion-watch §3) by
  changing one implementation behind a stable trait.
- Claim semantics, the journal ABI, the codec, the router, the SDK, and the CLI
  are all insulated from the swap by construction (D2). The equality invariant
  (HANDOFF §7) is repurposed as the trait's acceptance test, so the two
  implementations are held byte-identical or one is rejected in CI.
- The trust-anchor nature of the swap is named *now*, before anyone can mistake
  it for a mere optimization. The circuit-VK-is-a-trust-anchor framing
  (image ID → VK + SRS) is on the record, so the future ADR-005a inherits a
  fail-closed checklist rather than re-litigating it (THREAT_MODEL A6/A7).

**Negative / costs.**

- A trait boundary with **one implementation today** is, on its face, the
  "abstraction with one caller" that code hygiene forbids (HANDOFF §5;
  CLAUDE.md code hygiene). This is justified explicitly: the second
  implementation is a *known, specified, upstream-in-flight* target with a
  matching public state shape (Context fact 2), not a speculative
  generalization — the three-concrete-cases rule is waived because the second
  case is documented in mithril-stm 0.10.5 source, not imagined. The boundary
  is drawn at Sextant's own existing seam (sextant-legs §3.2), so it adds
  essentially no surface over the STM-walk implementation we must write anyway.
- Carrying an unimplemented `NativeRecursiveSource` target risks rot. Mitigated
  by: the watch item lives in docs/notes/mithril-recursion-watch.md with a
  dated recon and reproducible method; the Mithril-consumer note is a ship
  deliverable (HANDOFF §3); THREAT_MODEL §3 carries the watch row and re-pins
  at every vendor bump.

**Neutral / obligations created.**

- `hg-claims` must define `CheckpointState` such that both implementations can
  populate it identically. ADR-003 D5 resolves the constraint this ADR raises:
  `avk_commitment` / `next_avk_commitment` (CLAIMS S5/S6) are defined over the
  **Mithril-protocol AVK root** (`mt_root ‖ total_stake`), which is the AVK the
  protocol itself defines — source-invariant, exposed by the STM-walk directly
  and required to be exposed by any native source (its internal Poseidon hashing
  is not the commitment). The commitment is therefore a binding commitment to
  the *protocol* AVK, not a passthrough of a proof-system-internal hash, and the
  native source must surface `mt_root` to reproduce it (ADR-003 D5).
- When ADR-005a is written, it must record the rejected option verbatim
  (the const-vs-input anchor placement, CLAIMS §6 open question 3;
  THREAT_MODEL A11) and walk the full governed rotation
  (THREAT_MODEL T-A11-2 anchor-rotation drill) if activation rides a
  re-genesis.

---

## Alternatives considered

**A. No trait — call `verify_chain_anchored` directly in the guest.**
Rejected. The native recursive certificate is not speculative: the primitive
ships in the pinned dependency behind `future_snark`, with a public IVC state
shape that already matches `CheckpointState` (Context fact 2). Hard-wiring the
STM walk would make the eventual swap a claim-schema rewrite touching the guest,
codec, router, SDK, and CLI at once — exactly the entanglement HANDOFF §0
("the journal is the ABI of truth") and this project's tier-discipline forbid.
The retrofit cost dwarfs the near-zero cost of drawing the seam now at Sextant's
own backend boundary.

**B. Adopt the native recursive certificate as the v0.1 checkpoint source.**
Rejected, and blocked. It cannot clear the fail-closed bar today (D3): the SRS
is regenerated in-function ("unsafe setup", upstream #3300 open), the Midnight
ZK audit is in flight, and there is no release-network activation date
(mithril-recursion-watch §2, §5; THREAT_MODEL §3 watch row). Adopting it would
replace a reproducible, pinned image-ID anchor (ADR-004) with an unpinned,
unaudited SRS — a strict downgrade of the trust root, in direct violation of
HANDOFF §0 fail-closed. It is also a §9 gate 2 vendor decision and, plausibly,
a §9 gate 7 re-genesis event; neither is signed.

**C. Two claim types — one for STM-walk checkpoints, one for native-recursive
checkpoints — instead of one behind a trait.**
Rejected. This would encode the discharge method into the claim identity,
making a consumer's verified fact depend on *how* the checkpoint was proven
rather than *what* it asserts. That is a tier/semantics distinction where none
exists (HANDOFF §0: a proven verdict keeps its tier; both paths prove the
identical `CheckpointState`). It would also double the downstream surface —
every inclusion/utxo-read anchor binding (CLAIMS §2.3) would need to accept both
checkpoint types — for zero semantic gain. The correct place for the
method distinction is the trait implementation and the *trust anchor pin*
(image ID vs circuit VK), which is governance-visible without being
claim-visible.

**D. A generic "proof source" trait spanning all legs (header, inclusion,
utxo-read), not just the checkpoint.**
Rejected as over-generalization (HANDOFF §5; CLAUDE.md: three concrete cases
before generalizing). Only the checkpoint leg has a real, in-flight upstream
alternative implementation. The header and inclusion legs have exactly one
discharge method each (Sextant's pure-Rust verify) with no second implementer
on any horizon. A trait there would be an abstraction with one caller and no
prospect of a second — precisely the dead weight the hygiene rules name.

---

## Citations

- **HANDOFF.md** — §0 (fail-closed; "a proven verdict keeps its tier"; the
  journal is the ABI of truth; Sextant is upstream, never a fork); §4 Phase 1
  ("ADR-005 Swappable checkpoint source — the Mithril STM leg sits behind a
  trait so native recursive Mithril certificates … can replace it without
  touching claim semantics"); §5 (architecture; abstraction discipline); §6
  (dependency pins are ADR-worthy trust-anchor rotations); §7 (equality
  invariant); §9 (human gates 2 vendor/anchor rotation, 7 mainnet/re-genesis).
- **docs/notes/mithril-recursion-watch.md** — §1 (in-guest STM cost + blst
  build finding); §2 (the `future_snark` SNARK track; `halo2_ivc` `State`
  near-1:1 to `CheckpointState`; "the trust surface does not vanish — it moves:
  image ID → circuit VK + SRS provenance"; the in-function "unsafe setup"
  caveat and #3300; Midnight audit in flight; "Timeline read (honest)"); §3
  (105-hop chains; re-genesis rotates the anchor; ~105× amortization); §4 (asks
  2 SRS/VK provenance, 5 golden vectors, 6 publish the Midnight audit, 7
  first-consumer commitment); §5 (honest unknowns: no activation date, SRS
  provenance undocumented).
- **docs/notes/sextant-legs.md** — Leg 2 (`verify_chain_anchored`, the STM
  walk this trait wraps); §2.2 (the `mithril` feature is the guest blocker:
  blst is C, rayon needs std threads); §3.2 ("STM backend seam" — four types +
  one call; the exact boundary this ADR draws).
- **docs/CLAIMS.md** — §H4 (`genesis_vkey` a versioned claim input, never an
  image constant); §1.4 (fail-closed verification); §1.5 (a proven verdict
  keeps its tier; no laundering); §2.3 (anchor binding modes downstream legs
  cite the checkpoint through); §2.4 (`CheckpointState` S1..S13, modelled on
  the upstream IVC `State`, "so the ADR-005 checkpoint-source swap … changes
  the verification workload without changing claim semantics"); §3.1 (`0x0001`
  checkpoint — PROVES/ASSUMES/TIER, "The proof upgrades nothing"); §4
  (journaled rejections, not panics); §5.5 (no tier or basis upgrades); §6
  open question 3 (const-vs-input anchor placement, deferred to ADR-002/004).
- **docs/THREAT_MODEL.md** — §3 vendor-trust surface **watch row** verbatim:
  "if ADR-005 ever swaps the STM leg for native recursive Mithril
  certificates, the trust surface moves rather than vanishes: image ID →
  Midnight Halo2/KZG circuit VK + SRS provenance. Today that setup is
  regenerated in-function ('unsafe setup', upstream #3300) and the Midnight ZK
  library audit is in progress — the swap cannot clear the fail-closed bar
  until both are fixed and published"; A6 (image-ID supply chain — the
  fail-closed bar the VK+SRS must clear); A7 (trusted-setup provenance;
  1-of-N ceremony honesty); A11 (re-genesis anchor rotation; T-A11-2 drill);
  A12 (Sextant-inherited assumptions carried verbatim; T-A12-1 equality
  invariant).

## HANDOFF

For the next session picking up Phase 1 / entering BUILD:

- **This ADR fixes only the boundary and the swap policy.** It does not
  implement `StmWalkSource` (that is M1, HANDOFF §4 Phase 2) and does not write
  `NativeRecursiveSource` (blocked, D3).
- **Blocks / dependencies raised for other ADRs:**
  - ADR-003 (`hg-claims` codec) inherits a hard constraint from D2/Consequences:
    `avk_commitment` / `next_avk_commitment` (CLAIMS S5/S6) preimage encodings
    must be populatable *identically* from both the STM-walk AVK (Blake2b-256
    Merkle root + total stake) and the native path's Poseidon-committed Merkle
    root — i.e. the field is heliograph's own binding commitment, defined by the
    codec, not a passthrough of either proof system's internal hash. Resolve at
    ADR-003.
  - ADR-002 (recursion) and this ADR are consistent: extend-by-one (CLAIMS
    §3.2) sits above the trait; a native-recursive checkpoint is still extended
    by one certificate the same way. No conflict; note the cross-reference.
- **The native path activation is a §9 gate 2 + (likely) gate 7 event** and
  needs its own ADR-005a when upstream clears #3300 + publishes the Midnight
  audit + names an activation network. Until then the entry in
  `NativeRecursiveSource` stays `unimplemented!()`-shaped and documented, never
  a silent stub that could compile into a proof path.
- **Watch cadence:** re-pin the mithril-recursion-watch note at every
  mithril-stm bump and at each Intersect Mithril update; the trip conditions
  are #3300 closing, the Midnight audit publishing, and any
  release-preprod/mainnet activation announcement.
