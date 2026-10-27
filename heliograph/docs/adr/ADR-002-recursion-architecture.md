# ADR-002 Recursion architecture

- **Status:** Accepted (2026-07-14). One decision item — the in-guest
  composition primitive on the RISC Zero path (D3) — is **provisional pending
  the M1 self-recursion spike** (HANDOFF Phase 2 M1; docs/notes/risc0.md §6, §7.4).
  The architecture below holds under either M1 outcome; only the guest wiring of
  the `0x0002` composed path (`anchor_mode = 2`) is spike-gated, and its fallback
  is recorded in §Consequences and §Alternatives.
- **Deciders:** sole senior engineer (HANDOFF §0), under the SIGNED §12
  thresholds (STATUS.md: `MAX_PROOF_TIME ≤ 10 min/update`,
  `MAX_PROOF_COST ≤ $1/update`, `BENCH_HARDWARE = AWS g6e.xlarge`,
  claim scope `0x0001`–`0x0005`).
- **Supersedes / relates:** implements HANDOFF §4 Phase-1 ADR-002; consumes
  ADR-001 (zkVM selection — SKELETON, §9-gate-2 human sign-off pending M0);
  hands the journal-field and inner-image-ID encoding to ADR-003; hands the
  reproducible image-ID trust anchor to ADR-004; leaves the checkpoint-source
  workload swap to ADR-005. Vendor-neutral: the decision is expressed once and
  instantiated per vendor, so ADR-001 does not reopen it.

---

## Context

### The problem, priced

Heliograph's trust terminus is the Mithril STM certificate chain from the
pinned genesis vkey to the tip (CLAIMS.md §3.1 `0x0001`; sextant-legs Leg 2).
Re-proving that whole chain on every update is the cost we must avoid:

- The mainnet chain is **106 certificates (105 hops), one hop per epoch**, and
  was 106 deep because both networks were **re-genesised in February 2025**
  (docs/notes/mithril-recursion-watch.md §3). A full from-genesis re-verify is
  `1 Ed25519 + 105 STM verifies ≈ 105 pairing checks + 210 MSMs + ~256k lottery
  evaluations + ~13.2 MB guest input` (mithril-recursion-watch §3, "The numbers
  ADR-002 rests on").
- **Extend-by-one is one STM verify**: `hash/link/AVK-bind + 1 STM verify ≈ 1
  pairing check + 2 MSMs + ~2.4k lottery evals + ~126 KB input` — the same cost
  whether advancing the tip within an epoch or crossing an epoch boundary
  (mithril-recursion-watch §3).
- **Amortization ≈ 105× today, growing ~73/year** until the next re-genesis
  resets it. At plausible zkVM costs the full walk is minutes-to-hours while
  extend-by-one is the `MAX_PROOF_TIME`-shaped unit the M0 bakeoff prices
  (mithril-recursion-watch §3). Recursion is **not optional at mainnet scale**.

There is also no BLS12-381 pairing precompile on either vendor (only G1/Fp/Fp2
ops; docs/notes/sp1.md §2, docs/notes/risc0.md §2), so each STM verify is
expensive in-guest and the "prove once, extend by one" shape is what keeps a
checkpoint update inside the signed thresholds.

### What HANDOFF §4 directed, and what the recon found

HANDOFF ADR-002 says: *"prove the certificate chain once from the pinned genesis
vkey → cache the proven checkpoint → each update proves exactly one new
certificate against the prior proof (composition). Header and inclusion claims
compose the latest checkpoint proof rather than re-proving the chain."*

The light-client survey qualifies "compose" with a load-bearing finding
(docs/notes/lightclient-patterns.md §3): **no production light client re-proves
from genesis, and none extends a prior *proof* in-guest for its update loop —
all extend prior proven *state* via contract-side chaining.** In-guest
composition (`verify_sp1_proof` / `env::verify`) exists as a vendor primitive
but is used for **aggregation, not the LC extension loop** (lightclient-patterns
§3). This is a divergence to reconcile, not ignore: HANDOFF says "against the
prior proof (composition)"; the battle-tested pattern is "against the prior
*checkpoint state* the contract stored."

The reconciliation is that heliograph has **two consumers with different trust
substrates** (lightclient-patterns §3, "Split by consumer"), and each wants a
different chaining mechanism:

1. **On-chain (the router):** a contract already stores the latest proven
   checkpoint. Chaining the new certificate against *stored state* (journal
   `prev_tip_hash == stored checkpoint tip_hash` + strict `chain_length`+1) is the
   SP1Tendermint / Blobstream0 / SP1Helios pattern (lightclient-patterns §1.4,
   §2b) — no recursion machinery, each proof small because the Mithril chain's
   own structure (cert N signs the AVK committed by cert N−1) plays the role
   Tendermint's validator-set continuity plays (lightclient-patterns §1
   "Mapping").

2. **Offline / portable verdict, and cross-leg composition:** there is **no
   contract to hold the checkpoint**. The extension guest must verify the prior
   checkpoint *proof* in-guest (`env::verify` / `verify_sp1_proof`), and the
   header/inclusion guests must compose the latest checkpoint proof instead of
   re-running the STM walk (lightclient-patterns §3, item 2).

Both are needed. The flagship `checkpoint-update/` and `portable-verdict/`
demos (HANDOFF §1) require the offline path; the `evm-oracle/` demo and the M4
router require the on-chain path. CLAIMS.md already anticipated this with the
**anchor-binding modes** (§2.3): `anchor_mode = 1` external (verifier binds the
anchor to independently verified state) and `anchor_mode = 2` composed (the
guest verified an inner proof, inner image ID journaled). This ADR ratifies that
those two modes are exactly the two chaining mechanisms, not two encodings of one.

### The two soundness hazards this design must close

- **A3 cross-image replay** (THREAT_MODEL A3): a proof from a *different* guest
  program presented to the verifier. For recursion this sharpens: the inner
  proof's image ID is an *input* to the composing guest, and *an unjournaled
  inner ID is an unbound input* (THREAT_MODEL A3 mitigations; CLAIMS §1.2, §2.3;
  lightclient-patterns §3 "an inner image ID that is an input MUST be
  journaled"). A guest cannot contain its own image ID as a const (hash cycle),
  so self-recursion **forces** the inner ID onto the input+journal path.
- **A10 malicious-prover input selection** (THREAT_MODEL A10): all inputs
  authentic, every proof valid, but the prover *selects* an old checkpoint
  (regression) or a minority fork. The on-chain defense is the router accepting
  extensions only (`journal.prev_checkpoint == stored checkpoint` + strict
  `chain_length`+1 progress; THREAT_MODEL A10 mitigations, lightclient-patterns
  §1.4). Off-chain,
  the journal's anchor fields are the only defense and the consumer must check
  them (THREAT_MODEL A10 residual risk).

### Vendor-primitive reality (constrains the composed path)

- **SP1:** `verify_sp1_proof(vkey_digest, public_values_digest)` verifies an
  inner proof in-guest; **only *compressed* SP1 proofs can be aggregated**
  (docs/notes/sp1.md §6). So the cached checkpoint is a *compressed* proof; the
  Groth16/PLONK wrap happens only at the EVM edge. The inner vkey digest cannot
  be a compile-time constant under self-recursion — it is an input committed to
  the journal (sp1.md §6, "Extend-by-one-certificate loop is feasible as
  specified").
- **RISC Zero:** `env::verify(image_id, journal)` adds an *assumption* to the
  ReceiptClaim (a conditional receipt), discharged in the recursion circuit
  during `Succinct`/`Groth16` proving — **in-guest receipt verification costs
  ~zero guest cycles** (docs/notes/risc0.md §6). But the **self-recursion
  inner-ID pattern (a checkpoint guest verifying a prior receipt of *itself*) is
  vendor-undocumented** (risc0.md §6, §7.4 open item 4) — it is an **M1 spike
  item before this ADR's composed-path wording freezes.** The vendor-documented
  fallback that avoids self-reference entirely is a **fixed-depth pair of guests
  (step guest + aggregator guest), at the cost of two image IDs** in the trust
  anchor set (risc0.md §6).

---

## Decision

Heliograph adopts a **three-layer hybrid recursion architecture**. The base
case is its own claim type; extension is done by *two* mechanisms selected by
`anchor_mode`; the router chains checkpoints contract-side; and the header and
inclusion legs compose the latest checkpoint proof rather than re-proving the
chain.

### D1 — The base case is `0x0001`, a distinct claim type (never an extension)

`0x0001` checkpoint proves the genesis→tip STM walk from the pinned
`genesis_vkey` with **no inner proof** (CLAIMS §3.1). It is proved once per
chain era and cached as the checkpoint proof. Because the base case is a
*separate* claim type from the extension (`0x0002`), a verifier can never be
handed an "extension" that anchors nowhere — the genesis base case is
structurally distinguished from a step, which is the exact discipline
lightclient-patterns §3 ("Genesis base case") requires and CLAIMS §3.2 already
encodes ("the base case is its own claim type … so a verifier can never be
handed an extension that anchors nowhere"). Re-proving the full walk happens
**only** on: first bring-up of a network, a re-genesis (A11 anchor rotation), or
a checkpoint-source swap (ADR-005).

### D2 — `0x0002` checkpoint-extension folds *exactly one* new certificate, in one of two anchor modes

`0x0002` is a state-*transition* claim: "the one new certificate is the verified
successor of the prior checkpoint state" (CLAIMS §3.2). v0 fixes **extend-by-one**
(batch width > 1 is deferred to §Open Questions and CLAIMS §6.7). The prior
state's validity is supplied by one of the two `anchor_mode` values (CLAIMS §2.3),
**both of which must exist** because heliograph serves both an on-chain and an
offline consumer:

- **`anchor_mode = 1` (external / claimed):** the prior `CheckpointState` is a
  committed input, journaled but **not re-proven in-guest**; the *verifier* binds
  it to independently verified state. This is the mechanism the router uses (D4).
  Mode-1 anchors are *claimed, not proven* — a consumer that accepts a mode-1
  journal without discharging the anchor binding against separately proven state
  has verified nothing (CLAIMS §2.3). Its residual trust is the integrity of the
  verifier's stored checkpoint (THREAT_MODEL A10; the router admin surface,
  A8 — see D4).

- **`anchor_mode = 2` (composed / proven):** the guest verifies an **inner
  checkpoint or checkpoint-extension proof in-guest** (`env::verify` /
  `verify_sp1_proof`), and the inner journal supplies the prior state. This is
  the mechanism the offline/portable path uses (D3). The inner `image_id` is an
  **input, committed verbatim to the journal** (`E2 inner_image_id`; CLAIMS §2.3,
  §3.2) — the A3 cross-image-replay defense. The guest MUST additionally check,
  fail-closed and journaled as a rejection, that (i) the inner journal's header
  matches its own (`claim_version`, `network_id`, `genesis_vkey`); (ii) the inner
  `claim_type` is one it accepts as an anchor (`0x0001` or `0x0002`); (iii) the
  inner journal's `tip_hash` (S2) equals this extension's `prev_tip_hash` (E3)
  (CLAIMS §2.3, §3.2 PROVES). This is the aggregation-example discipline: child
  image IDs arrive as inputs and are committed into the journal so the outer
  verifier learns exactly which programs were composed (lightclient-patterns §3).

Composition **does not launder assumptions**: `0x0002` carries verbatim every
assumption of the base checkpoint claim, plus (mode 2) the zkVM vendor's
recursion soundness, or (mode 1) the integrity of the verifier's stored
checkpoint (CLAIMS §1.5, §3.2 ASSUMES; HANDOFF §0 "a proven verdict keeps its
tier").

### D3 — The composed path (`anchor_mode = 2`) uses the vendor in-guest verify primitive; self-recursion is an M1 spike gate

The offline extend-by-one loop is: guest N+1 takes `(prior checkpoint proof,
certificate N+1, inner_image_id)`, verifies the inner proof in-guest, verifies
the one new certificate natively (Sextant `verify_chain` link + AVK-bind + one
`verify_standard` STM check; sextant-legs Leg 2), and commits journal N+1 with
`inner_image_id` and the new `CheckpointState`.

- **SP1 instantiation:** `verify_sp1_proof(inner_vkey_digest,
  inner_pv_digest)`; the cached checkpoint proof is a **compressed** SP1 proof
  (sp1.md §6). The inner vkey digest is the journaled `inner_image_id`
  (ADR-003 fixes the digest encoding).
- **RISC Zero instantiation:** `env::verify(inner_image_id, inner_journal)`
  adds an assumption discharged in the recursion circuit (risc0.md §6).

**Spike gate (M1, before this sub-decision freezes; HANDOFF Phase 2 M1,
risc0.md §7.4 open item 4):** the RISC Zero *self*-recursion inner-ID pattern is
vendor-undocumented. M1 MUST prove a minimal two-step chain (base `0x0001` proof
→ one `0x0002` extension verifying it in-guest → a second `0x0002` extension
verifying *that*) with the inner ID as input+journal on the selected vendor
before the composed-path wording is treated as final. **Fallback if the spike
fails or is uneconomic:** factor the composed path into a **fixed-depth pair of
guests — a step guest and an aggregator guest — avoiding self-reference at the
cost of two image IDs** in the trust anchor set (risc0.md §6; the two-program
factoring precedent is sp1-vector's `HeaderRangeProof`/`RotateProof` and
argumentcomputer's `epoch_change`/`inclusion` split, lightclient-patterns §3).
Either outcome leaves D1/D2/D4/D5 and the journal ABI unchanged — only the guest
image count and the wiring of `anchor_mode = 2` differ, and CLAIMS §2.3 already
journals an arbitrary `inner_image_id`, so the fallback is not a schema change.

**The offline verifier (CLI) enforces the same fail-closed chain the router
does:** it walks the journaled `inner_image_id` chain against its allowlist,
checks each `prev_tip_hash` link, and rejects an unknown inner image ID,
unknown version, wrong network, or genesis-vkey mismatch (CLAIMS §4.6;
THREAT_MODEL A2/A3 cross-layer-agreement obligation T-A2-3 / T-A3-2).

### D4 — The router chains checkpoints CONTRACT-SIDE (the A10 defense)

On-chain, the router stores the latest proven checkpoint and **accepts
extensions only**, exactly like every surveyed production LC
(lightclient-patterns §1.4, §2b):

- It accepts a `0x0002` proof in `anchor_mode = 1` and requires
  `journal.prev_tip_hash (E3) == stored checkpoint tip_hash` **plus strict
  `chain_length`+1 progress** (`chain_length == stored + 1`; CLAIMS §3.2, E5-E17),
  which is strictly monotone by construction for BOTH extension shapes, **plus a
  NON-DECREASING `tip_epoch`** (same-epoch extensions keep the epoch constant —
  the dominant case, ~765 intra-epoch certs per boundary crossing,
  mithril-recursion-watch §3; only a strictly decreasing epoch is a regression).
  A checkpoint has no `slot` field (CLAIMS §2.4), so there is no slot rule.
  An old-checkpoint regression (extend checkpoint N−k against a router at N) is
  structurally rejected — the A10 defense (THREAT_MODEL A10 mitigations;
  T-A10-1). This is the mode-1 anchor discharge "by construction" (CLAIMS §2.3).
- It also accepts a base `0x0001` proof to install/rotate the checkpoint (first
  bring-up, re-genesis cutover) under the timelocked registry (A11; D4 admin
  surface below).
- **No admin action may affect an already-proven checkpoint.** The router
  exposes **no** `adminSetTrustedState`-equivalent — the Blobstream0 anti-pattern
  named in THREAT_MODEL A8 and lightclient-patterns §2b/§4.4. Its only admin
  surface is the timelocked allowed-image-ID / trust-anchor registry (HANDOFF §1;
  THREAT_MODEL A8; key custody is §9-gate-3). Pinned by T-A8-1 (no-state-rewrite
  ABI surface).
- **Anti-griefing is mandatory, not optional.** Permissionless submission
  (A9) + extension-only chaining (A10) is the exact Blobstream0 shape whose
  only High audit finding was a valid-proof front-run that stalls progress; with
  heliograph's worse cost asymmetry (a lost race discards a minutes-long proof)
  the **minimum-progress rule is mandatory** and its parameter is sized against
  measured proving latency and recorded in the verifier-contract ADR
  (THREAT_MODEL A13; lightclient-patterns §4.3/§6.5; T-A13-1). This ADR fixes
  *that* the router carries a minimum-progress rule; the numeric parameter is a
  post-M0 value owned by the router-contract design (HANDOFF §4 Phase-1
  "Verifier contract design").

The router's image ID for the verify call comes from its timelocked
allowed-image-ID registry (fail-closed on unknown IDs; THREAT_MODEL A3, A8;
lightclient-patterns §2c). Both vendors bind the image ID *into* the verify —
`verifyProof(programVKey, …)` (sp1.md §4) and `verify(seal, imageId,
journalDigest)` with RISC Zero reconstructing the claim digest from the image ID
(risc0.md §4) — so a foreign-image proof simply fails verification (T-A3-1).

### D5 — Header-segment (`0x0003`) and tx-inclusion (`0x0004`) COMPOSE the latest checkpoint proof, never re-prove the chain

The chain-anchored legs do not re-run the STM walk:

- **`0x0004` tx-inclusion** anchors its `certified_root` to a checkpoint claim's
  `ctx_merkle_root` (a Leg-2 tip with `has_certified_transactions = 1`), bound
  per `anchor_mode` (CLAIMS §3.4): mode 2 verifies the inner checkpoint proof
  in-guest and checks `anchor_tip_hash (I3) == inner S2` and `certified_root (I4)
  == inner S11`; mode 1 hands both checks to the verifier against independently
  verified state. This is the same composition primitive as D3, anchoring onto a
  checkpoint rather than a prior extension.
- **`0x0003` header-segment** verifies no Mithril anchor in-guest; its
  `genesis_vkey` (H4) is the *declared trust context* it is scoped to compose
  with (CLAIMS §2 H4, §3.3). A header segment is **not proven canonical** — that
  rests on the Mithril anchor, a surfaced assumption (CLAIMS §3.3 ASSUMES;
  sextant-legs Leg 1) — so its composition with a checkpoint is what a consumer
  needs for canonicality, and the journal says so. In v0.1 scope the header
  segment's `eta0` is a committed input (P1), not derived from a checkpoint
  in-guest; deriving it is future work (CLAIMS §3.3).
- **`0x0005` utxo-read** composes inclusion *internally* in one call
  (`verify_utxo_read`; CLAIMS §3.5) and anchors to a checkpoint the same way as
  `0x0004` — one claim, not a composition of a `0x0004` claim.

In every case, "compose the latest checkpoint proof" is realized by the
`anchor_mode` machinery (mode 2 in-guest verify with journaled `inner_image_id`,
or mode 1 verifier-side binding), reusing D2/D3 rather than inventing a second
recursion mechanism.

### D6 — The recursion mechanism is invariant under ADR-005

The cached checkpoint proof is the boundary. If ADR-005 swaps the proven-STM
walk for a native recursive Mithril certificate, the guest verifies **one
Halo2/KZG proof** whose public state binds `(epoch, AVK root, next-AVK root,
params, msg)` — the same `CheckpointState` the journal already carries
(CLAIMS §2.4; mithril-recursion-watch §2, §4). D2/D4/D5 are unchanged: only the
*workload inside the base/extension guest* changes, and the trust surface moves
(image ID → circuit VK + SRS provenance), it does not vanish
(mithril-recursion-watch §4; THREAT_MODEL §3 watch row). The `CheckpointState`
group was deliberately shaped to mirror the upstream IVC `State` for exactly this
reason (CLAIMS §2.4). **Do not block v0.1 on the native track** — primitives are
done and running on an internal test network, but productization gates (unsafe-
setup refactor #3300, Midnight ZK audit, era switch/re-genesis) remain and there
is no public activation date (mithril-recursion-watch §2, §5).

---

## Consequences

### Positive

- **Amortized cost meets the thresholds by construction.** Each update is one
  STM verify against a cached proof, not 105 — the ≈105× amortization
  (mithril-recursion-watch §3) is what puts a checkpoint update inside the
  SIGNED `MAX_PROOF_TIME ≤ 10 min` / `MAX_PROOF_COST ≤ $1` (STATUS.md §12);
  M0/M1 measure the actual number and ADR-001's go/no-go is against it.
- **The on-chain path uses zero unproven recursion machinery.** Contract-side
  chaining (D4) is the SP1Tendermint/Blobstream0/SP1Helios pattern with a large
  production track record (lightclient-patterns §1.4). The router never depends
  on the vendor-undocumented self-recursion primitive.
- **A3 is closed on the recursion path.** The inner image ID is always an
  input+journal field (`E2`/`I2`/`U2`), never a silent input; the router, SDK,
  and CLI all check the journaled ID chain against the allowlist (T-A3-2,
  cross-layer). Self-reference is impossible-by-design and handled the only sound
  way (lightclient-patterns §3; sp1.md §6; risc0.md §6).
- **A10 regression is structurally rejected on-chain** (extension-only +
  monotonic; T-A10-1) and **legible off-chain** (journaled anchor fields;
  T-A10-2, T-A10-3).
- **ADR-005 is a drop-in** (D6): the native recursive certificate changes the
  workload, not the claim semantics or the chaining.

### Negative / costs

- **Two anchor mechanisms to build, test, and document** (mode 1 + mode 2).
  Mitigation: they are one `u8` discriminant in a shared schema (CLAIMS §2.3),
  and both are pinned by the zoo (`E1`/`I1`/`U1` mutants) and cross-layer
  agreement tests; the router only ever uses mode 1, the offline path only ever
  uses mode 2, so each *consumer* sees one mechanism.
- **The composed path carries an M1 open risk on RISC Zero** (self-recursion
  undocumented; risc0.md §7.4). Mitigation: the spike gate (D3) with a
  vendor-documented two-guest fallback that costs one extra image ID and no
  schema change; and the whole *offline* path is not on the v0.1 critical path
  for the on-chain oracle (the router uses mode 1). If M1 shows self-recursion is
  unavailable/uneconomic on the selected vendor, `checkpoint-update/` and
  `portable-verdict/` demos use the two-guest factoring; the `evm-oracle/` demo
  is unaffected.
- **The compressed-proof constraint (SP1) fixes the cache format**: the cached
  checkpoint is a compressed SP1 proof, wrapped to Groth16/PLONK only at the EVM
  edge (sp1.md §6). This is an artifact-format constraint for M3 (proof artifact
  = proof + journal + image ID + claim version; HANDOFF M3), not a soundness
  cost.
- **Mainnet fixtures are mandatory for cost claims.** Preprod is ~20× cheaper
  per certificate and *wrong for cost extrapolation* (k=5 vs k=1,944 changes
  lottery-eval count 200–400×); M0/M1 MUST bench a mainnet-read-only fixture
  (mithril-recursion-watch §3; THREAT_MODEL A12 T-A12-3).

### Neutral / follow-through obligations

- **Off-chain consumers must check the journaled anchor fields themselves** —
  they have no stored checkpoint; the journal is their only defense against A5
  staleness and A10 selection (THREAT_MODEL A5/A10 residual risk). This is the
  single largest documentation obligation ("What a proof proves, precisely",
  HANDOFF Phase 4).
- **Re-genesis triggers a base-case re-prove** (D1) and a governed anchor
  rotation (A11; T-A11-2 drill). The genesis vkey is a versioned journal field,
  never an image constant (CLAIMS §2 H4; mithril-recursion-watch §3) — so one
  image serves all eras and rotation is registry governance, not an image bump.
- **The minimum-progress numeric parameter** and the router storage shape
  (latest-only vs history vs append-only nonce ledger; lightclient-patterns §2b,
  §6.4) are owned by the verifier-contract design (HANDOFF §4 Phase-1), sized
  after M0 latency numbers.

---

## Alternatives considered

1. **Re-prove the whole chain every update (no recursion).** Rejected on cost:
   105 STM verifies + 13.2 MB input per update is minutes-to-hours of proving,
   blowing `MAX_PROOF_TIME` by orders of magnitude (mithril-recursion-watch §3).
   HANDOFF §4 already directs against it.

2. **In-guest composition for the on-chain loop too (extend the prior *proof*
   in-guest, then submit to the router).** Rejected: no production LC does this
   for its update loop (lightclient-patterns §3), it puts the
   vendor-undocumented self-recursion primitive (risc0.md §7.4) on the critical
   on-chain path, and it is strictly more expensive than contract-side chaining
   for the same guarantee — the router already stores the checkpoint, so binding
   to stored state (mode 1) is free where re-verifying the inner proof is not.
   Kept for the offline path *only*, where there is no contract (D3).

3. **Contract-side chaining for the offline path too (no in-guest composition
   at all).** Rejected: impossible — there is no contract off-chain, so a
   portable verdict extending a checkpoint has nothing to bind its mode-1 anchor
   against. The offline path *requires* mode 2 (D3); this is why both modes
   exist.

4. **Bake the genesis anchor into the guest as a const (image-ID-as-network-
   binding).** Rejected here and recorded as the rejected option per CLAIMS §6.3
   and lightclient-patterns §2a/§6.1: re-genesis is real and recurring
   (Feb 2025, both networks; mithril-recursion-watch §3), so a guest-const anchor
   would rotate the image ID per network *and* per genesis era — a trust-anchor
   rotation on every re-genesis instead of a governed registry update. The
   journaled-field + registry-pin design (H4) lets one image serve all networks
   and eras; the const alternative is strictly more operational churn for no
   soundness gain (both are fail-closed). Final placement is ratified jointly
   with ADR-004.

5. **Batch width > 1 for `0x0002` (fold K certificates per proof).** Deferred,
   not rejected: v0 fixes extend-by-one (CLAIMS §3.2, §6.7). Batching is an
   economics question to settle with M0 numbers (is one K-cert proof cheaper
   than K one-cert proofs, given per-composition overhead? sp1.md §6 notes
   aggregation "adds some small overhead"). It changes no claim semantics — the
   journal's `chain_length` already tracks depth — so it is a post-M0 extension.

6. **Two-guest fixed-depth factoring (step + aggregator) as the *primary*
   composed-path design.** Held as the **fallback** (D3), not the default:
   it costs a second image ID in the trust anchor set (risc0.md §6) and a second
   reproducible-build/registry entry, which is real trust-surface and ADR-004
   overhead. Chosen only if the M1 self-recursion spike fails or is uneconomic on
   the selected vendor. Recording it now means the M1 outcome is a wiring choice,
   not a re-architecture.

---

## Citations (load-bearing)

- **HANDOFF.md** §0 (non-negotiables, precedence, "a proven verdict keeps its
  tier"), §1 (mission, flagship demos), §4 Phase-1 ADR-002 directive + Phase-2
  M0/M1 gates, §5 (architecture directives, `/docs/adr/`), §9 (human gates 2/3).
- **docs/CLAIMS.md** §1.2/§1.5 (claim identity, no assumption laundering),
  §2 H4 (genesis vkey as versioned field), §2.3 (anchor-binding modes 1/2 —
  the load-bearing reconciliation), §2.4 (`CheckpointState`, IVC-mirror),
  §3.1 `0x0001`, §3.2 `0x0002` (extend-by-one, PROVES/ASSUMES), §3.3 `0x0003`,
  §3.4 `0x0004`, §3.5 `0x0005`, §4.6 (verifier-side rejections), §6.3/§6.7
  (rejected guest-const option, batch-width open question).
- **docs/THREAT_MODEL.md** A3 (cross-image replay; inner-ID-must-be-journaled),
  A10 (input selection; extension-only + monotonic router), A8 (admin surface;
  no state-rewrite), A9 (permissionless liveness), A11 (re-genesis rotation),
  A13 (mandatory minimum-progress + front-run race); tests T-A3-1/2,
  T-A10-1/2/3, T-A8-1, T-A11-2, T-A13-1.
- **docs/notes/lightclient-patterns.md** §1 (the five-stage pipeline + heliograph
  mapping), §1.4/§2b (extension-only contract-side chaining, admin ladder),
  §2a/§6.1 (anchor placement), §2c (Steel network-ID + unknown-version reject),
  §3 (in-guest composition = aggregation not LC-extension; inner-ID journaling;
  genesis base case is its own claim type; two-program factoring precedent),
  §4.3/§6.5 (minimum-progress), §4.4 (`adminSetTrustedState` anti-pattern).
- **docs/notes/mithril-recursion-watch.md** §2 (upstream halo2_ivc `State`;
  native recursive certificate), §3 (106 certs / 105 hops, extend-by-one = 1 STM
  verify, ≈105× amortization, re-genesis rotates the anchor, mainnet-fixture
  requirement), §4/§5 (ADR-005 boundary; no public activation date).
- **docs/notes/sp1.md** §2 (no BLS12-381 pairing precompile), §4 (image-ID-bound
  verify, gateway admin), §6 (`verify_sp1_proof`, compressed-only aggregation,
  self-recursion inner-vkey-as-input).
- **docs/notes/risc0.md** §2 (no pairing/G2 precompile), §4 (image ID bound into
  reconstructed claim digest; router timelock + emergency stop), §6 (`env::verify`
  ~zero-cycle composition; self-recursion undocumented → M1 spike; two-guest
  fallback), §7.4 (self-recursion open item).
- **docs/notes/sextant-legs.md** Leg 1 (header segment / eta0 / not-canonical),
  Leg 2 (`verify_chain_anchored`, genesis Ed25519, STM verify, signed-parts
  rule), Leg 3 (inclusion / MMR), Leg 4 (utxo-read / `NotEstablished`).

---

## HANDOFF — for the next session

- **State:** ADR-002 Accepted; D3 composed-path guest wiring on the selected
  vendor is **provisional pending the M1 self-recursion spike**. No code exists
  yet — this is a Phase-1 design artifact.
- **The M1 spike is the one gating unknown** (HANDOFF Phase 2 M1; risc0.md §7.4):
  prove a minimal 3-proof chain (`0x0001` base → `0x0002` → `0x0002`) with the
  inner image ID as an input committed to the journal, on the ADR-001-selected
  vendor. Success → D3 wording is final. Failure/uneconomic → switch the composed
  path to the two-guest (step + aggregator) factoring (Alternative 6); this is a
  wiring change, not a schema change (CLAIMS §2.3 already journals an arbitrary
  `inner_image_id`).
- **Depends on ADR-001** (zkVM selection, §9-gate-2, awaits M0 numbers) for which
  vendor's primitive (`verify_sp1_proof` compressed vs `env::verify` assumption)
  D3 instantiates. The architecture is vendor-neutral; only the instantiation
  waits.
- **Hands to ADR-003:** the byte encoding of `inner_image_id`, `anchor_mode`,
  `prev_tip_hash`, and the full `CheckpointState` group; the inner-ID digest
  form (SP1 vkey digest vs RISC Zero image ID).
- **Hands to ADR-004:** the reproducible image-ID recipe (the trust anchor the
  journaled `inner_image_id` is checked against) and, if Alternative 6 is taken,
  the *second* image ID (aggregator guest).
- **Hands to the verifier-contract design** (HANDOFF §4 Phase-1): the
  minimum-progress numeric parameter (post-M0 latency), the router storage shape,
  and whether to adopt the RISC Zero permissionless emergency-stop pattern
  (risc0.md §4; THREAT_MODEL A8 open design question).
- **Do not block on ADR-005** (native recursive certificates): the trait boundary
  is D6; v0.1 ships the proven-STM-walk checkpoint source.
