# CLAIMS.md — heliograph claim schema

**Status: v0 DRAFT.** This document fixes the claim-type inventory, the journal
field sets, their semantics, and the rejection model. It does **not** fix the
canonical byte layout — that is ADR-003 (`hg-claims` codec), golden-tested and
mirrored constant-for-constant in the Solidity router. v1 freeze is a Phase-2
(BUILD) event, taken when golden encodings exist and the equality invariant runs
against them; every schema change after the v1 freeze is a breaking-change
review under HANDOFF §9 human gate 6.

Authority and sources:

- **HANDOFF.md** §0 (non-negotiables), §1 (mission), §2 (non-goals), §3
  (definition of shipped), §4 Phase 0/2/3, §5 (architecture directives), §7
  (verification doctrine). This document implements the Phase-0 deliverable
  "`CLAIMS.md` v0: every claim type as (inputs, journal fields, what is proven,
  what is assumed, tier)."
- **docs/notes/sextant-legs.md** — the authoritative claims inventory, citing
  Sextant `D:/fluxPoint/sextant` @ `3a68b2f` file:line throughout. Sextant is
  upstream; nothing here is re-derived (HANDOFF §0, §8). If Sextant cannot
  verify it, no claim type exists for it (HANDOFF §2).
- **docs/notes/lightclient-patterns.md** — journal-binding patterns from the
  audited zkVM light clients; the network-ID/claim-version lesson (Steel's
  `Commitment{id, configID}`, §2c) and the under-constrained-journal incident
  (sp1-helios PR #54, §4.1).
- **docs/notes/mithril-recursion-watch.md** — checkpoint state shape (§2, the
  upstream IVC `State`) and the re-genesis lesson (§3): both networks were
  re-genesised in February 2025; the genesis anchor is a **versioned claim
  input, never an image constant**.

---

## 1. Rules

These rules are normative for every claim type, present and future.

1. **The journal is the ABI of truth** (HANDOFF §0). Anything a verdict depends
   on MUST be bound in the guest's public output (journal) or committed via the
   image ID. An input that can change the verdict without changing the journal
   is a soundness bug of the highest severity (the sp1-helios PR #54 class:
   prover-supplied data reaching the journal without passing through
   verification).
2. **Claim identity = (image ID, journal).** The journal never contains its own
   image ID (self-reference is impossible); the image ID travels with the proof
   and is checked against the verifier's allowlist. The proof artifact format
   (HANDOFF M3) is self-contained: proof + journal + image ID + claim version.
   Inner image IDs used in composition ARE journal fields (§3.2) — an inner
   image ID that arrives as an input and is not journaled is an unbound input.
3. **Versioning.** `claim_version` is a single monotonic `u16` covering the
   entire journal schema (header + all claim bodies + verdict-code mapping +
   canonical codec). Any change to field set, field order, types, semantics,
   verdict codes, or encoding increments it. There are no minor versions.
   - `claim_version = 0` is reserved **DRAFT**: every production verifier path
     (router, SDK, CLI, in-guest composition) rejects it unconditionally.
     Pre-freeze development emits 0, so no draft-era proof can ever be accepted
     in production. The v1 freeze assigns `claim_version = 1`.
   - **Unknown-version rejection everywhere:** each verifier pins the explicit
     set of versions it accepts (normally one). Anything else — higher, lower,
     or draft — is rejected. No downgrade acceptance, no "best effort" decode
     (the Steel `validateCommitment` behavior, generalized).
4. **Fail-closed verification, extended to proofs** (HANDOFF §0). A verifier
   rejects on: unknown image ID; unknown `claim_version`; unknown `claim_type`;
   `network_id` mismatch; `genesis_vkey` mismatch against the pinned
   expectation for that network; unresolved anchor binding (§3 `anchor_mode`);
   non-allowlisted inner image ID. A proof that cannot be fully bound is a
   rejected proof.
5. **A proven verdict keeps its tier** (HANDOFF §0). Heliograph adds proven
   computation, not stronger claims. A proof of a Tier-0 `NotEstablished` read
   is Tier-0; a proof of a Tier-1 windowed verdict is Tier-1, with its
   assumptions carried verbatim into the journal. Laundering a tier through a
   proof is forbidden. Tier and basis bands are uncoercible (Sextant
   `SpendStatus`/`AnchorBasis` discipline, utxo.rs:121-191).
6. **Assumptions discipline.** Assumptions fixed by the claim type (e.g.
   header-segment's eta0 provenance) are bound by `(image ID, claim_type)` and
   documented in this file. Assumptions that vary per verification instance
   (Sextant's `WindowAssumptions`, window.rs:171-187) MUST be journal fields —
   mandatory data, not prose.
7. **Every journal field must earn a mutant** (HANDOFF §7 unbound-input zoo):
   for each field, a mutant demonstrating that mutation changes the
   journal/verdict, or a written, reviewed argument for verdict-irrelevance.
   The "why load-bearing" column in each field table below is the seed of that
   mutant. Fields that commit inputs verbatim satisfy the zoo trivially
   (input flip ⇒ journal flip); that is by design.
8. **Encoding discipline (deferred to ADR-003, constrained here).** All
   integers fixed-width (`u8/u16/u32/u64`), all hashes `[u8;32]`, no varints,
   no implicit optionality (presence flags are explicit bytes; absent fields
   are zeroed and MUST NOT be consumed). Field ORDER as listed is normative.
   One encoding per value (canonical). Recommendation to ADR-003: big-endian,
   matching Sextant's `BE64` message encodings and EVM convention — but v0
   fixes the field set and semantics, not the byte layout.

---

## 2. Common journal header

Every claim, of every type, accepted or rejected, begins with this header, in
this order. `claim_version` is first so any decoder can dispatch before
touching anything version-dependent; `claim_type` is second so a shared image
with claim dispatch is fail-closed on unknown values (the sp1-vector
precedent: proof type as the leading journal field).

| # | field | type | why it is load-bearing |
|---|-------|------|------------------------|
| H1 | `claim_version` | `u16` | Selects the schema for everything that follows. Unknown ⇒ reject everywhere (§1.3). Mutant: flip ⇒ verifier rejects. |
| H2 | `claim_type` | `u16` | Selects the body layout and semantics. Registry below; unknown ⇒ reject. Prevents a proof of one claim being consumed as another. |
| H3 | `network_id` | `u32` | Explicit network binding — the Steel `configID` lesson (lightclient-patterns §2c): continuity binding alone is insufficient for a portable verdict, which must be self-describing with no contract to supply context. Encoding: Cardano network magic (mainnet 764824073, preprod 1, preview 2 — confirm at ADR-003). Wrong network ⇒ reject. Kills cross-network replay (preprod proof against mainnet consumer) at the journal layer, in addition to the verifier-side pin. |
| H4 | `genesis_vkey` | `[u8;32]` | The pinned Mithril genesis Ed25519 vkey this claim's trust chain terminates at (Sextant mithril.rs:371-372) — **a versioned claim input, never an image constant**, because re-genesis is a real, recurring event (both networks re-genesised February 2025; mainnet Pythagoras era switch at epoch 539 + GHSA-724h-fpm5-4qvr — mithril-recursion-watch §3). One image serves all networks and all genesis eras; the verifier checks this field against its pinned expectation for `network_id`. Together `(network_id, genesis_vkey)` disambiguate network AND genesis era. For claim types with no in-guest Mithril verification (header-segment), this is the declared trust context the claim is scoped to compose with; it is still committed verbatim and still checked. |
| H5 | `verdict` | `u16` | 0 = accepted; nonzero = **journaled rejection** (§4). Codes adopt the Sextant C-ABI bands (ABI v5, ffi.rs:46) 1:1 — exact numeric table is ADR-003, golden-tested. The verdict is data, not a panic. |
| H6 | `reject_index` | `u32` | Claim-type-specific rejection detail (offending block index for header-segment, offending certificate index for checkpoint — the detail Sextant's error types already carry, ffi.rs:143). Meaningful only when `verdict != 0` and the claim type defines it; zero otherwise. Makes a rejection attributable to a specific input element. |

The header is followed by the claim body (§3). A rejection journal carries the
**full** header and all identity/anchor fields of its body (payload fields the
verification never reached are zeroed) — a rejection with no attribution is
not a verdict.

### 2.1 Claim-type registry

| `claim_type` | name | status | Sextant leg |
|---|---|---|---|
| `0x0000` | — | invalid, never emitted | — |
| `0x0001` | checkpoint | v0 | Leg 2 (`verify_chain_anchored`) |
| `0x0002` | checkpoint-extension | v0 | Leg 2 (extend-by-one, ADR-002) |
| `0x0003` | header-segment | v0 | Leg 1 (`verify_segment`) |
| `0x0004` | tx-inclusion | v0 | Leg 3 (`verify_tx_inclusion`) |
| `0x0005` | utxo-read | v0 | Leg 4 (`verify_utxo_read`) |
| `0x0006` | watched-window | **RESERVED — deferred** (§3.6) | Leg 5 (`verify_watched_window`) |
| `0x0007` | certified-set-membership | **RESERVED — deferred** (§3.7) | Leg 6 (`certified_spend_status`) |
| `0x0008` | certified-set-transition | **RESERVED — deferred** (§3.7) | Leg 6 (`apply_block` batch) |
| `0x0F00`–`0x0FFF` | benchmark-only band | **RESERVED — never production** | BENCH.md (M0 uses `0x0F01`) |

IDs are banded now, per the tier-ladder discipline: none of these are
coercible into one another, and deferred IDs are reserved so a later addition
is an extension, not a re-numbering. The `0x0F00`–`0x0FFF` band is reserved
for benchmark claim types (BENCH.md §2.3): they are emitted only under
`claim_version 0` (DRAFT — rejected by every production verifier, §1.3), so a
bench proof is doubly unacceptable in production — by version AND by type.

### 2.2 Per-claim as-of scoping

Every claim body MUST carry its as-of fields — the point on the Cardano chain
the claim speaks as of. There is no wall-clock anywhere (the guest is
clockless; Sextant is sans-io). As-of fields are the ONLY freshness data a
claim carries; recency is consumer policy (§5.1).

| claim_type | as-of fields |
|---|---|
| checkpoint | `tip_epoch`; `ctx_block_number` when `has_certified_transactions = 1` |
| checkpoint-extension | same, of the NEW state |
| header-segment | `seg_tip_slot`, `seg_tip_number` |
| tx-inclusion | `certified_epoch`, `certified_block_number` |
| utxo-read | `certified_epoch`, `certified_at_block` |

### 2.3 Anchor binding modes (shared by claim types 0x0002, 0x0004, 0x0005)

Claims that build on a prior checkpoint claim carry:

| field | type | semantics |
|---|---|---|
| `anchor_mode` | `u8` | `1` = **external**: the anchor state is a committed input; the VERIFIER must bind it to independently verified state (the router's stored checkpoint, or a CLI-verified sibling proof). `2` = **composed**: the guest verified an inner checkpoint proof in-guest (`env::verify` / `verify_sp1_proof`); the inner journal supplied the anchor state. Any other value ⇒ invalid. |
| `inner_image_id` | `[u8;32]` | Mode 2 only: the image ID of the verified inner proof, committed verbatim — the aggregation-example discipline (lightclient-patterns §3): an inner image ID that is an input MUST be journaled. Zeroed in mode 1. The top-level verifier checks the journaled ID chain against its allowlist. |

**Mode-1 anchors are claimed, not proven.** A consumer that accepts a mode-1
journal without discharging the anchor binding against separately proven state
has verified nothing about Cardano. The router does this by construction
(journal anchor fields == stored checkpoint, the SP1Tendermint/Blobstream0
pattern); the offline CLI does it by verifying the sibling checkpoint proof in
the same artifact. In mode 2 the guest MUST check that the inner journal's
header matches its own (`claim_version`, `network_id`, `genesis_vkey`) and that
the inner `claim_type` is one it accepts as an anchor — fail-closed on all
mismatches, journaled as rejections.

### 2.4 CheckpointState (shared field group)

The checkpoint and checkpoint-extension claims commit this state group — the
IVC-like per-epoch state. It deliberately mirrors the upstream Mithril
recursion prototype's IVC `State` `{counter, msg, merkle_root,
next_merkle_root, protocol_params, next_protocol_params, current_epoch}`
(mithril-stm 0.10.5 `circuits/halo2_ivc/state.rs`; mithril-recursion-watch §2),
so the ADR-005 checkpoint-source swap (proven STM walk → native recursive
certificate) changes the verification workload without changing claim
semantics.

| # | field | type | why it is load-bearing |
|---|-------|------|------------------------|
| S1 | `root_hash` | `[u8;32]` | Content hash of the genesis certificate (Sextant `compute_hash` — the canonical commitment). With `genesis_vkey` it pins WHICH chain era this checkpoint descends from; re-genesis produces a new root. Mutant: splice a different root ⇒ genesis verify fails or journal differs. |
| S2 | `tip_hash` | `[u8;32]` | Content hash of the tip certificate. Pins the entire tip content (integrity rule: recomputed content hash == committed hash, mithril.rs:288). This is the checkpoint's identity; extensions bind to it. |
| S3 | `tip_epoch` | `u64` | The tip certificate's epoch — as-of scope, and the input to the AVK-binding rule at the next extension (same-epoch vs epoch-boundary, mithril.rs:298-308). |
| S4 | `chain_length` | `u32` | Number of certificates verified in the walk from genesis inclusive (106 on both networks today, one hop per epoch). Surfaces walk depth; monotone across extensions (`+1`). Mutant: drop a certificate ⇒ linkage fails or length differs. |
| S5 | `avk_commitment` | `[u8;32]` | Binding commitment to the tip's aggregate verification key (the stake-weighted registered-signer Merkle commitment + total stake). What the next certificate's STM signature must verify under. Preimage encoding: ADR-003. |
| S6 | `next_avk_commitment` | `[u8;32]` | Binding commitment to the tip's signed `next_aggregate_verification_key` protocol-message part — what authorizes the NEXT epoch's AVK (the AVK-binding rule's cross-epoch arm). Preimage encoding: ADR-003. |
| S7 | `stm_k` | `u64` | STM quorum parameter, pinned by the tip cert hash but surfaced so consumers can apply parameter-adequacy policy (the parameters' adequacy is an external assumption — sextant-legs Leg 2). |
| S8 | `stm_m` | `u64` | STM lottery parameter, same rationale. |
| S9 | `stm_phi_f_fixed` | `u32` | `phi_f` as U8F24 fixed-point — Sextant's exact encoding (mithril.rs:892-894), no floats in the journal. Same rationale as S7. |
| S10 | `has_certified_transactions` | `u8` | `1` iff the tip certificate is a CardanoTransactions certificate and S11–S13 are populated; `0` ⇒ S11–S13 zeroed and MUST NOT be consumed. Explicit because the per-epoch hop certificate is typically MithrilStakeDistribution (mithril-recursion-watch §5); an inclusion claim can only anchor to a checkpoint with this flag = 1. Fail-closed presence, not implicit optionality. |
| S11 | `ctx_merkle_root` | `[u8;32]` | The certified transaction-set Merkle root — read from the **signed protocol-message parts only**, never from `signed_entity_type`, which is not covered by `signed_message` and could be resealed by an aggregator (mithril.rs:129-165; carried verbatim per mithril-recursion-watch §5). The anchor every tx-inclusion and utxo-read claim cites. |
| S12 | `ctx_epoch` | `u64` | Epoch of the certified transaction set (signed part). |
| S13 | `ctx_block_number` | `u64` | Block number through which the transaction set is certified (signed part). The as-of for everything downstream. |

---

## 3. Claim types

Each claim below states: INPUTS (untrusted bytes + trust anchors), JOURNAL
FIELDS (header §2 + body), PROVES, ASSUMES (surfaced verbatim from Sextant),
TIER. All Sextant citations are via docs/notes/sextant-legs.md against
`3a68b2f`.

### 3.1 `0x0001` checkpoint — Mithril STM chain to genesis

The trust terminus. Everything Mithril-anchored cites this claim.

**INPUTS.**
- Untrusted: aggregator certificate JSON, oldest-first, parsed on Sextant's own
  path (`Certificate::from_json`, mithril.rs:104). DoS caps are compiled into
  the image (`MAX_STM_BLOB_HEX` 4 MiB, `MAX_AVK_LEAVES` 2^24,
  `MAX_SINGLE_SIGS` 2^16, `MAX_LOTTERY_INDICES` 2^18; mithril.rs:530-545,
  564-610) — they bound guest cycles as well as memory.
- Trust anchor: `genesis_vkey` (header H4) — committed input, journaled,
  checked by the verifier against its per-network pin.

**JOURNAL FIELDS.** Header (§2) + `CheckpointState` (§2.4). No other body
fields. `reject_index` = offending certificate index on chain-band failures.

**PROVES.** A hash-linked, AVK-bound certificate chain from a genesis
certificate — whose recomputed content hash is `root_hash` and whose 64-byte
Ed25519 signature over the ASCII-hex `signed_message` verifies under
`genesis_vkey` on Sextant's libsodium-strict path (mithril.rs:373-378,
ed25519.rs:26) — to the tip certificate with content hash `tip_hash`, where
every link satisfies integrity (recomputed hash == committed `hash`,
mithril.rs:288), linkage (`previous_hash` == parent hash, mithril.rs:295), and
AVK binding (same-epoch AVK unchanged, or next-epoch AVK == parent's committed
`next_aggregate_verification_key`, mithril.rs:298-308); every rising
certificate carries a valid stake-threshold STM multi-signature under its own
predecessor-authorized AVK with parameters `(stm_k, stm_m, stm_phi_f_fixed)`
pinned by its content hash, degenerate thresholds refused
(`k==0 || m==0 || phi_f ∉ (0,1)`, mithril.rs:484), and chain checks run BEFORE
`verify_standard` so a parameter-weakened forgery never reaches the STM
verifier with attacker-chosen thresholds (mithril.rs:662-664). When
`has_certified_transactions = 1`, `{ctx_merkle_root, ctx_epoch,
ctx_block_number}` were read from the signed protocol-message parts of the tip
only. Nothing more: not canonicality of Cardano beyond what the Mithril stake
threshold yields, not freshness, not that this tip is THE latest tip.

**ASSUMES** (surfaced, carried verbatim from Sextant Leg 2):
- The pinned genesis key is the network's (reviewed out of band,
  mithril.rs:371-372).
- Mithril's own security assumption: the adversary is below the stake
  threshold parameterized by `k/m/phi_f`. The parameters are pinned by the
  certificate hash, but their **adequacy** is an external
  (aggregator-parameter) assumption — which is why S7–S9 are journaled.
- Unknown signed-entity/part-key tags fail closed as deserialization errors
  inside Sextant (mithril.rs:727, :846).
- A malicious prover can select a stale-but-valid chain (an old tip). The
  as-of fields make this visible; they do not prevent it (§5.1).

**TIER.** Trust terminus / building block — no spend-status tier of its own.
The proof upgrades nothing: a proven checkpoint is exactly as trustworthy as
native `verify_chain_anchored` plus the zkVM's soundness, no more.

### 3.2 `0x0002` checkpoint-extension — extend-by-one

The recursion claim (ADR-002). A state-*transition* claim, never absolute
(lightclient-patterns §1.3): it proves "new state follows from prior state,"
and the prior state's validity comes from composition or from verifier-side
chaining — the base case is its own claim type (`0x0001`), so a verifier can
never be handed an extension that anchors nowhere (lightclient-patterns §3).

**INPUTS.**
- Untrusted: exactly one new certificate JSON (v0 fixes extend-by-one; batch
  width > 1 is an open question); the prior tip certificate bytes, re-opened
  by content-hash recompute against `prev_tip_hash` where the AVK-binding
  check needs the parent's committed parts.
- Anchor: the prior checkpoint claim — per `anchor_mode` (§2.3): mode 1, prior
  `CheckpointState` as committed input bound by the verifier; mode 2, inner
  checkpoint or checkpoint-extension proof verified in-guest, inner image ID
  journaled.

**JOURNAL FIELDS.** Header (§2) + :

| # | field | type | why it is load-bearing |
|---|-------|------|------------------------|
| E1 | `anchor_mode` | `u8` | §2.3. Distinguishes claimed-anchor from composed-anchor; a consumer's obligations differ. |
| E2 | `inner_image_id` | `[u8;32]` | §2.3. Unbound inner program = unbound input. |
| E3 | `prev_tip_hash` | `[u8;32]` | Identity of the prior checkpoint this extension builds on. The router requires it == stored checkpoint `tip_hash`; the offline verifier requires it == inner journal S2. Without it the proof floats free of any base. |
| E4 | `prev_tip_epoch` | `u64` | Prior epoch — lets verifiers enforce monotonicity without reopening the previous journal. |
| E5–E17 | `CheckpointState` (new) | §2.4 | The verified successor state. `chain_length` == prev + 1; `root_hash` carried through unchanged from the prior state. |

**PROVES.** GIVEN a prior checkpoint state identified by `prev_tip_hash`
(whose validity is NOT re-proven here), the one new certificate: has integrity
(recomputed content hash == committed hash), links to the prior tip
(`previous_hash` rule — same cost within an epoch or across the boundary,
mithril-recursion-watch §3), satisfies the AVK-binding rule against the prior
tip's AVK / committed next-AVK (mithril.rs:298-308), and carries a valid STM
multi-signature under its predecessor-authorized AVK with journaled
parameters. The journal's new `CheckpointState` is the verified successor of
the prior state. In mode 2, additionally: an inner proof with journaled
`inner_image_id` was verified whose journal is a checkpoint or
checkpoint-extension claim with matching header and `tip_hash == prev_tip_hash`.

**ASSUMES.** Everything the base checkpoint claim assumes, carried verbatim —
composition does not launder assumptions (§1.5). Additionally: in mode 2, the
zkVM vendor's recursion soundness; in mode 1, the integrity of the verifier's
stored checkpoint (the router admin surface — THREAT_MODEL's
"admin-can-rewrite-history" anti-pattern, lightclient-patterns §4.4).

**TIER.** Same as checkpoint: building block, no upgrade.

### 3.3 `0x0003` header-segment — Praos opcert / VRF / KES / hash links

**INPUTS.**
- Untrusted: the ledger `[era, block]` CBOR of each block in a single-epoch
  segment; eras Babbage=6 / Conway=7 only (header.rs:26-29).
- Committed input (assumed, not verified): `eta0`, the 32-byte epoch nonce for
  the segment. It is derivable from verified headers via Sextant's nonce
  primitives (nonce.rs:28-65, proven across a real 299→300 epoch boundary),
  but THIS claim takes it as input and journals it; its provenance is the
  composer's/consumer's obligation.
- No Mithril anchor is verified in-guest; header H4 `genesis_vkey` is the
  declared trust context for composition (§2, H4 note).

**JOURNAL FIELDS.** Header (§2; `reject_index` = offending block index) + :

| # | field | type | why it is load-bearing |
|---|-------|------|------------------------|
| P1 | `eta0` | `[u8;32]` | The assumed epoch nonce, committed verbatim. Every VRF check derives from it (`alpha = Blake2b256(BE64(slot) ‖ eta0)`, vrf.rs:94-152); an unjournaled eta0 would let a prover verify against a nonce of its choosing invisibly. |
| P2 | `block_count` | `u32` | Segment length. Mutant: truncate the segment ⇒ count or tip differs. |
| P3 | `seg_first_hash` | `[u8;32]` | Blake2b-256 header hash of the first block — the segment's rear edge, what a composer splices against. |
| P4 | `seg_first_number` | `u64` | Block number of the first block. |
| P5 | `seg_tip_hash` | `[u8;32]` | Header hash of the tip block — the forward edge. |
| P6 | `seg_tip_number` | `u64` | Tip block number — as-of scope. |
| P7 | `seg_tip_slot` | `u64` | Tip slot — as-of scope. |

(Model: Sextant's `chain_status` flattening, ffi.rs:329-349, +
`SextantErrorDetail`, ffi.rs:143.)

**PROVES.** Every header in the segment decodes strictly (exact CBOR shape, no
trailing bytes, header.rs:106-120); each block's `prev_hash` equals its
predecessor's Blake2b-256 header hash (chain.rs:87-90); and each header's
authorship is valid: cold→hot Ed25519 operational certificate over
`hot_vkey ‖ BE64(seq) ‖ BE64(kes_period)` (kes.rs:71-88), leader VRF
(ECVRF-ED25519-SHA512-Elligator2 draft-03) against
`alpha = Blake2b256(BE64(slot) ‖ eta0)` (vrf.rs:94-152), and a `Sum6Kes` body
signature over the raw `header_body` bytes at the header-implied evolution
period (kes.rs:118-129). That is all a valid segment buys: correctly-authored,
hash-linked headers under the supplied nonce.

**ASSUMES** (surfaced verbatim — sextant-legs Leg 1):
- The supplied `eta0` is the true epoch nonce (provenance not checked here).
- **A verified segment is NOT proven canonical** — "that rests on the Mithril
  anchor, a surfaced assumption" (Sextant README.md:143). Canonicality comes
  only from composition with a checkpoint claim.
- Honest-majority block authorship is what a valid header buys, nothing more.
  Sextant holds no stake distribution: the VRF proof is verified, but leader
  *eligibility* against stake is not (window.rs:174-183 — a colluding
  registered producer can author valid headers).

**TIER.** Building block — no spend-status tier of its own.

### 3.4 `0x0004` tx-inclusion — membership in the certified transaction set

**INPUTS.**
- Untrusted: the aggregator's HEX(JSON) `MKMapProof<BlockRange>` (capped at
  `MAX_PROOF_HEX` 8 MiB, inclusion.rs:36; MMR size ≤ 2^40, inclusion.rs:41).
- Claim input: the 32-byte `tx_hash` (appears in the proof as lowercase-hex
  ASCII leaves, inclusion.rs:404-405).
- Anchor: `certified_root` — genesis-anchored **only** when taken from a
  checkpoint claim's `ctx_merkle_root` (a Leg-2 verified tip with
  `has_certified_transactions = 1`); bound per `anchor_mode` (§2.3).

**JOURNAL FIELDS.** Header (§2) + :

| # | field | type | why it is load-bearing |
|---|-------|------|------------------------|
| I1 | `anchor_mode` | `u8` | §2.3. |
| I2 | `inner_image_id` | `[u8;32]` | §2.3. |
| I3 | `anchor_tip_hash` | `[u8;32]` | Identity of the checkpoint claim supplying the root. Mode 2: guest-checked against the inner journal's S2 (and `certified_root` against its S11). Mode 1: the verifier MUST check both against independently verified state. |
| I4 | `certified_root` | `[u8;32]` | The root membership is proven against. Root provenance is the whole trust story of this claim (inclusion.rs assumes nothing beyond it). |
| I5 | `tx_hash` | `[u8;32]` | The fact being claimed. |
| I6 | `certified_epoch` | `u64` | As-of scope (= anchor S12). |
| I7 | `certified_block_number` | `u64` | As-of scope (= anchor S13): the set is certified through this block. |

Verdict codes: the 400-band (ffi.rs:131-133) — Ok / NotIncluded /
RootMismatch / MalformedProof — journaled, not panicked.

**PROVES.** `tx_hash` is a member of the Mithril-certified transaction set
with root `certified_root`: every sub-proof root is recomputed (BLAKE2s-256
MMR, ported with checked arithmetic from ckb-mmr, inclusion.rs:116-315) and
bound into the master tree as a `merge("start-end", sub_root)` leaf
(inclusion.rs:334-357); stated `inner_root` fields in the proof are **never
deserialized** (inclusion.rs:75-77). Membership is a **monotone "created"
predicate** trailing the chain tip by ~100 blocks (inclusion.rs:11-18) — the
transaction was included at or before `certified_block_number`. It is
explicitly NOT unspent, NOT "currently exists," NOT unique-payment semantics.

**ASSUMES.** Nothing beyond the root's provenance — which is exactly the
checkpoint claim's assumption set, carried verbatim through the anchor
binding (§1.5).

**TIER.** Building block for utxo-read (and the deferred Tier-2 legs). No
spend-status tier.

### 3.5 `0x0005` utxo-read — verified output bytes

**INPUTS.**
- Untrusted: raw Conway tx-body CBOR (`tx_bytes` — hashed in-guest to
  Blake2b-256; a provider-supplied hash is never accepted, utxo.rs:29-34,260);
  the inclusion proof hex; `out_index`.
- Anchors: `certified_root` + `block_number` from a checkpoint claim tip
  (echoed as `certified_at_block`), bound per `anchor_mode` (§2.3).

Note: the inclusion verification is internal to this claim
(`verify_utxo_read` composes it in one call, utxo.rs:253) — it is one claim,
not a composition of a tx-inclusion claim.

**JOURNAL FIELDS.** Header (§2) + (model: `SextantVerifiedOutput`,
ffi.rs:191-211):

| # | field | type | why it is load-bearing |
|---|-------|------|------------------------|
| U1 | `anchor_mode` | `u8` | §2.3. |
| U2 | `inner_image_id` | `[u8;32]` | §2.3. |
| U3 | `anchor_tip_hash` | `[u8;32]` | As I3. |
| U4 | `certified_root` | `[u8;32]` | As I4. |
| U5 | `tx_id` | `[u8;32]` | = Blake2b-256(`tx_bytes`), computed in-guest — the guest, not the prover, names the transaction. |
| U6 | `out_index` | `u16` | Which output of the transaction (matches Sextant's BE-u16 outpoint key convention). |
| U7 | `lovelace` | `u64` | The verified coin value — a fact consumers act on; must be bound or a prover could attach any value to a real outpoint. |
| U8 | `address_hash` | `[u8;32]` | Blake2b-256 over the raw address bytes (variable-length; journal commits hash + length, sextant-legs Leg 4). The raw address travels in the proof artifact; the SDK/consumer checks it against this commitment. |
| U9 | `address_len` | `u16` | Length of the raw address bytes (commitment completeness — hash alone does not pin length-extension-shaped confusion at the artifact layer). |
| U10 | `datum_kind` | `u8` | 0 = none / 1 = datum hash / 2 = inline datum (ffi model). Consumers dispatch on it; unbound kind would let a prover present an inline datum as a hash or vice versa. |
| U11 | `datum_commitment` | `[u8;32]` | Kind 1: the datum hash as on chain. Kind 2: Blake2b-256 of the inline datum bytes (raw bytes in the artifact). Kind 0: zeroed, MUST NOT be consumed. |
| U12 | `spend_status` | `u8` | **Always 0 = `NotEstablished` on this claim type** (pinned in the return type, utxo.rs:269). Journaled explicitly, not implied, so the tier band is machine-checkable: any nonzero value on claim `0x0005` is invalid ⇒ reject. Bands 2 (`SEXTANT_SPEND_CERTIFIED`) and 3+ (attested/economic, reserved) exist only in the deferred claim types (ffi.rs:58-75). |
| U13 | `certified_epoch` | `u64` | As-of scope (anchor S12). |
| U14 | `certified_at_block` | `u64` | As-of scope: the certification point the read speaks as of (anchor S13, echoed as `certified_at` — utxo.rs). |

**PROVES.** The returned `{address, lovelace, datum}` commitments are over the
authentic on-chain bytes of output `(tx_id, out_index)` of a Mithril-certified
transaction, as of `certified_at_block`: `tx_id` was recomputed in-guest from
the presented `tx_bytes`, membership of `tx_id` in the certified set with root
`certified_root` was verified by full MMR recompute, and the output fields were
decoded from those same bytes. It does **not** prove the output is unspent
(utxo.rs:8-27) — the transaction that created this output is certified to
exist; nothing is said about any later transaction spending it.

**ASSUMES.** Root provenance — the checkpoint claim's assumption set, carried
verbatim. Nothing else.

**TIER.** **Tier 0, `NotEstablished`** — and the proof does not upgrade it. A
zero-knowledge proof of a `NotEstablished` read is a `NotEstablished` read.

### 3.6 `0x0006` watched-window — RESERVED / DEFERRED

Sextant Leg 5 (`verify_watched_window`, window.rs:368): the Tier-1
`Unspent{WatchedWindow}` / `SpentObserved` / `Stalled` verdict over a
gap-free, body-committed block window bound to a Leg-2 anchor. Inventoried
here so the claim-type ID and the journal band are fixed now; **deferred
pending the v0.1 scope decision** (HANDOFF §12: claim scope is a human item;
the suggested v0.1 scope is inclusion + utxo-read).

When specified, its journal adopts `SextantWatchVerdict` (ffi.rs:884-919)
nearly verbatim: `kind`(1/2/3), `basis`(=1 `WatchedWindow`; band 1..=9
cryptographic-with-assumptions, ledger-state reserved in-band),
**`assumptions` bitset as mandatory data** (bit0 `mithril_quorum`, bit1
`data_complete` — the per-instance assumption discipline of §1.6),
`stall_reason`(1..=11), `spend_region`(1/2 — `HeaderVouched` vs
`MithrilCertified`, upgraded only by a verified inclusion proof of the
spending tx, never by height, window.rs:289-292,497-508), `anchor_height`,
`as_of_height`, `as_of_slot`, `verified_through`, `spend_at_height`,
`spend_at_slot`, `spending_txid`, **plus the inputs**: `watch{tx_id, index}`,
`eta0`, `require_through`, `freshness{slot_now, max_lag}`. The freshness pair
is caller-supplied policy data (the guest has no clock); journaling it means
the proof proves the verdict GIVEN that asserted clock — it is not a
wall-clock freshness proof (§5.1). A withheld block collapses to `Stalled`,
never to a false `Unspent`.

Tier when built: **Tier 1**, assumptions journaled, no upgrade through proving
(HANDOFF §0 names this claim explicitly as the tier-laundering example).

### 3.7 `0x0007` / `0x0008` certified-set claims (Tier 2) — RESERVED / DEFERRED

Sextant Leg 6: membership at a certified snapshot S plus a header-verified,
body-committed follow window (`ancillary::verify_ancillary_manifest` →
`setfollow::apply_block` → `UtxoSet::certified_spend_status`,
ancillary.rs:113 / setfollow.rs:64 / utxoset.rs:426). Inventoried, IDs
reserved, **deferred pending the same §12 scope decision** — and upstream the
T4/T5 seam is still the active edge (T3 bootstrap shipped; band the journal
now, build later).

- `0x0007` certified-set-membership: journal model `SextantSpendStatus`
  (ffi.rs:228-242): `tier`(0/2), `basis`(1 = `StmCertified` / 2 =
  `AncillarySigned` — **the anchor-basis distinction carried verbatim**,
  uncoercible; the ancillary path is a single pinned IOG Ed25519 key,
  ancillary.rs:32-41, dischargeable to quorum only via the extraction audit,
  Sextant docs/tier2-bootstrap.md:43-65), `mithril_quorum`(0/1 — whether
  `through_block` ≤ the Leg-2-certified frontier), `through_block`, the
  outpoint, `SnapshotAnchor{tip{number, hash}, basis}` (utxoset.rs:90), the
  certified frontier height, and the set `fingerprint` (SHA-256 over every
  outpoint `tx_id ‖ BE-u16 index` in ascending key order, utxoset.rs:386 —
  byte-identical to the ancillary `tables` key layout).
- `0x0008` certified-set-transition — the natural zkVM state-transition claim
  (sextant-legs Leg 6): `journal = {fingerprint_in, tip_in, fingerprint_out,
  tip_out, eta0(s), n_blocks}` per `apply_block` batch, with
  `certified_spend_status` a cheap membership read against the proven state.

Tier when built: **Tier 2** (`CertifiedUnspent{basis, through_block,
mithril_quorum}`) — never a false positive (`NotEstablished` otherwise,
utxoset.rs:426), never upgraded by proving, basis never coerced.

---

## 4. Rejection semantics

**Expected rejections are journaled verdicts, not panics** (HANDOFF §5). No
surveyed light client does this (they all `assert!`/panic, producing no proof
and no evidence — lightclient-patterns §4.6); heliograph builds it without
prior art because rejection evidence is a product requirement.

1. **The verdict fields.** A rejection is carried by header field H5 `verdict`
   (nonzero, Sextant-ABI-banded: 100/110/120 header-leaf codes and the
   200-band for chain errors, 300/310/320 for Mithril chain/genesis/standard,
   400-band for inclusion — ffi.rs, `SEXTANT_ABI_VERSION = 5`) plus H6
   `reject_index` where the claim type defines it (offending block /
   certificate index). Mapping rule fixed here, numeric table fixed by
   ADR-003 and golden fixtures: **one journal code per Sextant error variant,
   no lossy collapsing.**
2. **A rejection journal is a full journal.** It carries the complete common
   header and the body's identity/anchor fields (payload fields the
   verification never reached are zeroed). A rejection that cannot say what
   was rejected, on which network, against which anchor, is not a verdict.
3. **A journaled rejection proves only that the presented inputs fail
   verification.** It never proves the negation of the positive claim.
   `NotIncluded` is not a non-membership proof — a prover can always present
   a garbage proof for a transaction that IS in the set. There are no
   negative claims in this schema (§5.4).
4. **Panics are proving failures, not verdicts.** A guest panic yields no
   proof and therefore no claim — fail-closed, harming liveness only. Every
   rejection reachable from the enumerated untrusted-input space MUST take
   the journaled path; any residual panic-reachable condition requires a
   written, reviewed argument in the unbound-input zoo.
5. **Parity is CI-blocking, both ways** (HANDOFF §7). For every fixture in the
   Sextant corpus — golden AND mutant — guest verdict == native Sextant
   verdict, including the exact error variant and index. Acceptance parity
   AND rejection parity block CI equally; golden journals are byte-exact for
   accepted and rejected claims alike.
6. **Verifier-side rejections** (no proof exists, so nothing is journaled —
   the router/SDK/CLI reject the submission): unknown image ID; unknown
   `claim_version` (including DRAFT 0); unknown `claim_type`; `network_id`
   mismatch; `genesis_vkey` mismatch; mode-1 anchor binding failure; mode-2
   `inner_image_id` not allowlisted; structurally invalid journal encoding;
   any field violating its band (e.g. `spend_status != 0` on `0x0005`,
   consuming S11–S13 with `has_certified_transactions = 0`).

---

## 5. Explicit non-claims

What no journal in this schema asserts, ever. Consumers who need these
properties must obtain them elsewhere or not at all.

1. **No freshness or recency.** The guest is clockless; the chain of trust
   ends at as-of fields (§2.2). A proof over hours-old data verifies exactly
   as well as one over fresh data — the "stale-but-valid selection" adversary
   is mitigated by *visibility* (journaled as-of), not prevention. Recency is
   **consumer policy over journaled as-of data**, and the consumer's recency
   obligation is a documented integration requirement, not a default
   (lightclient-patterns §2d: trusting-period checks against
   prover-adjacent timestamps are freshness theater; no in-proof freshness
   exists anywhere in the surveyed corpus, and heliograph does not pretend
   otherwise).
2. **No unspent claims from the single-tx path.** tx-inclusion (`0x0004`) is a
   monotone created-predicate; utxo-read (`0x0005`) journals
   `spend_status = NotEstablished` unconditionally. Treating a utxo-read as
   "spendable now" is a consumer bug, not a heliograph claim. Unspent-ness
   enters only through the deferred Tier-1/Tier-2 claim types, with their
   assumptions journaled as data.
3. **No canonicality without the Mithril anchor.** A header-segment claim
   proves correctly-authored, hash-linked headers under an assumed `eta0` —
   not that those headers are the canonical chain, and not that their
   authors were stake-eligible leaders (Sextant holds no stake
   distribution). Canonicality is obtained solely by composition against a
   checkpoint claim.
4. **No negative claims.** No non-membership, no non-existence, no "this
   transaction never happened." Journaled rejections prove input failure
   only (§4.3).
5. **No tier or basis upgrades.** Proving preserves tier (§1.5);
   `StmCertified` and `AncillarySigned` are distinct, uncoercible trust
   classes carried verbatim from Sextant; no code path converts one to the
   other (discharge is an out-of-band audit event, not a claim transform).
6. **No liveness.** A prover (or its data sources) can withhold inputs;
   withheld data means no proof, and in the deferred window claims a
   withheld block means `Stalled`, never a false `Unspent`. Heliograph
   proofs are permissionlessly verifiable, not guaranteed to exist.
7. **No semantics beyond Sextant** (HANDOFF §2). Claim types exist only for
   what the pinned Sextant commit verifies. If Sextant cannot verify it,
   heliograph cannot prove it — new claim semantics require new upstream
   verification first.

---

## 6. Open questions (tracked for humans / later ADRs)

1. v0.1 claim scope (HANDOFF §12): inclusion-only vs inclusion + utxo-read;
   whether `0x0006`–`0x0008` stay deferred. Recommendation: ship `0x0001`
   through `0x0005`, keep `0x0006`–`0x0008` reserved.
2. Canonical codec (ADR-003): endianness, framing, golden vectors.
   Recommendation: big-endian, flat fixed-width layout.
3. Genesis-anchor placement ratification (ADR-002/ADR-004): this v0 commits
   to input-and-journaled (H4) with a verifier-side pin, per the re-genesis
   lesson; the guest-const alternative is recorded as rejected pending ADR.
4. Shared image with claim dispatch vs image-per-leg (ADR-003/ADR-004): this
   header supports both (`claim_type` is field 2 regardless).
5. `network_id` encoding: Cardano network magic `u32` vs config-digest
   (Steel-style). Recommendation: network magic; confirm at ADR-003.
6. Verdict-code numeric table: adopt Sextant ABI v5 band values verbatim;
   fix at ADR-003 with golden fixtures.
7. checkpoint-extension batch width: v0 fixes extend-by-one; batching is an
   ADR-002 economics question after M0 numbers.
