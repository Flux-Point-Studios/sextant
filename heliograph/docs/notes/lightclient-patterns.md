# ZK light-client architecture patterns

Phase-0 recon note. Sources are vendor example repos read at code level (2026-07-14).
Architecture patterns only — every place an example makes a *trust decision* is flagged
as heliograph-owned, per HANDOFF §8 ("read for architecture, never copy trust decisions").

## Corpus surveyed

| Repo | What it is | Key files read |
|---|---|---|
| [succinctlabs/sp1-tendermint-example](https://github.com/succinctlabs/sp1-tendermint-example) | Minimal SP1 Tendermint LC template | `program/src/main.rs`, `contracts/src/SP1Tendermint.sol`, `README.md` |
| [succinctlabs/sp1-helios](https://github.com/succinctlabs/sp1-helios) | Production Ethereum (Altair sync-committee) LC on SP1; Zellic-audited | `program/src/light_client.rs`, `contracts/src/SP1Helios.sol`, PRs #43–#56, `audits/` |
| [risc0/blobstream0](https://github.com/risc0/blobstream0) | Production Celestia/Tendermint LC on RISC Zero; Veridise-audited | `light-client-guest/guest/src/main.rs`, `primitives/src/lib.rs`, `contracts/src/Blobstream0.sol`, PRs |
| [succinctlabs/sp1-vector](https://github.com/succinctlabs/sp1-vector) | Avail Vector bridge, SP1 | `program/src/main.rs` |
| [succinctlabs/sp1](https://github.com/succinctlabs/sp1) | zkVM; in-guest proof-verification example | `examples/aggregation/program/src/main.rs` |
| [risc0 composition docs](https://dev.risczero.com/api/zkvm/composition) | `env::verify` semantics | — |
| [boundless-xyz/steel](https://github.com/boundless-xyz/steel) (ex risc0-ethereum) | EVM view-call proofs; journal commitment validation pattern | `contracts/src/Steel.sol` |
| [argumentcomputer/zk-light-clients](https://github.com/argumentcomputer/zk-light-clients) | Aptos/Ethereum/Kadena LCs (Sphinx zkVM, SP1 fork) | [docs](https://argumentcomputer.github.io/zk-light-clients/) |
| [eryxcoop/zk-bridge](https://github.com/eryxcoop/zk-bridge) | Cardano/Mithril ZK bridge (Catalyst; custom circuits) | repo layout, milestone deliverables |
| [cardano-foundation/cardano-ibc-incubator](https://github.com/cardano-foundation/cardano-ibc-incubator) | Non-ZK Cardano IBC light client | README |

## 1. The recurring architecture

Every example instantiates the same five-stage pipeline:

1. **Host fetches untrusted input.** An "operator"/"service" binary polls RPC endpoints and
   assembles raw bytes: two `LightBlock`s (sp1-tendermint), `updates + finality_update + store`
   (sp1-helios), trusted block + untrusted block + intermediate headers (blobstream0). Nothing
   the host does is load-bearing; it can lie freely.
2. **Guest verifies from a trust anchor that arrives as *input*.** The guest deserializes,
   runs the real light-client verifier library (tendermint-light-client `ProdVerifier`; the
   `helios` consensus crate), and links the untrusted data back to a trusted prior state that
   was *read as input*, not hardcoded (see §2 — this is the big const-vs-input fork).
3. **Journal commits `(old_state, new_state, params)`.** Always ABI-encoded for the EVM
   consumer:
   - sp1-tendermint: `{trustedHeight, targetHeight, trustedHeaderHash, targetHeaderHash}`.
   - sp1-helios `ProofOutputs`: `{prevHeader, prevHead, prevSyncCommitteeHash, newHead,
     newHeader, executionStateRoot, executionBlockNumber, syncCommitteeHash,
     nextSyncCommitteeHash, storageSlots[]}`.
   - blobstream0 `RangeCommitment`: `{trustedHeaderHash, newHeight, newHeaderHash, merkleRoot}`
     (+ validator bitmap for equivocation attribution).
   The old-state fields exist *solely* so the verifier can bind the proof to its stored
   checkpoint — the proof is a state-*transition* claim, never an absolute claim.
4. **On-chain contract stores the latest proven checkpoint and accepts only extensions.**
   `SP1Tendermint.verifyTendermintProof` reverts `InvalidTrustedHeader()` unless
   `trustedHeaderHash == latestHeader && trustedHeight == latestHeight`; `Blobstream0.updateRange`
   reverts unless `commit.trustedHeaderHash == latestBlockHash` and
   `commit.newHeight > latestHeight + minBatchSize`; `SP1Helios.update` binds the proof's
   `prevHeader/prevHead` to its own stored `headers[head]`/`head` and requires
   `newHead > head` plus `newHead % 32 == 0`. Verification is always
   `verifier.verify(proof, vkey_or_imageId, journal)` against the vendor's audited verifier,
   with the program identity (SP1 vkey hash / RISC Zero image ID) held by the consumer contract.
5. **Consumers read the stored checkpoint + events.** `headers[slot]`,
   `executionStateRoots[blockNumber]`, `merkleRoots[proofNonce]`; events
   (`HeadUpdate`, `DataCommitmentStored`) feed indexers.

### Mapping to the heliograph checkpoint leg

| Pattern element | heliograph instantiation |
|---|---|
| Operator/host | `hg-host` fetch adapters (untrusted bytes, Sextant pattern) |
| LC verifier library in guest | Sextant `mithril` path (pinned dep, `guest` feature) in `hg-guest` |
| Trusted prior state | Prior proven Mithril checkpoint (certificate hash / avk + epoch), rooted at the pinned genesis vkey |
| Journal `(old, new, params)` | `hg-claims` journal: prev-checkpoint binding, new checkpoint, network ID, claim version, tier, anchor basis (`StmCertified`/ancillary), as-of slots |
| `latestHeader/latestHeight` + extension-only update | Router's stored checkpoint + monotonic epoch/slot rule |
| vkey/imageId held by contract | Allowed-image-ID registry behind timelocked admin |
| `HeadUpdate`-style events | Router events for indexer consumption (HANDOFF Phase-1) |

Note the direct structural rhyme: Tendermint's "trusted block → untrusted block" skip
verification is shaped exactly like "prior Mithril certificate → next certificate (signed by
avk the prior one committed to)". The examples transfer almost mechanically.

## 2. How the examples handle the four hard sub-problems

### 2a. Trust-anchor pinning: const-in-guest vs committed input

**Every surveyed example passes the anchor as guest *input* and commits it to the journal;
none hardcode it as a guest const.** The binding is deferred to the verifier: the contract
compares the journal's old-state fields to its own storage. Consequences of that choice:
one guest image serves every network and every checkpoint; the image ID identifies *logic
only*; the genesis anchor lives in the contract constructor instead (SP1Tendermint takes
initial header+height at deploy; sp1-helios has a `genesis.rs` script producing constructor
args incl. immutables `GENESIS_VALIDATORS_ROOT, GENESIS_TIME, SECONDS_PER_SLOT,
SLOTS_PER_PERIOD, SLOTS_PER_EPOCH, SOURCE_CHAIN_ID`; Blobstream0 has `adminSetTrustedState`).

> **Trust decision heliograph owns (ADR-002/ADR-004):** HANDOFF leans "pinned genesis vkey"
> — if pinned as a guest const, the image ID *is* the network binding (preprod and mainnet
> get different image IDs; fail-closed by construction, but image rotation per network).
> If passed as committed input (the examples' pattern), one image covers all networks and
> the router/registry must pin the anchor — a second load-bearing config surface. Neither
> is copyable from the examples; the fail-closed doctrine argues for const-or-journaled,
> never silent input. Decide explicitly and record the rejected option.

### 2b. Checkpoint storage + update authorization on-chain

- **Storage shape:** single latest slot (SP1Tendermint: `latestHeader/latestHeight`) vs
  history mappings (SP1Helios: `headers[slot]`, `executionStateRoots[blockNumber]`,
  `syncCommittees[period]`) vs append-only nonce ledger (Blobstream0: `merkleRoots[proofNonce]`
  with monotonic `proofNonce` — consumers reference commitments by nonce forever, immune to
  head reorgs of the mapping).
- **Who may call update:** permissionless in all three (`update()`/`verifyTendermintProof`/
  `updateRange` have no caller gate) — soundness rests on the proof, liveness on anyone.
  Blobstream0 added `minBatchSize` (PR [#49](https://github.com/risc0/blobstream0/pull/49))
  purely as an anti-griefing measure (spam of tiny valid updates).
- **Admin surface (widest divergence):** SP1Tendermint: none. SP1Helios: `guardian` can
  update vkeys (and renounce to zero address). Blobstream0: UUPS-upgradeable, owner can
  `adminSetImageId`, `adminSetVerifier`, and `adminSetTrustedState` — the last one can
  *rewrite the trusted head outright*.

> **Trust decision heliograph owns (§9 gate 3):** the admin ladder runs from "immutable,
> re-deploy to rotate" to "owner can rewrite history". Heliograph's stated design
> (timelocked allowed-image-ID registry, vendor verifier untouched) sits in the middle;
> pick the rung deliberately and document what the admin can and cannot do to an
> already-proven checkpoint. `adminSetTrustedState` is the anti-pattern to name in
> THREAT_MODEL ("router admin compromise").

### 2c. Replay / network-ID binding in journals

Two live patterns:

- **Implicit continuity binding (all three LCs):** no chain-ID field in the journal. A
  preprod-shaped proof cannot land on a mainnet contract because its `trustedHeaderHash`
  will never equal that contract's stored head (and Tendermint's `ProdVerifier` checks
  chain-ID equality between trusted and untrusted headers *inside* the guest, so continuity
  transitively pins the network). SP1Helios stores `SOURCE_CHAIN_ID` as an immutable but it
  is informational, not proof-checked.
- **Explicit config binding (Steel):** journal commits `Commitment {id (versioned), digest,
  configID}` where `configID` is "the cryptographic digest of the network configuration";
  `Steel.validateCommitment` checks `configID` against the chain's expected digest, decodes
  a 16-bit version from the id's upper bits, and **reverts on unknown versions** — the
  closest existing artifact to heliograph's journal header (claim version + network ID,
  unknown versions rejected everywhere, ADR-003).

Cross-*image* replay is handled uniformly: the verifier call takes the vkey/imageId from
contract state, so a proof from a different program simply fails verification. Downgrade
pressure therefore concentrates on the registry/admin, not the proof path.

> **Heliograph keeps its stronger rule:** explicit network ID + claim version in every
> journal (Steel-style), *in addition to* continuity binding — belt and suspenders is the
> fail-closed reading, and it is what makes the portable-verdict file self-describing
> off-chain, where no contract supplies context.

### 2d. Proof freshness / staleness for consumers

The most under-handled area in the corpus, and directly heliograph's
"stale-but-valid selection" adversary:

- **Guests are clockless and fake the clock from attacker-adjacent data.** sp1-tendermint
  sets verification time to the *untrusted* header's timestamp + 20s; blobstream0 to
  untrusted header time + 1s (trusting period 1,209,600s, clock drift 0). The trusting-period
  check inside the guest is therefore evaluated against a timestamp the prover chose to
  include — it bounds trusted→target *spread*, but proves nothing about wall-clock freshness.
- **Contracts enforce ordering, not recency.** `newHead > head`, `newHeight > latestHeight`:
  monotonicity only. A proof over data that is hours old is accepted if it extends the head.
- **Recency is pushed to the consumer.** SP1Helios consumers compute staleness from
  `GENESIS_TIME + head * SECONDS_PER_SLOT`; Steel is the only one with an in-protocol
  freshness gate — commitment validation fails once the block leaves the EVM's 256-block
  `blockhash` window or the EIP-4788 beacon-root ring buffer.
- **Liveness cadence is an off-chain ops contract:** argumentcomputer's Ethereum LC states
  committee-change proofs "must be generated and submitted at least every 54.6 hours" or the
  client falls out of sync.

> **Heliograph mapping:** as-of slots in the journal (already specified) are the analog of
> Helios's slot math; the consumer's recency obligation must be documented explicitly
> (HANDOFF Phase-3 red-team item). There is no example to copy for "proof of freshness" —
> because none exists; freshness is always a consumer-side policy over journaled as-of data.

## 3. Recursion in practice

**Finding: none of the production examples re-prove from genesis, and none extend a prior
*proof* in-guest for the LC update loop. All extend prior proven *state* via contract-side
chaining.** Each proof covers only the delta (trusted → target), and the "previous proof"
is represented by the checkpoint the contract already stored when it verified that proof.
Amortization is achieved two ways without recursion:

- **Skip verification:** Tendermint's LC protocol jumps many heights in one verification if
  ≥2/3 of the trusted validator set signed the target (sp1-tendermint, blobstream0).
- **Batch-in-one-execution:** blobstream0 verifies a whole header range in a single guest
  run (hash-linking each intermediate header's `last_block_id.hash` to the previous computed
  hash, folding them into one Merkle root); sp1-helios applies a *list* of sync-committee
  updates plus a finality update in one run. (Current blobstream0 `main` contains no
  `env::verify` — batching replaced composition; earlier batch-guest history unconfirmed.)

**In-guest composition exists as a vendor primitive, used for aggregation, not LC extension:**

- SP1: `sp1_zkvm::lib::verify::verify_sp1_proof(vkey, &public_values_digest)` — in the
  `examples/aggregation` guest, child **vkeys arrive as inputs** and are **committed into the
  journal** (each Merkle leaf is `vkey || len || committed_values`), so the outer verifier
  learns exactly which programs were composed. This is the discipline heliograph must copy:
  an inner image ID that is an input MUST be journaled, else it is an unbound input.
- RISC Zero: `env::verify(image_id, journal)` "adds an assumption to the ReceiptClaim"
  (conditional receipt); assumptions are resolved during proving with
  `ReceiptKind::Succinct`/`Groth16` via the recursion circuit.

### Which pattern fits ADR-002's extend-by-one-certificate loop

Split by consumer:

1. **On-chain leg (router): contract-side chaining, exactly like the examples.** Each proof
   verifies *one new certificate* against the prior checkpoint passed as committed input;
   the router requires journal.prev-checkpoint == stored checkpoint. Battle-tested
   (SP1Tendermint/Blobstream0-shaped), no recursion machinery, each proof is small because
   the Mithril chain's own structure (cert N signs the avk committed by cert N−1) plays the
   role Tendermint's validator-set continuity plays.
2. **Offline/portable verdict and leg composition: in-guest composition.** With no contract
   to hold the checkpoint, the extend guest verifies the previous checkpoint *proof*
   (`env::verify` / `verify_sp1_proof`) and the header/inclusion guests compose the latest
   checkpoint proof instead of re-running STM verification. Two structural cautions from
   the vendor primitives:
   - **Self-reference:** a guest cannot contain its own image ID as a const (circular). The
     working pattern is the aggregation example's: inner image ID/vkey as *input, committed
     to the journal*, with the top-level verifier (router or CLI) checking the journaled ID
     chain against its allowlist. Journal-size discipline: commit the ID once, not per step.
   - **Genesis base case:** step 0 proves from the pinned genesis vkey with no inner proof;
     the journal must distinguish base-case from extension (or the base case is its own
     claim type) so a verifier can't be handed an "extension" that anchors nowhere.

Two-program factoring precedent: sp1-vector runs `HeaderRangeProof` and `RotateProof`
(authority-set handoff) as two proof types inside one image, committing
`proof_type as u8` first; argumentcomputer factors `epoch_change` vs `inclusion` into
separate programs with separate program hashes. Both match heliograph's checkpoint-leg vs
header/inclusion-leg split — whether legs share one image (claim dispatch, HANDOFF §5) or
get separate image IDs is an ADR-003/ADR-004 decision; sp1-vector shows the shared-image
variant needs the claim type as the *first* journal field, fail-closed on unknown values.

## 4. Anti-patterns and incidents → THREAT_MODEL adversary catalog

1. **Under-constrained journal passthrough (real, critical, recent):** sp1-helios
   PR [#54](https://github.com/succinctlabs/sp1-helios/pull/54) — the guest committed
   `store.next_sync_committee` (prover-supplied) to `nextSyncCommitteeHash` **without
   verification when the `updates` list was empty**; a malicious prover could inject an
   arbitrary committee, which the contract would store, handing over the light client at the
   next period. Fix: reset the field to `None` on deserialization so only `verify_update`-validated
   data can populate it; PR [#55](https://github.com/succinctlabs/sp1-helios/pull/55) added an
   executor-based regression test. This is the exact adversary heliograph's unbound-input zoo
   exists to kill: *any guest input that can reach the journal without passing through
   verification is a soundness hole*, and it survived in an audited flagship. The zoo must
   cover the "empty update list" / degenerate-path cases specifically.
2. **Journal ABI designed too small, then evolved under pressure:** sp1-helios
   #53/#56 retrofit execution block hash + receipts root into `ProofOutputs` because
   consumers needed them. Journal changes rotate integration surfaces; heliograph freezes
   CLAIMS.md v1 with explicit versioning instead of retrofitting (ADR-003 vindicated).
3. **Griefing via minimal valid updates:** Blobstream0 added `minBatchSize`
   (PR #49, "prevent DOS attacks") only after the fact. Catalog entry: economic spam with
   *valid* proofs that advance state uselessly.
4. **Admin who can rewrite proven history:** `adminSetTrustedState` + mutable `imageId` +
   UUPS upgrade (Blobstream0) concentrate full takeover in one key. Contrast SP1Helios
   (guardian limited to vkey rotation, renounceable) and SP1Tendermint (no admin). Feeds
   "verifier-contract admin-key compromise" with concrete shapes for the timelock ADR.
5. **Clockless-guest freshness theater:** trusting-period checks evaluated at
   `untrusted_header.time + ε` (both Tendermint guests) must never be presented as a
   freshness guarantee. Catalog: "stale-but-valid data selection by a malicious prover" —
   mitigated only by journaled as-of + consumer recency policy (and Steel's window-expiry
   pattern where applicable).
6. **Panic-as-rejection:** all surveyed guests `assert!`/panic on invalid input, so a
   rejection produces no proof and no evidence — fine for a bridge relayer, wrong for
   heliograph, where rejection parity is a product requirement (HANDOFF §5: "every expected
   rejection must be a *journaled verdict*, not a panic"). No example demonstrates journaled
   rejections; heliograph builds this without prior art.
7. **Template code mistaken for product:** sp1-tendermint-example README: "This repository
   is still an active work-in-progress and is not audited or meant for production usage" —
   and indeed it enforces no trusting-period-vs-now, no batch minimum, no admin story.
   Architecture yes, deployment shape no.
8. **Attribution surface as a feature:** blobstream0 journals a validator bitmap and the
   contract emits `ValidatorBitmapEquivocation`, making signer misbehavior attributable
   on-chain. Worth considering for Mithril signer-set evidence in a later version (not v0.1).

Audit artifacts located but not fully extracted: sp1-helios `audits/SP1 Helios - Zellic
Audit Report.pdf` (image-only PDF, not machine-readable this session; post-audit fixes
landed in PR #44) and blobstream0's Veridise assessment (referenced from its README).
Reading both is cheap Phase-0 follow-up before THREAT_MODEL v1 freezes.

## 5. Cardano-adjacent prior art (code form)

- **[eryxcoop/zk-bridge](https://github.com/eryxcoop/zk-bridge)** — the only public
  Cardano/Mithril ZK-bridge code found (Catalyst-funded, milestone-deliverable maturity).
  Custom circuits (Circom + Halo2: `circuit_inclusion_exclusion`,
  `circuit_jubjub_schnorr_verification`, `circuit_transaction_snapshot`), Aiken contracts,
  and zkFold's `plutus-halo2-verifier-gen` for on-chain verification *on Cardano*. Per its
  design docs: Mithril certificates as circuit inputs (stake-distribution updates per epoch +
  tx-inclusion Merkle proofs), a used-transaction registry against double-mint. Two
  divergences from heliograph: custom circuits (heliograph's §9 hard no) and a
  jubjub/Schnorr verification circuit rather than Mithril's native BLS12-381 STM path —
  suggesting a re-signing or wrapping layer; not confirmed at code level. Architecture-only
  value: epoch-update contract + inclusion-consumer split mirrors checkpoint-leg vs
  inclusion-leg.
- **[zkFold/plutus-halo2-verifier-gen](https://github.com/zkFold/plutus-halo2-verifier-gen)** —
  Halo2 proof verification on Cardano; prior art for the *inbound* leg only (heliograph
  v0.1 non-goal; cite in the two-way-vision page).
- **[cardano-foundation/cardano-ibc-incubator](https://github.com/cardano-foundation/cardano-ibc-incubator)** —
  non-ZK Cardano light client for IBC. Two signals worth recording: its **Mithril light
  client is explicitly "deprecated, disabled, and not maintained"** (replaced by a
  probabilistic-finality client trusting configured observers), and it cites the lack of
  protocol-level state/UTxO inclusion proofs (CIP-0165) as the gap. Heliograph's
  Sextant-based approach (prove the verification, not the protocol) is the road around
  exactly that gap; the deprecation is a data point for ADR-005's swappable-checkpoint
  caution, not against Mithril itself.
- **No public zkVM-based Mithril verification was found** (GitHub repo searches:
  `mithril zk|snark|light-client`, `cardano ibc|ouroboros light client`, org sweeps of
  zkFold; the IOG `mithril` repo's recursive-certificate workstream remains the upstream
  watch item). Heliograph's checkpoint leg appears to be first public code in this slot.

## 6. Trust decisions heliograph must make independently (do not copy)

1. Genesis-anchor placement: guest const (image-ID-as-network-binding) vs committed input +
   router pin (examples' pattern). ADR-002/004.
2. Explicit network-ID + claim-version journal fields (Steel-style) on top of continuity
   binding — keep, the examples' implicit-only binding is insufficient for portable verdicts.
   ADR-003.
3. Admin/registry powers and timelock parameters; whether any admin action may affect
   already-proven checkpoints (Blobstream0 says yes; heliograph should say no). §9 gate 3.
4. Checkpoint storage shape: latest-only vs history mapping vs append-only nonce ledger
   (nonce ledger composes best with indexers and never orphans a consumer reference).
5. Permissionless update + anti-griefing minimum vs allowlisted relayer.
6. Freshness contract: journaled as-of slots + documented consumer recency obligation;
   no example provides in-proof freshness and heliograph must not pretend to.
7. Journaled rejection verdicts (no prior art — heliograph-specific requirement).
8. One image with claim dispatch vs image-per-leg (sp1-vector vs argumentcomputer factoring).

## Open follow-ups

- Read both audit PDFs (Zellic/sp1-helios, Veridise/blobstream0) manually; harvest findings
  into THREAT_MODEL v1.
- Code-level confirmation of how sp1-helios binds `genesis_root`/`forks` inputs (committed
  vs transitively constrained via committee continuity) — instructive for the anchor ADR
  either way; do not cite as a defect without confirmation.
- Confirm whether blobstream0 ever shipped a composing batch-guest (git history), to cite
  composition-vs-batching cost experience in ADR-002.
- eryxcoop/zk-bridge: read milestone deliverables to pin down what is actually proven about
  Mithril certificates (BLS STM vs wrapped scheme) before citing it as more than layout prior art.
