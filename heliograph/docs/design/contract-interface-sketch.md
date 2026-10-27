# Contract interface sketch — the heliograph verifier-router

- **Status:** DESIGN sketch (Phase 1). Interfaces + NatSpec, not implementations.
  This document is the Phase-1 exit-gate deliverable "contract interface sketch"
  (HANDOFF §4 Phase-1 exit gate) and the "Verifier contract design" line item
  (HANDOFF §4 Phase-1: "vendor's audited verifier untouched; thin router above
  it; allowed-image-ID registry behind a timelocked admin … events designed for
  indexer consumption").
- **Date:** 2026-07-14.
- **Realizes:** ADR-002 D4 (contract-side checkpoint chaining), ADR-003 (the
  `hg-claims` codec the router mirrors constant-for-constant), ADR-004 (image ID
  is the trust anchor; the registry allowlists it). Vendor-neutral per ADR-001
  (DEFERRED): the router sits over *either* vendor's audited verifier through one
  adapter seam (§2), selected at deploy time, never reopening this sketch.
- **Pins closed by THREAT_MODEL:** A8 (narrow admin: timelocked image-ID/anchor
  registry, **no `adminSetTrustedState`-equivalent**), A14 (deploy-time params +
  key domains documented at each mapping), A10 (extension-only chaining), A13
  (mandatory minimum-progress rule + front-run race), A4 (hash exactly the bytes
  you decode; bindings-from-ABI; no silent canonicalization), A3 (image-ID
  registry binding), A2 (network binding), A11 (re-genesis anchor rotation as a
  governed registry event).

---

## 0. What this sketch fixes, and what it defers

**Fixes (frozen for M4 build):**

- The three-contract split: `HeliographRouter` (thin, app-owned) over an
  `IVendorVerifier` adapter over the vendor's **audited, unmodified, unowned-by-us**
  verifier; a `HeliographRegistry` (timelocked allowlist of image IDs + genesis
  anchors); the router's checkpoint storage as an **append-only nonce ledger**
  (lightclient-patterns §6.4).
- The router's public ABI surface: what it accepts, what it stores, what it
  emits, and — decisively — **the complete set of custom errors**, each of which
  MUST get a T-A8-4 negative test (THREAT_MODEL A8; §9 of this doc).
- The **key domain of every mapping**, documented at the declaration (A14
  T-A14-1/2/3): the three Cardano height domains heliograph carries (slot,
  block number, epoch) plus the checkpoint nonce and the image-ID/anchor sets.
- The invariant **"no function mutates a stored checkpoint"** (A8 T-A8-1),
  enforced by construction: the ledger is append-only and there is no
  `adminSetTrustedState`-equivalent selector anywhere in the ABI.

**Defers (owned elsewhere, cited here):**

- **Vendor selection** — ADR-001 (M0 numbers, §9 gate 2). The `IVendorVerifier`
  adapter (§2) is the one seam that differs per vendor; the router never sees it.
- **The `minProgress` numeric value** — sized against measured proving latency
  after M0 (ADR-002 D4; THREAT_MODEL A13). This sketch fixes *that* the rule
  exists and *where* it is enforced; the number is a deploy-time param.
- **Whether to adopt a permissionless emergency-stop** on the router (RISC Zero's
  `estop(Receipt)` circuit-breaker pattern — risc0.md §4; THREAT_MODEL A8 "open
  design question"). Recorded in §8 as a decision for M4 review, not frozen here.
- **The exact `hg-claims` offset/width constants** — ADR-003 froze them; this
  sketch references `Constants.sol` (mechanically generated from the Rust `const`
  block, D8 / T-A4-4), it does not re-type them.

---

## 1. Architecture: three contracts, one audited verifier untouched

```
                        ┌─────────────────────────────────────────────┐
   proof submitter ───► │ HeliographRouter (app-owned, thin)          │
   (permissionless)     │  - decodes journal by hg-claims offsets     │
                        │  - fail-closed R1..R8 (ADR-003 D7)          │
                        │  - contract-side checkpoint chaining (A10)  │
                        │  - append-only nonce ledger (no mutation)   │
                        └───────┬──────────────────────┬──────────────┘
                                │ reads (view)         │ verify (view, no state)
                                ▼                      ▼
              ┌──────────────────────────┐   ┌──────────────────────────────┐
              │ HeliographRegistry       │   │ IVendorVerifier (adapter)    │
              │  (timelocked allowlist)  │   │  wraps the vendor's AUDITED   │
              │  - image IDs             │   │  verifier BYTE-IDENTICAL,     │
              │  - genesis anchors       │   │  unmodified, UNOWNED BY US    │
              │  - propose/execute/cancel│   │  (SP1 gateway / RZ verifier)  │
              │  - events at PROPOSE time│   └──────────────────────────────┘
              └──────────────────────────┘
```

Standing rules that shape every interface below:

- **The vendor verifier is vendored byte-identical and never owned by us**
  (HANDOFF §6; THREAT_MODEL §1.1, A8). Its admin surface (SP1 gateway ownership —
  *undocumented, resolve before M4*, sp1.md open item 5; RISC Zero router
  `TimelockController` — risc0.md §4) is upstream of ours and documented as
  vendor trust (THREAT_MODEL §3), not re-implemented here. `IVendorVerifier` is a
  *thin adapter* that normalizes the two vendors' call shapes (§2); it adds no
  trust surface of its own.
- **The router is thin.** It decodes the journal by fixed `hg-claims` offsets,
  runs the fail-closed R1..R8 sequence (ADR-003 D7), chains checkpoints
  contract-side, and appends to the ledger. It holds no proving logic and no
  vendor secrets.
- **One buffer, no re-encode** (ADR-003 D0; THREAT_MODEL A4 / T-A4-5): the exact
  `journal` calldata slice whose digest is handed to the vendor verifier is the
  exact slice the router reads fields from. The router MUST NOT decode-to-struct
  then re-encode-to-hash. This is a structural property (flat fixed-offset
  layout), not a runtime check — there is no canonicalization step to diverge.

---

## 2. The vendor-verifier seam (`IVendorVerifier`) — the only per-vendor code

ADR-001 is DEFERRED; both vendors expose an image-ID-bound, **stateless/view**
verify that reverts on failure. The seam normalizes their two shapes so the
router is written once:

- **SP1** (`ISP1Verifier`, sp1.md §4):
  `verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view` —
  reverts on failure. `publicValues` **is** the journal buffer; `programVKey`
  **is** the image ID.
- **RISC Zero** (`IRiscZeroVerifier`, risc0.md §4):
  `verify(bytes seal, bytes32 imageId, bytes32 journalDigest) external view`
  where `journalDigest = sha256(journal)`; the Groth16 verifier reconstructs the
  claim from `imageId` on-chain (binds, not compares).

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IVendorVerifier — thin normalization over ONE vendor's audited verifier.
/// @notice Wraps the vendor's byte-identical, unmodified, unowned-by-us verifier
///         (SP1 gateway / RISC Zero verifier). Adds NO trust surface: it forwards
///         to the audited contract and reverts exactly when the vendor reverts.
///         Selected at deploy time by ADR-001; the router never branches on vendor.
/// @dev    THREAT_MODEL A3 (image-ID binding is in the verify call itself), §1.1
///         (vendor verifier is load-bearing, vendored byte-identical, HANDOFF §6).
interface IVendorVerifier {
    /// @notice Verify a wrapped proof against a pinned image ID and the exact
    ///         journal bytes. Reverts on any verification failure (the vendor's
    ///         own revert). MUST be `view` — verification mutates no state.
    /// @param imageId  The guest program identity (SP1 programVKey / RZ imageId).
    ///                  Supplied by the router from the timelocked registry (A3/A8);
    ///                  never a router constant, never caller-supplied.
    /// @param journal  The EXACT journal byte buffer (SP1 publicValues / the bytes
    ///                  RZ hashes to journalDigest). This is the SAME slice the
    ///                  router decodes fields from — one buffer, no re-encode
    ///                  (ADR-003 D0; A4 / T-A4-5). The adapter computes any digest
    ///                  the vendor needs (RZ: sha256(journal)) over THIS slice.
    /// @param seal     The vendor proof bytes (SP1 proofBytes / RZ seal). The
    ///                  vendor pins its own wrap-circuit version inside these bytes
    ///                  (SP1 4-byte VERIFIER_HASH prefix / RZ 4-byte selector).
    function verifyProof(bytes32 imageId, bytes calldata journal, bytes calldata seal)
        external
        view;
}
```

**Why an adapter and not the vendor interface directly:** the two vendors differ
only in (a) whether the router passes `journal` or `sha256(journal)`, and (b)
parameter order. Wrapping both behind one `view` call keeps the router's R1..R8
sequence vendor-agnostic and lets ADR-001 land without touching the router. This
is *not* an abstraction with one caller: it has exactly two concrete implementers
(the M0 bakeoff runs both; ADR-004 D5 CI matrix), which is the code-hygiene bar.

---

## 3. `Constants.sol` — the mirrored `hg-claims` codec (generated, never hand-typed)

The router reads journal fields by the ADR-003-frozen offsets. Those offsets live
in **one** source of truth (the Rust `hg-claims` `const` block) and are
mechanically propagated to Solidity (`Constants.sol`) and diffed in CI
(ADR-003 D8; THREAT_MODEL T-A4-4). **No offset, width, magic, verdict code, or
length is typed by hand in two places.** Reproduced here for legibility only —
`Constants.sol` (generated) is normative:

```solidity
// GENERATED from hg-claims const block — DO NOT EDIT. Diffed in CI (T-A4-4).
library HgClaims {
    // Header (ADR-003 D2) — 46 bytes, identical for every claim type.
    uint256 internal constant HDR_OFF_VERSION      = 0;   // u16
    uint256 internal constant HDR_OFF_CLAIM_TYPE   = 2;   // u16
    uint256 internal constant HDR_OFF_NETWORK_ID   = 4;   // u32 (Cardano magic)
    uint256 internal constant HDR_OFF_GENESIS_VKEY = 8;   // [u8;32]
    uint256 internal constant HDR_OFF_VERDICT      = 40;  // u16
    uint256 internal constant HDR_OFF_REJECT_INDEX = 42;  // u32
    uint256 internal constant HDR_LEN              = 46;
    uint256 internal constant BODY_OFF             = 46;

    // Frozen claim types (CLAIMS.md §2.1). Accepted claim version (normally {1}).
    uint16 internal constant CLAIM_CHECKPOINT           = 0x0001;
    uint16 internal constant CLAIM_CHECKPOINT_EXTENSION = 0x0002;
    uint16 internal constant CLAIM_HEADER_SEGMENT       = 0x0003;
    uint16 internal constant CLAIM_TX_INCLUSION         = 0x0004;
    uint16 internal constant CLAIM_UTXO_READ            = 0x0005;

    // Per-type total journal length (ADR-003 body tables). Length gate = R1.
    uint256 internal constant LEN_CHECKPOINT           = 255; // 46 + 209
    uint256 internal constant LEN_CHECKPOINT_EXTENSION = 328; // 46 + 73 + 209
    uint256 internal constant LEN_HEADER_SEGMENT       = 170; // 46 + 124
    uint256 internal constant LEN_TX_INCLUSION         = 191; // 46 + 145
    uint256 internal constant LEN_UTXO_READ            = 269; // 46 + 223

    // CheckpointState group (ADR-003) — offsets within the 209-byte group.
    // Body of 0x0001 starts at BODY_OFF; the group in 0x0002 starts at BODY_OFF+73.
    uint256 internal constant CS_OFF_ROOT_HASH        = 0;
    uint256 internal constant CS_OFF_TIP_HASH         = 32;
    uint256 internal constant CS_OFF_TIP_EPOCH        = 64;  // u64  (Cardano epoch)
    uint256 internal constant CS_OFF_CHAIN_LENGTH     = 72;  // u32
    uint256 internal constant CS_OFF_AVK_COMMITMENT   = 76;
    uint256 internal constant CS_OFF_NEXT_AVK_COMMIT  = 108;
    uint256 internal constant CS_OFF_STM_K            = 140; // u64
    uint256 internal constant CS_OFF_STM_M            = 148; // u64
    uint256 internal constant CS_OFF_STM_PHI_F        = 156; // u32 (U8F24 fixed)
    uint256 internal constant CS_OFF_HAS_CTX          = 160; // u8  presence flag
    uint256 internal constant CS_OFF_CTX_MERKLE_ROOT  = 161;
    uint256 internal constant CS_OFF_CTX_EPOCH        = 193; // u64 (Cardano epoch)
    uint256 internal constant CS_OFF_CTX_BLOCK_NUMBER = 201; // u64 (block number)
    uint256 internal constant CS_GROUP_LEN            = 209;

    // 0x0002 extension prefix (ADR-003) — offsets within the body (BODY_OFF-based).
    uint256 internal constant EXT_OFF_ANCHOR_MODE     = 0;   // u8 {1,2}
    uint256 internal constant EXT_OFF_INNER_IMAGE_ID  = 1;   // [u8;32]
    uint256 internal constant EXT_OFF_PREV_TIP_HASH   = 33;  // [u8;32]
    uint256 internal constant EXT_OFF_PREV_TIP_EPOCH  = 65;  // u64 (Cardano epoch)
    uint256 internal constant EXT_OFF_NEW_STATE       = 73;  // CheckpointState group

    // Presence-flag / discriminant allowed values (ADR-003 D3, R7).
    uint8 internal constant ANCHOR_MODE_EXTERNAL = 1;   // router uses ONLY this
    uint8 internal constant ANCHOR_MODE_COMPOSED = 2;   // offline/CLI path (D3)

    // Cardano network magic (ADR-003 D4). Router pins exactly ONE at deploy.
    uint32 internal constant NET_MAINNET = 764824073; // 0x2D964A09
    uint32 internal constant NET_PREPROD = 1;
    uint32 internal constant NET_PREVIEW = 2;

    uint16 internal constant CLAIM_VERSION_DRAFT = 0; // rejected unconditionally
}
```

The router reads fields with constant-offset calldata loads over the `journal`
slice (big-endian, native to EVM words — ADR-003 D1/Context 4). It never
`abi.decode`s the journal into a struct (that would be a second buffer — A4).

---

## 4. `HeliographRegistry` — the timelocked trust-anchor allowlist (A8, A11)

The registry is the router's **only** admin surface, and it governs exactly two
sets: allowed guest **image IDs** (A3) and the pinned **genesis anchor** per
network (A11). It sits at the *narrow end* of the admin ladder
(lightclient-patterns §2b/§4.4): the vendor verifier is untouched and unowned by
us; there is **no `adminSetTrustedState`-equivalent** — the registry cannot touch
a stored checkpoint (A8; ADR-002 D4). Every change is timelocked and **emits an
event at PROPOSE time** so indexers get the full delay window as early warning
(THREAT_MODEL A8 T-A8-2).

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title HeliographRegistry — timelocked allowlist of image IDs + genesis anchors.
/// @notice The ROUTER'S ONLY ADMIN SURFACE. Governs which guest image IDs the
///         router trusts (A3) and which Mithril genesis vkey is pinned per network
///         (A11). Every mutation is a propose → (timelock) → execute flow; a
///         PROPOSE emits an event immediately so consumers/indexers get the whole
///         delay window as early warning (A8 T-A8-2). Key custody + the timelock
///         delay are a §9-gate-3 human decision (HANDOFF §9).
/// @dev    NO function here mutates a stored checkpoint — that lives in the router
///         and is append-only (A8 T-A8-1). This registry cannot rewrite history;
///         it can only change what FUTURE proofs are checked against. Already-
///         accepted checkpoints stay valid across a registry change (A8; A11-2).
interface IHeliographRegistry {
    // ─────────────────────────── Key domains (A14 T-A14-1) ────────────────────
    // imageId       : bytes32  — SP1 programVKey / RZ image ID (ADR-004 trust
    //                            anchor). Domain = "guest program identity".
    //                            NOT a Cardano value; NOT a hash of the journal.
    // networkId     : uint32   — Cardano network magic (ADR-003 D4). Domain =
    //                            "Cardano network". Router pins exactly one.
    // genesisVkey   : bytes32  — Mithril genesis Ed25519 vkey (CLAIMS.md H4).
    //                            Domain = "Cardano Mithril genesis anchor per era".
    //                            Rotates on re-genesis (A11); versioned input,
    //                            never an image constant (ADR-004 D4).

    // ─────────────────────────────── Views ────────────────────────────────────

    /// @notice True iff `imageId` is currently allowlisted (post-timelock).
    /// @dev R5 (ADR-003 D7): the router calls this for BOTH the top-level image ID
    ///      and any journaled inner_image_id (composed claims, A3). Unknown ⇒ the
    ///      router rejects (fail-closed, HANDOFF §0).
    function isAllowedImageId(bytes32 imageId) external view returns (bool);

    /// @notice The pinned genesis anchor for `networkId`, or zero if unset.
    /// @dev R4 (ADR-003 D7): the router checks journal H4 genesis_vkey == this.
    ///      A re-genesis is a governed rotation of THIS value (A11), not an image
    ///      bump — one image serves all eras (ADR-004 D4).
    function genesisAnchor(uint32 networkId) external view returns (bytes32 genesisVkey);

    /// @notice The configured timelock delay (seconds). Deploy-time param (A14).
    function timelockDelay() external view returns (uint64);

    /// @notice Details of a pending change, keyed by its proposal id.
    /// @dev proposalId domain = keccak256 over (kind, key, value, salt); NOT a
    ///      Cardano value and NOT sequential — an opaque content id.
    function pendingChange(bytes32 proposalId)
        external
        view
        returns (uint8 kind, bytes32 key, bytes32 value, uint64 executableAt, bool cancelled);

    // ───────────────────────── Governed mutations ─────────────────────────────
    // All revert with NotAdmin() unless caller is the admin (custody = §9 gate 3).

    /// @notice Propose adding an image ID to the allowlist. Emits ImageIdProposed
    ///         NOW (consumer early-warning); executable only after timelockDelay.
    function proposeAddImageId(bytes32 imageId, bytes32 salt) external returns (bytes32 proposalId);

    /// @notice Propose removing an image ID. Removal is future-only: proofs already
    ///         accepted under it stay in the ledger (A8: no history rewrite).
    function proposeRemoveImageId(bytes32 imageId, bytes32 salt) external returns (bytes32 proposalId);

    /// @notice Propose setting/rotating the genesis anchor for a network (A11).
    function proposeSetGenesisAnchor(uint32 networkId, bytes32 genesisVkey, bytes32 salt)
        external
        returns (bytes32 proposalId);

    /// @notice Execute a proposal after its timelock has elapsed. Reverts
    ///         TimelockNotElapsed() before executableAt, ProposalCancelled() if
    ///         cancelled, UnknownProposal() if never proposed.
    function executeChange(bytes32 proposalId) external;

    /// @notice Cancel a pending proposal before execution (admin escape hatch for
    ///         a mistaken/observed-malicious proposal during its delay window).
    function cancelChange(bytes32 proposalId) external;

    // ───────────────────────────── Events ─────────────────────────────────────
    // Emitted at PROPOSE time (A8 T-A8-2: indexers watch these for the full delay).

    event ImageIdProposed(bytes32 indexed proposalId, bytes32 indexed imageId, bool add, uint64 executableAt);
    event GenesisAnchorProposed(bytes32 indexed proposalId, uint32 indexed networkId, bytes32 genesisVkey, uint64 executableAt);
    event ChangeExecuted(bytes32 indexed proposalId, uint8 kind);
    event ChangeCancelled(bytes32 indexed proposalId);
}
```

**Deliberately absent from this ABI** (each absence is an A8 defense, pinned by
the T-A8-1 enumerated-selector test):

- No `setImageId` / `setGenesisAnchor` *immediate* setter — every change is
  propose→timelock→execute. (Contrast SP1Helios `guardian` instant vkey swap,
  "Constraints: None" — Zellic §5.1; THREAT_MODEL A8.)
- No `adminSetTrustedState` / `setCheckpoint` / `forceCheckpoint` — the registry
  cannot reach the router's ledger at all. (This is the Blobstream0 anti-pattern
  named in THREAT_MODEL A8 and lightclient-patterns §4.4.)
- No `upgradeTo` / UUPS proxy on the registry or router. (Contrast Blobstream0's
  UUPS + `adminSetTrustedState` single-key full takeover — Veridise
  V-BLOB-VUL-002; THREAT_MODEL A8.) Rotation is a fresh deploy + registry
  migration, a governed event, not a proxy swap.

**Renounce/freeze:** if a renounce-admin path is ever added (SP1Helios
`relinquishGuardian` → irreversible freeze), its irreversibility is an
ADR-recorded decision pinned by a fork test — a frozen registry still verifies
already-accepted proofs and rejects all future registry mutations (THREAT_MODEL
A8). **Not in this sketch's ABI**; recorded as a §8 open item.

---

## 5. `HeliographRouter` — thin verify + contract-side chaining (A2, A3, A10, A13)

The router is the public entry point. It verifies a wrapped proof against the
registry-pinned image ID, decodes the journal by fixed offsets, runs the
fail-closed R1..R8 sequence (ADR-003 D7), and — for checkpoint claims — chains
**contract-side** against the append-only ledger (ADR-002 D4). It accepts
**mode-1 (external) anchors only** (ADR-002 D4: the router binds the anchor to
its stored checkpoint; mode-2 composed proofs are the offline/CLI path).

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title HeliographRouter — thin claim-router over an audited vendor verifier.
/// @notice Accepts permissionless proof submissions (A9), verifies them against a
///         registry-pinned image ID (A3) with the vendor's audited verifier (§2,
///         untouched/unowned), decodes the hg-claims journal by fixed offsets
///         (ADR-003), enforces the fail-closed R1..R8 sequence (ADR-003 D7), and
///         chains checkpoints contract-side into an append-only nonce ledger
///         (ADR-002 D4; A10). NO function mutates a stored checkpoint (A8 T-A8-1).
/// @dev    Realizes ADR-002 D4. The router is written ONCE against IVendorVerifier
///         (§2); ADR-001 selects the vendor at deploy time without touching this.
interface IHeliographRouter {
    // ═══════════════════════════ Key domains (A14) ════════════════════════════
    // The router carries THREE distinct Cardano height domains through the journal
    // into storage. Confusing them is the sp1-helios 3.2 constructor bug (A14).
    // Documented here at the ABI and asserted by T-A14-1/2/3:
    //
    //   tipEpoch          : uint64 — Cardano EPOCH (CheckpointState S3 / ctxEpoch
    //                                S12). Domain = "epoch counter". Monotonic
    //                                non-decreasing across extensions (A10).
    //   ctxBlockNumber    : uint64 — Cardano BLOCK NUMBER (CheckpointState S13).
    //                                Domain = "block height of certified tx set".
    //   segTipSlot        : uint64 — Cardano SLOT (header-segment P7). Domain =
    //                                "absolute slot". SLOT ≠ BLOCK NUMBER — a slot
    //                                may be empty; never key one by the other.
    //   checkpointNonce   : uint64 — heliograph ledger index (§6). Domain =
    //                                "monotonic append counter", NOT a Cardano
    //                                value. Consumers reference checkpoints by this
    //                                forever (nonce-ledger, lightclient-patterns
    //                                §6.4); it never orphans on any reorg of ours.

    // ═════════════════════════════ Submission ═════════════════════════════════

    /// @notice Install or rotate the base checkpoint (claim 0x0001). Used for
    ///         first bring-up and re-genesis cutover (ADR-002 D1; A11). Because a
    ///         base case is a DISTINCT claim type from an extension, a verifier can
    ///         never be handed an extension that anchors nowhere (CLAIMS §3.2).
    /// @dev    Fail-closed R1..R8 (ADR-003 D7): length gate for LEN_CHECKPOINT (R1);
    ///         claim_version in accepted set, DRAFT 0 rejected (R2); claim_type ==
    ///         0x0001 && network_id == configured (R3); genesis_vkey == registry
    ///         anchor for the network (R4); imageId in registry (R5); band/presence
    ///         validity (R7); read verdict (R8). STORING GATE: H5 verdict MUST be 0
    ///         before any ledger write — a nonzero verdict is a valid proof of a
    ///         Mithril-chain REJECTION, and installing one as a live checkpoint would
    ///         make a proof-of-rejection the tip all downstream reads anchor against
    ///         (RejectedCheckpointNotStorable; ADR-002 D4 "stores the latest PROVEN
    ///         checkpoint"; T-A8-4). Installing a base checkpoint is itself governed —
    ///         see `baseInstallAuthority` in §8; it is NOT a plain permissionless
    ///         append, because it does not chain onto stored state.
    /// @param imageId  Guest image ID; router checks it against the registry (R5),
    ///                  then passes it to the verifier (A3). NOT caller-trusted.
    /// @param journal  The exact hg-claims journal buffer (one buffer, no re-encode
    ///                  — A4/T-A4-5). Router decodes fields from THIS slice and the
    ///                  verifier's digest is computed over THIS slice.
    /// @param seal     Vendor proof bytes.
    /// @return nonce   The ledger index assigned to the installed checkpoint.
    function submitBaseCheckpoint(bytes32 imageId, bytes calldata journal, bytes calldata seal)
        external
        returns (uint64 nonce);

    /// @notice Submit a checkpoint EXTENSION (claim 0x0002) that folds exactly one
    ///         new certificate onto the current stored checkpoint. PERMISSIONLESS
    ///         (A9): any address may submit. Soundness rests on the proof; liveness
    ///         on anyone. Contract-side chaining (A10):
    ///           - journal.anchor_mode MUST be ANCHOR_MODE_EXTERNAL (1). A mode-2
    ///             (composed) extension is rejected here — that is the offline/CLI
    ///             path, not the router's (ADR-002 D4). (R7 + AnchorModeUnsupported.)
    ///           - journal.prev_tip_hash (E3) MUST equal the stored checkpoint's
    ///             tip_hash (StaleAnchor otherwise — the A10 old-checkpoint
    ///             regression defense; T-A10-1).
    ///           - STORING GATE: H5 verdict MUST be 0 before the ledger write — a
    ///             journaled REJECTION (nonzero verdict) is a valid proof and passes
    ///             R1..R7, but must never be stored as a live checkpoint
    ///             (RejectedCheckpointNotStorable; T-A8-4).
    ///           - chain_length MUST equal stored chain_length + 1 (extend-BY-ONE,
    ///             CLAIMS §3.2; BadChainLength otherwise). This IS the strict-progress
    ///             key: every extension is prev+1 (CLAIMS §3.2, E5-E17), so
    ///             chain_length is strictly monotone BY CONSTRUCTION for BOTH
    ///             extension shapes — no separate strict-epoch rule is needed.
    ///           - tip_epoch MUST be NON-DECREASING over the stored tip_epoch
    ///             (EpochRegression otherwise) — NOT strictly increasing. A same-epoch
    ///             extension (AVK unchanged, tip_epoch CONSTANT, mithril.rs:298-308)
    ///             is the DOMINANT case: mainnet emits ~765 CardanoTransactions certs
    ///             per 5-day epoch vs ~1 epoch-boundary crossing
    ///             (mithril-recursion-watch §3), and intra-epoch tip freshness (~10 min)
    ///             is the exact liveness path ADR-002 serves. A strict rule would
    ///             reject ~765 of every 766 legitimate extensions; only a strictly
    ///             DECREASING epoch is a regression.
    ///           - MINIMUM-PROGRESS RULE (A13, MANDATORY): the extension MUST advance
    ///             `ctx_block_number` by at least `minProgress` (BelowMinProgress
    ///             otherwise). Keyed on ctx_block_number, NOT epoch/slot, because the
    ///             dominant same-epoch extension advances block height within a
    ///             CONSTANT epoch (a front-run that does not advance the block is the
    ///             attack). Requires has_certified_transactions == 1 on both states.
    ///             This closes the valid-proof front-run that stalls progress
    ///             (Blobstream0 V-BLOB-VUL-001; T-A13-1). The numeric minProgress is
    ///             a deploy-time param sized after M0 latency.
    /// @return nonce   The new ledger index (stored + 1). Consumers reference it.
    function submitExtension(bytes32 imageId, bytes calldata journal, bytes calldata seal)
        external
        returns (uint64 nonce);

    /// @notice Verify a NON-checkpoint claim (header-segment 0x0003, tx-inclusion
    ///         0x0004, utxo-read 0x0005) against a stored checkpoint, WITHOUT
    ///         storing anything. Pure verification for consumers that want the
    ///         router to attest a fact on-demand; the fact is returned/evented, not
    ///         persisted (these claims are reads, not state transitions).
    /// @dev    For 0x0004/0x0005 in mode 1, the router binds the journal's anchor
    ///         fields (anchor_tip_hash I3/U3, certified_root I4/U4) to a STORED
    ///         checkpoint identified by `anchorNonce` (R6): anchor_tip_hash ==
    ///         ledger[anchorNonce].tip_hash AND certified_root == that checkpoint's
    ///         ctx_merkle_root (which requires has_certified_transactions == 1 on
    ///         that checkpoint; NoCertifiedTxSet otherwise). Mode 2 is rejected here
    ///         (composed anchors are the offline path). 0x0003 has no Mithril anchor
    ///         (CLAIMS §3.3) — it is verified and evented as not-canonical-alone.
    ///         Reverts on any R1..R7 failure; R8 (read H5) NEVER reverts — a nonzero
    ///         verdict is a journaled rejection that is RETURNED, not reverted (a valid
    ///         proof of a rejection, NOT a proof of negation — CLAIMS §4.3). verifyClaim
    ///         is a READ (non-storing), so unlike the two storing paths it has no
    ///         verdict==0 gate. On success emits ClaimVerified.
    /// @param anchorNonce  Ledger index of the checkpoint this claim anchors to
    ///                     (domain = checkpointNonce). Ignored for 0x0003.
    /// @return verdict     The journaled H5 verdict code (0 = accepted).
    function verifyClaim(
        bytes32 imageId,
        bytes calldata journal,
        bytes calldata seal,
        uint64 anchorNonce
    ) external returns (uint16 verdict);

    // ═════════════════════════════ Views (§6) ═════════════════════════════════

    /// @notice The current head checkpoint nonce (highest appended). Consumers read
    ///         head, then `checkpointAt(head)`.
    function headNonce() external view returns (uint64);

    /// @notice The stored checkpoint at a ledger nonce. Reverts UnknownCheckpoint()
    ///         for a nonce that was never appended. NEVER reverts for a superseded
    ///         one — old checkpoints are retained (append-only; A8/A9).
    /// @dev    checkpointNonce domain (A14). The returned struct mirrors the
    ///         hg-claims CheckpointState the router extracted and verified.
    function checkpointAt(uint64 nonce) external view returns (StoredCheckpoint memory);

    /// @notice The configured network magic (ADR-003 D4). Deploy-time immutable.
    function networkId() external view returns (uint32);

    /// @notice The configured minimum-progress parameter (A13). Deploy-time param.
    function minProgress() external view returns (uint64);

    /// @notice The registry and vendor-verifier this router is wired to (immutables
    ///         set at deploy; A14 T-A14-3 diffs these against the deploy fixture).
    function registry() external view returns (address);
    function vendorVerifier() external view returns (address);

    // ═════════════════════════════ Events ═════════════════════════════════════

    /// @notice A checkpoint was appended (base install or extension). Indexers
    ///         track the head from this (lightclient-patterns §5, HeadUpdate-shape).
    event CheckpointAppended(
        uint64 indexed nonce,
        bytes32 indexed tipHash,
        uint64 tipEpoch,
        uint32 chainLength,
        bool isBase
    );

    /// @notice A non-storing claim (0x0003/0x0004/0x0005) was verified on-chain.
    ///         Carries the verdict so consumers/indexers see accepts AND journaled
    ///         rejections (CLAIMS §4).
    event ClaimVerified(uint16 indexed claimType, uint64 indexed anchorNonce, uint16 verdict, bytes32 factId);
}

/// @dev Mirror of the hg-claims CheckpointState the router persists. Field domains
///      documented at IHeliographRouter's key-domain block (A14).
struct StoredCheckpoint {
    bytes32 rootHash;            // S1 — genesis cert content hash (carried verbatim)
    bytes32 tipHash;            // S2 — tip cert content hash; the chain identity (E3 binds here)
    uint64  tipEpoch;           // S3 — Cardano EPOCH (monotonic across extensions)
    uint32  chainLength;        // S4 — hops from genesis (extend-by-one: +1)
    bytes32 avkCommitment;      // S5
    bytes32 nextAvkCommitment;  // S6
    uint64  stmK;               // S7
    uint64  stmM;               // S8
    uint32  stmPhiFFixed;       // S9 — U8F24 fixed-point (no float on-chain)
    bool    hasCertifiedTx;     // S10 — presence flag gating ctx* (ADR-003 D3)
    bytes32 ctxMerkleRoot;      // S11 — certified tx-set root (anchor for 0x0004/0x0005)
    uint64  ctxEpoch;           // S12 — Cardano EPOCH of the certified set
    uint64  ctxBlockNumber;     // S13 — Cardano BLOCK NUMBER of the certified set
}
```

---

## 6. Checkpoint storage — the append-only nonce ledger (A8, A9, A10)

Recommendation adopted from lightclient-patterns §6.4: **the append-only nonce
ledger** (Blobstream0's `merkleRoots[proofNonce]` shape), not latest-only and not
a head-keyed history mapping.

```solidity
// Conceptual storage (implementation detail; shown for the invariant it enforces).
mapping(uint64 => StoredCheckpoint) internal _ledger;  // checkpointNonce → state
uint64 internal _headNonce;                             // highest appended nonce
```

- **`checkpointNonce` key domain** (A14): a monotonic append counter starting at
  the base install's nonce. It is **not** a Cardano value — not an epoch, not a
  slot, not a block number. Consumers pin a checkpoint by nonce and that reference
  is stable forever; nothing the router does can orphan it (no reorg of *our*
  mapping, no overwrite). This is the property latest-only and head-keyed mappings
  lack (lightclient-patterns §6.4).
- **Append-only, enforced structurally (A8 T-A8-1):** the ONLY writes to
  `_ledger` are `_ledger[_headNonce + 1] = newState; _headNonce += 1` inside
  `submitExtension`, and the base install inside `submitBaseCheckpoint`. **No
  function overwrites an existing `_ledger[n]`, and no admin path reaches
  `_ledger` at all.** The enumerated-selector test (T-A8-1) fails if any
  state-rewriting selector is ever added. There is no `adminSetTrustedState`,
  no `setCheckpoint`, no `forceCheckpoint` — by construction (A8; ADR-002 D4).
- **Extension chaining reads `_ledger[_headNonce]`** (the current head) and binds
  `journal.prev_tip_hash == _ledger[_headNonce].tipHash` + monotonic
  `tipEpoch` + `chainLength + 1` + minimum-progress (A10/A13, §5). An extension
  of a non-head checkpoint (`prev_tip_hash` matches an old `_ledger[n]`, n <
  head) is a `StaleAnchor` revert — the A10 old-checkpoint regression defense
  (T-A10-1).
- **Base install after genesis** (re-genesis cutover, A11) starts a **new nonce
  run** but does not delete old entries; portable verdicts rooted at the old
  anchor remain independently verifiable and old ledger entries stay readable
  (A11 residual-risk: consumers holding cross-re-genesis verdicts must re-check
  the journaled anchor against the new root — a documented consumer obligation).

---

## 7. Custom errors — the complete set (each MUST get a T-A8-4 negative test)

THREAT_MODEL A8 T-A8-4: *"every custom error declared in the router ABI is
exercised by at least one negative test, and every revert path in every logical
branch has a negative test … any unreached selector fails the gate."* Zellic 3.5
(dead selectors mask missing constraints) is why this list is exhaustive and why
each entry names the check it guards and the R-rule / adversary it enforces. **A
declared error with no negative test, or a check with no declared error, fails
the gate.**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title HeliographErrors — every router/registry revert selector.
/// @notice Each error below MUST have a negative test (A8 T-A8-4). The comment on
///         each names the fail-closed check it fires on and the ADR-003 R-rule /
///         THREAT_MODEL adversary it enforces. No dead selectors (Zellic 3.5).
interface IHeliographErrors {
    // ── ADR-003 D7 decode-and-reject order (R1..R8) ────────────────────────────
    error BadJournalLength(uint256 got, uint256 expected); // R1 length gate (A4/T-A4-5)
    error UnknownClaimVersion(uint16 version);             // R2 version ∉ accepted set (A4)
    error DraftVersionRejected();                          // R2 claim_version == 0 DRAFT (CLAIMS §1.3)
    error UnknownClaimType(uint16 claimType);              // R3 claim_type not accepted here
    error WrongNetwork(uint32 got, uint32 expected);       // R3 network_id mismatch (A2/T-A2-1)
    error GenesisAnchorMismatch(bytes32 got, bytes32 pinned); // R4 genesis_vkey ≠ registry (A11/R4)
    error UnknownImageId(bytes32 imageId);                 // R5 imageId ∉ registry (A3/A8)
    error UnknownInnerImageId(bytes32 innerImageId);       // R5 journaled inner id ∉ registry (A3/T-A3-2)
    error AnchorBindingFailed();                           // R6 mode-1 anchor ≠ stored state (A10)
    error BadPresenceFlag(uint256 offset, uint8 value);    // R7 presence flag ∉ {0,1} (ADR-003 D3)
    error BadDiscriminant(uint256 offset, uint8 value);    // R7 datum_kind ∉ {0,1,2} / bad enum (D3)
    error GatedPayloadConsumed(uint256 offset);            // R7 consumed a slot while its flag == 0 (D3)
    error BandViolation(uint256 offset);                   // R7 e.g. spend_status != 0 on 0x0005 (CLAIMS U12)

    // ── Contract-side checkpoint chaining (ADR-002 D4; A10/A13) ────────────────
    error AnchorModeUnsupported(uint8 mode);   // router accepts mode 1 only; mode 2 is offline (D4)
    error StaleAnchor(bytes32 prevTipHash, bytes32 headTipHash); // prev_tip_hash ≠ head (A10/T-A10-1)
    error EpochRegression(uint64 got, uint64 head);             // tip_epoch strictly DECREASED (non-decreasing rule; same-epoch is valid) (A10)
    error BadChainLength(uint32 got, uint32 expected);          // chain_length ≠ head+1 (extend-by-one, THE strict-progress key, CLAIMS §3.2)
    error BelowMinProgress(uint64 advance, uint64 minProgress); // ctx_block_number advance < minProgress (A13/T-A13-1, MANDATORY)
    error RejectedCheckpointNotStorable(uint16 verdict);        // H5 verdict != 0 on a storing path — a proof-of-rejection may not become a live checkpoint (A8/T-A8-4)
    error NoCertifiedTxSet(uint64 anchorNonce);                 // anchor checkpoint has_certified_transactions == 0 (0x0004/0x0005)
    error UnknownCheckpoint(uint64 nonce);                      // anchorNonce/read of a never-appended nonce

    // ── Base-checkpoint install authority (§8; A8/A11 governed cutover) ────────
    error NotBaseInstallAuthority(address caller); // base install is not a plain permissionless append

    // ── Registry (A8; timelock governance) ─────────────────────────────────────
    error NotAdmin(address caller);            // caller ∉ admin (custody = §9 gate 3)
    error TimelockNotElapsed(uint64 executableAt); // execute before delay (A8 T-A8-2)
    error UnknownProposal(bytes32 proposalId);     // execute/cancel a nonexistent proposal
    error ProposalCancelled(bytes32 proposalId);   // execute a cancelled proposal
    error DuplicateProposal(bytes32 proposalId);   // propose an already-pending change (salt collision guard)
    error ZeroImageId();                           // reject adding the zero image id (footgun guard)
    error ZeroGenesisAnchor();                     // reject setting/deploying a zero genesis anchor (registry AND deploy)

    // ── Deploy-time (constructor) guards (§8; A14 T-A14-1/3, A8) ───────────────
    error ZeroMinProgress();                       // minProgress == 0 defeats the A13 front-run defense
    error ZeroTimelockDelay();                     // timelockDelay == 0 is an instant admin (A8 anti-pattern)
    error UnsupportedNetwork(uint32 networkId);    // networkId ∉ {mainnet, preprod, preview} (A2 network magic)
}
```

Every custom error above is exercised by at least one negative test (T-A8-4);
this block is the **complete** revert-selector set — a router revert branch with
no declared error fails the T-A8-4 gate. The deploy-time guards
(`ZeroMinProgress`, `ZeroTimelockDelay`, `UnsupportedNetwork`, `ZeroGenesisAnchor`,
`ZeroImageId`) back the §8 constructor invariants and are covered by the
golden-deployment tests (T-A14-1/3).

**Coverage obligations this list creates (wired into `docs/journal-coverage.md`
and `contracts/test`):**

- Every selector above has a negative test that triggers exactly it (T-A8-4).
- Every R-rule (R1..R8) has at least one selector and one negative test; the
  fixed order is asserted (a version-bad-AND-length-bad journal reverts on the
  length gate R1 first — the cheapest most-discriminating check, ADR-003 D7).
- The extension-chaining errors (`StaleAnchor`, `EpochRegression`,
  `BadChainLength`, `BelowMinProgress`) are each pinned by a mutant fork test
  that FAILS if the corresponding check is deleted (the A10 load-bearing-checks
  ledger — THREAT_MODEL A10: every contract-side check is load-bearing or
  documented-redundant, redundancy proven by a test).

---

## 8. Constructor / deploy-time parameters (A14 — key domains at each mapping)

Deployment installs state **no proof ever checks** (THREAT_MODEL A14). The
sp1-helios 3.2 bug was a constructor keying a mapping by the wrong height domain
(beacon slot vs execution block number) and never initializing another. The
router carries three Cardano height domains plus the nonce; every one is
documented here at its parameter and asserted by T-A14-1/2/3 against a committed,
golden-tested deploy fixture (run against the ACTUAL deploy script, not a mock).

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title HeliographDeployParams — constructor inputs, each with its key domain.
/// @notice A14: deployment is a governed event using a committed, golden-tested
///         params fixture. Every field's domain is documented; the deploy script's
///         emitted params are round-tripped and diffed against the fixture
///         (T-A14-3). First-interaction reads succeed against constructor state
///         alone, before any update (T-A14-2 — the inverted sp1-helios 3.2 bug).
struct HeliographDeployParams {
    // ── Wiring (addresses; T-A14-3 diffs these) ───────────────────────────────
    address vendorVerifier;   // the IVendorVerifier adapter over the AUDITED vendor
                              //   verifier (§2). Domain = "contract address".
                              //   Selected by ADR-001; unowned by us (A8).
    address registry;         // the HeliographRegistry (§4). Domain = "contract addr".

    // ── Network + anchor binding (A2, A11) ─────────────────────────────────────
    uint32  networkId;        // Cardano network magic (ADR-003 D4). Domain =
                              //   "Cardano network". The router pins EXACTLY this
                              //   one; a proof for any other network reverts
                              //   WrongNetwork (A2). Fixture value is human-checked.
    bytes32 genesisVkey;      // Mithril genesis Ed25519 vkey for `networkId`
                              //   (CLAIMS.md H4). Domain = "Cardano Mithril genesis
                              //   anchor". Seeds the registry's genesisAnchor(net);
                              //   rotates on re-genesis via the registry (A11), never
                              //   here again.

    // ── Anti-griefing (A13) ────────────────────────────────────────────────────
    uint64  minProgress;      // MANDATORY minimum-progress parameter (A13). Domain =
                              //   ctx_block_number advance per extension (Cardano BLOCK
                              //   height), NOT epoch/slot — the dominant same-epoch
                              //   extension advances block height within a constant
                              //   epoch. Sized against measured proving latency after
                              //   M0 (ADR-002 D4); a value of 0 is REJECTED at deploy
                              //   (ZeroMinProgress — defeats the front-run defense,
                              //   V-BLOB-VUL-001).

    // ── Initial checkpoint (base case; A14 T-A14-2) ────────────────────────────
    // The router MAY be deployed with NO checkpoint (headNonce reads reverts
    // cleanly / returns sentinel) and receive its base via submitBaseCheckpoint,
    // OR seeded with a genesis-proven base at deploy. If seeded, EVERY field of the
    // initial StoredCheckpoint is documented by its CheckpointState domain (S1..S13,
    // §5 struct) and the initial checkpointNonce is fixed (domain = ledger index,
    // NOT a Cardano value). First-interaction reads (headNonce, checkpointAt,
    // verifyClaim against it) MUST succeed before any update — T-A14-2.
    bool             seedInitialCheckpoint;
    StoredCheckpoint initialCheckpoint;   // meaningful iff seedInitialCheckpoint
    uint64           initialNonce;        // ledger index for the seed; domain = checkpointNonce

    // ── Admin / timelock (A8; §9 gate 3 — key custody is a HUMAN decision) ─────
    address admin;            // registry admin (custody = §9 gate 3). Domain = addr.
    uint64  timelockDelay;    // registry timelock (seconds). Domain = "delay". A
                              //   value of 0 is REJECTED (an instant admin defeats
                              //   A8; SP1Helios "Constraints: None" is the anti-pattern).

    // ── Base-install authority (§5 submitBaseCheckpoint; A11 cutover) ──────────
    address baseInstallAuthority; // who may install/rotate the base checkpoint.
                              //   Domain = addr. Base install does NOT chain onto
                              //   stored state, so it is not a plain permissionless
                              //   append — it is governed (re-genesis cutover, A11).
                              //   MAY equal the timelock; MUST NOT be able to
                              //   overwrite an existing ledger entry (append-only,
                              //   A8 T-A8-1). Extensions stay PERMISSIONLESS (A9).
}
```

**Deploy-time invariants asserted by the golden-deployment tests (T-A14-1/2/3):**

- `minProgress != 0` and `timelockDelay != 0` (both zeros are A13/A8 footguns).
- `networkId ∈ {mainnet, preprod, preview}` and `genesisVkey != 0` — and the
  registry's `genesisAnchor(networkId)` returns exactly `genesisVkey` immediately
  after deploy (T-A14-1: every getter returns the fixture value under its domain).
- If `seedInitialCheckpoint`, then `headNonce() == initialNonce` and
  `checkpointAt(initialNonce)` returns `initialCheckpoint` field-for-field, and a
  `verifyClaim` for a 0x0004/0x0005 anchored at `initialNonce` succeeds against
  constructor state alone (T-A14-2 — the sp1-helios 3.2 failure inverted).
- The deploy script's emitted params parse back and diff clean against the
  committed fixture (T-A14-3 — script↔contract drift guard).

---

## 9. Open items for M4 review (not frozen here)

Recorded so the M4 router build resolves them explicitly, not by default:

1. **Permissionless emergency-stop** (RISC Zero `estop(Receipt)` circuit-breaker,
   risc0.md §4; THREAT_MODEL A8 "open design question"). Adopting an
   app-level circuit breaker over the heliograph router — anyone presenting a
   proof-of-unsoundness halts it permanently — is attractive but interacts with
   liveness (A9) and with the vendor verifier's own estop. **Decision deferred to
   M4**; if adopted, its irreversibility is pinned by a fork test.
2. **Renounce/freeze path on the registry.** Not in the §4 ABI. If added, its
   irreversibility is an ADR-recorded decision with a fork test (frozen registry
   still verifies already-accepted proofs, rejects all future mutations —
   THREAT_MODEL A8). Default: **not present**.
3. **`minProgress` numeric value** — post-M0 latency (ADR-002 D4; A13).
4. **Managed-router vs app-owned-router over the same audited base verifier**
   (RISC Zero supports both — risc0.md §4). This sketch assumes an **app-owned**
   thin router over the audited base verifier via `IVendorVerifier`; sitting on
   the vendor's managed router instead inherits the vendor's timelock/multisig
   trust. Decide at M4 with the vendor fixed (ADR-001).
5. **SP1 gateway ownership** (sp1.md open item 5; THREAT_MODEL A8 residual) —
   MUST be resolved before M4 if SP1 is selected; it is an admin surface upstream
   of ours that this sketch cannot close.
6. **Base-install authority shape** (§8 `baseInstallAuthority`): timelock-gated
   vs a dedicated governed key. Base install is rare (bring-up, re-genesis
   cutover) and does not chain onto stored state, so it is governed, not
   permissionless — but the exact custody is a §9-gate-3 human decision alongside
   the registry admin.

---

## 10. Traceability — every requirement in the task → where it is realized

| Requirement | Realized in |
|---|---|
| Realize ADR-002 (contract-side checkpoint chaining) | §5 `submitExtension` (prev_tip_hash == head, monotonic epoch, +1 length), §6 ledger |
| Vendor's AUDITED verifier held UNTOUCHED and unowned by us, beneath a thin router | §1 architecture, §2 `IVendorVerifier` (adapter only, forwards to audited/unowned) |
| Allowed-image-ID + trust-anchor registry behind a timelocked admin | §4 `IHeliographRegistry` (propose→timelock→execute) |
| Events at proposal time for indexer early-warning | §4 `ImageIdProposed`/`GenesisAnchorProposed` emitted at PROPOSE |
| Checkpoint storage = append-only nonce ledger (lightclient-patterns §6.4) | §6 `_ledger[nonce]` + `_headNonce` |
| prev_checkpoint == stored + strict `chain_length`+1 + non-decreasing `tip_epoch` enforced | §5 `StaleAnchor`, `BadChainLength`, `EpochRegression` |
| Minimum-progress parameter (mandatory, A13) | §5 `BelowMinProgress`, §8 `minProgress` param (0 rejected) |
| Explicit "no function mutates a stored checkpoint" (T-A8-1) | §4 (registry can't reach ledger), §6 (append-only, no rewrite selector), §7 (no such error because no such path) |
| Constructor/deploy params, each mapping key-domain documented (T-A14-1/2/3) | §8 `HeliographDeployParams` (three Cardano height domains + nonce, each at its field) |
| Cardano slot/height/epoch domains documented | §5 key-domain block, §6 nonce domain, §8 per-field domains |
| Solidity interface + NatSpec, not full impls | §2/§4/§5/§8 interfaces + `///` NatSpec throughout |
| Enumerate every custom error (each → a T-A8-4 negative test) | §7 `IHeliographErrors` (complete set, each names its check + adversary) |
| A4: hash exactly the bytes you decode; bindings-from-ABI | §1/§2 one-buffer-no-re-encode; §3 `Constants.sol` generated + CI-diffed |
| A14 key domains; A10 extension-only; A13 min-progress; A8 narrow admin | §8, §5/§6, §5/§8, §4 respectively |

---

## Citations

- **HANDOFF.md** §0 (fail-closed; journal-is-ABI; a proven verdict keeps its
  tier; Sextant unforked), §1 (mission; EVM verifier = vendor's audited verifier
  + thin claim-router), §4 Phase-1 ("Verifier contract design: vendor's audited
  verifier untouched; thin router above it; allowed-image-ID registry behind a
  timelocked admin … events designed for indexer consumption") + exit gate
  (contract interface sketch), §5 (`/contracts` layout; codec mirrored
  constant-for-constant in Solidity), §6 (vendor verifier byte-identical, never
  modified; pins are trust-anchor rotations), §9 gate 3 (admin/registry key
  custody; timelock), §11 (boring/explicit/canonical).
- **ADR-002** D1 (base case is its own claim type), D2 (anchor modes), D4 (router
  chains contract-side; mode-1 only; `prev_tip_hash == stored`; monotonic;
  no `adminSetTrustedState`; mandatory minimum-progress), D5 (0x0003/0x0004/0x0005
  compose the checkpoint), D6 (ADR-005 invariance).
- **ADR-003** D0 (one buffer, no re-encode — T-A4-5), D1 (flat fixed-offset
  BE layout), D2 (46-byte header offsets), D3 (presence flags / discriminants),
  D4 (network magic), D6 (verdict table), D7 (R1..R8 decode-and-reject order),
  D8 (bindings generated from ABI — T-A4-4); the per-claim body length tables
  (LEN_* = 255/328/170/191/269) and the CheckpointState 209-byte group offsets.
- **ADR-004** (image ID is the trust anchor the registry allowlists; one image
  serves all networks/eras so re-genesis is a registry rotation, not an image
  bump — D4).
- **THREAT_MODEL.md** A2 (network binding / `WrongNetwork`), A3 (image-ID
  registry binding; inner-ID journaled — `UnknownImageId`/`UnknownInnerImageId`),
  A4 (one-buffer / bindings-from-ABI — §1/§2/§3), A8 (narrow admin: timelocked
  registry, no state-rewrite, events at propose, T-A8-1 no-mutation ABI, T-A8-2
  timelock+event, T-A8-4 every-error-a-negative-test; SP1 gateway ownership
  residual), A9 (permissionless submission), A10 (extension-only + monotonic;
  load-bearing-checks ledger; T-A10-1), A11 (re-genesis anchor rotation via
  registry; T-A11-2 drill), A13 (mandatory minimum-progress + front-run race;
  T-A13-1), A14 (deploy params + key-domain-at-each-mapping; T-A14-1/2/3).
- **docs/notes/lightclient-patterns.md** §2b (storage shapes; admin ladder), §3
  (contract-side chaining is the on-chain pattern; genesis base case distinct),
  §4.3/§4.4 (griefing minimum; `adminSetTrustedState` anti-pattern), §5 (events
  feed indexers), §6.3 (admin powers heliograph owns), §6.4 (**append-only nonce
  ledger never orphans a consumer reference — recommended**), §6.5
  (minimum-progress).
- **docs/notes/risc0.md** §4 (`IRiscZeroVerifier.verify(seal, imageId,
  journalDigest)`, `journalDigest = sha256(journal)`; router `TimelockController`
  + tombstoned selectors + permissionless `estop(Receipt)` circuit breaker;
  Base Sepolia 84532 addresses; managed-router-vs-app-router both supported).
- **docs/notes/sp1.md** §4 (`ISP1Verifier.verifyProof(programVKey, publicValues,
  proofBytes) view`; `programVKey` = image-ID pattern; gateway ownership
  undocumented — resolve before M4).

---

## HANDOFF — for the M4 (EVM verifier + SDK) build

- **This is an interface sketch, not an implementation.** M4 builds
  `HeliographRouter`, `HeliographRegistry`, and the selected vendor's
  `IVendorVerifier` adapter in the Foundry project (`/contracts`, HANDOFF §5),
  with the vendor fixed by ADR-001.
- **`Constants.sol` is generated, not written** (ADR-003 D8): produce it from the
  `hg-claims` `const` block and CI-diff it (T-A4-4). Do not hand-type an offset.
- **Every §7 error gets a negative test** before M4 is done (T-A8-4); every
  extension-chaining check gets a delete-it-and-it-fails mutant test (A10 ledger).
- **Deploy against the golden fixture, tested via the actual deploy script**
  (T-A14-1/2/3), not a mock. `minProgress` and `timelockDelay` are set from
  post-M0 numbers; both-zero is rejected at deploy.
- **Resolve the §9 open items with the vendor fixed:** emergency-stop adoption,
  managed-vs-app router, base-install authority custody (§9 gate 3), and — if SP1 —
  the gateway ownership question (sp1.md open item 5). None of these change the
  ABI shape frozen here; they parameterize it.
- **Testnet deployment is a §9 gate 1 human touchpoint** (Base Sepolia, the signed
  `EVM_TESTNET`); the accept ⇔ local-verify ⇔ native-verdict fork tests
  (HANDOFF §7) exercise this whole ABI end-to-end.
