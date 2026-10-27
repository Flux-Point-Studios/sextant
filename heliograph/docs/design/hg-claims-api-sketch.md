# `hg-claims` API sketch — the canonical journal codec

- **Status:** DESIGN sketch (Phase 1). Signatures + doc comments, not impls.
- **Realizes:** ADR-003 (journal-as-ABI canonical codec, v1 frozen layout) and
  `docs/CLAIMS.md` v0 (field sets + semantics). Where this sketch and ADR-003's
  body-layout tables disagree on an offset, **ADR-003's `const` block and the
  golden vectors win** (ADR-003 §"Per-claim body layouts" closing note); this
  file transcribes them, it does not re-derive them.
- **Crate:** `hg-claims` (ADR-000 §Decision-2), `#![no_std]` + `extern crate
  alloc` (HANDOFF §5; ADR-003 D0). Published free (ADR-000 sweep).
- **Consumers (D0):** `hg-guest` writes journals; `hg-host` + `hg-sdk-ts` read
  them; `/contracts` router mirrors the constants. **One encode + one decode per
  claim type, over one flat buffer** — no decode→re-encode→hash round-trip
  (ADR-003 D0 / T-A4-5 / Veridise V-BLOB-VUL-004).
- **Sextant is cited, never re-derived** (HANDOFF §0 precedence 3). Every field
  that commits a Sextant value carries it verbatim; the citations are to
  `docs/notes/sextant-legs.md` and Sextant `@ 3a68b2f`.

This is the crate the whole schema hangs on. It is deliberately boring: a
`const` block, a set of `#[repr(u16)]`/`#[repr(u8)]` enums with fixed numeric
values, and one typed accessor per field. There is no serde, no derive-based
wire format, no framing (ADR-003 D1, Alternative-3). The buffer *is* the ABI.

---

## 0. Module map

```text
hg-claims/
  src/
    lib.rs          #![no_std]; extern crate alloc; re-exports; crate-level invariants doc
    consts.rs       the SINGLE source of truth: OFFSET_*/W_*/LEN_* + magics (D0/D8)
    version.rs      ClaimVersion (H1)                — unknown ⇒ fail-closed
    claim_type.rs   ClaimType     (H2)               — unknown ⇒ fail-closed
    network.rs      NetworkId     (H3, D4 magics)    — unknown ⇒ fail-closed
    verdict.rs      Verdict       (H5, D6 table)     — 1:1 SextantStatus, u16
    header.rs       JournalHeader (H1..H6) view + encode
    state.rs        CheckpointState (S1..S13) view + encode; presence-gated tx group (D3)
    anchor.rs       AnchorMode (§2.3) + AnchorBinding (inner_image_id) shared group
    body/
      checkpoint.rs           0x0001
      checkpoint_extension.rs 0x0002
      header_segment.rs       0x0003
      tx_inclusion.rs         0x0004
      utxo_read.rs            0x0005
    decode.rs       the fixed R1..R8 decode-and-reject pipeline (D7)
    error.rs        DecodeError — every fail-closed reason, distinct variant
    codegen.rs      (build-time) emits Constants.sol from consts.rs (D8)
```

`consts.rs` is normative over every table below. `codegen.rs` mechanically emits
`Constants.sol` for the Solidity mirror **and** the host/SDK read the same
constants from the compiled router ABI, CI-diffed — no constant is hand-typed in
two places (ADR-003 D8 / T-A4-4 / Zellic sp1-helios 3.3).

---

## 1. The constant block (`consts.rs`) — single source of truth

Every offset/width/length below is transcribed from ADR-003 D2 and the per-claim
body tables. The golden vectors (Phase-2) pin the bytes; if any arithmetic here
slips, the vector is authoritative (ADR-003 HANDOFF).

```rust
//! The one place any offset, width, length, network magic, or verdict code is
//! written. `hg-guest`, `hg-host`, `hg-sdk-ts` read from here; `codegen.rs`
//! emits `Constants.sol` from here (ADR-003 D0/D8). Nothing downstream hard-codes
//! a literal offset — that is what makes the four-surface mirror one source.

// ── Common header (ADR-003 D2) — 46 bytes, identical for every claim type ──
pub const HDR_OFF_VERSION:      usize = 0;   pub const HDR_W_VERSION:      usize = 2;
pub const HDR_OFF_CLAIM_TYPE:   usize = 2;   pub const HDR_W_CLAIM_TYPE:   usize = 2;
pub const HDR_OFF_NETWORK_ID:   usize = 4;   pub const HDR_W_NETWORK_ID:   usize = 4;
pub const HDR_OFF_GENESIS_VKEY: usize = 8;   pub const HDR_W_GENESIS_VKEY: usize = 32;
pub const HDR_OFF_VERDICT:      usize = 40;  pub const HDR_W_VERDICT:      usize = 2;
pub const HDR_OFF_REJECT_INDEX: usize = 42;  pub const HDR_W_REJECT_INDEX: usize = 4;
pub const HDR_LEN:              usize = 46;
pub const BODY_OFF:             usize = 46;

// ── CheckpointState shared group (ADR-003 §CheckpointState) — 209 bytes ──
// Offsets are WITHIN the group; add BODY_OFF (0x0001) or BODY_OFF+73 (0x0002).
pub const CS_OFF_ROOT_HASH:        usize = 0;    pub const CS_W_HASH:  usize = 32;
pub const CS_OFF_TIP_HASH:         usize = 32;
pub const CS_OFF_TIP_EPOCH:        usize = 64;   pub const CS_W_U64:   usize = 8;
pub const CS_OFF_CHAIN_LENGTH:     usize = 72;   pub const CS_W_U32:   usize = 4;
pub const CS_OFF_AVK_COMMITMENT:   usize = 76;
pub const CS_OFF_NEXT_AVK_COMMIT:  usize = 108;
pub const CS_OFF_STM_K:            usize = 140;
pub const CS_OFF_STM_M:            usize = 148;
pub const CS_OFF_STM_PHI_F_FIXED:  usize = 156;  // u32, U8F24 (mithril.rs:892-894)
pub const CS_OFF_HAS_CERT_TXS:     usize = 160;  pub const CS_W_U8:    usize = 1;
pub const CS_OFF_CTX_MERKLE_ROOT:  usize = 161;  // S11 — presence-gated by S10 (D3)
pub const CS_OFF_CTX_EPOCH:        usize = 193;
pub const CS_OFF_CTX_BLOCK_NUMBER: usize = 201;
pub const CS_LEN:                  usize = 209;

// ── Anchor-binding shared group (§2.3) — 33 bytes, prefix of 0x0002/0x0004/0x0005 ──
pub const ANCHOR_OFF_MODE:           usize = 0;   // u8, {1,2}
pub const ANCHOR_OFF_INNER_IMAGE_ID: usize = 1;   // [u8;32], zeroed in mode 1
pub const ANCHOR_LEN:                usize = 33;

// ── Per-claim total lengths (ADR-003) — the length gate R1 keys on these ──
pub const LEN_CHECKPOINT:           usize = 255; // 46 + 209
pub const LEN_CHECKPOINT_EXTENSION: usize = 328; // 46 + 73 + 209
pub const LEN_HEADER_SEGMENT:       usize = 170; // 46 + 124
pub const LEN_TX_INCLUSION:         usize = 191; // 46 + 145
pub const LEN_UTXO_READ:            usize = 269; // 46 + 223

// ── Network magics (ADR-003 D4) — Cardano network magic, u32 BE ──
pub const NET_MAGIC_MAINNET: u32 = 764_824_073; // 0x2D96_4A09
pub const NET_MAGIC_PREPROD: u32 = 1;
pub const NET_MAGIC_PREVIEW: u32 = 2;

/// `LEN[claim_type]` for the R1 length gate. Returns `None` for any
/// claim_type this codec does not decode (deferred 0x0006–0x0008, bench band,
/// invalid 0x0000) → R1 fail-closed.
pub const fn expected_len(t: ClaimType) -> usize;
```

Bodies below re-list per-claim offsets as `const` for `codegen.rs`; only the
delta from the shared groups is spelled out per claim (checkpoint = header +
`CheckpointState`; the three anchored claims = header + `ANCHOR` + body tail).

---

## 2. Fail-closed enums — fixed numeric values, unknown ⇒ reject

Every enum here is a **decode gate**: an out-of-set byte is a `DecodeError`, not
a silently-tolerated value (CLAIMS §1.4; ADR-003 D7 R2/R3/R7). None derive
`Default` — there is no "zero-valued default" that could mask an unset field.

### 2.1 `ClaimVersion` (H1, `u16`)

```rust
/// Journal schema version (CLAIMS H1/§1.3). A single monotonic `u16` covering
/// the ENTIRE schema — header + every body + verdict table + this codec. Any
/// change to field set, order, type, semantics, verdict codes, or encoding
/// increments it. There are no minor versions.
///
/// `0` is reserved DRAFT: rejected unconditionally in every production verifier
/// (CLAIMS §1.3). Pre-freeze `hg-guest` emits `0`, so no draft-era proof is ever
/// accepted. `V1` is assigned at the CLAIMS v1 freeze (Phase-2, CLAIMS §1.3).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClaimVersion {
    Draft = 0,
    V1 = 1,
}

impl ClaimVersion {
    /// Decode a raw `u16`. `Ok(Draft)`/`Ok(V1)` for known values; any other
    /// value ⇒ `Err(DecodeError::UnknownVersion(raw))` — fail-closed, no
    /// "best-effort" decode of an unknown layout (the Steel `validateCommitment`
    /// lesson generalized, CLAIMS §1.3; ADR-003 D7 R2).
    pub fn from_u16(raw: u16) -> Result<Self, DecodeError>;
    pub const fn as_u16(self) -> u16;
}
```

**Verifier note (R2):** decoding a version is *not* accepting it. Each verifier
pins the explicit set it accepts (normally `{V1}`); `Draft` decodes but is
rejected by policy in every production path (`decode.rs` R2). This keeps
"is this a version I recognize" (codec) separate from "is this a version I
accept" (policy) — a downgrade to a *known-but-old* version still rejects.

### 2.2 `ClaimType` (H2, `u16`)

```rust
/// Selects body layout + semantics (CLAIMS §2.1 registry). `claim_type` is the
/// SECOND journal field so a shared image with claim dispatch is fail-closed on
/// unknown type (the sp1-vector claim-type-first precedent,
/// lightclient-patterns §3; ADR-003 D2).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClaimType {
    Checkpoint          = 0x0001, // Sextant Leg 2 verify_chain_anchored
    CheckpointExtension = 0x0002, // Leg 2 extend-by-one (ADR-002)
    HeaderSegment       = 0x0003, // Leg 1 verify_segment
    TxInclusion         = 0x0004, // Leg 3 verify_tx_inclusion
    UtxoRead            = 0x0005, // Leg 4 verify_utxo_read
}

impl ClaimType {
    /// `0x0001..=0x0005` decode. `0x0000` (invalid, never emitted), the deferred
    /// band `0x0006..=0x0008`, the `0x0F00..=0x0FFF` bench band, and every other
    /// value ⇒ `Err(DecodeError::UnknownClaimType(raw))` (CLAIMS §2.1; ADR-003
    /// D7 R3). Deferred types are reserved, NOT decodable here — a later addition
    /// is an extension, never a re-layout of 0x0001–0x0005 (ADR-003 §Scope).
    pub fn from_u16(raw: u16) -> Result<Self, DecodeError>;
    pub const fn as_u16(self) -> u16;

    /// `true` iff this claim type carries an `AnchorMode`/`inner_image_id` prefix
    /// (§2.3): CheckpointExtension, TxInclusion, UtxoRead. Checkpoint and
    /// HeaderSegment do not. Drives which body view the decoder constructs.
    pub const fn has_anchor_binding(self) -> bool;

    /// Byte length of a complete journal of this type (`consts::expected_len`);
    /// the R1 length gate reads this before trusting any field.
    pub const fn expected_len(self) -> usize;
}
```

### 2.3 `NetworkId` (H3, `u32` — Cardano network magic, D4)

```rust
/// Explicit network binding — the Steel `configID` lesson: a portable verdict is
/// self-describing, with no contract required to supply context
/// (lightclient-patterns §2c; CLAIMS H3). Cardano network magic, `u32` BE
/// (ADR-003 D4), NOT a config-digest (heliograph binds params S7–S9 and genesis
/// H4 explicitly and separately, so a digest would only reduce legibility).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NetworkId(u32);

impl NetworkId {
    pub const MAINNET: NetworkId = NetworkId(consts::NET_MAGIC_MAINNET);
    pub const PREPROD: NetworkId = NetworkId(consts::NET_MAGIC_PREPROD);
    pub const PREVIEW: NetworkId = NetworkId(consts::NET_MAGIC_PREVIEW);

    /// Any `u32` is a structurally-valid magic (private/devnets are other
    /// values), so this never fails at decode — the FAIL-CLOSED check is at the
    /// verifier (R3), which pins the exact set it accepts (normally one) and
    /// rejects an unrecognized magic. Kept as a newtype (not a closed enum) so a
    /// devnet magic round-trips without a schema change; the router, not the
    /// codec, is the network allowlist (ADR-003 D4).
    pub const fn from_u32(raw: u32) -> Self;
    pub const fn as_u32(self) -> u32;
    pub const fn is_known(self) -> bool; // mainnet/preprod/preview
}
```

### 2.4 `Verdict` (H5, `u16` — Sextant `SextantStatus` 1:1, D6)

```rust
/// H5 verdict (CLAIMS H5/§4). `0` = accepted; nonzero = a JOURNALED rejection
/// (data, not a panic). Adopts Sextant `SextantStatus` `#[repr(i32)]` band values
/// 1:1, VERBATIM, no lossy collapsing — one journal code per Sextant variant
/// (CLAIMS §4.1; ADR-003 D6; Sextant ffi.rs:83-136, SEXTANT_ABI_VERSION = 5).
///
/// `u16` (not `i32`) is deliberate: Sextant's negative codes (ErrNullPointer −1
/// … ErrPanic −9) are boundary/caller errors that NEVER journal — a guest panic
/// yields no proof and therefore no verdict (CLAIMS §4.4). Using `u16` makes
/// "no negative verdict is journalable" a TYPE-LEVEL fact (ADR-003 D6, Alt-7).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Verdict {
    Ok = 0,

    // ── header-leaf band (reachable on 0x0003) ──
    DecodeMalformedCbor     = 100,
    DecodeUnsupportedEra    = 101,
    DecodeBadHashLen        = 102,
    DecodeTrailingBytes     = 103,
    VrfInvalidGamma         = 110,
    VrfInvalidPublicKey     = 111,
    VrfSmallOrderPublicKey  = 112,
    VrfVerificationFailed   = 113,
    KesOpCertInvalidSignature = 120,
    KesInvalidSignature     = 121,
    KesPeriodOutOfRange     = 122,

    // ── praos-chain band (0x0003) ──
    ChainDecode     = 200,
    ChainBrokenLink = 201,
    ChainOpCert     = 202,
    ChainVrf        = 203,
    ChainKes        = 204,

    // ── mithril-chain band (0x0001, 0x0002) ──
    MithrilChainEmpty      = 300,
    MithrilChainHash       = 301,
    MithrilChainBrokenLink = 302,
    MithrilChainAvkBinding = 303,

    // ── mithril-genesis band (0x0001) ──
    MithrilGenesisNotGenesis        = 310,
    MithrilGenesisMalformedSignature = 311,
    MithrilGenesisMessageMismatch   = 312,
    MithrilGenesisInvalidSignature  = 313,

    // ── mithril-standard band (0x0001, 0x0002) ──
    MithrilStdNotStandard         = 320,
    MithrilStdMessageMismatch     = 321,
    MithrilStdWeakParameters      = 322,
    MithrilStdImplausibleAvk      = 323,
    MithrilStdMalformedAvk        = 324,
    MithrilStdMalformedSignature  = 325,
    MithrilStdInvalidMultiSignature = 326,
    MithrilStdMalformedCertJson   = 327,

    // ── inclusion band (0x0004, 0x0005) ──
    UtxoInclusionNotIncluded     = 400,
    UtxoInclusionRootMismatch    = 401,
    UtxoInclusionMalformedProof  = 402,

    // ── utxo band (0x0005) ──
    UtxoMalformedTx           = 410,
    UtxoOutputIndexOutOfRange = 411,
}

impl Verdict {
    /// Total, lossless mapping. Every reachable `SextantStatus` variant has
    /// exactly one code; every code maps back to exactly one variant. An
    /// unrecognized code ⇒ `Err(DecodeError::UnknownVerdict(raw))` (a code the
    /// guest could not have proved is a codec/guest defect — caught by the
    /// equality invariant T-A12-1, and here fail-closed).
    pub fn from_u16(raw: u16) -> Result<Self, DecodeError>;
    pub const fn as_u16(self) -> u16;

    pub const fn is_accept(self) -> bool; // == Ok

    /// `true` iff this code is reachable on `t` (the D6 "reachable on" column).
    /// The router does NOT separately whitelist codes-per-type (that would be a
    /// second encoding of reachability the guest already enforces — ADR-003 D6);
    /// this predicate exists for the golden corpus + the verdict-table mutants
    /// (T-A12-1), not as a runtime gate.
    pub const fn reachable_on(self, t: ClaimType) -> bool;
}
```

> **Build note (equality invariant, HANDOFF §7 / T-A12-1).** This enum is the
> heliograph half of the mapping to Sextant `SextantStatus` (ffi.rs:83-136).
> Sextant's exhaustive-match tripwire (ffi.rs:244-247 — a new tier fails to
> compile) protects the mapping *upstream*; a golden fixture per reachable code
> plus the guest==native comparison protects it here. The mapping table lives in
> `verdict.rs` and is the one place a Sextant-variant→`Verdict` correspondence is
> written.

---

## 3. Common header view (`header.rs`, H1–H6)

```rust
/// A zero-copy, validated view over the 46-byte common header of one journal
/// buffer (ADR-003 D2). Construction runs R2–R4 of the decode pipeline
/// (version/type/network/genesis are read here); the anchor/body checks (R5–R8)
/// run in the per-type body decoders. Holds a borrow of the ORIGINAL buffer —
/// there is no owned copy, so there is no second buffer to diverge (D0/T-A4-5).
pub struct JournalHeader<'a> {
    buf: &'a [u8], // the full journal buffer; header lives at [0, 46)
}

impl<'a> JournalHeader<'a> {
    /// Read + validate the header of `buf`. Runs: R2 version decode (unknown ⇒
    /// err), R3 claim_type decode (unknown ⇒ err). Does NOT run R1 length here
    /// (the caller `decode_journal` runs R1 first, having read type from offset 2)
    /// nor the R3 network-allowlist / R4 genesis-pin policy checks — those need
    /// the verifier's pinned expectations and live in the verifier, not the codec
    /// (ADR-003 D7). This constructor only decodes the self-contained header
    /// fields into typed values, fail-closed on unknown enum bytes.
    pub fn read(buf: &'a [u8]) -> Result<Self, DecodeError>;

    pub fn claim_version(&self) -> ClaimVersion; // H1 @ 0  (u16 BE)
    pub fn claim_type(&self) -> ClaimType;       // H2 @ 2  (u16 BE)
    pub fn network_id(&self) -> NetworkId;        // H3 @ 4  (u32 BE)
    pub fn genesis_vkey(&self) -> &'a [u8; 32];   // H4 @ 8  (raw)
    pub fn verdict(&self) -> Result<Verdict, DecodeError>; // H5 @ 40 (u16 BE)
    pub fn reject_index(&self) -> u32;            // H6 @ 42 (u32 BE)
}

/// Owned header field set — the `encode` input for `hg-guest`. Every field is a
/// typed value, so the guest cannot commit an out-of-set version/type/verdict.
pub struct HeaderFields {
    pub version: ClaimVersion,
    pub claim_type: ClaimType,
    pub network_id: NetworkId,
    pub genesis_vkey: [u8; 32],
    pub verdict: Verdict,
    pub reject_index: u32,
}

impl HeaderFields {
    /// Write the 46-byte header (big-endian) into `out[0..46]`. Called by every
    /// body encoder before the body bytes. `out` must be exactly
    /// `claim_type.expected_len()` long (the encoder allocates it once, D0).
    pub fn encode_into(&self, out: &mut [u8]);
}
```

**Rejection journals are full journals** (CLAIMS §4.2): the header + all
identity/anchor fields are populated even on `verdict != 0`; only payload fields
the verification never reached are zeroed. `reject_index` is meaningful only
when `verdict != 0` and the claim type defines it (H6 @ 42).

---

## 4. Shared field groups

### 4.1 `AnchorMode` + `AnchorBinding` (`anchor.rs`, §2.3)

Shared by `0x0002`, `0x0004`, `0x0005` as their 33-byte body prefix.

```rust
/// §2.3. `1` = external (verifier binds the anchor to independently-verified
/// state); `2` = composed (the guest verified an inner proof in-guest, inner
/// journal supplied the anchor). Any other value ⇒ reject (R7).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AnchorMode { External = 1, Composed = 2 }

impl AnchorMode {
    pub fn from_u8(raw: u8) -> Result<Self, DecodeError>; // {1,2} else UnknownAnchorMode
    pub const fn as_u8(self) -> u8;
}

/// The `{anchor_mode, inner_image_id}` prefix (§2.3). `inner_image_id` is the
/// image ID of the verified inner proof, committed VERBATIM — an inner image ID
/// that arrives as an input MUST be journaled or it is an unbound input
/// (lightclient-patterns §3; CLAIMS §1.2). Zeroed in External mode (D3-shaped:
/// present, zeroed, MUST NOT be consumed unless mode == Composed).
pub struct AnchorBinding<'a> { buf: &'a [u8] } // borrows the 33-byte prefix slice

impl<'a> AnchorBinding<'a> {
    pub fn mode(&self) -> Result<AnchorMode, DecodeError>; // @ +0

    /// The inner image ID — **only readable in Composed mode**. Returns
    /// `Ok(None)` in External mode (the slot is present and zeroed but MUST NOT
    /// be consumed, CLAIMS §2.3 / ADR-003 D3), `Ok(Some(&id))` in Composed mode.
    /// The "MUST NOT consume when absent" rule is enforced by this accessor's
    /// type, not by caller discipline (ADR-003 D3).
    pub fn inner_image_id(&self) -> Result<Option<&'a [u8; 32]>, DecodeError>;
}
```

**Verifier obligation (R6).** In External mode the verifier MUST bind the
journal's anchor fields (`prev_tip_hash` / `anchor_tip_hash` / `certified_root`)
to independently-verified state — the router's stored checkpoint, or a
CLI-verified sibling proof (CLAIMS §2.3). In Composed mode the *guest* already
checked the inner journal's header match + inner `claim_type` + tip binding and
journaled the `inner_image_id`; the verifier only checks that
`inner_image_id ∈ allowlist` (R5). A mode-1 journal accepted without discharging
the anchor has verified nothing about Cardano (CLAIMS §2.3).

### 4.2 `CheckpointState` (`state.rs`, S1–S13, D3 presence gate)

The 209-byte IVC-like state group, shared by `0x0001` (at body offset 0) and
`0x0002` (at body offset 73). It deliberately mirrors the upstream Mithril
recursion prototype's IVC `State` so the ADR-005 checkpoint-source swap changes
the *workload*, not the *schema* (CLAIMS §2.4; ADR-005 D2).

```rust
/// Read-only view over the 209-byte CheckpointState group. Borrows the parent
/// journal buffer — no owned copy. S11–S13 are presence-gated by S10
/// (`has_certified_transactions`), enforced by the accessor type (D3).
pub struct CheckpointState<'a> { buf: &'a [u8] } // the 209-byte group slice

impl<'a> CheckpointState<'a> {
    // ── carried VERBATIM from Sextant compute_hash (D5, no re-hash) ──
    pub fn root_hash(&self) -> &'a [u8; 32];  // S1 @ 0   — genesis cert content hash
    pub fn tip_hash(&self) -> &'a [u8; 32];   // S2 @ 32  — tip cert content hash
    pub fn tip_epoch(&self) -> u64;           // S3 @ 64  (u64 BE) — as-of scope
    pub fn chain_length(&self) -> u32;        // S4 @ 72  (u32 BE) — genesis-inclusive walk depth

    // ── binding commitments (D5); preimage FORMULAS frozen, bytes lock at M1 ──
    /// S5 @ 76. `Blake2b256(mt_root ‖ BE64(total_stake))` — the AVK commitment the
    /// NEXT certificate's STM signature verifies under (CLAIMS S5; ADR-003 D5;
    /// AVK shape {mt_commitment.root, total_stake} from sextant-legs §2.3 step 1).
    /// `nr_leaves` is NOT in the preimage (bounded by MAX_AVK_LEAVES, pinned by S2).
    pub fn avk_commitment(&self) -> &'a [u8; 32];
    /// S6 @ 108. `Blake2b256(next_avk_signed_bytes)` read from the SIGNED
    /// protocol-message parts only, never `signed_entity_type` (aggregator-
    /// reseal-able — sextant-legs Leg 2, mithril.rs:129-137; ADR-003 D5).
    pub fn next_avk_commitment(&self) -> &'a [u8; 32];

    // ── STM parameters, pinned by tip hash, journaled for adequacy policy ──
    pub fn stm_k(&self) -> u64;               // S7 @ 140 (u64 BE)
    pub fn stm_m(&self) -> u64;               // S8 @ 148 (u64 BE)
    /// S9 @ 156. `phi_f` as U8F24 fixed-point (u32) — Sextant's exact encoding
    /// (mithril.rs:892-894); NO float in the journal (CLAIMS S9).
    pub fn stm_phi_f_fixed(&self) -> u32;

    // ── presence-gated certified-transactions group (S10..S13, D3) ──
    /// S10 @ 160. `1` iff the tip is a CardanoTransactions certificate and
    /// S11–S13 are populated; `0` ⇒ S11–S13 zeroed and MUST NOT be consumed.
    /// An inclusion/utxo claim can only anchor to a checkpoint with this == 1.
    pub fn has_certified_transactions(&self) -> Result<bool, DecodeError>; // {0,1} else err

    /// S11–S13 as ONE gated accessor: `Ok(Some(_))` iff S10 == 1, else `Ok(None)`
    /// (present, zeroed, non-consumable — D3). Returning them together makes it
    /// impossible to read one without the flag having gated all three.
    /// `ctx_merkle_root` (S11) is read from the SIGNED parts only (mithril.rs:129-165).
    pub fn certified_transactions(&self)
        -> Result<Option<CertifiedTxAnchor<'a>>, DecodeError>;
}

/// The S11–S13 payload, only obtainable when S10 == 1. Every downstream
/// tx-inclusion / utxo-read anchor cites these (§2.4).
pub struct CertifiedTxAnchor<'a> {
    pub ctx_merkle_root: &'a [u8; 32], // S11 @ 161 — the certified-set root
    pub ctx_epoch: u64,                // S12 @ 193 (u64 BE)
    pub ctx_block_number: u64,         // S13 @ 201 (u64 BE) — the downstream as-of
}

/// Owned CheckpointState — the encode input from `hg-guest`. The tx group is an
/// `Option`, so the guest CANNOT set S11–S13 while S10 == 0 (the D3 invariant is
/// unrepresentable in the wrong state, not merely checked): `Some` ⇒ flag 1 +
/// payload written; `None` ⇒ flag 0 + payload zeroed.
pub struct CheckpointStateFields {
    pub root_hash: [u8; 32],
    pub tip_hash: [u8; 32],
    pub tip_epoch: u64,
    pub chain_length: u32,
    pub avk_commitment: [u8; 32],
    pub next_avk_commitment: [u8; 32],
    pub stm_k: u64,
    pub stm_m: u64,
    pub stm_phi_f_fixed: u32,
    pub certified_transactions: Option<CertifiedTxFields>, // Some ⇒ S10=1
}

pub struct CertifiedTxFields {
    pub ctx_merkle_root: [u8; 32],
    pub ctx_epoch: u64,
    pub ctx_block_number: u64,
}

impl CheckpointStateFields {
    /// Write the 209-byte group into `out[off..off+209]`, big-endian. When
    /// `certified_transactions` is `None`, S10 is written `0` and S11–S13 are
    /// zeroed (D3). Panics (a proving failure, not a verdict) if `out` is too
    /// short — the encoder sizes `out` from `expected_len` so this is unreachable
    /// in-guest; the bound is a checked-arithmetic guardrail (HANDOFF §5).
    pub fn encode_into(&self, out: &mut [u8], off: usize);
}
```

**S5/S6 build note.** The preimage *shapes* are frozen here
(`Blake2b256(mt_root ‖ BE64(total_stake))`, `Blake2b256(next_avk_signed_bytes)`);
their **bytes lock at M1** when the mithril-stm 0.10.5 AVK wire order is
transcribed (sextant-legs §4 unresolved; ADR-003 D5 / HANDOFF). The `hg-claims`
offsets are fixed *now*; only the preimage byte order of the hashed input
remains to pin. Both the `StmWalkSource` (Blake2b-256 Merkle root + total stake)
and the future `NativeRecursiveSource` (Poseidon-committed root) must populate
these *identically* — the field is heliograph's own binding commitment, defined
by this codec, not a passthrough of either proof system's internal hash
(ADR-005 D2 / HANDOFF constraint on ADR-003).

---

## 5. Per-claim bodies (`body/`)

Each type exposes: a `View<'a>` (read, borrows the buffer) and a `Fields`
(owned, encode input). Views expose the header via `JournalHeader` plus
body-specific accessors. All offsets are from ADR-003's per-claim tables.

### 5.1 `0x0001` checkpoint — `LEN = 255` (`body/checkpoint.rs`)

```rust
/// Header (46) + CheckpointState (209 @ BODY_OFF). No other body fields
/// (CLAIMS §3.1). `reject_index` = offending certificate index on chain-band
/// failures. The trust terminus — everything Mithril-anchored cites it.
pub struct CheckpointView<'a> { buf: &'a [u8] }

impl<'a> CheckpointView<'a> {
    pub fn header(&self) -> JournalHeader<'a>;
    pub fn state(&self) -> CheckpointState<'a>; // @ BODY_OFF (46)
}

pub struct CheckpointFields {
    pub header: HeaderFields,      // claim_type MUST be Checkpoint
    pub state: CheckpointStateFields,
}

impl CheckpointFields {
    /// Allocate a 255-byte buffer and write header + state (D0: one buffer, the
    /// exact bytes the verifier digests). Returns the owned journal bytes the
    /// guest commits. `alloc`-only (no_std).
    pub fn encode(&self) -> alloc::vec::Vec<u8>;
}
```

### 5.2 `0x0002` checkpoint-extension — `LEN = 328` (`body/checkpoint_extension.rs`)

```rust
/// Header (46) + extension prefix (73 @ BODY_OFF) + new CheckpointState (209 @
/// BODY_OFF+73). The recursion claim (ADR-002): a state-TRANSITION claim, never
/// absolute — the base case is its own type (0x0001), so a verifier can never be
/// handed an extension that anchors nowhere (CLAIMS §3.2; lightclient-patterns §3).
pub struct CheckpointExtensionView<'a> { buf: &'a [u8] }

impl<'a> CheckpointExtensionView<'a> {
    pub fn header(&self) -> JournalHeader<'a>;
    pub fn anchor(&self) -> AnchorBinding<'a>;      // E1/E2 @ BODY_OFF (prefix +0)
    pub fn prev_tip_hash(&self) -> &'a [u8; 32];    // E3 @ BODY_OFF+33
    pub fn prev_tip_epoch(&self) -> u64;            // E4 @ BODY_OFF+65 (u64 BE)
    pub fn new_state(&self) -> CheckpointState<'a>; // E5..E17 @ BODY_OFF+73
}

pub struct CheckpointExtensionFields {
    pub header: HeaderFields,             // claim_type MUST be CheckpointExtension
    pub anchor_mode: AnchorMode,
    pub inner_image_id: Option<[u8; 32]>, // Some ⇒ Composed; None ⇒ External (zeroed)
    pub prev_tip_hash: [u8; 32],
    pub prev_tip_epoch: u64,
    pub new_state: CheckpointStateFields, // chain_length == prev+1; root_hash carried through
}

impl CheckpointExtensionFields {
    /// Encode into a 328-byte buffer. Invariant (checked in `hg-guest`, journaled
    /// as data, not asserted at encode): `new_state.chain_length == prev + 1` and
    /// `new_state.root_hash` carried through unchanged (CLAIMS E5–E17). The
    /// `Option<inner_image_id>` makes External-mode-with-nonzero-inner-id
    /// unrepresentable (D3).
    pub fn encode(&self) -> alloc::vec::Vec<u8>;
}
```

**Guest bind (mode 2, CLAIMS §3.2).** The guest MUST check the inner journal's
header matches its own (`claim_version`, `network_id`, `genesis_vkey`), the inner
`claim_type` ∈ {Checkpoint, CheckpointExtension}, and inner `tip_hash ==
prev_tip_hash` — all fail-closed, journaled as rejections. This is the A3
cross-image-replay defense: the inner image ID is always input+journal, never a
silent const (ADR-002 D2).

### 5.3 `0x0003` header-segment — `LEN = 170` (`body/header_segment.rs`)

```rust
/// Header (46) + body (124 @ BODY_OFF). NO anchor prefix (header_segment does
/// not build on a checkpoint in-guest; H4 genesis_vkey is the declared trust
/// context for composition, CLAIMS §3.3). `reject_index` = offending block index.
pub struct HeaderSegmentView<'a> { buf: &'a [u8] }

impl<'a> HeaderSegmentView<'a> {
    pub fn header(&self) -> JournalHeader<'a>;
    pub fn eta0(&self) -> &'a [u8; 32];       // P1 @ BODY_OFF+0  — assumed epoch nonce, verbatim
    pub fn block_count(&self) -> u32;         // P2 @ +32 (u32 BE)
    pub fn seg_first_hash(&self) -> &'a [u8; 32]; // P3 @ +36 — rear edge
    pub fn seg_first_number(&self) -> u64;    // P4 @ +68 (u64 BE)
    pub fn seg_tip_hash(&self) -> &'a [u8; 32];   // P5 @ +76 — forward edge
    pub fn seg_tip_number(&self) -> u64;      // P6 @ +108 (u64 BE) — as-of
    pub fn seg_tip_slot(&self) -> u64;        // P7 @ +116 (u64 BE) — as-of
}

pub struct HeaderSegmentFields {
    pub header: HeaderFields,          // claim_type MUST be HeaderSegment
    pub eta0: [u8; 32],
    pub block_count: u32,
    pub seg_first_hash: [u8; 32],
    pub seg_first_number: u64,
    pub seg_tip_hash: [u8; 32],
    pub seg_tip_number: u64,
    pub seg_tip_slot: u64,
}

impl HeaderSegmentFields { pub fn encode(&self) -> alloc::vec::Vec<u8>; }
```

`eta0` is committed verbatim: an unjournaled nonce would let a prover verify
against a nonce of its choosing invisibly (CLAIMS P1). A verified segment is NOT
proven canonical (that rests on the Mithril anchor — CLAIMS §3.3 ASSUMES).

### 5.4 `0x0004` tx-inclusion — `LEN = 191` (`body/tx_inclusion.rs`)

```rust
/// Header (46) + anchor prefix (33 @ BODY_OFF) + body tail (112). Membership in
/// the certified transaction set, anchored to a checkpoint's `ctx_merkle_root`
/// via `anchor_mode` (CLAIMS §3.4). Verdict codes: the 400 band.
pub struct TxInclusionView<'a> { buf: &'a [u8] }

impl<'a> TxInclusionView<'a> {
    pub fn header(&self) -> JournalHeader<'a>;
    pub fn anchor(&self) -> AnchorBinding<'a>;    // I1/I2 @ BODY_OFF (prefix)
    pub fn anchor_tip_hash(&self) -> &'a [u8; 32]; // I3 @ BODY_OFF+33 — checkpoint identity
    pub fn certified_root(&self) -> &'a [u8; 32];  // I4 @ +65 — root membership proven against
    pub fn tx_hash(&self) -> &'a [u8; 32];         // I5 @ +97 — the claimed fact
    pub fn certified_epoch(&self) -> u64;          // I6 @ +129 (u64 BE) = anchor S12
    pub fn certified_block_number(&self) -> u64;   // I7 @ +137 (u64 BE) = anchor S13
}

pub struct TxInclusionFields {
    pub header: HeaderFields,             // claim_type MUST be TxInclusion
    pub anchor_mode: AnchorMode,
    pub inner_image_id: Option<[u8; 32]>,
    pub anchor_tip_hash: [u8; 32],
    pub certified_root: [u8; 32],
    pub tx_hash: [u8; 32],
    pub certified_epoch: u64,
    pub certified_block_number: u64,
}

impl TxInclusionFields { pub fn encode(&self) -> alloc::vec::Vec<u8>; }
```

Membership is a monotone "created" predicate — NOT unspent, NOT "currently
exists" (CLAIMS §3.4). In mode 2 the guest checks `anchor_tip_hash` against the
inner journal's S2 and `certified_root` against its S11 (CLAIMS I3).

### 5.5 `0x0005` utxo-read — `LEN = 269` (`body/utxo_read.rs`)

```rust
/// Header (46) + anchor prefix (33 @ BODY_OFF) + output group (190). Verified
/// output bytes of a Mithril-certified transaction, as-of `certified_at_block`
/// (CLAIMS §3.5; model SextantVerifiedOutput, ffi.rs:191-211). Inclusion is
/// verified INTERNALLY (one claim, not a composition of 0x0004 — utxo.rs:253).
pub struct UtxoReadView<'a> { buf: &'a [u8] }

impl<'a> UtxoReadView<'a> {
    pub fn header(&self) -> JournalHeader<'a>;
    pub fn anchor(&self) -> AnchorBinding<'a>;      // U1/U2 @ BODY_OFF (prefix)
    pub fn anchor_tip_hash(&self) -> &'a [u8; 32];  // U3 @ BODY_OFF+33
    pub fn certified_root(&self) -> &'a [u8; 32];   // U4 @ +65
    pub fn tx_id(&self) -> &'a [u8; 32];            // U5 @ +97 — Blake2b256(tx_bytes), in-guest
    pub fn out_index(&self) -> u16;                 // U6 @ +129 (u16 BE) — Sextant BE-u16 outpoint key
    pub fn lovelace(&self) -> u64;                  // U7 @ +131 (u64 BE)
    pub fn address_hash(&self) -> &'a [u8; 32];     // U8 @ +139 — Blake2b256(raw_address)
    pub fn address_len(&self) -> u16;               // U9 @ +171 (u16 BE) — length commitment
    /// U10 @ +173. Typed discriminant {0=None,1=Hash,2=Inline}; any other value
    /// ⇒ reject (R7). Selects which D5 rule U11 obeys.
    pub fn datum_kind(&self) -> Result<DatumKind, DecodeError>;
    /// U11 @ +174, presence-gated by U10 (D3). `Ok(None)` when kind == None (slot
    /// zeroed, MUST NOT be consumed). Kind Hash ⇒ the on-chain datum hash verbatim;
    /// kind Inline ⇒ `Blake2b256(inline_datum_cbor)`.
    pub fn datum_commitment(&self) -> Result<Option<&'a [u8; 32]>, DecodeError>;
    /// U12 @ +206. MUST be `0` (NotEstablished) on this claim type — pinned in
    /// the Sextant return type (utxo.rs:269). Any nonzero value ⇒ reject (R7):
    /// the tier band is machine-checkable, a proof does not upgrade Tier 0.
    pub fn spend_status(&self) -> Result<SpendStatus, DecodeError>;
    pub fn certified_epoch(&self) -> u64;           // U13 @ +207 (u64 BE) = anchor S12
    pub fn certified_at_block(&self) -> u64;        // U14 @ +215 (u64 BE) = anchor S13
}

/// U10 typed discriminant (ffi model). NOT a boolean — obeys the fixed-slot /
/// explicit-value / earns-a-mutant discipline (ADR-003 D3).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DatumKind { None = 0, Hash = 1, Inline = 2 }

impl DatumKind {
    pub fn from_u8(raw: u8) -> Result<Self, DecodeError>; // {0,1,2} else UnknownDatumKind
    pub const fn as_u8(self) -> u8;
}

/// U12. On 0x0005 the ONLY legal value is `NotEstablished` (0). The full band
/// (2 = SEXTANT_SPEND_CERTIFIED, 3+ attested/economic reserved) exists only in
/// the deferred claim types (ffi.rs:58-75); decoding any nonzero value on 0x0005
/// is a reject (R7). Modeled as an enum so the tier band is uncoercible in the
/// type (CLAIMS §1.5 / U12; Sextant utxo.rs:121-191 discipline).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpendStatus { NotEstablished = 0 }

impl SpendStatus {
    /// On 0x0005: `0` ⇒ Ok(NotEstablished); any nonzero ⇒
    /// Err(DecodeError::IllegalSpendStatusOnUtxoRead(raw)).
    pub fn from_u8_utxo_read(raw: u8) -> Result<Self, DecodeError>;
    pub const fn as_u8(self) -> u8;
}

pub struct UtxoReadFields {
    pub header: HeaderFields,             // claim_type MUST be UtxoRead
    pub anchor_mode: AnchorMode,
    pub inner_image_id: Option<[u8; 32]>,
    pub anchor_tip_hash: [u8; 32],
    pub certified_root: [u8; 32],
    pub tx_id: [u8; 32],
    pub out_index: u16,
    pub lovelace: u64,
    pub address_hash: [u8; 32],
    pub address_len: u16,
    pub datum: DatumField,                // Option-shaped: None/Hash/Inline, gates U11
    pub certified_epoch: u64,
    pub certified_at_block: u64,
    // spend_status is NOT a field: it is pinned to NotEstablished by the encoder.
}

/// Ties U10 and U11 together so an Inline/Hash kind ALWAYS carries a commitment
/// and `None` NEVER does — the D3 gate is unrepresentable in the wrong state.
pub enum DatumField { None, Hash([u8; 32]), Inline([u8; 32]) }

impl UtxoReadFields {
    /// Encode into 269 bytes. Writes U12 `spend_status = 0` unconditionally (the
    /// tier band is not the guest's to choose on this claim type). `datum` gates
    /// U10/U11 per D3.
    pub fn encode(&self) -> alloc::vec::Vec<u8>;
}
```

---

## 6. The decode-and-reject pipeline (`decode.rs`, D7)

The single entry point host/SDK use to turn calldata/artifact bytes into a typed,
validated claim. Runs R1–R7 (structural, verifier-side) and hands R8 (the
in-journal verdict) to the caller. **Reads every field by fixed offset from the
one input slice** — the same slice whose digest the vendor verifier checks
(D0/T-A4-5); there is no intermediate struct that is re-encoded to hash.

```rust
/// A fully-decoded, structurally-valid journal — one variant per claim type.
/// Each variant borrows the ORIGINAL buffer (`'a`), so obtaining a `Claim` is
/// proof that R1–R7 passed over exactly the bytes the caller holds.
pub enum Claim<'a> {
    Checkpoint(CheckpointView<'a>),
    CheckpointExtension(CheckpointExtensionView<'a>),
    HeaderSegment(HeaderSegmentView<'a>),
    TxInclusion(TxInclusionView<'a>),
    UtxoRead(UtxoReadView<'a>),
}

/// The verifier's pinned expectations — the POLICY half of R2/R3/R4 the codec
/// cannot know on its own. Supplied by the router/SDK/CLI, never defaulted.
pub struct VerifierPolicy {
    pub accepted_versions: &'static [ClaimVersion], // normally &[V1]; Draft never here
    pub accepted_types: &'static [ClaimType],
    pub accepted_networks: &'static [NetworkId],
    /// The pinned genesis vkey for each accepted network (R4). Re-genesis is a
    /// governed rotation (A11); this is where the pin lives.
    pub genesis_vkey_for: fn(NetworkId) -> Option<[u8; 32]>,
}

/// Decode-and-reject, one pass, one buffer (D7). Runs, in order:
///   R1 length gate    — len(buf) == expected_len(decoded claim_type), else reject
///   R2 version        — claim_version ∈ policy.accepted_versions (Draft 0 never)
///   R3 type + network — claim_type ∈ accepted_types; network_id ∈ accepted_networks
///   R4 genesis anchor — genesis_vkey == policy.genesis_vkey_for(network_id)
///   R7 band/presence  — every enum byte in-set; every presence flag ∈{0,1};
///                       no gated payload consumed while its flag is 0
/// R5 (image ID / inner-ID allowlist) and R6 (anchor binding to independently-
/// verified state) are NOT here: the image ID is not a journal field (it travels
/// with the proof, CLAIMS §1.2) and R6 needs external state — both belong to the
/// verifier layer that OWNS that state (router/CLI), which calls this after R5
/// and performs R6 on the returned view. R8 (read H5 verdict) is the caller's,
/// via `view.header().verdict()`.
///
/// Returns the borrowing `Claim` on success; a distinct `DecodeError` on the
/// first failing rule — fail-closed, no partial claim escapes.
pub fn decode_journal<'a>(
    buf: &'a [u8],
    policy: &VerifierPolicy,
) -> Result<Claim<'a>, DecodeError>;

/// Codec-only decode (no policy): runs R1 + the structural R7 band/presence
/// checks and the enum decodes, but NOT the R2/R3/R4 policy pins. Used by
/// `hg-guest`'s in-guest inner-journal check (mode 2), which validates structure
/// + does its OWN header-match against the outer journal, and by golden-vector
/// round-trip tests. Never sufficient for acceptance on its own.
pub fn decode_structural<'a>(buf: &'a [u8]) -> Result<Claim<'a>, DecodeError>;
```

```rust
/// Every fail-closed reason is a distinct variant — a rejection must say WHAT
/// was rejected (CLAIMS §4.2 discipline, applied to the codec's own errors).
/// These are VERIFIER-SIDE rejections (no proof is accepted, nothing is
/// journaled — CLAIMS §4.6); they are NOT journal verdicts (those are `Verdict`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    LengthMismatch { expected: usize, actual: usize }, // R1
    UnknownVersion(u16),                                // R2 codec
    VersionNotAccepted(ClaimVersion),                   // R2 policy (incl. Draft)
    UnknownClaimType(u16),                              // R3 codec
    ClaimTypeNotAccepted(ClaimType),                    // R3 policy
    NetworkNotAccepted(u32),                            // R3 policy
    GenesisVkeyMismatch,                                // R4
    UnknownVerdict(u16),                                // H5 decode
    UnknownAnchorMode(u8),                              // R7
    UnknownDatumKind(u8),                               // R7
    IllegalSpendStatusOnUtxoRead(u8),                   // R7 (nonzero on 0x0005)
    IllegalPresenceFlag { field: &'static str, value: u8 }, // R7 (S10 ∉ {0,1})
    ConsumedGatedPayloadWhileAbsent { field: &'static str }, // D3 accessor guard
}
```

**Why no `Ok`-on-unknown anywhere.** Every `from_uNN` above returns `Result`,
never a fallback variant. There is no `Unknown(u16)` catch-all in `ClaimType`,
`Verdict`, `AnchorMode`, or `DatumKind` — an unrecognized byte is a hard reject,
because a tolerated unknown is exactly the "best-effort decode of an unknown
layout" the Steel `validateCommitment` incident warns against (CLAIMS §1.3;
lightclient-patterns §2c). Unknown-version/type/network rejection is uniform
across all four surfaces (guest inner check, host, SDK, router).

---

## 7. Encode side (guest) — one buffer, no re-encode

`hg-guest` builds a journal by populating a typed `*Fields` and calling
`encode()`; the returned `Vec<u8>` is committed as the public output. That exact
buffer is what the vendor verifier digests and what the router later reads fields
from (D0). There is deliberately **no** `Claim::to_bytes()` on the *view* side —
a view borrows bytes that already exist; re-serializing a decoded view would be
the decode→re-encode round-trip D0 forbids (T-A4-5 / V-BLOB-VUL-004). Encoding is
a one-way street from typed `*Fields` → bytes; reading is a one-way street from
bytes → borrowing view.

```rust
/// Every `*Fields::encode()` (§5) funnels through this: allocate exactly
/// `claim_type.expected_len()`, write the header (46) then the body at BODY_OFF,
/// return the owned buffer. `debug_assert` the written length equals
/// `expected_len` (a slip is a guest defect caught before any proof exists). The
/// guest commits this buffer verbatim; nothing re-encodes it.
```

---

## 8. Mutant-testability hooks (§7 zoo — every field reachable)

The codec makes every journal field independently reachable so the §7 mutant zoo
(coverage in `docs/journal-coverage.md`; `make gate` fails on gaps — HANDOFF §7)
can flip each one and assert a verdict/meaning change. ADR-003 adds fields'
bytes, not fields, so CLAIMS §1.7 per-field obligations transfer directly
(input-verbatim fields — S1/S2, U5, I5, P1 — satisfy the zoo trivially: an input
flip is a journal flip). The codec-specific hooks:

```rust
/// TEST-ONLY (behind `#[cfg(any(test, feature = "mutate"))]`). Owns a mutable
/// copy of a journal buffer and exposes byte-precise mutation keyed by the SAME
/// `const OFFSET_*` the codec reads — so a mutant cannot drift from the layout it
/// tests. Every method returns the mutated buffer for re-decode + native-Sextant
/// comparison (T-A12-1) or verifier round-trip (T-A4-*).
pub struct JournalMutator { buf: alloc::vec::Vec<u8> }

impl JournalMutator {
    pub fn from_journal(buf: &[u8]) -> Self;
    pub fn into_bytes(self) -> alloc::vec::Vec<u8>;

    /// Flip any single field's bytes by its const offset+width. Covers the
    /// per-field input-flip mutants for EVERY field of every claim type (the
    /// "why load-bearing" column seeds, CLAIMS §1.7).
    pub fn set_field(&mut self, off: usize, bytes: &[u8]) -> &mut Self;

    // ── codec-specific mutant classes ADR-003 §"necessity by mutant" newly obligates ──

    /// Endianness mutant: byte-swap a multi-byte field BE→LE in place. Asserts BE
    /// is load-bearing — a swapped value decodes differently or fails a band/len
    /// gate (T-A4-3).
    pub fn byteswap_field(&mut self, off: usize, width: usize) -> &mut Self;

    /// Presence-flag mutants (D3): flip S10 (has_certified_transactions) with
    /// S11–S13 held constant, or flip U10 (datum_kind) 1↔2 with U11 held — the
    /// group's consumability / commitment-meaning must change (T-A1-2).
    pub fn flip_has_certified_txs(&mut self) -> &mut Self;
    pub fn set_datum_kind(&mut self, kind: u8) -> &mut Self;

    /// Verdict-table mutant: overwrite H5 with any u16, incl. codes valid on a
    /// DIFFERENT claim type, to exercise `Verdict::reachable_on` + the equality
    /// invariant (T-A12-1, D6).
    pub fn set_verdict(&mut self, raw: u16) -> &mut Self;

    /// No-silent-canonicalization mutant (T-A4-5): produce a length-padded or
    /// field-reordered buffer and assert it FAILS the R1 length / offset gate —
    /// there is no alternate buffer decoding to the same claim, which is what
    /// makes the single-buffer digest sound.
    pub fn pad(&mut self, extra: usize) -> &mut Self;

    /// Length-gate mutant (R1): truncate/extend by one byte → reject before any
    /// field is trusted.
    pub fn resize_by(&mut self, delta: isize) -> &mut Self;

    /// Anchor-mode / inner-ID mutants (A3): set External mode but write a nonzero
    /// inner_image_id (must reject at R7 / be non-consumable), or corrupt a
    /// journaled inner_image_id (must miss the allowlist at R5).
    pub fn set_anchor_mode(&mut self, raw: u8) -> &mut Self;
    pub fn corrupt_inner_image_id(&mut self) -> &mut Self;
}
```

Each hook maps to a named mutant class in `docs/journal-coverage.md`:
endianness, presence-flag, verdict-table, commitment-preimage (S5/S6 exercised
via `set_field` over the AVK/next-AVK commitment offsets once M1 locks their
bytes), no-silent-canonicalization, length-gate, anchor-binding. The commitment
preimage mutant asserts that altering `total_stake` under S5 or the next-AVK
signed part under S6 changes the commitment (ADR-003 D5) — its golden bytes lock
at M1 (sextant-legs §4), the offset/mutation path exist now.

---

## 9. The Solidity mirror + TS bindings are GENERATED (D8 / T-A4-4)

Nothing in §1–§8 is transcribed by hand into a second language. Two mechanical
paths, both CI-gated:

1. **`Constants.sol`** — `codegen.rs` emits the entire `consts.rs` block
   (`OFFSET_*`, `W_*`, `LEN_*`, network magics, the `Verdict` numeric table,
   `ClaimType` IDs) as Solidity `constant`s at build time. The router `import`s
   it and reads journal fields with constant-offset calldata loads (ADR-003 D2/D8;
   the BE layout is native to EVM words, no byte-swap — Context-4). The router
   NEVER decodes-into-a-struct-then-re-hashes: it digests the received calldata
   slice and reads fields by offset from that same slice (D0).
2. **Host + SDK Solidity bindings** — generated from the compiled router ABI
   artifact (Foundry `out/*.json`), committed, and CI-diffed; any drift fails the
   gate (T-A4-4 / Zellic sp1-helios 3.3 — the hand-written-`sol!`-drifts-from-
   contract bug). No `sol!` binding is hand-authored (ADR-003 D8, Alt-8).

The invariant is **one source, mechanically propagated, golden-diffed across
four surfaces** (guest write, host/SDK read, Solidity read). Direction of
generation (Rust→Sol constants vs a shared spec→both) is a BUILD detail; the
property is that no offset/width/magic/verdict is typed by hand in two places
(ADR-003 D8).

---

## 10. What this sketch fixes vs. what locks at BUILD

**Fixed now (this sketch, from ADR-003 v1):** every enum's numeric values;
every field's typed accessor and its const offset; the fail-closed
`Result`-returning decode of every discriminant; the presence-gate accessor
shapes (S10→S11–S13, U10→U11) that make the D3 "MUST NOT consume" rule a
type-level fact; the one-buffer encode/decode split (no view→bytes re-encode);
the R1–R7 decode pipeline signature; the mutant-hook surface.

**Locks at BUILD (Phase 2), NOT re-litigated here:**
- **S5/S6 preimage bytes** — formulas frozen (D5), the mithril-stm 0.10.5 AVK
  wire byte order transcribes at M1 (sextant-legs §4); offsets are already fixed.
- **Golden vectors** — one accepted + one rejected journal per claim type
  minimum, byte-exact, NORMATIVE over every offset in this prose (HANDOFF §7;
  ADR-003 HANDOFF). If an offset here disagrees with a vector, fix the prose.
- **`codegen.rs` direction** and the exact `Constants.sol` / bindings CI jobs
  (land with the router at M4, D8).
- **Deferred bodies 0x0006–0x0008** — band reserved, header + shared groups
  reusable; a later freeze is an extension, not a re-layout of 0x0001–0x0005
  (ADR-003 §Scope).

---

## Citations

- **docs/CLAIMS.md** v0 — §1.1–1.8 (rules; journal-is-ABI; single u16 version +
  DRAFT 0; fail-closed; tier preservation; encoding discipline), §2 (header
  H1–H6), §2.1 (registry + bench band), §2.2 (as-of scoping), §2.3 (anchor modes
  + inner_image_id), §2.4 (CheckpointState S1–S13, IVC mirror), §3.1–§3.5 (bodies
  0x0001–0x0005 INPUTS/PROVES/ASSUMES/TIER), §4 (rejection semantics; verdict as
  data; §4.6 verifier-side rejections), §5 (explicit non-claims), §6 (open
  questions, all resolved by ADR-003).
- **docs/adr/ADR-003** — D0 (one codec, four consumers, one buffer; no re-encode),
  D1 (BE/flat/fixed-offset), D2 (46-byte header layout + const block), D3
  (presence-gated optionals + accessor-enforced non-consumption), D4 (network
  magic u32 BE), D5 (commitment preimages; S5/S6 formulas, bytes-at-M1), D6
  (verdict table 1:1 SextantStatus, u16), D7 (R1–R8 decode-and-reject order), D8
  (bindings generated, never hand-written); per-claim body-layout tables
  (0x0001–0x0005) + the closing "golden vector is normative" note.
- **docs/THREAT_MODEL.md** v1 — A2/T-A2-1 (network binding), A3/T-A3-1/-2
  (cross-image replay; inner-ID journaling), A4/T-A4-1 (unknown-version reject),
  T-A4-3 (canonicality), T-A4-4 (bindings-from-ABI), T-A4-5
  (no-silent-canonicalization), A11 (re-genesis / genesis pin + R4), A12/T-A12-1
  (equality invariant — guest verdict == native Sextant, incl. reject index).
- **docs/notes/sextant-legs.md** (@ `3a68b2f`) — Leg 1 (BE64 opcert/VRF messages;
  eta0; header/segment fields = P1–P7), Leg 2 (`verify_chain_anchored`;
  `compute_hash` content hashes = S1/S2; signed-parts-only for S6/S11; AVK
  `{mt_commitment.root, total_stake}` = S5 shape; `phi_f` U8F24 mithril.rs:892-894
  = S9), Leg 3 (inclusion 400-band = I-verdicts), Leg 4 (`SextantVerifiedOutput`
  = U-fields; Blake2b address hash; `SpendStatus::NotEstablished` pinned
  utxo.rs:269 = U12), Leg 6 (`tx_id ‖ BE-u16 index` outpoint key = U6 convention),
  §2.1 (default graph no_std+alloc), §2.2 (mithril backend seam), §4 (mithril-stm
  0.10.5 AVK wire order unresolved → S5/S6 bytes at M1).
- **docs/notes/lightclient-patterns.md** — §2c (Steel `configID` / version-tagged
  network field, unknown⇒reject — the explicit-network + fail-closed-decode
  lesson), §3 (aggregation discipline: inner image ID as input MUST be journaled;
  sp1-vector claim-type-first).
- **docs/adr/ADR-000** — §Decision-2 (`hg-*` crate namespace; `hg-claims` free).
  **ADR-002** — recursion anchor_mode machinery (mode 1 external / mode 2
  composed; inner image ID always input+journal). **ADR-005** — D2 (a swap does
  not touch claim semantics; S5/S6 must populate identically from both sources).
- **HANDOFF.md** — §0 (non-negotiables), §5 (`hg-claims` no_std, canonical,
  golden-tested, mirrored constant-for-constant in Solidity; checked arithmetic;
  panics are proof failures, rejections are journaled), §7 (equality invariant,
  golden journals, journal zoo, `make gate`), §9 gate 6 (post-freeze schema
  changes are breaking).
