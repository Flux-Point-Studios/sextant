# ADR-003 — Journal-as-ABI: the canonical `hg-claims` codec

- **Status:** Accepted (codec frozen at v1). 2026-07-14.
- **Deciders:** sole senior engineer, under HANDOFF.md as contract.
- **Supersedes:** the byte-layout deferral in `docs/CLAIMS.md` v0 §1.8, §6 open
  questions 2/5/6. CLAIMS.md v0 fixed the field *set* and semantics; this ADR
  fixes the *bytes*. CLAIMS.md is authoritative for which fields exist and what
  they mean; this ADR is authoritative for how they are encoded.
- **Scope of the freeze:** the wire layout of the common journal header (H1–H6)
  and the bodies of claim types `0x0001`–`0x0005` (the SIGNED v0.1 scope,
  STATUS.md §12). Deferred claim types `0x0006`–`0x0008` are banded but their
  bodies are NOT frozen here (they reuse the header and the shared field groups
  §2.4/§2.3, so a later freeze is an extension, not a re-layout). "v1" below is
  `claim_version = 1`, assigned at the CLAIMS.md v1 freeze (a Phase-2 event,
  CLAIMS.md §1.3); the codec *rules* are frozen now so the golden vectors that
  drive that freeze have a fixed target.

---

## Context

The journal is the ABI of truth (HANDOFF §0, §11; CLAIMS.md §1.1). A verdict is
a promise made to strangers: the image ID is the signature, the journal is the
document. Three independent implementations must agree on that document
byte-for-byte — the guest that *writes* it (`hg-guest`), the host and SDK that
*read* it (`hg-host`, `hg-sdk-ts`), and the Solidity router that *acts on* it
(`/contracts`). A single byte of disagreement between any two is either a
soundness hole (the router acts on a value the guest never proved) or a
liveness break (a valid proof is rejected). CLAIMS.md v0 deferred the byte
layout to this ADR precisely so it could be decided once, in one place, and
golden-tested.

Four constraints bound the decision, all already established upstream of this
ADR:

1. **CLAIMS.md §1.8 encoding discipline (normative, already fixed).** All
   integers fixed-width; all hashes `[u8;32]`; no varints; no implicit
   optionality (presence flags are explicit bytes; absent fields zeroed and
   MUST NOT be consumed); field ORDER as listed in CLAIMS.md is normative; one
   encoding per value. This ADR chooses the remaining free parameters
   (endianness, framing, the exact width and placement of every field, the
   verdict numeric table, the optional-field discipline, the commitment
   preimages) *within* that discipline.
2. **THREAT_MODEL A4 (claim-version downgrade / ABI drift).** Unknown versions
   rejected everywhere; the codec's canonicality is what makes the version
   check meaningful (T-A4-1, T-A4-3). Plus three audit-harvested rules that
   this ADR must satisfy structurally, not merely test: T-A4-3 canonicality
   (one encoding per value, golden-tested), T-A4-4 bindings-from-ABI (host/SDK
   Solidity bindings generated from the compiled artifact, never hand-written —
   Zellic sp1-helios 3.3), T-A4-5 no-silent-canonicalization (the SAME buffer
   feeds the verifier digest and the field parsing — Veridise blobstream0
   V-BLOB-VUL-004).
3. **Sextant conventions (the semantics we mirror, never re-derive — HANDOFF
   §0 precedence 3).** Sextant already encodes its wire in big-endian: the
   opcert message is `hot_vkey ‖ BE64(seq) ‖ BE64(kes_period)`
   (sextant-legs.md Leg 1, `kes.rs:71-88`); the VRF alpha is
   `Blake2b256(BE64(slot) ‖ eta0)` (`vrf.rs:94-152`); the outpoint key and the
   set fingerprint use `tx_id ‖ BE-u16 index` (sextant-legs.md Leg 6,
   `utxoset.rs:386`). The verdict codes are the `SextantStatus` `#[repr(i32)]`
   enum at `sextant/src/ffi.rs:83-136` (`SEXTANT_ABI_VERSION = 5`).
4. **EVM convention.** Solidity/EVM words are big-endian; `abi.decode` of a
   packed buffer, and every `uintN` cast, reads most-significant-byte-first. A
   big-endian journal is parsed by the router with shifts and masks over
   calldata, no byte-swapping.

Endianness is therefore not a free choice: Sextant is big-endian and EVM is
big-endian, so a little-endian journal would byte-swap at *both* the guest
(against Sextant's own BE64 helpers) and the router (against EVM word order).
Big-endian is the only choice that is native on both load-bearing ends.

---

## Decision

### D0. One codec crate, four consumers, one buffer

`hg-claims` is the single Rust codec, `no_std + alloc` (HANDOFF §5), shared
constant-for-constant by `hg-guest` (writes journals), `hg-host` and
`hg-sdk-ts` (read journals), and mirrored constant-for-constant in the Solidity
router (`/contracts`). There is exactly one encode function and one decode
function per claim type; the guest's `commit` path and the host/SDK's parse
path call the same code. The Solidity mirror is not a second implementation of
the *logic* — it is a transcription of the *constants* (offsets, widths, the
verdict table, `network_id` magics, `claim_type` IDs) whose correctness is
pinned by cross-layer golden tests (T-A4-3) and by generating the host/SDK
Solidity bindings from the compiled router ABI, never by hand (D8 / T-A4-4).

**One buffer, no re-encode (T-A4-5 / V-BLOB-VUL-004).** The exact byte buffer
whose digest is checked by the vendor verifier is the exact byte buffer the
router decodes fields from. The router MUST NOT decode-into-a-struct then
re-encode-to-hash: it computes the verifier's journal digest over the received
calldata slice and reads every field by fixed offset from that same slice. This
is a structural property of the layout (D1: flat, fixed-offset, self-framing),
not a runtime check — there is no canonicalization step that could diverge.
Blobstream0's bug was a decode→re-encode→`sha256` round-trip that is sound only
if the codec is strictly canonical; heliograph removes the round-trip entirely.

### D1. Big-endian, flat, fixed-width, fixed-offset

- **Big-endian** for every multi-byte integer (`u16`, `u32`, `u64`), matching
  Sextant's `BE64` message encodings and EVM word order (Context 3–4). Hashes
  and keys (`[u8;32]`) are raw bytes, no endianness.
- **Flat:** the journal is a single contiguous byte string — header (§2)
  immediately followed by the claim body (§3), no length prefixes, no offsets,
  no framing tags between fields. The header's `claim_version` (H1) and
  `claim_type` (H2) determine the total length and the layout of everything
  after them; a decoder dispatches on those two fields and then reads
  fixed-offset, fixed-width fields to the end. There is no self-describing
  framing because the schema *is* the frame — the (version, type) pair names
  exactly one layout.
- **Fixed-width, fixed-offset:** every field of a given `(claim_version,
  claim_type)` sits at a compile-time-constant offset with a compile-time
  constant width. No field's position depends on any other field's *value*
  (presence flags gate whether a fixed-slot region is *populated*, never
  whether it *exists* — D3). This is what lets the router read fields with
  constant-offset calldata loads and lets `hg-claims` expose `const OFFSET_*`
  that the Solidity mirror transcribes.
- **Total length is a function of `(version, type)` alone**, published as a
  `const LEN_*` per claim type. A journal whose byte length ≠ the expected
  length for its decoded `(version, type)` is rejected before any field is
  trusted (D7 rule R6).

Rationale for flat-vs-length-prefixed: length prefixes and offset tables are a
second encoding of information the schema already fixes, and every redundant
encoding is a canonicality hazard (two buffers that decode to the same value —
exactly the A4 attack). A flat fixed layout has, by construction, one encoding
per value: there is nowhere to hide a non-canonical byte. Variable-length data
(the raw address, inline datum, the certificate JSON) never enters the journal;
only its fixed-width commitment does (D5), so the journal itself is always
fixed-length per type.

### D2. The common journal header (H1–H6) — exact layout

All offsets from the start of the journal. Header length = **46 bytes**, fixed,
identical for every claim type (accepted or rejected); the body begins at
offset 46.

| off | field | type | width | encoding |
|----:|-------|------|------:|----------|
| 0 | `claim_version` (H1) | `u16` | 2 | big-endian |
| 2 | `claim_type` (H2) | `u16` | 2 | big-endian |
| 4 | `network_id` (H3) | `u32` | 4 | big-endian Cardano network magic (D4) |
| 8 | `genesis_vkey` (H4) | `[u8;32]` | 32 | raw bytes, as pinned (Ed25519 vkey) |
| 40 | `verdict` (H5) | `u16` | 2 | big-endian verdict code (D6) |
| 42 | `reject_index` (H6) | `u32` | 4 | big-endian; claim-type-specific detail |

`reject_index` (H6) is a `u32` (CLAIMS.md H6): the offending block index for
header-segment, the offending certificate index for checkpoint; meaningful only
when `verdict != 0` and the claim type defines it, zero otherwise. Widths sum to
2+2+4+32+2+4 = **46**. The header is `claim_version` first so any decoder
dispatches before touching
version-dependent bytes (CLAIMS.md §2), and `claim_type` second so a shared
image with claim dispatch is fail-closed on unknown type (the sp1-vector
claim-type-first precedent, lightclient-patterns.md §3). `network_id` and
`genesis_vkey` precede the body because they are checked by the verifier before
any body field is trusted (D7).

Header constant block (mirrored in Solidity):

```
HDR_OFF_VERSION      = 0   HDR_W_VERSION      = 2
HDR_OFF_CLAIM_TYPE   = 2   HDR_W_CLAIM_TYPE   = 2
HDR_OFF_NETWORK_ID   = 4   HDR_W_NETWORK_ID   = 4
HDR_OFF_GENESIS_VKEY = 8   HDR_W_GENESIS_VKEY = 32
HDR_OFF_VERDICT      = 40  HDR_W_VERDICT      = 2
HDR_OFF_REJECT_INDEX = 42  HDR_W_REJECT_INDEX = 4
HDR_LEN              = 46
BODY_OFF             = 46
```

### D3. Optional / presence-gated fields — explicit flag byte, fixed slot

CLAIMS.md §1.8 forbids implicit optionality. Frozen rule:

- Every optional field group is gated by an explicit `u8` presence flag that
  occupies its own fixed offset and is `0` (absent) or `1` (present). Any other
  value ⇒ reject (R7). The flag is ALWAYS present and ALWAYS read; it is the
  *payload* that is conditionally populated.
- When the flag is `0`, the payload slots it gates are **present in the byte
  layout, zeroed, and MUST NOT be consumed** (CLAIMS.md §1.8, S10). The slots
  do not disappear — the layout stays fixed-offset (D1). A decoder that reads a
  gated payload while its flag is `0` is a defect; the codec exposes the payload
  only through an accessor that returns `None`/reverts when the flag is `0`, so
  the "MUST NOT consume" rule is enforced by the type, not by discipline.
- **The presence flag is itself a journal field and earns its own mutant**
  (§7 zoo): flipping the flag with the payload held constant must change the
  decoded verdict/meaning (S10 → S11–S13 become consumable or not).

Concrete instance — `CheckpointState` transaction group (§2.4 S10–S13):
`has_certified_transactions` (`u8`) is the flag at its fixed offset; S11
`ctx_merkle_root` `[u8;32]`, S12 `ctx_epoch` `u64`, S13 `ctx_block_number`
`u64` follow at fixed offsets and are zeroed when the flag is `0`. The router
rejects any journal that presents S11–S13 nonzero with the flag `0`, or
consumes them with the flag `0` (CLAIMS.md §4.6).

Concrete instance — `datum` group (utxo-read §3.5 U10–U11): `datum_kind`
(`u8`, values 0/1/2 only — any other value rejects, R7) is the discriminant;
`datum_commitment` `[u8;32]` is zeroed and MUST NOT be consumed when
`datum_kind == 0`. `datum_kind` is a *typed discriminant*, not a boolean flag,
but obeys the same fixed-slot / explicit-value / earns-a-mutant discipline.

### D4. `network_id` encoding (resolves CLAIMS.md §6 open question 5)

**Cardano network magic as `u32` big-endian**, not a config-digest. Frozen
values:

| network | magic (`u32`) | hex |
|---|---:|---|
| mainnet | 764824073 | `0x2D964A09` |
| preprod | 1 | `0x00000001` |
| preview | 2 | `0x00000002` |

Rationale: the network magic is the canonical, protocol-native network
identifier already carried in Cardano's own handshake and consumed by every
Cardano tool; it is self-describing (the portable-verdict file names its
network with no external table, satisfying the Steel `configID` lesson —
lightclient-patterns.md §2c — with a value that is *meaningful*, not an opaque
digest). A config-digest (Steel's approach) would bind more than the network
(protocol params, genesis time) but heliograph binds those separately and
explicitly (`genesis_vkey` H4, the STM params S7–S9), so folding them into one
opaque digest would *reduce* legibility. The `u32` width holds every current
and foreseeable magic (mainnet's 764824073 needs 30 bits). Wrong network ⇒
reject at the router (against its configured network) AND self-evident in the
portable artifact (A2 / T-A2-1, T-A2-2).

A private/devnet magic is any other `u32`; the router pins the exact set it
accepts (normally one), so an unrecognized magic rejects (fail-closed, R3).

### D5. Commitment preimages (resolves the avk/next-avk/address/datum "ADR-003"
placeholders in CLAIMS.md §2.4 and §3.5)

Every commitment in the journal is **Blake2b-256 over an explicitly specified
preimage** unless CLAIMS/Sextant already fixes a different hash for that exact
value (in which case the journal carries Sextant's value verbatim — never a
re-hash). Blake2b-256 is Sextant's and Cardano's native 32-byte hash
(sextant-legs.md Leg 1/4: header hash, address hash, datum-bytes hash are all
Blake2b-256); using it everywhere keeps one hash function across the guest and
avoids importing a second.

- **S1 `root_hash` / S2 `tip_hash`:** carried **verbatim** from Sextant —
  these ARE Sextant's `compute_hash` content hashes of the genesis and tip
  certificates (the canonical commitment, sextant-legs.md Leg 2,
  `mithril.rs:288`; guest-feature note item 4). No re-hash; the guest journals
  the bytes Sextant computed. Mutant: any spliced root/tip changes these bytes.
- **S5 `avk_commitment`:** `Blake2b256( mt_root ‖ BE64(total_stake) )`, where
  `mt_root` is the **Mithril-protocol AVK Merkle root** (`mt_commitment.root`,
  32 bytes) and `total_stake` is its `u64` total stake — the two fields Sextant
  deserializes as the AVK (`{mt_commitment:{root, nr_leaves}, total_stake}`,
  sextant-legs.md §2.3 step 1). **`mt_root` is source-invariant by construction:**
  it is the aggregate verification key as the *Mithril protocol* defines it (the
  Blake2b commitment the STM aggregate signature verifies under), not an artifact
  of any one proof system. This is what makes S5 reproducible under ADR-005: a
  native recursive-certificate checkpoint source MUST expose this same protocol
  `mt_root` (its internal Poseidon hashing, if any, is not the commitment); if a
  future source cannot surface the protocol root, that is a codec-revision
  trigger BEFORE the `claim_version=1` freeze, not a silent divergence. `nr_leaves`
  is NOT in the preimage: `mt_root` already commits the tree (leaf count and
  shape) at the mithril-stm layer, and for a mode-1 extension the prior
  `CheckpointState`'s S5 is bound via R6 to a previously-proven stored checkpoint
  (whose S5 was proven when appended), so `nr_leaves` is transitively bound; the
  commitment binds *what the next signature verifies under* (root + stake), which
  is exactly `(mt_root, total_stake)`. The exact byte order of the AVK wire is
  transcribed from mithril-stm 0.10.5 at M1 (sextant-legs.md §4 unresolved); this
  ADR fixes the preimage *shape* — `mt_root ‖ BE64(stake)`, Blake2b-256 — and the
  golden vector locks the bytes at M1. Mutant: a forged AVK root or altered stake
  changes the commitment; the next extension's STM verify then fails against it
  (S5 is what the successor certificate's signature is checked under,
  CLAIMS.md §3.2).
- **S6 `next_avk_commitment`:** `Blake2b256( next_avk_bytes )` where
  `next_avk_bytes` is the raw
  `ProtocolMessagePartKey::NextAggregateVerificationKey` value read from the
  **signed** protocol-message parts of the tip only (never from
  `signed_entity_type`, which is unsigned and aggregator-reseal-able —
  sextant-legs.md Leg 2, `mithril.rs:129-137`). Commit the hash of the exact
  signed bytes, so the cross-epoch AVK-binding arm (CLAIMS.md §3.1,
  `mithril.rs:298-308`) is journal-visible. Mutant: altering the next-AVK part
  changes S6 and breaks the epoch-boundary extension check.
- **U8 `address_hash`:** `Blake2b256( raw_address_bytes )` — Sextant's own
  address hashing (sextant-legs.md Leg 4). U9 `address_len` (`u16` BE) commits
  the raw length so the artifact-layer address (which travels in the proof
  artifact, not the journal) is pinned in both content and length (CLAIMS.md
  U9: hash alone does not pin length). The SDK/consumer recomputes
  `Blake2b256(address)` and checks length == U9 before trusting the address
  bytes.
- **U11 `datum_commitment`:** kind 1 → the 32-byte datum **hash as it appears
  on chain**, verbatim (Cardano already commits the datum by Blake2b-256 hash;
  no re-hash). Kind 2 → `Blake2b256( inline_datum_cbor_bytes )` over the raw
  `#6.24`-unwrapped plutus-data bytes (the bytes Sextant surfaces,
  `ffi.rs:203-205`). Kind 0 → zeroed, gated by the D3 rule. The kind
  discriminant (U10) is what selects which rule applies, and is itself
  mutation-checked.

### D6. Verdict codes (H5) — the exact numeric table (resolves CLAIMS.md §6
open question 6; CLAIMS.md H5/§4.1 pin this to "ADR-003 + golden fixtures")

`verdict` (H5, `u16` BE) adopts the Sextant `SextantStatus` `#[repr(i32)]` band
values **1:1, verbatim, no lossy collapsing** (CLAIMS.md §4.1: one journal code
per Sextant error variant). `0` = accepted. The frozen table (from
`sextant/src/ffi.rs:83-136`, `SEXTANT_ABI_VERSION = 5`):

| code | Sextant variant | band | reachable on claim types |
|---:|---|---|---|
| 0 | `Ok` | accept | all |
| 100 | `DecodeMalformedCbor` | header-leaf | 0x0003 |
| 101 | `DecodeUnsupportedEra` | header-leaf | 0x0003 |
| 102 | `DecodeBadHashLen` | header-leaf | 0x0003 |
| 103 | `DecodeTrailingBytes` | header-leaf | 0x0003 |
| 110 | `VrfInvalidGamma` | header-leaf | 0x0003 |
| 111 | `VrfInvalidPublicKey` | header-leaf | 0x0003 |
| 112 | `VrfSmallOrderPublicKey` | header-leaf | 0x0003 |
| 113 | `VrfVerificationFailed` | header-leaf | 0x0003 |
| 120 | `KesOpCertInvalidSignature` | header-leaf | 0x0003 |
| 121 | `KesInvalidSignature` | header-leaf | 0x0003 |
| 122 | `KesPeriodOutOfRange` | header-leaf | 0x0003 |
| 200 | `ChainDecode` | praos-chain | 0x0003 |
| 201 | `ChainBrokenLink` | praos-chain | 0x0003 |
| 202 | `ChainOpCert` | praos-chain | 0x0003 |
| 203 | `ChainVrf` | praos-chain | 0x0003 |
| 204 | `ChainKes` | praos-chain | 0x0003 |
| 300 | `MithrilChainEmpty` | mithril-chain | 0x0001, 0x0002 |
| 301 | `MithrilChainHash` | mithril-chain | 0x0001, 0x0002 |
| 302 | `MithrilChainBrokenLink` | mithril-chain | 0x0001, 0x0002 |
| 303 | `MithrilChainAvkBinding` | mithril-chain | 0x0001, 0x0002 |
| 310 | `MithrilGenesisNotGenesis` | mithril-genesis | 0x0001 |
| 311 | `MithrilGenesisMalformedSignature` | mithril-genesis | 0x0001 |
| 312 | `MithrilGenesisMessageMismatch` | mithril-genesis | 0x0001 |
| 313 | `MithrilGenesisInvalidSignature` | mithril-genesis | 0x0001 |
| 320 | `MithrilStdNotStandard` | mithril-standard | 0x0001, 0x0002 |
| 321 | `MithrilStdMessageMismatch` | mithril-standard | 0x0001, 0x0002 |
| 322 | `MithrilStdWeakParameters` | mithril-standard | 0x0001, 0x0002 |
| 323 | `MithrilStdImplausibleAvk` | mithril-standard | 0x0001, 0x0002 |
| 324 | `MithrilStdMalformedAvk` | mithril-standard | 0x0001, 0x0002 |
| 325 | `MithrilStdMalformedSignature` | mithril-standard | 0x0001, 0x0002 |
| 326 | `MithrilStdInvalidMultiSignature` | mithril-standard | 0x0001, 0x0002 |
| 327 | `MithrilStdMalformedCertJson` | mithril-standard | 0x0001, 0x0002 |
| 400 | `UtxoInclusionNotIncluded` | inclusion | 0x0004, 0x0005 |
| 401 | `UtxoInclusionRootMismatch` | inclusion | 0x0004, 0x0005 |
| 402 | `UtxoInclusionMalformedProof` | inclusion | 0x0004, 0x0005 |
| 410 | `UtxoMalformedTx` | utxo | 0x0005 |
| 411 | `UtxoOutputIndexOutOfRange` | utxo | 0x0005 |

Notes:
- The Sextant negative codes (`ErrNullPointer` −1 … `ErrPanic` −9) are
  **boundary/caller errors that NEVER appear in a journal**: a guest panic
  yields no proof and therefore no verdict (CLAIMS.md §4.4). The journal's H5
  space is exactly the non-negative `SextantStatus` bands, which fit in `u16`
  (max 411). Using `u16` (not `i32`) makes "no negative verdict is journalable"
  a *type-level* fact.
- **Mapping rule is total and lossless:** every reachable `SextantStatus`
  variant has exactly one H5 code (the same integer), and every H5 code maps
  back to exactly one variant. Golden fixtures pin the full table (T-A4-3); the
  equality invariant (T-A12-1) asserts guest H5 == native `SextantStatus` for
  every mutant, including the exact index in H6.
- A verdict code appearing on a claim type it is not reachable on (last column)
  is a codec/guest defect caught by the equality invariant; the router does not
  separately whitelist codes-per-type (that would be a second encoding of the
  reachability the guest already enforces), but the golden corpus covers the
  reachable set per type.

### D7. Verifier decode-and-reject order (fail-closed, one pass, one buffer)

A verifier (router, SDK, CLI, or in-guest anchor check) processes a journal in
this fixed order; any failure is a rejection (CLAIMS.md §1.4, §4.6). The digest
handed to the vendor verifier is computed over the identical buffer these rules
read (D0 / T-A4-5).

1. **R1 — length gate.** `len(journal) == LEN[claim_type]` for the decoded
   `claim_type`, else reject. (Requires reading H1/H2 first; those live at
   fixed offsets 0/2, before any variable interpretation.)
2. **R2 — version.** `claim_version` (H1) ∈ the verifier's pinned accepted set
   (normally `{1}`); anything else — higher, lower, or DRAFT `0` — rejects
   (A4 / T-A4-1). DRAFT `0` is rejected unconditionally in every production path
   (CLAIMS.md §1.3).
3. **R3 — claim type + network.** `claim_type` (H2) is one this verifier
   accepts; `network_id` (H3) ∈ its pinned network set. Else reject
   (A2 / T-A2-1).
4. **R4 — genesis anchor.** `genesis_vkey` (H4) == the verifier's pinned
   expectation for `network_id` (CLAIMS.md H4; re-genesis handled as a governed
   rotation, A11). Else reject.
5. **R5 — image ID.** The proof's image ID ∈ the allowlist / registry
   (A3 / A8); for composed claims (mode 2), the journaled `inner_image_id` ∈
   the allowlist too (CLAIMS.md §2.3). (Image ID is not a journal field — it
   travels with the proof, CLAIMS.md §1.2 — but the check belongs in this
   sequence.)
6. **R6 — anchor binding.** Per `anchor_mode` (§2.3): mode 1, the journal's
   anchor fields == independently verified state (router's stored checkpoint /
   sibling proof); mode 2, the in-guest inner-journal checks already ran and
   `inner_image_id` passed R5. Else reject. R6 applies **uniformly regardless of
   H5** — identity/anchor fields are committed INPUTS (CLAIMS §3.4), populated on
   both accept and rejection journals; only unreached PAYLOAD/result fields are
   zeroed on a rejection (CLAIMS §4.2). A BUILD implementation MUST NOT "zero all
   body fields on any rejection" — that would break R6 on a valid journaled
   rejection (e.g. `NotIncluded`, which checks membership against a populated
   `certified_root`).
7. **R7 — band/presence validity.** Every presence flag ∈ {0,1}; every typed
   discriminant in its allowed set (`datum_kind` ∈ {0,1,2}; `anchor_mode` ∈
   {1,2}; `spend_status == 0` on 0x0005, CLAIMS.md U12/§4.6); no gated payload
   consumed while its flag is 0. Else reject.
8. **R8 — verdict.** Read H5. `0` ⇒ the positive claim holds (subject to R1–R7);
   nonzero ⇒ a journaled rejection (CLAIMS.md §4): the presented inputs failed
   verification, and H6 `reject_index` attributes it. A journaled rejection is
   a *valid proof of a rejection*, not a proof of the claim's negation
   (CLAIMS.md §4.3, §5.4).

R1–R7 are verifier-side structural checks that reject a *submission* with no
journaled verdict (CLAIMS.md §4.6). R8 reads the in-journal verdict the guest
proved. The order is fixed so the cheapest, most-discriminating checks (length,
version, type, network, anchor) run before the proof's own verdict is trusted.

### D8. Bindings generated, never hand-written (T-A4-4 / Zellic 3.3)

The Rust host's and TS SDK's view of the Solidity router ABI is a *fourth*
codec surface (after guest, host/SDK Rust, and Solidity). Rule: host and SDK
Solidity bindings are **generated from the compiled router ABI artifact**
(Foundry `out/*.json`), committed to the repo, and diffed in CI; any drift
fails the gate (T-A4-4). The `hg-claims` offset/width/verdict constants are the
single source of truth: the Solidity mirror `import`s them from one generated
`Constants.sol` produced from the Rust `const` block (or the Rust consts are
generated from a shared spec — the direction is a BUILD detail; the invariant
is one source, mechanically propagated, golden-diffed). No offset, width,
magic, or verdict code is typed by hand in two places.

---

## Per-claim body layouts (v1 frozen, types 0x0001–0x0005)

Bodies begin at `BODY_OFF = 46`. All multi-byte integers big-endian; all
`[u8;32]`/`[u8]` raw. Field order is CLAIMS.md order (normative, §1.8). Each
`LEN_*` is `HDR_LEN (46) + body length`.

### `CheckpointState` shared group (§2.4) — 209 bytes

| off (in group) | field | type | w |
|----:|---|---|---:|
| 0 | S1 `root_hash` | `[u8;32]` | 32 |
| 32 | S2 `tip_hash` | `[u8;32]` | 32 |
| 64 | S3 `tip_epoch` | `u64` | 8 |
| 72 | S4 `chain_length` | `u32` | 4 |
| 76 | S5 `avk_commitment` | `[u8;32]` | 32 |
| 108 | S6 `next_avk_commitment` | `[u8;32]` | 32 |
| 140 | S7 `stm_k` | `u64` | 8 |
| 148 | S8 `stm_m` | `u64` | 8 |
| 156 | S9 `stm_phi_f_fixed` | `u32` | 4 |
| 160 | S10 `has_certified_transactions` | `u8` | 1 |
| 161 | S11 `ctx_merkle_root` | `[u8;32]` | 32 |
| 193 | S12 `ctx_epoch` | `u64` | 8 |
| 201 | S13 `ctx_block_number` | `u64` | 8 |

Group length = **209 bytes** (S10–S13 always present; S11–S13 zeroed and
non-consumable when S10 == 0, D3). `stm_phi_f_fixed` (S9) is the U8F24
fixed-point `phi_f` (`u32`), Sextant's exact encoding (`mithril.rs:892-894`) —
no float in the journal.

### `0x0001` checkpoint — `LEN = 46 + 209 = 255`

Header + `CheckpointState` (body offset 0, i.e. journal offset 46). No other
body fields (CLAIMS.md §3.1). `reject_index` (H6) = offending certificate index
on chain-band failures.

### `0x0002` checkpoint-extension — `LEN = 46 + 73 + 209 = 328`

Header + extension prefix (73 bytes) + new `CheckpointState` (209 bytes at body
offset 73):

| off (in body) | field | type | w |
|----:|---|---|---:|
| 0 | E1 `anchor_mode` | `u8` | 1 |
| 1 | E2 `inner_image_id` | `[u8;32]` | 32 |
| 33 | E3 `prev_tip_hash` | `[u8;32]` | 32 |
| 65 | E4 `prev_tip_epoch` | `u64` | 8 |
| 73 | E5–E17 `CheckpointState` (new) | group | 209 |

Prefix = 1+32+32+8 = **73**; total body = 73+209 = 282; `LEN = 46 + 282 = 328`.
`anchor_mode` ∈ {1,2} (R7); `inner_image_id` zeroed in mode 1 (D3);
`chain_length` in the new state == prev + 1, `root_hash` carried through
unchanged (CLAIMS.md E5–E17).

### `0x0003` header-segment — `LEN = 46 + 124 = 170`

Header + body (CLAIMS.md §3.3); `reject_index` = offending block index:

| off | field | type | w |
|----:|---|---|---:|
| 0 | P1 `eta0` | `[u8;32]` | 32 |
| 32 | P2 `block_count` | `u32` | 4 |
| 36 | P3 `seg_first_hash` | `[u8;32]` | 32 |
| 68 | P4 `seg_first_number` | `u64` | 8 |
| 76 | P5 `seg_tip_hash` | `[u8;32]` | 32 |
| 108 | P6 `seg_tip_number` | `u64` | 8 |
| 116 | P7 `seg_tip_slot` | `u64` | 8 |

Body length = 32+4+32+8+32+8+8 = **124 bytes**; `LEN = 46 + 124 = 170`. (P4
`seg_first_number` `u64` at offset 68 → 76; P7 `seg_tip_slot` ends at 124.)

### `0x0004` tx-inclusion — body

Header + anchor-binding group + body (CLAIMS.md §3.4):

| off | field | type | w |
|----:|---|---|---:|
| 0 | I1 `anchor_mode` | `u8` | 1 |
| 1 | I2 `inner_image_id` | `[u8;32]` | 32 |
| 33 | I3 `anchor_tip_hash` | `[u8;32]` | 32 |
| 65 | I4 `certified_root` | `[u8;32]` | 32 |
| 97 | I5 `tx_hash` | `[u8;32]` | 32 |
| 129 | I6 `certified_epoch` | `u64` | 8 |
| 137 | I7 `certified_block_number` | `u64` | 8 |

Body length = 1+32+32+32+32+8+8 = **145 bytes**; `LEN = 46 + 145 = 191`.
`anchor_mode` ∈ {1,2} (R7); `inner_image_id` zeroed in mode 1.

### `0x0005` utxo-read — body

Header + anchor-binding + output group (CLAIMS.md §3.5):

| off | field | type | w |
|----:|---|---|---:|
| 0 | U1 `anchor_mode` | `u8` | 1 |
| 1 | U2 `inner_image_id` | `[u8;32]` | 32 |
| 33 | U3 `anchor_tip_hash` | `[u8;32]` | 32 |
| 65 | U4 `certified_root` | `[u8;32]` | 32 |
| 97 | U5 `tx_id` | `[u8;32]` | 32 |
| 129 | U6 `out_index` | `u16` | 2 |
| 131 | U7 `lovelace` | `u64` | 8 |
| 139 | U8 `address_hash` | `[u8;32]` | 32 |
| 171 | U9 `address_len` | `u16` | 2 |
| 173 | U10 `datum_kind` | `u8` | 1 |
| 174 | U11 `datum_commitment` | `[u8;32]` | 32 |
| 206 | U12 `spend_status` | `u8` | 1 |
| 207 | U13 `certified_epoch` | `u64` | 8 |
| 215 | U14 `certified_at_block` | `u64` | 8 |

Body length = 1+32+32+32+32+2+8+32+2+1+32+1+8+8 = **223 bytes**;
`LEN = 46 + 223 = 269`. `out_index` (U6) is `u16` BE, matching Sextant's BE-u16
outpoint key convention (`utxoset.rs:386`). `spend_status` (U12) MUST be `0`;
any nonzero value on `0x0005` rejects (CLAIMS.md U12/§4.6, R7). `datum_kind`
(U10) ∈ {0,1,2}; `datum_commitment` zeroed and non-consumable when kind 0 (D3).

*(The per-field offsets above are the frozen v1 layout; the `const OFFSET_*` /
`const LEN_*` block in `hg-claims` is the machine-checked source of truth and
the golden vectors pin every byte. Any arithmetic slip in this prose is
corrected by the golden vector, never the reverse — the vector is normative.)*

---

## Every field's necessity is proven by a mutant (§7 zoo)

CLAIMS.md §1.7 and THREAT_MODEL T-A1-1 require every journal field to earn a
mutant: a fixture where mutating that field's bytes changes the decoded
verdict/meaning, or a filed, reviewed verdict-irrelevance argument. This ADR
does not add fields; it fixes their bytes, so the zoo obligation transfers
directly. The "why load-bearing" column in every CLAIMS.md field table is the
seed. Fields that commit inputs verbatim (S1/S2, U5, I5, P1, …) satisfy the zoo
trivially — an input-byte flip is a journal-byte flip (CLAIMS.md §1.7). The
codec-specific mutants this ADR *newly* obligates:

- **Endianness mutant:** a journal byte-swapped from BE to LE for any
  multi-byte field decodes to a different value / fails the length or band gate
  — asserts the BE choice is load-bearing, not cosmetic (T-A4-3).
- **Presence-flag mutants (D3):** flip `has_certified_transactions` (S10) with
  S11–S13 held → the tx group flips between consumable and rejected; flip
  `datum_kind` (U10) 1↔2 with U11 held → the commitment's meaning changes
  (hash vs bytes-hash) — both A1-degenerate-path class (T-A1-2).
- **Verdict-table mutants (D6):** every reachable `SextantStatus` code has a
  fixture whose H5 byte carries exactly that code and whose native Sextant
  verdict matches (equality invariant T-A12-1); a code on a wrong claim type,
  or a collapsed/aliased code, fails.
- **Commitment-preimage mutants (D5):** altering `total_stake` under S5, the
  next-AVK signed part under S6, or the raw address under U8 changes the
  respective commitment; the golden vector locks the exact preimage bytes at M1
  so a preimage-shape drift is caught.
- **No-silent-canonicalization mutant (T-A4-5):** a second, non-canonical
  encoding of a valid claim (e.g. a length-padded or reordered buffer) fails
  the length/offset gate (R1) — there is no alternate buffer that decodes to
  the same claim, which is what makes the single-buffer digest sound.
- **Length-gate mutant (R1):** a journal one byte short/long for its
  `(version, type)` rejects before any field is trusted.

Coverage is tracked in `docs/journal-coverage.md`; `make gate` fails on gaps
(HANDOFF §7).

---

## Consequences

**Positive.**
- One canonical encoding per value by construction (flat, fixed-offset, no
  redundant framing) — the A4 downgrade/ABI-drift surface is closed
  structurally, not by runtime canonicalization that could itself diverge.
- The single-buffer / no-re-encode rule (D0) makes the Veridise blobstream0
  V-BLOB-VUL-004 class (digest over canonicalized bytes ≠ bytes acted on)
  *unrepresentable* in the router: there is no second buffer.
- Big-endian is native on both load-bearing ends (Sextant BE64, EVM words); no
  byte-swap in the guest or the router.
- The verdict table is Sextant's `SextantStatus` verbatim, so rejection parity
  (T-A12-1) is a byte comparison, and the C-ABI's own exhaustiveness discipline
  (`ffi.rs:244-247`: a new tier fails to compile) protects the mapping upstream.
- Fixed per-type length + fixed offsets let the Solidity router read fields with
  constant-offset calldata loads and let the whole codec be `const`-driven and
  golden-diffed across four surfaces (D8).

**Negative / accepted costs.**
- **No forward/backward wire compatibility across versions — by design.**
  `claim_version` is a single monotonic `u16` for the whole schema (CLAIMS.md
  §1.3); any field change is a new version and old encodings are rejected, not
  migrated. This is the fail-closed choice: no "best-effort" decode of an
  unknown layout (the Steel behavior generalized). The cost is that a schema
  change forces a coordinated version bump across guest/host/SDK/router — which
  is exactly the §9-gate-6 breaking-change review, intended.
- **Fixed-length journals waste bytes on zeroed optional slots** (S11–S13 when
  no certified transactions; U11 when no datum). Accepted: the wasted bytes are
  tens per journal, the calldata/gas cost is negligible against the proof
  verification cost, and the fixed layout is what buys canonicality and
  constant-offset reads. Variable-length data never enters the journal (only
  its commitment does), so the waste is bounded and small.
- **Two commitment preimages (S5, S6) are shape-frozen but byte-locked only at
  M1**, pending transcription of the mithril-stm 0.10.5 AVK wire order
  (sextant-legs.md §4). This ADR freezes the preimage *formula*
  (`Blake2b256(mt_root ‖ BE64(total_stake))`, `Blake2b256(next_avk_signed_bytes)`);
  the golden vector locks the bytes when the guest STM backend lands. This is
  the one place the freeze is formula-now, bytes-at-M1 — flagged as an open
  item rather than hidden.
- **The `hg-claims` ↔ Solidity mirror is a standing correctness obligation.**
  It is discharged by generated constants + cross-layer golden tests + the
  bindings-from-ABI CI check (D8), not by trust; if that machinery is
  weakened, ABI drift (A4) reopens.

**Neutral.**
- Shared-image-with-dispatch vs image-per-leg (CLAIMS.md §6 Q4) stays open for
  ADR-004: this header supports both, since `claim_type` is field 2 regardless
  and the length/offset tables are keyed on `(version, type)` either way.
- Genesis-anchor placement (guest-const vs journaled-input) stays with
  ADR-002/ADR-004; this ADR encodes H4 as a journaled field per HANDOFF §1 and
  CLAIMS.md H4, which is compatible with either final placement (a guest-const
  design still journals the anchor verbatim, just also binding it via image ID).

---

## Alternatives considered

1. **Little-endian journal.** Rejected: Sextant encodes big-endian (BE64
   opcert/VRF messages, BE-u16 outpoint keys — sextant-legs.md Leg 1/6) and EVM
   words are big-endian, so LE byte-swaps at *both* load-bearing ends. No
   upside; two byte-swap surfaces are two bug surfaces.
2. **Length-prefixed / TLV / offset-table framing.** Rejected: any
   self-describing framing is a second encoding of information the
   `(version, type)` pair already fixes, creating two buffers that decode to
   the same value — the exact canonicality hazard A4 exploits. Flat
   fixed-offset has one encoding per value by construction (D1).
3. **`serde`/`bincode` or CBOR/RLP for the journal.** Rejected: general codecs
   admit multiple encodings of the same value (CBOR notoriously — the very
   non-canonicality Sextant guards against by hashing block CBOR *verbatim*,
   sextant-legs.md Leg 5) and are painful to mirror constant-for-constant in
   Solidity. The journal is a fixed schema, not an open document; a bespoke
   flat layout is smaller, canonical, and trivially transcribed to calldata
   offsets.
4. **Config-digest `network_id` (Steel `configID`).** Rejected for Cardano:
   folds network + params + genesis into one opaque digest, but heliograph
   binds params (S7–S9) and genesis (H4) *explicitly and separately*, so a
   digest would reduce legibility. The network magic is protocol-native,
   self-describing, and human-checkable (D4). (Steel's *lesson* — an explicit,
   checked, version-tagged network field, unknown⇒reject — is adopted; only its
   opaque-digest *representation* is not.)
5. **Decode-into-struct then re-encode-to-hash in the router** (the
   Blobstream0 shape). Rejected as a soundness anti-pattern: sound only if the
   codec is strictly canonical, and even then it is a redundant round-trip that
   invites drift (V-BLOB-VUL-004). D0 mandates the single buffer instead.
6. **Collapsing verdict codes into coarse bands** (e.g. one "mithril error"
   code). Rejected: CLAIMS.md §4.1 requires one journal code per Sextant
   variant, no lossy collapsing — rejection *attribution* (which cert, which
   check) is a product requirement (CLAIMS.md §4.2), and collapsing would break
   rejection parity (T-A12-1) against native Sextant.
7. **`i32` verdict field to match `SextantStatus` exactly.** Rejected: the
   negative boundary/panic codes (−1…−9) are never journalable (a panic yields
   no proof, CLAIMS.md §4.4), so a signed field would encode unreachable
   states. `u16` holds every reachable band (≤411) and makes
   "no negative verdict is journalable" a type-level fact.
8. **Hand-written Solidity `sol!` bindings in the host** (sp1-helios's shape).
   Rejected: Zellic sp1-helios 3.3 is exactly this bug (bindings declared a
   function the contract lacked, omitted one it had). D8 generates bindings from
   the compiled ABI and CI-diffs them (T-A4-4).

---

## Citations

- **HANDOFF.md** §0 (journal-is-ABI, fail-closed, tier-preservation
  non-negotiables), §5 (architecture: `hg-claims` canonical/versioned/golden,
  mirrored constant-for-constant in Solidity; guest checked-arithmetic),
  §9 gate 6 (post-freeze schema changes), §11 (boring/explicit/canonical tone).
- **docs/CLAIMS.md** v0 — §1.2 (claim identity, inner image IDs are journal
  fields), §1.3 (single `u16` version; DRAFT 0; unknown-version rejection),
  §1.4 (fail-closed rejection triggers), §1.7 (every field earns a mutant),
  §1.8 (encoding discipline — fixed-width, no varints, explicit presence flags,
  normative order, one encoding per value; BE recommendation), §2 (header
  H1–H6), §2.1 (registry, 0x0F00 bench band), §2.3 (anchor modes 1/2,
  `inner_image_id`), §2.4 (`CheckpointState` S1–S13), §3.1–§3.5 (bodies for
  0x0001–0x0005), §4 (rejection semantics, verdict codes to ADR-003), §4.6
  (verifier-side rejections), §5 (explicit non-claims), §6 open questions
  2/5/6 (codec/endianness, network_id encoding, verdict table — all resolved
  here).
- **docs/THREAT_MODEL.md** v1 — A2 (cross-network replay; `network_id`
  field / T-A2-1..3), A3 (cross-image replay; inner-ID journaling / T-A3-1..2),
  **A4** (claim-version downgrade / ABI drift; T-A4-1 unknown-version reject,
  T-A4-3 canonicality, **T-A4-4 bindings-from-ABI**, **T-A4-5
  no-silent-canonicalization**), A11 (re-genesis; genesis_vkey journaled + R4),
  A12 (Sextant-inherited assumptions; tier/assumption fields journaled,
  T-A12-1 equality invariant, T-A12-2 tier-laundering negative).
- **docs/notes/sextant-legs.md** (@ `3a68b2f`) — Leg 1 (BE64 opcert/VRF
  messages; header/eta0 fields), Leg 2 (`compute_hash` content hashes = S1/S2;
  signed-parts-only rule for S6/S11; AVK `{mt_commitment.root, total_stake}`
  shape for S5), Leg 3/4 (inclusion + utxo-read fields; Blake2b address hash;
  `SpendStatus::NotEstablished` pinned), Leg 6 (`tx_id ‖ BE-u16 index` key =
  U6 convention), §2.3 (STM verify structure), §4 (mithril-stm 0.10.5 AVK wire
  order unresolved → S5/S6 bytes locked at M1).
- **docs/notes/lightclient-patterns.md** — §2c (Steel `configID` /
  version-tagged commitment, unknown⇒reject — the explicit-network-field
  lesson), §3 (aggregation-example discipline: inner image ID as input MUST be
  journaled; sp1-vector claim-type-first), §4 (anti-patterns: under-constrained
  journal #1, ABI-too-small-then-evolved #2, panic-as-rejection #6).
- **Sextant** `src/ffi.rs:46,58-75,83-136,191-242` (@ `3a68b2f`,
  `SEXTANT_ABI_VERSION = 5`) — the `SextantStatus` verdict enum (D6 table
  verbatim), the spend/basis band constants, `SextantVerifiedOutput` /
  `SextantSpendStatus` shapes, and the exhaustive-match tripwire
  (`ffi.rs:244-247`).

---

## HANDOFF (for the next session / the BUILD phase)

- **`hg-claims` is the deliverable this ADR specifies.** BUILD it as the single
  `no_std + alloc` codec: one `const` block of `OFFSET_*` / `WIDTH_*` / `LEN_*`
  / verdict codes / network magics (the source of truth), one `encode`/`decode`
  per claim type over a single flat buffer, exposing gated payloads only through
  accessors that enforce the D3 "MUST NOT consume when flag 0" rule at the type
  level. Mirror the `const` block into `Constants.sol` mechanically (D8); do not
  re-type any constant.
- **The golden vectors are normative over this prose.** Where a hand-computed
  offset/length in the body-layout tables above disagrees with the `const`
  block, the `const` block + golden vector win; fix the doc, never the vector.
  Freeze the byte-exact golden journals per claim type at the CLAIMS.md v1
  freeze (Phase-2), one accepted and one rejected per type minimum (HANDOFF §7).
- **S5 / S6 preimage bytes lock at M1.** The preimage *formulas* are frozen
  (D5); transcribe the mithril-stm 0.10.5 AVK wire byte order when the guest STM
  backend lands (sextant-legs.md §4), then lock S5/S6 golden bytes. This is the
  single "formula-now, bytes-at-M1" item — do not treat it as unresolved
  *layout*; the offsets are fixed, only the preimage byte order of a hashed
  input remains to be pinned.
- **Wire the mutant zoo from this ADR's list** (the "necessity by mutant"
  section) into `docs/journal-coverage.md` as codec-specific classes: endianness,
  presence-flag, verdict-table, commitment-preimage, no-silent-canonicalization,
  length-gate — on top of the per-field input-flip mutants CLAIMS.md already
  seeds. `make gate` fails on coverage gaps (HANDOFF §7).
- **D8 bindings-from-ABI is a CI job, not a convention.** Generate host + SDK
  Solidity bindings from Foundry `out/*.json`, commit them, diff in CI
  (T-A4-4). Land it with the router in M4; until then, no hand-written `sol!`.
- **Open, deliberately deferred (not blocking v1 freeze):** bodies for deferred
  claim types 0x0006–0x0008 (band reserved, header + shared groups reusable);
  checkpoint-extension batch width > 1 (CLAIMS.md §6 Q7 / ADR-002 economics
  after M0); shared-image-vs-image-per-leg (ADR-004). None of these re-layout
  0x0001–0x0005.
