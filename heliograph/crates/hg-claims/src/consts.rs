//! The one place any offset, width, length, network magic, version id, or
//! claim-type id is written (ADR-003 D0/D8). Transcribed from the ADR-003 D2
//! header table and the per-claim body tables — never re-derived. The golden
//! vectors are normative over this block; the `const _` asserts below only
//! check the transcription's internal arithmetic.

// ── Common header (ADR-003 D2) — 46 bytes, identical for every claim type ──
pub const HDR_OFF_VERSION: usize = 0;
pub const HDR_W_VERSION: usize = 2;
pub const HDR_OFF_CLAIM_TYPE: usize = 2;
pub const HDR_W_CLAIM_TYPE: usize = 2;
pub const HDR_OFF_NETWORK_ID: usize = 4;
pub const HDR_W_NETWORK_ID: usize = 4;
pub const HDR_OFF_GENESIS_VKEY: usize = 8;
pub const HDR_W_GENESIS_VKEY: usize = 32;
pub const HDR_OFF_VERDICT: usize = 40;
pub const HDR_W_VERDICT: usize = 2;
pub const HDR_OFF_REJECT_INDEX: usize = 42;
pub const HDR_W_REJECT_INDEX: usize = 4;
pub const HDR_LEN: usize = 46;
pub const BODY_OFF: usize = 46;

// ── CheckpointState shared group (ADR-003 §CheckpointState) — 209 bytes ──
// Offsets are WITHIN the group; add BODY_OFF (0x0001) or BODY_OFF +
// EXT_OFF_NEW_STATE (0x0002).
pub const CS_OFF_ROOT_HASH: usize = 0;
pub const CS_W_HASH: usize = 32;
pub const CS_OFF_TIP_HASH: usize = 32;
pub const CS_OFF_TIP_EPOCH: usize = 64;
pub const CS_W_U64: usize = 8;
pub const CS_OFF_CHAIN_LENGTH: usize = 72;
pub const CS_W_U32: usize = 4;
pub const CS_OFF_AVK_COMMITMENT: usize = 76;
pub const CS_OFF_NEXT_AVK_COMMIT: usize = 108;
pub const CS_OFF_STM_K: usize = 140;
pub const CS_OFF_STM_M: usize = 148;
// u32, U8F24 fixed-point phi_f — Sextant's exact encoding (mithril.rs:892-894).
pub const CS_OFF_STM_PHI_F_FIXED: usize = 156;
pub const CS_OFF_HAS_CERT_TXS: usize = 160;
pub const CS_W_U8: usize = 1;
// S11-S13 — presence-gated by S10 (ADR-003 D3).
pub const CS_OFF_CTX_MERKLE_ROOT: usize = 161;
pub const CS_OFF_CTX_EPOCH: usize = 193;
pub const CS_OFF_CTX_BLOCK_NUMBER: usize = 201;
pub const CS_LEN: usize = 209;

// ── Anchor-binding shared group (CLAIMS §2.3) — 33-byte body prefix of
// 0x0002 / 0x0004 / 0x0005 ──
pub const ANCHOR_OFF_MODE: usize = 0;
// [u8;32], zeroed in External mode (ADR-003 D3).
pub const ANCHOR_OFF_INNER_IMAGE_ID: usize = 1;
pub const ANCHOR_LEN: usize = 33;

// ── 0x0002 checkpoint-extension body (offsets within the body) ──
pub const EXT_OFF_ANCHOR: usize = 0;
pub const EXT_OFF_PREV_TIP_HASH: usize = 33;
pub const EXT_OFF_PREV_TIP_EPOCH: usize = 65;
pub const EXT_OFF_NEW_STATE: usize = 73;

// ── 0x0003 header-segment body (offsets within the body) ──
pub const HS_OFF_ETA0: usize = 0;
pub const HS_OFF_BLOCK_COUNT: usize = 32;
pub const HS_OFF_SEG_FIRST_HASH: usize = 36;
pub const HS_OFF_SEG_FIRST_NUMBER: usize = 68;
pub const HS_OFF_SEG_TIP_HASH: usize = 76;
pub const HS_OFF_SEG_TIP_NUMBER: usize = 108;
pub const HS_OFF_SEG_TIP_SLOT: usize = 116;
pub const HS_BODY_LEN: usize = 124;

// ── 0x0004 tx-inclusion body (offsets within the body) ──
pub const TX_OFF_ANCHOR: usize = 0;
pub const TX_OFF_ANCHOR_TIP_HASH: usize = 33;
pub const TX_OFF_CERTIFIED_ROOT: usize = 65;
pub const TX_OFF_TX_HASH: usize = 97;
pub const TX_OFF_CERTIFIED_EPOCH: usize = 129;
pub const TX_OFF_CERTIFIED_BLOCK_NUMBER: usize = 137;
pub const TX_BODY_LEN: usize = 145;

// ── 0x0005 utxo-read body (offsets within the body) ──
pub const UR_OFF_ANCHOR: usize = 0;
pub const UR_OFF_ANCHOR_TIP_HASH: usize = 33;
pub const UR_OFF_CERTIFIED_ROOT: usize = 65;
pub const UR_OFF_TX_ID: usize = 97;
// u16 BE — Sextant's BE-u16 outpoint key convention (utxoset.rs:386).
pub const UR_OFF_OUT_INDEX: usize = 129;
pub const UR_OFF_LOVELACE: usize = 131;
pub const UR_OFF_ADDRESS_HASH: usize = 139;
pub const UR_OFF_ADDRESS_LEN: usize = 171;
pub const UR_OFF_DATUM_KIND: usize = 173;
// [u8;32], gated by datum_kind (ADR-003 D3/D5).
pub const UR_OFF_DATUM_COMMITMENT: usize = 174;
// u8, MUST be 0 (NotEstablished) on 0x0005 (CLAIMS U12, R7).
pub const UR_OFF_SPEND_STATUS: usize = 206;
pub const UR_OFF_CERTIFIED_EPOCH: usize = 207;
pub const UR_OFF_CERTIFIED_AT_BLOCK: usize = 215;
pub const UR_BODY_LEN: usize = 223;

// ── Per-claim total lengths (ADR-003) — the R1 length gate keys on these ──
pub const LEN_CHECKPOINT: usize = 255;
pub const LEN_CHECKPOINT_EXTENSION: usize = 328;
pub const LEN_HEADER_SEGMENT: usize = 170;
pub const LEN_TX_INCLUSION: usize = 191;
pub const LEN_UTXO_READ: usize = 269;

// ── Claim-type ids (CLAIMS §2.1 registry) ──
pub const CLAIM_TYPE_CHECKPOINT: u16 = 0x0001;
pub const CLAIM_TYPE_CHECKPOINT_EXTENSION: u16 = 0x0002;
pub const CLAIM_TYPE_HEADER_SEGMENT: u16 = 0x0003;
pub const CLAIM_TYPE_TX_INCLUSION: u16 = 0x0004;
pub const CLAIM_TYPE_UTXO_READ: u16 = 0x0005;
// Reserved / deferred — banded now so a later addition is an extension,
// never a re-numbering; NOT decodable by this codec (R3 fail-closed).
pub const CLAIM_TYPE_WATCHED_WINDOW_RESERVED: u16 = 0x0006;
pub const CLAIM_TYPE_CERTIFIED_SET_MEMBERSHIP_RESERVED: u16 = 0x0007;
pub const CLAIM_TYPE_CERTIFIED_SET_TRANSITION_RESERVED: u16 = 0x0008;
// Benchmark-only band (BENCH.md §2.3) — never production, never decodable.
pub const CLAIM_TYPE_BENCH_BAND_MIN: u16 = 0x0F00;
pub const CLAIM_TYPE_BENCH_BAND_MAX: u16 = 0x0FFF;

// ── Claim versions (CLAIMS §1.3) ──
// DRAFT 0: pre-freeze development only; rejected unconditionally by every
// production verifier path. V1 is assigned at the CLAIMS.md v1 freeze.
pub const CLAIM_VERSION_DRAFT: u16 = 0;
pub const CLAIM_VERSION_V1: u16 = 1;

// ── Network magics (ADR-003 D4) — Cardano network magic, u32 BE ──
pub const NET_MAGIC_MAINNET: u32 = 764_824_073; // 0x2D96_4A09
pub const NET_MAGIC_PREPROD: u32 = 1;
pub const NET_MAGIC_PREVIEW: u32 = 2;

// Transcription-consistency proofs (compile-time; the golden vectors remain
// the normative pin).
const _: () = assert!(HDR_LEN == HDR_OFF_REJECT_INDEX + HDR_W_REJECT_INDEX);
const _: () = assert!(CS_LEN == CS_OFF_CTX_BLOCK_NUMBER + CS_W_U64);
const _: () = assert!(ANCHOR_LEN == ANCHOR_OFF_INNER_IMAGE_ID + CS_W_HASH);
const _: () = assert!(HS_BODY_LEN == HS_OFF_SEG_TIP_SLOT + CS_W_U64);
const _: () = assert!(TX_BODY_LEN == TX_OFF_CERTIFIED_BLOCK_NUMBER + CS_W_U64);
const _: () = assert!(UR_BODY_LEN == UR_OFF_CERTIFIED_AT_BLOCK + CS_W_U64);
const _: () = assert!(LEN_CHECKPOINT == HDR_LEN + CS_LEN);
const _: () = assert!(LEN_CHECKPOINT_EXTENSION == HDR_LEN + EXT_OFF_NEW_STATE + CS_LEN);
const _: () = assert!(LEN_HEADER_SEGMENT == HDR_LEN + HS_BODY_LEN);
const _: () = assert!(LEN_TX_INCLUSION == HDR_LEN + TX_BODY_LEN);
const _: () = assert!(LEN_UTXO_READ == HDR_LEN + UR_BODY_LEN);
