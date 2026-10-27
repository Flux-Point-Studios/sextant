//! Shared fixtures. The golden hex constants were derived from the ADR-003
//! layout tables by an independent construction (not by this crate's encoder),
//! so the encoder is tested against an implementation-independent target.
//! Synthetic field values; the LAYOUT is what is golden.

use hg_claims::{
    AnchorField, CertifiedTxFields, CheckpointExtensionFields, CheckpointFields,
    CheckpointStateFields, Claim, ClaimVersion, DatumField, HeaderFields, HeaderSegmentFields,
    NetworkId, TxInclusionFields, UtxoReadFields, Verdict,
};

pub const GENESIS_VKEY: [u8; 32] = [0x47; 32];

pub fn h32(b: u8) -> [u8; 32] {
    [b; 32]
}

pub fn header(verdict: Verdict, reject_index: u32) -> HeaderFields {
    HeaderFields {
        version: ClaimVersion::V1,
        network_id: NetworkId::MAINNET,
        genesis_vkey: GENESIS_VKEY,
        verdict,
        reject_index,
    }
}

pub fn zero_state() -> CheckpointStateFields {
    CheckpointStateFields {
        root_hash: [0; 32],
        tip_hash: [0; 32],
        tip_epoch: 0,
        chain_length: 0,
        avk_commitment: [0; 32],
        next_avk_commitment: [0; 32],
        stm_k: 0,
        stm_m: 0,
        stm_phi_f_fixed: 0,
        certified_transactions: None,
    }
}

pub fn checkpoint_accept() -> CheckpointFields {
    CheckpointFields {
        header: header(Verdict::Ok, 0),
        state: CheckpointStateFields {
            root_hash: h32(0x11),
            tip_hash: h32(0x22),
            tip_epoch: 500,
            chain_length: 106,
            avk_commitment: h32(0x33),
            next_avk_commitment: h32(0x44),
            stm_k: 2422,
            stm_m: 20973,
            stm_phi_f_fixed: 0x0028_F5C2,
            certified_transactions: Some(CertifiedTxFields {
                ctx_merkle_root: h32(0x55),
                ctx_epoch: 500,
                ctx_block_number: 11_000_000,
            }),
        },
    }
}

/// Rejection journal (CLAIMS §4.2): identity fields populated (`root_hash`),
/// payload the walk never reached zeroed.
pub fn checkpoint_reject() -> CheckpointFields {
    CheckpointFields {
        header: header(Verdict::MithrilChainHash, 3),
        state: CheckpointStateFields {
            root_hash: h32(0x11),
            ..zero_state()
        },
    }
}

pub fn checkpoint_extension_accept() -> CheckpointExtensionFields {
    CheckpointExtensionFields {
        header: header(Verdict::Ok, 0),
        anchor: AnchorField::Composed(h32(0xC2)),
        prev_tip_hash: h32(0x22),
        prev_tip_epoch: 500,
        new_state: CheckpointStateFields {
            root_hash: h32(0x11),
            tip_hash: h32(0x66),
            tip_epoch: 501,
            chain_length: 107,
            avk_commitment: h32(0x44),
            next_avk_commitment: h32(0x77),
            stm_k: 2422,
            stm_m: 20973,
            stm_phi_f_fixed: 0x0028_F5C2,
            certified_transactions: None,
        },
    }
}

pub fn checkpoint_extension_reject() -> CheckpointExtensionFields {
    CheckpointExtensionFields {
        header: header(Verdict::MithrilChainBrokenLink, 1),
        anchor: AnchorField::External,
        prev_tip_hash: h32(0x33),
        prev_tip_epoch: 500,
        new_state: zero_state(),
    }
}

pub fn header_segment_accept() -> HeaderSegmentFields {
    HeaderSegmentFields {
        header: header(Verdict::Ok, 0),
        eta0: h32(0xE7),
        block_count: 4320,
        seg_first_hash: h32(0x88),
        seg_first_number: 11_000_001,
        seg_tip_hash: h32(0x99),
        seg_tip_number: 11_004_320,
        seg_tip_slot: 133_660_800,
    }
}

pub fn header_segment_reject() -> HeaderSegmentFields {
    HeaderSegmentFields {
        header: header(Verdict::ChainVrf, 7),
        eta0: h32(0xE7),
        block_count: 0,
        seg_first_hash: h32(0x88),
        seg_first_number: 11_000_001,
        seg_tip_hash: [0; 32],
        seg_tip_number: 0,
        seg_tip_slot: 0,
    }
}

pub fn tx_inclusion_accept() -> TxInclusionFields {
    TxInclusionFields {
        header: header(Verdict::Ok, 0),
        anchor: AnchorField::External,
        anchor_tip_hash: h32(0x22),
        certified_root: h32(0x55),
        tx_hash: h32(0xAB),
        certified_epoch: 500,
        certified_block_number: 11_000_000,
    }
}

/// `NotIncluded` is a journaled rejection over a fully populated body: the
/// membership check ran against a populated `certified_root` (ADR-003 R6 note).
pub fn tx_inclusion_reject() -> TxInclusionFields {
    TxInclusionFields {
        header: header(Verdict::UtxoInclusionNotIncluded, 0),
        anchor: AnchorField::Composed(h32(0xC4)),
        anchor_tip_hash: h32(0x22),
        certified_root: h32(0x55),
        tx_hash: h32(0xAC),
        certified_epoch: 500,
        certified_block_number: 11_000_000,
    }
}

pub fn utxo_read_accept() -> UtxoReadFields {
    UtxoReadFields {
        header: header(Verdict::Ok, 0),
        anchor: AnchorField::Composed(h32(0xC5)),
        anchor_tip_hash: h32(0x22),
        certified_root: h32(0x55),
        tx_id: h32(0xAB),
        out_index: 3,
        lovelace: 1_234_567,
        address_hash: h32(0xAD),
        address_len: 57,
        datum: DatumField::Hash(h32(0xDA)),
        certified_epoch: 500,
        certified_at_block: 11_000_000,
    }
}

pub fn utxo_read_reject() -> UtxoReadFields {
    UtxoReadFields {
        header: header(Verdict::UtxoOutputIndexOutOfRange, 0),
        anchor: AnchorField::External,
        anchor_tip_hash: h32(0x22),
        certified_root: h32(0x55),
        tx_id: h32(0xAB),
        out_index: 9,
        lovelace: 0,
        address_hash: [0; 32],
        address_len: 0,
        datum: DatumField::None,
        certified_epoch: 500,
        certified_at_block: 11_000_000,
    }
}

pub const GOLDEN_CHECKPOINT_ACCEPT: &str = concat!(
    "000100012d964a0947474747474747474747474747474747474747474747474747474747474747470000000000001111",
    "111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222",
    "222222222222222222222222222200000000000001f40000006a33333333333333333333333333333333333333333333",
    "333333333333333333334444444444444444444444444444444444444444444444444444444444444444000000000000",
    "097600000000000051ed0028f5c201555555555555555555555555555555555555555555555555555555555555555500",
    "000000000001f40000000000a7d8c0",
);

pub const GOLDEN_CHECKPOINT_REJECT: &str = concat!(
    "000100012d964a094747474747474747474747474747474747474747474747474747474747474747012d000000031111",
    "111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000",
);

pub const GOLDEN_CHECKPOINT_EXTENSION_ACCEPT: &str = concat!(
    "000100022d964a09474747474747474747474747474747474747474747474747474747474747474700000000000002c2",
    "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c22222222222222222222222222222222222",
    "22222222222222222222222222222200000000000001f411111111111111111111111111111111111111111111111111",
    "11111111111111666666666666666666666666666666666666666666666666666666666666666600000000000001f500",
    "00006b444444444444444444444444444444444444444444444444444444444444444477777777777777777777777777",
    "77777777777777777777777777777777777777000000000000097600000000000051ed0028f5c2000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
);

pub const GOLDEN_CHECKPOINT_EXTENSION_REJECT: &str = concat!(
    "000100022d964a094747474747474747474747474747474747474747474747474747474747474747012e000000010100",
    "000000000000000000000000000000000000000000000000000000000000003333333333333333333333333333333333",
    "33333333333333333333333333333300000000000001f400000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
);

pub const GOLDEN_HEADER_SEGMENT_ACCEPT: &str = concat!(
    "000100032d964a094747474747474747474747474747474747474747474747474747474747474747000000000000e7e7",
    "e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7000010e08888888888888888888888888888",
    "8888888888888888888888888888888888880000000000a7d8c199999999999999999999999999999999999999999999",
    "999999999999999999990000000000a7e9a00000000007f78080",
);

pub const GOLDEN_HEADER_SEGMENT_REJECT: &str = concat!(
    "000100032d964a09474747474747474747474747474747474747474747474747474747474747474700cb00000007e7e7",
    "e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7000000008888888888888888888888888888",
    "8888888888888888888888888888888888880000000000a7d8c100000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000",
);

pub const GOLDEN_TX_INCLUSION_ACCEPT: &str = concat!(
    "000100042d964a0947474747474747474747474747474747474747474747474747474747474747470000000000000100",
    "000000000000000000000000000000000000000000000000000000000000002222222222222222222222222222222222",
    "2222222222222222222222222222225555555555555555555555555555555555555555555555555555555555555555ab",
    "ababababababababababababababababababababababababababababababab00000000000001f40000000000a7d8c0",
);

pub const GOLDEN_TX_INCLUSION_REJECT: &str = concat!(
    "000100042d964a09474747474747474747474747474747474747474747474747474747474747474701900000000002c4",
    "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c42222222222222222222222222222222222",
    "2222222222222222222222222222225555555555555555555555555555555555555555555555555555555555555555ac",
    "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac00000000000001f40000000000a7d8c0",
);

pub const GOLDEN_UTXO_READ_ACCEPT: &str = concat!(
    "000100052d964a09474747474747474747474747474747474747474747474747474747474747474700000000000002c5",
    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c52222222222222222222222222222222222",
    "2222222222222222222222222222225555555555555555555555555555555555555555555555555555555555555555ab",
    "ababababababababababababababababababababababababababababababab0003000000000012d687adadadadadadad",
    "adadadadadadadadadadadadadadadadadadadadadadadadad003901dadadadadadadadadadadadadadadadadadadada",
    "dadadadadadadadadadadada0000000000000001f40000000000a7d8c0",
);

pub const GOLDEN_UTXO_READ_REJECT: &str = concat!(
    "000100052d964a094747474747474747474747474747474747474747474747474747474747474747019b000000000100",
    "000000000000000000000000000000000000000000000000000000000000002222222222222222222222222222222222",
    "2222222222222222222222222222225555555555555555555555555555555555555555555555555555555555555555ab",
    "ababababababababababababababababababababababababababababababab0009000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000001f40000000000a7d8c0",
);

/// Decode expecting a structural rejection; panics on acceptance.
pub fn decode_err(buf: &[u8]) -> hg_claims::DecodeError {
    match hg_claims::decode_structural(buf) {
        Ok(_) => panic!("expected structural rejection, journal decoded"),
        Err(e) => e,
    }
}

/// Draft-mode decode expecting a structural rejection; panics on acceptance.
pub fn decode_draft_err(buf: &[u8]) -> hg_claims::DecodeError {
    match hg_claims::decode_structural_draft(buf) {
        Ok(_) => panic!("expected structural rejection, draft journal decoded"),
        Err(e) => e,
    }
}

pub fn golden_bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("golden hex is valid")
}

pub fn all_goldens() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("checkpoint_accept", golden_bytes(GOLDEN_CHECKPOINT_ACCEPT)),
        ("checkpoint_reject", golden_bytes(GOLDEN_CHECKPOINT_REJECT)),
        (
            "checkpoint_extension_accept",
            golden_bytes(GOLDEN_CHECKPOINT_EXTENSION_ACCEPT),
        ),
        (
            "checkpoint_extension_reject",
            golden_bytes(GOLDEN_CHECKPOINT_EXTENSION_REJECT),
        ),
        (
            "header_segment_accept",
            golden_bytes(GOLDEN_HEADER_SEGMENT_ACCEPT),
        ),
        (
            "header_segment_reject",
            golden_bytes(GOLDEN_HEADER_SEGMENT_REJECT),
        ),
        (
            "tx_inclusion_accept",
            golden_bytes(GOLDEN_TX_INCLUSION_ACCEPT),
        ),
        (
            "tx_inclusion_reject",
            golden_bytes(GOLDEN_TX_INCLUSION_REJECT),
        ),
        ("utxo_read_accept", golden_bytes(GOLDEN_UTXO_READ_ACCEPT)),
        ("utxo_read_reject", golden_bytes(GOLDEN_UTXO_READ_REJECT)),
    ]
}

/// Serialize every accessor of a decoded claim into a comparable byte string.
/// Test-only: the production codec never re-encodes a view (ADR-003 D0); this
/// exists so the mutant zoo can assert "some decoded field differs".
pub fn fingerprint(claim: &Claim) -> Vec<u8> {
    let mut f = Vec::new();
    let h = claim.header();
    f.extend(h.claim_version().as_u16().to_be_bytes());
    f.extend(h.claim_type().as_u16().to_be_bytes());
    f.extend(h.network_id().as_u32().to_be_bytes());
    f.extend(h.genesis_vkey());
    f.extend(h.verdict().as_u16().to_be_bytes());
    f.extend(h.reject_index().to_be_bytes());
    match claim {
        Claim::Checkpoint(v) => fp_state(&mut f, &v.state()),
        Claim::CheckpointExtension(v) => {
            fp_anchor(&mut f, &v.anchor());
            f.extend(v.prev_tip_hash());
            f.extend(v.prev_tip_epoch().to_be_bytes());
            fp_state(&mut f, &v.new_state());
        }
        Claim::HeaderSegment(v) => {
            f.extend(v.eta0());
            f.extend(v.block_count().to_be_bytes());
            f.extend(v.seg_first_hash());
            f.extend(v.seg_first_number().to_be_bytes());
            f.extend(v.seg_tip_hash());
            f.extend(v.seg_tip_number().to_be_bytes());
            f.extend(v.seg_tip_slot().to_be_bytes());
        }
        Claim::TxInclusion(v) => {
            fp_anchor(&mut f, &v.anchor());
            f.extend(v.anchor_tip_hash());
            f.extend(v.certified_root());
            f.extend(v.tx_hash());
            f.extend(v.certified_epoch().to_be_bytes());
            f.extend(v.certified_block_number().to_be_bytes());
        }
        Claim::UtxoRead(v) => {
            fp_anchor(&mut f, &v.anchor());
            f.extend(v.anchor_tip_hash());
            f.extend(v.certified_root());
            f.extend(v.tx_id());
            f.extend(v.out_index().to_be_bytes());
            f.extend(v.lovelace().to_be_bytes());
            f.extend(v.address_hash());
            f.extend(v.address_len().to_be_bytes());
            f.push(v.datum_kind().as_u8());
            match v.datum_commitment() {
                None => f.push(0),
                Some(c) => {
                    f.push(1);
                    f.extend(c);
                }
            }
            f.push(v.spend_status().as_u8());
            f.extend(v.certified_epoch().to_be_bytes());
            f.extend(v.certified_at_block().to_be_bytes());
        }
    }
    f
}

fn fp_state(f: &mut Vec<u8>, s: &hg_claims::CheckpointState) {
    f.extend(s.root_hash());
    f.extend(s.tip_hash());
    f.extend(s.tip_epoch().to_be_bytes());
    f.extend(s.chain_length().to_be_bytes());
    f.extend(s.avk_commitment());
    f.extend(s.next_avk_commitment());
    f.extend(s.stm_k().to_be_bytes());
    f.extend(s.stm_m().to_be_bytes());
    f.extend(s.stm_phi_f_fixed().to_be_bytes());
    f.push(u8::from(s.has_certified_transactions()));
    match s.certified_transactions() {
        None => f.push(0),
        Some(ctx) => {
            f.push(1);
            f.extend(ctx.ctx_merkle_root);
            f.extend(ctx.ctx_epoch.to_be_bytes());
            f.extend(ctx.ctx_block_number.to_be_bytes());
        }
    }
}

fn fp_anchor(f: &mut Vec<u8>, a: &hg_claims::AnchorBinding) {
    f.push(a.mode().as_u8());
    match a.inner_image_id() {
        None => f.push(0),
        Some(id) => {
            f.push(1);
            f.extend(id);
        }
    }
}
