//! The frozen numeric surfaces: claim-type ids, version ids, network magics,
//! the D6 verdict table (1:1 SextantStatus, ABI v5), discriminants, and the
//! const-block arithmetic ADR-003 transcribes.

use hg_claims::consts::*;
use hg_claims::{
    AnchorMode, ClaimType, ClaimVersion, DatumKind, DecodeError, NetworkId, SpendStatus, Verdict,
};

#[test]
fn claim_version_ids() {
    assert_eq!(CLAIM_VERSION_DRAFT, 0);
    assert_eq!(CLAIM_VERSION_V1, 1);
    assert_eq!(ClaimVersion::Draft.as_u16(), CLAIM_VERSION_DRAFT);
    assert_eq!(ClaimVersion::V1.as_u16(), CLAIM_VERSION_V1);
    assert_eq!(ClaimVersion::from_u16(0), Ok(ClaimVersion::Draft));
    assert_eq!(ClaimVersion::from_u16(1), Ok(ClaimVersion::V1));
    assert_eq!(
        ClaimVersion::from_u16(2),
        Err(DecodeError::UnknownVersion(2))
    );
}

#[test]
fn claim_type_ids_and_bands() {
    assert_eq!(ClaimType::Checkpoint.as_u16(), 0x0001);
    assert_eq!(ClaimType::CheckpointExtension.as_u16(), 0x0002);
    assert_eq!(ClaimType::HeaderSegment.as_u16(), 0x0003);
    assert_eq!(ClaimType::TxInclusion.as_u16(), 0x0004);
    assert_eq!(ClaimType::UtxoRead.as_u16(), 0x0005);
    // Reserved deferred band + bench band are named but NOT decodable.
    assert_eq!(CLAIM_TYPE_WATCHED_WINDOW_RESERVED, 0x0006);
    assert_eq!(CLAIM_TYPE_CERTIFIED_SET_MEMBERSHIP_RESERVED, 0x0007);
    assert_eq!(CLAIM_TYPE_CERTIFIED_SET_TRANSITION_RESERVED, 0x0008);
    assert_eq!(CLAIM_TYPE_BENCH_BAND_MIN, 0x0F00);
    assert_eq!(CLAIM_TYPE_BENCH_BAND_MAX, 0x0FFF);
    for raw in 1u16..=5 {
        let t = ClaimType::from_u16(raw).expect("production band decodes");
        assert_eq!(t.as_u16(), raw);
    }
    for raw in [0x0000, 0x0006, 0x0007, 0x0008, 0x0F00, 0x0FFF] {
        assert_eq!(
            ClaimType::from_u16(raw),
            Err(DecodeError::UnknownClaimType(raw))
        );
    }
}

#[test]
fn claim_type_expected_len() {
    assert_eq!(ClaimType::Checkpoint.expected_len(), LEN_CHECKPOINT);
    assert_eq!(
        ClaimType::CheckpointExtension.expected_len(),
        LEN_CHECKPOINT_EXTENSION
    );
    assert_eq!(ClaimType::HeaderSegment.expected_len(), LEN_HEADER_SEGMENT);
    assert_eq!(ClaimType::TxInclusion.expected_len(), LEN_TX_INCLUSION);
    assert_eq!(ClaimType::UtxoRead.expected_len(), LEN_UTXO_READ);
}

#[test]
fn claim_type_anchor_binding_presence() {
    assert!(!ClaimType::Checkpoint.has_anchor_binding());
    assert!(ClaimType::CheckpointExtension.has_anchor_binding());
    assert!(!ClaimType::HeaderSegment.has_anchor_binding());
    assert!(ClaimType::TxInclusion.has_anchor_binding());
    assert!(ClaimType::UtxoRead.has_anchor_binding());
}

#[test]
fn network_magics() {
    assert_eq!(NET_MAGIC_MAINNET, 764_824_073);
    assert_eq!(NET_MAGIC_MAINNET, 0x2D96_4A09);
    assert_eq!(NET_MAGIC_PREPROD, 1);
    assert_eq!(NET_MAGIC_PREVIEW, 2);
    assert_eq!(NetworkId::MAINNET.as_u32(), NET_MAGIC_MAINNET);
    assert_eq!(NetworkId::PREPROD.as_u32(), NET_MAGIC_PREPROD);
    assert_eq!(NetworkId::PREVIEW.as_u32(), NET_MAGIC_PREVIEW);
    assert!(NetworkId::MAINNET.is_known());
    assert!(NetworkId::PREPROD.is_known());
    assert!(NetworkId::PREVIEW.is_known());
    // Any other u32 is a structurally valid devnet magic (D4): it round-trips;
    // the verifier's pinned set — not the codec — is the allowlist.
    let devnet = NetworkId::from_u32(42);
    assert_eq!(devnet.as_u32(), 42);
    assert!(!devnet.is_known());
}

#[test]
fn verdict_table_is_total_and_lossless() {
    // D6: every code maps back to exactly one variant, same integer.
    assert_eq!(Verdict::ALL.len(), 38);
    for v in Verdict::ALL {
        assert_eq!(Verdict::from_u16(v.as_u16()), Ok(v));
    }
    let mut codes: Vec<u16> = Verdict::ALL.iter().map(|v| v.as_u16()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 38, "no aliased verdict codes");
}

#[test]
fn verdict_band_values_spot_check() {
    // Transcribed from Sextant SextantStatus (ffi.rs:83-136, ABI v5).
    assert_eq!(Verdict::Ok.as_u16(), 0);
    assert_eq!(Verdict::DecodeMalformedCbor.as_u16(), 100);
    assert_eq!(Verdict::KesPeriodOutOfRange.as_u16(), 122);
    assert_eq!(Verdict::ChainDecode.as_u16(), 200);
    assert_eq!(Verdict::ChainKes.as_u16(), 204);
    assert_eq!(Verdict::MithrilChainEmpty.as_u16(), 300);
    assert_eq!(Verdict::MithrilChainAvkBinding.as_u16(), 303);
    assert_eq!(Verdict::MithrilGenesisNotGenesis.as_u16(), 310);
    assert_eq!(Verdict::MithrilGenesisInvalidSignature.as_u16(), 313);
    assert_eq!(Verdict::MithrilStdNotStandard.as_u16(), 320);
    assert_eq!(Verdict::MithrilStdMalformedCertJson.as_u16(), 327);
    assert_eq!(Verdict::UtxoInclusionNotIncluded.as_u16(), 400);
    assert_eq!(Verdict::UtxoInclusionMalformedProof.as_u16(), 402);
    assert_eq!(Verdict::UtxoMalformedTx.as_u16(), 410);
    assert_eq!(Verdict::UtxoOutputIndexOutOfRange.as_u16(), 411);
}

#[test]
fn verdict_accept_predicate() {
    assert!(Verdict::Ok.is_accept());
    for v in Verdict::ALL {
        if v != Verdict::Ok {
            assert!(!v.is_accept(), "{v:?} is a journaled rejection, not accept");
        }
    }
}

#[test]
fn verdict_reachability_bands() {
    use ClaimType::*;
    // Ok is reachable everywhere.
    for t in [
        Checkpoint,
        CheckpointExtension,
        HeaderSegment,
        TxInclusion,
        UtxoRead,
    ] {
        assert!(Verdict::Ok.reachable_on(t));
    }
    // Header-leaf + praos-chain bands: 0x0003 only.
    for v in [
        Verdict::DecodeMalformedCbor,
        Verdict::VrfVerificationFailed,
        Verdict::ChainVrf,
    ] {
        assert!(v.reachable_on(HeaderSegment));
        assert!(!v.reachable_on(Checkpoint));
        assert!(!v.reachable_on(UtxoRead));
    }
    // Mithril-chain + standard bands: 0x0001 and 0x0002.
    for v in [
        Verdict::MithrilChainHash,
        Verdict::MithrilStdInvalidMultiSignature,
    ] {
        assert!(v.reachable_on(Checkpoint));
        assert!(v.reachable_on(CheckpointExtension));
        assert!(!v.reachable_on(HeaderSegment));
    }
    // Mithril-genesis band: 0x0001 only.
    assert!(Verdict::MithrilGenesisNotGenesis.reachable_on(Checkpoint));
    assert!(!Verdict::MithrilGenesisNotGenesis.reachable_on(CheckpointExtension));
    // Inclusion band: 0x0004 and 0x0005.
    assert!(Verdict::UtxoInclusionNotIncluded.reachable_on(TxInclusion));
    assert!(Verdict::UtxoInclusionNotIncluded.reachable_on(UtxoRead));
    assert!(!Verdict::UtxoInclusionNotIncluded.reachable_on(Checkpoint));
    // Utxo band: 0x0005 only.
    assert!(Verdict::UtxoOutputIndexOutOfRange.reachable_on(UtxoRead));
    assert!(!Verdict::UtxoOutputIndexOutOfRange.reachable_on(TxInclusion));
}

#[test]
fn anchor_mode_values() {
    assert_eq!(AnchorMode::External.as_u8(), 1);
    assert_eq!(AnchorMode::Composed.as_u8(), 2);
    assert_eq!(AnchorMode::from_u8(1), Ok(AnchorMode::External));
    assert_eq!(AnchorMode::from_u8(2), Ok(AnchorMode::Composed));
    assert_eq!(
        AnchorMode::from_u8(0),
        Err(DecodeError::UnknownAnchorMode(0))
    );
    assert_eq!(
        AnchorMode::from_u8(3),
        Err(DecodeError::UnknownAnchorMode(3))
    );
}

#[test]
fn datum_kind_values() {
    assert_eq!(DatumKind::None.as_u8(), 0);
    assert_eq!(DatumKind::Hash.as_u8(), 1);
    assert_eq!(DatumKind::Inline.as_u8(), 2);
    assert_eq!(DatumKind::from_u8(0), Ok(DatumKind::None));
    assert_eq!(DatumKind::from_u8(1), Ok(DatumKind::Hash));
    assert_eq!(DatumKind::from_u8(2), Ok(DatumKind::Inline));
    assert_eq!(DatumKind::from_u8(3), Err(DecodeError::UnknownDatumKind(3)));
}

#[test]
fn spend_status_band_is_uncoercible() {
    assert_eq!(SpendStatus::NotEstablished.as_u8(), 0);
    assert_eq!(
        SpendStatus::from_u8_utxo_read(0),
        Ok(SpendStatus::NotEstablished)
    );
    for raw in [1u8, 2, 3, 0xFF] {
        assert_eq!(
            SpendStatus::from_u8_utxo_read(raw),
            Err(DecodeError::IllegalSpendStatusOnUtxoRead(raw))
        );
    }
}

#[test]
fn header_const_block_matches_adr003_d2() {
    assert_eq!(HDR_OFF_VERSION, 0);
    assert_eq!(HDR_W_VERSION, 2);
    assert_eq!(HDR_OFF_CLAIM_TYPE, 2);
    assert_eq!(HDR_W_CLAIM_TYPE, 2);
    assert_eq!(HDR_OFF_NETWORK_ID, 4);
    assert_eq!(HDR_W_NETWORK_ID, 4);
    assert_eq!(HDR_OFF_GENESIS_VKEY, 8);
    assert_eq!(HDR_W_GENESIS_VKEY, 32);
    assert_eq!(HDR_OFF_VERDICT, 40);
    assert_eq!(HDR_W_VERDICT, 2);
    assert_eq!(HDR_OFF_REJECT_INDEX, 42);
    assert_eq!(HDR_W_REJECT_INDEX, 4);
    assert_eq!(HDR_LEN, 46);
    assert_eq!(BODY_OFF, 46);
}

#[test]
fn body_const_blocks_match_adr003_tables() {
    // CheckpointState group.
    assert_eq!(CS_OFF_ROOT_HASH, 0);
    assert_eq!(CS_OFF_TIP_HASH, 32);
    assert_eq!(CS_OFF_TIP_EPOCH, 64);
    assert_eq!(CS_OFF_CHAIN_LENGTH, 72);
    assert_eq!(CS_OFF_AVK_COMMITMENT, 76);
    assert_eq!(CS_OFF_NEXT_AVK_COMMIT, 108);
    assert_eq!(CS_OFF_STM_K, 140);
    assert_eq!(CS_OFF_STM_M, 148);
    assert_eq!(CS_OFF_STM_PHI_F_FIXED, 156);
    assert_eq!(CS_OFF_HAS_CERT_TXS, 160);
    assert_eq!(CS_OFF_CTX_MERKLE_ROOT, 161);
    assert_eq!(CS_OFF_CTX_EPOCH, 193);
    assert_eq!(CS_OFF_CTX_BLOCK_NUMBER, 201);
    assert_eq!(CS_LEN, 209);
    // Anchor group.
    assert_eq!(ANCHOR_OFF_MODE, 0);
    assert_eq!(ANCHOR_OFF_INNER_IMAGE_ID, 1);
    assert_eq!(ANCHOR_LEN, 33);
    // 0x0002 body.
    assert_eq!(EXT_OFF_ANCHOR, 0);
    assert_eq!(EXT_OFF_PREV_TIP_HASH, 33);
    assert_eq!(EXT_OFF_PREV_TIP_EPOCH, 65);
    assert_eq!(EXT_OFF_NEW_STATE, 73);
    // 0x0003 body.
    assert_eq!(HS_OFF_ETA0, 0);
    assert_eq!(HS_OFF_BLOCK_COUNT, 32);
    assert_eq!(HS_OFF_SEG_FIRST_HASH, 36);
    assert_eq!(HS_OFF_SEG_FIRST_NUMBER, 68);
    assert_eq!(HS_OFF_SEG_TIP_HASH, 76);
    assert_eq!(HS_OFF_SEG_TIP_NUMBER, 108);
    assert_eq!(HS_OFF_SEG_TIP_SLOT, 116);
    // 0x0004 body.
    assert_eq!(TX_OFF_ANCHOR, 0);
    assert_eq!(TX_OFF_ANCHOR_TIP_HASH, 33);
    assert_eq!(TX_OFF_CERTIFIED_ROOT, 65);
    assert_eq!(TX_OFF_TX_HASH, 97);
    assert_eq!(TX_OFF_CERTIFIED_EPOCH, 129);
    assert_eq!(TX_OFF_CERTIFIED_BLOCK_NUMBER, 137);
    // 0x0005 body.
    assert_eq!(UR_OFF_ANCHOR, 0);
    assert_eq!(UR_OFF_ANCHOR_TIP_HASH, 33);
    assert_eq!(UR_OFF_CERTIFIED_ROOT, 65);
    assert_eq!(UR_OFF_TX_ID, 97);
    assert_eq!(UR_OFF_OUT_INDEX, 129);
    assert_eq!(UR_OFF_LOVELACE, 131);
    assert_eq!(UR_OFF_ADDRESS_HASH, 139);
    assert_eq!(UR_OFF_ADDRESS_LEN, 171);
    assert_eq!(UR_OFF_DATUM_KIND, 173);
    assert_eq!(UR_OFF_DATUM_COMMITMENT, 174);
    assert_eq!(UR_OFF_SPEND_STATUS, 206);
    assert_eq!(UR_OFF_CERTIFIED_EPOCH, 207);
    assert_eq!(UR_OFF_CERTIFIED_AT_BLOCK, 215);
}
