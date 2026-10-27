//! Fail-closed decode (ADR-003 D7 R1/R2/R3/R7): every rejection reason is a
//! distinct error, asserted exactly — unknown version, draft gate, unknown
//! claim type (incl. deferred + bench bands), wrong length, unknown verdict,
//! bad presence flag, bad discriminants, gated-payload and band violations.

use crate::common::*;
use hg_claims::consts::*;
use hg_claims::{ClaimVersion, DecodeError, decode_structural_draft};

fn with_u16_at(bytes: &[u8], off: usize, v: u16) -> Vec<u8> {
    let mut m = bytes.to_vec();
    m[off..off + 2].copy_from_slice(&v.to_be_bytes());
    m
}

#[test]
fn unknown_version_rejected() {
    let golden = golden_bytes(GOLDEN_CHECKPOINT_ACCEPT);
    for raw in [2u16, 3, 0x00FF, 0xFFFF] {
        let m = with_u16_at(&golden, HDR_OFF_VERSION, raw);
        assert_eq!(decode_err(&m), DecodeError::UnknownVersion(raw));
        // Unknown even in draft mode — the draft gate widens the accepted
        // set to {0, 1}, never beyond it.
        assert_eq!(decode_draft_err(&m), DecodeError::UnknownVersion(raw));
    }
}

#[test]
fn draft_version_rejected_in_production_mode() {
    let mut f = checkpoint_accept();
    f.header.version = ClaimVersion::Draft;
    let bytes = f.encode();
    assert_eq!(
        decode_err(&bytes),
        DecodeError::VersionNotAccepted(ClaimVersion::Draft)
    );
}

#[test]
fn v1_accepted_in_draft_mode_too() {
    // Draft mode is a superset {Draft, V1}, so golden V1 vectors decode there.
    let golden = golden_bytes(GOLDEN_CHECKPOINT_ACCEPT);
    assert!(decode_structural_draft(&golden).is_ok());
}

#[test]
fn unknown_claim_type_rejected() {
    let golden = golden_bytes(GOLDEN_CHECKPOINT_ACCEPT);
    // 0x0000 invalid; 0x0006-0x0008 deferred (reserved, NOT decodable);
    // 0x0F00-0x0FFF bench band (never production); plus arbitrary unknowns.
    for raw in [
        0x0000u16, 0x0006, 0x0007, 0x0008, 0x0009, 0x0F00, 0x0F01, 0x0FFF, 0xFFFF,
    ] {
        let m = with_u16_at(&golden, HDR_OFF_CLAIM_TYPE, raw);
        assert_eq!(decode_err(&m), DecodeError::UnknownClaimType(raw));
    }
}

#[test]
fn known_type_with_wrong_length_rejected() {
    // A checkpoint-sized buffer relabeled as header-segment must fail R1
    // before any field is trusted.
    let golden = golden_bytes(GOLDEN_CHECKPOINT_ACCEPT);
    let m = with_u16_at(&golden, HDR_OFF_CLAIM_TYPE, 0x0003);
    assert_eq!(
        decode_err(&m),
        DecodeError::LengthMismatch {
            expected: LEN_HEADER_SEGMENT,
            actual: LEN_CHECKPOINT
        }
    );
}

#[test]
fn unknown_verdict_rejected() {
    let golden = golden_bytes(GOLDEN_CHECKPOINT_ACCEPT);
    // Holes in and around every D6 band, plus the max.
    for raw in [
        1u16, 99, 104, 109, 114, 119, 123, 205, 299, 304, 309, 314, 328, 403, 409, 412, 0xFFFF,
    ] {
        let m = with_u16_at(&golden, HDR_OFF_VERDICT, raw);
        assert_eq!(decode_err(&m), DecodeError::UnknownVerdict(raw));
    }
}

#[test]
fn bad_presence_flag_rejected() {
    let golden = golden_bytes(GOLDEN_CHECKPOINT_ACCEPT);
    for value in [2u8, 3, 0xFF] {
        let mut m = golden.clone();
        m[BODY_OFF + CS_OFF_HAS_CERT_TXS] = value;
        assert_eq!(
            decode_err(&m),
            DecodeError::IllegalPresenceFlag {
                field: "has_certified_transactions",
                value
            }
        );
    }
}

#[test]
fn gated_ctx_payload_nonzero_while_flag_zero_rejected() {
    // D3: S11-S13 present-but-zeroed when S10 == 0; presenting them nonzero
    // with the flag down is a rejection (CLAIMS §4.6).
    let mut m = golden_bytes(GOLDEN_CHECKPOINT_ACCEPT);
    m[BODY_OFF + CS_OFF_HAS_CERT_TXS] = 0;
    assert_eq!(
        decode_err(&m),
        DecodeError::NonzeroGatedPayload {
            field: "certified_transactions"
        }
    );
}

#[test]
fn bad_anchor_mode_rejected() {
    for (golden, anchor_off) in [
        (
            golden_bytes(GOLDEN_CHECKPOINT_EXTENSION_ACCEPT),
            BODY_OFF + EXT_OFF_ANCHOR,
        ),
        (
            golden_bytes(GOLDEN_TX_INCLUSION_ACCEPT),
            BODY_OFF + TX_OFF_ANCHOR,
        ),
        (
            golden_bytes(GOLDEN_UTXO_READ_ACCEPT),
            BODY_OFF + UR_OFF_ANCHOR,
        ),
    ] {
        for raw in [0u8, 3, 0xFF] {
            let mut m = golden.clone();
            m[anchor_off + ANCHOR_OFF_MODE] = raw;
            assert_eq!(decode_err(&m), DecodeError::UnknownAnchorMode(raw));
        }
    }
}

#[test]
fn gated_inner_image_id_nonzero_in_external_mode_rejected() {
    // The extension golden is Composed with a nonzero inner image id; forcing
    // External mode over it presents a nonzero gated slot (D3 / A3).
    let mut m = golden_bytes(GOLDEN_CHECKPOINT_EXTENSION_ACCEPT);
    m[BODY_OFF + EXT_OFF_ANCHOR + ANCHOR_OFF_MODE] = 1;
    assert_eq!(
        decode_err(&m),
        DecodeError::NonzeroGatedPayload {
            field: "inner_image_id"
        }
    );
}

#[test]
fn bad_datum_kind_rejected() {
    let golden = golden_bytes(GOLDEN_UTXO_READ_ACCEPT);
    for raw in [3u8, 4, 0xFF] {
        let mut m = golden.clone();
        m[BODY_OFF + UR_OFF_DATUM_KIND] = raw;
        assert_eq!(decode_err(&m), DecodeError::UnknownDatumKind(raw));
    }
}

#[test]
fn gated_datum_commitment_nonzero_while_kind_none_rejected() {
    let mut m = golden_bytes(GOLDEN_UTXO_READ_ACCEPT);
    m[BODY_OFF + UR_OFF_DATUM_KIND] = 0;
    assert_eq!(
        decode_err(&m),
        DecodeError::NonzeroGatedPayload {
            field: "datum_commitment"
        }
    );
}

#[test]
fn spend_status_band_violation_rejected() {
    // CLAIMS U12: any nonzero spend_status on 0x0005 rejects — the tier band
    // is machine-checkable; a proof does not upgrade Tier 0.
    let golden = golden_bytes(GOLDEN_UTXO_READ_ACCEPT);
    for raw in [1u8, 2, 3, 0xFF] {
        let mut m = golden.clone();
        m[BODY_OFF + UR_OFF_SPEND_STATUS] = raw;
        assert_eq!(
            decode_err(&m),
            DecodeError::IllegalSpendStatusOnUtxoRead(raw)
        );
    }
}

#[test]
fn every_error_variant_is_distinct() {
    let errors = [
        DecodeError::TruncatedHeader { actual: 3 },
        DecodeError::LengthMismatch {
            expected: 255,
            actual: 254,
        },
        DecodeError::UnknownVersion(2),
        DecodeError::VersionNotAccepted(ClaimVersion::Draft),
        DecodeError::UnknownClaimType(0x0F01),
        DecodeError::UnknownVerdict(1),
        DecodeError::UnknownAnchorMode(0),
        DecodeError::UnknownDatumKind(3),
        DecodeError::IllegalSpendStatusOnUtxoRead(2),
        DecodeError::IllegalPresenceFlag {
            field: "has_certified_transactions",
            value: 2,
        },
        DecodeError::NonzeroGatedPayload {
            field: "inner_image_id",
        },
    ];
    for (i, a) in errors.iter().enumerate() {
        for (j, b) in errors.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert_ne!(
                    a.to_string(),
                    b.to_string(),
                    "Display must attribute the rejection"
                );
            }
        }
    }
}

#[test]
fn decode_error_implements_core_error() {
    let e: &dyn core::error::Error = &DecodeError::UnknownVersion(9);
    assert!(!e.to_string().is_empty());
}
