//! Golden vectors (HANDOFF §7): byte-exact expected journals per claim type,
//! one accept-path and one rejection-path each, plus normative-offset spot
//! checks transcribed from ADR-003 D2 and the per-claim body tables.

use crate::common::*;
use hg_claims::consts::*;

#[test]
fn golden_checkpoint_accept_bytes() {
    assert_eq!(
        checkpoint_accept().encode(),
        golden_bytes(GOLDEN_CHECKPOINT_ACCEPT)
    );
}

#[test]
fn golden_checkpoint_reject_bytes() {
    assert_eq!(
        checkpoint_reject().encode(),
        golden_bytes(GOLDEN_CHECKPOINT_REJECT)
    );
}

#[test]
fn golden_checkpoint_extension_accept_bytes() {
    assert_eq!(
        checkpoint_extension_accept().encode(),
        golden_bytes(GOLDEN_CHECKPOINT_EXTENSION_ACCEPT)
    );
}

#[test]
fn golden_checkpoint_extension_reject_bytes() {
    assert_eq!(
        checkpoint_extension_reject().encode(),
        golden_bytes(GOLDEN_CHECKPOINT_EXTENSION_REJECT)
    );
}

#[test]
fn golden_header_segment_accept_bytes() {
    assert_eq!(
        header_segment_accept().encode(),
        golden_bytes(GOLDEN_HEADER_SEGMENT_ACCEPT)
    );
}

#[test]
fn golden_header_segment_reject_bytes() {
    assert_eq!(
        header_segment_reject().encode(),
        golden_bytes(GOLDEN_HEADER_SEGMENT_REJECT)
    );
}

#[test]
fn golden_tx_inclusion_accept_bytes() {
    assert_eq!(
        tx_inclusion_accept().encode(),
        golden_bytes(GOLDEN_TX_INCLUSION_ACCEPT)
    );
}

#[test]
fn golden_tx_inclusion_reject_bytes() {
    assert_eq!(
        tx_inclusion_reject().encode(),
        golden_bytes(GOLDEN_TX_INCLUSION_REJECT)
    );
}

#[test]
fn golden_utxo_read_accept_bytes() {
    assert_eq!(
        utxo_read_accept().encode(),
        golden_bytes(GOLDEN_UTXO_READ_ACCEPT)
    );
}

#[test]
fn golden_utxo_read_reject_bytes() {
    assert_eq!(
        utxo_read_reject().encode(),
        golden_bytes(GOLDEN_UTXO_READ_REJECT)
    );
}

#[test]
fn golden_lengths_match_the_frozen_len_table() {
    // ADR-003 per-claim LEN table, transcribed.
    assert_eq!(LEN_CHECKPOINT, 255);
    assert_eq!(LEN_CHECKPOINT_EXTENSION, 328);
    assert_eq!(LEN_HEADER_SEGMENT, 170);
    assert_eq!(LEN_TX_INCLUSION, 191);
    assert_eq!(LEN_UTXO_READ, 269);
    let expected = [
        LEN_CHECKPOINT,
        LEN_CHECKPOINT,
        LEN_CHECKPOINT_EXTENSION,
        LEN_CHECKPOINT_EXTENSION,
        LEN_HEADER_SEGMENT,
        LEN_HEADER_SEGMENT,
        LEN_TX_INCLUSION,
        LEN_TX_INCLUSION,
        LEN_UTXO_READ,
        LEN_UTXO_READ,
    ];
    for ((name, bytes), len) in all_goldens().iter().zip(expected) {
        assert_eq!(bytes.len(), len, "golden length for {name}");
    }
}

#[test]
fn golden_header_offsets_spot_check() {
    // ADR-003 D2: version @0, type @2, network @4, genesis @8, verdict @40,
    // reject_index @42 — checked at absolute offsets against raw bytes.
    let v = golden_bytes(GOLDEN_CHECKPOINT_REJECT);
    assert_eq!(
        v[HDR_OFF_VERSION..HDR_OFF_VERSION + HDR_W_VERSION],
        [0x00, 0x01]
    );
    assert_eq!(
        v[HDR_OFF_CLAIM_TYPE..HDR_OFF_CLAIM_TYPE + HDR_W_CLAIM_TYPE],
        [0x00, 0x01]
    );
    assert_eq!(
        v[HDR_OFF_NETWORK_ID..HDR_OFF_NETWORK_ID + HDR_W_NETWORK_ID],
        [0x2D, 0x96, 0x4A, 0x09]
    );
    assert_eq!(
        v[HDR_OFF_GENESIS_VKEY..HDR_OFF_GENESIS_VKEY + HDR_W_GENESIS_VKEY],
        [0x47; 32]
    );
    // MithrilChainHash = 301 = 0x012D
    assert_eq!(
        v[HDR_OFF_VERDICT..HDR_OFF_VERDICT + HDR_W_VERDICT],
        [0x01, 0x2D]
    );
    assert_eq!(
        v[HDR_OFF_REJECT_INDEX..HDR_OFF_REJECT_INDEX + HDR_W_REJECT_INDEX],
        [0x00, 0x00, 0x00, 0x03]
    );
}

#[test]
fn golden_body_offsets_spot_check() {
    // Checkpoint: S10 flag @ body+160, ctx root @ body+161 (ADR-003 §CheckpointState).
    let cp = golden_bytes(GOLDEN_CHECKPOINT_ACCEPT);
    assert_eq!(cp[BODY_OFF + CS_OFF_HAS_CERT_TXS], 0x01);
    assert_eq!(
        cp[BODY_OFF + CS_OFF_CTX_MERKLE_ROOT..BODY_OFF + CS_OFF_CTX_MERKLE_ROOT + 32],
        [0x55; 32]
    );

    // Extension: anchor mode @ body+0, prev_tip @ body+33, new state @ body+73.
    let ext = golden_bytes(GOLDEN_CHECKPOINT_EXTENSION_ACCEPT);
    assert_eq!(ext[BODY_OFF + EXT_OFF_ANCHOR + ANCHOR_OFF_MODE], 0x02);
    assert_eq!(
        ext[BODY_OFF + EXT_OFF_PREV_TIP_HASH..BODY_OFF + EXT_OFF_PREV_TIP_HASH + 32],
        [0x22; 32]
    );
    assert_eq!(
        ext[BODY_OFF + EXT_OFF_NEW_STATE..BODY_OFF + EXT_OFF_NEW_STATE + 32],
        [0x11; 32]
    );

    // Header-segment: eta0 @ body+0, tip slot @ body+116.
    let hs = golden_bytes(GOLDEN_HEADER_SEGMENT_ACCEPT);
    assert_eq!(
        hs[BODY_OFF + HS_OFF_ETA0..BODY_OFF + HS_OFF_ETA0 + 32],
        [0xE7; 32]
    );
    // 133_660_800 = 0x07F7_8080
    assert_eq!(
        hs[BODY_OFF + HS_OFF_SEG_TIP_SLOT..BODY_OFF + HS_OFF_SEG_TIP_SLOT + 8],
        [0x00, 0x00, 0x00, 0x00, 0x07, 0xF7, 0x80, 0x80]
    );

    // Tx-inclusion: tx_hash @ body+97.
    let tx = golden_bytes(GOLDEN_TX_INCLUSION_ACCEPT);
    assert_eq!(
        tx[BODY_OFF + TX_OFF_TX_HASH..BODY_OFF + TX_OFF_TX_HASH + 32],
        [0xAB; 32]
    );

    // Utxo-read: out_index @ body+129 (BE-u16, Sextant outpoint convention),
    // datum kind @ body+173, spend_status @ body+206 (MUST be 0).
    let ur = golden_bytes(GOLDEN_UTXO_READ_ACCEPT);
    assert_eq!(
        ur[BODY_OFF + UR_OFF_OUT_INDEX..BODY_OFF + UR_OFF_OUT_INDEX + 2],
        [0x00, 0x03]
    );
    assert_eq!(ur[BODY_OFF + UR_OFF_DATUM_KIND], 0x01);
    assert_eq!(ur[BODY_OFF + UR_OFF_SPEND_STATUS], 0x00);
}

#[test]
fn encode_is_deterministic() {
    // Canonicality witness (T-A4-3): the encoder is a pure function of the
    // typed fields — same value, same bytes, every time.
    assert_eq!(checkpoint_accept().encode(), checkpoint_accept().encode());
    assert_eq!(
        checkpoint_extension_accept().encode(),
        checkpoint_extension_accept().encode()
    );
    assert_eq!(
        header_segment_accept().encode(),
        header_segment_accept().encode()
    );
    assert_eq!(
        tx_inclusion_accept().encode(),
        tx_inclusion_accept().encode()
    );
    assert_eq!(utxo_read_accept().encode(), utxo_read_accept().encode());
}
