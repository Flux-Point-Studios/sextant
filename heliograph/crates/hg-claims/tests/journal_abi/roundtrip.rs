//! Round-trip: encode -> decode_structural == identity on every field, for
//! every claim type, accept and rejection paths, and every gated-field shape.

use crate::common::*;
use hg_claims::{
    AnchorBinding, AnchorField, CheckpointExtensionFields, CheckpointFields, CheckpointState,
    CheckpointStateFields, Claim, ClaimType, ClaimVersion, DatumField, DatumKind,
    HeaderSegmentFields, JournalHeader, SpendStatus, TxInclusionFields, UtxoReadFields,
    decode_structural, decode_structural_draft,
};

fn assert_header_eq(h: &JournalHeader, f: &hg_claims::HeaderFields, claim_type: ClaimType) {
    assert_eq!(h.claim_version(), f.version);
    assert_eq!(h.claim_type(), claim_type);
    assert_eq!(h.network_id(), f.network_id);
    assert_eq!(h.genesis_vkey(), &f.genesis_vkey);
    assert_eq!(h.verdict(), f.verdict);
    assert_eq!(h.reject_index(), f.reject_index);
}

fn assert_state_eq(s: &CheckpointState, f: &CheckpointStateFields) {
    assert_eq!(s.root_hash(), &f.root_hash);
    assert_eq!(s.tip_hash(), &f.tip_hash);
    assert_eq!(s.tip_epoch(), f.tip_epoch);
    assert_eq!(s.chain_length(), f.chain_length);
    assert_eq!(s.avk_commitment(), &f.avk_commitment);
    assert_eq!(s.next_avk_commitment(), &f.next_avk_commitment);
    assert_eq!(s.stm_k(), f.stm_k);
    assert_eq!(s.stm_m(), f.stm_m);
    assert_eq!(s.stm_phi_f_fixed(), f.stm_phi_f_fixed);
    match &f.certified_transactions {
        None => {
            assert!(!s.has_certified_transactions());
            assert!(s.certified_transactions().is_none());
        }
        Some(ctx) => {
            assert!(s.has_certified_transactions());
            let a = s
                .certified_transactions()
                .expect("gated payload present when flag is 1");
            assert_eq!(a.ctx_merkle_root, &ctx.ctx_merkle_root);
            assert_eq!(a.ctx_epoch, ctx.ctx_epoch);
            assert_eq!(a.ctx_block_number, ctx.ctx_block_number);
        }
    }
}

fn assert_anchor_eq(a: &AnchorBinding, f: &AnchorField) {
    match f {
        AnchorField::External => {
            assert_eq!(a.mode().as_u8(), 1);
            // D3: the zeroed slot MUST NOT be consumable in External mode.
            assert!(a.inner_image_id().is_none());
        }
        AnchorField::Composed(id) => {
            assert_eq!(a.mode().as_u8(), 2);
            assert_eq!(a.inner_image_id(), Some(id));
        }
    }
}

fn roundtrip_checkpoint(f: &CheckpointFields) {
    let bytes = f.encode();
    let Ok(Claim::Checkpoint(v)) = decode_structural(&bytes) else {
        panic!("checkpoint journal must decode as Claim::Checkpoint");
    };
    assert_header_eq(v.header(), &f.header, ClaimType::Checkpoint);
    assert_state_eq(&v.state(), &f.state);
}

fn roundtrip_extension(f: &CheckpointExtensionFields) {
    let bytes = f.encode();
    let Ok(Claim::CheckpointExtension(v)) = decode_structural(&bytes) else {
        panic!("extension journal must decode as Claim::CheckpointExtension");
    };
    assert_header_eq(v.header(), &f.header, ClaimType::CheckpointExtension);
    assert_anchor_eq(&v.anchor(), &f.anchor);
    assert_eq!(v.prev_tip_hash(), &f.prev_tip_hash);
    assert_eq!(v.prev_tip_epoch(), f.prev_tip_epoch);
    assert_state_eq(&v.new_state(), &f.new_state);
}

fn roundtrip_segment(f: &HeaderSegmentFields) {
    let bytes = f.encode();
    let Ok(Claim::HeaderSegment(v)) = decode_structural(&bytes) else {
        panic!("header-segment journal must decode as Claim::HeaderSegment");
    };
    assert_header_eq(v.header(), &f.header, ClaimType::HeaderSegment);
    assert_eq!(v.eta0(), &f.eta0);
    assert_eq!(v.block_count(), f.block_count);
    assert_eq!(v.seg_first_hash(), &f.seg_first_hash);
    assert_eq!(v.seg_first_number(), f.seg_first_number);
    assert_eq!(v.seg_tip_hash(), &f.seg_tip_hash);
    assert_eq!(v.seg_tip_number(), f.seg_tip_number);
    assert_eq!(v.seg_tip_slot(), f.seg_tip_slot);
}

fn roundtrip_tx(f: &TxInclusionFields) {
    let bytes = f.encode();
    let Ok(Claim::TxInclusion(v)) = decode_structural(&bytes) else {
        panic!("tx-inclusion journal must decode as Claim::TxInclusion");
    };
    assert_header_eq(v.header(), &f.header, ClaimType::TxInclusion);
    assert_anchor_eq(&v.anchor(), &f.anchor);
    assert_eq!(v.anchor_tip_hash(), &f.anchor_tip_hash);
    assert_eq!(v.certified_root(), &f.certified_root);
    assert_eq!(v.tx_hash(), &f.tx_hash);
    assert_eq!(v.certified_epoch(), f.certified_epoch);
    assert_eq!(v.certified_block_number(), f.certified_block_number);
}

fn roundtrip_utxo(f: &UtxoReadFields) {
    let bytes = f.encode();
    let Ok(Claim::UtxoRead(v)) = decode_structural(&bytes) else {
        panic!("utxo-read journal must decode as Claim::UtxoRead");
    };
    assert_header_eq(v.header(), &f.header, ClaimType::UtxoRead);
    assert_anchor_eq(&v.anchor(), &f.anchor);
    assert_eq!(v.anchor_tip_hash(), &f.anchor_tip_hash);
    assert_eq!(v.certified_root(), &f.certified_root);
    assert_eq!(v.tx_id(), &f.tx_id);
    assert_eq!(v.out_index(), f.out_index);
    assert_eq!(v.lovelace(), f.lovelace);
    assert_eq!(v.address_hash(), &f.address_hash);
    assert_eq!(v.address_len(), f.address_len);
    match &f.datum {
        DatumField::None => {
            assert_eq!(v.datum_kind(), DatumKind::None);
            assert!(v.datum_commitment().is_none());
        }
        DatumField::Hash(c) => {
            assert_eq!(v.datum_kind(), DatumKind::Hash);
            assert_eq!(v.datum_commitment(), Some(c));
        }
        DatumField::Inline(c) => {
            assert_eq!(v.datum_kind(), DatumKind::Inline);
            assert_eq!(v.datum_commitment(), Some(c));
        }
    }
    assert_eq!(v.spend_status(), SpendStatus::NotEstablished);
    assert_eq!(v.certified_epoch(), f.certified_epoch);
    assert_eq!(v.certified_at_block(), f.certified_at_block);
}

#[test]
fn roundtrip_checkpoint_accept() {
    roundtrip_checkpoint(&checkpoint_accept());
}

#[test]
fn roundtrip_checkpoint_reject() {
    roundtrip_checkpoint(&checkpoint_reject());
}

#[test]
fn roundtrip_checkpoint_extension_accept() {
    roundtrip_extension(&checkpoint_extension_accept());
}

#[test]
fn roundtrip_checkpoint_extension_reject() {
    roundtrip_extension(&checkpoint_extension_reject());
}

#[test]
fn roundtrip_checkpoint_extension_external_mode() {
    let f = CheckpointExtensionFields {
        anchor: AnchorField::External,
        ..checkpoint_extension_accept()
    };
    roundtrip_extension(&f);
}

#[test]
fn roundtrip_header_segment_accept() {
    roundtrip_segment(&header_segment_accept());
}

#[test]
fn roundtrip_header_segment_reject() {
    roundtrip_segment(&header_segment_reject());
}

#[test]
fn roundtrip_tx_inclusion_accept() {
    roundtrip_tx(&tx_inclusion_accept());
}

#[test]
fn roundtrip_tx_inclusion_reject() {
    roundtrip_tx(&tx_inclusion_reject());
}

#[test]
fn roundtrip_utxo_read_accept() {
    roundtrip_utxo(&utxo_read_accept());
}

#[test]
fn roundtrip_utxo_read_reject() {
    roundtrip_utxo(&utxo_read_reject());
}

#[test]
fn roundtrip_utxo_read_datum_inline() {
    let f = UtxoReadFields {
        datum: DatumField::Inline(h32(0xD1)),
        ..utxo_read_accept()
    };
    roundtrip_utxo(&f);
}

#[test]
fn roundtrip_utxo_read_datum_none() {
    let f = UtxoReadFields {
        datum: DatumField::None,
        ..utxo_read_accept()
    };
    roundtrip_utxo(&f);
}

#[test]
fn roundtrip_draft_version_through_draft_constructor() {
    // Pre-freeze hg-guest emits Draft 0 (CLAIMS §1.3); only the explicit
    // draft-mode entry point decodes it.
    let mut f = checkpoint_accept();
    f.header.version = ClaimVersion::Draft;
    let bytes = f.encode();
    let Ok(Claim::Checkpoint(v)) = decode_structural_draft(&bytes) else {
        panic!("draft journal must decode through the draft-mode constructor");
    };
    assert_eq!(v.header().claim_version(), ClaimVersion::Draft);
    assert_state_eq(&v.state(), &f.state);
}
