//! Slice 1 — decode a real current-era (Conway) block header and assert the
//! read-path fields, cross-checked against pallas as an independent oracle.
//!
//! The vector is a byte input a provider supplies; Sextant recomputes every
//! field on its own code path and never trusts the provider for a verdict.

use sextant::header::HeaderView;

// Real mainnet Conway block, ledger `[era, block]` CBOR
// (pallas golden vector test_data/conway1.block).
const CONWAY1: &str = include_str!("vectors/conway1.block");

fn vector() -> Vec<u8> {
    hex::decode(CONWAY1.trim()).expect("vector is valid hex")
}

#[test]
fn decodes_conway_header_fields() {
    let view = HeaderView::from_block_cbor(&vector()).expect("decode header");
    assert_eq!(view.block_number, 1_093_546);
    assert_eq!(view.slot, 22_075_282);
    assert_eq!(
        hex::encode(view.issuer_vkey),
        "e856c84a3d90c8526891bd58d957afadc522de37b14ae04c395db8a7a1b08c4a",
    );
}

#[test]
fn matches_pallas_on_the_same_bytes() {
    let bytes = vector();
    let mine = HeaderView::from_block_cbor(&bytes).expect("sextant decode");
    let block = pallas_traverse::MultiEraBlock::decode(&bytes).expect("pallas decode");
    let theirs = block.header();
    assert_eq!(mine.block_number, theirs.number(), "block_number parity");
    assert_eq!(mine.slot, theirs.slot(), "slot parity");
    assert_eq!(
        Some(mine.issuer_vkey.as_slice()),
        theirs.issuer_vkey(),
        "issuer_vkey parity",
    );
}
