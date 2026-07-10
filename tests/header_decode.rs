//! Slice 1 — decode real current-era (Praos) block headers, cross-checked
//! against pallas as an independent oracle, plus adversarial regression tests:
//! an untrusted byte provider must never coax a wrong *successful* decode.

use sextant::header::{DecodeError, HeaderView};

// Real mainnet blocks, ledger `[era, block]` CBOR (pallas golden vectors).
const CONWAY1: &str = include_str!("vectors/conway1.block"); // era 7
const BABBAGE1: &str = include_str!("vectors/babbage1.block"); // era 6

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

// ---- positive: correct decode, and parity with the pallas oracle ----------

#[test]
fn decodes_conway_header_fields() {
    let view = HeaderView::from_block_cbor(&unhex(CONWAY1)).expect("decode header");
    assert_eq!(view.block_number, 1_093_546);
    assert_eq!(view.slot, 22_075_282);
    assert_eq!(
        hex::encode(view.issuer_vkey),
        "e856c84a3d90c8526891bd58d957afadc522de37b14ae04c395db8a7a1b08c4a",
    );
}

#[test]
fn matches_pallas_on_the_same_bytes() {
    for vector in [CONWAY1, BABBAGE1] {
        let bytes = unhex(vector);
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
}

// ---- adversarial regressions (each closes a red-team finding) --------------

/// Finding 2: Byron / EBB / unknown eras must not take the Praos layout.
#[test]
fn rejects_non_praos_era() {
    // outer [era, _]; era read then rejected before the body is even parsed.
    assert_eq!(
        HeaderView::from_block_cbor(&unhex("820080")), // era 0 (EBB)
        Err(DecodeError::UnsupportedEra(0)),
    );
    assert_eq!(
        HeaderView::from_block_cbor(&unhex("820180")), // era 1 (Byron)
        Err(DecodeError::UnsupportedEra(1)),
    );
    assert_eq!(
        HeaderView::from_block_cbor(&unhex("820280")), // era 2 (Shelley, TPraos)
        Err(DecodeError::UnsupportedEra(2)),
    );
    assert_eq!(
        HeaderView::from_block_cbor(&unhex("820880")), // era 8 (future/unknown)
        Err(DecodeError::UnsupportedEra(8)),
    );
}

/// Finding 1: a header_body with the wrong element count must be rejected,
/// not reshaped into attacker-chosen fields.
#[test]
fn rejects_wrong_header_body_count() {
    // [7, [<5>, [<2>, <header_body claims 2 items>]]] -> expected 10.
    let reshaped = "8207858282";
    assert_eq!(
        HeaderView::from_block_cbor(&unhex(reshaped)),
        Err(DecodeError::MalformedCbor),
    );
}

/// Finding 1: indefinite-length arrays are never a valid fixed-shape header.
#[test]
fn rejects_indefinite_outer_array() {
    // 9f 07 ff  = indefinite array [7]
    assert_eq!(
        HeaderView::from_block_cbor(&unhex("9f07ff")),
        Err(DecodeError::MalformedCbor),
    );
}

/// Finding 3: prev_hash must be exactly 32 bytes (or genesis null); a shorter
/// string must not shift issuer_vkey to the wrong field.
#[test]
fn rejects_short_prev_hash() {
    // [7,[..[.., [bn=0, slot=0, prev_hash=4-byte-string, ...]]]]
    let short = "820785828a000044deadbeef";
    assert_eq!(
        HeaderView::from_block_cbor(&unhex(short)),
        Err(DecodeError::BadHashLen(4)),
    );
}

/// Finding 3/1: issuer_vkey must be exactly 32 bytes.
#[test]
fn rejects_bad_issuer_len() {
    // bn=0, slot=0, valid 32-byte prev_hash, then a 31-byte issuer (581f...).
    let mut body = String::from("820785828a0000"); // [7,[..[.., [0, 0, ...]]]]
    body.push_str("5820");
    body.push_str(&"00".repeat(32)); // prev_hash: 32 bytes
    body.push_str("581f");
    body.push_str(&"00".repeat(31)); // issuer_vkey: 31 bytes (one short)
    assert_eq!(
        HeaderView::from_block_cbor(&unhex(&body)),
        Err(DecodeError::BadHashLen(31)),
    );
}

/// Finding 4: trailing bytes after a valid block must be rejected.
#[test]
fn rejects_trailing_bytes() {
    let mut bytes = unhex(CONWAY1);
    bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        HeaderView::from_block_cbor(&bytes),
        Err(DecodeError::TrailingBytes),
    );
}

/// The era must be a canonical U8 token, matching pallas's `block_era` probe.
/// A u64-widened era on the real Conway block is Ok in a naive widening reader
/// but Err in pallas — reject it so the two stay byte-identical.
#[test]
fn rejects_non_canonical_era_encoding() {
    let full = unhex(CONWAY1); // full[0]=0x82 outer, full[1]=0x07 era, full[2..]=block
    let mut wedged = vec![0x82, 0x1b, 0, 0, 0, 0, 0, 0, 0, 0x07]; // era 7 as u64
    wedged.extend_from_slice(&full[2..]);

    assert_eq!(
        HeaderView::from_block_cbor(&wedged),
        Err(DecodeError::MalformedCbor),
    );
    // Parity with the oracle: pallas rejects the identical bytes too.
    assert!(pallas_traverse::MultiEraBlock::decode(&wedged).is_err());
}

/// Truncated input decodes to an error, never a partial success or panic.
#[test]
fn rejects_truncated_input() {
    let full = unhex(CONWAY1);
    for cut in [0usize, 1, 5, 10, 50, full.len() / 2, full.len() - 1] {
        assert!(
            HeaderView::from_block_cbor(&full[..cut]).is_err(),
            "truncation at {cut} must error",
        );
    }
}
