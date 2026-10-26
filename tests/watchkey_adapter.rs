//! The content-bound selector: a spent output's address read from the body of the
//! transaction that created it, bound to the outpoint by that body's BLAKE2b-256. It
//! names a candidate only. Whether the output existed is the canonical membership's to
//! say, and anything the body cannot bind to one address leaves the input unresolved,
//! which the scan reads as INCOMPLETE.

use std::collections::{BTreeMap, BTreeSet};

use pallas_crypto::hash::Hasher;
use sextant::utxo::OutPoint;
use sextant::watchkey::{Scan, bound_output_address, transaction_use};

const A: [u8; 28] = [0xa1; 28];
const B: [u8; 28] = [0xb2; 28];
const C: [u8; 28] = [0xc3; 28];

/// A mainnet Icarus-style Byron address (tests/vectors/mainnet-192261788.block).
const BYRON: &str =
    "82d818582183581cf195a03699f48d9660d7159f66bf0b0c3eda9e454e526242dfc8ced4a0001a1648e9b2";

/// `h'60 ‖ credential'`, an enterprise address.
fn address(credential: &[u8; 28]) -> Vec<u8> {
    [vec![0x60], credential.to_vec()].concat()
}

fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
    let head = match u8::try_from(bytes.len()).expect("short") {
        len @ 0..=23 => vec![0x40 | len],
        len => vec![0x58, len],
    };
    [head, bytes.to_vec()].concat()
}

/// `{0: address, 1: 1}`
fn output_to(address: &[u8]) -> Vec<u8> {
    [vec![0xa2, 0x00], cbor_bytes(address), vec![0x01, 0x01]].concat()
}

/// `[address, 2]`
fn legacy_output_to(address: &[u8]) -> Vec<u8> {
    [vec![0x82], cbor_bytes(address), vec![0x02]].concat()
}

/// `{1: [{0: a, 1: 1}, [b, 2]]}`
fn body_plain() -> Vec<u8> {
    [
        vec![0xa1, 0x01, 0x82],
        output_to(&address(&A)),
        legacy_output_to(&address(&B)),
    ]
    .concat()
}

/// `{1: [{0: a, 1: 1}, [b, 2]], 16: {0: c, 1: 1}}`: two outputs and a collateral return.
fn body_with_return() -> Vec<u8> {
    [
        vec![0xa2, 0x01, 0x82],
        output_to(&address(&A)),
        legacy_output_to(&address(&B)),
        vec![0x10],
        output_to(&address(&C)),
    ]
    .concat()
}

fn tx_id(body: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(Hasher::<256>::hash(body).as_ref()).expect("32-byte hash")
}

fn outpoint(body: &[u8], index: u16) -> OutPoint {
    OutPoint {
        tx_id: tx_id(body),
        index,
    }
}

fn bound(body: &[u8], index: u16) -> Option<Vec<u8>> {
    bound_output_address(&outpoint(body, index), body)
}

#[test]
fn an_index_below_the_output_count_names_that_output() {
    let body = body_plain();
    assert_eq!(bound(&body, 0), Some(address(&A)));
    assert_eq!(bound(&body, 1), Some(address(&B)));
}

#[test]
fn the_index_after_the_outputs_names_the_collateral_return() {
    let body = body_with_return();
    assert_eq!(bound(&body, 2), Some(address(&C)));
    assert_eq!(bound(&body, 3), None);
    // {1: [], 16: {0: c, 1: 1}}: with no outputs the collateral return is index 0.
    let only_return = [vec![0xa2, 0x01, 0x80, 0x10], output_to(&address(&C))].concat();
    assert_eq!(bound(&only_return, 0), Some(address(&C)));
    assert_eq!(bound(&only_return, 1), None);
}

#[test]
fn the_selector_names_candidates_not_creations() {
    // A body names its outputs and its collateral return whatever its phase-2 outcome:
    // a valid transaction made only the first, an invalid one only the second, and the
    // canonical UTxO membership, outside this selector, says which one existed.
    let body = body_with_return();
    assert_eq!(bound(&body, 0), Some(address(&A)));
    assert_eq!(bound(&body, 2), Some(address(&C)));
}

#[test]
fn an_index_with_no_output_binds_nothing() {
    let body = body_plain();
    assert_eq!(bound(&body, 2), None);
    assert_eq!(bound(&body, u16::MAX), None);
}

#[test]
fn the_body_must_hash_to_the_outpoints_tx_id() {
    let body = body_plain();
    let mut mutated = body.clone();
    *mutated.last_mut().expect("non-empty") = 0x03;
    assert_eq!(bound_output_address(&outpoint(&body, 0), &mutated), None);
    let elsewhere = OutPoint {
        tx_id: [0x77; 32],
        index: 0,
    };
    assert_eq!(bound_output_address(&elsewhere, &body), None);
}

#[test]
fn a_repeated_body_or_output_field_binds_nothing() {
    for (body, index) in [
        // {1: [a], 1: [b]}: the outputs repeated.
        (
            [
                vec![0xa2, 0x01, 0x81],
                output_to(&address(&A)),
                vec![0x01, 0x81],
                output_to(&address(&B)),
            ]
            .concat(),
            0,
        ),
        // {1: [a], 16: c, 16: c}: the collateral return repeated.
        (
            [
                vec![0xa3, 0x01, 0x81],
                output_to(&address(&A)),
                vec![0x10],
                output_to(&address(&C)),
                vec![0x10],
                output_to(&address(&C)),
            ]
            .concat(),
            1,
        ),
        // {1: [{0: a, 0: b, 1: 1}]}: the target output's address repeated.
        (
            [
                vec![0xa1, 0x01, 0x81, 0xa3, 0x00],
                cbor_bytes(&address(&A)),
                vec![0x00],
                cbor_bytes(&address(&B)),
                vec![0x01, 0x01],
            ]
            .concat(),
            0,
        ),
        // {1: [{0: a, 1: 1, 1: 2}]}: the target output's coin repeated.
        (
            [
                vec![0xa1, 0x01, 0x81, 0xa3, 0x00],
                cbor_bytes(&address(&A)),
                vec![0x01, 0x01, 0x01, 0x02],
            ]
            .concat(),
            0,
        ),
    ] {
        assert_eq!(bound(&body, index), None, "{body:02x?}");
    }
}

#[test]
fn a_repeat_in_another_output_does_not_unbind_the_target() {
    // {1: [{0: a, 0: b, 1: 1}, [b, 2]]}
    let body = [
        vec![0xa1, 0x01, 0x82, 0xa3, 0x00],
        cbor_bytes(&address(&A)),
        vec![0x00],
        cbor_bytes(&address(&B)),
        vec![0x01, 0x01],
        legacy_output_to(&address(&B)),
    ]
    .concat();
    assert_eq!(bound(&body, 1), Some(address(&B)));
}

#[test]
fn an_address_that_names_no_spending_key_binds_nothing() {
    let byron = hex::decode(BYRON).expect("hex");
    let mut bad_crc = byron.clone();
    *bad_crc.last_mut().expect("non-empty") ^= 1;
    for (address, expected) in [
        (byron.clone(), Some(byron)),
        (bad_crc, None),
        ([vec![0xe0], A.to_vec()].concat(), None),
        (Vec::new(), None),
        (address(&A)[..28].to_vec(), None),
    ] {
        let body = [vec![0xa1, 0x01, 0x81], output_to(&address)].concat();
        assert_eq!(bound(&body, 0), expected, "{address:02x?}");
    }
}

#[test]
fn a_body_that_does_not_decode_binds_nothing() {
    for body in [
        // {1: [a]} and one more byte.
        [vec![0xa1, 0x01, 0x81], output_to(&address(&A)), vec![0x00]].concat(),
        // {1: [{1: 1}]}: an output with no address.
        vec![0xa1, 0x01, 0x81, 0xa1, 0x01, 0x01],
    ] {
        assert_eq!(bound(&body, 0), None, "{body:02x?}");
    }
}

#[test]
fn transaction_use_resolves_a_spend_through_its_creating_body() {
    let creating = body_plain();
    let resolved: BTreeMap<OutPoint, Vec<u8>> = [0, 1]
        .into_iter()
        .filter_map(|index| {
            let spent = outpoint(&creating, index);
            bound_output_address(&spent, &creating).map(|address| (spent, address))
        })
        .collect();
    let watched = BTreeSet::from([B]);
    let spend = |tx_id: &[u8], index: u8| {
        [
            vec![0xa1, 0x00, 0x81, 0x82, 0x58, 0x20],
            tx_id.to_vec(),
            vec![index],
        ]
        .concat()
    };
    // {0: [[tx_id, 1]]}: output 1 pays B.
    let scan = transaction_use(
        &spend(&tx_id(&creating), 1),
        &[0xa0],
        true,
        &watched,
        |spent| Ok(resolved.get(spent).map(Vec::as_slice)),
    );
    assert_eq!(
        scan.inputs,
        Scan {
            found: true,
            complete: true
        }
    );
    // An outpoint whose creating body is unavailable stays unresolved.
    let scan = transaction_use(&spend(&[0x77; 32], 0), &[0xa0], true, &watched, |spent| {
        Ok(resolved.get(spent).map(Vec::as_slice))
    });
    assert_eq!(
        scan.inputs,
        Scan {
            found: false,
            complete: false
        }
    );
}
