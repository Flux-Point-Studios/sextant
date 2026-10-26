//! CBOR edges the oracle fixtures cannot express: shapes a JSON-decoding reference
//! never sees (duplicate map keys, chunked byte strings, misplaced breaks,
//! indefinite-length arrays) and the guards that keep each of them from reading as
//! a clean NO_USE.

use sextant::watchkey::{
    Scan, native_script_use, output_use, proposal_use, transaction_use, update_use,
};
use std::collections::BTreeSet;

const WATCHED: [u8; 28] = [0xa1; 28];
const OTHER: [u8; 28] = [0xc9; 28];

const FOUND: Scan = Scan {
    found: true,
    complete: true,
};

fn watched() -> BTreeSet<[u8; 28]> {
    BTreeSet::from([WATCHED])
}

/// `h'60 ‖ credential'`, an enterprise address, as a CBOR byte string.
fn address(credential: &[u8; 28]) -> Vec<u8> {
    [vec![0x58, 0x1d, 0x60], credential.to_vec()].concat()
}

/// `h'e0 ‖ credential'`, a reward account, as a CBOR byte string.
fn reward_account(credential: &[u8; 28]) -> Vec<u8> {
    [vec![0x58, 0x1d, 0xe0], credential.to_vec()].concat()
}

/// `["a", h'00 x 32']`, an anchor.
fn anchor() -> Vec<u8> {
    [vec![0x82, 0x61, 0x61, 0x58, 0x20], vec![0; 32]].concat()
}

/// `{20: [[1000000, reward(other), action, anchor], ...]}`.
fn proposals(actions: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![0xa1, 0x14, 0x80 | actions.len() as u8];
    for action in actions {
        body.extend_from_slice(&[0x84, 0x1a, 0x00, 0x0f, 0x42, 0x40]);
        body.extend(reward_account(&OTHER));
        body.extend_from_slice(action);
        body.extend(anchor());
    }
    body
}

#[test]
fn an_indefinite_gov_action_is_read() {
    // [_ 2, {reward(watched): 1}, null]
    let action = [
        vec![0x9f, 0x02, 0xa1],
        reward_account(&WATCHED),
        vec![0x01, 0xf6, 0xff],
    ]
    .concat();
    assert_eq!(proposal_use(&proposals(&[action]), &watched()), FOUND);
}

#[test]
fn an_indefinite_constitution_is_read() {
    // [5, null, [_ anchor, h'watched']]
    let action = [
        vec![0x83, 0x05, 0xf6, 0x9f],
        anchor(),
        vec![0x58, 0x1c],
        WATCHED.to_vec(),
        vec![0xff],
    ]
    .concat();
    assert_eq!(proposal_use(&proposals(&[action]), &watched()), FOUND);
}

#[test]
fn an_indefinite_cold_credential_is_read() {
    // [4, null, [[_ 0, h'watched']], {}, 30([2, 3])]
    let action = [
        vec![0x85, 0x04, 0xf6, 0x81, 0x9f, 0x00, 0x58, 0x1c],
        WATCHED.to_vec(),
        vec![0xff, 0xa0, 0xd8, 0x1e, 0x82, 0x02, 0x03],
    ]
    .concat();
    assert_eq!(proposal_use(&proposals(&[action]), &watched()), FOUND);
}

#[test]
fn an_indefinite_constitution_does_not_hide_a_later_proposal() {
    let constitution = [
        vec![0x83, 0x05, 0xf6, 0x9f],
        anchor(),
        vec![0x58, 0x1c],
        OTHER.to_vec(),
        vec![0xff],
    ]
    .concat();
    let treasury = [
        vec![0x83, 0x02, 0xa1],
        reward_account(&WATCHED),
        vec![0x01, 0xf6],
    ]
    .concat();
    assert_eq!(
        proposal_use(&proposals(&[constitution, treasury]), &watched()),
        FOUND
    );
}

#[test]
fn bytes_after_the_body_map_leave_it_unproven() {
    let scan = transaction_use(&[0xa0, 0x00], &[0xa0], true, &watched(), |_| Ok(None));
    assert!(!scan.surfaces.complete);
}

#[test]
fn a_repeated_address_key_counts_every_address_and_is_incomplete() {
    // {1: [{0: watched, 0: other, 1: 1}]}: a last-wins decoder would read only `other`.
    for (first, second) in [(&WATCHED, &OTHER), (&OTHER, &WATCHED)] {
        let body = [
            vec![0xa1, 0x01, 0x81, 0xa3, 0x00],
            address(first),
            vec![0x00],
            address(second),
            vec![0x01, 0x01],
        ]
        .concat();
        assert_eq!(
            output_use(&body, &watched()),
            Scan {
                found: true,
                complete: false
            }
        );
    }
}

#[test]
fn chunked_bytes_under_tag_24_are_incomplete() {
    // A script_ref whose tag-24 payload is an indefinite byte string.
    let script = [vec![0x82, 0x00, 0x82, 0x00, 0x58, 0x1c], OTHER.to_vec()].concat();
    let (head, tail) = script.split_at(2);
    let output = [
        vec![0xa3, 0x00],
        address(&OTHER),
        vec![0x01, 0x01, 0x03, 0xd8, 0x18, 0x5f, 0x42],
        head.to_vec(),
        vec![0x58, tail.len() as u8],
        tail.to_vec(),
        vec![0xff],
    ]
    .concat();
    let body = [vec![0xa1, 0x01, 0x81], output].concat();
    assert_eq!(
        output_use(&body, &watched()),
        Scan {
            found: false,
            complete: false
        }
    );
}

#[test]
fn an_indefinite_script_ref_array_is_incomplete() {
    // tag24(bytes([_ 0, [0, other]])): the wrapper must be the definite pair.
    let inner = [
        vec![0x9f, 0x00, 0x82, 0x00, 0x58, 0x1c],
        OTHER.to_vec(),
        vec![0xff],
    ]
    .concat();
    let output = [
        vec![0xa3, 0x00],
        address(&OTHER),
        vec![0x01, 0x01, 0x03, 0xd8, 0x18, 0x58, inner.len() as u8],
        inner,
    ]
    .concat();
    let body = [vec![0xa1, 0x01, 0x81], output].concat();
    assert!(!output_use(&body, &watched()).complete);
}

#[test]
fn a_break_where_an_item_is_due_is_incomplete() {
    // {1: [[break]]}: a native script whose only element is a stray break.
    assert!(!native_script_use(&[0xa1, 0x01, 0x81, 0x81, 0xff], &watched()).complete);
}

#[test]
fn an_indefinite_map_cannot_break_between_a_key_and_its_value() {
    // {6: {_ 1: break}}
    assert!(!update_use(&[0xa1, 0x06, 0xbf, 0x01, 0xff], &watched()).complete);
}

#[test]
fn a_definite_map_value_is_walked() {
    // {6: {1: h'watched'}}: a walk counting pairs as single items would stop at the key.
    let body = [vec![0xa1, 0x06, 0xa1, 0x01, 0x58, 0x1c], WATCHED.to_vec()].concat();
    assert_eq!(
        update_use(&body, &watched()),
        Scan {
            found: true,
            complete: true
        }
    );
}
