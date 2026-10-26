use sextant::watchkey::{Scan, native_script_use, output_use};
use std::collections::BTreeSet;

const WATCHED: [u8; 28] = [0xa1; 28];
const OTHER: [u8; 28] = [0xc9; 28];

const FOUND: Scan = Scan {
    found: true,
    complete: true,
};
const CLEAN: Scan = Scan {
    found: false,
    complete: true,
};
const GAP: Scan = Scan {
    found: false,
    complete: false,
};

fn watched() -> BTreeSet<[u8; 28]> {
    BTreeSet::from([WATCHED])
}

/// The CBOR head of a `major` type carrying argument `n`.
fn head(major: u8, n: usize) -> Vec<u8> {
    let major = major << 5;
    match n {
        0..=23 => vec![major | n as u8],
        24..=0xff => vec![major | 24, n as u8],
        _ => [
            vec![major | 25],
            u16::try_from(n)
                .expect("test sizes fit u16")
                .to_be_bytes()
                .to_vec(),
        ]
        .concat(),
    }
}

fn bytes(data: &[u8]) -> Vec<u8> {
    [head(2, data.len()), data.to_vec()].concat()
}

/// A native `sig` clause, `[0, key_hash]`.
fn sig(key: &[u8; 28]) -> Vec<u8> {
    [vec![0x82, 0x00], bytes(key)].concat()
}

/// The tag-24 reference script `[script_type, script]`.
fn script_ref(script_type: u8, script: &[u8]) -> Vec<u8> {
    [
        vec![0xd8, 0x18],
        bytes(&[vec![0x82, script_type], script.to_vec()].concat()),
    ]
    .concat()
}

/// A map-form output to an unwatched address whose key 3 holds `script_ref`.
fn output_with(script_ref: &[u8]) -> Vec<u8> {
    let mut address = vec![0x60];
    address.extend_from_slice(&OTHER);
    [
        vec![0xa3, 0x00],
        bytes(&address),
        vec![0x01, 0x01, 0x03],
        script_ref.to_vec(),
    ]
    .concat()
}

/// `{1: outputs}`.
fn body_with_outputs(outputs: &[Vec<u8>]) -> Vec<u8> {
    [vec![0xa1, 0x01], head(4, outputs.len()), outputs.concat()].concat()
}

/// `{1: [script]}`: a witness set carrying one native script.
fn witnesses_with(script: &[u8]) -> Vec<u8> {
    [vec![0xa1, 0x01, 0x81], script.to_vec()].concat()
}

#[test]
fn plutus_reference_script_bytes_are_not_credentials() {
    // Bytecode that is exactly the watched hash still names no credential.
    let output = output_with(&script_ref(2, &bytes(&WATCHED)));
    assert_eq!(output_use(&body_with_outputs(&[output]), &watched()), CLEAN);
}

#[test]
fn unknown_reference_script_type_is_incomplete() {
    let output = output_with(&script_ref(9, &sig(&OTHER)));
    assert_eq!(output_use(&body_with_outputs(&[output]), &watched()), GAP);
}

#[test]
fn reference_script_without_its_tag_24_wrapper_is_incomplete() {
    let bare = bytes(&[vec![0x82, 0x00], sig(&WATCHED)].concat());
    let output = output_with(&bare);
    assert_eq!(output_use(&body_with_outputs(&[output]), &watched()), GAP);
}

#[test]
fn reference_scripts_share_one_walk_budget() {
    // Each script alone fits the 100,000-node budget; together they exhaust it.
    let wide = [vec![0x82, 0x01], head(4, 60_000), vec![0x00; 60_000]].concat();
    let one = body_with_outputs(&[output_with(&script_ref(0, &wide))]);
    let two = body_with_outputs(&[
        output_with(&script_ref(0, &wide)),
        output_with(&script_ref(0, &wide)),
    ]);
    assert_eq!(output_use(&one, &watched()), CLEAN);
    assert_eq!(output_use(&two, &watched()), GAP);
}

#[test]
fn deep_native_script_is_walked_without_a_depth_cap() {
    // 10,000 nested `all` clauses around one sig: far past any recursion cap,
    // well inside the node budget.
    let script = [[0x82, 0x01, 0x81].repeat(10_000), sig(&WATCHED)].concat();
    assert_eq!(
        native_script_use(&witnesses_with(&script), &watched()),
        FOUND
    );
}

#[test]
fn chunked_key_hash_counts_as_its_joined_bytes() {
    // `[0, (_ h'a1 x 14', h'a1 x 14')]`: the sig hash as an indefinite byte string.
    let chunked = [
        vec![0x82, 0x00, 0x5f],
        bytes(&WATCHED[..14]),
        bytes(&WATCHED[14..]),
        vec![0xff],
    ]
    .concat();
    assert_eq!(
        native_script_use(&witnesses_with(&chunked), &watched()),
        FOUND
    );
}
