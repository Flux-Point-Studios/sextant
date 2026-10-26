use sextant::watchkey::{
    Scan, certificate_use, native_script_use, proposal_use, update_use, voting_use, withdrawal_use,
    witness_use,
};
use std::collections::BTreeSet;

const WATCHED: [u8; 28] = [0xa1; 28];

fn watched() -> BTreeSet<[u8; 28]> {
    BTreeSet::from([WATCHED])
}

fn truncated_after_hash(prefix: &[u8]) -> Vec<u8> {
    let mut encoded = prefix.to_vec();
    encoded.extend_from_slice(&WATCHED);
    encoded.push(0x18); // A uint header without its argument byte.
    encoded
}

#[test]
fn voter_without_credential_is_incomplete() {
    // {19: {[0]: {}}}
    assert_eq!(
        voting_use(&[0xa1, 0x13, 0xa1, 0x81, 0x00, 0xa0], &watched()),
        Scan {
            found: false,
            complete: false
        }
    );
}

#[test]
fn proposal_without_reward_account_is_incomplete() {
    // {20: [[1]]}
    assert_eq!(
        proposal_use(&[0xa1, 0x14, 0x81, 0x81, 0x01], &watched()),
        Scan {
            found: false,
            complete: false
        }
    );
}

#[test]
fn withdrawal_without_reward_account_is_incomplete() {
    // {5: {1: 0}}
    assert_eq!(
        withdrawal_use(&[0xa1, 0x05, 0xa1, 0x01, 0x00], &watched()),
        Scan {
            found: false,
            complete: false
        }
    );
}

#[test]
fn witness_without_verification_key_is_incomplete() {
    // {0: [[1]]}
    assert_eq!(
        witness_use(&[0xa1, 0x00, 0x81, 0x81, 0x01], &watched()),
        Scan {
            found: false,
            complete: false
        }
    );
}

#[test]
fn native_script_match_survives_a_later_malformed_child() {
    let encoded = truncated_after_hash(&[0xa1, 0x01, 0x81, 0x83, 0x00, 0x58, 0x1c]);
    assert_eq!(
        native_script_use(&encoded, &watched()),
        Scan {
            found: true,
            complete: false
        }
    );
}

#[test]
fn certificate_match_survives_a_later_malformed_child() {
    let encoded = truncated_after_hash(&[0xa1, 0x04, 0x81, 0x82, 0x00, 0x82, 0x58, 0x1c]);
    assert_eq!(
        certificate_use(&encoded, &watched()),
        Scan {
            found: true,
            complete: false
        }
    );
}

#[test]
fn update_match_survives_a_later_malformed_child() {
    let encoded = truncated_after_hash(&[0xa1, 0x06, 0x82, 0x58, 0x1c]);
    assert_eq!(
        update_use(&encoded, &watched()),
        Scan {
            found: true,
            complete: false
        }
    );
}
