use sextant::watchkey::{Scan, input_use};
use std::collections::BTreeSet;

const WATCHED: [u8; 28] = [0xa1; 28];
const OTHER: [u8; 28] = [0xa2; 28];

fn watched() -> BTreeSet<[u8; 28]> {
    BTreeSet::from([WATCHED])
}

fn address(payment: &[u8; 28]) -> Vec<u8> {
    let mut bytes = vec![0x60];
    bytes.extend_from_slice(payment);
    bytes
}

fn input_set(ids: &[u8]) -> Vec<u8> {
    assert!(ids.len() < 24);
    let mut bytes = vec![0x80 + ids.len() as u8];
    for id in ids {
        bytes.extend_from_slice(&[0x82, 0x58, 0x20]);
        bytes.extend_from_slice(&[*id; 32]);
        bytes.push(0);
    }
    bytes
}

fn body(key: u8, ids: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa1, key];
    bytes.extend_from_slice(&input_set(ids));
    bytes
}

fn all_input_fields() -> Vec<u8> {
    let mut bytes = vec![0xa3];
    for (key, id) in [(0, 1), (13, 2), (18, 3)] {
        bytes.push(key);
        bytes.extend_from_slice(&input_set(&[id]));
    }
    bytes
}

#[test]
fn watched_spent_payment_is_found() {
    let payment = address(&WATCHED);
    assert_eq!(
        input_use(&body(0, &[1]), true, &watched(), |_| Ok(Some(&payment))),
        Scan {
            found: true,
            complete: true
        }
    );
}

#[test]
fn unwatched_spent_payment_is_complete() {
    let payment = address(&OTHER);
    assert_eq!(
        input_use(&body(0, &[1]), true, &watched(), |_| Ok(Some(&payment))),
        Scan {
            found: false,
            complete: true
        }
    );
}

#[test]
fn spent_input_does_not_count_the_stake_credential() {
    let mut base_address = vec![0x00];
    base_address.extend_from_slice(&OTHER);
    base_address.extend_from_slice(&WATCHED);
    assert_eq!(
        input_use(&body(0, &[1]), true, &watched(), |_| Ok(Some(
            &base_address
        ))),
        Scan {
            found: false,
            complete: true
        }
    );
}

#[test]
fn valid_transaction_resolves_only_regular_inputs() {
    let payment = address(&WATCHED);
    let mut resolved = Vec::new();
    let scan = input_use(&all_input_fields(), true, &watched(), |input| {
        resolved.push(*input);
        Ok(Some(&payment))
    });
    assert_eq!(
        scan,
        Scan {
            found: true,
            complete: true
        }
    );
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].tx_id, [1; 32]);
    assert_eq!(resolved[0].index, 0);
}

#[test]
fn invalid_transaction_resolves_only_collateral_inputs() {
    let payment = address(&WATCHED);
    let mut resolved = Vec::new();
    let scan = input_use(&all_input_fields(), false, &watched(), |input| {
        resolved.push(*input);
        Ok(Some(&payment))
    });
    assert_eq!(
        scan,
        Scan {
            found: true,
            complete: true
        }
    );
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].tx_id, [2; 32]);
    assert_eq!(resolved[0].index, 0);
}

#[test]
fn unresolved_input_leaves_a_gap_beside_a_proven_match() {
    let payment = address(&WATCHED);
    for order in [[1, 2], [2, 1]] {
        let scan = input_use(&body(0, &order), true, &watched(), |input| {
            Ok((input.tx_id == [2; 32]).then_some(payment.as_slice()))
        });
        assert_eq!(
            scan,
            Scan {
                found: true,
                complete: false
            }
        );
    }
}

#[test]
fn resolver_error_leaves_a_gap_beside_a_proven_match() {
    let payment = address(&WATCHED);
    for order in [[1, 2], [2, 1]] {
        let scan = input_use(&body(0, &order), true, &watched(), |input| {
            if input.tx_id == [1; 32] {
                Err(())
            } else {
                Ok(Some(&payment))
            }
        });
        assert_eq!(
            scan,
            Scan {
                found: true,
                complete: false
            }
        );
    }
}

#[test]
fn proven_input_match_survives_a_later_malformed_input() {
    let payment = address(&WATCHED);
    let mut encoded = body(0, &[1]);
    encoded[2] = 0x82;
    encoded.push(0x01); // A uint where an input pair must appear.
    assert_eq!(
        input_use(&encoded, true, &watched(), |_| Ok(Some(&payment))),
        Scan {
            found: true,
            complete: false
        }
    );
}

#[test]
fn tagged_input_set_resolves_its_payment_credential() {
    let payment = address(&WATCHED);
    let mut encoded = body(0, &[1]);
    encoded.splice(2..2, [0xd9, 0x01, 0x02]);
    assert_eq!(
        input_use(&encoded, true, &watched(), |_| Ok(Some(&payment))),
        Scan {
            found: true,
            complete: true
        }
    );
}

#[test]
fn indefinite_input_set_resolves_its_payment_credential() {
    let payment = address(&WATCHED);
    let mut encoded = body(0, &[1]);
    encoded[2] = 0x9f;
    encoded.push(0xff);
    assert_eq!(
        input_use(&encoded, true, &watched(), |_| Ok(Some(&payment))),
        Scan {
            found: true,
            complete: true
        }
    );
}

#[test]
fn malformed_input_set_is_incomplete() {
    assert_eq!(
        input_use(&[0xa1, 0x00, 0x01], true, &watched(), |_| panic!(
            "malformed input was resolved"
        )),
        Scan {
            found: false,
            complete: false
        }
    );
}

#[test]
fn absent_input_set_is_complete_and_does_not_resolve() {
    assert_eq!(
        input_use(&[0xa0], true, &watched(), |_| panic!(
            "absent input was resolved"
        )),
        Scan {
            found: false,
            complete: true
        }
    );
}

#[test]
fn short_resolved_address_is_incomplete() {
    assert_eq!(
        input_use(&body(0, &[1]), true, &watched(), |_| Ok(Some(&[0x60]))),
        Scan {
            found: false,
            complete: false
        }
    );
}

#[test]
fn reward_address_cannot_prove_a_spent_payment_credential() {
    let mut reward = vec![0xe0];
    reward.extend_from_slice(&WATCHED);
    assert_eq!(
        input_use(&body(0, &[1]), true, &watched(), |_| Ok(Some(&reward))),
        Scan {
            found: false,
            complete: false
        }
    );
}
