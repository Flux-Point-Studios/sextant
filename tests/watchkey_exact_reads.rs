//! Output addresses and body walks the transaction scan must read exactly: every Shelley
//! payment header, a break inside an indefinite array, an indefinite Byron attribute map,
//! and a map output or collateral return whose address yields no payment credential.

use sextant::watchkey::{Verdict, payment_credential, transaction_use};
use std::collections::BTreeSet;

const UNWATCHED: [u8; 28] = [0xee; 28];

fn input() -> Vec<u8> {
    [&[0x81, 0x82, 0x58, 0x20][..], &[0x88; 32], &[0x00]].concat()
}

/// `{0: [[88.., 0]], 1: [output], 2: 200000}` followed by `extra` key and value bytes,
/// in a map of `entries` entries.
fn body(output: &[u8], extra: &[u8], entries: u8) -> Vec<u8> {
    [
        &[0xa0 | entries, 0x00][..],
        &input(),
        &[0x01, 0x81],
        output,
        &[0x02, 0x1a, 0x00, 0x03, 0x0d, 0x40],
        extra,
    ]
    .concat()
}

fn legacy(address: &[u8]) -> Vec<u8> {
    [
        &[0x82, 0x58, address.len() as u8][..],
        address,
        &[0x1a, 0x00, 0x1e, 0x84, 0x80],
    ]
    .concat()
}

fn map_output(address: &[u8]) -> Vec<u8> {
    [
        &[0xa2, 0x00, 0x58, address.len() as u8][..],
        address,
        &[0x01, 0x1a, 0x00, 0x1e, 0x84, 0x80],
    ]
    .concat()
}

fn verdict(body: &[u8]) -> Verdict {
    let resolved = [&[0x61u8][..], &[0xd7; 28]].concat();
    transaction_use(body, &[0xa0], true, &BTreeSet::from([UNWATCHED]), |_| {
        Ok(Some(resolved.as_slice()))
    })
    .verdict()
}

fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &byte| {
        (0..8).fold(crc ^ u32::from(byte), |crc, _| {
            (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg())
        })
    })
}

fn byron(payload: &[u8], crc: u32) -> Vec<u8> {
    [
        &[0x82, 0xd8, 0x18, 0x58, payload.len() as u8][..],
        payload,
        &[0x1a],
        &crc.to_be_bytes(),
    ]
    .concat()
}

/// Every Shelley payment header, key or script, on either network, yields the payment
/// credential and reads complete.
#[test]
fn every_shelley_payment_header_reads_complete_when_unwatched() {
    for header in [
        0x00u8, 0x01, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x40, 0x41, 0x50, 0x51, 0x60, 0x61, 0x70,
        0x71,
    ] {
        let mut address = vec![header];
        address.extend_from_slice(&[0xa1; 28]);
        match header >> 4 {
            0..=3 => address.extend_from_slice(&[0xa2; 28]),
            4 | 5 => address.extend_from_slice(&[0x81, 0x00, 0x00, 0x00]),
            _ => {}
        }
        assert_eq!(
            payment_credential(&address),
            Some([0xa1; 28]),
            "{header:02x}"
        );
        assert_eq!(
            verdict(&body(&legacy(&address), &[], 3)),
            Verdict::NoUse,
            "{header:02x}"
        );
    }
}

/// Body key 8 as `[_ [1, break]]`: the break ends the inner definite array early.
#[test]
fn a_break_inside_an_indefinite_array_is_incomplete() {
    let output = legacy(&[&[0x61u8][..], &[0xd7; 28]].concat());
    assert_eq!(
        verdict(&body(&output, &[0x08, 0x9f, 0x82, 0x01, 0xff], 4)),
        Verdict::Incomplete
    );
    assert_eq!(
        verdict(&body(&output, &[0x08, 0x9f, 0x82, 0x01, 0x01, 0xff], 4)),
        Verdict::NoUse
    );
}

/// A Byron payload whose attribute map opens indefinite, and never closes, has no root.
#[test]
fn an_unterminated_indefinite_byron_attribute_map_yields_no_root() {
    let payload = [&[0x83, 0x58, 0x1c][..], &[0xa1; 28], &[0xbf, 0x00]].concat();
    let address = byron(&payload, crc32(&payload));
    assert_eq!(payment_credential(&address), None);
    assert_eq!(
        verdict(&body(&legacy(&address), &[], 3)),
        Verdict::Incomplete
    );
}

/// A map output or a collateral return whose address yields no payment credential, a
/// reward address or a Byron address with a wrong CRC, reads incomplete; with an
/// enterprise address, the same shapes read complete.
#[test]
fn a_map_output_or_collateral_return_without_a_credential_is_incomplete() {
    let reward = [&[0xe1u8][..], &[0xd7; 28]].concat();
    let payload = [&[0x83, 0x58, 0x1c][..], &[0xa1; 28], &[0xa0, 0x00]].concat();
    let broken_byron = byron(&payload, crc32(&payload) ^ 1);
    let enterprise = [&[0x61u8][..], &[0xd7; 28]].concat();
    for address in [&reward, &broken_byron] {
        assert_eq!(
            verdict(&body(&map_output(address), &[], 3)),
            Verdict::Incomplete
        );
        let collateral_return = [&[0x10][..], &map_output(address)].concat();
        assert_eq!(
            verdict(&body(&legacy(&enterprise), &collateral_return, 4)),
            Verdict::Incomplete
        );
    }
    assert_eq!(
        verdict(&body(&map_output(&enterprise), &[], 3)),
        Verdict::NoUse
    );
    let collateral_return = [&[0x10][..], &map_output(&enterprise)].concat();
    assert_eq!(
        verdict(&body(&legacy(&enterprise), &collateral_return, 4)),
        Verdict::NoUse
    );
}
