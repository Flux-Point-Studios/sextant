//! The unbound-input zoo seed (T-A4-3 / T-A1-1): every byte of every golden
//! vector is load-bearing. Flip any single byte and the buffer must either
//! fail decode or decode to a different field somewhere — no silent
//! don't-care bytes, which is what makes one-encoding-per-value true.

use crate::common::{all_goldens, fingerprint, golden_bytes};
use hg_claims::decode_structural;

fn zoo(name: &str, golden: &[u8]) {
    let base =
        decode_structural(golden).unwrap_or_else(|e| panic!("golden {name} must decode: {e:?}"));
    let base_fp = fingerprint(&base);
    for (i, _) in golden.iter().enumerate() {
        // Two mutants per offset: low-bit and full-byte flips.
        for flip in [0x01u8, 0xFF] {
            let mut mutant = golden.to_vec();
            mutant[i] ^= flip;
            match decode_structural(&mutant) {
                Err(_) => {} // fail-closed: the flip hit a gate
                Ok(claim) => {
                    assert_ne!(
                        fingerprint(&claim),
                        base_fp,
                        "{name}: silent don't-care byte at offset {i} (flip {flip:#04x})"
                    );
                }
            }
        }
    }
}

#[test]
fn every_byte_earns_its_place_in_every_golden() {
    for (name, bytes) in all_goldens() {
        zoo(name, &bytes);
    }
}

#[test]
fn endianness_is_load_bearing() {
    // ADR-003 "endianness mutant": byte-swap a multi-byte field BE->LE in
    // place and the decoded value must differ (or decode must fail).
    use hg_claims::{Claim, consts};
    let golden = golden_bytes(crate::common::GOLDEN_CHECKPOINT_ACCEPT);
    let off = consts::BODY_OFF + consts::CS_OFF_TIP_EPOCH;
    let mut swapped = golden.clone();
    swapped[off..off + 8].reverse();
    let Ok(Claim::Checkpoint(orig)) = decode_structural(&golden) else {
        panic!("golden must decode");
    };
    let Ok(Claim::Checkpoint(m)) = decode_structural(&swapped) else {
        panic!("byte-swapped tip_epoch still passes structural gates");
    };
    // A BE field read from LE-ordered bytes is the byte-swapped value.
    assert_ne!(m.state().tip_epoch(), orig.state().tip_epoch());
    assert_eq!(m.state().tip_epoch(), 500u64.swap_bytes());
}
