//! Length-gate mutants (ADR-003 R1): every strict prefix and every extended
//! buffer of every golden vector rejects before any field is trusted. There
//! is no length-padded alternate encoding (T-A4-5).

use crate::common::{all_goldens, decode_err};
use hg_claims::{DecodeError, decode_structural};

// The (version, claim_type) prelude R1 keys on.
const PRELUDE: usize = 4;

#[test]
fn every_prefix_fails() {
    for (name, golden) in all_goldens() {
        for len in 0..golden.len() {
            let err = decode_structural(&golden[..len])
                .expect_err(&format!("{name}: prefix of length {len} must reject"));
            if len < PRELUDE {
                assert_eq!(
                    err,
                    DecodeError::TruncatedHeader { actual: len },
                    "{name} @ {len}"
                );
            } else {
                assert_eq!(
                    err,
                    DecodeError::LengthMismatch {
                        expected: golden.len(),
                        actual: len
                    },
                    "{name} @ {len}"
                );
            }
        }
    }
}

#[test]
fn every_extension_fails() {
    for (name, golden) in all_goldens() {
        for extra in [1usize, 2, 33, 64] {
            // Padding content must not matter — zeros and non-zeros both reject.
            for pad in [0x00u8, 0xEE] {
                let mut m = golden.clone();
                m.extend(core::iter::repeat_n(pad, extra));
                assert_eq!(
                    decode_err(&m),
                    DecodeError::LengthMismatch {
                        expected: golden.len(),
                        actual: golden.len() + extra,
                    },
                    "{name} extended by {extra} (pad {pad:#04x})"
                );
            }
        }
    }
}
