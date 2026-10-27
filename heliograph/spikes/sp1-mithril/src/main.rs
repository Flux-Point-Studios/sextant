//! S-0002 / M0 executor — SP1 arm (BENCH.md §6.1, ADR-001).
//! Reads Mithril certificate JSON bytes via `sp1_zkvm::io`, verifies on
//! Sextant's `mithril` path, commits a `u32` verdict:
//! 0 = accepted, 1 = parse error, 2 = content-hash mismatch,
//! 3 = `verify_standard` rejection. Stage boundaries carry SP1
//! `cycle-tracker-report` markers so the host executor's `ExecutionReport`
//! yields the BENCH.md §4.2(11) stage split.
#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    println!("cycle-tracker-report-start: read-input");
    let bytes = sp1_zkvm::io::read_vec();
    println!("cycle-tracker-report-end: read-input");
    let verdict = verdict(&bytes);
    sp1_zkvm::io::commit(&verdict);
}

/// The BENCH.md §2.1 workload minus the journal codec — parse,
/// content-hash recompute, `verify_standard`.
#[cfg(feature = "mithril")]
fn verdict(bytes: &[u8]) -> u32 {
    use sextant::mithril::{Certificate, verify_standard};
    println!("cycle-tracker-report-start: parse-content-hash");
    let parsed = Certificate::from_json(bytes);
    let hash_ok = parsed
        .as_ref()
        .map(|cert| cert.compute_hash() == cert.hash)
        .unwrap_or(false);
    println!("cycle-tracker-report-end: parse-content-hash");
    let cert = match parsed {
        Ok(c) => c,
        Err(_) => return 1,
    };
    if !hash_ok {
        return 2;
    }
    println!("cycle-tracker-report-start: verify-standard");
    let outcome = verify_standard(&cert);
    println!("cycle-tracker-report-end: verify-standard");
    match outcome {
        Ok(()) => 0,
        Err(_) => 3,
    }
}

/// Layer 1: sextant `default-features = false` only — no `mithril` module
/// exists, so exercise a default-graph verify (input = vkey ‖ sig ‖ msg) to
/// keep sextant genuinely in the build.
#[cfg(not(feature = "mithril"))]
fn verdict(bytes: &[u8]) -> u32 {
    if bytes.len() < 96 {
        return 1;
    }
    let mut vkey = [0u8; 32];
    vkey.copy_from_slice(&bytes[..32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[32..96]);
    u32::from(!sextant::ed25519::verify(&vkey, &bytes[96..], &sig))
}
