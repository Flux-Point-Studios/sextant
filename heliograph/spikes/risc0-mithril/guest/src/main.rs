//! M0 executor guest: one Mithril standard-certificate verification on
//! Sextant's `mithril` path, inside the RISC Zero zkVM, with per-stage
//! `env::cycle_count()` instrumentation (BENCH.md §4.2 item 11). Journals a
//! u32 verdict code — accepted or rejected, never a bare panic (HANDOFF §5).
//!
//! Stage split goes to stderr as `HG_STAGE <name>=<cycles>` lines (forwarded
//! to the host by the executor); the journal stays verdict-only so journal
//! bytes are identical across backend configurations.
#![no_main]
risc0_zkvm::guest::entry!(main);

use risc0_zkvm::guest::env;

fn main() {
    let c0 = env::cycle_count();
    let cert_json: Vec<u8> = env::read();
    let c1 = env::cycle_count();
    eprintln!("HG_STAGE read_input={}", c1 - c0);
    let code = verdict(&cert_json);
    eprintln!("HG_STAGE total={}", env::cycle_count() - c0);
    eprintln!("HG_VERDICT {code}");
    env::commit(&code);
}

/// Verdict codes (mirrored byte-for-byte by the native differential binary,
/// `../native`): 0 = accepted; 1 = JSON parse failure; 2..=8 = the
/// `StandardError` variants in declaration order (mithril.rs:392); 9 =
/// content-hash mismatch (recomputed `Certificate::compute_hash()` != the
/// declared `hash` field — BENCH.md §2.1 step 2, `verify_chain`'s integrity
/// check applied to the single fixture certificate).
#[cfg(feature = "mithril")]
fn verdict(cert_json: &[u8]) -> u32 {
    use sextant::mithril::{verify_standard, Certificate, StandardError};
    let c0 = env::cycle_count();
    let cert = match Certificate::from_json(cert_json) {
        Ok(cert) => cert,
        Err(_) => return 1,
    };
    let c1 = env::cycle_count();
    eprintln!("HG_STAGE parse={}", c1 - c0);
    let hash_ok = cert.compute_hash() == cert.hash;
    let c2 = env::cycle_count();
    eprintln!("HG_STAGE content_hash={}", c2 - c1);
    if !hash_ok {
        return 9;
    }
    let res = verify_standard(&cert);
    let c3 = env::cycle_count();
    eprintln!("HG_STAGE verify_standard={}", c3 - c2);
    match res {
        Ok(()) => 0,
        Err(StandardError::NotStandard) => 2,
        Err(StandardError::MessageMismatch) => 3,
        Err(StandardError::WeakParameters) => 4,
        Err(StandardError::ImplausibleAvk) => 5,
        Err(StandardError::MalformedAvk) => 6,
        Err(StandardError::MalformedSignature) => 7,
        Err(StandardError::InvalidMultiSignature) => 8,
    }
}

/// Bisect layer 1 (no `mithril` feature): prove the default no_std-canary-gated
/// sextant graph compiles and links for the zkVM target. Touches a real
/// verify-path entry point so the linker cannot drop the rlib wholesale.
#[cfg(not(feature = "mithril"))]
fn verdict(_cert_json: &[u8]) -> u32 {
    let n = sextant::nonce::combine(&[0u8; 32], &[0u8; 32]);
    u32::MAX - u32::from(n[0])
}
