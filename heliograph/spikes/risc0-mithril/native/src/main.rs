//! M0 native differential: parse → content-hash → verify_standard on native
//! Sextant, printing the same verdict mapping as the guest (guest/src/main.rs):
//! 0 = accepted; 1 = JSON parse failure; 2..=8 = `StandardError` variants in
//! declaration order; 9 = content-hash mismatch.
//!
//! Usage: hg-m0-native <fixture.json>

use std::time::Instant;

use anyhow::Context;
use sextant::mithril::{verify_standard, Certificate, StandardError};

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: hg-m0-native <fixture.json>")?;
    let bytes = std::fs::read(&path).with_context(|| format!("read {path}"))?;

    let t0 = Instant::now();
    let (code, t1, t2, t3) = pipeline(&bytes, t0);
    println!(
        "HG_NATIVE fixture={path} verdict={code} parse_s={:.6} content_hash_s={:.6} \
         verify_standard_s={:.6} total_s={:.6}",
        (t1 - t0).as_secs_f64(),
        (t2 - t1).as_secs_f64(),
        (t3 - t2).as_secs_f64(),
        (t3 - t0).as_secs_f64(),
    );
    Ok(())
}

fn pipeline(bytes: &[u8], t0: Instant) -> (u32, Instant, Instant, Instant) {
    let cert = match Certificate::from_json(bytes) {
        Ok(cert) => cert,
        Err(_) => {
            let t = Instant::now();
            return (1, t, t, t);
        }
    };
    let t1 = Instant::now();
    let hash_ok = cert.compute_hash() == cert.hash;
    let t2 = Instant::now();
    if !hash_ok {
        return (9, t1, t2, t2);
    }
    let code = match verify_standard(&cert) {
        Ok(()) => 0,
        Err(StandardError::NotStandard) => 2,
        Err(StandardError::MessageMismatch) => 3,
        Err(StandardError::WeakParameters) => 4,
        Err(StandardError::ImplausibleAvk) => 5,
        Err(StandardError::MalformedAvk) => 6,
        Err(StandardError::MalformedSignature) => 7,
        Err(StandardError::InvalidMultiSignature) => 8,
    };
    (code, t1, t2, Instant::now())
}
