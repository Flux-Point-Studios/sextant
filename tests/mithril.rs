//! Mithril certificate hashing (DoD line 4, part 1): `Certificate::compute_hash`
//! on Sextant's own path is byte-exact to what the preprod aggregator committed.
//!
//! The aggregator's own `hash` is the oracle, and it is self-authenticating: it
//! is the SHA-256 the real `mithril-common` produced over each certificate's
//! content, pinned on the live network, and every non-genesis certificate's
//! `previous_hash` IS the parent certificate's content hash. So recomputing the
//! hash on Sextant's path and matching all harvested certificates (and their
//! links) constrains the algorithm as tightly as a same-input differential — a
//! single wrong byte in the field set, ordering, or fixed-point encoding would
//! diverge on SHA-256.
//!
//! Signature verification (genesis Ed25519 anchor, STM multi-signature, AVK
//! binding, and the full tip→genesis walk) are the subsequent Mithril slices;
//! this slice proves only the hash-chain integrity primitive they all ride on.
#![cfg(feature = "mithril")]

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use sextant::mithril::Certificate;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// Every harvested `mithril-cert-*.json`, parsed on Sextant's own path.
fn harvested_certs() -> Vec<Certificate> {
    let mut certs = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with("mithril-cert-")
            || path.extension().and_then(|e| e.to_str()) != Some("json")
        {
            continue;
        }
        let bytes = fs::read(&path).expect("read cert vector");
        let cert = Certificate::from_json(&bytes)
            .unwrap_or_else(|e| panic!("parse {}: {e:?}", path.display()));
        certs.push(cert);
    }
    certs
}

/// The core proof: on every harvested preprod certificate, Sextant's own
/// `compute_hash` equals the hash the aggregator committed. Covers both
/// `MithrilStakeDistribution` and `CardanoTransactions` certificates, whose
/// `signed_entity_type` and `protocol_message` part sets differ.
#[test]
fn certificate_hash_matches_aggregator() {
    let certs = harvested_certs();
    assert!(
        certs.len() >= 10,
        "expected ≥10 harvested mithril certificates, found {}",
        certs.len(),
    );
    for cert in &certs {
        assert_eq!(
            cert.compute_hash(),
            cert.hash,
            "compute_hash must equal the aggregator's committed hash for {}",
            cert.hash,
        );
    }
}

/// The harvested segment is hash-linked: every certificate whose parent is also
/// in the segment has `previous_hash` equal to that parent's recomputed content
/// hash. This is the chain-integrity primitive the genesis-anchored walk builds
/// on — a spliced or reordered certificate cannot preserve the link.
#[test]
fn previous_hash_links_to_parent_content() {
    let certs = harvested_certs();
    let by_hash: HashMap<&str, &Certificate> = certs.iter().map(|c| (c.hash.as_str(), c)).collect();

    let mut linked = 0usize;
    for cert in &certs {
        if let Some(parent) = by_hash.get(cert.previous_hash.as_str()) {
            assert_eq!(
                parent.compute_hash(),
                cert.previous_hash,
                "child {}'s previous_hash must be the parent's content hash",
                cert.hash,
            );
            linked += 1;
        }
    }
    assert!(
        linked >= 10,
        "expected ≥10 in-segment parent links, found {linked}",
    );
}

/// Corrupting any hashed field must break the self-hash: the aggregator's hash
/// is a genuine commitment to the whole certificate, not a coincidence.
#[test]
fn tampered_certificate_breaks_the_hash() {
    let mut certs = harvested_certs();
    let cert = certs.pop().expect("at least one certificate");
    let good = cert.compute_hash();
    assert_eq!(good, cert.hash);

    // Re-parse and flip one hex nibble of the signed message; the recomputed
    // hash must no longer match the committed one.
    let raw = String::from_utf8(
        fs::read(vectors_dir().join(format!("mithril-cert-{}.json", cert.hash))).expect("read"),
    )
    .expect("utf8");
    let tampered = raw.replacen(
        &cert.signed_message,
        &flip_first_nibble(&cert.signed_message),
        1,
    );
    assert_ne!(tampered, raw, "tamper actually changed the bytes");
    let other = Certificate::from_json(tampered.as_bytes()).expect("still valid json");
    assert_ne!(
        other.compute_hash(),
        cert.hash,
        "a tampered signed_message must not reproduce the committed hash",
    );
}

fn flip_first_nibble(hex: &str) -> String {
    let mut chars: Vec<char> = hex.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}
