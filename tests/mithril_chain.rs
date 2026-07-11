//! Mithril certificate-chain verification (DoD line 4, part 2): the harvested
//! preprod segment is a hash-linked, AVK-bound chain of trust on Sextant's own
//! path — each certificate's aggregate verification key is the one its
//! predecessor authorized, so no certificate can be reordered, dropped, spliced,
//! or have its signer set (AVK) substituted.
//!
//! This composes part 1's [`Certificate::compute_hash`] (integrity + linkage)
//! with the AVK-binding rule from mithril-common's `verify_certificate`: a
//! certificate either shares its predecessor's epoch (and keeps the same AVK) or
//! is the next epoch (and its AVK is the `next_aggregate_verification_key` the
//! predecessor committed). The genesis Ed25519 anchor and the STM multi-signature
//! verify — the roots this chain of trust terminates in and rides on — are the
//! subsequent Mithril slices.
//!
//! The binding is self-authenticating: `next_aggregate_verification_key` is a
//! hashed field of the predecessor's protocol message, so its value is pinned by
//! the same SHA-256 commitment part 1 proves against the aggregator. Matching the
//! child's AVK to it across 10 real epoch transitions (plus one same-epoch link)
//! constrains the rule as tightly as a differential.
#![cfg(feature = "mithril")]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use sextant::mithril::{Certificate, ChainError, verify_chain};

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
        certs.push(
            Certificate::from_json(&bytes)
                .unwrap_or_else(|e| panic!("parse {}: {e:?}", path.display())),
        );
    }
    certs
}

/// Order the harvested certificates oldest→newest (segment root first, tip last)
/// by following `previous_hash`: the root is the certificate whose parent lies
/// outside the segment, and each next certificate is the one that names the
/// current one as its `previous_hash`. Panics unless the segment is one linear
/// chain (the shape `verify_chain` consumes).
fn ordered_root_to_tip(certs: Vec<Certificate>) -> Vec<Certificate> {
    let known: HashSet<&str> = certs.iter().map(|c| c.hash.as_str()).collect();
    let child_of: HashMap<&str, usize> = certs
        .iter()
        .enumerate()
        .map(|(i, c)| (c.previous_hash.as_str(), i))
        .collect();
    let root = certs
        .iter()
        .position(|c| !known.contains(c.previous_hash.as_str()))
        .expect("segment must have a root whose parent is outside it");

    let mut order = vec![root];
    while let Some(&next) = child_of.get(certs[*order.last().unwrap()].hash.as_str()) {
        order.push(next);
    }
    assert_eq!(
        order.len(),
        certs.len(),
        "harvested certificates must form one linear chain",
    );
    order.into_iter().map(|i| certs[i].clone()).collect()
}

/// The core proof: the whole harvested preprod segment verifies as a hash-linked,
/// AVK-bound chain, naming its tip certificate hash. Exercises both chaining
/// cases — 10 epoch transitions (child AVK == parent's committed next-AVK) and
/// one same-epoch link (the two epoch-300 certificates share an AVK).
#[test]
fn harvested_segment_is_an_avk_bound_chain() {
    let ordered = ordered_root_to_tip(harvested_certs());
    assert!(
        ordered.len() >= 11,
        "expected ≥11 certificates in the chain, found {}",
        ordered.len(),
    );

    let verified = verify_chain(&ordered).expect("harvested segment must verify as a chain");
    assert_eq!(verified.length, ordered.len());
    assert_eq!(verified.root_hash, ordered.first().unwrap().hash);
    assert_eq!(verified.tip_hash, ordered.last().unwrap().hash);
    // Name the tip certificate hash the walk anchors on (DoD line 4).
    assert_eq!(
        verified.tip_hash,
        "96602b8f11c48c3f6c4d1127793b2e1b2a08df0c5c5565d95475ed3b5b869795",
    );

    // The chain really spans multiple epochs, so the transition binding is
    // exercised (a single-epoch segment would prove nothing about it).
    let epochs: HashSet<u64> = ordered.iter().map(|c| c.epoch).collect();
    assert!(epochs.len() >= 10, "chain must span ≥10 epochs");
}

/// An empty segment is a clean error, never a vacuous success.
#[test]
fn empty_segment_is_rejected() {
    assert_eq!(verify_chain(&[]), Err(ChainError::Empty));
}

/// Corrupting a hashed field without repairing the committed hash breaks the
/// self-hash at that certificate's index — the integrity leg of the chain.
#[test]
fn tampered_certificate_body_is_rejected() {
    let mut ordered = ordered_root_to_tip(harvested_certs());
    // Flip a hashed field of a middle certificate; its committed `hash` no longer
    // matches, so `compute_hash` diverges before any linkage check.
    ordered[5].signed_message = flip_first_nibble(&ordered[5].signed_message);
    assert_eq!(verify_chain(&ordered), Err(ChainError::Hash { index: 5 }));
}

/// Removing a certificate from the middle breaks the hash linkage: the gap's
/// child no longer names its (now absent) parent's hash.
#[test]
fn broken_link_is_rejected() {
    let mut ordered = ordered_root_to_tip(harvested_certs());
    ordered.remove(5);
    // certs[5] (formerly [6]) now names the removed certificate as its parent.
    assert_eq!(
        verify_chain(&ordered),
        Err(ChainError::BrokenLink { index: 5 }),
    );
}

/// AVK-binding across an epoch transition is load-bearing: a self-consistent
/// certificate (its own hash repaired) whose AVK is NOT the one its predecessor
/// committed as next-AVK is rejected — the exact forged-child attack the binding
/// exists to stop. Truncate to make the transition certificate the tip so the
/// mutation has no downstream link to disturb.
#[test]
fn transition_avk_substitution_is_rejected() {
    let mut ordered = ordered_root_to_tip(harvested_certs());
    ordered.truncate(ordered.len() - 1); // drop the same-epoch tip; new tip is a transition
    let tip = ordered.len() - 1;
    let parent_epoch = ordered[tip - 1].epoch;
    assert_eq!(
        ordered[tip].epoch,
        parent_epoch + 1,
        "tip must be a transition"
    );

    ordered[tip].aggregate_verification_key =
        flip_first_nibble(&ordered[tip].aggregate_verification_key);
    ordered[tip].hash = ordered[tip].compute_hash(); // repair integrity; only the binding is wrong

    assert_eq!(
        verify_chain(&ordered),
        Err(ChainError::AvkBinding { index: tip }),
    );
}

/// AVK-binding within an epoch is load-bearing too: the same-epoch tip whose AVK
/// no longer equals its predecessor's is rejected even with its own hash repaired.
#[test]
fn same_epoch_avk_substitution_is_rejected() {
    let mut ordered = ordered_root_to_tip(harvested_certs());
    let tip = ordered.len() - 1;
    assert_eq!(
        ordered[tip].epoch,
        ordered[tip - 1].epoch,
        "tip must be a same-epoch link",
    );

    ordered[tip].aggregate_verification_key =
        flip_first_nibble(&ordered[tip].aggregate_verification_key);
    ordered[tip].hash = ordered[tip].compute_hash();

    assert_eq!(
        verify_chain(&ordered),
        Err(ChainError::AvkBinding { index: tip }),
    );
}

fn flip_first_nibble(hex: &str) -> String {
    let mut chars: Vec<char> = hex.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}
