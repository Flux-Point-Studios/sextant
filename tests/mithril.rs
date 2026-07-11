//! Mithril certificate verification on Sextant's own path.
//!
//! Part 1 (hashing): `Certificate::compute_hash` is byte-exact to what the
//! preprod aggregator committed. The aggregator's own `hash` is a
//! self-authenticating oracle — the SHA-256 the real `mithril-common` produced
//! over each certificate's content, pinned on the live network, and every
//! non-genesis certificate's `previous_hash` IS the parent's content hash. So
//! recomputing the hash and matching all harvested certificates (and their
//! links) constrains the algorithm as tightly as a same-input differential.
//!
//! Part 3 (genesis anchor): the trust root the chain terminates in. The oldest
//! certificate is a *genesis* certificate, signed not by an STM multi-signature
//! but by the network genesis Ed25519 key over its `signed_message`. The real
//! preprod genesis certificate verifies on Sextant's own Ed25519 path under the
//! pinned network genesis verification key, byte-identical to pallas-crypto's
//! independent (cryptoxide) verdict, and its immediate child is hash-linked and
//! AVK-bound to it — the genesis trust root authorizes the next epoch's signer set.
//!
//! Part 4 (STM multi-signature): the authority every *standard* certificate rides
//! on. Each is signed by a stake-based threshold multi-signature over its
//! `signed_message` under its own aggregate verification key. All 12 real preprod
//! standard multi-signatures verify on Sextant's own path (wire deserialize +
//! parameter assembly + message binding), and swapping the message, the AVK, or
//! the protocol message — or corrupting the blobs — is rejected. The BLS
//! aggregate / lottery / Merkle-batch check is the composed `mithril-stm`
//! primitive: it is the reference STM implementation, so the oracle here is the
//! real on-chain signatures themselves (a threshold BLS signature no adversary can
//! forge), not a second library.
//!
//! Part 5 (genesis-anchored walk): [`verify_chain_anchored`] composes all three —
//! the segment's hash-linkage + AVK-binding + integrity (`verify_chain`), the root
//! as the network genesis anchor (`verify_genesis`), and every rising certificate's
//! STM multi-signature (`verify_standard`) — into one bytes-in/verdict-out verifier.
//! A real preprod chain rooted in the epoch-196 re-genesis verifies end-to-end,
//! naming the tip certificate hash; a broken link, substituted signer set, tampered
//! multi-signature, or wrong genesis key anywhere in the walk rejects.
#![cfg(feature = "mithril")]

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use pallas_crypto::key::ed25519::{PublicKey, Signature};
use sextant::mithril::{
    AnchoredError, Certificate, ChainError, GenesisError, ProtocolMessagePartKey, StandardError,
    verify_chain, verify_chain_anchored, verify_genesis, verify_standard,
};

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

/// The real preprod Mithril genesis certificate hash — the trust root this whole
/// certificate chain terminates in (release-preprod re-genesis at epoch 196).
const GENESIS_HASH: &str = "69bc3bdfff0bb134675396e83b301f43e763d576d4b85856f6b3cb806af7ad59";

fn read_cert(name: &str) -> Certificate {
    let bytes = fs::read(vectors_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_json(&bytes).unwrap_or_else(|e| panic!("parse {name}: {e:?}"))
}

/// The pinned per-network genesis verification key (`mithril-genesis.vkey`, the
/// decoded 32-byte Ed25519 key published in the mithril repo, reviewed in the PR).
fn genesis_vkey() -> [u8; 32] {
    let text = fs::read_to_string(vectors_dir().join("mithril-genesis.vkey")).expect("read vkey");
    hex::decode(text.trim())
        .expect("vkey hex")
        .try_into()
        .expect("32-byte genesis vkey")
}

/// The trust root: the real preprod genesis certificate verifies on Sextant's own
/// Ed25519 path under the pinned network genesis verification key. Names the hash.
#[test]
fn real_preprod_genesis_certificate_verifies() {
    let cert = read_cert("mithril-genesis-cert.json");
    assert_eq!(cert.hash, GENESIS_HASH, "genesis certificate hash");
    // A genuine, self-consistent genesis certificate with no parent.
    assert_eq!(
        cert.compute_hash(),
        cert.hash,
        "genesis self-hash must hold"
    );
    assert!(cert.previous_hash.is_empty(), "genesis has no parent");
    assert!(cert.is_genesis(), "carries a genesis signature");
    verify_genesis(&cert, &genesis_vkey()).expect("genuine genesis certificate must verify");
}

/// Sextant's genesis-signature verdict agrees, on the same (vkey, message,
/// signature), with pallas-crypto's Ed25519 — an independent cryptoxide backend,
/// not the curve25519-dalek fork Sextant's own path uses. The DoD's
/// "byte-identical verdicts to pallas", now for the Mithril trust root.
#[test]
fn genesis_verdict_matches_independent_oracle() {
    let cert = read_cert("mithril-genesis-cert.json");
    let vkey = genesis_vkey();
    let sig: [u8; 64] = hex::decode(&cert.genesis_signature)
        .expect("sig hex")
        .try_into()
        .expect("64-byte genesis signature");
    let msg = cert.signed_message.as_bytes();
    let pk = PublicKey::from(vkey);

    // Genuine: Sextant and pallas agree, and both accept.
    let sextant = sextant::ed25519::verify(&vkey, msg, &sig);
    let oracle = pk.verify(msg, &Signature::from(sig));
    assert_eq!(sextant, oracle, "genuine verdict ≠ oracle");
    assert!(sextant, "genesis signature must verify");
    assert!(verify_genesis(&cert, &vkey).is_ok());

    // One-bit flip in the signature: both reject.
    let mut bad = sig;
    bad[0] ^= 0x01;
    let sextant_bad = sextant::ed25519::verify(&vkey, msg, &bad);
    let oracle_bad = pk.verify(msg, &Signature::from(bad));
    assert_eq!(sextant_bad, oracle_bad, "tampered verdict ≠ oracle");
    assert!(!sextant_bad, "tampered genesis signature must be rejected");
}

/// Every way the anchor can be forged is rejected, each with a distinct verdict:
/// a perturbed signature or a wrong genesis key fails Ed25519; a swapped protocol
/// message is no longer bound by `signed_message`; a standard certificate is not a
/// genesis anchor at all; a malformed signature never reaches the curve.
#[test]
fn tampered_genesis_certificate_is_rejected() {
    let good = read_cert("mithril-genesis-cert.json");
    let vkey = genesis_vkey();
    assert!(verify_genesis(&good, &vkey).is_ok());

    // Flipped signature byte → Ed25519 rejects.
    let mut sig_bad = good.clone();
    let mut sig = hex::decode(&good.genesis_signature).unwrap();
    sig[0] ^= 0x01;
    sig_bad.genesis_signature = hex::encode(sig);
    assert_eq!(
        verify_genesis(&sig_bad, &vkey),
        Err(GenesisError::InvalidSignature),
    );

    // Wrong genesis verification key → Ed25519 rejects.
    let mut wrong = vkey;
    wrong[0] ^= 0x01;
    assert_eq!(
        verify_genesis(&good, &wrong),
        Err(GenesisError::InvalidSignature),
    );

    // Swapped protocol message → signed_message no longer binds it.
    let mut msg_bad = good.clone();
    msg_bad
        .protocol_message
        .message_parts
        .insert(ProtocolMessagePartKey::CurrentEpoch, "999".to_string());
    assert_eq!(
        verify_genesis(&msg_bad, &vkey),
        Err(GenesisError::MessageMismatch),
    );

    // A standard certificate carries no genesis signature.
    let standard = read_cert("mithril-genesis-child.json");
    assert!(!standard.is_genesis());
    assert_eq!(
        verify_genesis(&standard, &vkey),
        Err(GenesisError::NotGenesis),
    );

    // Malformed signature hex → rejected before any curve work.
    let mut malformed = good.clone();
    malformed.genesis_signature = "abcd".to_string();
    assert_eq!(
        verify_genesis(&malformed, &vkey),
        Err(GenesisError::MalformedSignature),
    );
}

/// The genesis anchor authorizes the next epoch: its immediate child is
/// hash-linked to it and carries the AVK the genesis certificate signed, so
/// `verify_chain` accepts the two-certificate segment rooted at the verified
/// genesis. This is one hop of the chain of trust rising from the anchor.
#[test]
fn genesis_anchors_its_child() {
    let genesis = read_cert("mithril-genesis-cert.json");
    let child = read_cert("mithril-genesis-child.json");
    assert_eq!(child.previous_hash, genesis.hash, "child links to genesis");

    verify_genesis(&genesis, &genesis_vkey()).expect("genesis anchor verifies");
    let verified =
        verify_chain(&[genesis.clone(), child.clone()]).expect("genesis→child chain verifies");
    assert_eq!(verified.root_hash, genesis.hash);
    assert_eq!(verified.tip_hash, child.hash);
    assert_eq!(verified.length, 2);
}

/// Every harvested *standard* certificate — one that rides on an STM
/// multi-signature rather than a genesis Ed25519 signature.
fn standard_certs() -> Vec<Certificate> {
    let mut certs: Vec<Certificate> = harvested_certs()
        .into_iter()
        .filter(|c| !c.is_genesis() && !c.multi_signature.is_empty())
        .collect();
    // Deterministic order so per-index tampering picks the same target every run.
    certs.sort_by(|a, b| a.hash.cmp(&b.hash));
    certs
}

/// The STM half of the trust chain: every real preprod *standard* certificate is
/// authorized by a valid STM (stake-based threshold multi-signature) over its own
/// `signed_message`, under its own aggregate verification key and the protocol
/// parameters in force. Verified on Sextant's own path — wire deserialize,
/// parameter assembly, and the signed-message binding are Sextant's; the BLS
/// aggregate / lottery-eligibility / Merkle-batch verify is the composed
/// mithril-stm primitive. These are real multi-signatures produced by real
/// preprod signers, so a valid verdict is genuine ground truth, not a fixture.
#[test]
fn real_preprod_multi_signatures_verify() {
    let certs = standard_certs();
    assert!(
        certs.len() >= 10,
        "expected ≥10 harvested standard certificates, found {}",
        certs.len(),
    );
    for cert in &certs {
        verify_standard(cert)
            .unwrap_or_else(|e| panic!("standard certificate {} must verify: {e:?}", cert.hash));
    }
}

/// The multi-signature genuinely binds {message, AVK, parameters}: swapping in a
/// different certificate's signed message or aggregate verification key makes the
/// STM verify fail. Non-vacuous — the real BLS signature only satisfies its own
/// message and signer set.
#[test]
fn multi_signature_binds_message_and_avk() {
    let certs = standard_certs();
    let a = &certs[0];
    let b = certs
        .iter()
        .find(|c| {
            c.signed_message != a.signed_message
                && c.aggregate_verification_key != a.aggregate_verification_key
        })
        .expect("a second distinct standard certificate");

    // Genuine certificate verifies.
    assert!(verify_standard(a).is_ok());

    // A's multi-signature over B's message → STM rejects.
    let mut wrong_message = a.clone();
    wrong_message.protocol_message = b.protocol_message.clone();
    wrong_message.signed_message = b.signed_message.clone();
    assert_eq!(
        verify_standard(&wrong_message),
        Err(StandardError::InvalidMultiSignature),
    );

    // A's multi-signature under B's aggregate verification key → STM rejects.
    let mut wrong_avk = a.clone();
    wrong_avk.aggregate_verification_key = b.aggregate_verification_key.clone();
    assert_eq!(
        verify_standard(&wrong_avk),
        Err(StandardError::InvalidMultiSignature),
    );
}

/// Every way a standard-certificate authorization can be forged is rejected with a
/// distinct verdict: a genesis certificate is not STM-signed; a swapped protocol
/// message is no longer bound by `signed_message`; a corrupted signature or AVK
/// blob never reaches the curve.
#[test]
fn tampered_standard_certificate_is_rejected() {
    let good = standard_certs().remove(0);
    assert!(verify_standard(&good).is_ok());

    // A genesis certificate carries no multi-signature.
    let genesis = read_cert("mithril-genesis-cert.json");
    assert_eq!(verify_standard(&genesis), Err(StandardError::NotStandard));

    // Swapped protocol message → signed_message no longer binds it, caught before
    // any curve work.
    let mut msg_bad = good.clone();
    msg_bad
        .protocol_message
        .message_parts
        .insert(ProtocolMessagePartKey::CurrentEpoch, "999".to_string());
    assert_eq!(
        verify_standard(&msg_bad),
        Err(StandardError::MessageMismatch),
    );

    // Malformed multi-signature hex → rejected as malformed, never a false accept.
    let mut sig_bad = good.clone();
    sig_bad.multi_signature = "not-hex".to_string();
    assert_eq!(
        verify_standard(&sig_bad),
        Err(StandardError::MalformedSignature),
    );

    // Malformed aggregate verification key hex → rejected as malformed.
    let mut avk_bad = good.clone();
    avk_bad.aggregate_verification_key = "zzzz".to_string();
    assert_eq!(verify_standard(&avk_bad), Err(StandardError::MalformedAvk));
}

/// The real preprod tip certificate the genesis-anchored chain terminates under —
/// the epoch-197 child of the epoch-196 re-genesis.
const ANCHORED_TIP_HASH: &str = "fc979366ab86682b08901ad69c4de5c9cce503684fba038807d44c59f2d56b72";

/// DoD line 4: a real preprod genesis-anchored certificate chain verifies
/// end-to-end on Sextant's own path. `verify_chain_anchored` composes the three
/// verifiers built across parts 2–4 into one bytes-in/verdict-out control flow:
/// the segment's hash-linkage + AVK-binding + integrity ([`verify_chain`]), the
/// root as the network genesis anchor ([`verify_genesis`]), and every rising
/// certificate's STM multi-signature ([`verify_standard`]). The chain rooted in
/// the epoch-196 re-genesis and rising to its epoch-197 child verifies; the
/// returned endpoints name the genesis root and the tip.
#[test]
fn real_preprod_genesis_anchored_chain_verifies() {
    let genesis = read_cert("mithril-genesis-cert.json");
    let child = read_cert("mithril-genesis-child.json");
    let segment = [genesis, child.clone()];

    let verified =
        verify_chain_anchored(&segment, &genesis_vkey()).expect("genesis-anchored chain verifies");

    assert_eq!(
        verified.root_hash, GENESIS_HASH,
        "root is the genesis anchor"
    );
    assert_eq!(
        verified.tip_hash, ANCHORED_TIP_HASH,
        "tip is the epoch-197 child",
    );
    assert_eq!(verified.length, 2);
    // The tip genuinely rises from the anchor: it is a standard certificate
    // authorized by a real STM multi-signature, not the genesis key.
    assert!(!child.is_genesis());
    verify_standard(&child).expect("tip rides an STM multi-signature");
}

/// Recompute a certificate's committed hash so a targeted-field tamper stays
/// self-consistent — forcing the *deeper* verifier (link / AVK-binding / STM),
/// not the integrity guard, to be the one that rejects it.
fn reseal(mut cert: Certificate) -> Certificate {
    cert.hash = cert.compute_hash();
    cert
}

/// A distinct real standard certificate whose AVK and multi-signature differ from
/// `exclude` — a valid signer set / signature to substitute in negative tests.
fn foreign_standard_cert(exclude: &Certificate) -> Certificate {
    standard_certs()
        .into_iter()
        .find(|c| {
            c.aggregate_verification_key != exclude.aggregate_verification_key
                && c.multi_signature != exclude.multi_signature
        })
        .expect("a distinct standard certificate for substitution")
}

/// Every way the genesis-anchored walk can be forged is rejected, each with a
/// distinct verdict pointing at the offending certificate. Self-consistent tampers
/// (hash resealed) prove the *deeper* verifier catches what the integrity guard
/// cannot — the whole point of composing all three.
#[test]
fn chain_anchored_rejects_forgeries() {
    let genesis = read_cert("mithril-genesis-cert.json");
    let child = read_cert("mithril-genesis-child.json");
    let vkey = genesis_vkey();
    let good = [genesis.clone(), child.clone()];
    assert!(verify_chain_anchored(&good, &vkey).is_ok());

    // Empty segment.
    assert_eq!(
        verify_chain_anchored(&[], &vkey),
        Err(AnchoredError::Chain(ChainError::Empty)),
    );

    // Wrong genesis verification key → the anchor's Ed25519 signature rejects.
    let mut wrong_vkey = vkey;
    wrong_vkey[0] ^= 0x01;
    assert_eq!(
        verify_chain_anchored(&good, &wrong_vkey),
        Err(AnchoredError::Genesis(GenesisError::InvalidSignature)),
    );

    // Root is a standard certificate, not the genesis anchor.
    assert_eq!(
        verify_chain_anchored(std::slice::from_ref(&child), &vkey),
        Err(AnchoredError::Genesis(GenesisError::NotGenesis)),
    );

    // Broken link: the child points somewhere other than its genesis parent, even
    // with a self-consistent hash.
    let mut relinked = child.clone();
    relinked.previous_hash = "00".repeat(32);
    assert_eq!(
        verify_chain_anchored(&[genesis.clone(), reseal(relinked)], &vkey),
        Err(AnchoredError::Chain(ChainError::BrokenLink { index: 1 })),
    );

    // Naive field tamper (hash NOT resealed) is caught by the integrity guard
    // first — this is what pins each certificate's k/m/phi_f to its committed hash.
    let mut naive = child.clone();
    naive.aggregate_verification_key = flip_first_nibble(&naive.aggregate_verification_key);
    assert_eq!(
        verify_chain_anchored(&[genesis.clone(), naive], &vkey),
        Err(AnchoredError::Chain(ChainError::Hash { index: 1 })),
    );

    // Substituted signer set: a self-consistent child carrying a *different* valid
    // AVK is not the one the genesis certificate committed → AVK-binding rejects.
    let foreign = foreign_standard_cert(&child);
    let mut swapped_avk = child.clone();
    swapped_avk.aggregate_verification_key = foreign.aggregate_verification_key.clone();
    assert_eq!(
        verify_chain_anchored(&[genesis.clone(), reseal(swapped_avk)], &vkey),
        Err(AnchoredError::Chain(ChainError::AvkBinding { index: 1 })),
    );

    // Tampered authority: a self-consistent child whose AVK still binds but whose
    // multi-signature is a *different* real signature → rejected at the standard-cert
    // layer, attributed to the certificate at its index. (A foreign signature is
    // inconsistent with the child's committed stake, so the bounds guard catches it
    // before the STM verify; either way it is an `AnchoredError::Standard`.)
    let mut swapped_sig = child.clone();
    swapped_sig.multi_signature = foreign.multi_signature.clone();
    let verdict = verify_chain_anchored(&[genesis, reseal(swapped_sig)], &vkey);
    assert!(
        matches!(verdict, Err(AnchoredError::Standard { index: 1, .. })),
        "swapped multi-signature must be rejected at the standard-cert layer, got {verdict:?}",
    );
}

/// Hardening (part-4 red-team carry): `verify_standard` fails closed on degenerate
/// protocol parameters. Standalone, a certificate's own `k`/`m`/`phi_f` are
/// attacker-controlled; a `k=0` or `phi_f≥1` threshold would let a trivial
/// multi-signature clear the bar (`phi_f == 1` makes every claimed lottery win, so
/// one signer alone reaches the quorum). The guard rejects them before any curve
/// work, independent of the chain-integrity check that also pins them to the
/// committed hash.
#[test]
fn verify_standard_rejects_weak_parameters() {
    let child = read_cert("mithril-genesis-child.json");
    verify_standard(&child).expect("genuine parameters verify");

    let mut k0 = child.clone();
    k0.metadata.protocol_parameters.k = 0;
    assert_eq!(verify_standard(&k0), Err(StandardError::WeakParameters));

    let mut m0 = child.clone();
    m0.metadata.protocol_parameters.m = 0;
    assert_eq!(verify_standard(&m0), Err(StandardError::WeakParameters));

    let mut phi_zero = child.clone();
    phi_zero.metadata.protocol_parameters.phi_f = 0.0;
    assert_eq!(
        verify_standard(&phi_zero),
        Err(StandardError::WeakParameters)
    );

    let mut phi_high = child.clone();
    phi_high.metadata.protocol_parameters.phi_f = 1.5;
    assert_eq!(
        verify_standard(&phi_high),
        Err(StandardError::WeakParameters)
    );

    let mut phi_nan = child.clone();
    phi_nan.metadata.protocol_parameters.phi_f = f64::NAN;
    assert_eq!(
        verify_standard(&phi_nan),
        Err(StandardError::WeakParameters)
    );

    // phi_f = 1.0 makes every claimed lottery win, so it is rejected as degenerate
    // even though a higher phi_f would otherwise only ease the lottery — a lone
    // signer must not be able to clear the quorum. (A hair below, phi_f < 1, is
    // accepted; the genuine 0.65 verifies above.)
    let mut phi_one = child;
    phi_one.metadata.protocol_parameters.phi_f = 1.0;
    assert_eq!(
        verify_standard(&phi_one),
        Err(StandardError::WeakParameters)
    );
}

/// Decode an aggregator json-hex field back to its JSON string, for targeted
/// hostile mutation.
fn decode_hex_to_string(hex: &str) -> String {
    String::from_utf8(hex::decode(hex).expect("hex")).expect("utf8 json")
}

/// Run `verify_standard` on a worker thread, returning its verdict only if it
/// completes within `secs` — `None` on timeout. A hostile input that drove the STM
/// verifier into unbounded work would time out here, turning a would-be hang into a
/// clean assertion failure instead of a stuck test process.
fn verify_standard_within(cert: Certificate, secs: u64) -> Option<Result<(), StandardError>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(verify_standard(&cert));
    });
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

/// Hardening (part-4 red-team carry): hostile STM serde inputs are rejected as
/// clean, prompt `Err`s — never a panic, hang, or unbounded allocation.
/// `verify_standard` is the untrusted-bytes deserialize entry point the chain walk
/// exposes. Two of these — a signer claiming more stake than the total, and a
/// `nr_leaves` near the u64 overflow — drive stock mithril-stm into unbounded work;
/// [`guard_stm_bounds`](sextant::mithril) must fail them closed *before* the verify,
/// which the bounded-time assertion (`Some(..)`) proves.
#[test]
fn verify_standard_rejects_hostile_stm_inputs() {
    let child = read_cert("mithril-genesis-child.json");
    verify_standard(&child).expect("baseline verifies");
    let avk_json = decode_hex_to_string(&child.aggregate_verification_key);
    let sig_json = decode_hex_to_string(&child.multi_signature);

    // Truncated AVK JSON → deserialize fails cleanly.
    let mut avk_trunc = child.clone();
    avk_trunc.aggregate_verification_key = hex::encode(&avk_json.as_bytes()[..avk_json.len() - 6]);
    assert_eq!(
        verify_standard(&avk_trunc),
        Err(StandardError::MalformedAvk)
    );

    // Odd-length AVK hex → not even bytes.
    let mut avk_odd = child.clone();
    avk_odd.aggregate_verification_key = "abc".to_string();
    assert_eq!(verify_standard(&avk_odd), Err(StandardError::MalformedAvk));

    // DoS: a total_stake below a signer's claimed stake makes the eligibility
    // Taylor series never converge — the guard rejects it promptly, no hang.
    let mut avk_stake = child.clone();
    avk_stake.aggregate_verification_key = hex::encode(
        avk_json
            .replacen("\"total_stake\":52279233772202", "\"total_stake\":1", 1)
            .as_bytes(),
    );
    assert_eq!(
        verify_standard_within(avk_stake, 10),
        Some(Err(StandardError::ImplausibleAvk)),
    );

    // DoS: nr_leaves near the u64 overflow makes the Merkle verify never terminate —
    // the guard rejects it promptly, no hang.
    let mut avk_huge = child.clone();
    avk_huge.aggregate_verification_key = hex::encode(
        avk_json
            .replacen("\"nr_leaves\":26", "\"nr_leaves\":18446744073709551615", 1)
            .as_bytes(),
    );
    assert_eq!(
        verify_standard_within(avk_huge, 10),
        Some(Err(StandardError::ImplausibleAvk)),
    );

    // Oversized blobs are capped on length before any decode — a memory DoS
    // (mithril-stm's deserialize and the guard's `serde_json::Value` both allocate
    // proportional to the input).
    let mut avk_big = child.clone();
    avk_big.aggregate_verification_key = "0".repeat((1 << 22) + 2);
    assert_eq!(verify_standard(&avk_big), Err(StandardError::MalformedAvk));
    let mut sig_big = child.clone();
    sig_big.multi_signature = "0".repeat((1 << 22) + 2);
    assert_eq!(
        verify_standard(&sig_big),
        Err(StandardError::MalformedSignature),
    );

    // DoS: an oversized `indexes` array — mithril-stm evaluates one lottery per
    // index across all signatures *before* checking the count against k, so a
    // signature with a huge indexes array must be rejected before the verify. The
    // bounded-time assertion proves the guard fires, not the loop.
    let idx_key = "\"indexes\":[";
    let idx_start = sig_json.find(idx_key).expect("indexes array") + idx_key.len();
    let idx_end = idx_start + sig_json[idx_start..].find(']').expect("indexes close");
    let flood = vec!["0"; 400_000].join(",");
    let hostile = format!("{}{flood}{}", &sig_json[..idx_start], &sig_json[idx_end..]);
    let mut idx_flood = child.clone();
    idx_flood.multi_signature = hex::encode(hostile.as_bytes());
    assert_eq!(
        verify_standard_within(idx_flood, 10),
        Some(Err(StandardError::ImplausibleAvk)),
    );

    // Valid JSON, invalid BLS point: a corrupted signature curve point never
    // deserializes to a valid signature.
    let mut sig_point = child.clone();
    sig_point.multi_signature = hex::encode(
        sig_json
            .replacen("[152,236,234,187", "[255,236,234,187", 1)
            .as_bytes(),
    );
    assert_eq!(
        verify_standard(&sig_point),
        Err(StandardError::MalformedSignature),
    );

    // Truncated signature JSON → deserialize fails cleanly.
    let mut sig_trunc = child;
    sig_trunc.multi_signature = hex::encode(&sig_json.as_bytes()[..sig_json.len() - 6]);
    assert_eq!(
        verify_standard(&sig_trunc),
        Err(StandardError::MalformedSignature),
    );
}
