//! Operational-certificate verification, differentially checked against the
//! chain itself. Every Praos header carries an operational certificate at
//! header_body index 8: the pool's hot KES verification key, a sequence
//! number, the KES-period counter it was issued at, and an Ed25519 signature
//! by the pool's COLD key (the header's `issuer_vkey`) over
//! `hot_vkey || BE64(sequence_number) || BE64(kes_period)`.
//!
//! The opcert is what binds an ephemeral KES key to the pool's registered cold
//! key, so a spoofed header cannot borrow a real pool's identity. cardano-node
//! minted and accepted these blocks, so a genuine opcert must verify on
//! Sextant's own code path, and any tampering must be rejected.

use std::fs;
use std::path::PathBuf;

use pallas_crypto::key::ed25519::{PublicKey, Signature};
use sextant::header::HeaderView;
use sextant::kes::{self, KesError};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// A real header's cold key and the operational certificate it authorizes.
struct OpCertCase {
    slot: u64,
    cold_vkey: [u8; 32],
    view: HeaderView,
}

/// Every preprod vector, decoded into an opcert case, sorted by slot for a
/// deterministic anchor (`fs::read_dir` order is platform-dependent).
fn opcert_cases() -> Vec<OpCertCase> {
    opcert_cases_with_prefix("preprod-")
}

/// Every freshly-harvested vector for `prefix`, marked by its `.eta0` sidecar
/// (which excludes the synthetic mainnet decode-fixtures), decoded into an opcert
/// case, sorted by slot for a deterministic anchor.
fn opcert_cases_with_prefix(prefix: &str) -> Vec<OpCertCase> {
    let mut cases = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with(prefix) || path.extension().and_then(|e| e.to_str()) != Some("block") {
            continue;
        }
        if !path.with_extension("eta0").exists() {
            continue;
        }
        let view =
            HeaderView::from_block_cbor(&unhex(&fs::read_to_string(&path).expect("read vector")))
                .unwrap_or_else(|e| panic!("decode {}: {e:?}", path.display()));
        cases.push(OpCertCase {
            slot: view.slot,
            cold_vkey: view.issuer_vkey,
            view,
        });
    }
    cases.sort_by_key(|c| c.slot);
    cases
}

/// The core slice: every real preprod operational certificate verifies on
/// Sextant's own Ed25519 code path — the cold key genuinely signed the hot KES
/// key, sequence number, and issue period. This is cardano-node ground truth.
#[test]
fn real_preprod_opcerts_verify() {
    let cases = opcert_cases();
    assert!(
        cases.len() >= 20,
        "DoD requires ≥20 opcert-verify vectors, found {}",
        cases.len(),
    );
    for c in &cases {
        kes::verify_opcert(&c.cold_vkey, &c.view.opcert).unwrap_or_else(|e| {
            panic!(
                "slot {} rejected a genuine operational certificate: {e:?}",
                c.slot
            )
        });
    }
}

/// The "from mainnet" half of the cold→hot delegation: every freshly-harvested
/// mainnet operational certificate verifies on Sextant's own Ed25519 path (the
/// pool's cold key genuinely signed the hot KES key, sequence, and period), and
/// pallas-crypto's independent cryptoxide Ed25519 agrees on the same inputs.
#[test]
fn real_mainnet_opcerts_verify() {
    let cases = opcert_cases_with_prefix("mainnet-");
    assert!(
        cases.len() >= 20,
        "DoD line 2 requires ≥20 mainnet opcert-verify vectors, found {}",
        cases.len(),
    );
    for c in &cases {
        kes::verify_opcert(&c.cold_vkey, &c.view.opcert).unwrap_or_else(|e| {
            panic!(
                "mainnet slot {} rejected a genuine operational certificate: {e:?}",
                c.slot
            )
        });
        let msg = kes::opcert_signable(&c.view.opcert);
        let pk = PublicKey::from(c.cold_vkey);
        let sextant = sextant::ed25519::verify(&c.cold_vkey, &msg, &c.view.opcert.sigma);
        let oracle = pk.verify(msg, &Signature::from(c.view.opcert.sigma));
        assert_eq!(sextant, oracle, "mainnet slot {}: verdict ≠ oracle", c.slot);
        assert!(
            sextant,
            "mainnet slot {}: genuine opcert must be accepted",
            c.slot
        );
    }
}

/// The opcert is bound to every field the cold key signed: perturbing the
/// signature, the hot vkey, the sequence number, or the KES period each breaks
/// verification. A wrong cold key cannot claim another pool's opcert either.
#[test]
fn tampered_opcert_is_rejected() {
    let cases = opcert_cases();
    let c = &cases[0];
    let good = &c.view.opcert;

    let bad_sig = {
        let mut oc = good.clone();
        oc.sigma[0] ^= 0x01;
        oc
    };
    assert_eq!(
        kes::verify_opcert(&c.cold_vkey, &bad_sig),
        Err(KesError::OpCertInvalidSignature),
    );

    let bad_hot = {
        let mut oc = good.clone();
        oc.hot_vkey[0] ^= 0x01;
        oc
    };
    assert_eq!(
        kes::verify_opcert(&c.cold_vkey, &bad_hot),
        Err(KesError::OpCertInvalidSignature),
    );

    let bad_seq = {
        let mut oc = good.clone();
        oc.sequence_number ^= 1;
        oc
    };
    assert_eq!(
        kes::verify_opcert(&c.cold_vkey, &bad_seq),
        Err(KesError::OpCertInvalidSignature),
    );

    let bad_period = {
        let mut oc = good.clone();
        oc.kes_period ^= 1;
        oc
    };
    assert_eq!(
        kes::verify_opcert(&c.cold_vkey, &bad_period),
        Err(KesError::OpCertInvalidSignature),
    );

    // Another pool's cold key cannot verify this opcert. Consecutive preprod
    // blocks can share a pool, so pick a case whose cold key genuinely differs.
    let other = cases
        .iter()
        .find(|o| o.cold_vkey != c.cold_vkey)
        .expect("vector set must contain ≥2 distinct cold keys");
    assert_eq!(
        kes::verify_opcert(&other.cold_vkey, good),
        Err(KesError::OpCertInvalidSignature),
    );
}

/// Sextant's accept/reject verdict agrees, on the same (cold key, signable,
/// signature), with pallas-crypto's Ed25519 — which runs on cryptoxide, an
/// independent pure-Rust backend, not the curve25519-dalek fork Sextant's own
/// path uses. This is the DoD's "byte-identical verdicts to pallas".
#[test]
fn opcert_verdict_matches_independent_oracle() {
    for c in opcert_cases() {
        let oc = &c.view.opcert;
        let msg = kes::opcert_signable(oc);
        let pk = PublicKey::from(c.cold_vkey);

        // Sextant's own Ed25519 path and pallas (cryptoxide) agree on genuine.
        let sextant = sextant::ed25519::verify(&c.cold_vkey, &msg, &oc.sigma);
        let oracle = pk.verify(msg, &Signature::from(oc.sigma));
        assert_eq!(sextant, oracle, "slot {}: genuine verdict ≠ oracle", c.slot);
        assert!(sextant, "slot {}: genuine opcert must be accepted", c.slot);

        // A one-bit flip in the signature: both implementations must reject.
        let mut bad = oc.sigma;
        bad[0] ^= 0x01;
        let sextant_bad = sextant::ed25519::verify(&c.cold_vkey, &msg, &bad);
        let oracle_bad = pk.verify(msg, &Signature::from(bad));
        assert_eq!(
            sextant_bad, oracle_bad,
            "slot {}: tampered verdict ≠ oracle",
            c.slot
        );
        assert!(
            !sextant_bad,
            "slot {}: tampered signature must be rejected",
            c.slot
        );
    }
}

/// The Ed25519 group order L, little-endian.
const GROUP_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Little-endian 32-byte addition (no final carry-out for the values used here).
fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    out
}

/// A malleated response scalar `S' = S + L` reduces to the same scalar and so
/// satisfies the verification equation arithmetically, but Sextant rejects it —
/// matching libsodium's canonical-`S` requirement and closing the malleability
/// a plain `from_bytes_mod_order` would admit. Checked directly on the opcert
/// path (oracle-independent).
#[test]
fn opcert_rejects_non_canonical_scalar() {
    let cases = opcert_cases();
    let c = &cases[0];
    let good = &c.view.opcert;
    assert!(kes::verify_opcert(&c.cold_vkey, good).is_ok());

    let mut s = [0u8; 32];
    s.copy_from_slice(&good.sigma[32..64]);
    let s_plus_l = add_le(&s, &GROUP_ORDER_LE); // S + L ≥ L, non-canonical

    let mut tampered = good.clone();
    tampered.sigma[32..64].copy_from_slice(&s_plus_l);
    assert_eq!(
        kes::verify_opcert(&c.cold_vkey, &tampered),
        Err(KesError::OpCertInvalidSignature),
    );
}
