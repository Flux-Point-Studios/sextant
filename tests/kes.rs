//! KES body-signature verification, differentially checked against the chain
//! itself. Every Praos header is `[header_body, body_signature]`, where
//! `body_signature` is a `Sum6Kes` signature over the raw CBOR bytes of
//! `header_body`, produced by the ephemeral hot KES key whose root verification
//! key is the operational certificate's `hot_vkey`. The signing period is
//! `slot / 129600 − opcert.kes_period` (the KES evolution offset from when the
//! cert was issued).
//!
//! cardano-node minted and accepted these blocks, so a genuine body signature
//! must verify on Sextant's own recursive KES path (Blake2b256 vk tree over
//! Ed25519 leaves), and any tampering — of the signature, the message, the
//! period, or the root key — must be rejected. Together with the operational
//! certificate (cold→hot delegation), this closes DoD line 2's KES half: the
//! block body was signed by the hot key the pool's cold key authorized.

use std::fs;
use std::path::PathBuf;

use pallas_crypto::kes::common::PublicKey;
use pallas_crypto::kes::summed_kes::Sum6KesSig;
use pallas_crypto::kes::traits::KesSig;
use sextant::header::HeaderView;
use sextant::kes::{self, KesError};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// A real preprod header and the KES evolution period its body signature
/// commits to.
struct KesCase {
    slot: u64,
    period: u32,
    view: HeaderView,
}

/// Every preprod vector, decoded into a KES case, sorted by slot for a
/// deterministic anchor (`fs::read_dir` order is platform-dependent). Preprod
/// blocks are freshly harvested off a live relay, so their slot obeys the
/// Shelley `slotsPerKESPeriod` rule and `verify_header_kes` derives the true
/// signing period — unlike pallas's synthetic mainnet decode-fixtures, whose
/// hand-set slots do not.
fn kes_cases() -> Vec<KesCase> {
    kes_cases_with_prefix("preprod-")
}

/// Every freshly-harvested vector for `prefix`, marked by its `.eta0` sidecar —
/// which excludes the synthetic mainnet decode-fixtures whose hand-set slots do
/// not obey the Shelley `slotsPerKESPeriod` rule — decoded into a KES case, sorted
/// by slot. The eta0 value is unused here; its presence certifies a real block
/// harvested off a live relay, so `verify_header_kes` derives the true period.
fn kes_cases_with_prefix(prefix: &str) -> Vec<KesCase> {
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
        let period = (view.slot / kes::SLOTS_PER_KES_PERIOD - view.opcert.kes_period) as u32;
        cases.push(KesCase {
            slot: view.slot,
            period,
            view,
        });
    }
    cases.sort_by_key(|c| c.slot);
    cases
}

/// The core slice: every real preprod header's KES body signature verifies on
/// Sextant's own recursive `Sum6Kes` path, at the period derived from the slot
/// and the operational certificate. This is cardano-node ground truth — the
/// network accepted these blocks, so the hot KES key genuinely signed each
/// header body.
#[test]
fn real_preprod_kes_body_sigs_verify() {
    let cases = kes_cases();
    assert!(
        cases.len() >= 20,
        "DoD requires ≥20 KES-verify vectors, found {}",
        cases.len(),
    );
    for c in &cases {
        kes::verify_header_kes(&c.view).unwrap_or_else(|e| {
            panic!(
                "slot {} (period {}) rejected a genuine KES body signature: {e:?}",
                c.slot, c.period
            )
        });
    }
}

/// The "from mainnet" half of DoD line 2 (KES): every freshly-harvested mainnet
/// header's body signature verifies on Sextant's own recursive `Sum6Kes` path at
/// the slot-derived period (cardano-node ground truth), and the independent
/// `pallas` `Sum6Kes` oracle accepts the same signature on the same message.
#[test]
fn real_mainnet_kes_body_sigs_verify() {
    let cases = kes_cases_with_prefix("mainnet-");
    assert!(
        cases.len() >= 20,
        "DoD line 2 requires ≥20 mainnet KES-verify vectors, found {}",
        cases.len(),
    );
    for c in &cases {
        kes::verify_header_kes(&c.view).unwrap_or_else(|e| {
            panic!(
                "mainnet slot {} (period {}) rejected a genuine KES body signature: {e:?}",
                c.slot, c.period
            )
        });
        let pk = PublicKey::from_bytes(&c.view.opcert.hot_vkey).expect("valid KES root key");
        let osig =
            Sum6KesSig::from_bytes(&c.view.body_signature).expect("valid Sum6 KES signature");
        assert!(
            osig.verify(c.period, &pk, &c.view.header_body).is_ok(),
            "mainnet slot {}: independent oracle rejected a genuine signature",
            c.slot,
        );
    }
}

/// The body signature is bound to the root hot KES key, the header-body message,
/// the evolution period, and every byte of the 448-byte signature. Perturbing
/// any of them breaks verification; a signature valid at one period must not
/// verify at another.
#[test]
fn tampered_kes_body_sig_is_rejected() {
    let cases = kes_cases();
    let c = &cases[0];
    let root = c.view.opcert.hot_vkey;
    let msg = &c.view.header_body;
    let sig = &c.view.body_signature;
    let period = c.period;

    assert!(kes::verify_kes(&root, period, msg, sig).is_ok());

    // A one-bit flip anywhere in the signature: the top Ed25519 leaf or a vk
    // hash-tree node no longer matches, so verification fails.
    let bad_sig = {
        let mut s = *sig;
        s[0] ^= 0x01;
        s
    };
    assert_eq!(
        kes::verify_kes(&root, period, msg, &bad_sig),
        Err(KesError::KesInvalidSignature),
    );

    // A flipped byte in the last vk-tree node (`vk_1`, the final 32 bytes)
    // breaks the Blake2b256 root-hash check, not the Ed25519 leaf.
    let bad_vk = {
        let mut s = *sig;
        s[447] ^= 0x01;
        s
    };
    assert_eq!(
        kes::verify_kes(&root, period, msg, &bad_vk),
        Err(KesError::KesInvalidSignature),
    );

    // A different root hot key cannot claim this signature.
    let bad_root = {
        let mut r = root;
        r[0] ^= 0x01;
        r
    };
    assert_eq!(
        kes::verify_kes(&bad_root, period, msg, sig),
        Err(KesError::KesInvalidSignature),
    );

    // Tampering with the signed message (the header body) breaks the leaf.
    let bad_msg = {
        let mut m = msg.clone();
        m[0] ^= 0x01;
        m
    };
    assert_eq!(
        kes::verify_kes(&root, period, &bad_msg, sig),
        Err(KesError::KesInvalidSignature),
    );

    // A signature valid at its own period must not verify at a different one:
    // the recursion walks a different subtree.
    let other_period = if period == 0 { 1 } else { period - 1 };
    assert_eq!(
        kes::verify_kes(&root, other_period, msg, sig),
        Err(KesError::KesInvalidSignature),
    );
}

/// A period past the Sum6 tree's 64 evolutions, and a header whose slot precedes
/// its own operational certificate's issue period (an underflow), are both
/// rejected as out-of-range rather than silently walking the wrong subtree.
#[test]
fn kes_period_out_of_range_is_rejected() {
    let cases = kes_cases();
    let c = &cases[0];
    let root = c.view.opcert.hot_vkey;
    let msg = &c.view.header_body;
    let sig = &c.view.body_signature;

    assert_eq!(
        kes::verify_kes(&root, 64, msg, sig),
        Err(KesError::KesPeriodOutOfRange),
    );
    assert_eq!(
        kes::verify_kes(&root, u32::MAX, msg, sig),
        Err(KesError::KesPeriodOutOfRange),
    );

    // A header whose opcert claims a KES period after the header's own slot
    // would underflow the evolution offset; `verify_header_kes` fails closed.
    let mut bad = c.view.clone();
    bad.opcert.kes_period = bad.slot / kes::SLOTS_PER_KES_PERIOD + 1;
    assert_eq!(
        kes::verify_header_kes(&bad),
        Err(KesError::KesPeriodOutOfRange),
    );
}

/// Sextant's accept/reject verdict agrees, on the same (root key, period,
/// message, signature), with pallas-crypto's `Sum6Kes` verifier — an
/// independent implementation. This is the DoD's "byte-identical verdicts to
/// pallas" for the KES half.
#[test]
fn kes_verdict_matches_independent_oracle() {
    for c in kes_cases() {
        let root = c.view.opcert.hot_vkey;
        let msg = &c.view.header_body;
        let sig = &c.view.body_signature;
        let period = c.period;

        let pk = PublicKey::from_bytes(&root).expect("valid KES root key");
        let osig = Sum6KesSig::from_bytes(sig).expect("valid Sum6 KES signature");

        // Genuine: both accept.
        let sextant = kes::verify_kes(&root, period, msg, sig).is_ok();
        let oracle = osig.verify(period, &pk, msg).is_ok();
        assert_eq!(sextant, oracle, "slot {}: genuine verdict ≠ oracle", c.slot);
        assert!(sextant, "slot {}: genuine KES sig must be accepted", c.slot);

        // Tampered signature: both reject.
        let mut bad = *sig;
        bad[0] ^= 0x01;
        let sextant_bad = kes::verify_kes(&root, period, msg, &bad).is_ok();
        let obad = Sum6KesSig::from_bytes(&bad).expect("still 448 bytes");
        let oracle_bad = obad.verify(period, &pk, msg).is_ok();
        assert_eq!(
            sextant_bad, oracle_bad,
            "slot {}: tampered verdict ≠ oracle",
            c.slot
        );
        assert!(
            !sextant_bad,
            "slot {}: tampered KES sig must be rejected",
            c.slot
        );
    }
}
