//! Leader-VRF verification, differentially checked against the chain itself.
//! Every Praos header commits a 64-byte VRF output (beta) and an 80-byte proof
//! that its producer computed with libsodium's `crypto_vrf_ietfdraft03`.
//!
//! Two independent checks run on Sextant's own code path:
//!
//! * `vrf::proof_to_hash` recomputes beta from the proof; it must equal the
//!   committed `vrf_output` byte-for-byte. Nonce-independent, so it covers
//!   every real vector with no epoch nonce.
//! * `vrf::verify_praos_leader` runs the full draft-03 equation, binding the
//!   proof to the header's public key and `alpha = Blake2b256(BE64(slot)||eta0)`.
//!   The 22 preprod vectors carry a `.eta0` sidecar (the epoch's active nonce,
//!   from Koios), so a genuine leader proof must verify and a proof bound to a
//!   different slot, nonce, or key must be rejected.
//!
//! pallas 1.1.1 ships no VRF, so the oracle is the canonical producer
//! (cardano-node) that minted these blocks, cross-checked against
//! `cardano-crypto` — an independent, non-dalek pure-Rust reimplementation.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use cardano_crypto::vrf::VrfDraft03;
use sextant::header::HeaderView;
use sextant::vrf::{self, VrfError};

const CONWAY1: &str = include_str!("vectors/mainnet-conway1.block"); // era 7

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// A real preprod leader proof and the epoch nonce it was cast under.
struct LeaderCase {
    slot: u64,
    vkey: [u8; 32],
    eta0: [u8; 32],
    proof: [u8; 80],
    output: [u8; 64],
}

/// Every preprod vector that has an `.eta0` sidecar, decoded into a leader case.
fn leader_cases() -> Vec<LeaderCase> {
    let mut cases = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with("preprod-")
            || path.extension().and_then(|e| e.to_str()) != Some("block")
        {
            continue;
        }
        let eta0_path = path.with_extension("eta0");
        let Ok(eta0_hex) = fs::read_to_string(&eta0_path) else {
            continue;
        };
        let view =
            HeaderView::from_block_cbor(&unhex(&fs::read_to_string(&path).expect("read vector")))
                .unwrap_or_else(|e| panic!("decode {}: {e:?}", path.display()));
        let eta0: [u8; 32] = unhex(&eta0_hex).try_into().expect("eta0 is 32 bytes");
        cases.push(LeaderCase {
            slot: view.slot,
            vkey: view.vrf_vkey,
            eta0,
            proof: view.vrf_proof,
            output: view.vrf_output,
        });
    }
    cases
}

/// The header decoder surfaces the VRF fields at the exact bytes carried in a
/// real Conway header (index 4 = vrf_vkey, index 5 = [output(64), proof(80)]).
#[test]
fn decodes_conway_vrf_fields() {
    let view = HeaderView::from_block_cbor(&unhex(CONWAY1)).expect("decode header");
    assert_eq!(
        hex::encode(view.vrf_vkey),
        "15587d5633be324f8de97168399ab59d7113f0a74bc7412b81f7cc1007491671",
    );
    assert_eq!(
        hex::encode(view.vrf_output),
        "af9ff8cb146880eba1b12beb72d86be46fbc98f6b88110cd009bd6746d255a14\
         bb0637e3a29b7204bff28236c1b9f73e501fed1eb5634bd741be120332d25e5e",
    );
    assert_eq!(view.vrf_proof.len(), 80);
}

/// Anchor: Sextant's `proof_to_hash` reproduces the exact 64-byte output the
/// Conway block producer committed on-chain.
#[test]
fn proof_to_hash_matches_onchain_output_conway1() {
    let view = HeaderView::from_block_cbor(&unhex(CONWAY1)).expect("decode header");
    let beta = vrf::proof_to_hash(&view.vrf_proof).expect("valid Gamma");
    assert_eq!(beta, view.vrf_output);
}

/// Every real vector: Sextant's independently-computed VRF output equals the
/// committed one. This is the differential check against the canonical
/// producer, at the DoD's ≥20-vector floor over distinct blocks.
#[test]
fn every_vector_output_equals_proof_to_hash() {
    let mut distinct: HashSet<Vec<u8>> = HashSet::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("block") {
            continue;
        }
        let bytes = unhex(&fs::read_to_string(&path).expect("read vector"));
        let view = HeaderView::from_block_cbor(&bytes)
            .unwrap_or_else(|e| panic!("decode {}: {e:?}", path.display()));
        let beta = vrf::proof_to_hash(&view.vrf_proof)
            .unwrap_or_else(|e| panic!("proof_to_hash {}: {e:?}", path.display()));
        assert_eq!(
            beta,
            view.vrf_output,
            "VRF output mismatch vs on-chain in {}",
            path.display(),
        );
        distinct.insert(bytes);
    }
    assert!(
        distinct.len() >= 20,
        "DoD requires ≥20 distinct verified vectors, found {}",
        distinct.len(),
    );
}

/// A tampered proof must not reproduce the committed output: perturbing Gamma
/// either yields a different beta or leaves the curve entirely.
#[test]
fn tampered_gamma_breaks_output() {
    let view = HeaderView::from_block_cbor(&unhex(CONWAY1)).expect("decode header");
    let mut proof = view.vrf_proof;
    proof[0] ^= 0x01; // perturb the low byte of Gamma
    match vrf::proof_to_hash(&proof) {
        Ok(beta) => assert_ne!(beta, view.vrf_output),
        Err(e) => assert_eq!(e, VrfError::InvalidGamma),
    }
}

/// An off-curve Gamma is rejected, not silently mapped to some output — proving
/// the `InvalidGamma` path is live. Some high-byte value of the y-encoding has
/// no matching x, so search a few until decompression fails.
#[test]
fn off_curve_gamma_is_rejected() {
    let view = HeaderView::from_block_cbor(&unhex(CONWAY1)).expect("decode header");
    let rejected = (0u8..=255).any(|b| {
        let mut proof = view.vrf_proof;
        proof[31] = b; // top byte of Gamma's compressed y
        matches!(vrf::proof_to_hash(&proof), Err(VrfError::InvalidGamma))
    });
    assert!(
        rejected,
        "expected some off-curve Gamma encoding to be rejected"
    );
}

/// The core slice: every real preprod leader proof verifies on Sextant's own
/// draft-03 code path — binding public key + `Blake2b256(BE64(slot)||eta0)` —
/// and yields exactly the output the producer committed. This is cardano-node
/// ground truth: these blocks were minted and accepted by the live network.
#[test]
fn real_preprod_leader_proofs_verify() {
    let cases = leader_cases();
    assert!(
        cases.len() >= 20,
        "DoD requires ≥20 leader-verify vectors, found {}",
        cases.len(),
    );
    for c in &cases {
        let out = vrf::verify_praos_leader(&c.vkey, c.slot, &c.eta0, &c.proof)
            .unwrap_or_else(|e| panic!("slot {} rejected a genuine leader proof: {e:?}", c.slot));
        assert_eq!(
            out, c.output,
            "slot {}: verified output ≠ committed",
            c.slot
        );
    }
}

/// Sextant's accept/reject verdict and certified output agree, on the same
/// inputs, with an independent non-dalek reimplementation (`cardano-crypto`).
#[test]
fn verdict_matches_independent_oracle() {
    for c in leader_cases() {
        let alpha = vrf::praos_vrf_input(c.slot, &c.eta0);
        let sextant = vrf::verify(&c.vkey, &alpha, &c.proof);
        let oracle = VrfDraft03::verify(&c.vkey, &c.proof, &alpha);
        assert_eq!(
            sextant.is_ok(),
            oracle.is_ok(),
            "slot {}: verdict disagrees with oracle",
            c.slot,
        );
        if let (Ok(a), Ok(b)) = (&sextant, &oracle) {
            assert_eq!(a, b, "slot {}: output disagrees with oracle", c.slot);
        }
    }
}

/// A leader proof is bound to its inputs: perturbing the response scalar, the
/// epoch nonce, the slot, or the public key each breaks verification. Sextant
/// and the independent oracle both reject the tampered proof.
#[test]
fn tampered_leader_proof_is_rejected() {
    let c = &leader_cases()[0];
    let alpha = vrf::praos_vrf_input(c.slot, &c.eta0);

    let mut proof = c.proof;
    proof[60] ^= 0x01; // perturb the response scalar s
    assert_eq!(
        vrf::verify(&c.vkey, &alpha, &proof),
        Err(VrfError::VerificationFailed),
    );
    assert!(VrfDraft03::verify(&c.vkey, &proof, &alpha).is_err());

    // Wrong epoch nonce → different alpha → rejected.
    let mut eta0 = c.eta0;
    eta0[0] ^= 0x01;
    assert!(vrf::verify_praos_leader(&c.vkey, c.slot, &eta0, &c.proof).is_err());

    // Wrong slot → different alpha → rejected.
    assert!(vrf::verify_praos_leader(&c.vkey, c.slot ^ 1, &c.eta0, &c.proof).is_err());

    // Another block's public key cannot claim this proof.
    let other = &leader_cases()[1];
    assert!(other.vkey != c.vkey);
    assert!(vrf::verify(&other.vkey, &alpha, &c.proof).is_err());
}
