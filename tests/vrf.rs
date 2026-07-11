//! Leader-VRF output verification, differentially checked against the chain
//! itself. Every Praos header commits a 64-byte VRF output (beta) that its
//! producer computed with libsodium's `crypto_vrf_ietfdraft03`. Sextant
//! recomputes beta from the 80-byte proof on its own code path
//! (`vrf::proof_to_hash`) and it must equal the committed `vrf_output`
//! byte-for-byte — so the oracle is the canonical producer (cardano-node),
//! not pallas (whose 1.1.1 crate ships no VRF).
//!
//! `proof_to_hash` is nonce-independent, so this covers every real vector with
//! no epoch nonce. Binding the proof to the header's slot + epoch nonce (the
//! full leader-eligibility verify) is the next slice.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use sextant::header::HeaderView;
use sextant::vrf::{self, VrfError};

const CONWAY1: &str = include_str!("vectors/mainnet-conway1.block"); // era 7

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
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
        Err(VrfError::InvalidGamma) => {}
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
