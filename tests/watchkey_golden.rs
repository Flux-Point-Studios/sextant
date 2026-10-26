//! The 21 hand-labelled U1 watched-key vectors replayed through the nine surface
//! scans and the consumed-input scan. The oracle is r57-live's
//! `scripts/u1_watched_key_vectors.json`, git blob a32cf41a; its CRLF Windows
//! working copy hashes to d0c1ea33. Only `target_found`, `complete` and `verdict`
//! are contract. No production aggregate exists yet, so the envelope split, the
//! surface union and the verdict rule below stand in for it.

use minicbor::Decoder;
use serde_json::Value;
use sextant::utxo::OutPoint;
use sextant::watchkey::{
    Scan, certificate_use, input_use, native_script_use, output_use, proposal_use,
    required_signer_use, update_use, voting_use, withdrawal_use, witness_use,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const ORACLE: &str = include_str!("vectors/u1_watched_key_vectors.json");

const GAP: Scan = Scan {
    found: false,
    complete: false,
};

fn vectors() -> Vec<Value> {
    let oracle: Value = serde_json::from_str(ORACLE).expect("oracle is JSON");
    oracle["vectors"]
        .as_array()
        .expect("oracle vectors")
        .clone()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("valid hex")
}

/// Body span, witness-set span and validity flag of a Conway
/// `[body, witness_set, is_valid, auxiliary_data]`; `None` when it does not decode.
fn envelope(tx: &[u8]) -> Option<(&[u8], &[u8], bool)> {
    let mut d = Decoder::new(tx);
    if d.array().ok()? != Some(4) {
        return None;
    }
    let body = d.position();
    d.skip().ok()?;
    let witnesses = d.position();
    d.skip().ok()?;
    let end = d.position();
    let is_valid = d.bool().ok()?;
    d.skip().ok()?;
    if d.position() != tx.len() {
        return None;
    }
    Some((&tx[body..witnesses], &tx[witnesses..end], is_valid))
}

fn resolutions(vector: &Value) -> BTreeMap<OutPoint, Vec<u8>> {
    vector["resolve"]
        .as_object()
        .expect("resolve map")
        .iter()
        .map(|(reference, address)| {
            let (tx_id, index) = reference.split_once('#').expect("txid#index");
            let outpoint = OutPoint {
                tx_id: hex::decode(tx_id)
                    .expect("hex txid")
                    .try_into()
                    .expect("32-byte txid"),
                index: index.parse().expect("u16 index"),
            };
            (outpoint, hex_bytes(address))
        })
        .collect()
}

fn expected(vector: &Value, side: &str) -> Scan {
    Scan {
        found: vector["expected"][side]["target_found"]
            .as_bool()
            .expect("target_found"),
        complete: vector["expected"][side]["complete"]
            .as_bool()
            .expect("complete"),
    }
}

fn union(scans: &[Scan]) -> Scan {
    Scan {
        found: scans.iter().any(|scan| scan.found),
        complete: scans.iter().all(|scan| scan.complete),
    }
}

/// A proven use outranks any gap; with no use, any gap refuses a clean NO_USE.
fn verdict(surfaces: Scan, inputs: Scan) -> &'static str {
    if surfaces.found || inputs.found {
        "USE_FOUND"
    } else if surfaces.complete && inputs.complete {
        "NO_USE"
    } else {
        "INCOMPLETE"
    }
}

fn check(name: &str) {
    let vector = vectors()
        .into_iter()
        .find(|vector| vector["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("no oracle vector {name}"));
    let tx = hex_bytes(&vector["raw_tx_hex"]);
    let target: [u8; 28] = hex_bytes(&vector["target_vkh"])
        .try_into()
        .expect("28-byte target");
    let watched = BTreeSet::from([target]);
    let resolved = resolutions(&vector);
    let (surfaces, inputs) = match envelope(&tx) {
        Some((body, witnesses, is_valid)) => (
            union(&[
                required_signer_use(body, &watched),
                output_use(body, &watched),
                withdrawal_use(body, &watched),
                voting_use(body, &watched),
                proposal_use(body, &watched),
                certificate_use(body, &watched),
                update_use(body, &watched),
                witness_use(witnesses, &watched),
                native_script_use(witnesses, &watched),
            ]),
            input_use(body, is_valid, &watched, |input| {
                Ok(resolved.get(input).map(Vec::as_slice))
            }),
        ),
        // An envelope that does not decode proves nothing on either side.
        None => (GAP, GAP),
    };
    assert_eq!(
        surfaces,
        expected(&vector, "use_surfaces"),
        "{name}: use_surfaces"
    );
    assert_eq!(
        inputs,
        expected(&vector, "resolved_input"),
        "{name}: resolved_input"
    );
    assert_eq!(
        Some(verdict(surfaces, inputs)),
        vector["expected"]["verdict"].as_str(),
        "{name}: verdict"
    );
}

macro_rules! golden {
    ($($name:ident),* $(,)?) => {
        const COVERED: &[&str] = &[$(stringify!($name)),*];
        $(
            #[test]
            fn $name() {
                check(stringify!($name));
            }
        )*
    };
}

golden!(
    supported_era_no_use,
    output_payment,
    output_stake,
    required_signer_array,
    required_signer_tagged_set,
    vkey_witness_c_control,
    withdrawal,
    pool_owner_tagged_set,
    pool_reward_account,
    native_script_sig,
    native_script_deep70,
    reference_script_native,
    collateral_return_refscript,
    proposal_reward_array,
    proposal_reward_tagged_set,
    spent_input_payment,
    phase2_collateral_input,
    unsupported_era_body_key,
    unknown_cert_kind,
    undecodable,
    unresolved_spent_input,
);

#[test]
fn oracle_is_the_pinned_hand_labelled_file() {
    assert_eq!(
        hex::encode(Sha256::digest(ORACLE.as_bytes())),
        "3b4bc95ec13a600a5dde8c552c4600bf5d67634894a9abde709929e9ee5eee39"
    );
}

#[test]
fn every_oracle_vector_has_a_golden_test() {
    let vectors = vectors();
    let names: Vec<&str> = vectors
        .iter()
        .map(|vector| vector["name"].as_str().expect("vector name"))
        .collect();
    assert_eq!(names, COVERED);
}
