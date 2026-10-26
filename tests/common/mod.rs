//! Replays a hand-labelled U1 oracle through `transaction_use`. The oracles store
//! standalone `[body, witness_set, is_valid, auxiliary_data]` transactions, so
//! each is split into the spans a block carries. Only `target_found`, `complete`
//! and `verdict` are contract.

use minicbor::Decoder;
use serde_json::Value;
use sextant::utxo::{OutPoint, item_end};
use sextant::watchkey::{Scan, Verdict, transaction_use};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn sha256_hex(oracle: &str) -> String {
    hex::encode(Sha256::digest(oracle.as_bytes()))
}

pub fn names(oracle: &str) -> Vec<String> {
    vectors(oracle)
        .iter()
        .map(|vector| vector["name"].as_str().expect("vector name").to_owned())
        .collect()
}

fn vectors(oracle: &str) -> Vec<Value> {
    let oracle: Value = serde_json::from_str(oracle).expect("oracle is JSON");
    oracle["vectors"]
        .as_array()
        .expect("oracle vectors")
        .clone()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("valid hex")
}

/// Body span, witness-set span and validity flag of an Alonzo-onward
/// `[body, witness_set, is_valid, auxiliary_data]`, or of a Shelley-to-Mary
/// `[body, witness_set, auxiliary_data]`, valid by construction. The auxiliary data
/// must be one well-formed item ending the input, as the reference frames it; the body
/// and the witness set are delimited here, and `transaction_use` judges them. `None`
/// for any other framing.
fn envelope(tx: &[u8]) -> Option<(&[u8], &[u8], bool)> {
    let mut d = Decoder::new(tx);
    let count = d.array().ok()??;
    if count != 3 && count != 4 {
        return None;
    }
    let body = d.position();
    d.skip().ok()?;
    let witnesses = d.position();
    d.skip().ok()?;
    let end = d.position();
    let is_valid = count == 3 || d.bool().ok()?;
    (item_end(tx, d.position()) == Some(tx.len())).then_some((
        &tx[body..witnesses],
        &tx[witnesses..end],
        is_valid,
    ))
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

pub fn check(oracle: &str, name: &str) {
    let vector = vectors(oracle)
        .into_iter()
        .find(|vector| vector["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("no oracle vector {name}"));
    let tx = hex_bytes(&vector["raw_tx_hex"]);
    let target: [u8; 28] = hex_bytes(&vector["target_vkh"])
        .try_into()
        .expect("28-byte target");
    let watched = BTreeSet::from([target]);
    let resolved = resolutions(&vector);
    // A transaction that does not split reaches the scan whole, which must refuse it.
    let (body, witnesses, is_valid) = envelope(&tx).unwrap_or((tx.as_slice(), tx.as_slice(), true));
    let scan = transaction_use(body, witnesses, is_valid, &watched, |input| {
        Ok(resolved.get(input).map(Vec::as_slice))
    });
    assert_eq!(
        scan.surfaces,
        expected(&vector, "use_surfaces"),
        "{name}: use_surfaces"
    );
    assert_eq!(
        scan.inputs,
        expected(&vector, "resolved_input"),
        "{name}: resolved_input"
    );
    let verdict = match scan.verdict() {
        Verdict::NoUse => "NO_USE",
        Verdict::UseFound => "USE_FOUND",
        Verdict::Incomplete => "INCOMPLETE",
    };
    assert_eq!(
        Some(verdict),
        vector["expected"]["verdict"].as_str(),
        "{name}: verdict"
    );
}

/// One test per named vector of `$oracle`, a test pinning the oracle's bytes, and
/// a test that the names cover every vector the oracle holds, in order.
macro_rules! oracle_tests {
    ($oracle:expr, $sha256:expr; $($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                common::check($oracle, stringify!($name));
            }
        )*

        #[test]
        fn oracle_is_the_pinned_hand_labelled_file() {
            assert_eq!(common::sha256_hex($oracle), $sha256);
        }

        #[test]
        fn every_oracle_vector_has_a_test() {
            assert_eq!(common::names($oracle), [$(stringify!($name)),*]);
        }
    };
}
