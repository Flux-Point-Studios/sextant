//! Skeptic replay of cbor2-built vectors (scratch only).
use serde_json::Value;
use sextant::utxo::OutPoint;
use sextant::watchkey::{Verdict, transaction_use};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn skeptic_replay() {
    let path = std::env::var("SKEPTIC_VECTORS").expect("SKEPTIC_VECTORS");
    let vectors: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut mismatches = 0;
    for v in &vectors {
        let body = hex::decode(v["body"].as_str().unwrap()).unwrap();
        let wits = hex::decode(v["wits"].as_str().unwrap()).unwrap();
        let watched: [u8; 28] = hex::decode(v["watched"].as_str().unwrap()).unwrap().try_into().unwrap();
        let resolved: BTreeMap<OutPoint, Vec<u8>> = v["resolve"].as_object().unwrap().iter().map(|(k, a)| {
            let (id, ix) = k.split_once('#').unwrap();
            (OutPoint { tx_id: hex::decode(id).unwrap().try_into().unwrap(), index: ix.parse().unwrap() },
             hex::decode(a.as_str().unwrap()).unwrap())
        }).collect();
        let scan = transaction_use(&body, &wits, v["valid"].as_bool().unwrap(), &BTreeSet::from([watched]), |i| {
            Ok(resolved.get(i).map(Vec::as_slice))
        });
        let got = match scan.verdict() { Verdict::NoUse => "NoUse", Verdict::UseFound => "UseFound", Verdict::Incomplete => "Incomplete" };
        let ok = got == v["expect"].as_str().unwrap();
        if !ok { mismatches += 1; }
        println!("{:4} {:45} expect={:10} got={:10} surfaces={:?} inputs={:?}", if ok { "OK" } else { "DIFF" },
                 v["name"].as_str().unwrap(), v["expect"].as_str().unwrap(), got, scan.surfaces, scan.inputs);
    }
    assert_eq!(mismatches, 0);
}
