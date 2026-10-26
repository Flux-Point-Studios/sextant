//! Red-team PoCs against the U1 watched-key predicate (scratch only).
//! An `exploit_*` test PASSES when the vulnerable behaviour is observed.
//! A `defended_*` test PASSES when the attack reaches the boundary and is refused.

mod rt_common;
use pallas_primitives::StakeCredential;
use pallas_primitives::conway::{GovAction, TransactionOutput, Value};
use rt_common::*;
use sextant::utxo::OutPoint;
use sextant::watchkey::{Scan, Verdict, output_use};
use std::collections::{BTreeMap, BTreeSet};

fn proposal(gov_action: Vec<u8>, deposit_return: &[u8]) -> Vec<u8> {
    arr(&[uint(100_000_000_000), bytes(deposit_return), gov_action, anchor()])
}
fn body_with_proposal(gov_action: Vec<u8>) -> Vec<u8> {
    encode_map(&with(base_body(), 20, set(&[proposal(gov_action, &reward_key(&OTHER))])))
}
fn wits() -> Vec<u8> {
    encode_map(&base_wits())
}
fn unit_interval() -> Vec<u8> {
    tag(30, arr(&[uint(2), uint(3)]))
}
fn cold(cred: &[u8; 28]) -> Vec<u8> {
    arr(&[uint(0), bytes(cred)])
}

// ---------------------------------------------------------------- baseline

#[test]
fn control_baseline_is_no_use_and_pallas_accepts() {
    let body = encode_map(&base_body());
    pallas_body(&body).expect("pallas decodes the base body");
    pallas_wits(&wits()).expect("pallas decodes the base witnesses");
    assert_eq!(verdict(&body, &wits(), &[W]), Verdict::NoUse);
}

// ------------------------------------------------- A: governance actions

#[test]
fn exploit_update_committee_added_member_reads_no_use() {
    let action = arr(&[uint(4), null(), set(&[]), map(&[(cold(&W), uint(500))]), unit_interval()]);
    let body = body_with_proposal(action);
    let decoded = pallas_body(&body).expect("pallas decodes the proposal");
    let gov = &decoded.proposal_procedures.as_ref().unwrap()[0].gov_action;
    match gov {
        GovAction::UpdateCommittee(_, _, add, _) => assert!(
            add.keys().any(|c| matches!(c, StakeCredential::AddrKeyhash(h) if h.as_ref() == W)),
            "pallas sees W as a typed committee_cold_credential"
        ),
        other => panic!("unexpected gov action {other:?}"),
    }
    assert_eq!(verdict(&body, &wits(), &[W]), Verdict::NoUse, "FALSE NO_USE");

    // Controls: the same credential in the deposit-return slot, and as a cold
    // credential inside a certificate, are both found.
    let control = encode_map(&with(
        base_body(),
        20,
        set(&[proposal(arr(&[uint(6)]), &reward_key(&W))]),
    ));
    pallas_body(&control).expect("control decodes");
    assert_eq!(verdict(&control, &wits(), &[W]), Verdict::UseFound);
    let cert = encode_map(&with(base_body(), 4, set(&[arr(&[uint(14), cold(&W), cold(&OTHER)])])));
    pallas_body(&cert).expect("cert control decodes");
    assert_eq!(verdict(&cert, &wits(), &[W]), Verdict::UseFound);
}

#[test]
fn exploit_update_committee_removed_member_reads_no_use() {
    let action = arr(&[uint(4), null(), set(&[cold(&W)]), map(&[]), unit_interval()]);
    let body = body_with_proposal(action);
    let decoded = pallas_body(&body).expect("pallas decodes");
    match &decoded.proposal_procedures.as_ref().unwrap()[0].gov_action {
        GovAction::UpdateCommittee(_, remove, _, _) => assert!(
            remove.iter().any(|c| matches!(c, StakeCredential::AddrKeyhash(h) if h.as_ref() == W))
        ),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(verdict(&body, &wits(), &[W]), Verdict::NoUse, "FALSE NO_USE");
}

#[test]
fn exploit_treasury_withdrawal_reward_account_reads_no_use() {
    let action = arr(&[uint(2), map(&[(bytes(&reward_key(&W)), uint(1_000_000))]), null()]);
    let body = body_with_proposal(action);
    let decoded = pallas_body(&body).expect("pallas decodes");
    match &decoded.proposal_procedures.as_ref().unwrap()[0].gov_action {
        GovAction::TreasuryWithdrawals(accounts, _) => {
            assert!(accounts.keys().any(|a| Vec::<u8>::from(a.clone()) == reward_key(&W)))
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(verdict(&body, &wits(), &[W]), Verdict::NoUse, "FALSE NO_USE");
    // Control: the identical reward account as a body-5 withdrawal is found.
    let control = encode_map(&with(base_body(), 5, map(&[(bytes(&reward_key(&W)), uint(0))])));
    assert_eq!(verdict(&control, &wits(), &[W]), Verdict::UseFound);
}

#[test]
fn exploit_guardrail_script_hash_reads_no_use() {
    let s: [u8; 28] = [0xa6; 28];
    let actions = [
        arr(&[uint(0), null(), map(&[(uint(0), uint(44))]), bytes(&s)]),
        arr(&[uint(2), map(&[(bytes(&reward_key(&OTHER)), uint(1))]), bytes(&s)]),
        arr(&[uint(5), null(), arr(&[anchor(), bytes(&s)])]),
    ];
    for action in actions {
        let body = body_with_proposal(action);
        pallas_body(&body).expect("pallas decodes");
        assert_eq!(verdict(&body, &wits(), &[s]), Verdict::NoUse, "FALSE NO_USE");
    }
    // Control: the script hash as a withdrawn script reward account is found.
    let control = encode_map(&with(base_body(), 5, map(&[(bytes(&reward_script(&s)), uint(0))])));
    assert_eq!(verdict(&control, &wits(), &[s]), Verdict::UseFound);
}

// ------------------------------------------------------------ B: minting

#[test]
fn exploit_mint_under_watched_native_policy_reads_no_use() {
    // Policy = hash of a native script the witness set itself carries.
    let script = sig_clause(&OTHER);
    let policy = blake224(&[vec![0x00], script.clone()].concat());
    let body = encode_map(&with(
        base_body(),
        9,
        map(&[(bytes(&policy), map(&[(bytes(b"tok"), uint(1))]))]),
    ));
    let witness = encode_map(&with(base_wits(), 1, set(&[script])));
    let decoded = pallas_body(&body).expect("pallas decodes the mint");
    assert!(decoded.mint.as_ref().unwrap().keys().any(|p| p.as_ref() == policy));
    pallas_wits(&witness).expect("pallas decodes the witness set");
    assert_eq!(verdict(&body, &witness, &[policy]), Verdict::NoUse, "FALSE NO_USE");

    // Control: spending from the same script's address is found.
    let script_addr = [vec![0x70], policy.to_vec()].concat();
    let resolved = BTreeMap::from([(OutPoint { tx_id: TXID, index: 0 }, script_addr)]);
    let scan = scan_with(&encode_map(&base_body()), &witness, true, &[policy], &resolved);
    assert_eq!(scan.verdict(), Verdict::UseFound);
}

#[test]
fn exploit_output_multiasset_policy_reads_no_use() {
    let s: [u8; 28] = [0xa6; 28];
    let value = arr(&[uint(2_000_000), map(&[(bytes(&s), map(&[(bytes(b"tok"), uint(1))]))])]);
    let body = encode_map(&[
        (0, set(&[outpoint(TXID, 0)])),
        (1, arr(&[map_output(&ent_addr(&OTHER), value)])),
        (2, uint(200_000)),
    ]);
    let decoded = pallas_body(&body).expect("pallas decodes");
    match &decoded.outputs[0] {
        TransactionOutput::PostAlonzo(o) => match &o.value {
            Value::Multiasset(_, assets) => assert!(assets.keys().any(|p| p.as_ref() == s)),
            other => panic!("unexpected value {other:?}"),
        },
        other => panic!("unexpected output {other:?}"),
    }
    assert_eq!(verdict(&body, &wits(), &[s]), Verdict::NoUse);
}

// ------------------------------------------- C: decoder-level differentials

#[test]
fn exploit_duplicate_output_address_key_hides_first_address() {
    let output = map(&[
        (uint(0), bytes(&ent_addr(&W))),
        (uint(0), bytes(&ent_addr(&OTHER))),
        (uint(1), uint(2_000_000)),
    ]);
    let body = encode_map(&[
        (0, set(&[outpoint(TXID, 0)])),
        (1, arr(&[output])),
        (2, uint(200_000)),
    ]);
    let pallas = pallas_body(&body).map(|b| match &b.outputs[0] {
        TransactionOutput::PostAlonzo(o) => hex::encode(Vec::<u8>::from(o.address.clone())),
        TransactionOutput::Legacy(o) => hex::encode(Vec::<u8>::from(o.address.clone())),
    });
    eprintln!("pallas view of duplicated-address output: {pallas:?}");
    assert_eq!(verdict(&body, &wits(), &[W]), Verdict::NoUse, "first address dropped");
    // Control: either single address alone is found / clean.
    let single = encode_map(&[
        (0, set(&[outpoint(TXID, 0)])),
        (1, arr(&[map_output(&ent_addr(&W), uint(1))])),
        (2, uint(200_000)),
    ]);
    assert_eq!(verdict(&single, &wits(), &[W]), Verdict::UseFound);
}

#[test]
fn exploit_malformed_cbor_reads_as_clean_no_use() {
    // fee slot holds a bare break: minicbor `skip` consumes 0xff as an item.
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("fee = break", encode_map(&with(base_body()[..2].to_vec(), 2, vec![0xff])), wits()),
        ("mint = [break]", encode_map(&with(base_body(), 9, vec![0x81, 0xff])), wits()),
        (
            "ttl = [_ {1: break}]",
            encode_map(&with(base_body(), 3, vec![0x9f, 0xa1, 0x01, 0xff])),
            wits(),
        ),
        ("trailing junk after body", [encode_map(&base_body()), vec![0xff, 0x00]].concat(), wits()),
        ("trailing junk after witnesses", encode_map(&base_body()), [wits(), vec![0xff]].concat()),
        (
            "witness key 5 (redeemers) = break",
            encode_map(&base_body()),
            encode_map(&with(base_wits(), 5, vec![0xff])),
        ),
    ];
    for (name, body, witness) in cases {
        let strict = pallas_body(&body).is_ok() && pallas_wits(&witness).is_ok();
        let v = verdict(&body, &witness, &[W]);
        eprintln!("{name}: pallas_accepts={strict} verdict={v:?}");
        assert_eq!(v, Verdict::NoUse, "{name}: malformed input reads NO_USE");
    }
}

#[test]
fn exploit_unknown_witness_key_is_not_incomplete() {
    let witness = encode_map(&with(base_wits(), 8, arr(&[sig_clause(&W)])));
    let body = encode_map(&base_body());
    assert_eq!(verdict(&body, &witness, &[W]), Verdict::NoUse);
    // Contrast: the same shape under an unknown BODY key is refused.
    let unknown_body = encode_map(&with(base_body(), 23, arr(&[sig_clause(&W)])));
    assert_eq!(verdict(&unknown_body, &wits(), &[W]), Verdict::Incomplete);
}

#[test]
fn exploit_unknown_output_key_is_not_incomplete() {
    let output = map(&[
        (uint(0), bytes(&ent_addr(&OTHER))),
        (uint(1), uint(2_000_000)),
        (uint(4), sig_clause(&W)),
    ]);
    let body = encode_map(&[
        (0, set(&[outpoint(TXID, 0)])),
        (1, arr(&[output])),
        (2, uint(200_000)),
    ]);
    assert_eq!(verdict(&body, &wits(), &[W]), Verdict::NoUse);
}

#[test]
fn exploit_plutus_script_ref_trailing_bytes_unchecked() {
    // [2, h'00'] followed by a trailing native sig clause, all inside tag 24.
    let inner_trailing = [arr_head(2), uint(2), bytes(&[0x00]), sig_clause(&W)].concat();
    let output = map(&[
        (uint(0), bytes(&ent_addr(&OTHER))),
        (uint(1), uint(2_000_000)),
        (uint(3), tag(24, bytes(&inner_trailing))),
    ]);
    let body = arr_body(output.clone());
    let clean = Scan { found: false, complete: true };
    assert_eq!(output_use(&body, &BTreeSet::from([W])), clean, "plutus trailing bytes accepted");
    // Contrast: a native script ref with trailing bytes is refused.
    let native_trailing = [arr_head(2), uint(0), sig_clause(&OTHER), vec![0x00]].concat();
    let output = map(&[
        (uint(0), bytes(&ent_addr(&OTHER))),
        (uint(1), uint(2_000_000)),
        (uint(3), tag(24, bytes(&native_trailing))),
    ]);
    assert_eq!(
        output_use(&arr_body(output), &BTreeSet::from([W])),
        Scan { found: false, complete: false }
    );
}

fn arr_body(output: Vec<u8>) -> Vec<u8> {
    encode_map(&[(1, arr(&[output]))])
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[test]
fn exploit_byron_output_reads_complete_while_byron_input_is_incomplete() {
    let payload = arr(&[bytes(&W), map(&[]), uint(0)]);
    let byron = arr(&[tag(24, bytes(&payload)), uint(crc32(&payload) as u64)]);
    let body = encode_map(&[
        (0, set(&[outpoint(TXID, 0)])),
        (1, arr(&[arr(&[bytes(&byron), uint(2_000_000)])])),
        (2, uint(200_000)),
    ]);
    pallas_body(&body).expect("pallas decodes a legacy Byron-address output");
    assert_eq!(verdict(&body, &wits(), &[W]), Verdict::NoUse);
    let resolved = BTreeMap::from([(OutPoint { tx_id: TXID, index: 0 }, byron.clone())]);
    let scan = scan_with(&encode_map(&base_body()), &wits(), true, &[W], &resolved);
    assert_eq!(scan.verdict(), Verdict::Incomplete);
}

#[test]
fn exploit_wrong_length_credential_slots_read_complete() {
    let w = BTreeSet::from([W]);
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            "voter hash of 29 bytes",
            encode_map(&with(
                base_body(),
                19,
                map(&[(arr(&[uint(2), bytes(&[[0x00].as_slice(), &W].concat())]), map(&[]))]),
            )),
            wits(),
        ),
        (
            "31-byte vkey witness",
            encode_map(&base_body()),
            encode_map(&[(0, set(&[arr(&[bytes(&[0xb1; 31]), bytes(&SIG)])]))]),
        ),
        (
            "10-byte withdrawal account",
            encode_map(&with(base_body(), 5, map(&[(bytes(&[0xe0; 10]), uint(0))]))),
            wits(),
        ),
        (
            "20-byte enterprise output address",
            encode_map(&[
                (0, set(&[outpoint(TXID, 0)])),
                (1, arr(&[map_output(&[0x60; 20], uint(1))])),
                (2, uint(200_000)),
            ]),
            wits(),
        ),
    ];
    let _ = &w;
    for (name, body, witness) in cases {
        let v = verdict(&body, &witness, &[W]);
        eprintln!("{name}: pallas={:?} verdict={v:?}", pallas_body(&body).is_ok() && pallas_wits(&witness).is_ok());
        assert_eq!(v, Verdict::NoUse, "{name}");
    }
}

// ------------------------------------------------------------ defended

/// Witness set carrying one native script `[1, [items...]]` (script_all).
fn witness_script_all(items: &[Vec<u8>]) -> Vec<u8> {
    encode_map(&[(1, set(&[arr(&[uint(1), arr(items)])]))])
}

#[test]
fn defended_budget_exhaustion_never_reads_complete() {
    // 100,001 leaves: the walk budget (100,000 nodes incl. containers) runs out
    // before the trailing sig clause.
    let mut items: Vec<Vec<u8>> = vec![uint(4); 100_001];
    items.push(sig_clause(&W));
    let late = witness_script_all(&items);
    let s = scan_with(&encode_map(&base_body()), &late, true, &[W], &base_resolver());
    assert_eq!(s.surfaces, Scan { found: false, complete: false });
    assert_eq!(s.verdict(), Verdict::Incomplete);
    // Control: the clause first is found; a small clean script is NoUse.
    items.rotate_right(1);
    let early = witness_script_all(&items);
    assert_eq!(verdict(&encode_map(&base_body()), &early, &[W]), Verdict::UseFound);
    let small = witness_script_all(&[uint(4), sig_clause(&OTHER)]);
    assert_eq!(verdict(&encode_map(&base_body()), &small, &[W]), Verdict::NoUse);
}

#[test]
fn defended_budget_boundary_exact() {
    // Script node count: outer set is NOT counted (seq loop), the script array 1,
    // uint 1 1, inner array 1, then n leaves. Find the largest n that stays complete.
    let mut last_complete = None;
    for n in 99_990u64..100_000 {
        let items: Vec<Vec<u8>> = vec![uint(4); n as usize];
        let w = witness_script_all(&items);
        let s = scan_with(&encode_map(&base_body()), &w, true, &[W], &base_resolver());
        if s.surfaces.complete {
            last_complete = Some(n);
        }
    }
    eprintln!("largest complete leaf count = {last_complete:?}");
    assert_eq!(last_complete, Some(99_997), "budget counts 3 container/kind nodes + n leaves");
}

#[test]
fn defended_shared_output_budget_leaves_gap() {
    let wide: Vec<u8> = [arr_head(2), uint(1), head(4, 60_000), vec![0x04; 60_000]].concat();
    let with_w: Vec<u8> = [arr_head(2), uint(1), arr(&[uint(4), sig_clause(&W)])].concat();
    let _ = with_w;
    // Output 1 exhausts 60k, output 2 carries the clause past the remaining budget.
    let late: Vec<u8> = [
        arr_head(2),
        uint(1),
        head(4, 50_001),
        vec![0x04; 50_000],
        sig_clause(&W),
    ]
    .concat();
    let body = encode_map(&[(
        1,
        arr(&[
            output_with_ref(&ent_addr(&OTHER), 0, &wide),
            output_with_ref(&ent_addr(&OTHER), 0, &late),
        ]),
    )]);
    assert_eq!(output_use(&body, &BTreeSet::from([W])), Scan { found: false, complete: false });
}

#[test]
fn defended_tag24_variants() {
    let w = BTreeSet::from([W]);
    let native = [arr_head(2), uint(0), sig_clause(&W)].concat();
    let out = |script_ref: Vec<u8>| {
        arr_body(map(&[
            (uint(0), bytes(&ent_addr(&OTHER))),
            (uint(1), uint(1)),
            (uint(3), script_ref),
        ]))
    };
    let gap = Scan { found: false, complete: false };
    // control
    assert_eq!(output_use(&out(tag(24, bytes(&native))), &w), Scan { found: true, complete: true });
    // attacks
    assert_eq!(output_use(&out(tag(24, bytes_chunked(&native, 7))), &w), gap, "indefinite bytes");
    assert_eq!(output_use(&out(tag(25, bytes(&native))), &w), gap, "tag 25");
    assert_eq!(output_use(&out(tag(24, tag(24, bytes(&native)))), &w), gap, "nested tag outside");
    assert_eq!(
        output_use(&out(tag(24, bytes(&tag(24, bytes(&native))))), &w),
        gap,
        "nested tag inside"
    );
    assert_eq!(output_use(&out(bytes(&native)), &w), gap, "bare bytes");
    let three = [arr_head(3), uint(0), sig_clause(&W), uint(0)].concat();
    assert_eq!(output_use(&out(tag(24, bytes(&three))), &w).complete, false, "arity 3");
    let indef = [vec![0x9f], uint(0), sig_clause(&W), vec![0xff]].concat();
    assert_eq!(output_use(&out(tag(24, bytes(&indef))), &w), gap, "indefinite inner array");
    let kind4 = [arr_head(2), uint(4), sig_clause(&W)].concat();
    assert_eq!(output_use(&out(tag(24, bytes(&kind4))), &w), gap, "script type 4");
    // key 3 twice: the second, watched, is still read.
    let twice = arr_body(map(&[
        (uint(0), bytes(&ent_addr(&OTHER))),
        (uint(1), uint(1)),
        (uint(3), tag(24, bytes(&[arr_head(2), uint(2), bytes(&[1])].concat()))),
        (uint(3), tag(24, bytes(&native))),
    ]));
    assert_eq!(output_use(&twice, &w).found, true, "duplicate key 3");
    // malformed output after a valid watched one keeps the find, loses completeness
    let after = encode_map(&[(1, arr(&[map_output(&ent_addr(&W), uint(1)), uint(5)]))]);
    assert_eq!(output_use(&after, &w), Scan { found: true, complete: false });
    // malformed output BEFORE a watched one: scan stops, gap reported.
    let before = encode_map(&[(1, arr(&[uint(5), map_output(&ent_addr(&W), uint(1))]))]);
    assert_eq!(output_use(&before, &w), gap);
    // indefinite output map: refused (fail-closed).
    let indef_out = encode_map(&[(1, arr(&[map_indef(&[(uint(0), bytes(&ent_addr(&W))), (uint(1), uint(1))])]))]);
    assert_eq!(output_use(&indef_out, &w), gap);
}

#[test]
fn defended_indefinite_abuse_in_deep_walk() {
    let body = encode_map(&base_body());
    let one = |script: Vec<u8>| encode_map(&[(1, set(&[script]))]);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("break as indef-map value", [vec![0x82, 0x01, 0xbf, 0x01, 0xff], sig_clause(&W)].concat()),
        ("break in definite array", vec![0x82, 0x01, 0xff]),
        ("unterminated indef array", vec![0x82, 0x01, 0x9f, 0x01]),
        ("odd indef map", vec![0x82, 0x01, 0xbf, 0x01, 0x02, 0x03, 0xff]),
        ("text chunk in indef bytes", vec![0x82, 0x00, 0x5f, 0x41, 0xa5, 0x61, 0x41, 0xff]),
        ("nested indef bytes chunk", vec![0x82, 0x00, 0x5f, 0x5f, 0x41, 0xa5, 0xff, 0xff]),
        ("bare top-level break", vec![0xff]),
        ("map 2^63 pairs", vec![0xbb, 0x80, 0, 0, 0, 0, 0, 0, 0]),
        ("bytes len 2^64-1", vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ("reserved info 28", vec![0x1c]),
    ];
    for (name, script) in cases {
        let s = scan_with(&body, &one(script), true, &[W], &base_resolver());
        eprintln!("{name}: {:?}", s.surfaces);
        assert!(!s.surfaces.complete, "{name} must be incomplete");
        assert_ne!(s.verdict(), Verdict::NoUse, "{name}");
    }
    // zero-length chunks around a chunked hash still match
    let chunks = [vec![0x82, 0x00, 0x5f, 0x40], bytes(&W[..10]), vec![0x40], bytes(&W[10..]), vec![0x40, 0xff]].concat();
    assert_eq!(verdict(&body, &one(chunks), &[W]), Verdict::UseFound);
}

#[test]
fn defended_body_key_shapes() {
    let w = wits();
    let k = |key: Vec<u8>| {
        let mut b = head(5, 4);
        for (kk, v) in base_body() {
            b.extend(uint(kk));
            b.extend(v);
        }
        b.extend(key);
        b.extend(uint(0));
        b
    };
    assert_eq!(verdict(&k(uint(10)), &w, &[W]), Verdict::Incomplete, "key 10");
    assert_eq!(verdict(&k(uint(12)), &w, &[W]), Verdict::Incomplete, "key 12");
    assert_eq!(verdict(&k(uint(99)), &w, &[W]), Verdict::Incomplete, "key 99");
    assert_eq!(verdict(&k(vec![0x20]), &w, &[W]), Verdict::Incomplete, "negative key");
    assert_eq!(verdict(&k(tag(1, uint(2))), &w, &[W]), Verdict::Incomplete, "tagged key");
    assert_eq!(verdict(&k(bytes(b"k")), &w, &[W]), Verdict::Incomplete, "bytes key");
    // non-minimal key encodings of known keys behave like the minimal ones
    let mut b = head(5, 4);
    for (kk, v) in base_body() {
        b.extend(uint(kk));
        b.extend(v);
    }
    b.extend(head_wide(0, 14, 8));
    b.extend(head_wide(4, 1, 8));
    b.extend(head_wide(2, 28, 8));
    b.extend(W);
    assert_eq!(verdict(&b, &w, &[W]), Verdict::UseFound, "non-minimal 64-bit heads");
    // duplicate key 14: watched in either occurrence is found
    for order in [[W, OTHER], [OTHER, W]] {
        let body = encode_map(&[
            (0, set(&[outpoint(TXID, 0)])),
            (14, set(&[bytes(&order[0])])),
            (14, set(&[bytes(&order[1])])),
        ]);
        assert_eq!(verdict(&body, &w, &[W]), Verdict::UseFound, "duplicate key 14");
    }
    // indefinite body map
    let body = map_indef(&[(uint(0), set(&[outpoint(TXID, 0)])), (uint(14), arr_indef(&[bytes(&W)]))]);
    assert_eq!(verdict(&body, &w, &[W]), Verdict::UseFound, "indefinite body map");
}

#[test]
fn defended_credential_encodings() {
    let w = wits();
    let b = |key: u64, v: Vec<u8>| encode_map(&with(base_body(), key, v));
    assert_eq!(verdict(&b(14, set(&[bytes(&W)])), &w, &[W]), Verdict::UseFound, "tag-258 signer");
    assert_eq!(verdict(&b(14, arr(&[bytes(&W)])), &w, &[W]), Verdict::UseFound, "bare signer");
    assert_eq!(verdict(&b(14, tag(259, arr(&[bytes(&W)]))), &w, &[W]), Verdict::Incomplete, "tag 259 set");
    assert_eq!(verdict(&b(14, arr(&[bytes_chunked(&W, 14)])), &w, &[W]), Verdict::Incomplete, "chunked signer");
    assert_eq!(verdict(&b(14, arr(&[tag(1, bytes(&W))])), &w, &[W]), Verdict::Incomplete, "tagged signer");
    assert_eq!(verdict(&b(14, arr(&[vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 0]])), &w, &[W]), Verdict::Incomplete, "float signer");
    assert_eq!(verdict(&b(14, arr(&[bytes(&W[..27])])), &w, &[W]), Verdict::Incomplete, "27-byte signer");
    // deep-walk surfaces join chunks and see through tags
    let cert = |cred: Vec<u8>| b(4, set(&[arr(&[uint(0), arr(&[uint(0), cred])])]));
    assert_eq!(verdict(&cert(bytes_chunked(&W, 5)), &w, &[W]), Verdict::UseFound, "chunked cert cred");
    assert_eq!(verdict(&cert(tag(7, bytes(&W))), &w, &[W]), Verdict::UseFound, "tagged cert cred");
    // withdrawal / voter / proposal / output slots are strict
    assert_eq!(verdict(&b(5, map(&[(bytes_chunked(&reward_key(&W), 9), uint(0))])), &w, &[W]), Verdict::Incomplete);
    assert_eq!(verdict(&b(19, map(&[(arr(&[uint(2), bytes_chunked(&W, 9)]), map(&[]))])), &w, &[W]), Verdict::Incomplete);
}

#[test]
fn defended_invalid_tx_semantics() {
    let w = wits();
    let coll = [0x66u8; 32];
    let body = encode_map(&with(
        with(base_body(), 13, set(&[outpoint(coll, 1)])),
        16,
        map_output(&ent_addr(&OTHER), uint(1)),
    ));
    let watched_regular = BTreeMap::from([
        (OutPoint { tx_id: TXID, index: 0 }, ent_addr(&W)),
        (OutPoint { tx_id: coll, index: 1 }, ent_addr(&OTHER)),
    ]);
    let watched_collateral = BTreeMap::from([
        (OutPoint { tx_id: TXID, index: 0 }, ent_addr(&OTHER)),
        (OutPoint { tx_id: coll, index: 1 }, ent_addr(&W)),
    ]);
    // invalid: only collateral is consumed
    assert_eq!(scan_with(&body, &w, false, &[W], &watched_collateral).verdict(), Verdict::UseFound);
    assert_eq!(scan_with(&body, &w, false, &[W], &watched_regular).verdict(), Verdict::NoUse, "regular input of an invalid tx is not consumed (by design)");
    // valid: only regular inputs are consumed
    assert_eq!(scan_with(&body, &w, true, &[W], &watched_regular).verdict(), Verdict::UseFound);
    assert_eq!(scan_with(&body, &w, true, &[W], &watched_collateral).verdict(), Verdict::NoUse, "collateral of a valid tx is not consumed (by design)");
    // collateral return is scanned for both validity flags
    let ret = encode_map(&with(base_body(), 16, map_output(&ent_addr(&W), uint(1))));
    assert_eq!(scan_with(&ret, &w, false, &[W], &base_resolver()).verdict(), Verdict::UseFound);
    assert_eq!(scan_with(&ret, &w, true, &[W], &base_resolver()).verdict(), Verdict::UseFound);
    // a witness vkey is seen for an invalid transaction too
    let vk_hash = blake224(&VK);
    assert_eq!(scan_with(&body, &w, false, &[vk_hash], &watched_collateral).verdict(), Verdict::UseFound);
}

#[test]
fn defended_whole_transaction_is_incomplete() {
    let body = encode_map(&with(base_body(), 14, set(&[bytes(&OTHER)])));
    let tx = arr(&[body, wits(), vec![0xf5], null()]);
    assert_eq!(verdict(&tx, &tx, &[W]), Verdict::Incomplete);
    // body handed over as both spans
    let body = encode_map(&base_body());
    assert_eq!(verdict(&body, &body, &[W]), Verdict::Incomplete);
    // empty witness span
    assert_eq!(verdict(&body, &[], &[W]), Verdict::Incomplete);
}

/// Largest `n` for which `[1, inner(n)]` as a witness native script stays complete.
fn largest_complete(lo: u64, hi: u64, inner: impl Fn(u64) -> Vec<u8>) -> Option<u64> {
    let body = encode_map(&base_body());
    let mut best = None;
    for n in lo..hi {
        let script = [arr_head(2), uint(1), inner(n)].concat();
        let w = encode_map(&[(1, set(&[script]))]);
        if scan_with(&body, &w, true, &[W], &base_resolver()).surfaces.complete {
            best = Some(n);
        }
    }
    best
}

#[test]
fn defended_budget_counts_every_node_kind() {
    // definite map: header + 2 per pair
    let m = largest_complete(49_990, 50_005, |n| [head(5, n), vec![0x00, 0x00].repeat(n as usize)].concat());
    // tags: tag + tagged item per element inside a definite array
    let t = largest_complete(49_990, 50_005, |n| [head(4, n), vec![0xc1, 0x00].repeat(n as usize)].concat());
    // indefinite array: header 1, break free
    let i = largest_complete(99_990, 100_005, |n| [vec![0x9f], vec![0x00; n as usize], vec![0xff]].concat());
    // indefinite bytes: chunks are not counted (one node per string)
    let c = largest_complete(99_990, 100_005, |n| [head(4, n), vec![0x5f, 0x40, 0x40, 0x40, 0xff].repeat(n as usize)].concat());
    eprintln!("map pairs {m:?}, tags {t:?}, indef items {i:?}, chunked strings {c:?}");
    assert_eq!(m, Some(49_998)); // 2 (outer array, kind) + 1 map + 2n <= 100_000
    assert_eq!(t, Some(49_998)); // 2 + 1 array + 2n
    assert_eq!(i, Some(99_997)); // 2 + 1 + n
    assert_eq!(c, Some(99_997)); // 2 + 1 + n, chunk count irrelevant
}
