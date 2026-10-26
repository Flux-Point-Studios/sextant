//! Red-team CBOR helpers (scratch only, never committed).
#![allow(dead_code)]

use sextant::utxo::OutPoint;
use sextant::watchkey::{TransactionScan, Verdict, transaction_use};
use std::collections::{BTreeMap, BTreeSet};

pub const W: [u8; 28] = [0xa5; 28];
pub const OTHER: [u8; 28] = [0xc9; 28];
pub const VK: [u8; 32] = [0xb1; 32];
pub const SIG: [u8; 64] = [0xb2; 64];
pub const TXID: [u8; 32] = [0x55; 32];

pub fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => [vec![m | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![m | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 27], n.to_be_bytes().to_vec()].concat(),
    }
}

/// A non-minimal head: `width` bytes of argument (1, 2, 4 or 8) regardless of `n`.
pub fn head_wide(major: u8, n: u64, width: u8) -> Vec<u8> {
    let m = major << 5;
    match width {
        1 => vec![m | 24, n as u8],
        2 => [vec![m | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        4 => [vec![m | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 27], n.to_be_bytes().to_vec()].concat(),
    }
}

pub fn uint(n: u64) -> Vec<u8> {
    head(0, n)
}
pub fn bytes(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}
/// Indefinite byte string split into chunks of at most `chunk` bytes.
pub fn bytes_chunked(b: &[u8], chunk: usize) -> Vec<u8> {
    let mut v = vec![0x5f];
    for c in b.chunks(chunk.max(1)) {
        v.extend(bytes(c));
    }
    v.push(0xff);
    v
}
pub fn text(s: &str) -> Vec<u8> {
    [head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
}
pub fn arr(items: &[Vec<u8>]) -> Vec<u8> {
    [head(4, items.len() as u64), items.concat()].concat()
}
pub fn arr_indef(items: &[Vec<u8>]) -> Vec<u8> {
    [vec![0x9f], items.concat(), vec![0xff]].concat()
}
pub fn map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = head(5, pairs.len() as u64);
    for (k, val) in pairs {
        v.extend_from_slice(k);
        v.extend_from_slice(val);
    }
    v
}
pub fn map_indef(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = vec![0xbf];
    for (k, val) in pairs {
        v.extend_from_slice(k);
        v.extend_from_slice(val);
    }
    v.push(0xff);
    v
}
pub fn tag(t: u64, item: Vec<u8>) -> Vec<u8> {
    [head(6, t), item].concat()
}
pub fn set(items: &[Vec<u8>]) -> Vec<u8> {
    tag(258, arr(items))
}
pub fn null() -> Vec<u8> {
    vec![0xf6]
}

pub fn ent_addr(cred: &[u8; 28]) -> Vec<u8> {
    [vec![0x60], cred.to_vec()].concat()
}
pub fn base_addr(pay: &[u8; 28], stk: &[u8; 28]) -> Vec<u8> {
    [vec![0x00], pay.to_vec(), stk.to_vec()].concat()
}
pub fn reward_key(cred: &[u8; 28]) -> Vec<u8> {
    [vec![0xe0], cred.to_vec()].concat()
}
pub fn reward_script(cred: &[u8; 28]) -> Vec<u8> {
    [vec![0xf0], cred.to_vec()].concat()
}
pub fn outpoint(id: [u8; 32], idx: u64) -> Vec<u8> {
    arr(&[bytes(&id), uint(idx)])
}
pub fn anchor() -> Vec<u8> {
    arr(&[text("https://x.example"), bytes(&[0u8; 32])])
}
pub fn map_output(address: &[u8], value: Vec<u8>) -> Vec<u8> {
    map(&[(uint(0), bytes(address)), (uint(1), value)])
}
/// `{0: address, 1: coin, 3: #6.24(bytes([script_type, script]))}`.
pub fn output_with_ref(address: &[u8], script_type: u64, script: &[u8]) -> Vec<u8> {
    map(&[
        (uint(0), bytes(address)),
        (uint(1), uint(2_000_000)),
        (uint(3), tag(24, bytes(&[arr_head(2), uint(script_type), script.to_vec()].concat()))),
    ])
}
pub fn arr_head(n: u64) -> Vec<u8> {
    head(4, n)
}
pub fn sig_clause(key: &[u8; 28]) -> Vec<u8> {
    arr(&[uint(0), bytes(key)])
}

/// Conway body entries; key order is kept as given.
pub fn base_body() -> Vec<(u64, Vec<u8>)> {
    vec![
        (0, set(&[outpoint(TXID, 0)])),
        (1, arr(&[map_output(&ent_addr(&OTHER), uint(2_000_000))])),
        (2, uint(200_000)),
    ]
}
pub fn base_wits() -> Vec<(u64, Vec<u8>)> {
    vec![(0, set(&[arr(&[bytes(&VK), bytes(&SIG)])]))]
}
pub fn encode_map(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = entries.iter().map(|(k, v)| (uint(*k), v.clone())).collect();
    map(&pairs)
}
pub fn with(mut entries: Vec<(u64, Vec<u8>)>, key: u64, value: Vec<u8>) -> Vec<(u64, Vec<u8>)> {
    entries.push((key, value));
    entries
}

/// The base input `TXID#0` resolves to an unwatched enterprise address.
pub fn base_resolver() -> BTreeMap<OutPoint, Vec<u8>> {
    BTreeMap::from([(OutPoint { tx_id: TXID, index: 0 }, ent_addr(&OTHER))])
}

pub fn scan_with(
    body: &[u8],
    wits: &[u8],
    is_valid: bool,
    watched: &[[u8; 28]],
    resolved: &BTreeMap<OutPoint, Vec<u8>>,
) -> TransactionScan {
    let watched: BTreeSet<[u8; 28]> = watched.iter().copied().collect();
    transaction_use(body, wits, is_valid, &watched, |input| {
        Ok(resolved.get(input).map(Vec::as_slice))
    })
}

pub fn verdict(body: &[u8], wits: &[u8], watched: &[[u8; 28]]) -> Verdict {
    scan_with(body, wits, true, watched, &base_resolver()).verdict()
}

pub fn blake224(data: &[u8]) -> [u8; 28] {
    let h = pallas_crypto::hash::Hasher::<224>::hash(data);
    let mut out = [0u8; 28];
    out.copy_from_slice(h.as_ref());
    out
}

/// Independent CDDL-shape check through pallas's Conway codec.
pub fn pallas_body(body: &[u8]) -> Result<pallas_primitives::conway::TransactionBody<'_>, String> {
    pallas_codec::minicbor::decode::<pallas_primitives::conway::TransactionBody>(body)
        .map_err(|e| e.to_string())
}
pub fn pallas_wits(wits: &[u8]) -> Result<pallas_primitives::conway::WitnessSet<'_>, String> {
    pallas_codec::minicbor::decode::<pallas_primitives::conway::WitnessSet>(wits)
        .map_err(|e| e.to_string())
}
