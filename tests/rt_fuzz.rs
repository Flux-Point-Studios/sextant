//! Red-team fuzzers for the U1 watched-key predicate (scratch only).
mod rt_common;
use minicbor::Decoder;
use pallas_codec::utils::{Bytes as PBytes, CborWrap};
use pallas_primitives::StakeCredential;
use pallas_primitives::conway::{
    Certificate, DRep, NativeScript, ScriptRef, TransactionBody, TransactionOutput, Voter, WitnessSet,
};
use rt_common::*;
use serde_json::Value as Json;
use sextant::utxo::OutPoint;
use sextant::watchkey::{Verdict, transaction_use};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

const ORACLE: &str = include_str!("vectors/u1_watched_key_vectors.json");

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
}

fn iters(default: u64) -> u64 {
    std::env::var("RT_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

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

// ------------------------------------------------ independent pallas oracle

fn addr_hit(a: &[u8], t: &[u8; 28]) -> bool {
    (a.len() >= 29 && a[0] >> 4 <= 7 && a[1..29] == t[..])
        || (a.len() >= 57 && a[0] >> 4 <= 3 && a[29..57] == t[..])
}
fn native_hit(n: &NativeScript, t: &[u8; 28]) -> bool {
    match n {
        NativeScript::ScriptPubkey(h) => h.as_ref() == t,
        NativeScript::ScriptAll(v) | NativeScript::ScriptAny(v) | NativeScript::ScriptNOfK(_, v) => {
            v.iter().any(|s| native_hit(s, t))
        }
        _ => false,
    }
}
fn cred_hit(c: &StakeCredential, t: &[u8; 28]) -> bool {
    match c {
        StakeCredential::AddrKeyhash(h) | StakeCredential::ScriptHash(h) => h.as_ref() == t,
    }
}
fn reward_hit(r: &PBytes, t: &[u8; 28]) -> bool {
    let v: Vec<u8> = r.clone().into();
    v.len() >= 29 && v[1..29] == t[..]
}
fn drep_hit(d: &DRep, t: &[u8; 28]) -> bool {
    matches!(d, DRep::Key(h) | DRep::Script(h) if h.as_ref() == t)
}
fn output_hit(o: &TransactionOutput, t: &[u8; 28]) -> bool {
    match o {
        TransactionOutput::Legacy(l) => addr_hit(&Vec::<u8>::from(l.address.clone()), t),
        TransactionOutput::PostAlonzo(p) => {
            addr_hit(&Vec::<u8>::from(p.address.clone()), t)
                || match &p.script_ref {
                    Some(CborWrap(ScriptRef::NativeScript(n))) => native_hit(n, t),
                    _ => false,
                }
        }
    }
}
fn cert_hit(c: &Certificate, t: &[u8; 28]) -> bool {
    use Certificate::*;
    match c {
        StakeRegistration(s) | StakeDeregistration(s) | Reg(s, _) | UnReg(s, _) => cred_hit(s, t),
        StakeDelegation(s, p) | StakeRegDeleg(s, p, _) => cred_hit(s, t) || p.as_ref() == t,
        PoolRegistration { operator, reward_account, pool_owners, .. } => {
            operator.as_ref() == t || reward_hit(reward_account, t) || pool_owners.iter().any(|o| o.as_ref() == t)
        }
        PoolRetirement(p, _) => p.as_ref() == t,
        VoteDeleg(s, d) | VoteRegDeleg(s, d, _) => cred_hit(s, t) || drep_hit(d, t),
        StakeVoteDeleg(s, p, d) | StakeVoteRegDeleg(s, p, d, _) => {
            cred_hit(s, t) || p.as_ref() == t || drep_hit(d, t)
        }
        AuthCommitteeHot(a, b) => cred_hit(a, t) || cred_hit(b, t),
        ResignCommitteeCold(a, _) | RegDRepCert(a, _, _) | UnRegDRepCert(a, _) | UpdateDRepCert(a, _) => {
            cred_hit(a, t)
        }
    }
}

/// `Some(hit)` when pallas decodes both spans: whether `t` sits in a typed
/// position the predicate claims to cover.
fn pallas_covered(
    body: &[u8],
    wits: &[u8],
    is_valid: bool,
    t: &[u8; 28],
    resolved: &BTreeMap<OutPoint, Vec<u8>>,
) -> Option<bool> {
    let b: TransactionBody = pallas_codec::minicbor::decode(body).ok()?;
    let w: WitnessSet = pallas_codec::minicbor::decode(wits).ok()?;
    let mut hit = b.outputs.iter().any(|o| output_hit(o, t))
        || b.collateral_return.as_ref().is_some_and(|o| output_hit(o, t))
        || b.required_signers.as_ref().is_some_and(|s| s.iter().any(|h| h.as_ref() == t))
        || b.withdrawals.as_ref().is_some_and(|m| m.keys().any(|r| reward_hit(r, t)))
        || b.certificates.as_ref().is_some_and(|s| s.iter().any(|c| cert_hit(c, t)))
        || b.voting_procedures.as_ref().is_some_and(|m| {
            m.keys().any(|v| match v {
                Voter::ConstitutionalCommitteeScript(h)
                | Voter::ConstitutionalCommitteeKey(h)
                | Voter::DRepScript(h)
                | Voter::DRepKey(h)
                | Voter::StakePoolKey(h) => h.as_ref() == t,
            })
        })
        || b.proposal_procedures.as_ref().is_some_and(|s| s.iter().any(|p| reward_hit(&p.reward_account, t)));
    hit |= w.vkeywitness.as_ref().is_some_and(|s| {
        s.iter().any(|v| {
            let k: Vec<u8> = v.vkey.clone().into();
            k.len() == 32 && blake224(&k) == *t
        })
    });
    hit |= w.bootstrap_witness.as_ref().is_some_and(|s| {
        s.iter().any(|v| {
            let k: Vec<u8> = v.public_key.clone().into();
            k.len() == 32 && blake224(&k) == *t
        })
    });
    hit |= w.native_script.as_ref().is_some_and(|s| s.iter().any(|n| native_hit(n, t)));
    let consumed: Vec<_> = if is_valid {
        b.inputs.iter().cloned().collect()
    } else {
        b.collateral.as_ref().map(|c| c.iter().cloned().collect()).unwrap_or_default()
    };
    for input in consumed {
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(input.transaction_id.as_ref());
        let op = OutPoint { tx_id, index: input.index as u16 };
        if let Some(a) = resolved.get(&op) {
            if a.len() >= 29 && a[0] >> 4 <= 7 && a[1..29] == t[..] {
                hit = true;
            }
        }
    }
    Some(hit)
}

fn run(body: &[u8], wits: &[u8], is_valid: bool, t: &[u8; 28], resolved: &BTreeMap<OutPoint, Vec<u8>>) -> Result<(Verdict, Duration), String> {
    let watched = BTreeSet::from([*t]);
    let start = Instant::now();
    let out = catch_unwind(AssertUnwindSafe(|| {
        transaction_use(body, wits, is_valid, &watched, |input| Ok(resolved.get(input).map(Vec::as_slice)))
            .verdict()
    }));
    let elapsed = start.elapsed();
    out.map(|v| (v, elapsed)).map_err(|e| {
        e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
    })
}

// --------------------------------------------------------- grammar fuzzer

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Pos {
    OutPay, OutStake, OutRef, RetPay, RetRef, Signer, Withdrawal, Cert, Voter, PropReward,
    VkeyWit, BootWit, NativeWit, SpentInput,
    // contract-excluded (untyped)
    Datum, Redeemer, PlutusBytes,
    // typed but never read (the gap)
    Mint, Multiasset, GovCommittee, GovTreasury, GovGuardrail,
}
const COVERED: [Pos; 14] = [
    Pos::OutPay, Pos::OutStake, Pos::OutRef, Pos::RetPay, Pos::RetRef, Pos::Signer, Pos::Withdrawal,
    Pos::Cert, Pos::Voter, Pos::PropReward, Pos::VkeyWit, Pos::BootWit, Pos::NativeWit, Pos::SpentInput,
];
const EXCLUDED: [Pos; 3] = [Pos::Datum, Pos::Redeemer, Pos::PlutusBytes];
const GAP: [Pos; 5] = [Pos::Mint, Pos::Multiasset, Pos::GovCommittee, Pos::GovTreasury, Pos::GovGuardrail];

const VK_W: [u8; 32] = [0x77; 32];

/// The grammar target: the key hash of VK_W, so every position (vkey too) can carry it.
fn tgt() -> [u8; 28] {
    blake224(&VK_W)
}

struct Enc {
    r: Rng,
    exotic: bool,
}
impl Enc {
    fn head(&mut self, major: u8, n: u64) -> Vec<u8> {
        if self.exotic && self.r.chance(1, 4) {
            let min = if n < 24 { 1 } else if n <= 0xff { 1 } else if n <= 0xffff { 2 } else if n <= 0xffff_ffff { 4 } else { 8 };
            let widths: Vec<u8> = [1u8, 2, 4, 8].into_iter().filter(|w| *w >= min).collect();
            let w = widths[self.r.below(widths.len() as u64) as usize];
            head_wide(major, n, w)
        } else {
            head(major, n)
        }
    }
    fn uint(&mut self, n: u64) -> Vec<u8> {
        self.head(0, n)
    }
    fn bytes(&mut self, b: &[u8]) -> Vec<u8> {
        if self.exotic && self.r.chance(1, 12) {
            let c = 1 + self.r.below(b.len().max(1) as u64) as usize;
            return bytes_chunked(b, c);
        }
        [self.head(2, b.len() as u64), b.to_vec()].concat()
    }
    fn arr(&mut self, items: Vec<Vec<u8>>) -> Vec<u8> {
        if self.exotic && self.r.chance(1, 3) {
            arr_indef(&items)
        } else {
            [self.head(4, items.len() as u64), items.concat()].concat()
        }
    }
    fn map(&mut self, pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
        if self.exotic && self.r.chance(1, 3) {
            map_indef(&pairs)
        } else {
            let mut v = self.head(5, pairs.len() as u64);
            for (k, x) in pairs {
                v.extend(k);
                v.extend(x);
            }
            v
        }
    }
    fn set(&mut self, items: Vec<Vec<u8>>) -> Vec<u8> {
        let a = self.arr(items);
        if self.r.chance(1, 2) { [self.head(6, 258), a].concat() } else { a }
    }
    fn other(&mut self) -> [u8; 28] {
        let mut h = [0u8; 28];
        for b in h.iter_mut() {
            *b = (self.r.next() as u8) | 1;
        }
        h[0] = 0x10 + (self.r.below(8) as u8); // never 0xa5 / 0x77-derived
        h
    }
    fn cred(&mut self, h: &[u8; 28]) -> Vec<u8> {
        let k = self.r.below(2);
        let (a, b) = (self.uint(k), self.bytes(h));
        self.arr(vec![a, b])
    }
    fn anchor_or_null(&mut self) -> Vec<u8> {
        if self.r.chance(1, 2) { null() } else { anchor() }
    }
    fn native(&mut self, depth: u32, w: Option<&[u8; 28]>) -> Vec<u8> {
        if depth == 0 || self.r.chance(1, 3) {
            let leaf = match w {
                Some(t) => *t,
                None => self.other(),
            };
            return match (w.is_some(), self.r.below(3)) {
                (false, 1) => { let n = self.r.below(1000); let (a, b) = (self.uint(4), self.uint(n)); self.arr(vec![a, b]) }
                (false, 2) => { let n = self.r.below(1000); let (a, b) = (self.uint(5), self.uint(n)); self.arr(vec![a, b]) }
                _ => { let (a, b) = (self.uint(0), self.bytes(&leaf)); self.arr(vec![a, b]) }
            };
        }
        let n = 1 + self.r.below(3) as usize;
        let at = self.r.below(n as u64) as usize;
        let kids: Vec<Vec<u8>> = (0..n).map(|i| self.native(depth - 1, if i == at { w } else { None })).collect();
        let list = self.arr(kids);
        match self.r.below(3) {
            0 => { let k = self.uint(1); self.arr(vec![k, list]) }
            1 => { let k = self.uint(2); self.arr(vec![k, list]) }
            _ => { let (k, m) = (self.uint(3), self.uint(1)); self.arr(vec![k, m, list]) }
        }
    }
    fn address(&mut self, pay: &[u8; 28], stake: Option<&[u8; 28]>) -> Vec<u8> {
        match stake {
            Some(s) => [vec![(self.r.below(4) as u8) << 4 | 1], pay.to_vec(), s.to_vec()].concat(),
            None => match self.r.below(3) {
                0 => [vec![0x61 | ((self.r.below(2) as u8) << 4)], pay.to_vec()].concat(),
                1 => [vec![0x41], pay.to_vec(), vec![0x81, 0x00, 0x05]].concat(), // pointer
                _ => { let o = self.other(); [vec![0x01], pay.to_vec(), o.to_vec()].concat() }
            },
        }
    }
    fn value(&mut self, policy: &[u8; 28]) -> Vec<u8> {
        if self.r.chance(1, 2) {
            let n = self.r.below(1000);
            self.uint(1_000_000 + n)
        } else {
            let (c, p, n, q) = (self.uint(2_000_000), self.bytes(policy), self.bytes(b"tok"), self.uint(1));
            let inner = self.map(vec![(n, q)]);
            let ma = self.map(vec![(p, inner)]);
            self.arr(vec![c, ma])
        }
    }
    fn output(&mut self, pay: &[u8; 28], stake: Option<&[u8; 28]>, refw: Option<&[u8; 28]>, policy: &[u8; 28], datum_w: bool) -> Vec<u8> {
        let addr = self.address(pay, stake);
        let legacy = refw.is_none() && !datum_w && self.r.chance(1, 4);
        if legacy {
            let (a, v) = (self.bytes(&addr), self.value(policy));
            if self.r.chance(1, 2) {
                return self.arr(vec![a, v]);
            }
            let h = self.bytes(&[0x44; 32]);
            return self.arr(vec![a, v, h]);
        }
        let mut pairs = vec![(self.uint(0), self.bytes(&addr)), (self.uint(1), self.value(policy))];
        if datum_w || self.r.chance(1, 3) {
            let pd = if datum_w { bytes(&tgt()) } else { bytes(&[0x01, 0x02]) };
            let (k, t) = (self.uint(2), self.uint(1));
            let inner = tag(24, self.bytes(&pd));
            pairs.push((k, self.arr(vec![t, inner])));
        }
        if refw.is_some() || self.r.chance(1, 4) {
            let script = if refw.is_some() || self.r.chance(1, 2) {
                [arr_head(2), uint(0), self.native(3, refw)].concat()
            } else {
                [arr_head(2), uint(2), bytes(&[0x4d, 0x01, 0x00, 0x00])].concat()
            };
            let k = self.uint(3);
            pairs.push((k, tag(24, self.bytes(&script))));
        }
        let n = pairs.len();
        for i in (1..n).rev() {
            let j = self.r.below(i as u64 + 1) as usize;
            pairs.swap(i, j);
        }
        self.map(pairs)
    }
    fn cert(&mut self, w: Option<&[u8; 28]>) -> Vec<u8> {
        let kinds = [0u64, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
        let kind = kinds[self.r.below(kinds.len() as u64) as usize];
        // number of credential-ish slots per kind
        let slots = match kind { 0 | 1 | 4 | 7 | 8 | 15 | 16 | 17 | 18 => 1, 2 | 9 | 11 | 12 | 14 => 2, 10 | 13 => 3, 3 => 3, _ => 1 };
        let at = self.r.below(slots);
        let h = |e: &mut Enc, i: u64| if i == at { w.copied().unwrap_or_else(|| e.other()) } else { e.other() };
        let k = self.uint(kind);
        let items = match kind {
            0 | 1 => { let c = h(self, 0); vec![k, self.cred(&c)] }
            2 => { let (c, p) = (h(self, 0), h(self, 1)); vec![k, self.cred(&c), self.bytes(&p)] }
            3 => {
                let (op, ra, ow) = (h(self, 0), h(self, 1), h(self, 2));
                let owners = { let b = self.bytes(&ow); self.set(vec![b]) };
                let margin = tag(30, { let (a, b) = (self.uint(1), self.uint(10)); self.arr(vec![a, b]) });
                vec![k, self.bytes(&op), self.bytes(&[0x33; 32]), self.uint(100), self.uint(340), margin,
                     self.bytes(&reward_key(&ra)), owners, self.arr(vec![]), null()]
            }
            4 => { let p = h(self, 0); vec![k, self.bytes(&p), self.uint(300)] }
            7 | 8 => { let c = h(self, 0); vec![k, self.cred(&c), self.uint(2_000_000)] }
            9 => { let (c, d) = (h(self, 0), h(self, 1)); vec![k, self.cred(&c), self.cred(&d)] }
            10 => { let (c, p, d) = (h(self, 0), h(self, 1), h(self, 2)); vec![k, self.cred(&c), self.bytes(&p), self.cred(&d)] }
            11 => { let (c, p) = (h(self, 0), h(self, 1)); vec![k, self.cred(&c), self.bytes(&p), self.uint(2_000_000)] }
            12 => { let (c, d) = (h(self, 0), h(self, 1)); vec![k, self.cred(&c), self.cred(&d), self.uint(2_000_000)] }
            13 => { let (c, p, d) = (h(self, 0), h(self, 1), h(self, 2)); vec![k, self.cred(&c), self.bytes(&p), self.cred(&d), self.uint(2_000_000)] }
            14 => { let (a, b) = (h(self, 0), h(self, 1)); vec![k, self.cred(&a), self.cred(&b)] }
            15 => { let a = h(self, 0); vec![k, self.cred(&a), self.anchor_or_null()] }
            16 => { let a = h(self, 0); vec![k, self.cred(&a), self.uint(500), self.anchor_or_null()] }
            17 => { let a = h(self, 0); vec![k, self.cred(&a), self.uint(500)] }
            _ => { let a = h(self, 0); vec![k, self.cred(&a), self.anchor_or_null()] }
        };
        self.arr(items)
    }
}

struct GenTx {
    body: Vec<u8>,
    wits: Vec<u8>,
    is_valid: bool,
    resolved: BTreeMap<OutPoint, Vec<u8>>,
}

fn gen_tx(e: &mut Enc, place: &BTreeSet<Pos>) -> GenTx {
    let has = |p: Pos| place.contains(&p);
    let mut body: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let is_valid = !e.r.chance(1, 4);
    let mut resolved = BTreeMap::new();
    let mut inputs = Vec::new();
    let mut collateral = Vec::new();
    for i in 0..(1 + e.r.below(3)) {
        let id = [0x20 + i as u8; 32];
        inputs.push(id);
    }
    for i in 0..(1 + e.r.below(2)) {
        collateral.push([0x40 + i as u8; 32]);
    }
    let spend_at = e.r.below(if is_valid { inputs.len() } else { collateral.len() } as u64) as usize;
    for (n, id) in inputs.iter().enumerate() {
        let pay = if has(Pos::SpentInput) && is_valid && n == spend_at { tgt() } else { e.other() };
        resolved.insert(OutPoint { tx_id: *id, index: 0 }, ent_addr(&pay));
    }
    for (n, id) in collateral.iter().enumerate() {
        let pay = if has(Pos::SpentInput) && !is_valid && n == spend_at { tgt() } else { e.other() };
        resolved.insert(OutPoint { tx_id: *id, index: 0 }, ent_addr(&pay));
    }
    let ins: Vec<Vec<u8>> = inputs.iter().map(|id| { let (a, b) = (e.bytes(id), e.uint(0)); e.arr(vec![a, b]) }).collect();
    body.push((e.uint(0), e.set(ins)));
    // outputs
    let n_out = 1 + e.r.below(3) as usize;
    let at = e.r.below(n_out as u64) as usize;
    let policy = if has(Pos::Multiasset) { tgt() } else { e.other() };
    let outs: Vec<Vec<u8>> = (0..n_out)
        .map(|i| {
            let here = i == at;
            let pay = if here && has(Pos::OutPay) { tgt() } else { e.other() };
            let stake = if here && has(Pos::OutStake) { Some(tgt()) } else { None };
            let refw = if here && has(Pos::OutRef) { Some(tgt()) } else { None };
            let pol = if here { policy } else { e.other() };
            e.output(&pay, stake.as_ref(), refw.as_ref(), &pol, here && has(Pos::Datum))
        })
        .collect();
    body.push((e.uint(1), e.arr(outs)));
    let fee = 170_000 + e.r.below(10_000);
    body.push((e.uint(2), e.uint(fee)));
    if e.r.chance(1, 2) { body.push((e.uint(3), e.uint(1_000_000))); }
    if has(Pos::Cert) || e.r.chance(1, 3) {
        let n = 1 + e.r.below(2) as usize;
        let at = e.r.below(n as u64) as usize;
        let t = tgt();
        let certs: Vec<Vec<u8>> = (0..n).map(|i| e.cert(if i == at && has(Pos::Cert) { Some(&t) } else { None })).collect();
        body.push((e.uint(4), e.set(certs)));
    }
    if has(Pos::Withdrawal) || e.r.chance(1, 3) {
        let c = if has(Pos::Withdrawal) { tgt() } else { e.other() };
        let (k, v) = (e.bytes(&reward_key(&c)), e.uint(0));
        body.push((e.uint(5), e.map(vec![(k, v)])));
    }
    if e.r.chance(1, 3) { body.push((e.uint(7), e.bytes(&[0x77; 32]))); }
    if e.r.chance(1, 3) { body.push((e.uint(8), e.uint(5))); }
    if has(Pos::Mint) || e.r.chance(1, 3) {
        let p = if has(Pos::Mint) { tgt() } else { e.other() };
        let (pk, nk, q) = (e.bytes(&p), e.bytes(b"tok"), e.uint(1));
        let inner = e.map(vec![(nk, q)]);
        body.push((e.uint(9), e.map(vec![(pk, inner)])));
    }
    if e.r.chance(1, 3) { body.push((e.uint(11), e.bytes(&[0x11; 32]))); }
    let coll: Vec<Vec<u8>> = collateral.iter().map(|id| { let (a, b) = (e.bytes(id), e.uint(0)); e.arr(vec![a, b]) }).collect();
    body.push((e.uint(13), e.set(coll)));
    if has(Pos::Signer) || e.r.chance(1, 3) {
        let s = if has(Pos::Signer) { tgt() } else { e.other() };
        let o = e.other();
        let items = vec![e.bytes(&o), e.bytes(&s)];
        body.push((e.uint(14), e.set(items)));
    }
    if e.r.chance(1, 3) { body.push((e.uint(15), e.uint(1))); }
    if has(Pos::RetPay) || has(Pos::RetRef) || e.r.chance(1, 3) {
        let pay = if has(Pos::RetPay) { tgt() } else { e.other() };
        let refw = if has(Pos::RetRef) { Some(tgt()) } else { None };
        let pol = e.other();
        body.push((e.uint(16), e.output(&pay, None, refw.as_ref(), &pol, false)));
    }
    if e.r.chance(1, 3) { body.push((e.uint(17), e.uint(5_000_000))); }
    if e.r.chance(1, 3) {
        let (a, b) = (e.bytes(&[0x99; 32]), e.uint(1));
        let r = e.arr(vec![a, b]);
        body.push((e.uint(18), e.set(vec![r])));
    }
    if has(Pos::Voter) || e.r.chance(1, 4) {
        let h = if has(Pos::Voter) { tgt() } else { e.other() };
        let vt = e.r.below(5);
        let (t, hb) = (e.uint(vt), e.bytes(&h));
        let voter = e.arr(vec![t, hb]);
        let (tx, ix) = (e.bytes(&[0x88; 32]), e.uint(0));
        let gaid = e.arr(vec![tx, ix]);
        let (vote, an) = (e.uint(1), e.anchor_or_null());
        let proc_ = e.arr(vec![vote, an]);
        let inner = e.map(vec![(gaid, proc_)]);
        body.push((e.uint(19), e.map(vec![(voter, inner)])));
    }
    if has(Pos::PropReward) || has(Pos::GovCommittee) || has(Pos::GovTreasury) || has(Pos::GovGuardrail) || e.r.chance(1, 4) {
        let ra = if has(Pos::PropReward) { tgt() } else { e.other() };
        let action = if has(Pos::GovCommittee) {
            let c = e.cred(&tgt());
            let (k, n, rm, ep, q) = (e.uint(4), null(), e.set(vec![]), e.uint(400), tag(30, arr(&[uint(1), uint(2)])));
            let add = e.map(vec![(c, ep)]);
            e.arr(vec![k, n, rm, add, q])
        } else if has(Pos::GovTreasury) {
            let (k, acct, amt) = (e.uint(2), e.bytes(&reward_key(&tgt())), e.uint(1));
            let m = e.map(vec![(acct, amt)]);
            e.arr(vec![k, m, null()])
        } else if has(Pos::GovGuardrail) {
            let (k, pp, pol) = (e.uint(0), e.map(vec![(uint(0), uint(44))]), e.bytes(&tgt()));
            e.arr(vec![k, null(), pp, pol])
        } else {
            let k = e.uint(6);
            e.arr(vec![k])
        };
        let (dep, rab) = (e.uint(100_000), e.bytes(&reward_key(&ra)));
        let prop = e.arr(vec![dep, rab, action, anchor()]);
        body.push((e.uint(20), e.set(vec![prop])));
    }
    if e.r.chance(1, 4) { body.push((e.uint(21), e.uint(9))); }
    if e.r.chance(1, 4) { body.push((e.uint(22), e.uint(9))); }
    // shuffle body keys
    for i in (1..body.len()).rev() {
        let j = e.r.below(i as u64 + 1) as usize;
        body.swap(i, j);
    }
    let body = e.map(body);

    let mut wits: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut vks = vec![[0x31u8; 32]];
    if has(Pos::VkeyWit) { vks.push(VK_W); }
    let vk_items: Vec<Vec<u8>> = vks.iter().map(|k| { let (a, b) = (e.bytes(k), e.bytes(&SIG)); e.arr(vec![a, b]) }).collect();
    wits.push((e.uint(0), e.set(vk_items)));
    if has(Pos::NativeWit) || e.r.chance(1, 3) {
        let t = tgt();
        let s = e.native(4, if has(Pos::NativeWit) { Some(&t) } else { None });
        wits.push((e.uint(1), e.set(vec![s])));
    }
    if has(Pos::BootWit) || e.r.chance(1, 4) {
        let k = if has(Pos::BootWit) { VK_W } else { [0x32; 32] };
        let (a, b, c, d) = (e.bytes(&k), e.bytes(&SIG), e.bytes(&[0x34; 32]), e.bytes(&[0xa0]));
        let bw = e.arr(vec![a, b, c, d]);
        wits.push((e.uint(2), e.set(vec![bw])));
    }
    if has(Pos::PlutusBytes) || e.r.chance(1, 4) {
        let s = if has(Pos::PlutusBytes) { tgt().to_vec() } else { vec![0x4d, 1, 0, 0] };
        let b = e.bytes(&s);
        wits.push((e.uint(6), e.set(vec![b])));
    }
    if e.r.chance(1, 4) {
        let d = e.bytes(&[0x01]);
        wits.push((e.uint(4), e.set(vec![d])));
    }
    if has(Pos::Redeemer) || e.r.chance(1, 4) {
        let data = if has(Pos::Redeemer) { bytes(&tgt()) } else { uint(0) };
        let (t, i, mem, steps) = (e.uint(0), e.uint(0), e.uint(1000), e.uint(100_000));
        let units = e.arr(vec![mem, steps]);
        let red = e.arr(vec![t, i, data, units]);
        wits.push((e.uint(5), e.arr(vec![red])));
    }
    for i in (1..wits.len()).rev() {
        let j = e.r.below(i as u64 + 1) as usize;
        wits.swap(i, j);
    }
    let wits = e.map(wits);
    GenTx { body, wits, is_valid, resolved }
}

#[test]
fn grammar_fuzz_valid_encodings() {
    let n = iters(4000);
    let mut stats: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    let mut pallas_rejects_plain = 0u64;
    let mut max_time = Duration::ZERO;
    let all: Vec<Pos> = COVERED.iter().chain(EXCLUDED.iter()).chain(GAP.iter()).copied().collect();
    for i in 0..n {
        let exotic = i % 2 == 1;
        let mut e = Enc { r: Rng(0x9E37_79B9_7F4A_7C15 ^ (i.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1)), exotic };
        let mut place = BTreeSet::new();
        let class = e.r.below(4);
        match class {
            0 => {}
            1 => { place.insert(COVERED[e.r.below(COVERED.len() as u64) as usize]); }
            2 => { place.insert(EXCLUDED[e.r.below(EXCLUDED.len() as u64) as usize]); }
            _ => { place.insert(GAP[e.r.below(GAP.len() as u64) as usize]); }
        }
        if e.r.chance(1, 5) { place.insert(all[e.r.below(all.len() as u64) as usize]); }
        let tx = gen_tx(&mut e, &place);
        let (v, t) = match run(&tx.body, &tx.wits, tx.is_valid, &tgt(), &tx.resolved) {
            Ok(x) => x,
            Err(p) => { failures.push(format!("PANIC {p} body={} wits={}", hex::encode(&tx.body), hex::encode(&tx.wits))); continue; }
        };
        max_time = max_time.max(t);
        let covered = place.iter().any(|p| COVERED.contains(p));
        let label = if covered { "covered".to_string() } else if place.is_empty() { "none".to_string() } else { format!("{:?}", place.iter().collect::<Vec<_>>()) };
        let key = format!("{label} exotic={exotic}");
        *stats.entry(key).or_default().entry(format!("{v:?}")).or_default() += 1;
        let pallas = pallas_covered(&tx.body, &tx.wits, tx.is_valid, &tgt(), &tx.resolved);
        if !exotic && pallas.is_none() { pallas_rejects_plain += 1; }
        if covered && v == Verdict::NoUse {
            failures.push(format!("FALSE NO_USE place={place:?} valid={} body={} wits={}", tx.is_valid, hex::encode(&tx.body), hex::encode(&tx.wits)));
        }
        if !exotic && covered && v != Verdict::UseFound {
            failures.push(format!("plain covered not found: {v:?} place={place:?} body={} wits={}", hex::encode(&tx.body), hex::encode(&tx.wits)));
        }
        if pallas == Some(true) && !covered {
            failures.push(format!("oracle sees tgt() outside placement {place:?}"));
        }
        if pallas == Some(true) && v == Verdict::NoUse {
            failures.push(format!("PALLAS-CONFIRMED FALSE NO_USE place={place:?}"));
        }
    }
    for (k, m) in &stats { eprintln!("{k}: {m:?}"); }
    eprintln!("plain txs pallas rejected: {pallas_rejects_plain}; max call time {max_time:?}; failures {}", failures.len());
    for f in failures.iter().take(10) { eprintln!("{f}"); }
    assert!(failures.is_empty(), "{} failures", failures.len());
}

// -------------------------------------------------------- mutation fuzzer

fn hex_bytes(v: &Json) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

struct Seed {
    name: String,
    tx: Vec<u8>,
    target: [u8; 28],
    evidence: Vec<u8>,
    resolved: BTreeMap<OutPoint, Vec<u8>>,
    found: bool,
}

fn seeds() -> Vec<Seed> {
    let oracle: Json = serde_json::from_str(ORACLE).unwrap();
    let mut out = Vec::new();
    for v in oracle["vectors"].as_array().unwrap() {
        let tx = hex_bytes(&v["raw_tx_hex"]);
        let target: [u8; 28] = hex_bytes(&v["target_vkh"]).try_into().unwrap();
        let resolved: BTreeMap<OutPoint, Vec<u8>> = v["resolve"].as_object().unwrap().iter().map(|(r, a)| {
            let (id, ix) = r.split_once('#').unwrap();
            (OutPoint { tx_id: hex::decode(id).unwrap().try_into().unwrap(), index: ix.parse().unwrap() }, hex_bytes(a))
        }).collect();
        // evidence: the target itself, or a 32-byte window hashing to it (vkey witness)
        let evidence = if tx.windows(28).any(|w| w == target) {
            target.to_vec()
        } else {
            tx.windows(32).find(|w| blake224(w) == target).map(|w| w.to_vec()).unwrap_or_default()
        };
        let found = v["expected"]["verdict"] == "USE_FOUND";
        out.push(Seed { name: v["name"].as_str().unwrap().to_string(), tx, target, evidence, resolved, found });
    }
    // generated seeds covering every claimed surface, plain encodings
    for (i, p) in COVERED.iter().enumerate() {
        let mut e = Enc { r: Rng(0xabcdef ^ (i as u64 + 1) * 7919), exotic: false };
        let tx = gen_tx(&mut e, &BTreeSet::from([*p]));
        let env = [arr_head(4), tx.body.clone(), tx.wits.clone(), vec![if tx.is_valid { 0xf5 } else { 0xf4 }], null()].concat();
        let evidence = if matches!(p, Pos::VkeyWit | Pos::BootWit) { VK_W.to_vec() } else { tgt().to_vec() };
        out.push(Seed { name: format!("gen_{p:?}"), tx: env, target: tgt(), evidence, resolved: tx.resolved, found: true });
    }
    out
}

const INTERESTING: [u8; 20] = [0x00, 0x18, 0x19, 0x1a, 0x1b, 0x40, 0x58, 0x5f, 0x7f, 0x80, 0x9f, 0xa0, 0xbf, 0xc0, 0xd8, 0xd9, 0xf6, 0xf7, 0xff, 0xfb];

fn mutate(r: &mut Rng, tx: &[u8], donors: &[Vec<u8>]) -> Vec<u8> {
    let mut m = tx.to_vec();
    let rounds = 1 + r.below(3);
    for _ in 0..rounds {
        if m.is_empty() { m.push(0xa0); }
        let at = r.below(m.len() as u64) as usize;
        match r.below(8) {
            0 => m[at] ^= 1 << r.below(8),
            1 => m[at] = INTERESTING[r.below(INTERESTING.len() as u64) as usize],
            2 => m.insert(at, INTERESTING[r.below(INTERESTING.len() as u64) as usize]),
            3 => { let n = (1 + r.below(4) as usize).min(m.len() - at); m.drain(at..at + n); }
            4 => m.truncate(at),
            5 => { let end = (at + 1 + r.below(16) as usize).min(m.len()); let piece = m[at..end].to_vec(); let to = r.below(m.len() as u64) as usize; m.splice(to..to, piece); }
            6 => { let d = &donors[r.below(donors.len() as u64) as usize]; if !d.is_empty() { let s = r.below(d.len() as u64) as usize; let e = (s + 1 + r.below(24) as usize).min(d.len()); m.splice(at..at, d[s..e].iter().copied()); } }
            _ => { let n = r.below(3) as usize + 1; for _ in 0..n { m.insert(at, 0xff); } }
        }
    }
    m
}

#[test]
fn mutation_fuzz_never_panics_and_triage_no_use() {
    let seeds = seeds();
    let donors: Vec<Vec<u8>> = seeds.iter().map(|s| s.tx.clone()).collect();
    let per = iters(4000);
    let mut r = Rng(0x1234_5678_9abc_def1);
    let mut panics = Vec::new();
    let mut confirmed = Vec::new();
    let mut suspicious: BTreeMap<String, u64> = BTreeMap::new();
    let mut examples: Vec<String> = Vec::new();
    let mut total = 0u64;
    let mut max_time = Duration::ZERO;
    for s in &seeds {
        for _ in 0..per {
            let m = mutate(&mut r, &s.tx, &donors);
            let (body, wits, valid) = envelope(&m).unwrap_or((m.as_slice(), m.as_slice(), true));
            total += 1;
            match run(body, wits, valid, &s.target, &s.resolved) {
                Err(p) => panics.push(format!("{}: {p} tx={}", s.name, hex::encode(&m))),
                Ok((v, t)) => {
                    max_time = max_time.max(t);
                    let oracle = pallas_covered(body, wits, valid, &s.target, &s.resolved);
                    if oracle == Some(true) && v == Verdict::NoUse {
                        confirmed.push(format!("{}: tx={}", s.name, hex::encode(&m)));
                    }
                    if s.found && v == Verdict::NoUse && !s.evidence.is_empty() && m.windows(s.evidence.len()).any(|w| w == s.evidence) {
                        let k = format!("{} pallas={:?}", s.name, oracle);
                        *suspicious.entry(k).or_default() += 1;
                        examples.push(format!("{} oracle={oracle:?} split={} tx={} ev={}", s.name, envelope(&m).is_some(), hex::encode(&m), hex::encode(&s.evidence)));
                    }
                }
            }
        }
    }
    eprintln!("mutants run: {total}; max call time {max_time:?}");
    eprintln!("panics: {}", panics.len());
    for p in panics.iter().take(5) { eprintln!("  {p}"); }
    eprintln!("pallas-confirmed false NO_USE: {}", confirmed.len());
    for c in confirmed.iter().take(10) { eprintln!("  {c}"); }
    eprintln!("NO_USE with target evidence still present (triage): {suspicious:?}");
    let path = std::env::var("RT_FUZZ_OUT").unwrap_or_else(|_| "/dev/null".into());
    std::fs::write(&path, examples.join("\n")).ok();
    assert!(panics.is_empty(), "panics found");
    assert!(confirmed.is_empty(), "pallas-confirmed false NO_USE found");
}

// ------------------------------------------------- stack / time / memory

fn small_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new().stack_size(128 * 1024).spawn(f).unwrap().join().expect("no stack overflow");
}

#[test]
fn deep_nesting_on_small_stack_is_bounded() {
    small_stack(|| {
        let depth = 1_000_000;
        // deep native script (deep walk): exceeds budget -> incomplete
        let deep: Vec<u8> = [vec![0x82, 0x01, 0x81].repeat(depth), sig_clause(&W)].concat();
        let wits = encode_map(&[(1, set(&[deep]))]);
        let body = encode_map(&base_body());
        let t = Instant::now();
        let (v, _) = run(&body, &wits, true, &W, &base_resolver()).unwrap();
        eprintln!("1M-deep native script: {v:?} in {:?}", t.elapsed());
        assert_ne!(v, Verdict::NoUse);
        // deep indefinite nesting in an unread key (minicbor skip)
        let junk: Vec<u8> = [vec![0x9f; depth], vec![0xff; depth]].concat();
        let body = encode_map(&with(base_body(), 9, junk));
        let t = Instant::now();
        let (v, _) = run(&body, &encode_map(&base_wits()), true, &W, &base_resolver()).unwrap();
        eprintln!("1M-deep indefinite junk in key 9: {v:?} in {:?}", t.elapsed());
        // deep definite nesting in key 6 (deep walk over update)
        let junk: Vec<u8> = [vec![0x81; depth], vec![0x00]].concat();
        let body = encode_map(&with(base_body(), 6, junk));
        let t = Instant::now();
        let (v, _) = run(&body, &encode_map(&base_wits()), true, &W, &base_resolver()).unwrap();
        eprintln!("1M-deep definite in key 6: {v:?} in {:?}", t.elapsed());
        assert_eq!(v, Verdict::Incomplete);
        // mixed deep nesting for skip's stack mode
        let junk: Vec<u8> = [vec![0x82, 0x9f].repeat(depth / 2), vec![0xff, 0x00].repeat(depth / 2)].concat();
        let body = encode_map(&with(base_body(), 9, junk));
        let t = Instant::now();
        let (v, _) = run(&body, &encode_map(&base_wits()), true, &W, &base_resolver()).unwrap();
        eprintln!("mixed deep in key 9: {v:?} in {:?}", t.elapsed());
    });
}

#[test]
fn large_inputs_scale_linearly() {
    for mb in [1usize, 4, 16] {
        let n = mb * 1024 * 1024;
        // many zero-length chunks in one indefinite byte string inside a cert (deep walk joins chunks)
        let chunks: Vec<u8> = [vec![0x5f], vec![0x40; n], vec![0xff]].concat();
        let body = encode_map(&with(base_body(), 4, set(&[arr(&[uint(0), arr(&[uint(0), chunks])])])));
        let t = Instant::now();
        let (v, _) = run(&body, &encode_map(&base_wits()), true, &W, &base_resolver()).unwrap();
        let chunk_t = t.elapsed();
        // one huge definite byte string leaf in a native script (copied into a Vec)
        let big = [vec![0x82, 0x00], bytes(&vec![0x11; n])].concat();
        let wits = encode_map(&[(1, set(&[big]))]);
        let t = Instant::now();
        let (v2, _) = run(&encode_map(&base_body()), &wits, true, &W, &base_resolver()).unwrap();
        let big_t = t.elapsed();
        // many outputs with tiny native ref scripts (shared budget)
        let out = output_with_ref(&ent_addr(&OTHER), 0, &sig_clause(&OTHER));
        let count = n / out.len();
        let body = encode_map(&[(0, set(&[outpoint(TXID, 0)])), (1, [head(4, count as u64), out.repeat(count)].concat()), (2, uint(1))]);
        let t = Instant::now();
        let (v3, _) = run(&body, &encode_map(&base_wits()), true, &W, &base_resolver()).unwrap();
        eprintln!("{mb} MiB: chunked {v:?} {chunk_t:?} | big leaf {v2:?} {big_t:?} | {count} ref-script outputs {v3:?} {:?}", t.elapsed());
    }
}

#[test]
fn duplicate_keys_get_fresh_budgets_but_stay_linear() {
    // 200 duplicate key-6 updates and 200 duplicate key-4 cert sets, each just under
    // its own 100k budget: every occurrence is walked in full, time stays linear.
    let update = arr(&[[head(4, 99_990), vec![0x00; 99_990]].concat(), uint(1)]);
    let cert = set(&[[arr_head(2), uint(0), arr(&[uint(0), [head(4, 99_990), vec![0x00; 99_990]].concat()])].concat()]);
    for copies in [50usize, 200] {
        let mut entries = base_body();
        for _ in 0..copies {
            entries.push((6, update.clone()));
            entries.push((4, cert.clone()));
        }
        let body = encode_map(&entries);
        let t = Instant::now();
        let (v, _) = run(&body, &encode_map(&base_wits()), true, &W, &base_resolver()).unwrap();
        eprintln!("{copies} duplicate key-6/key-4 pairs, {} MiB body: {v:?} in {:?}", body.len() >> 20, t.elapsed());
    }
}
