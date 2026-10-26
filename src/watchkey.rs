//! Watched transaction credentials and fail-closed scan coverage.

use alloc::collections::BTreeSet;
use minicbor::Decoder;
use minicbor::data::Type;

use crate::hash::blake2b224;
use crate::utxo::{
    OutPoint, decode_outpoint, decode_single_output, input_set_len, read_bytes, seq_has_next,
};

/// Payment key/script hash (28 bytes) of a Shelley address, or `None` when the
/// address carries no payment credential. Addresses whose header nibble is
/// 0..=7 carry one at bytes `[1..29]`; a reward address (nibble 14/15), a Byron
/// address (nibble 8), and any slice shorter than 29 bytes yield `None`.
pub fn payment_credential(address: &[u8]) -> Option<[u8; 28]> {
    if address.len() < 29 {
        return None;
    }
    if address[0] >> 4 <= 7 {
        address[1..29].try_into().ok()
    } else {
        None
    }
}

/// Stake key/script hash (28 bytes) of a base address — header nibble 0..=3,
/// which carries the stake credential at bytes `[29..57]`. Any other address
/// type, or a slice shorter than 57 bytes, yields `None`.
pub fn stake_credential(address: &[u8]) -> Option<[u8; 28]> {
    if address.len() < 57 {
        return None;
    }
    if address[0] >> 4 <= 3 {
        address[29..57].try_into().ok()
    } else {
        None
    }
}

/// Credential (28 bytes) of a reward account: a stake address of a header byte
/// followed by the 28-byte credential, read at `[1..29]`. Callers pass values a
/// surface already fixes as reward accounts (withdrawal keys, a proposal's
/// deposit-return account), so this does not re-check the header; a slice
/// shorter than 29 bytes yields `None`.
pub fn reward_credential(reward_account: &[u8]) -> Option<[u8; 28]> {
    if reward_account.len() >= 29 {
        reward_account[1..29].try_into().ok()
    } else {
        None
    }
}

/// The result of scanning a transaction surface for a watched key: whether a
/// watched credential was found, and whether coverage was provably complete. An
/// incomplete scan — a body shape the walker could not fully decode — must never
/// read as "no use"; the verdict refuses instead (malformed => INCOMPLETE, not
/// NO_USE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan {
    /// A watched key hash appeared in this surface.
    pub found: bool,
    /// Every credential-bearing field of this surface decoded; nothing skipped.
    pub complete: bool,
}

/// Payment credentials of regular inputs for valid transactions, collateral otherwise.
/// Unresolved or unsupported addresses and resolver errors leave coverage incomplete.
pub fn input_use<'a>(
    body: &[u8],
    is_valid: bool,
    watched: &BTreeSet<[u8; 28]>,
    mut resolve: impl FnMut(&OutPoint) -> Result<Option<&'a [u8]>, ()>,
) -> Scan {
    let consumed = if is_valid { 0 } else { 13 };
    scan_map(body, |key, d, scan| {
        if key != consumed {
            return d.skip().map_err(|_| ());
        }
        let len = input_set_len(d).map_err(|_| ())?;
        let mut i = 0;
        while seq_has_next(d, len, i).map_err(|_| ())? {
            let input = decode_outpoint(d).map_err(|_| ())?;
            match resolve(&input) {
                Ok(Some(address)) => match payment_credential(address) {
                    Some(credential) => scan.found |= watched.contains(&credential),
                    None => scan.complete = false,
                },
                Ok(None) | Err(()) => scan.complete = false,
            }
            i += 1;
        }
        Ok(())
    })
}

fn scan_map(
    data: &[u8],
    mut field: impl FnMut(u64, &mut Decoder<'_>, &mut Scan) -> Result<(), ()>,
) -> Scan {
    let mut d = Decoder::new(data);
    let mut scan = Scan {
        found: false,
        complete: true,
    };
    let result = (|| {
        let len = d.map().map_err(|_| ())?;
        let mut i = 0u64;
        while seq_has_next(&mut d, len, i).map_err(|_| ())? {
            let key = d.u64().map_err(|_| ())?;
            field(key, &mut d, &mut scan)?;
            i += 1;
        }
        Ok::<(), ()>(())
    })();
    if result.is_err() {
        scan.complete = false;
    }
    scan
}

/// Does a watched key appear as a required signer — body key 14, a
/// `set<addr_keyhash>` (tag-258 or a bare array) of 28-byte key hashes carried in
/// clear, so no hashing is needed. Reuses the crate's own body-map and set
/// cursor helpers. Any field that does not fully decode — a non-map body, a
/// key-14 value that is not a set, or a signer that is not a 28-byte hash —
/// yields `complete = false`, never a clean `found = false`.
pub fn required_signer_use(body: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(body, |key, d, scan| {
        if key == 14 {
            let set_len = match input_set_len(d) {
                Ok(set_len) => set_len,
                Err(_) => return Err(()),
            };
            let mut j = 0u64;
            loop {
                match seq_has_next(d, set_len, j) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                let bytes = match read_bytes(d) {
                    Ok(bytes) => bytes,
                    Err(_) => return Err(()),
                };
                match <[u8; 28]>::try_from(bytes.as_slice()) {
                    Ok(key_hash) => {
                        if watched.contains(&key_hash) {
                            scan.found = true;
                        }
                    }
                    Err(_) => return Err(()),
                }
                j += 1;
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Whether a raw address's payment OR stake credential is watched, via the
/// credential parsers above (Byron and reward addresses yield neither).
fn address_watched(address: &[u8], watched: &BTreeSet<[u8; 28]>) -> bool {
    payment_credential(address).is_some_and(|c| watched.contains(&c))
        || stake_credential(address).is_some_and(|c| watched.contains(&c))
}

/// Reads the byte string at a credential-bearing position.
fn credential_watched(d: &mut Decoder<'_>, watched: &BTreeSet<[u8; 28]>) -> Result<bool, ()> {
    match d.datatype().map_err(|_| ())? {
        Type::Bytes => {
            let bytes = read_bytes(d).map_err(|_| ())?;
            Ok(<[u8; 28]>::try_from(bytes.as_slice())
                .map(|h| watched.contains(&h))
                .unwrap_or(false))
        }
        _ => Err(()),
    }
}

/// Reads the byte string at a reward-account position.
fn reward_account_watched(d: &mut Decoder<'_>, watched: &BTreeSet<[u8; 28]>) -> Result<bool, ()> {
    match d.datatype().map_err(|_| ())? {
        Type::Bytes => {
            let account = read_bytes(d).map_err(|_| ())?;
            Ok(reward_credential(&account).is_some_and(|c| watched.contains(&c)))
        }
        _ => Err(()),
    }
}

/// Does a watched key appear in a transaction output -- a body-1 output or the
/// body-16 collateral return, both decoded by the crate's own decode_single_output
/// for the output's payment or stake credential. Body-1 is a list of
/// transaction_outputs; the body-16 collateral return is a single one.
pub fn output_use(body: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(body, |key, d, scan| {
        if key == 1 {
            let out_len = match d.array() {
                Ok(out_len) => out_len,
                Err(_) => return Err(()),
            };
            let mut j = 0u64;
            loop {
                match seq_has_next(d, out_len, j) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                match decode_single_output(d) {
                    Ok((address, _, _)) => {
                        if address_watched(&address, watched) {
                            scan.found = true;
                        }
                    }
                    Err(_) => return Err(()),
                }
                j += 1;
            }
        } else if key == 16 {
            match decode_single_output(d) {
                Ok((address, _, _)) => {
                    if address_watched(&address, watched) {
                        scan.found = true;
                    }
                }
                Err(_) => return Err(()),
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Does a watched key appear as a withdrawal reward account -- body key 5, a map
/// from a reward_account to coin; the 28-byte credential is bytes [1..29] of each
/// account key (the `reward_credential` parser above).
pub fn withdrawal_use(body: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(body, |key, d, scan| {
        if key == 5 {
            let wd_len = match d.map() {
                Ok(wd_len) => wd_len,
                Err(_) => return Err(()),
            };
            let mut j = 0u64;
            loop {
                match seq_has_next(d, wd_len, j) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                match reward_account_watched(d, watched) {
                    Ok(true) => scan.found = true,
                    Ok(false) => {}
                    Err(_) => return Err(()),
                }
                if d.skip().is_err() {
                    return Err(());
                }
                j += 1;
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Does a watched key appear as a voter -- body key 19, a map whose keys are
/// `[voter_type, 28-byte key hash]`. The key hash is element 1 of each voter.
pub fn voting_use(body: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(body, |key, d, scan| {
        if key == 19 {
            let v_len = match d.map() {
                Ok(v_len) => v_len,
                Err(_) => return Err(()),
            };
            let mut j = 0u64;
            loop {
                match seq_has_next(d, v_len, j) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                let voter_len = match d.array() {
                    Ok(voter_len) => voter_len,
                    Err(_) => return Err(()),
                };
                let mut k = 0u64;
                loop {
                    match seq_has_next(d, voter_len, k) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(_) => return Err(()),
                    }
                    if k == 1 {
                        match credential_watched(d, watched) {
                            Ok(true) => scan.found = true,
                            Ok(false) => {}
                            Err(_) => return Err(()),
                        }
                    } else if d.skip().is_err() {
                        return Err(());
                    }
                    k += 1;
                }
                if k < 2 {
                    return Err(());
                }
                if d.skip().is_err() {
                    return Err(());
                }
                j += 1;
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Does a watched key appear as a proposal's deposit-return reward account -- body
/// key 20, a set of `[deposit, reward_account, gov_action, anchor]`; the 28-byte
/// credential is bytes [1..29] of element 1.
pub fn proposal_use(body: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(body, |key, d, scan| {
        if key == 20 {
            let p_len = match input_set_len(d) {
                Ok(p_len) => p_len,
                Err(_) => return Err(()),
            };
            let mut j = 0u64;
            loop {
                match seq_has_next(d, p_len, j) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                let prop_len = match d.array() {
                    Ok(prop_len) => prop_len,
                    Err(_) => return Err(()),
                };
                let mut k = 0u64;
                loop {
                    match seq_has_next(d, prop_len, k) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(_) => return Err(()),
                    }
                    if k == 1 {
                        match reward_account_watched(d, watched) {
                            Ok(true) => scan.found = true,
                            Ok(false) => {}
                            Err(_) => return Err(()),
                        }
                    } else if d.skip().is_err() {
                        return Err(());
                    }
                    k += 1;
                }
                if k < 2 {
                    return Err(());
                }
                j += 1;
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Reads one verification-key witness `[vkey (32 bytes), signature, ...]` and
/// reports whether BLAKE2b-224 of its 32-byte vkey is watched. Elements after the
/// vkey are skipped; a non-bytes vkey leaves coverage incomplete.
fn witness_vkey_watched(d: &mut Decoder<'_>, watched: &BTreeSet<[u8; 28]>) -> Result<bool, ()> {
    let len = d.array().map_err(|_| ())?;
    let mut hit = false;
    let mut k = 0u64;
    loop {
        match seq_has_next(d, len, k) {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => return Err(()),
        }
        if k == 0 {
            if d.datatype().map_err(|_| ())? != Type::Bytes {
                return Err(());
            }
            let vkey = read_bytes(d).map_err(|_| ())?;
            if vkey.len() == 32 && watched.contains(&blake2b224(&vkey)) {
                hit = true;
            }
        } else {
            d.skip().map_err(|_| ())?;
        }
        k += 1;
    }
    Ok(hit)
}

/// Does a watched key appear as a verification-key witness -- witness-set key 0
/// (vkey witnesses) or key 2 (bootstrap witnesses), each a set of
/// `[vkey (32 bytes), signature, ...]`. The 28-byte key hash is BLAKE2b-224 of the
/// 32-byte vkey (Option A): the one watched-key surface that hashes rather than
/// reading a credential in clear.
pub fn witness_use(witnesses: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(witnesses, |key, d, scan| {
        if key == 0 || key == 2 {
            let set_len = match input_set_len(d) {
                Ok(set_len) => set_len,
                Err(_) => return Err(()),
            };
            let mut j = 0u64;
            loop {
                match seq_has_next(d, set_len, j) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                match witness_vkey_watched(d, watched) {
                    Ok(true) => scan.found = true,
                    Ok(false) => {}
                    Err(_) => return Err(()),
                }
                j += 1;
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Node budget and recursion depth for the deep walk. Real certificates, native
/// scripts and parameter updates are far smaller; exceeding either leaves coverage
/// unprovable, so the scan reports incomplete rather than reading absence.
const WALK_BUDGET: u32 = 100_000;
const WALK_DEPTH: u32 = 64;

/// Element count the Conway CDDL fixes for each modelled certificate kind. An
/// unknown kind, or a known kind of a different arity, marks the scan incomplete;
/// a future cert variant cannot read as absence. Mirrors the reference table.
fn certificate_arity(kind: u64) -> Option<u64> {
    match kind {
        0 | 1 => Some(2),
        2 | 4 | 7 | 8 | 9 | 14 | 15 | 17 | 18 => Some(3),
        3 => Some(10),
        10 | 11 | 12 | 16 => Some(4),
        13 => Some(5),
        _ => None,
    }
}

/// Records matches as leaves decode so a later malformed child cannot erase them.
fn collect_watched(
    d: &mut Decoder<'_>,
    watched: &BTreeSet<[u8; 28]>,
    budget: &mut u32,
    depth: u32,
    scan: &mut Scan,
) -> Result<(), ()> {
    if depth == 0 || *budget == 0 {
        scan.complete = false;
        d.skip().map_err(|_| ())?;
        return Ok(());
    }
    *budget -= 1;
    match d.datatype().map_err(|_| ())? {
        Type::Bytes => {
            let bytes = read_bytes(d).map_err(|_| ())?;
            let hit = match bytes.len() {
                28 => <[u8; 28]>::try_from(bytes.as_slice())
                    .map(|h| watched.contains(&h))
                    .unwrap_or(false),
                29 => reward_credential(&bytes).is_some_and(|c| watched.contains(&c)),
                _ => false,
            };
            scan.found |= hit;
            Ok(())
        }
        Type::Array | Type::ArrayIndef => {
            let len = d.array().map_err(|_| ())?;
            let mut i = 0u64;
            loop {
                match seq_has_next(d, len, i) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                collect_watched(d, watched, budget, depth - 1, scan)?;
                i += 1;
            }
            Ok(())
        }
        Type::Map | Type::MapIndef => {
            let len = d.map().map_err(|_| ())?;
            let mut i = 0u64;
            loop {
                match seq_has_next(d, len, i) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                collect_watched(d, watched, budget, depth - 1, scan)?;
                collect_watched(d, watched, budget, depth - 1, scan)?;
                i += 1;
            }
            Ok(())
        }
        Type::Tag => {
            d.tag().map_err(|_| ())?;
            collect_watched(d, watched, budget, depth - 1, scan)
        }
        _ => {
            d.skip().map_err(|_| ())?;
            Ok(())
        }
    }
}

/// Does a watched key appear in a certificate -- body key 4, a set of certs. Each
/// cert `[kind, ...]` has its kind/arity checked (an unknown kind or a wrong arity
/// leaves coverage incomplete) and its elements deep-walked for 28-byte
/// credentials and 29-byte reward accounts (stake / DRep / committee credentials,
/// pool owners and operators).
pub fn certificate_use(body: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(body, |key, d, scan| {
        if key == 4 {
            let set_len = match input_set_len(d) {
                Ok(set_len) => set_len,
                Err(_) => return Err(()),
            };
            let mut budget = WALK_BUDGET;
            let mut j = 0u64;
            loop {
                match seq_has_next(d, set_len, j) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                let cert_len = match d.array() {
                    Ok(cert_len) => cert_len,
                    Err(_) => return Err(()),
                };
                let mut kind: Option<u64> = None;
                let mut k = 0u64;
                loop {
                    match seq_has_next(d, cert_len, k) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(_) => return Err(()),
                    }
                    if k == 0
                        && matches!(
                            d.datatype(),
                            Ok(Type::U8 | Type::U16 | Type::U32 | Type::U64)
                        )
                    {
                        kind = match d.u64() {
                            Ok(kind) => Some(kind),
                            Err(_) => return Err(()),
                        };
                    } else {
                        collect_watched(d, watched, &mut budget, WALK_DEPTH, scan)?;
                    }
                    k += 1;
                }
                match kind.map(certificate_arity) {
                    Some(Some(arity)) => {
                        if cert_len != Some(arity) {
                            scan.complete = false;
                        }
                    }
                    _ => scan.complete = false,
                }
                j += 1;
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Does a watched key appear in a native script of the witness set -- witness-set
/// key 1, a set of native scripts whose `sig` clauses carry 28-byte key hashes in
/// clear. Malformed CBOR or an exhausted walk budget leaves coverage incomplete.
pub fn native_script_use(witnesses: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(witnesses, |key, d, scan| {
        if key == 1 {
            let set_len = match input_set_len(d) {
                Ok(set_len) => set_len,
                Err(_) => return Err(()),
            };
            let mut budget = WALK_BUDGET;
            let mut j = 0u64;
            loop {
                match seq_has_next(d, set_len, j) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(()),
                }
                collect_watched(d, watched, &mut budget, WALK_DEPTH, scan)?;
                j += 1;
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Does a watched key appear in the protocol-parameter update -- body key 6, whose
/// genesis-delegate key hashes are 28-byte leaves. The update value is deep-walked;
/// malformed CBOR or an exhausted walk budget leaves coverage incomplete.
pub fn update_use(body: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(body, |key, d, scan| {
        if key == 6 {
            let mut budget = WALK_BUDGET;
            collect_watched(d, watched, &mut budget, WALK_DEPTH, scan)?;
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAY: [u8; 28] = [0xA1; 28];
    const STK: [u8; 28] = [0xA2; 28];
    const NAT: [u8; 28] = [0xA3; 28];
    const VK: [u8; 32] = [0xB1; 32];
    const SIG: [u8; 64] = [0xB2; 64];
    const OTHER: [u8; 28] = [0xC9; 28];
    // BLAKE2b-224 of VK, precomputed: the witness surface hashes the 32-byte vkey.
    const VK_HASH: [u8; 28] = [
        0x7c, 0x06, 0x4e, 0xf9, 0x8a, 0xbe, 0xb5, 0xc3, 0xca, 0x85, 0xfa, 0xd6, 0x25, 0x61, 0x27,
        0xb2, 0xc9, 0xdd, 0xae, 0x79, 0xe2, 0x32, 0xe4, 0xf2, 0x7c, 0x45, 0x5f, 0x41,
    ];

    fn with_header(header: u8, body: &[&[u8]]) -> Vec<u8> {
        let mut a = vec![header];
        for part in body {
            a.extend_from_slice(part);
        }
        a
    }

    #[test]
    fn enterprise_address_has_payment_only() {
        let addr = with_header(0x60, &[&PAY]); // nibble 6
        assert_eq!(payment_credential(&addr), Some(PAY));
        assert_eq!(stake_credential(&addr), None);
    }

    #[test]
    fn base_address_has_payment_and_stake() {
        let addr = with_header(0x00, &[&PAY, &STK]); // nibble 0
        assert_eq!(payment_credential(&addr), Some(PAY));
        assert_eq!(stake_credential(&addr), Some(STK));
    }

    #[test]
    fn reward_address_has_no_payment_but_a_reward_credential() {
        let addr = with_header(0xe0, &[&STK]); // nibble 14
        assert_eq!(payment_credential(&addr), None);
        assert_eq!(reward_credential(&addr), Some(STK));
    }

    #[test]
    fn byron_address_yields_nothing() {
        let addr = with_header(0x82, &[&[0u8; 40]]); // nibble 8
        assert_eq!(payment_credential(&addr), None);
        assert_eq!(stake_credential(&addr), None);
    }

    #[test]
    fn short_slices_never_panic_and_yield_none() {
        for len in 0..29usize {
            let addr = vec![0x60u8; len];
            assert_eq!(payment_credential(&addr), None);
            assert_eq!(stake_credential(&addr), None);
            assert_eq!(reward_credential(&addr), None);
        }
    }

    fn watched_set(keys: &[[u8; 28]]) -> BTreeSet<[u8; 28]> {
        keys.iter().copied().collect()
    }

    /// A minimal Conway body `{14: set<addr_keyhash>}` with one 28-byte signer,
    /// hand-encoded so the test does not depend on an encoder's tag API. Bytes:
    /// `a1` map(1), `0e` key 14, optional `d9 0102` tag-258, `81` array(1),
    /// `58 1c` bytes(28), then the hash.
    fn body_with_signer(sig: &[u8; 28], tagged: bool) -> Vec<u8> {
        let mut b = vec![0xa1, 0x0e];
        if tagged {
            b.extend_from_slice(&[0xd9, 0x01, 0x02]);
        }
        b.extend_from_slice(&[0x81, 0x58, 0x1c]);
        b.extend_from_slice(sig);
        b
    }

    #[test]
    fn watched_required_signer_is_found_bare_and_tagged() {
        let w = watched_set(&[PAY]);
        assert!(required_signer_use(&body_with_signer(&PAY, false), &w).found);
        assert!(required_signer_use(&body_with_signer(&PAY, true), &w).found);
        assert!(required_signer_use(&body_with_signer(&PAY, false), &w).complete);
    }

    #[test]
    fn absent_required_signer_is_not_found_but_complete() {
        let s = required_signer_use(&body_with_signer(&PAY, false), &watched_set(&[STK]));
        assert!(!s.found && s.complete);
    }

    #[test]
    fn malformed_body_is_incomplete_never_a_clean_no_use() {
        // Map header declares one entry, key 14 present, its value truncated away.
        let s = required_signer_use(&[0xa1, 0x0e], &watched_set(&[PAY]));
        assert!(!s.complete);
    }

    /// `{1: [output]}` = a1 01 81 <output>.
    fn body_one_output(output: &[u8]) -> Vec<u8> {
        let mut b = vec![0xa1, 0x01, 0x81];
        b.extend_from_slice(output);
        b
    }

    /// Legacy output `[address, 1]` = 82 <address> 01.
    fn legacy_output(address: &[u8]) -> Vec<u8> {
        let mut o = vec![0x82];
        o.extend_from_slice(address);
        o.push(0x01);
        o
    }

    /// Enterprise address byte string: 58 1d (bytes, len 29) 60 (header) + 28-byte cred.
    fn enterprise_addr(cred: &[u8; 28]) -> Vec<u8> {
        let mut a = vec![0x58, 0x1d, 0x60];
        a.extend_from_slice(cred);
        a
    }

    /// Base address byte string: 58 39 (bytes, len 57) 00 (header) + 28 payment + 28 stake.
    fn base_addr(pay: &[u8; 28], stk: &[u8; 28]) -> Vec<u8> {
        let mut a = vec![0x58, 0x39, 0x00];
        a.extend_from_slice(pay);
        a.extend_from_slice(stk);
        a
    }

    #[test]
    fn watched_output_payment_credential_is_found() {
        let body = body_one_output(&legacy_output(&enterprise_addr(&PAY)));
        assert!(output_use(&body, &watched_set(&[PAY])).found);
    }

    #[test]
    fn watched_output_stake_credential_is_found() {
        let body = body_one_output(&legacy_output(&base_addr(&PAY, &STK)));
        assert!(output_use(&body, &watched_set(&[STK])).found);
    }

    #[test]
    fn unwatched_output_is_not_found_but_complete() {
        let s = output_use(
            &body_one_output(&legacy_output(&enterprise_addr(&PAY))),
            &watched_set(&[NAT]),
        );
        assert!(!s.found && s.complete);
    }

    #[test]
    fn malformed_output_is_incomplete() {
        // {1: [5]} — an output that is neither an array nor a map.
        let s = output_use(&[0xa1, 0x01, 0x81, 0x05], &watched_set(&[PAY]));
        assert!(!s.complete);
    }

    /// Reward account byte string: 58 1d (bytes len 29) e0 (stake-key header) + 28-byte cred.
    fn reward_account(cred: &[u8; 28]) -> Vec<u8> {
        let mut a = vec![0x58, 0x1d, 0xe0];
        a.extend_from_slice(cred);
        a
    }

    /// `{5: {<reward_account>: 0}}` = a1 05 a1 <account> 00.
    fn body_one_withdrawal(account: &[u8]) -> Vec<u8> {
        let mut b = vec![0xa1, 0x05, 0xa1];
        b.extend_from_slice(account);
        b.push(0x00);
        b
    }

    /// `{19: {[2, <28-byte key hash>]: {}}}` = a1 13 a1 82 02 58 1c <hash> a0.
    fn body_one_voter(key_hash: &[u8; 28]) -> Vec<u8> {
        let mut b = vec![0xa1, 0x13, 0xa1, 0x82, 0x02, 0x58, 0x1c];
        b.extend_from_slice(key_hash);
        b.push(0xa0);
        b
    }

    /// `{20: [[0, <reward_account>, 0, null]]}` = a1 14 81 84 00 <account> 00 f6.
    fn body_one_proposal(account: &[u8]) -> Vec<u8> {
        let mut b = vec![0xa1, 0x14, 0x81, 0x84, 0x00];
        b.extend_from_slice(account);
        b.extend_from_slice(&[0x00, 0xf6]);
        b
    }

    #[test]
    fn watched_withdrawal_credential_is_found() {
        let body = body_one_withdrawal(&reward_account(&STK));
        assert!(withdrawal_use(&body, &watched_set(&[STK])).found);
    }

    #[test]
    fn unwatched_withdrawal_is_not_found_but_complete() {
        let s = withdrawal_use(
            &body_one_withdrawal(&reward_account(&STK)),
            &watched_set(&[PAY]),
        );
        assert!(!s.found && s.complete);
    }

    #[test]
    fn malformed_withdrawal_is_incomplete() {
        // {5: 5} -- withdrawals not a map.
        assert!(!withdrawal_use(&[0xa1, 0x05, 0x05], &watched_set(&[STK])).complete);
    }

    #[test]
    fn watched_voter_credential_is_found() {
        assert!(voting_use(&body_one_voter(&STK), &watched_set(&[STK])).found);
    }

    #[test]
    fn unwatched_voter_is_not_found_but_complete() {
        let s = voting_use(&body_one_voter(&STK), &watched_set(&[PAY]));
        assert!(!s.found && s.complete);
    }

    #[test]
    fn malformed_voter_is_incomplete() {
        // {19: 5} -- voters not a map.
        assert!(!voting_use(&[0xa1, 0x13, 0x05], &watched_set(&[STK])).complete);
    }

    #[test]
    fn watched_proposal_reward_account_is_found() {
        let body = body_one_proposal(&reward_account(&STK));
        assert!(proposal_use(&body, &watched_set(&[STK])).found);
    }

    #[test]
    fn unwatched_proposal_is_not_found_but_complete() {
        let s = proposal_use(
            &body_one_proposal(&reward_account(&STK)),
            &watched_set(&[PAY]),
        );
        assert!(!s.found && s.complete);
    }

    #[test]
    fn malformed_proposal_is_incomplete() {
        // {20: 5} -- proposals not a set/array.
        assert!(!proposal_use(&[0xa1, 0x14, 0x05], &watched_set(&[STK])).complete);
    }

    /// `{slot: [[vkey(32), sig(64)]]}` = a1 <slot> 81 82 58 20 <vkey> 58 40 <sig>.
    fn witness_map(slot: u8) -> Vec<u8> {
        let mut w = vec![0xa1, slot, 0x81, 0x82, 0x58, 0x20];
        w.extend_from_slice(&VK);
        w.extend_from_slice(&[0x58, 0x40]);
        w.extend_from_slice(&SIG);
        w
    }

    #[test]
    fn watched_vkey_witness_is_found() {
        assert!(witness_use(&witness_map(0x00), &watched_set(&[VK_HASH])).found);
    }

    #[test]
    fn unwatched_vkey_witness_is_not_found_but_complete() {
        let s = witness_use(&witness_map(0x00), &watched_set(&[OTHER]));
        assert!(!s.found && s.complete);
    }

    #[test]
    fn watched_bootstrap_witness_is_found() {
        assert!(witness_use(&witness_map(0x02), &watched_set(&[VK_HASH])).found);
    }

    #[test]
    fn malformed_witness_is_incomplete() {
        // {0: 5} -- vkey witnesses not an array.
        assert!(!witness_use(&[0xa1, 0x00, 0x05], &watched_set(&[VK_HASH])).complete);
    }

    /// `{4: [[0, [0, <28-byte cred>]]]}` -- a stake-registration cert (kind 0) whose
    /// stake credential is `[0, addr_keyhash]`. = a1 04 81 82 00 82 00 58 1c <cred>.
    fn body_one_stake_cert(cred: &[u8; 28]) -> Vec<u8> {
        let mut b = vec![0xa1, 0x04, 0x81, 0x82, 0x00, 0x82, 0x00, 0x58, 0x1c];
        b.extend_from_slice(cred);
        b
    }

    #[test]
    fn watched_certificate_credential_is_found() {
        assert!(certificate_use(&body_one_stake_cert(&STK), &watched_set(&[STK])).found);
    }

    #[test]
    fn unwatched_certificate_is_not_found_but_complete() {
        let s = certificate_use(&body_one_stake_cert(&STK), &watched_set(&[PAY]));
        assert!(!s.found && s.complete);
    }

    #[test]
    fn unknown_certificate_kind_is_incomplete() {
        // {4: [[99, 5]]} -- a cert of an unmodelled kind; coverage cannot be proven complete.
        assert!(
            !certificate_use(
                &[0xa1, 0x04, 0x81, 0x82, 0x18, 0x63, 0x05],
                &watched_set(&[STK])
            )
            .complete
        );
    }

    #[test]
    fn malformed_certificates_is_incomplete() {
        // {4: 5} -- certificates not a set/array.
        assert!(!certificate_use(&[0xa1, 0x04, 0x05], &watched_set(&[STK])).complete);
    }

    // --- native script (witness key 1) / update (body key 6) / collateral return (body 16) ---

    /// `{1: [[0, <28-byte cred>]]}` -- a native `sig` clause. = a1 01 81 82 00 58 1c <cred>.
    fn witness_one_native_sig(cred: &[u8; 28]) -> Vec<u8> {
        let mut w = vec![0xa1, 0x01, 0x81, 0x82, 0x00, 0x58, 0x1c];
        w.extend_from_slice(cred);
        w
    }

    /// `{6: [{<28-byte genesis hash>: {}}, 0]}` = a1 06 82 a1 58 1c <hash> a0 00.
    fn body_one_update(genesis_hash: &[u8; 28]) -> Vec<u8> {
        let mut b = vec![0xa1, 0x06, 0x82, 0xa1, 0x58, 0x1c];
        b.extend_from_slice(genesis_hash);
        b.extend_from_slice(&[0xa0, 0x00]);
        b
    }

    /// `{16: [<enterprise address>, 0]}` -- a legacy collateral-return output.
    /// = a1 10 82 58 1d 60 <cred> 00.
    fn body_collateral_return(cred: &[u8; 28]) -> Vec<u8> {
        let mut b = vec![0xa1, 0x10, 0x82, 0x58, 0x1d, 0x60];
        b.extend_from_slice(cred);
        b.push(0x00);
        b
    }

    #[test]
    fn watched_native_script_sig_is_found() {
        assert!(native_script_use(&witness_one_native_sig(&STK), &watched_set(&[STK])).found);
    }

    #[test]
    fn unwatched_native_script_is_not_found_but_complete() {
        let s = native_script_use(&witness_one_native_sig(&STK), &watched_set(&[PAY]));
        assert!(!s.found && s.complete);
    }

    #[test]
    fn watched_update_genesis_hash_is_found() {
        assert!(update_use(&body_one_update(&STK), &watched_set(&[STK])).found);
    }

    #[test]
    fn unwatched_update_is_not_found_but_complete() {
        let s = update_use(&body_one_update(&STK), &watched_set(&[PAY]));
        assert!(!s.found && s.complete);
    }

    #[test]
    fn watched_collateral_return_credential_is_found() {
        assert!(output_use(&body_collateral_return(&STK), &watched_set(&[STK])).found);
    }

    #[test]
    fn malformed_collateral_return_is_incomplete() {
        // {16: 5} -- collateral return neither an array nor a map.
        assert!(!output_use(&[0xa1, 0x10, 0x05], &watched_set(&[STK])).complete);
    }
}
