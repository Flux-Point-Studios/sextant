//! Watched transaction credentials and fail-closed scan coverage.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use minicbor::Decoder;
use minicbor::data::Type;

use crate::hash::blake2b224;
use crate::utxo::{
    OutPoint, decode_outpoint, decode_single_output, input_set_len, read_bytes, seq_has_next,
    skip_item,
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

/// Whether `address` is a well-formed Byron address: exactly the CBOR item
/// `[#6.24(bytes payload), crc]`, the array definite, the payload a definite byte
/// string, `crc` its CRC-32, and the payload exactly `[bytes .size 28, attributes,
/// uint]` with that array definite and the attributes the ledger's
/// `Map Word8 ByteString`. A Byron address carries no VKH: the key behind it can
/// spend only through a bootstrap witness, which [`witness_use`] hashes.
fn byron_address(address: &[u8]) -> bool {
    let mut d = Decoder::new(address);
    let payload = (|| {
        if d.array().ok()? != Some(2) || d.tag().ok()?.as_u64() != 24 {
            return None;
        }
        let payload = d.bytes().ok()?;
        (d.u64().ok()? == u64::from(crc32(payload))).then_some(payload)
    })();
    payload.is_some_and(|payload| d.position() == address.len() && byron_payload(payload))
}

/// Whether a Byron address payload is exactly `[bytes .size 28, attributes, uint]`, the
/// attributes a map in either length form from uints below 256 to definite byte strings.
fn byron_payload(payload: &[u8]) -> bool {
    let mut d = Decoder::new(payload);
    let read = (|| {
        if d.array().ok()? != Some(3) || d.bytes().ok()?.len() != 28 {
            return None;
        }
        let attributes = d.map().ok()?;
        let mut i = 0;
        while seq_has_next(&mut d, attributes, i).ok()? {
            d.u8().ok()?;
            d.bytes().ok()?;
            i += 1;
        }
        d.u64().ok()
    })();
    read.is_some() && d.position() == payload.len()
}

/// CRC-32 with the IEEE polynomial, the checksum a Byron address carries.
fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &byte| {
        (0..8).fold(crc ^ u32::from(byte), |crc, _| {
            (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg())
        })
    })
}

/// Payment credentials of regular inputs for valid transactions, collateral otherwise.
/// Unresolved inputs, resolver errors, and resolved addresses without a payment
/// credential leave coverage incomplete, except a well-formed Byron address.
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
                    None => scan.complete &= byron_address(address),
                },
                Ok(None) | Err(()) => scan.complete = false,
            }
            i += 1;
        }
        Ok(())
    })
}

/// Hands each key of the CBOR map `data` to `field`. A malformed entry, or bytes
/// left after the map, leaves coverage incomplete.
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
    if result.is_err() || d.position() != data.len() {
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
/// body-16 collateral return -- as the output's payment or stake credential or in
/// a native reference script it carries. Body-1 is a list of transaction_outputs;
/// the body-16 collateral return is a single one. Every output's reference script
/// draws on one walk budget. An address counts only once the whole body has
/// decoded: an output that ends short reads its last entries from the field after
/// it, and only the failure that follows shows it.
pub fn output_use(body: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    let mut budget = WALK_BUDGET;
    let mut outputs = Scan {
        found: false,
        complete: true,
    };
    let walk = scan_map(body, |key, d, _| match key {
        1 => {
            let len = d.array().map_err(|_| ())?;
            let mut i = 0u64;
            while seq_has_next(d, len, i).map_err(|_| ())? {
                output_watched(d, watched, &mut budget, &mut outputs)?;
                i += 1;
            }
            Ok(())
        }
        16 => output_watched(d, watched, &mut budget, &mut outputs),
        _ => d.skip().map_err(|_| ()),
    });
    Scan {
        found: outputs.found && walk.complete,
        complete: outputs.complete && walk.complete,
    }
}

/// One output, read in place so its boundary is exact. A map's entries are walked
/// with skip_item, which takes no break for an item, reading every address a key 0
/// carries and every native reference script at key 3; a legacy array goes through
/// the crate's own decode_single_output. A map key outside 0-3 (address, value,
/// datum_option, script_ref), a repeated key, or a map that decoder refuses leaves
/// coverage incomplete, and every address read still counts.
fn output_watched(
    d: &mut Decoder<'_>,
    watched: &BTreeSet<[u8; 28]>,
    budget: &mut u32,
    scan: &mut Scan,
) -> Result<(), ()> {
    let start = d.position();
    if !matches!(d.datatype().map_err(|_| ())?, Type::Map | Type::MapIndef) {
        let (address, _, _) = decode_single_output(d).map_err(|_| ())?;
        scan.found |= address_watched(&address, watched);
        return Ok(());
    }
    let len = d.map().map_err(|_| ())?;
    let mut seen = [false; 4];
    let mut i = 0u64;
    while seq_has_next(d, len, i).map_err(|_| ())? {
        let key = d.u64().map_err(|_| ())?;
        let value = d.position();
        skip_item(d).map_err(|_| ())?;
        let item = &d.input()[value..d.position()];
        let repeated = key <= 3 && core::mem::replace(&mut seen[key as usize], true);
        let read = match key {
            0 => match Decoder::new(item).bytes() {
                Ok(address) => {
                    scan.found |= address_watched(address, watched);
                    true
                }
                Err(_) => false,
            },
            1 | 2 => true,
            3 => reference_script_watched(item, watched, budget, scan).is_ok(),
            _ => false,
        };
        scan.complete &= read && !repeated;
        i += 1;
    }
    let output = &d.input()[start..d.position()];
    scan.complete &= decode_single_output(&mut Decoder::new(output)).is_ok();
    Ok(())
}

/// A reference script: a tag-24 wrapper over CBOR `[script_type, script]`, the pair
/// in either length form, as the ledger reads it. A native script (type 0) carries
/// its sig clauses in clear and is deep-walked on the caller's budget; Plutus
/// scripts (types 1-3) are byte strings with no credential in clear. A wrapper that
/// does not unwrap, a pair of another arity, a Plutus script that is no byte string,
/// an unknown type or trailing bytes return `Err`, which leaves coverage incomplete.
fn reference_script_watched(
    wrapped: &[u8],
    watched: &BTreeSet<[u8; 28]>,
    budget: &mut u32,
    scan: &mut Scan,
) -> Result<(), ()> {
    let mut d = Decoder::new(wrapped);
    if d.tag().map_err(|_| ())?.as_u64() != 24 {
        return Err(());
    }
    let mut script = Decoder::new(d.bytes().map_err(|_| ())?);
    let len = script.array().map_err(|_| ())?;
    if len.is_some_and(|n| n != 2) {
        return Err(());
    }
    match script.u64().map_err(|_| ())? {
        0 => collect_watched(&mut script, watched, budget, scan)?,
        1..=3 => {
            script.bytes().map_err(|_| ())?;
        }
        _ => return Err(()),
    }
    if !seq_has_next(&mut script, len, 2).map_err(|_| ())?
        && script.position() == script.input().len()
    {
        Ok(())
    } else {
        Err(())
    }
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

/// Does a watched key appear in a proposal -- body key 20, a set of `[deposit,
/// reward_account, gov_action, anchor]` -- as its deposit-return reward account
/// (bytes [1..29] of element 1) or at a typed credential position of its
/// gov_action. A proposal of another arity leaves coverage incomplete; the
/// positions it does carry still count.
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
                    } else if k == 2 {
                        gov_action_watched(d, watched, scan)?;
                    } else if d.skip().is_err() {
                        return Err(());
                    }
                    k += 1;
                }
                if k != 4 {
                    scan.complete = false;
                }
                j += 1;
            }
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Element count of each Conway gov_action, its kind included.
fn gov_action_arity(kind: u64) -> Option<u64> {
    match kind {
        0 => Some(4),
        1 | 2 | 5 => Some(3),
        3 => Some(2),
        4 => Some(5),
        6 => Some(1),
        _ => None,
    }
}

/// Reads one gov_action and the credential positions its Conway shape types:
/// treasury recipients (kind 2), committee members removed and added (kind 4) and
/// the guardrail or constitution script hash (kinds 0, 2, 5). Action ids, anchors,
/// coins, epochs, protocol versions and parameter values are untyped data and are
/// skipped. An unknown kind or a wrong arity is read no further and leaves
/// coverage incomplete; a malformed typed position is an error.
fn gov_action_watched(
    d: &mut Decoder<'_>,
    watched: &BTreeSet<[u8; 28]>,
    scan: &mut Scan,
) -> Result<(), ()> {
    let count = array_count(d)?;
    let len = d.array().map_err(|_| ())?;
    if !seq_has_next(d, len, 0).map_err(|_| ())? {
        scan.complete = false;
        return Ok(());
    }
    let kind = d.u64().map_err(|_| ())?;
    let typed = gov_action_arity(kind) == Some(count);
    if !typed {
        scan.complete = false;
    }
    let mut k = 1u64;
    while seq_has_next(d, len, k).map_err(|_| ())? {
        match (typed, kind, k) {
            (true, 2, 1) => {
                let entries = d.map().map_err(|_| ())?;
                let mut i = 0u64;
                while seq_has_next(d, entries, i).map_err(|_| ())? {
                    scan.found |= reward_account_watched(d, watched)?;
                    d.skip().map_err(|_| ())?;
                    i += 1;
                }
            }
            (true, 4, 2) => {
                let members = input_set_len(d).map_err(|_| ())?;
                let mut i = 0u64;
                while seq_has_next(d, members, i).map_err(|_| ())? {
                    scan.found |= cold_credential_watched(d, watched)?;
                    i += 1;
                }
            }
            (true, 4, 3) => {
                let entries = d.map().map_err(|_| ())?;
                let mut i = 0u64;
                while seq_has_next(d, entries, i).map_err(|_| ())? {
                    scan.found |= cold_credential_watched(d, watched)?;
                    d.skip().map_err(|_| ())?;
                    i += 1;
                }
            }
            (true, 0, 3) | (true, 2, 2) => scan.found |= script_hash_watched(d, watched)?,
            (true, 5, 2) => {
                let len = d.array().map_err(|_| ())?;
                let mut i = 0u64;
                while seq_has_next(d, len, i).map_err(|_| ())? {
                    match i {
                        1 => scan.found |= script_hash_watched(d, watched)?,
                        _ => d.skip().map_err(|_| ())?,
                    }
                    i += 1;
                }
                if i != 2 {
                    return Err(());
                }
            }
            _ => d.skip().map_err(|_| ())?,
        }
        k += 1;
    }
    Ok(())
}

/// A 28-byte hash at a typed credential position; any other length is no such
/// credential.
fn hash28_watched(d: &mut Decoder<'_>, watched: &BTreeSet<[u8; 28]>) -> Result<bool, ()> {
    let bytes = read_bytes(d).map_err(|_| ())?;
    let hash: [u8; 28] = bytes.as_slice().try_into().map_err(|_| ())?;
    Ok(watched.contains(&hash))
}

/// A `policy_hash / nil` or `script_hash / nil` position.
fn script_hash_watched(d: &mut Decoder<'_>, watched: &BTreeSet<[u8; 28]>) -> Result<bool, ()> {
    if d.datatype().map_err(|_| ())? == Type::Null {
        d.skip().map_err(|_| ())?;
        return Ok(false);
    }
    hash28_watched(d, watched)
}

/// A committee cold credential, `[0, addr_keyhash]` or `[1, script_hash]`, in
/// either array encoding.
fn cold_credential_watched(d: &mut Decoder<'_>, watched: &BTreeSet<[u8; 28]>) -> Result<bool, ()> {
    let len = d.array().map_err(|_| ())?;
    let mut found = false;
    let mut i = 0u64;
    while seq_has_next(d, len, i).map_err(|_| ())? {
        match i {
            0 => {
                if d.u64().map_err(|_| ())? > 1 {
                    return Err(());
                }
            }
            1 => found = hash28_watched(d, watched)?,
            _ => return Err(()),
        }
        i += 1;
    }
    if i == 2 { Ok(found) } else { Err(()) }
}

/// Element count of the array at `d`, definite or indefinite; `d` does not move.
/// The ledger accepts both encodings, so an arity check must not depend on one.
fn array_count(d: &mut Decoder<'_>) -> Result<u64, ()> {
    let start = d.position();
    let len = d.array().map_err(|_| ())?;
    let mut count = 0u64;
    while seq_has_next(d, len, count).map_err(|_| ())? {
        d.skip().map_err(|_| ())?;
        count += 1;
    }
    d.set_position(start);
    Ok(count)
}

/// The byte-string sizes of a vkey witness row and a bootstrap witness row (Conway
/// CDDL), `None` for any length: `[vkey, signature]` and `[vkey, signature,
/// chain_code, attributes]`.
const VKEY_WITNESS: [Option<usize>; 2] = [Some(32), Some(64)];
const BOOTSTRAP_WITNESS: [Option<usize>; 4] = [Some(32), Some(64), Some(32), None];

/// The verification key of one witness row, read only in its CDDL shape: one definite
/// byte string per `shape` size, in either length form, the first the vkey. Any other
/// row, a break where an element is due included, is `None`.
fn witness_vkey<'b>(row: &'b [u8], shape: &[Option<usize>]) -> Option<&'b [u8]> {
    let mut d = Decoder::new(row);
    let len = d.array().ok()?;
    let mut vkey = None;
    for (k, size) in (0u64..).zip(shape) {
        if !seq_has_next(&mut d, len, k).ok()? {
            return None;
        }
        let element = d.bytes().ok()?;
        if size.is_some_and(|size| element.len() != size) {
            return None;
        }
        if k == 0 {
            vkey = Some(element);
        }
    }
    let end = u64::try_from(shape.len()).ok()?;
    if seq_has_next(&mut d, len, end).ok()? {
        return None;
    }
    vkey
}

/// Does a watched key appear as a verification-key witness -- witness-set key 0
/// (vkey witnesses) or key 2 (bootstrap witnesses). The 28-byte key hash is
/// BLAKE2b-224 of the 32-byte vkey (Option A): the one watched-key surface that
/// hashes rather than reading a credential in clear. Each row is read from its own
/// span, so a row outside its CDDL shape leaves coverage incomplete while the rows
/// after it are still read: a proven use dominates a malformed row.
pub fn witness_use(witnesses: &[u8], watched: &BTreeSet<[u8; 28]>) -> Scan {
    scan_map(witnesses, |key, d, scan| {
        let shape: &[Option<usize>] = match key {
            0 => &VKEY_WITNESS,
            2 => &BOOTSTRAP_WITNESS,
            _ => return d.skip().map_err(|_| ()),
        };
        let set_len = input_set_len(d).map_err(|_| ())?;
        let mut j = 0u64;
        while seq_has_next(d, set_len, j).map_err(|_| ())? {
            let start = d.position();
            d.skip().map_err(|_| ())?;
            match witness_vkey(&d.input()[start..d.position()], shape) {
                Some(vkey) => scan.found |= watched.contains(&blake2b224(vkey)),
                None => scan.complete = false,
            }
            j += 1;
        }
        Ok(())
    })
}

/// Node budget for the deep walk. Real certificates, native scripts and parameter
/// updates are far smaller; exhausting it leaves coverage unprovable, so the scan
/// reports incomplete rather than reading absence. The walk is iterative, so depth
/// costs only budget.
const WALK_BUDGET: u32 = 100_000;

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

/// An open container in the deep walk: the items still due in a definite one, or
/// `None` for an indefinite one, which ends at a break (a map's only between pairs).
struct Open {
    left: Option<u64>,
    map: bool,
    owes_value: bool,
}

/// Walks one CBOR item without recursion and records matches as leaves decode, so
/// a later malformed child cannot erase them. An indefinite byte string counts as
/// its joined chunks.
fn collect_watched(
    d: &mut Decoder<'_>,
    watched: &BTreeSet<[u8; 28]>,
    budget: &mut u32,
    scan: &mut Scan,
) -> Result<(), ()> {
    let mut open: Vec<Open> = Vec::new();
    let mut started = false;
    loop {
        match open.last_mut() {
            None if started => return Ok(()),
            None => started = true,
            Some(top) => match top.left.as_mut() {
                Some(0) => {
                    open.pop();
                    continue;
                }
                Some(left) => *left -= 1,
                None => {
                    if !top.owes_value && d.datatype().map_err(|_| ())? == Type::Break {
                        d.skip().map_err(|_| ())?;
                        open.pop();
                        continue;
                    }
                    top.owes_value = top.map && !top.owes_value;
                }
            },
        }
        if *budget == 0 {
            scan.complete = false;
            d.skip().map_err(|_| ())?;
            continue;
        }
        *budget -= 1;
        match d.datatype().map_err(|_| ())? {
            Type::Bytes | Type::BytesIndef => {
                let mut leaf = Vec::new();
                for chunk in d.bytes_iter().map_err(|_| ())? {
                    leaf.extend_from_slice(chunk.map_err(|_| ())?);
                }
                scan.found |= match leaf.len() {
                    28 => <[u8; 28]>::try_from(leaf.as_slice())
                        .is_ok_and(|hash| watched.contains(&hash)),
                    29 => reward_credential(&leaf).is_some_and(|c| watched.contains(&c)),
                    _ => false,
                };
            }
            Type::Array | Type::ArrayIndef => {
                let left = d.array().map_err(|_| ())?;
                open.push(Open {
                    left,
                    map: false,
                    owes_value: false,
                });
            }
            Type::Map | Type::MapIndef => {
                let left = match d.map().map_err(|_| ())? {
                    Some(pairs) => Some(pairs.checked_mul(2).ok_or(())?),
                    None => None,
                };
                open.push(Open {
                    left,
                    map: true,
                    owes_value: false,
                });
            }
            Type::Tag => {
                d.tag().map_err(|_| ())?;
                open.push(Open {
                    left: Some(1),
                    map: false,
                    owes_value: false,
                });
            }
            Type::Break => return Err(()),
            _ => d.skip().map_err(|_| ())?,
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
                        collect_watched(d, watched, &mut budget, scan)?;
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
                collect_watched(d, watched, &mut budget, scan)?;
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
            collect_watched(d, watched, &mut budget, scan)?;
        } else if d.skip().is_err() {
            return Err(());
        }
        Ok(())
    })
}

/// Body keys the ledger defines (key 6 is the pre-Conway update). A key outside
/// this set is a field no surface reads, so coverage cannot be proven.
const KNOWN_BODY_KEYS: [u64; 21] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
];

/// Witness-set keys the ledger defines: vkeys, native scripts, bootstrap, Plutus
/// V1, Plutus data, redeemers, Plutus V2 and Plutus V3.
const KNOWN_WITNESS_KEYS: core::ops::RangeInclusive<u64> = 0..=7;

/// The watched-key scan of one transaction: its body and witness surfaces folded
/// into one scan, beside the inputs it consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionScan {
    /// Every body and witness surface, plus the checks that the body and the
    /// witness set hold no key outside the ledger's.
    pub surfaces: Scan,
    /// The creating outputs of the inputs the transaction consumes.
    pub inputs: Scan,
}

/// What a transaction scan settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No watched key appears and every surface was fully read.
    NoUse,
    /// A watched key appears.
    UseFound,
    /// Nothing was found, but some surface could not be fully read.
    Incomplete,
}

impl TransactionScan {
    /// A proven use outranks any gap; with no use, any gap refuses a clean
    /// `NoUse`.
    pub fn verdict(&self) -> Verdict {
        if self.surfaces.found || self.inputs.found {
            Verdict::UseFound
        } else if self.surfaces.complete && self.inputs.complete {
            Verdict::NoUse
        } else {
            Verdict::Incomplete
        }
    }
}

/// Scans one transaction from the spans a block lays out -- its body, its witness
/// set and its phase-2 validity -- resolving each consumed input's creating output
/// through `resolve`. The spans must come from a hash-verified block: some CBOR no
/// ledger accepts (a stray break, a mistyped known field, an odd-length credential)
/// can still read complete.
pub fn transaction_use<'a>(
    body: &[u8],
    witnesses: &[u8],
    is_valid: bool,
    watched: &BTreeSet<[u8; 28]>,
    resolve: impl FnMut(&OutPoint) -> Result<Option<&'a [u8]>, ()>,
) -> TransactionScan {
    let scans = [
        scan_map(body, |key, d, scan| {
            scan.complete &= KNOWN_BODY_KEYS.contains(&key);
            d.skip().map_err(|_| ())
        }),
        scan_map(witnesses, |key, d, scan| {
            scan.complete &= KNOWN_WITNESS_KEYS.contains(&key);
            d.skip().map_err(|_| ())
        }),
        required_signer_use(body, watched),
        output_use(body, watched),
        withdrawal_use(body, watched),
        voting_use(body, watched),
        proposal_use(body, watched),
        certificate_use(body, watched),
        update_use(body, watched),
        witness_use(witnesses, watched),
        native_script_use(witnesses, watched),
    ];
    TransactionScan {
        surfaces: Scan {
            found: scans.iter().any(|scan| scan.found),
            complete: scans.iter().all(|scan| scan.complete),
        },
        inputs: input_use(body, is_valid, watched, resolve),
    }
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

    /// `{20: [[0, <reward_account>, [6], null]]}` = a1 14 81 84 00 <account> 81 06
    /// f6: a proposal whose gov_action is the info action, which names no credential.
    fn body_one_proposal(account: &[u8]) -> Vec<u8> {
        let mut b = vec![0xa1, 0x14, 0x81, 0x84, 0x00];
        b.extend_from_slice(account);
        b.extend_from_slice(&[0x81, 0x06, 0xf6]);
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

    /// `{slot: [row]}` with the slot's CDDL row: `[vkey(32), sig(64)]` for vkey witnesses
    /// (slot 0), and for bootstrap witnesses (slot 2) that plus a 32-byte chain code and
    /// empty attributes.
    fn witness_map(slot: u8) -> Vec<u8> {
        let bootstrap = slot == 2;
        let mut w = vec![
            0xa1,
            slot,
            0x81,
            if bootstrap { 0x84 } else { 0x82 },
            0x58,
            0x20,
        ];
        w.extend_from_slice(&VK);
        w.extend_from_slice(&[0x58, 0x40]);
        w.extend_from_slice(&SIG);
        if bootstrap {
            w.extend_from_slice(&[0x58, 0x20]);
            w.extend_from_slice(&[0u8; 32]);
            w.push(0x40);
        }
        w
    }

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn a_witness_row_holds_its_own_arity() {
        // [vkey, sig, chain code] and one more item after it: a bootstrap row of three
        // elements stays short of four whatever follows it.
        let mut row = vec![0x83, 0x58, 0x20];
        row.extend_from_slice(&VK);
        row.extend_from_slice(&[0x58, 0x40]);
        row.extend_from_slice(&SIG);
        row.extend_from_slice(&[0x58, 0x20]);
        row.extend_from_slice(&[0u8; 32]);
        row.push(0x40);
        assert_eq!(witness_vkey(&row, &BOOTSTRAP_WITNESS), None);
        row[0] = 0x84;
        assert_eq!(witness_vkey(&row, &BOOTSTRAP_WITNESS), Some(&VK[..]));
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
