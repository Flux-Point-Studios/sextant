//! Watched-key first use (U1): does a watched 28-byte key hash appear in a
//! transaction, and is that answer provably complete?
//!
//! This is the Rust counterpart of the Python reference extractor
//! (`aegis` r57-live `scripts/r57_first_use.py`) and is checked against the same
//! hand-labelled parity vectors. It reuses the crate's existing body navigation
//! (`crate::utxo`) and hand-rolled minicbor decoding; it adds no crypto and no
//! consensus or follower machinery.
//!
//! The one primitive the crate lacked is here: splitting a Shelley address or a
//! reward account into its 28-byte payment and stake credentials. That is pure
//! byte slicing — no hashing, no new dependency — and stays `no_std` + `alloc`
//! clean. The transaction-surface walk and the fail-closed watched-key verdict
//! build on these; this slice is the credential parser alone, so the no_std and
//! test harness is proven before the minicbor surface walk lands.

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

use alloc::collections::BTreeSet;

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

/// Does a watched key appear as a required signer — body key 14, a
/// `set<addr_keyhash>` (tag-258 or a bare array) of 28-byte key hashes carried in
/// clear, so no hashing is needed. A body that does not fully decode yields
/// `complete = false`.
///
/// STUB (RED): returns a definite wrong answer so the behavioural RED is genuine
/// before the real walk lands; replaced in the GREEN increment.
pub fn required_signer_use(_body: &[u8], _watched: &BTreeSet<[u8; 28]>) -> Scan {
    Scan {
        found: false,
        complete: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAY: [u8; 28] = [0xA1; 28];
    const STK: [u8; 28] = [0xA2; 28];

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
}
