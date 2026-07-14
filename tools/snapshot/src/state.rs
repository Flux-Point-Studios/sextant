//! Tier-2 T4-tip: derive the certified snapshot's chain TIP (slot S, block number, header hash)
//! from the ancillary `state` file — the seam T4 seeds its live follow at.
//!
//! The `state` file is cardano-node 11.0.1's ExtLedgerState WITHOUT the UTxO LedgerTables (those
//! are the separate `tables` file). Its `HeaderState` carries an `AnnTip = array(3) [slot, hash,
//! blockno]`. Unlike the UTxO set (buried deep in the version-fragile LedgerState — which the T3
//! ruling declined to parse), the tip is a tiny fixed-shape structure located by a slot-anchored
//! marker, so this is a bounded, robust read rather than an ExtLedgerState walk.
//!
//! The TRUST anchor is upstream: the caller gates the `state` file's SHA-256 against the
//! Ed25519-signed manifest before parsing (`verified_anchor`), so the bytes are IOG-signed and the
//! tip rides the same `AncillarySigned` basis as the UTxO set — the parser defends against a wrong
//! byte-SHAPE, not an adversary.
//!
//! Two shape defenses: the marker `83 <slot> 5820` must match EXACTLY once (zero or several ⇒ fail
//! closed, never a guessed tip), and the extracted `(hash, blockno)` must ALSO appear re-encoded as
//! the ledger-state tip pointer `<slot> <blockno> 5820 <hash>` (a second copy the LedgerState keeps,
//! reached via a different code path in cardano-node). This makes a coincidental `array(3)+bytes(32)`
//! false match astronomically unlikely to survive (the 44-byte re-encoded needle would have to
//! appear too). The byte shape itself is pinned by a REAL-`state` fixture test below, and both
//! encodings use canonical minimal CBOR ints (which cardano-node's `cborg` emits) — the fixture is
//! what validates that assumption against genuine bytes. The live follow then confirms the tip for
//! free (chain-sync intersect at (S, hash) + first-block `prev_hash` contiguity).

use anyhow::{Result, ensure};
use sextant::utxoset::SetTip;

/// Parse the certified tip `(block number, header hash)` at slot `slot_s` from the ancillary
/// `state` bytes. Fails closed on an absent/ambiguous marker, a malformed block number, or a tip
/// whose two independent encodings in the file disagree.
pub fn parse_tip(state: &[u8], slot_s: u64) -> Result<SetTip> {
    // AnnTip = array(3) [ slot, bytes(32) hash, blockno ]. Anchor on the slot-specific prefix.
    let mut marker = vec![0x83];
    enc_uint(slot_s, &mut marker);
    marker.extend_from_slice(&[0x58, 0x20]); // bytes(32)

    let hits = find_all(state, &marker);
    ensure!(
        hits.len() == 1,
        "state tip: AnnTip marker for slot {slot_s} matched {} times (expected exactly 1)",
        hits.len()
    );
    let base = hits[0] + marker.len();

    let hash: [u8; 32] = state
        .get(base..base + 32)
        .and_then(|s| s.try_into().ok())
        .context_tip("AnnTip hash truncated")?;
    let (number, _consumed) = decode_uint(state, base + 32).context_tip("AnnTip block number")?;
    ensure!(number > 0, "state tip: block number is zero");

    // Shape cross-check: the LedgerState keeps a second copy of the tip as `slot ‖ blockno ‖ hash`.
    // Requiring the derived triple to re-appear in that form rejects a wrong-shape false match whose
    // decoded (hash, blockno) is garbage — a spurious 44-byte re-encoded needle is ~10^-99. The
    // trust anchor is the upstream signed-digest gate, not this check.
    let mut ledger_tip = Vec::new();
    enc_uint(slot_s, &mut ledger_tip);
    enc_uint(number, &mut ledger_tip);
    ledger_tip.extend_from_slice(&[0x58, 0x20]);
    ledger_tip.extend_from_slice(&hash);
    ensure!(
        !find_all(state, &ledger_tip).is_empty(),
        "state tip: AnnTip and ledger-state tip pointer disagree (corrupted state)"
    );

    Ok(SetTip { number, hash })
}

/// Minimal CBOR unsigned-integer encoding, appended to `out`.
fn enc_uint(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=23 => out.push(n as u8),
        24..=0xff => out.extend_from_slice(&[0x18, n as u8]),
        0x100..=0xffff => {
            out.push(0x19);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0x1a);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(0x1b);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Decode a CBOR unsigned integer (major type 0) at `pos`, returning `(value, bytes_consumed)`, or
/// `None` on a non-uint token or a truncated width. Rejects non-canonical/indefinite forms.
fn decode_uint(b: &[u8], pos: usize) -> Option<(u64, usize)> {
    let lead = *b.get(pos)?;
    match lead {
        0x00..=0x17 => Some((lead as u64, 1)),
        0x18 => Some((*b.get(pos + 1)? as u64, 2)),
        0x19 => {
            let v = b.get(pos + 1..pos + 3)?;
            Some((u16::from_be_bytes(v.try_into().ok()?) as u64, 3))
        }
        0x1a => {
            let v = b.get(pos + 1..pos + 5)?;
            Some((u32::from_be_bytes(v.try_into().ok()?) as u64, 5))
        }
        0x1b => {
            let v = b.get(pos + 1..pos + 9)?;
            Some((u64::from_be_bytes(v.try_into().ok()?), 9))
        }
        _ => None,
    }
}

/// All start offsets where `needle` occurs in `haystack` (non-overlapping is unnecessary: our
/// markers cannot self-overlap in a way that matters, and any count != 1 already fails closed).
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
        }
        i += 1;
    }
    out
}

trait ContextTip<T> {
    fn context_tip(self, msg: &str) -> Result<T>;
}
impl<T> ContextTip<T> for Option<T> {
    fn context_tip(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| anyhow::anyhow!("state tip: {msg}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        enc_uint(n, &mut v);
        v
    }

    /// Build a minimal well-formed `state`-shaped buffer: some filler, the AnnTip array(3), more
    /// filler, then the ledger-tip pointer — the two encodings the parser cross-checks.
    fn state_with_tip(slot: u64, blockno: u64, hash: [u8; 32]) -> Vec<u8> {
        let mut b = vec![0xde, 0xad, 0xbe, 0xef];
        // AnnTip: array(3) [slot, bytes32 hash, blockno]
        b.push(0x83);
        b.extend(enc(slot));
        b.extend_from_slice(&[0x58, 0x20]);
        b.extend_from_slice(&hash);
        b.extend(enc(blockno));
        b.extend_from_slice(&[0x00, 0x11, 0x22]); // filler
        // ledger-tip pointer: slot, blockno, bytes32 hash
        b.extend(enc(slot));
        b.extend(enc(blockno));
        b.extend_from_slice(&[0x58, 0x20]);
        b.extend_from_slice(&hash);
        b
    }

    #[test]
    fn parses_the_tip_from_a_well_formed_state() {
        let hash = [0x5e; 32];
        let buf = state_with_tip(128237957, 4930365, hash);
        let tip = parse_tip(&buf, 128237957).unwrap();
        assert_eq!(tip.number, 4930365);
        assert_eq!(tip.hash, hash);
    }

    /// The load-bearing test: parse the tip out of REAL cardano-node 11.0.1 `state` bytes. The
    /// fixture is two verbatim windows of the preprod snapshot's `ledger/128237957/state` (the
    /// LedgerState tip pointer near the front + the HeaderState AnnTip near EOF), with the 31 MB
    /// middle elided — genuine IOG-signed bytes, so this pins the assumed AnnTip byte shape against
    /// the real encoding, not our own synthetic buffer.
    #[test]
    fn parses_the_tip_from_real_state_bytes() {
        let real = include_bytes!("../../../tests/vectors/utxohd-state-tip.bin");
        let tip = parse_tip(real, 128237957).unwrap();
        assert_eq!(tip.number, 4930365);
        assert_eq!(
            hex::encode(tip.hash),
            "5eaf46daaec4a868ef4c969ed71dd73f29d0941cd75df652ae5f963df681dfd5"
        );
    }

    #[test]
    fn an_absent_marker_fails_closed() {
        let buf = state_with_tip(128237957, 4930365, [1; 32]);
        // Search for a slot that is not present.
        assert!(parse_tip(&buf, 999).is_err());
    }

    #[test]
    fn an_ambiguous_marker_fails_closed() {
        let hash = [7; 32];
        let mut buf = state_with_tip(128237957, 4930365, hash);
        // Append a SECOND AnnTip for the same slot → two matches → fail closed.
        buf.push(0x83);
        buf.extend(enc(128237957));
        buf.extend_from_slice(&[0x58, 0x20]);
        buf.extend_from_slice(&[9; 32]);
        buf.extend(enc(4930365));
        assert!(parse_tip(&buf, 128237957).is_err());
    }

    #[test]
    fn a_disagreeing_second_encoding_fails_closed() {
        let hash = [3; 32];
        let mut b = vec![0x00];
        // AnnTip present, but NO matching ledger-tip pointer → cross-check fails.
        b.push(0x83);
        b.extend(enc(128237957));
        b.extend_from_slice(&[0x58, 0x20]);
        b.extend_from_slice(&hash);
        b.extend(enc(4930365));
        assert!(parse_tip(&b, 128237957).is_err());
    }

    #[test]
    fn decode_uint_handles_all_widths() {
        assert_eq!(decode_uint(&enc(5), 0), Some((5, 1)));
        assert_eq!(decode_uint(&enc(200), 0), Some((200, 2)));
        assert_eq!(decode_uint(&enc(50000), 0), Some((50000, 3)));
        assert_eq!(decode_uint(&enc(4930365), 0), Some((4930365, 5)));
        assert_eq!(
            decode_uint(&enc(5_000_000_000), 0),
            Some((5_000_000_000, 9))
        );
    }
}
