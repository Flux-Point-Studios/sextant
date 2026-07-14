//! Tier-2 T3-parse: decode the InMemory UTxO-HD `tables` file into the outpoint membership set,
//! on Sextant's own minicbor path (never a provider's).
//!
//! Format (observed on preprod e300/i5936, cardano-node 11.0.1; see `docs/utxo-hd-format.md`):
//! the `meta` sidecar pins the backend + codec version, and `tables` is
//! `81` (array-1) `bf` (indefinite map) of `bytes(34) -> bytes(N)`, where the 34-byte key is
//! `tx_id(32) || big-endian u16 index` and the value is the serialized `TxOut`. Membership reads
//! ONLY the keys; the value is read as a bytestring and discarded (reading it AS a bytestring is
//! what makes a `Break`-in-a-value-slot fail closed instead of realigning into a phantom key).
//!
//! The bytes handed here are already trust-established: the caller obtains them through
//! [`crate::verify_newest_tables`], which verifies the ancillary manifest signature and matches
//! this file's SHA-256 to the signed digest before any outpoint is decoded.
//!
//! The version gate is load-bearing: the codec version is asserted against the ONE this parser
//! was written for, so a future format churn fails closed instead of mis-decoding.

use anyhow::{Result, bail, ensure};
use minicbor::Decoder;
use minicbor::data::Type;
use serde::Deserialize;
use sextant::utxo::OutPoint;

/// The backing-store flavor Mithril ships (InMemory UTxO-HD) — the only one this parser decodes.
pub const EXPECTED_BACKEND: &str = "utxohd-mem";
/// The tables codec version this parser was written against. A different version fails closed.
pub const EXPECTED_TABLES_CODEC_VERSION: u64 = 1;

/// The `ledger/<slot>/meta` sidecar.
#[derive(Debug, Clone, Deserialize)]
pub struct UtxoHdMeta {
    /// The ledger backend flavor (`utxohd-mem` for the InMemory snapshot).
    pub backend: String,
    /// The version of the `tables` file encoding.
    #[serde(rename = "tablesCodecVersion")]
    pub tables_codec_version: u64,
}

/// Parse and GATE the `meta` sidecar: the backend must be the InMemory flavor and the tables
/// codec version must be the one this parser transcribes. Any other value fails closed — a
/// future cardano-node that bumps the encoding is refused, not silently mis-parsed.
pub fn parse_meta(bytes: &[u8]) -> Result<UtxoHdMeta> {
    let meta: UtxoHdMeta = serde_json::from_slice(bytes).context_meta()?;
    ensure!(
        meta.backend == EXPECTED_BACKEND,
        "unsupported ledger backend {:?} (expected {EXPECTED_BACKEND:?})",
        meta.backend
    );
    ensure!(
        meta.tables_codec_version == EXPECTED_TABLES_CODEC_VERSION,
        "unsupported tables codec version {} (this parser transcribes version {EXPECTED_TABLES_CODEC_VERSION})",
        meta.tables_codec_version
    );
    Ok(meta)
}

trait ContextMeta<T> {
    fn context_meta(self) -> Result<T>;
}
impl<T> ContextMeta<T> for Result<T, serde_json::Error> {
    fn context_meta(self) -> Result<T> {
        self.map_err(|e| anyhow::anyhow!("parse utxo-hd meta: {e}"))
    }
}

/// Decode the `tables` UTxO map, invoking `f` for each outpoint (the 34-byte key). Returns the
/// number of outpoints. Streams over the (memory-mapped) input, so the whole set is never
/// materialized unless `f` chooses to. Fails closed — never a partial/guessed set — on: a
/// malformed key length, a non-bytestring key OR value (a `Break` in a value slot cannot realign
/// the loop into a phantom key), or keys that are not strictly increasing (the sorted, no-dup
/// invariant of the serialized `Data.Map`, which also rejects a reordered/duplicate tamper).
pub fn for_each_outpoint(bytes: &[u8], mut f: impl FnMut(OutPoint) -> Result<()>) -> Result<usize> {
    let mut d = Decoder::new(bytes);

    match d.array().map_err(cbor)? {
        Some(1) => {}
        other => bail!("tables: expected array(1), got {other:?}"),
    }
    // The map is indefinite-length in the observed format; accept a definite one too.
    let definite = d.map().map_err(cbor)?;

    let mut count = 0usize;
    // Previous key, to enforce the strictly-increasing invariant: the tables are a serialized
    // `Data.Map` (sorted, no duplicates). Enforcing it rejects a reordered or duplicate-entry
    // tamper AND makes a file-order fingerprint a canonical set commitment.
    let mut prev: Option<[u8; 34]> = None;
    let read_entry = |d: &mut Decoder<'_>,
                      f: &mut dyn FnMut(OutPoint) -> Result<()>,
                      prev: &mut Option<[u8; 34]>|
     -> Result<()> {
        let key = d.bytes().map_err(cbor)?;
        ensure!(
            key.len() == 34,
            "tables: key is {} bytes, expected 34",
            key.len()
        );
        let key: [u8; 34] = key.try_into().expect("len checked == 34");
        if let Some(p) = prev {
            ensure!(
                key > *p,
                "tables: keys are not strictly increasing (reordered or duplicate entry)"
            );
        }
        *prev = Some(key);
        // The value MUST be a bytestring (the serialized TxOut). Read it AS one — a `Break`
        // in a value slot, or any other CBOR item, fails closed here rather than being
        // absorbed by a permissive `skip()` and realigning the loop into a phantom key.
        let _txout = d.bytes().map_err(cbor)?;
        let tx_id: [u8; 32] = key[..32].try_into().expect("34 >= 32");
        let index = u16::from_be_bytes([key[32], key[33]]);
        f(OutPoint { tx_id, index })?;
        Ok(())
    };

    match definite {
        Some(entries) => {
            for _ in 0..entries {
                read_entry(&mut d, &mut f, &mut prev)?;
                count += 1;
            }
        }
        None => loop {
            if d.datatype().map_err(cbor)? == Type::Break {
                d.skip().map_err(cbor)?;
                break;
            }
            read_entry(&mut d, &mut f, &mut prev)?;
            count += 1;
        },
    }
    Ok(count)
}

/// Collect all outpoints — for small fixtures/tests. Prefer [`for_each_outpoint`] at snapshot
/// scale so the ~11M-entry set is streamed into a store rather than held in memory.
pub fn outpoints(bytes: &[u8]) -> Result<Vec<OutPoint>> {
    let mut out = Vec::new();
    for_each_outpoint(bytes, |o| {
        out.push(o);
        Ok(())
    })?;
    Ok(out)
}

fn cbor(e: minicbor::decode::Error) -> anyhow::Error {
    anyhow::anyhow!("tables cbor: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_gate_accepts_the_pinned_version_and_refuses_others() {
        let ok =
            parse_meta(br#"{"backend":"utxohd-mem","checksum":1,"tablesCodecVersion":1}"#).unwrap();
        assert_eq!(ok.tables_codec_version, 1);
        // Wrong backend and a bumped codec version both fail closed.
        assert!(parse_meta(br#"{"backend":"utxohd-lmdb","tablesCodecVersion":1}"#).is_err());
        assert!(parse_meta(br#"{"backend":"utxohd-mem","tablesCodecVersion":2}"#).is_err());
    }

    /// Build a valid `tables`-shaped map from real-shaped entries and confirm the outpoints decode
    /// (key = tx_id ‖ BE index), the value is skipped, and the count is exact.
    #[test]
    fn decodes_the_tables_map_keys_as_outpoints() {
        fn key(tx: u8, index: u16) -> Vec<u8> {
            let mut k = vec![tx; 32];
            k.extend_from_slice(&index.to_be_bytes());
            k
        }
        // 81 bf (bytes34 key)(bytes value) ... ff
        let mut buf = vec![0x81, 0xbf];
        let enc = |k: &[u8], v: &[u8], b: &mut Vec<u8>| {
            b.push(0x58);
            b.push(k.len() as u8);
            b.extend_from_slice(k);
            b.push(0x58);
            b.push(v.len() as u8);
            b.extend_from_slice(v);
        };
        enc(&key(0xaa, 0), &[1, 2, 3], &mut buf);
        enc(&key(0xaa, 1), &[4], &mut buf);
        enc(&key(0xbb, 7), &[5, 6], &mut buf);
        buf.push(0xff);

        let ops = outpoints(&buf).unwrap();
        assert_eq!(ops.len(), 3);
        assert_eq!(
            ops,
            vec![
                OutPoint {
                    tx_id: [0xaa; 32],
                    index: 0
                },
                OutPoint {
                    tx_id: [0xaa; 32],
                    index: 1
                },
                OutPoint {
                    tx_id: [0xbb; 32],
                    index: 7
                },
            ]
        );
    }

    #[test]
    fn a_wrong_key_length_fails_closed() {
        // 81 bf (bytes3 = short key)(bytes1) ff — a 3-byte key is not a 34-byte outpoint.
        let buf = vec![0x81, 0xbf, 0x43, 1, 2, 3, 0x41, 9, 0xff];
        assert!(outpoints(&buf).is_err());
    }

    fn key34(tx: u8, index: u16) -> Vec<u8> {
        let mut k = vec![tx; 32];
        k.extend_from_slice(&index.to_be_bytes());
        k
    }
    fn bytes_hdr(len: usize) -> Vec<u8> {
        vec![0x58, len as u8]
    }

    /// A `Break` (0xff) where a value belongs must NOT be absorbed as if it were the value: doing
    /// so would realign the loop and promote a subsequent value-internal bytestring to a phantom
    /// key. It must fail closed. (The HIGH the red-team injected a phantom `#999` through.)
    #[test]
    fn a_break_in_a_value_slot_fails_closed() {
        // 81 bf (bytes34 key) ff  — the value slot holds a bare break.
        let mut buf = vec![0x81, 0xbf];
        buf.extend(bytes_hdr(34));
        buf.extend(key34(0x11, 0));
        buf.push(0xff);
        assert!(outpoints(&buf).is_err());
    }

    #[test]
    fn a_non_bytestring_value_fails_closed() {
        // 81 bf (bytes34 key)(u8 = 0x01, not a bytestring) ... — the value must be a TxOut bytes.
        let mut buf = vec![0x81, 0xbf];
        buf.extend(bytes_hdr(34));
        buf.extend(key34(0x11, 0));
        buf.push(0x01); // a CBOR unsigned int, not a bytestring
        buf.push(0xff);
        assert!(outpoints(&buf).is_err());
    }

    #[test]
    fn out_of_order_or_duplicate_keys_fail_closed() {
        let entry = |tx: u8, idx: u16, buf: &mut Vec<u8>| {
            buf.extend(bytes_hdr(34));
            buf.extend(key34(tx, idx));
            buf.push(0x41);
            buf.push(0u8); // 1-byte value
        };
        // Descending keys: 0x22.. then 0x11.. — not strictly increasing.
        let mut desc = vec![0x81, 0xbf];
        entry(0x22, 0, &mut desc);
        entry(0x11, 0, &mut desc);
        desc.push(0xff);
        assert!(outpoints(&desc).is_err());

        // Duplicate key: 0x11#0 twice — not STRICTLY increasing.
        let mut dup = vec![0x81, 0xbf];
        entry(0x11, 0, &mut dup);
        entry(0x11, 0, &mut dup);
        dup.push(0xff);
        assert!(outpoints(&dup).is_err());
    }
}
