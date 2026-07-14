//! Tier-2 T3-fetch: unpack the Mithril cardano-database ancillary (`.tar.zst`) — the InMemory
//! UTxO-HD ledger-state snapshot the certified-state bootstrap parses.
//!
//! zstd + tar live in this tools crate, never in the sextant trust core (which stays sans-io and
//! wasm-safe). The stream is decompressed and untarred incrementally, so the full 1.88 GB
//! uncompressed archive is never held in memory.

pub mod state;
pub mod tables;

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use memmap2::Mmap;
use sextant::ancillary::{VerifiedAncillaryManifest, verify_ancillary_manifest};
use sextant::utxoset::{AnchorBasis, SnapshotAnchor};
use sha2::{Digest, Sha256};

/// One unpacked entry: its path relative to the destination root and its size in bytes.
#[derive(Debug, Clone)]
pub struct Extracted {
    /// Path the entry was unpacked to.
    pub path: PathBuf,
    /// The entry's size in bytes (0 for non-regular entries).
    pub size: u64,
}

/// Decompress a `.tar.zst` archive and unpack it under `dest`, returning the unpacked regular
/// files (largest first). Path traversal is refused by `tar`'s `unpack_in`, so a hostile archive
/// cannot escape `dest`.
pub fn extract_tar_zst(archive: &Path, dest: &Path) -> Result<Vec<Extracted>> {
    let f = File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    let decoder = zstd::stream::read::Decoder::new(BufReader::new(f)).context("zstd decoder")?;
    let mut archive = tar::Archive::new(decoder);
    std::fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;

    let mut out = Vec::new();
    for entry in archive.entries().context("read tar entries")? {
        let mut entry = entry.context("tar entry")?;
        let rel = entry.path().context("entry path")?.into_owned();
        let is_file = entry.header().entry_type().is_file();
        let size = entry.header().size().unwrap_or(0);
        if entry.unpack_in(dest).context("unpack entry")? && is_file {
            out.push(Extracted {
                path: dest.join(&rel),
                size,
            });
        }
    }
    out.sort_by(|a, b| b.size.cmp(&a.size));
    Ok(out)
}

/// A `tables` mapping whose bytes are trusted: this exact memory map hashed to the digest committed
/// by a signature-verified ancillary manifest, and its `meta` sidecar passed the version gate. It
/// is the ONLY handle the parse path accepts — the T3-verify → T3-parse wiring the amended plan
/// requires ("no path where parsed-but-unverified state reaches the store"). The verified mapping
/// itself is handed to the parser, so there is no re-open between the digest check and the decode
/// (no swap-the-file TOCTOU): the bytes decoded ARE the bytes hashed.
pub struct VerifiedTables {
    tables: Mmap,
    /// The snapshot slot S (from the `ledger/<slot>/` directory).
    pub slot: u64,
}

impl VerifiedTables {
    /// The trusted `tables` bytes — the exact mapping whose SHA-256 matched the signed digest.
    pub fn bytes(&self) -> &[u8] {
        &self.tables
    }
}

/// Read and verify the `ancillary_manifest.json` under an unpacked ancillary directory: its Ed25519
/// signature must hold under the pinned per-network key (core [`verify_ancillary_manifest`]). The
/// returned handle carries the trusted per-file digests every other T3 step checks against — the
/// single trust root of the certified-state bootstrap.
pub fn verify_manifest(
    ancillary_dir: &Path,
    ancillary_vkey: &[u8; 32],
) -> Result<VerifiedAncillaryManifest> {
    let manifest_bytes = std::fs::read(ancillary_dir.join("ancillary_manifest.json"))
        .context("read ancillary_manifest.json")?;
    verify_ancillary_manifest(&manifest_bytes, ancillary_vkey)
        .map_err(|e| anyhow::anyhow!("ancillary manifest: {e}"))
}

/// Trust the newest `tables` file: confirm the on-disk `tables` and `meta` files hash to the
/// digests the verified manifest commits, then gate `meta`'s codec version. Returns a
/// [`VerifiedTables`] carrying the verified mapping itself — the only handle the parser accepts,
/// with no re-open between the digest check and the decode.
pub fn verified_tables(
    ancillary_dir: &Path,
    verified: &VerifiedAncillaryManifest,
) -> Result<VerifiedTables> {
    let (slot, tables_key) =
        newest_tables_key(verified).context("manifest commits no ledger/<slot>/tables entry")?;
    let meta_key = format!("ledger/{slot}/meta");

    // meta is tiny: read it, match its digest, gate the codec version.
    let meta_bytes = std::fs::read(ancillary_dir.join(&meta_key)).context("read meta")?;
    match_digest(sha256_bytes(&meta_bytes), verified, &meta_key)?;
    tables::parse_meta(&meta_bytes)?;

    // tables: map ONCE, hash THIS mapping, and hand the very same mapping back to the parser.
    let file = File::open(ancillary_dir.join(&tables_key)).context("open tables")?;
    // SAFETY: read-only mapping of a local file, owned by the returned VerifiedTables.
    let tables = unsafe { Mmap::map(&file) }.context("mmap tables")?;
    match_digest(sha256_bytes(&tables), verified, &tables_key)?;

    Ok(VerifiedTables { tables, slot })
}

/// Convenience for the parse path: verify the manifest and return the newest verified `tables`.
pub fn verify_newest_tables(
    ancillary_dir: &Path,
    ancillary_vkey: &[u8; 32],
) -> Result<VerifiedTables> {
    let verified = verify_manifest(ancillary_dir, ancillary_vkey)?;
    verified_tables(ancillary_dir, &verified)
}

/// Derive the certified snapshot's tip S (T4-tip): confirm the `state` file hashes to the digest
/// the verified manifest commits, then parse its AnnTip → [`SnapshotAnchor`]. The tip rides the
/// same signature as the UTxO set, so its basis is [`AnchorBasis::AncillarySigned`] — the T3→T4
/// seam that lets `snapshot-load` seed a `UtxoSet` at a coherent tip.
pub fn verified_anchor(
    ancillary_dir: &Path,
    verified: &VerifiedAncillaryManifest,
) -> Result<SnapshotAnchor> {
    let (slot, _tables_key) =
        newest_tables_key(verified).context("manifest commits no ledger/<slot>/tables entry")?;
    let state_key = format!("ledger/{slot}/state");

    let state_bytes = std::fs::read(ancillary_dir.join(&state_key)).context("read state")?;
    match_digest(sha256_bytes(&state_bytes), verified, &state_key)?;

    let tip = state::parse_tip(&state_bytes, slot)?;
    Ok(SnapshotAnchor {
        tip,
        basis: AnchorBasis::AncillarySigned,
    })
}

/// The `ledger/<slot>/tables` key with the greatest slot (two consecutive snapshots ship; the
/// newer's slot is S), with the slot parsed out.
fn newest_tables_key(verified: &VerifiedAncillaryManifest) -> Option<(u64, String)> {
    verified
        .files()
        .filter_map(|f| {
            let slot = f.strip_prefix("ledger/")?.strip_suffix("/tables")?;
            Some((slot.parse::<u64>().ok()?, f.to_string()))
        })
        .max_by_key(|(slot, _)| *slot)
}

/// Fail closed unless `actual` equals the digest the verified manifest commits for `key`.
fn match_digest(actual: [u8; 32], verified: &VerifiedAncillaryManifest, key: &str) -> Result<()> {
    let expected = verified
        .digest_for(key)
        .with_context(|| format!("manifest commits no digest for {key}"))?;
    if actual != expected {
        bail!(
            "{key}: SHA-256 {} does not match the manifest digest {}",
            hex::encode(actual),
            hex::encode(expected)
        );
    }
    Ok(())
}

/// SHA-256 of a byte slice.
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a `.tar.zst` with two files, then round-trip it through `extract_tar_zst`.
    #[test]
    fn round_trips_a_tar_zst_archive() {
        let dir = tempfile::tempdir().unwrap();

        // Build a tar in memory, then zstd-compress it to `archive.tar.zst`.
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (name, body) in [("ledger/snapshot", &b"UTXO-HD-BODY"[..]), ("meta", b"m")] {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, body).unwrap();
            }
            builder.finish().unwrap();
        }
        let archive = dir.path().join("archive.tar.zst");
        let mut f = File::create(&archive).unwrap();
        f.write_all(&zstd::encode_all(&tar_bytes[..], 3).unwrap())
            .unwrap();
        drop(f);

        let dest = dir.path().join("out");
        let extracted = extract_tar_zst(&archive, &dest).unwrap();

        assert_eq!(extracted.len(), 2);
        // Largest first: the snapshot body (12 bytes) before `meta` (1 byte).
        assert_eq!(extracted[0].size, 12);
        assert!(extracted[0].path.ends_with("ledger/snapshot"));
        assert_eq!(std::fs::read(&extracted[0].path).unwrap(), b"UTXO-HD-BODY");
    }

    /// `verify_manifest` reads and verifies the real committed manifest from a directory and
    /// exposes the trusted digests every T3 step checks against.
    #[test]
    fn verify_manifest_accepts_the_real_committed_manifest() {
        use sextant::ancillary::ANCILLARY_VKEY_PREPROD;
        let dir = tempfile::tempdir().unwrap();
        let manifest = include_bytes!("../../../tests/vectors/utxohd-ancillary-manifest.json");
        File::create(dir.path().join("ancillary_manifest.json"))
            .unwrap()
            .write_all(manifest)
            .unwrap();
        let verified = verify_manifest(dir.path(), &ANCILLARY_VKEY_PREPROD).unwrap();
        assert_eq!(
            hex::encode(verified.digest_for("ledger/128237957/tables").unwrap()),
            "d1d2288fdb89e125cefb82dc9274cb8b24b24c56777351637d2dacc85c37b23c"
        );
    }

    #[test]
    fn sha256_bytes_matches_a_known_digest() {
        // SHA-256("abc")
        assert_eq!(
            hex::encode(sha256_bytes(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// The gate fails closed on a manifest that does not carry a valid ancillary signature — no
    /// `tables` handle is issued, so an unsigned/tampered snapshot never reaches the parser.
    #[test]
    fn verify_newest_tables_fails_closed_without_a_valid_signature() {
        use sextant::ancillary::ANCILLARY_VKEY_PREPROD;
        let dir = tempfile::tempdir().unwrap();
        // A structurally-valid manifest whose signature is all-zero — cannot verify.
        let manifest = format!(
            r#"{{"data":{{"ledger/1/tables":"{}"}},"signature":"{}"}}"#,
            "00".repeat(32),
            "00".repeat(64)
        );
        File::create(dir.path().join("ancillary_manifest.json"))
            .unwrap()
            .write_all(manifest.as_bytes())
            .unwrap();
        assert!(verify_newest_tables(dir.path(), &ANCILLARY_VKEY_PREPROD).is_err());
    }
}
