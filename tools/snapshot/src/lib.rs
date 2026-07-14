//! Tier-2 T3-fetch: unpack the Mithril cardano-database ancillary (`.tar.zst`) — the InMemory
//! UTxO-HD ledger-state snapshot the certified-state bootstrap parses.
//!
//! zstd + tar live in this tools crate, never in the sextant trust core (which stays sans-io and
//! wasm-safe). The stream is decompressed and untarred incrementally, so the full 1.88 GB
//! uncompressed archive is never held in memory.

pub mod tables;

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sextant::ancillary::{VerifiedAncillaryManifest, verify_ancillary_manifest};
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

/// A `tables` file whose bytes are trusted: its SHA-256 matched the digest committed by a
/// signature-verified ancillary manifest, and its `meta` sidecar passed the version gate. This is
/// the ONLY handle the parse path accepts — the T3-verify → T3-parse wiring the amended plan
/// requires ("no path where parsed-but-unverified state reaches the store").
pub struct VerifiedTables {
    /// Path to the trusted `tables` file, ready to memory-map and stream.
    pub tables_path: PathBuf,
    /// The snapshot slot S (from the `ledger/<slot>/` directory).
    pub slot: u64,
}

/// Establish trust in the newest `tables` file under an unpacked ancillary directory, on the full
/// chain: verify the `ancillary_manifest.json` Ed25519 signature under the pinned network key
/// (core [`verify_ancillary_manifest`]), then confirm the on-disk `tables` and `meta` files hash
/// to the digests that signature commits, then gate `meta`'s codec version. Returns a
/// [`VerifiedTables`] only when every link holds — a tampered or unsigned blob fails closed here,
/// before a single outpoint is decoded.
pub fn verify_newest_tables(
    ancillary_dir: &Path,
    ancillary_vkey: &[u8; 32],
) -> Result<VerifiedTables> {
    let manifest_bytes = std::fs::read(ancillary_dir.join("ancillary_manifest.json"))
        .context("read ancillary_manifest.json")?;
    let verified = verify_ancillary_manifest(&manifest_bytes, ancillary_vkey)
        .map_err(|e| anyhow::anyhow!("ancillary manifest: {e}"))?;

    let (slot, tables_key) =
        newest_tables_key(&verified).context("manifest commits no ledger/<slot>/tables entry")?;
    let meta_key = format!("ledger/{slot}/meta");

    let tables_path = ancillary_dir.join(&tables_key);
    let meta_path = ancillary_dir.join(&meta_key);

    check_digest(&tables_path, &verified, &tables_key)?;
    check_digest(&meta_path, &verified, &meta_key)?;

    // Gate the codec version on the now-trusted meta bytes.
    tables::parse_meta(&std::fs::read(&meta_path).context("read meta")?)?;

    Ok(VerifiedTables { tables_path, slot })
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

/// Fail closed unless `path`'s SHA-256 equals the digest the verified manifest commits for `key`.
fn check_digest(path: &Path, verified: &VerifiedAncillaryManifest, key: &str) -> Result<()> {
    let expected = verified
        .digest_for(key)
        .with_context(|| format!("manifest commits no digest for {key}"))?;
    let actual = sha256_file(path)?;
    if actual != expected {
        bail!(
            "{key}: SHA-256 {} does not match the manifest digest {}",
            hex::encode(actual),
            hex::encode(expected)
        );
    }
    Ok(())
}

/// SHA-256 of a file, memory-mapped so a multi-hundred-MB `tables` blob is not read into the heap.
pub fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    // SAFETY: read-only mapping of a local file for the duration of the hash.
    let mmap =
        unsafe { memmap2::Mmap::map(&file) }.with_context(|| format!("mmap {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&mmap);
    Ok(hasher.finalize().into())
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

    #[test]
    fn sha256_file_matches_a_known_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        File::create(&path).unwrap().write_all(b"abc").unwrap();
        // SHA-256("abc")
        assert_eq!(
            hex::encode(sha256_file(&path).unwrap()),
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
