//! Tier-2 T3-fetch: unpack the Mithril cardano-database ancillary (`.tar.zst`) — the InMemory
//! UTxO-HD ledger-state snapshot the certified-state bootstrap parses.
//!
//! zstd + tar live in this tools crate, never in the sextant trust core (which stays sans-io and
//! wasm-safe). The stream is decompressed and untarred incrementally, so the full 1.88 GB
//! uncompressed archive is never held in memory.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

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
}
