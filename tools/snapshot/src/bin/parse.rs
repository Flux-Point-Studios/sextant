//! `snapshot-parse <ancillary-dir> <network>` — the GATED certified-state bootstrap read: verify
//! the ancillary manifest's Ed25519 signature under the pinned network key, confirm the on-disk
//! `tables`/`meta` hash to the digests that signature commits, gate the codec version, and only
//! THEN stream the UTxO outpoints on Sextant's own path. Prints the count, a set fingerprint, and
//! a few samples. No unverified bytes ever reach the parser.

use std::fs::File;

use anyhow::{Context, Result, bail};
use memmap2::Mmap;
use sextant::ancillary::{ANCILLARY_VKEY_MAINNET, ANCILLARY_VKEY_PREPROD};
use sha2::{Digest, Sha256};
use snapshot::{tables::for_each_outpoint, verify_newest_tables};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let ancillary_dir = args
        .next()
        .context("usage: snapshot-parse <ancillary-dir> <preprod|mainnet>")?;
    let network = args
        .next()
        .context("usage: snapshot-parse <ancillary-dir> <preprod|mainnet>")?;
    let vkey = match network.as_str() {
        "preprod" => &ANCILLARY_VKEY_PREPROD,
        "mainnet" => &ANCILLARY_VKEY_MAINNET,
        other => bail!("unknown network {other:?} (expected preprod or mainnet)"),
    };

    let verified = verify_newest_tables(std::path::Path::new(&ancillary_dir), vkey)?;
    eprintln!(
        "verified: manifest signature OK, tables+meta digests OK, codec gated (slot {})",
        verified.slot
    );

    let file = File::open(&verified.tables_path).context("open tables")?;
    // SAFETY: read-only mapping of a local file for the lifetime of this process.
    let mmap = unsafe { Mmap::map(&file) }.context("mmap tables")?;

    let mut hasher = Sha256::new();
    let mut samples = Vec::new();
    let count = for_each_outpoint(&mmap, |o| {
        hasher.update(o.tx_id);
        hasher.update(o.index.to_be_bytes());
        if samples.len() < 3 {
            samples.push(format!("{}#{}", hex::encode(o.tx_id), o.index));
        }
        Ok(())
    })?;

    println!("utxo_count: {count}");
    println!("set_fingerprint_sha256: {}", hex::encode(hasher.finalize()));
    println!("first_outpoints:");
    for s in &samples {
        println!("  {s}");
    }
    Ok(())
}
