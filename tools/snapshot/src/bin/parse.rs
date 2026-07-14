//! `snapshot-parse <meta> <tables>` — gate the meta, memory-map the tables file, stream the UTxO
//! outpoints on Sextant's own path, and print the count, a deterministic set fingerprint, and a
//! few samples. Tier-2 T3-parse: proves the parser at snapshot scale and produces the numbers the
//! differential (node `query utxo --whole-utxo`, Koios spot-samples) checks against.

use std::fs::File;

use anyhow::{Context, Result};
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use snapshot::tables::{for_each_outpoint, parse_meta};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let meta_path = args
        .next()
        .context("usage: snapshot-parse <meta> <tables>")?;
    let tables_path = args
        .next()
        .context("usage: snapshot-parse <meta> <tables>")?;

    let meta = parse_meta(&std::fs::read(&meta_path).context("read meta")?)?;
    eprintln!(
        "meta OK: backend={} tablesCodecVersion={}",
        meta.backend, meta.tables_codec_version
    );

    let file = File::open(&tables_path).context("open tables")?;
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
