//! `snapshot-extract <archive.tar.zst> <dest-dir>` — unpack a Mithril cardano-database ancillary
//! and print its contents (largest first), so the ledger-state snapshot file can be located and
//! its format inspected. Tier-2 T3-fetch tooling.

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let archive = args
        .next()
        .context("usage: snapshot-extract <archive.tar.zst> <dest-dir>")?;
    let dest = args
        .next()
        .context("usage: snapshot-extract <archive.tar.zst> <dest-dir>")?;

    let extracted = snapshot::extract_tar_zst(archive.as_ref(), dest.as_ref())?;
    println!("unpacked {} files into {dest}:", extracted.len());
    for e in &extracted {
        println!("  {:>13} B  {}", e.size, e.path.display());
    }
    Ok(())
}
