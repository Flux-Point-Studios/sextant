//! `snapshot-load <ancillary-dir> <preprod|mainnet> <redb-path>` — the Tier-2 T3-load step: verify
//! the ancillary manifest, stream the verified UTxO outpoints into an on-disk `RedbUtxoStore`, and
//! leave a persisted certified membership set — the outpoints unspent as of the snapshot slot S,
//! on the `AncillarySigned` basis. The store then answers "is this outpoint in the certified set at
//! S?" for any outpoint.
//!
//! The set is current as of S; binding it to a concrete tip block (hash + number) is the T3→T4
//! seam. S's block is not in the ancillary — the bundled immutable chunk is a LATER, unrelated
//! immutable file, and the ledger `state` tip sits inside the ExtLedgerState the amended plan
//! declines to parse — so T4 resolves S→block against the certified chain it must reach anyway,
//! then seeds a `UtxoSet` at that tip from this store (`UtxoSet::with_store`).

use anyhow::{Context, Result, bail};
use sextant::ancillary::{ANCILLARY_VKEY_MAINNET, ANCILLARY_VKEY_PREPROD};
use sextant::utxo::OutPoint;
use sextant::utxoset::{AnchorBasis, UtxoStore};
use snapshot::{tables::for_each_outpoint, verified_tables, verify_manifest};
use utxo_store::RedbUtxoStore;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let ancillary_dir = args
        .next()
        .context("usage: snapshot-load <ancillary-dir> <preprod|mainnet> <redb-path>")?;
    let network = args
        .next()
        .context("usage: snapshot-load <ancillary-dir> <preprod|mainnet> <redb-path>")?;
    let redb_path = args
        .next()
        .context("usage: snapshot-load <ancillary-dir> <preprod|mainnet> <redb-path>")?;
    let vkey = match network.as_str() {
        "preprod" => &ANCILLARY_VKEY_PREPROD,
        "mainnet" => &ANCILLARY_VKEY_MAINNET,
        other => bail!("unknown network {other:?} (expected preprod or mainnet)"),
    };
    let dir = std::path::Path::new(&ancillary_dir);

    // One trust root: verify the manifest, then trust the newest tables from its committed digest.
    let verified = verify_manifest(dir, vkey)?;
    let tables = verified_tables(dir, &verified)?;
    eprintln!(
        "verified: manifest signature OK, tables+meta digests OK, codec gated (slot {})",
        tables.slot
    );

    // Stream the verified outpoints, then bulk-seed the on-disk store in one atomic load.
    let mut outpoints = Vec::new();
    let parsed = for_each_outpoint(tables.bytes(), |o| {
        outpoints.push(o);
        Ok(())
    })?;
    let first = outpoints.first().copied();

    let mut store =
        RedbUtxoStore::create(&redb_path).map_err(|e| anyhow::anyhow!("store: {}", e.0))?;
    let loaded = store
        .bulk_insert(outpoints)
        .map_err(|e| anyhow::anyhow!("bulk load: {}", e.0))?;
    let len = store.len().map_err(|e| anyhow::anyhow!("store: {}", e.0))?;

    // Checked post-condition: the parser dedups (strictly-increasing keys) into a fresh store, so
    // every parsed outpoint is a new insert and the store holds exactly them. Any divergence means
    // a lossy load OR a non-empty start (a stale DB unioned in) — fail closed, never report clean.
    if loaded != parsed || len != parsed {
        bail!(
            "load discrepancy: parsed={parsed} loaded={loaded} store_len={len} (non-empty start or lossy load)"
        );
    }

    println!("slot_S: {}", tables.slot);
    println!("basis: {:?}", AnchorBasis::AncillarySigned);
    println!("parsed_outpoints: {parsed}");
    println!("loaded_outpoints: {loaded}");
    println!("store_len: {len}");
    // Membership probes: a real snapshot outpoint is in the set; a fabricated one is not.
    if let Some(o) = first {
        let present = store
            .contains(&o)
            .map_err(|e| anyhow::anyhow!("store: {}", e.0))?;
        println!(
            "probe_present {}#{}: contained={present}",
            hex::encode(o.tx_id),
            o.index
        );
    }
    let absent = OutPoint {
        tx_id: [0xff; 32],
        index: 0,
    };
    let absent_c = store
        .contains(&absent)
        .map_err(|e| anyhow::anyhow!("store: {}", e.0))?;
    println!("probe_absent ff..#0: contained={absent_c}");
    Ok(())
}
