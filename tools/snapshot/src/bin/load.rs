//! `snapshot-load <ancillary-dir> <preprod|mainnet> <redb-path>` — the Tier-2 T3-load + T4-tip
//! step: verify the ancillary manifest, derive the certified tip S (`state` AnnTip), stream the
//! verified UTxO outpoints into an on-disk `RedbUtxoStore`, and seed a `UtxoSet` at that tip on the
//! `AncillarySigned` basis. The result is a certified membership set anchored to a concrete tip
//! block — ready for T4 to follow S→tip via the relay (chain-sync intersect at the tip's
//! `(slot, hash)`, then apply blocks forward).

use anyhow::{Context, Result, bail};
use sextant::ancillary::{ANCILLARY_VKEY_MAINNET, ANCILLARY_VKEY_PREPROD};
use sextant::utxo::OutPoint;
use sextant::utxoset::{UtxoSet, UtxoStore};
use snapshot::{tables::for_each_outpoint, verified_anchor, verified_tables, verify_manifest};
use utxo_store::RedbUtxoStore;

/// The retained rollback window (k = 2160 blocks) the seeded set carries into the follow.
const DEPTH: usize = 2160;

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

    // One trust root: verify the manifest, then trust the newest tables + derive the tip from the
    // committed digests. The anchor's tip and the set share the AncillarySigned basis.
    let verified = verify_manifest(dir, vkey)?;
    let tables = verified_tables(dir, &verified)?;
    let anchor = verified_anchor(dir, &verified)?;
    eprintln!(
        "verified: manifest signature OK, tables+meta+state digests OK, tip #{} {} (slot {})",
        anchor.tip.number,
        hex::encode(anchor.tip.hash),
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

    // Seed the UtxoSet at the derived tip: the persisted store, anchored to (slot S, tip block),
    // ready for T4 to follow S→tip. Membership answers ride this tip.
    let set = UtxoSet::with_store(store, Some(anchor.tip), DEPTH);

    println!("slot_S: {}", tables.slot);
    println!(
        "anchor_tip: #{} {}",
        anchor.tip.number,
        hex::encode(anchor.tip.hash)
    );
    println!("basis: {:?}", anchor.basis);
    println!("parsed_outpoints: {parsed}");
    println!("loaded_outpoints: {loaded}");
    println!("set_len: {len}");
    // The loaded set's own commitment — must equal the ancillary tables' set_fingerprint_sha256
    // (snapshot-parse), proving the redb-backed load is byte-faithful to the signed snapshot.
    let fp = set
        .fingerprint()
        .map_err(|e| anyhow::anyhow!("fingerprint: {}", e.0))?;
    println!("set_fingerprint_sha256: {}", hex::encode(fp));
    // Membership probes: a real snapshot outpoint is unspent at the tip; a fabricated one is not.
    if let Some(o) = first {
        let unspent = set
            .is_unspent(&o)
            .map_err(|e| anyhow::anyhow!("store: {}", e.0))?;
        println!(
            "probe_present {}#{}: is_unspent={unspent}",
            hex::encode(o.tx_id),
            o.index
        );
    }
    let absent = OutPoint {
        tx_id: [0xff; 32],
        index: 0,
    };
    let absent_u = set
        .is_unspent(&absent)
        .map_err(|e| anyhow::anyhow!("store: {}", e.0))?;
    println!("probe_absent ff..#0: is_unspent={absent_u}");
    Ok(())
}
