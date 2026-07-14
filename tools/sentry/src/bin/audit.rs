//! Tier-2 discharge audit (provenance spot-check): sample transactions from the certified UTxO
//! set@S and prove each is a real, STM-stake-quorum-certified transaction — catching a PHANTOM the
//! forward follow cannot (an outpoint the ancillary padded that no window block re-creates).
//!
//! For each sampled `tx_id`: fetch the Mithril `CardanoTransactions` inclusion proof, and RECOMPUTE
//! it on Sextant's own path ([`sextant::inclusion::verify_tx_inclusion`]) against the Merkle root of
//! a `verify_chain_anchored`-authenticated certificate (via `fetch_fresh_anchor`, genesis-anchored to
//! the pinned vkey). The aggregator supplies BYTES (the proof); Sextant supplies the verdict — a
//! phantom's `tx_id` is listed non-certified or fails the recompute, never a trusted "yes".
//!
//! This is the trustless complement to the forward subset-consistency audit (setfollow.rs). It is a
//! SAMPLE, not the full set; a full `AncillarySigned → StmCertified` discharge proves every member.
//!
//! Usage: `sextant-audit <ancillary-dir> <preprod|mainnet> <sample-size>`

use anyhow::{Context, Result, bail};
use sentry::transport::{fetch_fresh_anchor, fetch_tx_proof, load_committed_base, vectors_dir};
use sextant::ancillary::{ANCILLARY_VKEY_MAINNET, ANCILLARY_VKEY_PREPROD};
use sextant::inclusion::verify_tx_inclusion;
use snapshot::{tables::for_each_outpoint, verified_tables, verify_manifest};
use std::collections::HashSet;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .context("usage: <ancillary-dir> <network> <sample-size>")?;
    let network = args
        .next()
        .context("usage: <ancillary-dir> <network> <sample-size>")?;
    let sample: usize = args
        .next()
        .context("usage: <ancillary-dir> <network> <sample-size>")?
        .parse()
        .context("sample-size")?;
    let vkey = match network.as_str() {
        "preprod" => &ANCILLARY_VKEY_PREPROD,
        "mainnet" => &ANCILLARY_VKEY_MAINNET,
        other => bail!("unknown network {other:?}"),
    };
    let dir = std::path::Path::new(&dir);

    // Trust the tables from the signed manifest, then sample distinct tx_ids from the set@S.
    let verified = verify_manifest(dir, vkey)?;
    let tables = verified_tables(dir, &verified)?;
    let mut seen = HashSet::new();
    let mut tx_ids: Vec<[u8; 32]> = Vec::new();
    let _ = for_each_outpoint(tables.bytes(), |o| {
        if seen.insert(o.tx_id) {
            tx_ids.push(o.tx_id);
            if tx_ids.len() >= sample {
                bail!("__sampled__"); // sentinel: stop after `sample` distinct tx_ids
            }
        }
        Ok(())
    });
    eprintln!(
        "sampled {} distinct tx_ids from the certified set@S",
        tx_ids.len()
    );

    // The genesis-anchored, STM-certified transaction Merkle root — the trust root the proofs are
    // recomputed against.
    let (base, genesis_vkey) = load_committed_base(&vectors_dir())?;
    let http = reqwest::Client::new();
    let anchor = fetch_fresh_anchor(&http, &base, &genesis_vkey).await?;
    let root = anchor
        .merkle_root_bytes()
        .context("certified anchor has a malformed merkle root")?;
    eprintln!(
        "certified transaction root @ epoch {} block {} (genesis-anchored)",
        anchor.epoch, anchor.block_number
    );

    let mut certified = 0usize;
    let mut phantom = 0usize;
    for (i, tx_id) in tx_ids.iter().enumerate() {
        let hex = hex::encode(tx_id);
        match fetch_tx_proof(&http, &hex).await? {
            None => {
                phantom += 1;
                eprintln!("PHANTOM: tx {hex} is NOT in the certified set");
            }
            Some(proof) => match verify_tx_inclusion(&proof, tx_id, &root) {
                Ok(()) => {
                    certified += 1;
                    if i < 3 || (i + 1) % 25 == 0 {
                        eprintln!("verified #{}: tx {hex} STM-certified", i + 1);
                    }
                }
                Err(e) => {
                    phantom += 1;
                    eprintln!("FAILED: tx {hex} proof did not recompute to the root: {e}");
                }
            },
        }
    }

    println!("sampled: {}", tx_ids.len());
    println!("certified_real: {certified}");
    println!("phantom_or_failed: {phantom}");
    if phantom == 0 {
        println!("result: PASS (every sampled set@S transaction is STM-certified real)");
    } else {
        println!("result: FAIL ({phantom} sampled transactions are not certified)");
    }
    Ok(())
}
