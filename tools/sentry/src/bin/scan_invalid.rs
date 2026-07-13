//! One-off harvest (Tier-2 T2b): sweep MAINNET blocks backward from tip over a relay and save
//! the first block carrying a phase-2-invalid transaction (pallas `!is_valid()`) — the vector
//! T2b needs to build + differential-test the collateral-spend delta. Mainnet because phase-2
//! failures are far denser there than on preprod (they cost the submitter collateral, so
//! testers avoid them). The extraction path is network-agnostic CBOR, so a mainnet block is a
//! valid vector, as the existing mainnet VRF/KES vectors already are. Not production.

use anyhow::{Context, Result};
use pallas_network::facades::PeerClient;
use pallas_network::miniprotocols::Point;
use pallas_traverse::MultiEraBlock;
use sentry::transport::blockfetch_range;
use serde::Deserialize;

const RELAY: &str = "backbone.cardano.iog.io:3001";
const MAGIC: u64 = 764_824_073;
const KOIOS: &str = "https://api.koios.rest/api/v1";

#[derive(Deserialize)]
struct TipRow {
    block_no: u64,
}

async fn koios_tip(http: &reqwest::Client) -> Result<u64> {
    let rows: Vec<TipRow> = http
        .get(format!("{KOIOS}/tip"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(rows.into_iter().next().context("koios tip empty")?.block_no)
}

async fn koios_point(http: &reqwest::Client, block_no: u64) -> Result<Point> {
    #[derive(Deserialize)]
    struct BlockRow {
        abs_slot: u64,
        hash: String,
        block_height: u64,
    }
    let list: Vec<BlockRow> = http
        .get(format!("{KOIOS}/blocks"))
        .query(&[
            ("select", "abs_slot,hash,block_height"),
            ("block_height", &format!("eq.{block_no}")),
            ("limit", "1"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let r = list
        .into_iter()
        .find(|r| r.block_height == block_no)
        .context("koios block not found")?;
    Ok(Point::Specific(r.abs_slot, hex::decode(&r.hash)?))
}

/// Fetch a single mainnet block by number and save it as a committed vector.
async fn fetch_one(http: &reqwest::Client, num: u64, label: &str) -> Result<()> {
    let pt = koios_point(http, num).await?;
    let mut peer = PeerClient::connect(RELAY, MAGIC)
        .await
        .context("connect mainnet relay")?;
    let blocks = blockfetch_range(&mut peer, pt.clone(), pt).await?;
    let raw = blocks.into_iter().next().context("no block returned")?;
    let b = MultiEraBlock::decode(&raw).context("decode fetched block")?;
    let path = format!(
        "{}/../../tests/vectors/{label}-{num}.block",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::write(&path, hex::encode(&raw))?;
    let invalid = b.txs().iter().filter(|t| !t.is_valid()).count();
    println!(
        "fetched block {num} ({} txs, {invalid} invalid) -> {path}",
        b.txs().len()
    );
    Ok(())
}

/// Vasil (Babbage) began at mainnet epoch 365 ≈ block 7_939_206; the collateral-return delta
/// this harvester targets is Babbage-onward, so a pre-Vasil hit cannot satisfy the slice.
const POST_VASIL_FLOOR: u64 = 7_939_206;

#[tokio::main]
async fn main() -> Result<()> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    if let Some(num) = std::env::var("FETCH_BLOCK")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        let label = std::env::var("FETCH_LABEL").unwrap_or_else(|_| "mainnet".to_string());
        return fetch_one(&http, num, &label).await;
    }

    let tip_block = match std::env::var("SCAN_FROM").ok().and_then(|v| v.parse().ok()) {
        Some(b) => b,
        None => koios_tip(&http).await?,
    };
    eprintln!("mainnet: scanning backward from block {tip_block} for a phase-2-invalid tx");

    let chunk: u64 = 200;
    let max_scan: u64 = std::env::var("MAX_SCAN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000);
    // Never scan below Vasil: a pre-Babbage invalid tx has a different (no-return) collateral
    // delta and would falsely "satisfy" the slice while exercising a rule we did not build.
    let stop = tip_block.saturating_sub(max_scan).max(POST_VASIL_FLOOR);
    let mut hi = tip_block.saturating_sub(4);
    let mut scanned = 0u64;
    let mut decoded = 0u64;
    let mut total_txs = 0u64;
    let mut decode_errs = 0u64;

    while hi > stop {
        let lo = (hi + 1).saturating_sub(chunk).max(stop);
        let (lo_pt, hi_pt) = match (koios_point(&http, lo).await, koios_point(&http, hi).await) {
            (Ok(l), Ok(h)) => (l, h),
            _ => {
                hi = lo.saturating_sub(1);
                continue;
            }
        };
        let mut peer = PeerClient::connect(RELAY, MAGIC)
            .await
            .context("connect mainnet relay")?;
        let blocks = match blockfetch_range(&mut peer, lo_pt, hi_pt).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  blockfetch {lo}..{hi} failed: {e}; skipping");
                hi = lo.saturating_sub(1);
                continue;
            }
        };
        for raw in &blocks {
            if let Ok(b) = MultiEraBlock::decode(raw) {
                decoded += 1;
                total_txs += b.txs().len() as u64;
                let invalid: Vec<usize> = b
                    .txs()
                    .iter()
                    .enumerate()
                    .filter(|(_, tx)| !tx.is_valid())
                    .map(|(i, _)| i)
                    .collect();
                if !invalid.is_empty() {
                    let num = b.number();
                    let path = format!(
                        "{}/../../tests/vectors/invalid-mainnet-{num}.block",
                        env!("CARGO_MANIFEST_DIR")
                    );
                    std::fs::write(&path, hex::encode(raw))?;
                    println!(
                        "FOUND mainnet invalid-tx block {num} (invalid indices {invalid:?} of {} txs) -> {path}",
                        b.txs().len()
                    );
                    return Ok(());
                }
            } else {
                decode_errs += 1;
            }
        }
        scanned += blocks.len() as u64;
        eprintln!(
            "  scanned {lo}..{hi} ({scanned} blocks, {decoded} decoded, {decode_errs} decode-err, {total_txs} txs, none invalid)"
        );
        hi = lo.saturating_sub(1);
    }
    println!("no phase-2-invalid tx found in the last {max_scan} mainnet blocks");
    Ok(())
}
