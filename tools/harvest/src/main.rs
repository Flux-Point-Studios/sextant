//! Vector harvester: pull recent preprod block CBOR off a public relay into
//! `tests/vectors/`, so the differential harness has real, current-era headers
//! to check Sextant's decoder against. Run manually — not wired into CI.
//!
//!   cargo run -p harvest [count]     # default 24 blocks
//!
//! Recent settled block points come from Koios preprod (keyless JSON); the raw
//! `[era, block]` CBOR comes from the relay via the node-to-node BlockFetch
//! mini-protocol. Vectors are inputs to verify, never trusted state.

use anyhow::{Context, Result, ensure};
use pallas_network::facades::PeerClient;
use pallas_network::miniprotocols::Point;
use serde::Deserialize;
use std::path::PathBuf;

const RELAY: &str = "preprod-node.play.dev.cardano.org:3001";
const KOIOS: &str = "https://preprod.koios.rest/api/v1/blocks";
const PREPROD_MAGIC: u64 = 1;
/// Skip the newest few blocks — near the tip they can still roll back.
const SETTLE_SKIP: usize = 8;

#[derive(Deserialize)]
struct KoiosBlock {
    abs_slot: u64,
    hash: String,
}

fn point(b: &KoiosBlock) -> Result<Point> {
    Ok(Point::Specific(b.abs_slot, hex::decode(&b.hash)?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let want: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);

    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .canonicalize()
        .context("tests/vectors must exist")?;

    // 1. Recent settled block points (newest-first) from Koios preprod.
    let url = format!("{KOIOS}?limit={}", want + SETTLE_SKIP + 4);
    let mut blocks: Vec<KoiosBlock> = reqwest::Client::new()
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await
        .context("koios request")?
        .error_for_status()?
        .json()
        .await
        .context("koios json")?;
    if blocks.len() > SETTLE_SKIP {
        blocks.drain(0..SETTLE_SKIP);
    }
    blocks.truncate(want);
    blocks.reverse(); // oldest -> newest, contiguous by height
    ensure!(blocks.len() >= 2, "koios returned too few blocks");

    let start = point(blocks.first().unwrap())?;
    let end = point(blocks.last().unwrap())?;
    println!(
        "fetching {} blocks from {RELAY}: slot {} .. {}",
        blocks.len(),
        blocks.first().unwrap().abs_slot,
        blocks.last().unwrap().abs_slot
    );

    // 2. BlockFetch the range as raw CBOR from a public preprod relay.
    let mut peer = PeerClient::connect(RELAY, PREPROD_MAGIC)
        .await
        .context("connect preprod relay")?;
    let raw_blocks = peer
        .blockfetch()
        .fetch_range((start, end))
        .await
        .context("blockfetch range")?;
    peer.abort().await;

    // 3. Sanity-decode each with pallas, then write hex named by slot.
    let mut written = 0usize;
    for bytes in &raw_blocks {
        let blk = pallas_traverse::MultiEraBlock::decode(bytes)
            .context("pallas decode of fetched block")?;
        let path = out_dir.join(format!("preprod-{}.block", blk.slot()));
        std::fs::write(&path, hex::encode(bytes)).context("write vector")?;
        println!("  wrote {} ({} bytes)", path.display(), bytes.len());
        written += 1;
    }
    println!(
        "harvested {written} preprod block vectors into {}",
        out_dir.display()
    );
    Ok(())
}
