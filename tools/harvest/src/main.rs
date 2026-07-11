//! Vector harvester: pull recent preprod block CBOR off a public relay into
//! `tests/vectors/`, so the differential harness has real, current-era headers
//! to check Sextant's decoder against. Run manually — not wired into CI.
//!
//!   cargo run -p harvest [count]     # fetch `count` (default 24) block vectors
//!   cargo run -p harvest eta0        # backfill epoch-nonce sidecars for them
//!
//! Recent settled block points come from Koios preprod (keyless JSON); the raw
//! `[era, block]` CBOR comes from the relay via the node-to-node BlockFetch
//! mini-protocol. The `eta0` mode adds, next to each `preprod-<slot>.block`, a
//! `preprod-<slot>.eta0` sidecar holding that block's epoch nonce (32-byte hex)
//! from Koios — the input the full leader-VRF verify binds `alpha` to. Both the
//! CBOR and the nonce are inputs to verify, never trusted state.

use anyhow::{Context, Result, ensure};
use pallas_network::facades::PeerClient;
use pallas_network::miniprotocols::Point;
use pallas_traverse::MultiEraBlock;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

const RELAY: &str = "preprod-node.play.dev.cardano.org:3001";
const KOIOS: &str = "https://preprod.koios.rest/api/v1";
const PREPROD_MAGIC: u64 = 1;
/// Skip the newest few blocks — near the tip they can still roll back.
const SETTLE_SKIP: usize = 8;

#[derive(Deserialize)]
struct KoiosBlock {
    abs_slot: u64,
    hash: String,
}

/// One `block_info` row: which epoch a block was minted in.
#[derive(Deserialize)]
struct BlockInfo {
    hash: String,
    epoch_no: u64,
}

/// One `epoch_params` row: the active epoch nonce (eta0) for leader election.
#[derive(Deserialize)]
struct EpochParam {
    nonce: Option<String>,
}

fn point(b: &KoiosBlock) -> Result<Point> {
    Ok(Point::Specific(b.abs_slot, hex::decode(&b.hash)?))
}

fn vectors_dir() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .canonicalize()
        .context("tests/vectors must exist")
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("eta0") {
        return backfill_eta0().await;
    }
    fetch_blocks().await
}

/// BlockFetch `count` recent settled preprod blocks off the relay and write
/// them as hex vectors named by slot.
async fn fetch_blocks() -> Result<()> {
    let want: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);

    let out_dir = vectors_dir()?;

    // 1. Recent settled block points (newest-first) from Koios preprod.
    let url = format!("{KOIOS}/blocks?limit={}", want + SETTLE_SKIP + 4);
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
        let blk = MultiEraBlock::decode(bytes).context("pallas decode of fetched block")?;
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

/// For every `preprod-<slot>.block` vector, look up the epoch it was minted in
/// and that epoch's active nonce (eta0), and write it as a `preprod-<slot>.eta0`
/// sidecar. Uses Koios only (no relay); leaves the block CBOR untouched.
async fn backfill_eta0() -> Result<()> {
    let out_dir = vectors_dir()?;
    let client = reqwest::Client::new();

    // 1. Map each preprod vector's block hash to its slot (from the CBOR).
    let mut slot_by_hash: HashMap<String, u64> = HashMap::new();
    for entry in std::fs::read_dir(&out_dir).context("read vectors dir")? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with("preprod-")
            || path.extension().and_then(|e| e.to_str()) != Some("block")
        {
            continue;
        }
        let bytes = hex::decode(std::fs::read_to_string(&path)?.trim())
            .with_context(|| format!("hex decode {}", path.display()))?;
        let blk = MultiEraBlock::decode(&bytes)
            .with_context(|| format!("pallas decode {}", path.display()))?;
        slot_by_hash.insert(blk.hash().to_string(), blk.slot());
    }
    ensure!(!slot_by_hash.is_empty(), "no preprod vectors found");
    let hashes: Vec<&String> = slot_by_hash.keys().collect();

    // 2. Koios block_info -> epoch per block hash.
    let infos: Vec<BlockInfo> = client
        .post(format!("{KOIOS}/block_info"))
        .header("accept", "application/json")
        .json(&serde_json::json!({ "_block_hashes": hashes }))
        .send()
        .await
        .context("koios block_info request")?
        .error_for_status()?
        .json()
        .await
        .context("koios block_info json")?;

    // 3. Koios epoch_params -> eta0 per distinct epoch (fetched once each).
    let mut nonce_by_epoch: HashMap<u64, [u8; 32]> = HashMap::new();
    for info in &infos {
        if nonce_by_epoch.contains_key(&info.epoch_no) {
            continue;
        }
        nonce_by_epoch.insert(info.epoch_no, fetch_eta0(&client, info.epoch_no).await?);
    }

    // 4. Write one sidecar per vector.
    let mut written = 0usize;
    for info in &infos {
        let slot = slot_by_hash
            .get(&info.hash)
            .with_context(|| format!("block_info returned unknown hash {}", info.hash))?;
        let eta0 = &nonce_by_epoch[&info.epoch_no];
        let path = out_dir.join(format!("preprod-{slot}.eta0"));
        std::fs::write(&path, hex::encode(eta0)).context("write eta0 sidecar")?;
        println!("  wrote {} (epoch {})", path.display(), info.epoch_no);
        written += 1;
    }
    println!(
        "backfilled {written} eta0 sidecars into {}",
        out_dir.display()
    );
    Ok(())
}

/// Fetch and validate the 32-byte active nonce for one preprod epoch.
async fn fetch_eta0(client: &reqwest::Client, epoch: u64) -> Result<[u8; 32]> {
    let params: Vec<EpochParam> = client
        .get(format!(
            "{KOIOS}/epoch_params?_epoch_no={epoch}&select=nonce"
        ))
        .header("accept", "application/json")
        .send()
        .await
        .with_context(|| format!("koios epoch_params epoch {epoch}"))?
        .error_for_status()?
        .json()
        .await
        .with_context(|| format!("koios epoch_params json epoch {epoch}"))?;
    let nonce = params
        .first()
        .and_then(|p| p.nonce.as_deref())
        .with_context(|| format!("no nonce for epoch {epoch}"))?;
    let bytes = hex::decode(nonce).with_context(|| format!("eta0 hex epoch {epoch}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("eta0 for epoch {epoch} was {} bytes, want 32", bytes.len()))
}
