//! Vector harvester: pull recent preprod/mainnet block CBOR off a public relay
//! into `tests/vectors/`, so the differential harness has real, current-era
//! headers to check Sextant's decoder against. Run manually — not wired into CI.
//!
//!   cargo run -p harvest [count]         # fetch `count` (default 24) preprod vectors
//!   cargo run -p harvest eta0            # backfill preprod epoch-nonce sidecars
//!   cargo run -p harvest mainnet [count] # fetch `count` mainnet block vectors
//!   cargo run -p harvest mainnet-eta0    # backfill mainnet epoch-nonce sidecars
//!   cargo run -p harvest boundary        # fetch a run spanning the 299→300 turn
//!   cargo run -p harvest mithril         # walk the cert chain tip→(12 hops)
//!   cargo run -p harvest mithril-genesis # walk tip→genesis, pin the trust root
//!   cargo run -p harvest mithril-anchor-chain [tip] # genesis→tip chain as one array
//!   cargo run -p harvest tx-cbor <hash>  # raw tx BODY CBOR (hashes to the txid)
//!
//! Recent settled block points come from Koios (keyless JSON); the raw
//! `[era, block]` CBOR comes from the relay via the node-to-node BlockFetch
//! mini-protocol. The `eta0` mode adds, next to each `preprod-<slot>.block`, a
//! `preprod-<slot>.eta0` sidecar holding that block's epoch nonce (32-byte hex)
//! from Koios — the input the full leader-VRF verify binds `alpha` to. The
//! `boundary` mode fetches a short contiguous run across the epoch 299→300 turn
//! as `boundary-<slot>.block` + `.eta0`, tagging each block with its own epoch's
//! nonce so the boundary test can prove leader election evolved with the nonce.
//! Both the CBOR and the nonce are inputs to verify, never trusted state.

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
/// Mithril aggregator for the preprod network the block vectors come from.
const MITHRIL_AGG: &str = "https://aggregator.release-preprod.api.mithril.network/aggregator";
/// Cap the tip→genesis walk so a long production chain can't harvest hundreds of
/// vectors; enough hops to prove byte-exact hashing + `previous_hash` linking.
const MITHRIL_HOPS: usize = 12;
/// The `mithril-genesis` walk is ~1 cert/epoch back to the genesis certificate;
/// release-preprod is a few hundred epochs deep. Bound it generously so a pruned
/// chain fails loudly instead of looping.
const GENESIS_MAX_HOPS: usize = 800;
/// preprod (release-preprod) Mithril genesis verification key, published in the
/// mithril repo. Fetched for provenance and pinned as a vector.
const GENESIS_VKEY_URL: &str = "https://raw.githubusercontent.com/input-output-hk/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey";
/// Skip the newest few blocks — near the tip they can still roll back.
const SETTLE_SKIP: usize = 8;

/// Mainnet harvest endpoints. Verifying leader-VRF + KES on real mainnet blocks
/// closes the "from mainnet" half of DoD line 2 (the verifiers are network-agnostic
/// given the block + its epoch nonce). Koios mainnet supplies settled points and
/// epoch nonces; the raw `[era, block]` CBOR comes from a public IOG backbone relay.
const MAINNET_RELAY: &str = "backbone.mainnet.cardanofoundation.org:3001";
const MAINNET_KOIOS: &str = "https://api.koios.rest/api/v1";
const MAINNET_MAGIC: u64 = 764_824_073;

/// A network's harvest endpoints: the N2N relay + magic to BlockFetch raw
/// `[era, block]` CBOR from, the Koios base for settled points and epoch nonces,
/// and the vector-filename prefix. Two instances (preprod, mainnet) let the `block`
/// and `eta0` harvest run against either network without duplicating the fetch path.
#[derive(Clone, Copy)]
struct Network {
    relay: &'static str,
    koios: &'static str,
    magic: u64,
    prefix: &'static str,
}

impl Network {
    fn preprod() -> Self {
        Network {
            relay: RELAY,
            koios: KOIOS,
            magic: PREPROD_MAGIC,
            prefix: "preprod",
        }
    }
    fn mainnet() -> Self {
        Network {
            relay: MAINNET_RELAY,
            koios: MAINNET_KOIOS,
            magic: MAINNET_MAGIC,
            prefix: "mainnet",
        }
    }
}

/// The block count from positional arg `n`, defaulting to 24.
fn want_arg(n: usize) -> usize {
    std::env::args()
        .nth(n)
        .and_then(|s| s.parse().ok())
        .unwrap_or(24)
}

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
    match std::env::args().nth(1).as_deref() {
        Some("eta0") => backfill_eta0(&Network::preprod()).await,
        Some("mainnet-eta0") => backfill_eta0(&Network::mainnet()).await,
        Some("mainnet") => fetch_blocks(&Network::mainnet(), want_arg(2)).await,
        Some("boundary") => fetch_boundary().await,
        Some("mithril") => fetch_mithril().await,
        Some("mithril-genesis") => fetch_mithril_genesis().await,
        Some("mithril-anchor-chain") => fetch_mithril_anchor_chain().await,
        Some("tx-cbor") => fetch_tx_body().await,
        _ => fetch_blocks(&Network::preprod(), want_arg(1)).await,
    }
}

/// Walk the Mithril certificate chain from `tip_hash` (positional arg 2; default the
/// golden Cardano-transactions cert `b3582978…`) down `previous_hash` to the genesis
/// anchor, collecting EVERY certificate verbatim, and write the whole contiguous
/// segment OLDEST-FIRST as one JSON array `mithril-anchor-chain.json`. This is the
/// genesis→tip chain `mithril::verify_chain_anchored` walks, so a consumer's verified
/// read is authenticated all the way back to the pinned network genesis key (rather
/// than only STM-authenticated at the tip). Aggregator bytes only — input to verify,
/// never trusted state; the walk fails loudly if it cannot reach a genesis cert.
async fn fetch_mithril_anchor_chain() -> Result<()> {
    let tip = std::env::args().nth(2).unwrap_or_else(|| {
        "b3582978c8ae855f1c05ac41f44904541d4857c8334354e64ce7fb53b767deea".to_string()
    });
    let out_dir = vectors_dir()?;
    let client = reqwest::Client::new();

    let mut hash = tip.clone();
    let mut chain: Vec<serde_json::Value> = Vec::new();
    let mut reached_genesis = false;
    for hop in 0..GENESIS_MAX_HOPS {
        let text = client
            .get(format!("{MITHRIL_AGG}/certificate/{hash}"))
            .header("accept", "application/json")
            .timeout(std::time::Duration::from_secs(25))
            .send()
            .await
            .with_context(|| format!("certificate {hash}"))?
            .error_for_status()?
            .text()
            .await
            .with_context(|| format!("certificate {hash} body"))?;
        let cert: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("parse certificate {hash}"))?;
        ensure!(
            cert.get("hash").and_then(|h| h.as_str()) == Some(hash.as_str()),
            "aggregator returned a different certificate for {hash}"
        );
        let is_genesis = cert
            .get("genesis_signature")
            .and_then(|s| s.as_str())
            .is_some_and(|s| !s.is_empty());
        let epoch = cert.get("epoch").and_then(|e| e.as_u64()).unwrap_or(0);
        let prev = cert
            .get("previous_hash")
            .and_then(|h| h.as_str())
            .unwrap_or_default()
            .to_string();
        eprintln!(
            "hop {hop}: {}… epoch {epoch}{}",
            &hash[..12.min(hash.len())],
            if is_genesis { " [GENESIS]" } else { "" }
        );
        chain.push(cert);
        if is_genesis {
            reached_genesis = true;
            break;
        }
        ensure!(
            !prev.is_empty(),
            "non-genesis certificate {hash} has no previous_hash"
        );
        hash = prev;
    }
    ensure!(
        reached_genesis,
        "did not reach a genesis anchor within {GENESIS_MAX_HOPS} hops"
    );
    // Oldest (genesis) first — the order `verify_chain_anchored` expects.
    chain.reverse();

    let path = out_dir.join("mithril-anchor-chain.json");
    let json = serde_json::to_vec(&chain).context("serialize anchor chain")?;
    std::fs::write(&path, &json).context("write anchor chain")?;
    println!(
        "harvested {}-certificate genesis-anchored chain (genesis → tip {}…) -> {}",
        chain.len(),
        &tip[..12.min(tip.len())],
        path.display()
    );
    Ok(())
}

/// One `tx_info` row: the block a transaction was minted in.
#[derive(Deserialize)]
struct TxInfoRow {
    block_hash: String,
    absolute_slot: u64,
}

/// Harvest the raw transaction BODY CBOR — the exact bytes whose Blake2b-256 is the
/// transaction id — for a certified transaction, so the UTxO-read verifier can hash
/// it to the id the Mithril inclusion proof attests and decode its outputs on
/// Sextant's own path. The body span is pallas's retained `KeepRaw` original bytes
/// (`Conway` era), never a re-encoding, so its hash matches the on-chain id exactly.
/// Preprod only (the tx-proof fixtures come from release-preprod).
async fn fetch_tx_body() -> Result<()> {
    let txhash = std::env::args()
        .nth(2)
        .context("usage: harvest tx-cbor <txhash>")?;
    let out_dir = vectors_dir()?;
    let client = reqwest::Client::new();

    // 1. Locate the tx's block (a chain point) via Koios.
    eprintln!("harvest: tx_info for {txhash}");
    let rows: Vec<TxInfoRow> = client
        .post(format!("{KOIOS}/tx_info"))
        .header("accept", "application/json")
        .json(&serde_json::json!({
            "_tx_hashes": [txhash],
            "_inputs": false,
            "_metadata": false,
            "_assets": false,
            "_withdrawals": false,
            "_certs": false,
            "_scripts": false,
            "_bytecode": false,
        }))
        .timeout(std::time::Duration::from_secs(25))
        .send()
        .await
        .context("koios tx_info request")?
        .error_for_status()?
        .json()
        .await
        .context("koios tx_info json")?;
    let row = rows.first().context("koios returned no tx_info")?;
    let point = Point::Specific(row.absolute_slot, hex::decode(&row.block_hash)?);
    eprintln!(
        "harvest: tx in block {} slot {}; blockfetching",
        row.block_hash, row.absolute_slot
    );

    // 2. BlockFetch the single containing block.
    let mut peer = PeerClient::connect(RELAY, PREPROD_MAGIC)
        .await
        .context("connect relay")?;
    let blocks = peer
        .blockfetch()
        .fetch_range((point.clone(), point))
        .await
        .context("blockfetch")?;
    peer.abort().await;
    let raw = blocks.first().context("blockfetch returned no block")?;

    // 3. Find the tx and extract its Conway body's retained raw bytes.
    let block = MultiEraBlock::decode(raw).context("pallas decode block")?;
    let mut body: Option<Vec<u8>> = None;
    for tx in block.txs() {
        if hex::encode(tx.hash()) != txhash {
            continue;
        }
        body = match &tx {
            pallas_traverse::MultiEraTx::Conway(x) => Some(x.transaction_body.raw_cbor().to_vec()),
            _ => anyhow::bail!("tx {txhash} is not a Conway transaction"),
        };
        // Cross-check the retained span hashes to the id we searched for.
        ensure!(
            hex::encode(tx.hash()) == txhash,
            "pallas tx hash disagrees with the requested id"
        );
        break;
    }
    let body =
        body.with_context(|| format!("tx {txhash} not found in block {}", row.block_hash))?;

    let path = out_dir.join("mithril-tx-body.cbor");
    std::fs::write(&path, hex::encode(&body)).context("write tx body")?;
    println!(
        "harvested tx body ({} bytes) for {txhash} -> {}",
        body.len(),
        path.display()
    );
    Ok(())
}

/// Walk the preprod Mithril certificate chain tip→(genesis | `MITHRIL_HOPS`
/// hops), saving each certificate as verbatim `mithril-cert-<hash>.json` (the
/// exact wire bytes `Certificate::compute_hash` is checked against). The
/// aggregator's own `hash` is the self-authenticating oracle: each cert's
/// `previous_hash` is the parent's content hash, so the saved segment is a
/// hash-linked chain. Uses the aggregator only; the bytes are input to verify,
/// never trusted state.
async fn fetch_mithril() -> Result<()> {
    let out_dir = vectors_dir()?;
    let client = reqwest::Client::new();

    // Tip certificate hash from the list (newest-first).
    let list: serde_json::Value = client
        .get(format!("{MITHRIL_AGG}/certificates"))
        .header("accept", "application/json")
        .send()
        .await
        .context("mithril certificates list")?
        .error_for_status()?
        .json()
        .await
        .context("mithril certificates json")?;
    let mut hash = list
        .get(0)
        .and_then(|c| c.get("hash"))
        .and_then(|h| h.as_str())
        .context("aggregator returned no certificates")?
        .to_string();

    let mut written = 0usize;
    let mut reached_genesis = false;
    for _ in 0..MITHRIL_HOPS {
        // Fetch the raw bytes verbatim — compute_hash must see the exact wire
        // strings (avk / multi_sig / timestamps), not a re-serialization.
        let text = client
            .get(format!("{MITHRIL_AGG}/certificate/{hash}"))
            .header("accept", "application/json")
            .send()
            .await
            .with_context(|| format!("mithril certificate {hash}"))?
            .error_for_status()?
            .text()
            .await
            .with_context(|| format!("mithril certificate {hash} body"))?;
        let cert: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("parse certificate {hash}"))?;
        let self_hash = cert
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or_default();
        ensure!(
            self_hash == hash,
            "aggregator returned cert {self_hash} for requested {hash}"
        );

        std::fs::write(out_dir.join(format!("mithril-cert-{hash}.json")), &text)
            .context("write certificate vector")?;
        written += 1;

        let genesis_sig = cert
            .get("genesis_signature")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        let prev = cert
            .get("previous_hash")
            .and_then(|h| h.as_str())
            .unwrap_or_default()
            .to_string();
        println!(
            "  wrote mithril-cert-{hash}.json (epoch {}, {} bytes){}",
            cert.get("epoch").and_then(|e| e.as_u64()).unwrap_or(0),
            text.len(),
            if genesis_sig.is_empty() {
                ""
            } else {
                " [GENESIS]"
            }
        );
        if !genesis_sig.is_empty() {
            reached_genesis = true;
            break;
        }
        ensure!(
            !prev.is_empty(),
            "non-genesis cert {hash} has no previous_hash"
        );
        hash = prev;
    }

    println!(
        "harvested {written} mithril certificate vectors into {} (genesis reached: {reached_genesis})",
        out_dir.display()
    );
    Ok(())
}

/// Fetch the Mithril trust root: the network genesis verification key and the
/// genesis certificate the chain terminates in. Walks tip→genesis via
/// `previous_hash` (paying the ~1-cert/epoch cost once, here), then checks in
/// only the genesis certificate (`mithril-genesis-cert.json`), its immediate
/// child (`mithril-genesis-child.json`, whose `previous_hash` is the genesis
/// content hash), and the raw genesis vkey (`mithril-genesis.vkey`) so the test
/// can load the anchor offline. The bytes are input to verify, never trusted state.
async fn fetch_mithril_genesis() -> Result<()> {
    let out_dir = vectors_dir()?;
    let client = reqwest::Client::new();

    // 1. Genesis verification key (the pinned per-network trust root).
    let vkey_text = client
        .get(GENESIS_VKEY_URL)
        .send()
        .await
        .context("fetch genesis vkey")?
        .error_for_status()
        .context("genesis vkey URL (path moved?)")?
        .text()
        .await
        .context("genesis vkey body")?;
    let vkey = parse_genesis_vkey(&vkey_text)?;
    // Write the decoded 32-byte key as hex so the test loads it directly (the
    // pinned trust root, human-reviewed in the PR against the mithril repo).
    std::fs::write(out_dir.join("mithril-genesis.vkey"), hex::encode(vkey))
        .context("write genesis vkey")?;
    println!(
        "genesis vkey ({} raw chars) -> 32-byte key {}",
        vkey_text.trim().len(),
        hex::encode(vkey),
    );

    // 2. Tip certificate hash (newest-first list).
    let list: serde_json::Value = client
        .get(format!("{MITHRIL_AGG}/certificates"))
        .header("accept", "application/json")
        .send()
        .await
        .context("mithril certificates list")?
        .error_for_status()?
        .json()
        .await
        .context("mithril certificates json")?;
    let mut hash = list
        .get(0)
        .and_then(|c| c.get("hash"))
        .and_then(|h| h.as_str())
        .context("aggregator returned no certificates")?
        .to_string();

    // 3. Walk tip→genesis, remembering the cert fetched just before genesis (its child).
    let mut child_text: Option<String> = None;
    for hop in 0..GENESIS_MAX_HOPS {
        let text = client
            .get(format!("{MITHRIL_AGG}/certificate/{hash}"))
            .header("accept", "application/json")
            .send()
            .await
            .with_context(|| format!("mithril certificate {hash}"))?
            .error_for_status()
            .with_context(|| format!("cert {hash} unavailable — chain pruned before genesis?"))?
            .text()
            .await
            .with_context(|| format!("mithril certificate {hash} body"))?;
        let cert: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("parse certificate {hash}"))?;
        let self_hash = cert
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or_default();
        ensure!(
            self_hash == hash,
            "aggregator returned {self_hash} for {hash}"
        );
        let epoch = cert.get("epoch").and_then(|e| e.as_u64()).unwrap_or(0);
        let genesis_sig = cert
            .get("genesis_signature")
            .and_then(|s| s.as_str())
            .unwrap_or_default();

        if !genesis_sig.is_empty() {
            std::fs::write(out_dir.join("mithril-genesis-cert.json"), &text)
                .context("write genesis cert vector")?;
            println!("reached GENESIS at hop {hop}: {hash} (epoch {epoch})");
            if let Some(child) = &child_text {
                std::fs::write(out_dir.join("mithril-genesis-child.json"), child)
                    .context("write genesis child vector")?;
                println!("  wrote mithril-genesis-child.json (links to genesis by previous_hash)");
            }
            println!("harvested genesis anchor into {}", out_dir.display());
            return Ok(());
        }
        if hop % 25 == 0 {
            println!("  hop {hop}: epoch {epoch} ({hash})");
        }
        let prev = cert
            .get("previous_hash")
            .and_then(|h| h.as_str())
            .unwrap_or_default()
            .to_string();
        ensure!(
            !prev.is_empty(),
            "non-genesis cert {hash} has no previous_hash"
        );
        child_text = Some(text);
        hash = prev;
    }
    anyhow::bail!("did not reach genesis within {GENESIS_MAX_HOPS} hops")
}

/// Decode a mithril genesis verification-key file to its 32-byte Ed25519 key.
/// mithril encodes it as hex whose bytes are the ASCII of a JSON `[u8; 32]`
/// array; defensively also accept the 32 raw key bytes hex-encoded directly.
fn parse_genesis_vkey(text: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(text.trim()).context("genesis vkey hex")?;
    if decoded.len() == 32 {
        return Ok(decoded.try_into().unwrap());
    }
    let arr: Vec<u8> = serde_json::from_slice(&decoded)
        .context("genesis vkey is neither 32 raw bytes nor a JSON u8 array")?;
    arr.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("genesis vkey JSON array was {} bytes, want 32", arr.len()))
}

/// BlockFetch `count` recent settled preprod blocks off the relay and write
/// them as hex vectors named by slot.
async fn fetch_blocks(net: &Network, want: usize) -> Result<()> {
    let &Network {
        relay,
        koios,
        magic,
        prefix,
    } = net;
    let out_dir = vectors_dir()?;

    // 1. Recent settled block points (newest-first) from Koios.
    let url = format!("{koios}/blocks?limit={}", want + SETTLE_SKIP + 4);
    eprintln!("harvest: querying {url}");
    let mut blocks: Vec<KoiosBlock> = reqwest::Client::new()
        .get(&url)
        .header("accept", "application/json")
        .timeout(std::time::Duration::from_secs(25))
        .send()
        .await
        .context("koios request")?
        .error_for_status()?
        .json()
        .await
        .context("koios json")?;
    eprintln!("harvest: got {} points", blocks.len());
    if blocks.len() > SETTLE_SKIP {
        blocks.drain(0..SETTLE_SKIP);
    }
    blocks.truncate(want);
    blocks.reverse(); // oldest -> newest, contiguous by height
    ensure!(blocks.len() >= 2, "koios returned too few blocks");

    let start = point(blocks.first().unwrap())?;
    let end = point(blocks.last().unwrap())?;
    // Progress to stderr (unbuffered) so a long network step is visible live.
    eprintln!(
        "fetching {} blocks from {relay}: slot {} .. {}",
        blocks.len(),
        blocks.first().unwrap().abs_slot,
        blocks.last().unwrap().abs_slot
    );

    // 2. BlockFetch the range as raw CBOR from a public relay.
    eprintln!("connecting to {relay} (magic {magic})...");
    let mut peer = PeerClient::connect(relay, magic)
        .await
        .context("connect relay")?;
    eprintln!("connected; blockfetching the range...");
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
        let path = out_dir.join(format!("{prefix}-{}.block", blk.slot()));
        std::fs::write(&path, hex::encode(bytes)).context("write vector")?;
        println!("  wrote {} ({} bytes)", path.display(), bytes.len());
        written += 1;
    }
    println!(
        "harvested {written} {prefix} block vectors into {}",
        out_dir.display()
    );
    Ok(())
}

/// Fetch a short contiguous run spanning the epoch 299→300 turn and write it as
/// `boundary-<slot>.block` vectors, each with a `boundary-<slot>.eta0` sidecar
/// holding ITS epoch's active nonce. The pre-turn blocks carry η0(299), the
/// post-turn blocks η0(300); the boundary test uses that per-epoch nonce to prove
/// leader election evolved with the nonce. The `boundary-` prefix keeps these out
/// of the single-epoch preprod chain sweep.
async fn fetch_boundary() -> Result<()> {
    const PRE_EPOCH: u64 = 299;
    const POST_EPOCH: u64 = 300;
    /// Blocks to pull on each side of the turn.
    const SPAN: usize = 5;

    let out_dir = vectors_dir()?;
    let client = reqwest::Client::new();

    // Last SPAN blocks of epoch 299 and first SPAN of epoch 300 (points only).
    let pre = koios_epoch_blocks(&client, PRE_EPOCH, "abs_slot.desc", SPAN).await?;
    let post = koios_epoch_blocks(&client, POST_EPOCH, "abs_slot.asc", SPAN).await?;
    ensure!(
        !pre.is_empty() && !post.is_empty(),
        "koios returned no blocks for one side of the boundary"
    );
    // The first block of epoch 300 marks the turn: any fetched block at or after
    // its slot is epoch 300, anything earlier is epoch 299.
    let turn_slot = post.iter().map(|b| b.abs_slot).min().unwrap();

    // BlockFetch the contiguous range [earliest 299 .. latest 300] off the relay.
    let start = point(pre.iter().min_by_key(|b| b.abs_slot).unwrap())?;
    let end = point(post.iter().max_by_key(|b| b.abs_slot).unwrap())?;
    println!(
        "fetching {PRE_EPOCH}->{POST_EPOCH} boundary from {RELAY}: slot {} .. {} (turn at {turn_slot})",
        pre.iter().map(|b| b.abs_slot).min().unwrap(),
        post.iter().map(|b| b.abs_slot).max().unwrap(),
    );
    let mut peer = PeerClient::connect(RELAY, PREPROD_MAGIC)
        .await
        .context("connect preprod relay")?;
    let raw_blocks = peer
        .blockfetch()
        .fetch_range((start, end))
        .await
        .context("blockfetch boundary range")?;
    peer.abort().await;

    // Each epoch's active nonce; they must differ or there is no evolution.
    let eta0_pre = fetch_eta0(&client, KOIOS, PRE_EPOCH).await?;
    let eta0_post = fetch_eta0(&client, KOIOS, POST_EPOCH).await?;
    ensure!(
        eta0_pre != eta0_post,
        "epoch nonce did not change across the boundary"
    );

    // Write each block with its epoch's nonce sidecar.
    let mut written = 0usize;
    for bytes in &raw_blocks {
        let blk = MultiEraBlock::decode(bytes).context("pallas decode of fetched block")?;
        let slot = blk.slot();
        let (epoch, eta0) = if slot >= turn_slot {
            (POST_EPOCH, &eta0_post)
        } else {
            (PRE_EPOCH, &eta0_pre)
        };
        std::fs::write(
            out_dir.join(format!("boundary-{slot}.block")),
            hex::encode(bytes),
        )
        .context("write boundary block vector")?;
        std::fs::write(
            out_dir.join(format!("boundary-{slot}.eta0")),
            hex::encode(eta0),
        )
        .context("write boundary eta0 sidecar")?;
        println!(
            "  wrote boundary-{slot}.block (epoch {epoch}, {} bytes)",
            bytes.len()
        );
        written += 1;
    }
    println!(
        "harvested {written} boundary block vectors into {}",
        out_dir.display()
    );
    Ok(())
}

/// Fetch block points (slot + hash) for one preprod epoch, ordered by `order`
/// (e.g. `abs_slot.desc`) and capped at `limit` rows.
async fn koios_epoch_blocks(
    client: &reqwest::Client,
    epoch: u64,
    order: &str,
    limit: usize,
) -> Result<Vec<KoiosBlock>> {
    client
        .get(format!(
            "{KOIOS}/blocks?epoch_no=eq.{epoch}&order={order}&limit={limit}&select=abs_slot,hash"
        ))
        .header("accept", "application/json")
        .send()
        .await
        .with_context(|| format!("koios blocks epoch {epoch}"))?
        .error_for_status()?
        .json()
        .await
        .with_context(|| format!("koios blocks json epoch {epoch}"))
}

/// For every `preprod-<slot>.block` vector, look up the epoch it was minted in
/// and that epoch's active nonce (eta0), and write it as a `preprod-<slot>.eta0`
/// sidecar. Uses Koios only (no relay); leaves the block CBOR untouched.
async fn backfill_eta0(net: &Network) -> Result<()> {
    let &Network { koios, prefix, .. } = net;
    let vec_prefix = format!("{prefix}-");
    let out_dir = vectors_dir()?;
    let client = reqwest::Client::new();

    // 1. Map each vector's block hash to its slot (from the CBOR).
    let mut slot_by_hash: HashMap<String, u64> = HashMap::new();
    for entry in std::fs::read_dir(&out_dir).context("read vectors dir")? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with(&vec_prefix)
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
    ensure!(!slot_by_hash.is_empty(), "no {prefix} vectors found");
    let hashes: Vec<&String> = slot_by_hash.keys().collect();

    // 2. Koios block_info -> epoch per block hash.
    let infos: Vec<BlockInfo> = client
        .post(format!("{koios}/block_info"))
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
        nonce_by_epoch.insert(
            info.epoch_no,
            fetch_eta0(&client, koios, info.epoch_no).await?,
        );
    }

    // 4. Write one sidecar per vector.
    let mut written = 0usize;
    for info in &infos {
        let slot = slot_by_hash
            .get(&info.hash)
            .with_context(|| format!("block_info returned unknown hash {}", info.hash))?;
        let eta0 = &nonce_by_epoch[&info.epoch_no];
        let path = out_dir.join(format!("{prefix}-{slot}.eta0"));
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
async fn fetch_eta0(client: &reqwest::Client, koios: &str, epoch: u64) -> Result<[u8; 32]> {
    let params: Vec<EpochParam> = client
        .get(format!(
            "{koios}/epoch_params?_epoch_no={epoch}&select=nonce"
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
