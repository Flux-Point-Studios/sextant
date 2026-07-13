//! Reusable node-to-node + aggregator + Koios transport primitives (behind the
//! `transport` feature) shared by the bounded demo (`sextant-sentry`) and the live
//! watch-daemon (`sextant-watchd`). Every value here is BYTES a provider supplies; the
//! follower re-verifies each block and the certified anchor is genesis-anchored, so the
//! transport is trusted for liveness only, never for a verdict.

use anyhow::{Context, Result, anyhow};
use pallas_network::facades::PeerClient;
use pallas_network::miniprotocols::Point;
use pallas_traverse::{MultiEraBlock, MultiEraHeader};
use serde::Deserialize;

use sextant::follow::SlotSchedule;
use sextant::mithril::{Certificate, verify_chain_anchored};
use sextant::utxo::CertifiedTransactions;

pub const RELAY: &str = "preprod-node.play.dev.cardano.org:3001";
pub const KOIOS: &str = "https://preprod.koios.rest/api/v1";
pub const MAGIC: u64 = 1;
/// preprod fixed-length 432000-slot epochs; the empirically-pinned anchor is epoch 300 /
/// first slot 127958400 (the schedule the committed-fixture tests use). The formula
/// extrapolates to any later epoch.
pub const PREPROD_EPOCH_LEN: u64 = 432_000;
pub const PREPROD_ANCHOR_EPOCH: u64 = 300;
pub const PREPROD_ANCHOR_FIRST_SLOT: u64 = 127_958_400;

pub fn preprod_schedule() -> SlotSchedule {
    SlotSchedule {
        epoch: PREPROD_ANCHOR_EPOCH,
        epoch_first_slot: PREPROD_ANCHOR_FIRST_SLOT,
        epoch_length_slots: PREPROD_EPOCH_LEN,
    }
}

/// Connect a node-to-node peer to the preprod relay.
pub async fn connect() -> Result<PeerClient> {
    PeerClient::connect(RELAY, MAGIC)
        .await
        .context("connect relay")
}

#[derive(Deserialize)]
struct TipRow {
    abs_slot: u64,
    block_no: u64,
}

/// The live chain tip's `(abs_slot, block_no)` from Koios — the slot feeds freshness.
pub async fn koios_tip(http: &reqwest::Client) -> Result<(u64, u64)> {
    let tip: TipRow = http
        .get(format!("{KOIOS}/tip"))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<TipRow>>()
        .await?
        .into_iter()
        .next()
        .context("koios tip empty")?;
    Ok((tip.abs_slot, tip.block_no))
}

/// The settled chain point `(slot, hash)` of a block number, from Koios.
pub async fn koios_point(http: &reqwest::Client, block_no: u64) -> Result<Point> {
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
        .context("koios blocks: height not found")?;
    Ok(Point::Specific(r.abs_slot, hex::decode(&r.hash)?))
}

/// The settled point of the block containing transaction `tx_id` (its creating block for
/// output-0 watches), from Koios `tx_info`.
pub async fn koios_tx_point(http: &reqwest::Client, tx_id: &str) -> Result<Point> {
    #[derive(Deserialize)]
    struct TxRow {
        absolute_slot: u64,
        block_hash: String,
    }
    let rows: Vec<TxRow> = http
        .post(format!("{KOIOS}/tx_info"))
        .json(&serde_json::json!({ "_tx_hashes": [tx_id] }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let r = rows
        .into_iter()
        .next()
        .context("koios tx_info: tx not found")?;
    Ok(Point::Specific(
        r.absolute_slot,
        hex::decode(&r.block_hash)?,
    ))
}

/// Block-fetch a contiguous `[lo, hi]` range of full `[era, block]` CBOR off the relay.
pub async fn blockfetch_range(peer: &mut PeerClient, lo: Point, hi: Point) -> Result<Vec<Vec<u8>>> {
    peer.blockfetch()
        .fetch_range((lo, hi))
        .await
        .context("blockfetch range")
}

/// The chain-sync point `(slot, hash)` of a RollForward header (N2N chain-sync carries
/// headers only; the caller block-fetches the body by this point).
pub fn header_point(variant: u8, byron_prefix: Option<u8>, cbor: &[u8]) -> Result<Point> {
    let hc = MultiEraHeader::decode(variant, byron_prefix, cbor).context("decode header")?;
    Ok(Point::Specific(hc.slot(), hc.hash().to_vec()))
}

pub fn block_number(block: &[u8]) -> Result<u64> {
    Ok(MultiEraBlock::decode(block)
        .context("decode block")?
        .number())
}

/// One `epoch_params` row: the active epoch nonce (eta0).
#[derive(Deserialize)]
struct EpochParam {
    epoch_no: u64,
    nonce: Option<String>,
}

/// The leader-election nonce η0 for `epoch`, from Koios `epoch_params`.
pub async fn epoch_nonce(http: &reqwest::Client, epoch: u64) -> Result<[u8; 32]> {
    let params: Vec<EpochParam> = http
        .get(format!("{KOIOS}/epoch_params"))
        .query(&[("_epoch_no", epoch.to_string())])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let nonce = params
        .into_iter()
        .find(|p| p.epoch_no == epoch)
        .and_then(|p| p.nonce)
        .context("koios epoch nonce missing")?;
    hex::decode(&nonce)?
        .try_into()
        .map_err(|_| anyhow!("epoch nonce not 32 bytes"))
}

/// The certified transactions anchor from a genesis-anchored Mithril verify over the
/// PINNED committed chain (`tests/vectors/`): the genesis vkey and the genesis→tip cert
/// chain are committed, so the trust root is pinned, never fetched. `verify_chain_anchored`
/// authenticates the whole chain to the genesis key and surfaces the certified
/// `(root, epoch, block)`. A production deployment re-anchors this to a fresh aggregator
/// cert as the chain advances (the follower's `re_anchor`); this pins it deterministically.
pub fn certified_anchor(vectors_dir: &std::path::Path) -> Result<CertifiedTransactions> {
    let vkey_hex = std::fs::read_to_string(vectors_dir.join("mithril-genesis.vkey"))
        .context("read committed genesis vkey")?;
    let genesis_vkey: [u8; 32] = hex::decode(vkey_hex.trim())?
        .try_into()
        .map_err(|_| anyhow!("committed genesis vkey not 32 bytes"))?;

    let chain_bytes = std::fs::read(vectors_dir.join("mithril-anchor-chain.json"))
        .context("read committed anchor chain")?;
    let chain: Vec<serde_json::Value> =
        serde_json::from_slice(&chain_bytes).context("anchor chain is a JSON array")?;
    let certs: Vec<Certificate> = chain
        .iter()
        .map(|c| Certificate::from_json(serde_json::to_vec(c).unwrap().as_slice()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("parse committed chain: {e:?}"))?;
    let verified = verify_chain_anchored(&certs, &genesis_vkey)
        .map_err(|e| anyhow!("committed chain not genesis-anchored: {e:?}"))?;
    verified
        .certified_transactions
        .context("committed tip certifies no transaction set")
}

/// The committed `tests/vectors` directory, relative to this crate.
pub fn vectors_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors")
}
