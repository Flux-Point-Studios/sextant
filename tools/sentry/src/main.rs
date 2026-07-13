//! The live windowed-unspent follower transport (BEYOND-DoD Epic F, F6b).
//!
//! A node-to-node chain-sync consumer that sources the [`sentry::SyncEvent`]s the sans-io
//! [`sentry`] lib drives into a [`sextant::follow::WindowFollower`]. It proves the
//! follower over a REAL relay: intersect near the live preprod tip, follow forward a
//! bounded run of blocks (block-fetching each one's full body — N2N chain-sync carries
//! headers only), pick a watch created inside that run, bootstrap on its creating block,
//! and emit the windowed verdict as each block arrives — with a genesis-anchored Mithril
//! re-anchor and a Koios-sourced `slot_now` for freshness.
//!
//! It watches a FRESH outpoint (created inside the followed run) on purpose: following a
//! historical outpoint from its creation would mean replaying millions of blocks to the
//! live tip — the unbounded cost Tier-2 (a certified snapshot) exists to collapse. A live
//! run over a fresh outpoint is the honest demonstration of the transport.
//!
//!   cargo run -p sentry --features transport --bin sextant-sentry [blocks]
//!
//! Untrusted-input rule holds end to end: the relay/Koios/aggregator supply BYTES; every
//! block is re-verified by the follower, and the certified root comes only from the
//! genesis-anchored `verify_chain_anchored`.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use pallas_network::facades::PeerClient;
use pallas_network::miniprotocols::Point;
use pallas_network::miniprotocols::chainsync::NextResponse;
use pallas_traverse::{MultiEraBlock, MultiEraHeader};
use serde::Deserialize;

use sentry::{DriveOutcome, SyncEvent, bootstrap, drive};
use sextant::follow::SlotSchedule;
use sextant::mithril::{Certificate, verify_chain_anchored};
use sextant::utxo::{CertifiedTransactions, OutPoint};
use sextant::window::{Freshness, WatchBasis, WatchVerdict};

const RELAY: &str = "preprod-node.play.dev.cardano.org:3001";
const KOIOS: &str = "https://preprod.koios.rest/api/v1";
const MAGIC: u64 = 1;
/// preprod fixed-length 432000-slot epochs; the empirically-pinned anchor is epoch 300 /
/// first slot 127958400 (the same schedule the committed-fixture tests use). The formula
/// extrapolates to any later epoch, so a run in epoch 300 or 301 places its slots
/// correctly and stages each epoch's nonce from Koios.
const PREPROD_EPOCH_LEN: u64 = 432_000;
const PREPROD_ANCHOR_EPOCH: u64 = 300;
const PREPROD_ANCHOR_FIRST_SLOT: u64 = 127_958_400;

#[derive(Deserialize)]
struct Tip {
    abs_slot: u64,
    block_no: u64,
}

#[derive(Deserialize)]
struct EpochParam {
    epoch_no: u64,
    nonce: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let want: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // 1. The certified anchor from a genesis-anchored Mithril verify over the pinned
    //    committed chain (the genesis vkey is the one trusted input — never fetched). The
    //    live run follows ACROSS this anchor so the `mithril_quorum` two-region behavior
    //    is observed: blocks at/below the certified height are quorum-backed, blocks above
    //    it are header-vouched only.
    let anchor = certified_anchor()?;
    eprintln!(
        "sentry: genesis-anchored certified block {} (epoch {})",
        anchor.block_number, anchor.epoch
    );

    // 2. Koios `tip` gives the live slot for freshness. Intersect ~20 blocks BELOW the
    //    certified anchor and follow forward across it (settled data — deterministic).
    let tip: Tip = http
        .get(format!("{KOIOS}/tip"))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<Tip>>()
        .await?
        .into_iter()
        .next()
        .context("koios tip empty")?;
    let slot_now = tip.abs_slot;
    let start_block = anchor.block_number.saturating_sub(20);
    let start = koios_point(&http, start_block).await?;
    eprintln!(
        "sentry: live tip block {} slot {}; intersecting at block {} to follow ~{want} across the anchor",
        tip.block_no, tip.abs_slot, start_block
    );

    // 3. Follow a bounded run off the relay, block-fetching each block's full body.
    let blocks = follow_run(&start, want).await?;
    if blocks.len() < 3 {
        bail!("followed only {} blocks; need a longer run", blocks.len());
    }
    let run_lo = block_number(&blocks[0])?;
    let run_hi = block_number(&blocks[blocks.len() - 1])?;
    eprintln!(
        "sentry: fetched {} live blocks ({run_lo}..={run_hi})",
        blocks.len()
    );

    // 4. Watch the first output of block[0]'s first transaction — created in the run, so
    //    its creation is observed in the first block; require_through = block[0] so an
    //    in-region tip already satisfies the coverage floor and can read no-spend.
    let watch = first_created_outpoint(&blocks[0]).context("no outpoint in the first block")?;
    eprintln!(
        "sentry: watching {}…#{} (created in block {run_lo})",
        hex::encode(&watch.tx_id[..6]),
        watch.index
    );

    // 5. Stage every epoch nonce the run spans (Koios epoch_params), keyed by epoch.
    let schedule = SlotSchedule {
        epoch: PREPROD_ANCHOR_EPOCH,
        epoch_first_slot: PREPROD_ANCHOR_FIRST_SLOT,
        epoch_length_slots: PREPROD_EPOCH_LEN,
    };
    let eta0s = stage_nonces(&http, &blocks, &schedule).await?;

    // 6. Bootstrap on the creating block, then drive the rest as Forward events, emitting
    //    the windowed verdict as each block lands — the mithril_quorum flip is visible as
    //    the tip crosses the certified anchor.
    let mut follower = bootstrap(watch, &anchor, run_lo, schedule, &eta0s, &blocks[0])
        .map_err(|e| anyhow::anyhow!("bootstrap refused: {e:?}"))?;
    let freshness = Freshness {
        slot_now,
        max_lag: 3 * PREPROD_EPOCH_LEN,
    };
    emit(1, run_lo, &follower.verdict(freshness));
    for (i, block) in blocks[1..].iter().enumerate() {
        match drive(&mut follower, SyncEvent::Forward(block.clone())) {
            DriveOutcome::Appended(n) => emit(i + 2, n, &follower.verdict(freshness)),
            DriveOutcome::Refused(r) => {
                eprintln!("sentry: block {} refused: {r:?}", i + 2);
                break;
            }
            DriveOutcome::RolledBack(_) => unreachable!("forward never rolls back"),
        }
    }

    let final_verdict = follower.verdict(freshness);
    eprintln!("sentry: final verdict {}", describe(&final_verdict));
    Ok(())
}

/// Emit one JSON-lines transcript row: the step, the appended block number, and the
/// windowed verdict.
fn emit(step: usize, block: u64, verdict: &WatchVerdict) {
    println!(
        r#"{{"step":{step},"block":{block},"verdict":"{}"}}"#,
        describe(verdict)
    );
}

fn describe(v: &WatchVerdict) -> String {
    match v {
        WatchVerdict::Unspent { as_of, basis } => {
            let assumptions = match basis {
                WatchBasis::WatchedWindow(a) => format!(
                    "mithril_quorum={} data_complete={}",
                    a.mithril_quorum, a.data_complete
                ),
                _ => "basis=unrecognized".to_string(),
            };
            format!(
                "no-spend-observed as_of={}@{} {assumptions}",
                as_of.as_of_height, as_of.as_of_slot
            )
        }
        WatchVerdict::SpentObserved {
            at_height, region, ..
        } => format!("spend-observed at={at_height} region={region:?}"),
        WatchVerdict::Stalled {
            verified_through,
            reason,
        } => format!("stalled through={verified_through} reason={reason:?}"),
    }
}

/// The Koios settled point (slot, hash) of a block number.
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
        .context("koios blocks: height not found")?;
    Ok(Point::Specific(r.abs_slot, hex::decode(&r.hash)?))
}

/// Chain-sync from `start`, block-fetching each RollForward's full block, until `want`
/// blocks are collected or the tip is reached.
async fn follow_run(start: &Point, want: usize) -> Result<Vec<Vec<u8>>> {
    let mut peer = PeerClient::connect(RELAY, MAGIC)
        .await
        .context("connect relay")?;
    peer.chainsync()
        .find_intersect(vec![start.clone()])
        .await
        .context("find_intersect")?;

    let mut points: Vec<Point> = Vec::new();
    while points.len() < want {
        match peer
            .chainsync()
            .request_next()
            .await
            .context("request_next")?
        {
            NextResponse::RollForward(header, _tip) => {
                let variant = header.variant;
                let hc =
                    MultiEraHeader::decode(variant, header.byron_prefix.map(|p| p.0), &header.cbor)
                        .context("decode header")?;
                points.push(Point::Specific(hc.slot(), hc.hash().to_vec()));
            }
            NextResponse::RollBackward(_point, _tip) => {
                // Intersecting inside settled data, an initial rollback to the intersect
                // is normal; ignore it and keep requesting forward.
                continue;
            }
            NextResponse::Await => break,
        }
    }
    // Block-fetch the collected points' full bodies as one range.
    let (lo, hi) = (
        points.first().context("no blocks followed")?.clone(),
        points.last().unwrap().clone(),
    );
    let raws = peer
        .blockfetch()
        .fetch_range((lo, hi))
        .await
        .context("blockfetch range")?;
    peer.abort().await;
    Ok(raws)
}

/// The first output's outpoint of the first transaction in a block — a fresh watch
/// target whose creation the run observes in its first block.
fn first_created_outpoint(block: &[u8]) -> Result<OutPoint> {
    let b = MultiEraBlock::decode(block).context("decode block")?;
    let tx = b.txs().into_iter().next().context("block has no txs")?;
    if tx.outputs().is_empty() {
        bail!("first tx has no outputs");
    }
    let id = tx.hash();
    Ok(OutPoint {
        tx_id: *id,
        index: 0,
    })
}

fn block_number(block: &[u8]) -> Result<u64> {
    Ok(MultiEraBlock::decode(block)
        .context("decode block")?
        .number())
}

/// Stage the η0 for every epoch the run's blocks span, from Koios `epoch_params`.
async fn stage_nonces(
    http: &reqwest::Client,
    blocks: &[Vec<u8>],
    schedule: &SlotSchedule,
) -> Result<Vec<(u64, [u8; 32])>> {
    let mut epochs: Vec<u64> = blocks
        .iter()
        .filter_map(|b| {
            MultiEraBlock::decode(b)
                .ok()
                .map(|d| schedule.epoch_of(d.slot()))
        })
        .collect();
    epochs.sort_unstable();
    epochs.dedup();
    let mut out = Vec::new();
    for epoch in epochs {
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
        let bytes: [u8; 32] = hex::decode(&nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("epoch nonce not 32 bytes"))?;
        out.push((epoch, bytes));
    }
    Ok(out)
}

/// The certified transactions anchor from a genesis-anchored Mithril verify over the
/// PINNED committed chain: the genesis verification key and the genesis→tip certificate
/// chain are committed fixtures (`tests/vectors/`), so the trust root is pinned, never
/// fetched. `verify_chain_anchored` authenticates the whole chain to the genesis key and
/// surfaces the certified `(root, epoch, block)` — a real, cryptographically-anchored
/// anchor the live run follows across. A production deployment re-anchors this to a fresh
/// aggregator cert as the chain advances (the follower's `re_anchor`, exercised in the
/// F1-F5 tests); the live demo pins it so the two-region behavior is deterministic.
fn certified_anchor() -> Result<CertifiedTransactions> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors");
    let vkey_hex = std::fs::read_to_string(dir.join("mithril-genesis.vkey"))
        .context("read committed genesis vkey")?;
    let genesis_vkey: [u8; 32] = hex::decode(vkey_hex.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("committed genesis vkey not 32 bytes"))?;

    let chain_bytes = std::fs::read(dir.join("mithril-anchor-chain.json"))
        .context("read committed anchor chain")?;
    let chain: Vec<serde_json::Value> =
        serde_json::from_slice(&chain_bytes).context("anchor chain is a JSON array")?;
    let certs: Vec<Certificate> = chain
        .iter()
        .map(|c| Certificate::from_json(serde_json::to_vec(c).unwrap().as_slice()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("parse committed chain: {e:?}"))?;
    let verified = verify_chain_anchored(&certs, &genesis_vkey)
        .map_err(|e| anyhow::anyhow!("committed chain not genesis-anchored: {e:?}"))?;
    verified
        .certified_transactions
        .context("committed tip certifies no transaction set")
}
