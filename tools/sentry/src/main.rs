//! The live windowed-unspent follower demo (BEYOND-DoD Epic F, F6b).
//!
//! A bounded node-to-node chain-sync run proving the follower over a REAL preprod relay:
//! genesis-anchor to a certified block, follow a bounded run ACROSS the anchor (so the
//! `mithril_quorum` two-region flip is visible), watch a fresh outpoint created in the
//! run, and emit the windowed verdict per block. The long-running multi-watch service is
//! `sextant-watchd`; this is the transcript demo.
//!
//!   cargo run -p sentry --features transport --bin sextant-sentry [blocks]

use std::time::Duration;

use anyhow::{Context, Result, bail};
use pallas_network::miniprotocols::Point;
use pallas_network::miniprotocols::chainsync::NextResponse;
use pallas_traverse::MultiEraBlock;

use sentry::transport::{
    self, PREPROD_EPOCH_LEN, blockfetch_range, certified_anchor, connect, epoch_nonce,
    header_point, koios_point, koios_tip, preprod_schedule, vectors_dir,
};
use sentry::{DriveOutcome, SyncEvent, bootstrap, drive};
use sextant::follow::SlotSchedule;
use sextant::utxo::OutPoint;
use sextant::window::{Freshness, WatchBasis, WatchVerdict};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let want: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // Genesis-anchored certified block; follow ACROSS it so the two-region flip shows.
    let anchor = certified_anchor(&vectors_dir())?;
    eprintln!(
        "sentry: genesis-anchored certified block {} (epoch {})",
        anchor.block_number, anchor.epoch
    );
    let (slot_now, tip_no) = koios_tip(&http).await?;
    let start_block = anchor.block_number.saturating_sub(20);
    let start = koios_point(&http, start_block).await?;
    eprintln!(
        "sentry: live tip block {tip_no} slot {slot_now}; intersecting at block {start_block} to follow ~{want} across the anchor"
    );

    let blocks = follow_run(&start, want).await?;
    if blocks.len() < 3 {
        bail!("followed only {} blocks; need a longer run", blocks.len());
    }
    let run_lo = transport::block_number(&blocks[0])?;
    let run_hi = transport::block_number(&blocks[blocks.len() - 1])?;
    eprintln!(
        "sentry: fetched {} live blocks ({run_lo}..={run_hi})",
        blocks.len()
    );

    let watch = first_created_outpoint(&blocks[0]).context("no outpoint in the first block")?;
    eprintln!(
        "sentry: watching {}…#{} (created in block {run_lo})",
        hex::encode(&watch.tx_id[..6]),
        watch.index
    );

    let schedule = preprod_schedule();
    let eta0s = stage_nonces(&http, &blocks, &schedule).await?;

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
    eprintln!(
        "sentry: final verdict {}",
        describe(&follower.verdict(freshness))
    );
    Ok(())
}

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
        } => {
            format!("spend-observed at={at_height} region={region:?}")
        }
        WatchVerdict::Stalled {
            verified_through,
            reason,
        } => {
            format!("stalled through={verified_through} reason={reason:?}")
        }
    }
}

/// Chain-sync from `start`, block-fetching each RollForward's full body, until `want`
/// blocks are collected or the tip is reached (the bounded demo loop).
async fn follow_run(start: &Point, want: usize) -> Result<Vec<Vec<u8>>> {
    let mut peer = connect().await?;
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
                points.push(header_point(
                    header.variant,
                    header.byron_prefix.map(|p| p.0),
                    &header.cbor,
                )?);
            }
            NextResponse::RollBackward(_point, _tip) => continue,
            NextResponse::Await => break,
        }
    }
    let (lo, hi) = (
        points.first().context("no blocks followed")?.clone(),
        points.last().unwrap().clone(),
    );
    let raws = blockfetch_range(&mut peer, lo, hi).await?;
    peer.abort().await;
    Ok(raws)
}

/// The first output's outpoint of a block's first transaction — a fresh watch target.
fn first_created_outpoint(block: &[u8]) -> Result<OutPoint> {
    let b = MultiEraBlock::decode(block).context("decode block")?;
    let tx = b.txs().into_iter().next().context("block has no txs")?;
    if tx.outputs().is_empty() {
        bail!("first tx has no outputs");
    }
    Ok(OutPoint {
        tx_id: *tx.hash(),
        index: 0,
    })
}

/// Stage the η0 for every epoch the run spans.
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
        out.push((epoch, epoch_nonce(http, epoch).await?));
    }
    Ok(out)
}
