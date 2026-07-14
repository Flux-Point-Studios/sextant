//! Tier-2 T5-daemon: the certified UTxO spend-status served over HTTP — the consumer surface.
//!
//! It bootstraps the certified UTxO set at snapshot S (verify the ancillary manifest, derive the
//! tip, open the pre-loaded `RedbUtxoStore`), follows the chain live from S to the tip
//! ([`sextant::setfollow::apply_block`] per block: header crypto → body-bind → contiguous apply),
//! periodically re-anchors the Mithril `CardanoTransactions`-certified frontier (lifting the
//! `mithril_quorum` bit), and serves the Tier-2 verdict for any outpoint:
//!
//! * `GET /health` → `ok`
//! * `GET /status?tx=<hex64>&index=<u16>` → the JSON verdict.
//!
//! The relay and Koios supply BYTES (blocks, epoch nonces, certs); the daemon supplies the verdict.
//! A forged/out-of-order block or a wrong nonce is refused, never applied — a malicious source can
//! stall the follow but never make the set answer `certified` for a spent or fabricated outpoint.
//!
//! Usage: `sextant-utxod <ancillary-dir> <preprod|mainnet> <redb-path>` (freshly `snapshot-load`ed).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use pallas_network::miniprotocols::Point;
use pallas_network::miniprotocols::chainsync::NextResponse;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use sentry::transport::{
    blockfetch_range, connect, epoch_nonce, fetch_fresh_anchor, header_point, load_committed_base,
    preprod_schedule, vectors_dir,
};
use sextant::ancillary::{ANCILLARY_VKEY_MAINNET, ANCILLARY_VKEY_PREPROD};
use sextant::follow::SlotSchedule;
use sextant::mithril::Certificate;
use sextant::setfollow::apply_block;
use sextant::utxo::{OutPoint, SpendStatus};
use sextant::utxoset::{AnchorBasis, UtxoSet};
use snapshot::{verified_anchor, verified_tables, verify_manifest};
use utxo_store::RedbUtxoStore;

/// The retained rollback window (k = 2160 blocks).
const DEPTH: usize = 2160;
/// How often to poll the aggregator for a fresher certified frontier.
const RE_ANCHOR_POLL: Duration = Duration::from_secs(120);

struct App {
    /// The certified UTxO set, mutated by the follow + re-anchor tasks and read by `/status`.
    set: Mutex<UtxoSet<RedbUtxoStore>>,
    /// The live chain tip slot the follow has reached (for the consumer's own freshness).
    tip_slot: Mutex<u64>,
    /// The certified snapshot's intersect point.
    s_slot: u64,
    s_hash: [u8; 32],
    schedule: SlotSchedule,
    /// The committed genesis→tip base + pinned genesis vkey — the trust root the periodic
    /// re-anchor's short aggregator extension splices onto (never re-walked to genesis).
    base: Vec<Certificate>,
    genesis_vkey: [u8; 32],
    http: reqwest::Client,
}

/// The Tier-2 verdict JSON a consumer reads.
#[derive(Serialize)]
struct StatusView {
    /// `not_established` | `certified` (certified: no spend of the outpoint observed in the window).
    tier: String,
    /// `stm_certified` | `ancillary_signed` | `null` — the anchor's trust class (only for `certified`).
    basis: Option<String>,
    /// The tip block number the no-spend window was maintained through (only for `certified`).
    through_block: Option<u64>,
    /// `true` iff the whole window is Mithril-quorum-backed, else header-vouched (only `certified`).
    mithril_quorum: Option<bool>,
    /// The live chain tip slot the daemon has reached — the consumer's freshness handle.
    tip_slot: u64,
}

#[derive(Deserialize)]
struct StatusQuery {
    tx: String,
    index: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .context("usage: <ancillary-dir> <network> <redb-path>")?;
    let network = args
        .next()
        .context("usage: <ancillary-dir> <network> <redb-path>")?;
    let redb_path = args
        .next()
        .context("usage: <ancillary-dir> <network> <redb-path>")?;
    if network != "preprod" {
        bail!("live follow targets the preprod relay; {network} is not wired");
    }
    let vkey = match network.as_str() {
        "preprod" => &ANCILLARY_VKEY_PREPROD,
        "mainnet" => &ANCILLARY_VKEY_MAINNET,
        other => bail!("unknown network {other:?}"),
    };
    let dir = std::path::Path::new(&dir);

    // Bootstrap: verify the manifest, derive the tip S, open the pre-loaded set at S.
    let verified = verify_manifest(dir, vkey)?;
    let s_slot = verified_tables(dir, &verified)?.slot;
    let anchor = verified_anchor(dir, &verified)?;
    let s_hash = anchor.tip.hash;
    let store =
        RedbUtxoStore::open(&redb_path).map_err(|e| anyhow::anyhow!("open store: {}", e.0))?;
    let set = UtxoSet::with_store_anchored(store, anchor, DEPTH);
    let len = set.len().map_err(|e| anyhow::anyhow!("{}", e.0))?;
    eprintln!(
        "sextant-utxod: certified set of {len} outpoints at slot {s_slot} #{} ({:?})",
        anchor.tip.number, anchor.basis
    );

    let (base, genesis_vkey) = load_committed_base(&vectors_dir())?;
    let app = Arc::new(App {
        set: Mutex::new(set),
        tip_slot: Mutex::new(s_slot),
        s_slot,
        s_hash,
        schedule: preprod_schedule(),
        base,
        genesis_vkey,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
    });

    tokio::spawn(follow_loop(app.clone()));
    tokio::spawn(re_anchor_loop(app.clone()));

    let router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/status", get(status))
        .with_state(app);
    let addr = std::env::var("UTXOD_ADDR").unwrap_or_else(|_| "0.0.0.0:8478".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.context("bind")?;
    eprintln!("sextant-utxod: serving on {addr}");
    axum::serve(listener, router).await.context("serve")?;
    Ok(())
}

/// The Tier-2 verdict for one outpoint — read from the live-followed certified set.
async fn status(State(app): State<Arc<App>>, Query(q): Query<StatusQuery>) -> impl IntoResponse {
    let Some(tx_id) = decode_hash32(&q.tx) else {
        return (StatusCode::BAD_REQUEST, "tx must be 64 hex chars").into_response();
    };
    let outpoint = OutPoint {
        tx_id,
        index: q.index,
    };
    let tip_slot = *app.tip_slot.lock().await;
    let status = {
        let set = app.set.lock().await;
        set.certified_spend_status(&outpoint)
    };
    match status {
        Ok(s) => (StatusCode::OK, Json(project(s, tip_slot))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("store: {}", e.0)).into_response(),
    }
}

fn project(s: SpendStatus, tip_slot: u64) -> StatusView {
    match s {
        SpendStatus::NotEstablished => StatusView {
            tier: "not_established".into(),
            basis: None,
            through_block: None,
            mithril_quorum: None,
            tip_slot,
        },
        SpendStatus::CertifiedUnspent {
            basis,
            through_block,
            mithril_quorum,
        } => StatusView {
            tier: "certified".into(),
            basis: Some(
                match basis {
                    AnchorBasis::StmCertified => "stm_certified",
                    AnchorBasis::AncillarySigned => "ancillary_signed",
                    // A future basis this daemon build predates: fail safe — surface it as unknown,
                    // never as the stronger stake-quorum class.
                    _ => "unknown",
                }
                .into(),
            ),
            through_block: Some(through_block),
            mithril_quorum: Some(mithril_quorum),
            tip_slot,
        },
        // A future ladder tier this daemon build predates: fail safe — never a positive `certified`
        // claim it cannot interpret, so a consumer treats it as not-established.
        _ => StatusView {
            tier: "unknown".into(),
            basis: None,
            through_block: None,
            mithril_quorum: None,
            tip_slot,
        },
    }
}

/// Follow the chain from S to the tip, applying each verified block to the shared set.
async fn follow_loop(app: Arc<App>) {
    loop {
        if let Err(e) = follow_once(&app).await {
            eprintln!("sextant-utxod: follow error, retrying in 10s: {e}");
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
}

async fn follow_once(app: &Arc<App>) -> Result<()> {
    let mut peer = connect().await.context("connect relay")?;
    let start = Point::Specific(app.s_slot, app.s_hash.to_vec());
    let (found, _tip) = peer
        .chainsync()
        .find_intersect(vec![start])
        .await
        .context("find_intersect")?;
    match &found {
        Some(Point::Specific(slot, h)) if *slot == app.s_slot && h == &app.s_hash.to_vec() => {}
        other => bail!("relay did not intersect at S (parsed tip not on chain): {other:?}"),
    }

    let mut staged: Vec<(u64, [u8; 32])> = Vec::new();
    loop {
        match peer
            .chainsync()
            .request_or_await_next()
            .await
            .context("chain-sync")?
        {
            NextResponse::RollForward(header, _tip) => {
                let point = header_point(
                    header.variant,
                    header.byron_prefix.map(|p| p.0),
                    &header.cbor,
                )?;
                let slot = point_slot(&point);
                let epoch = app.schedule.epoch_of(slot);
                if !staged.iter().any(|(e, _)| *e == epoch) {
                    staged.push((epoch, epoch_nonce(&app.http, epoch).await.context("nonce")?));
                }
                let eta0 = staged.iter().find(|(e, _)| *e == epoch).unwrap().1;
                let block = blockfetch_range(&mut peer, point.clone(), point)
                    .await
                    .context("blockfetch")?
                    .into_iter()
                    .next()
                    .context("empty blockfetch")?;
                let mut set = app.set.lock().await;
                apply_block(&mut set, &block, &eta0)
                    .map_err(|e| anyhow::anyhow!("apply at slot {slot}: {e}"))?;
                drop(set);
                *app.tip_slot.lock().await = slot;
            }
            NextResponse::RollBackward(point, _tip) => {
                let Point::Specific(_, h) = &point else {
                    bail!("relay sent an unusable rollback point: {point:?}");
                };
                let hash: [u8; 32] = h
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("rollback hash not 32 bytes"))?;
                app.set
                    .lock()
                    .await
                    .rollback_to(&hash)
                    .map_err(|e| anyhow::anyhow!("rollback: {e:?}"))?;
            }
            NextResponse::Await => {
                // Caught up to the tip; wait for the next block.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Poll the aggregator for a fresher certified frontier and lift the set's `mithril_quorum` region.
async fn re_anchor_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(RE_ANCHOR_POLL).await;
        match fetch_fresh_anchor(&app.http, &app.base, &app.genesis_vkey).await {
            Ok(fresh) => {
                let advanced = app.set.lock().await.re_anchor(&fresh);
                if advanced {
                    eprintln!(
                        "sextant-utxod: re-anchored certified frontier to block {}",
                        fresh.block_number
                    );
                }
            }
            Err(e) => eprintln!("sextant-utxod: re-anchor skipped: {e}"),
        }
    }
}

fn point_slot(p: &Point) -> u64 {
    match p {
        Point::Specific(slot, _) => *slot,
        Point::Origin => 0,
    }
}

/// Decode 64 lowercase/uppercase hex chars into a 32-byte hash, or `None`.
fn decode_hash32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok()?.try_into().ok()
}
