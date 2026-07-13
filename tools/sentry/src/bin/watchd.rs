//! `sextant-watchd` — the windowed-unspent watch-daemon (BEYOND-DoD Epic F, F6c).
//!
//! A long-running HTTP service: a consumer (e.g. adam-oc's order-fill pre-flight) POSTs an
//! outpoint to watch; the daemon follows the chain from that outpoint's creating block to
//! the live tip on a node-to-node relay, re-verifying every block through a
//! [`sextant::follow::WindowFollower`], and serves the windowed verdict as JSON. The
//! relay/Koios supply BYTES; the follower supplies the verdict — a spend is `SpentObserved`
//! (a definite "skip this order"), a no-spend is `no_spend_observed` with the surfaced
//! `mithril_quorum` assumption a consumer weighs, and anything unverifiable is `stalled`
//! (a fail-closed non-answer, never a false no-spend).
//!
//! Each watch runs its own follow task (one relay connection): simple and correct for the
//! handful of outpoints a consumer tracks at a time, with no live-stream join race. A
//! genesis-anchored re-anchor to a fresh aggregator certificate (which would lift
//! `mithril_quorum` to true for the not-yet-tip region) is a later refinement; v1 pins the
//! committed genesis-anchored anchor, so a live-tip watch is honestly `mithril_quorum=false`
//! (header-vouched) until then.
//!
//!   cargo run -p sentry --features daemon --bin sextant-watchd    # listens on :8477
//!   curl -XPOST :8477/watch -d '{"tx_id":"<hex64>","index":0}'
//!   curl ':8477/verdict?tx_id=<hex64>&index=0'

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use pallas_network::miniprotocols::Point;
use pallas_network::miniprotocols::chainsync::NextResponse;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use sentry::transport::{
    self, PREPROD_EPOCH_LEN, blockfetch_range, certified_anchor, connect, epoch_nonce,
    header_point, koios_tx_point, preprod_schedule, vectors_dir,
};
use sentry::{DriveOutcome, SyncEvent, bootstrap, drive};
use sextant::follow::SlotSchedule;
use sextant::utxo::{CertifiedTransactions, OutPoint};
use sextant::window::{Freshness, WatchBasis, WatchVerdict};

/// The verdict a consumer reads for a watched outpoint — the JSON the daemon serves.
#[derive(Clone, Serialize)]
struct VerdictView {
    /// `no_spend_observed` | `spend_observed` | `stalled` | `pending`.
    status: String,
    /// The verified tip height the answer holds as of (0 while pending).
    as_of_height: u64,
    /// The verified tip slot the answer holds as of.
    as_of_slot: u64,
    /// The live chain tip slot the daemon has reached (for the consumer's own freshness).
    tip_slot: u64,
    /// `true` iff the answer's region is Mithril-quorum-backed (else header-vouched).
    mithril_quorum: bool,
    /// For `spend_observed`: the block the spend was seen in.
    spend_at_height: u64,
    /// For `spend_observed`: whether the spend is Mithril-certified or header-vouched.
    spend_region: String,
    /// For `stalled`: the reason (a non-answer is a REFUSE).
    stall_reason: String,
}

/// Cap on concurrently-watched outpoints: each spawns a follow task holding a relay
/// connection, so an unbounded registry is an availability DoS. A consumer tracking a
/// handful of live orders stays well under it; over it, `POST /watch` is rejected 429.
const MAX_WATCHES: usize = 512;

struct App {
    watches: Mutex<HashMap<(String, u16), VerdictView>>,
    anchor: CertifiedTransactions,
    schedule: SlotSchedule,
    http: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    let anchor = certified_anchor(&vectors_dir())?;
    eprintln!(
        "sextant-watchd: genesis-anchored certified block {} (epoch {})",
        anchor.block_number, anchor.epoch
    );
    let app = Arc::new(App {
        watches: Mutex::new(HashMap::new()),
        anchor,
        schedule: preprod_schedule(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
    });

    let router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/watch", post(watch))
        .route("/verdict", get(verdict))
        .with_state(app);

    let addr = std::env::var("WATCHD_ADDR").unwrap_or_else(|_| "0.0.0.0:8477".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    eprintln!("sextant-watchd: listening on {addr}");
    axum::serve(listener, router).await.context("serve")?;
    Ok(())
}

#[derive(Deserialize)]
struct WatchReq {
    tx_id: String,
    index: u16,
}

/// Register an outpoint to watch. Idempotent: a second POST for the same outpoint is a
/// no-op. Spawns a follow task; returns immediately with the initial `pending` view.
async fn watch(State(app): State<Arc<App>>, Json(req): Json<WatchReq>) -> impl IntoResponse {
    let key = (req.tx_id.to_lowercase(), req.index);
    let tx_id: [u8; 32] = match hex::decode(&key.0).ok().and_then(|b| b.try_into().ok()) {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "tx_id must be 32-byte hex").into_response(),
    };
    let mut watches = app.watches.lock().await;
    if watches.contains_key(&key) {
        let v = watches.get(&key).cloned().unwrap();
        return (StatusCode::OK, Json(v)).into_response();
    }
    if watches.len() >= MAX_WATCHES {
        return (StatusCode::TOO_MANY_REQUESTS, "watch capacity reached").into_response();
    }
    let pending = VerdictView {
        status: "pending".into(),
        as_of_height: 0,
        as_of_slot: 0,
        tip_slot: 0,
        mithril_quorum: false,
        spend_at_height: 0,
        spend_region: String::new(),
        stall_reason: String::new(),
    };
    watches.insert(key.clone(), pending.clone());
    drop(watches);

    let app2 = app.clone();
    let outpoint = OutPoint {
        tx_id,
        index: req.index,
    };
    tokio::spawn(async move {
        if let Err(e) = follow_watch(app2.clone(), key.clone(), outpoint).await {
            let mut w = app2.watches.lock().await;
            if let Some(v) = w.get_mut(&key) {
                v.status = "stalled".into();
                v.stall_reason = format!("transport: {e}");
            }
        }
    });
    (StatusCode::ACCEPTED, Json(pending)).into_response()
}

#[derive(Deserialize)]
struct VerdictQuery {
    tx_id: String,
    index: u16,
}

/// The current windowed verdict for a watched outpoint (404 if not watched).
async fn verdict(State(app): State<Arc<App>>, Query(q): Query<VerdictQuery>) -> impl IntoResponse {
    let key = (q.tx_id.to_lowercase(), q.index);
    match app.watches.lock().await.get(&key).cloned() {
        Some(v) => (StatusCode::OK, Json(v)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "not watching this outpoint (POST /watch first)",
        )
            .into_response(),
    }
}

/// Follow one watched outpoint from its creating block to the live tip, updating its
/// shared verdict as each verified block lands. Bootstrap: block-fetch the creating block
/// (chain-sync serves only successors), append it, then intersect there and stream forward.
async fn follow_watch(app: Arc<App>, key: (String, u16), watch: OutPoint) -> Result<()> {
    // 1. The creating block's point + block, and the anchor/schedule.
    let create_point = koios_tx_point(&app.http, &key.0).await?;
    let mut peer = connect().await?;
    let creating_block = {
        let raws = blockfetch_range(&mut peer, create_point.clone(), create_point.clone()).await?;
        raws.into_iter()
            .next()
            .context("blockfetch creating block")?
    };
    let create_height = transport::block_number(&creating_block)?;

    // 2. Stage the creating epoch's nonce and bootstrap the follower on the creating block.
    let create_epoch = app.schedule.epoch_of(header_slot(&creating_block)?);
    let mut staged = vec![(create_epoch, epoch_nonce(&app.http, create_epoch).await?)];
    let mut follower = bootstrap(
        watch,
        &app.anchor,
        create_height,
        app.schedule,
        &staged,
        &creating_block,
    )
    .map_err(|e| anyhow::anyhow!("creating block did not verify: {e:?}"))?;

    // 3. Intersect at the creating block and stream its successors, re-verifying each.
    peer.chainsync()
        .find_intersect(vec![create_point])
        .await
        .context("find_intersect")?;
    loop {
        match peer
            .chainsync()
            .request_next()
            .await
            .context("request_next")?
        {
            NextResponse::RollForward(header, tip) => {
                let point = header_point(
                    header.variant,
                    header.byron_prefix.map(|p| p.0),
                    &header.cbor,
                )?;
                // Stage the epoch nonce if this block crossed into a new epoch.
                let slot = point_slot(&point);
                let epoch = app.schedule.epoch_of(slot);
                if !staged.iter().any(|(e, _)| *e == epoch) {
                    staged.push((epoch, epoch_nonce(&app.http, epoch).await?));
                    follower.supply_next_eta0(epoch, staged.last().unwrap().1);
                }
                let block = {
                    let raws = blockfetch_range(&mut peer, point.clone(), point).await?;
                    raws.into_iter()
                        .next()
                        .context("blockfetch forward block")?
                };
                match drive(&mut follower, SyncEvent::Forward(block)) {
                    DriveOutcome::Appended(_) => {}
                    DriveOutcome::Refused(_) => { /* fail-closed: the verdict stays as-is */ }
                    DriveOutcome::RolledBack(_) => unreachable!(),
                }
                publish(&app, &key, &follower, tip_slot(&tip)).await;
            }
            NextResponse::RollBackward(point, tip) => {
                let mut hash = [0u8; 32];
                if let Point::Specific(_, h) = &point {
                    if h.len() == 32 {
                        hash.copy_from_slice(h);
                    }
                }
                drive(
                    &mut follower,
                    SyncEvent::Backward {
                        slot: point_slot(&point),
                        hash,
                    },
                );
                publish(&app, &key, &follower, tip_slot(&tip)).await;
            }
            NextResponse::Await => {
                // Caught up to the tip; request_next again blocks until the next block.
                continue;
            }
        }
    }
}

/// Project the follower's current verdict into the shared view.
async fn publish(
    app: &Arc<App>,
    key: &(String, u16),
    follower: &sextant::follow::WindowFollower,
    tip_slot: u64,
) {
    let freshness = Freshness {
        slot_now: tip_slot,
        max_lag: 3 * PREPROD_EPOCH_LEN,
    };
    let view = project(&follower.verdict(freshness), tip_slot);
    if let Some(v) = app.watches.lock().await.get_mut(key) {
        *v = view;
    }
}

fn project(v: &WatchVerdict, tip_slot: u64) -> VerdictView {
    let mut view = VerdictView {
        status: String::new(),
        as_of_height: 0,
        as_of_slot: 0,
        tip_slot,
        mithril_quorum: false,
        spend_at_height: 0,
        spend_region: String::new(),
        stall_reason: String::new(),
    };
    match v {
        WatchVerdict::Unspent { as_of, basis } => {
            view.status = "no_spend_observed".into();
            view.as_of_height = as_of.as_of_height;
            view.as_of_slot = as_of.as_of_slot;
            if let WatchBasis::WatchedWindow(a) = basis {
                view.mithril_quorum = a.mithril_quorum;
            }
        }
        WatchVerdict::SpentObserved {
            at_height, region, ..
        } => {
            view.status = "spend_observed".into();
            view.spend_at_height = *at_height;
            view.spend_region = format!("{region:?}");
        }
        WatchVerdict::Stalled {
            verified_through,
            reason,
        } => {
            view.status = "stalled".into();
            view.as_of_height = *verified_through;
            view.stall_reason = format!("{reason:?}");
        }
    }
    view
}

fn point_slot(p: &Point) -> u64 {
    match p {
        Point::Specific(slot, _) => *slot,
        Point::Origin => 0,
    }
}

fn tip_slot(tip: &pallas_network::miniprotocols::chainsync::Tip) -> u64 {
    point_slot(&tip.0)
}

fn header_slot(block: &[u8]) -> Result<u64> {
    Ok(pallas_traverse::MultiEraBlock::decode(block)
        .context("decode block")?
        .slot())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sextant::window::{SpendRegion, StallReason, WatchBasis, WatchedTip, WindowAssumptions};

    /// The verdict→JSON projection is the consumer's safety boundary: a `Stalled` or
    /// `SpentObserved` follower verdict must NEVER read as `no_spend_observed`, and
    /// `mithril_quorum` must default false outside a genuine no-spend. Pins all three arms
    /// + the no-carryover rebuild.
    #[test]
    fn project_never_leaks_a_false_no_spend() {
        // Unspent → no_spend_observed, quorum bit read from the basis.
        let v = project(
            &WatchVerdict::Unspent {
                as_of: WatchedTip {
                    anchor_height: 10,
                    as_of_height: 9,
                    as_of_slot: 900,
                },
                basis: WatchBasis::WatchedWindow(WindowAssumptions {
                    mithril_quorum: true,
                    data_complete: true,
                }),
            },
            950,
        );
        assert_eq!(v.status, "no_spend_observed");
        assert!(v.mithril_quorum);
        assert_eq!((v.as_of_height, v.as_of_slot, v.tip_slot), (9, 900, 950));

        // SpentObserved → spend_observed (NEVER no_spend); quorum defaults false.
        let v = project(
            &WatchVerdict::SpentObserved {
                at_height: 5,
                at_slot: 500,
                spending_txid: [1u8; 32],
                region: SpendRegion::HeaderVouched,
            },
            950,
        );
        assert_eq!(v.status, "spend_observed");
        assert_ne!(v.status, "no_spend_observed");
        assert_eq!(v.spend_at_height, 5);
        assert!(!v.mithril_quorum);

        // Stalled → stalled (NEVER no_spend); quorum defaults false.
        let v = project(
            &WatchVerdict::Stalled {
                verified_through: 3,
                reason: StallReason::WindowTooShort,
            },
            950,
        );
        assert_eq!(v.status, "stalled");
        assert_ne!(v.status, "no_spend_observed");
        assert!(!v.mithril_quorum);
    }
}
