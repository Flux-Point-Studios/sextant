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
//! background task (F6d) polls the Mithril aggregator, splices the short fresh extension
//! onto the pinned committed genesis→tip base, verifies it to the genesis key, and swaps in
//! the fresher certified anchor; each watch's next publish re-anchors to it, so an outpoint
//! that has aged into the newly certified region reports `mithril_quorum=true`. A watch
//! whose tip is still ABOVE the freshest certified block is honestly `mithril_quorum=false`
//! (header-vouched) until the next poll certifies through it.
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
use tokio::sync::{Mutex, RwLock};

use sentry::transport::{
    self, PREPROD_EPOCH_LEN, anchor_from_chain, blockfetch_range, connect, epoch_nonce,
    fetch_fresh_anchor, header_point, koios_tx_point, load_committed_base, preprod_schedule,
    vectors_dir,
};
use sentry::{DriveOutcome, SyncEvent, bootstrap, drive};
use sextant::follow::SlotSchedule;
use sextant::mithril::Certificate;
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
    /// The current genesis-anchored certified anchor, swapped in by [`re_anchor_loop`] as
    /// the chain advances. `RwLock<Arc<_>>` so a follow task reads a cheap snapshot without
    /// blocking the periodic re-anchor writer.
    anchor: RwLock<Arc<CertifiedTransactions>>,
    /// The committed genesis→tip base and its pinned genesis vkey — the trust root the live
    /// re-anchor splices its short aggregator extension onto (never re-walked to genesis).
    base: Vec<Certificate>,
    genesis_vkey: [u8; 32],
    schedule: SlotSchedule,
    http: reqwest::Client,
}

/// How often to poll the aggregator for a fresher certified anchor.
const RE_ANCHOR_POLL: Duration = Duration::from_secs(120);

#[tokio::main]
async fn main() -> Result<()> {
    let (base, genesis_vkey) = load_committed_base(&vectors_dir())?;
    let anchor0 = anchor_from_chain(&base, &genesis_vkey)?;
    eprintln!(
        "sextant-watchd: genesis-anchored certified block {} (epoch {}); polling for fresher every {}s",
        anchor0.block_number,
        anchor0.epoch,
        RE_ANCHOR_POLL.as_secs(),
    );
    let app = Arc::new(App {
        watches: Mutex::new(HashMap::new()),
        anchor: RwLock::new(Arc::new(anchor0)),
        base,
        genesis_vkey,
        schedule: preprod_schedule(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
    });
    tokio::spawn(re_anchor_loop(app.clone()));

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
            // A dead follow task must serve a CLEAN stalled — a REFUSE — never a stale
            // no-spend and never a Frankenstein view keeping spend fields from the last
            // publish beside a `stalled` status. Keep only the last-known tip slot so a
            // consumer can still see how fresh the abandoned answer was.
            let mut w = app2.watches.lock().await;
            if let Some(v) = w.get_mut(&key) {
                *v = VerdictView {
                    status: "stalled".into(),
                    as_of_height: 0,
                    as_of_slot: 0,
                    tip_slot: v.tip_slot,
                    mithril_quorum: false,
                    spend_at_height: 0,
                    spend_region: String::new(),
                    stall_reason: format!("transport: {e}"),
                };
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

    // 2. Stage the creating epoch's nonce and bootstrap the follower on the creating block,
    //    against a snapshot of the current certified anchor (publish re-anchors it forward).
    let create_epoch = app.schedule.epoch_of(header_slot(&creating_block)?);
    let mut staged = vec![(create_epoch, epoch_nonce(&app.http, create_epoch).await?)];
    let anchor0 = app.anchor.read().await.clone();
    let mut follower = bootstrap(
        watch,
        anchor0.as_ref(),
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
        // `request_or_await_next` (not `request_next`): at the tip the server takes agency
        // (MustReply) and the client must WAIT for the next block via `recv_while_must_reply`.
        // Calling `request_next` there sends a request while the client has no agency — a
        // chain-sync protocol violation the relay answers by dropping the connection. This
        // dispatches on agency, so a caught-up follower blocks cleanly for the next block.
        match peer
            .chainsync()
            .request_or_await_next()
            .await
            .context("request_or_await_next")?
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
                publish(&app, &key, &mut follower, tip_slot(&tip)).await;
            }
            NextResponse::RollBackward(point, tip) => {
                let mut hash = [0u8; 32];
                if let Point::Specific(_, h) = &point
                    && h.len() == 32
                {
                    hash.copy_from_slice(h);
                }
                drive(
                    &mut follower,
                    SyncEvent::Backward {
                        slot: point_slot(&point),
                        hash,
                    },
                );
                publish(&app, &key, &mut follower, tip_slot(&tip)).await;
            }
            NextResponse::Await => {
                // Caught up to the tip: the server now holds agency. The next loop turn's
                // `request_or_await_next` sees no client agency and blocks in
                // `recv_while_must_reply` until the server sends the next block.
                continue;
            }
        }
    }
}

/// Re-anchor the follower to the freshest certified anchor, then project its verdict into
/// the shared view. Re-anchoring here (monotone: `re_anchor` never regresses the height)
/// is what lets a watch that has aged into a freshly certified region read
/// `mithril_quorum=true` — the anchor the periodic [`re_anchor_loop`] advanced now covers
/// this watch's tip. No spend proof is supplied (`None`): a no-spend upgrades by height
/// coverage, and a spend NEVER upgrades to certified without its inclusion proof.
async fn publish(
    app: &Arc<App>,
    key: &(String, u16),
    follower: &mut sextant::follow::WindowFollower,
    tip_slot: u64,
) {
    let anchor = app.anchor.read().await.clone();
    follower.re_anchor(anchor.as_ref(), None);
    let freshness = Freshness {
        slot_now: tip_slot,
        max_lag: 3 * PREPROD_EPOCH_LEN,
    };
    let view = project(&follower.verdict(freshness), tip_slot);
    if let Some(v) = app.watches.lock().await.get_mut(key) {
        *v = view;
    }
}

/// Poll the aggregator for a fresher genesis-anchored certified anchor and swap it in. Each
/// watch's next [`publish`] re-anchors to it, so an outpoint that has aged into the newly
/// certified region reports `mithril_quorum=true`. A fetch/verify failure keeps the current
/// anchor: freshness degrades, safety never does — the daemon can only ever serve a verdict
/// against an anchor it re-verified to the pinned genesis key.
async fn re_anchor_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(RE_ANCHOR_POLL).await;
        match fetch_fresh_anchor(&app.http, &app.base, &app.genesis_vkey).await {
            Ok(fresh) => {
                let cur = app.anchor.read().await.block_number;
                if fresh.block_number > cur {
                    let fb = fresh.block_number;
                    *app.anchor.write().await = Arc::new(fresh);
                    eprintln!("sextant-watchd: re-anchored to certified block {fb} (was {cur})");
                }
            }
            Err(e) => eprintln!("sextant-watchd: re-anchor skipped, kept current anchor: {e}"),
        }
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
