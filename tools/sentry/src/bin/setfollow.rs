//! Tier-2 T4-drive: a bounded LIVE follow proving the Tier-2 set-follower over a real preprod
//! relay. It opens the certified UTxO set at S (the `snapshot-load` output), verifies + derives the
//! tip from the ancillary (T4-tip), FindIntersects the relay at that exact `(slot, hash)` point —
//! which independently confirms the parsed tip — then streams the successors, block-fetches each,
//! and advances the set through [`sextant::setfollow::apply_block`] (header crypto → body-bind →
//! contiguous atomic apply). Rollbacks route to the set's own `rollback_to`.
//!
//! The relay supplies BYTES (headers, blocks, and — via Koios — each epoch's nonce); the follower
//! supplies the verdict. A wrong nonce or a forged/out-of-order block is refused, not applied.
//!
//! The `<redb-path>` must be a store freshly loaded by `snapshot-load` (seeded at S); the follow
//! advances it in place. Re-running against an already-advanced store fails closed (its spends were
//! already applied ⇒ `SpendOfUnknownOutput`), never silently wrong; resume-from-persisted-tip is a
//! later concern.
//!
//! Usage: `sextant-setfollow <ancillary-dir> <preprod|mainnet> <redb-path> <max-blocks>`

use anyhow::{Context, Result, bail};
use pallas_network::miniprotocols::Point;
use pallas_network::miniprotocols::chainsync::NextResponse;
use sentry::transport::{blockfetch_range, connect, epoch_nonce, header_point, preprod_schedule};
use sextant::ancillary::{ANCILLARY_VKEY_MAINNET, ANCILLARY_VKEY_PREPROD};
use sextant::setfollow::apply_block;
use sextant::utxoset::UtxoSet;
use snapshot::{verified_anchor, verified_tables, verify_manifest};
use utxo_store::RedbUtxoStore;

/// The retained rollback window (k = 2160 blocks).
const DEPTH: usize = 2160;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .context("usage: <ancillary-dir> <network> <redb-path> <max-blocks>")?;
    let network = args
        .next()
        .context("usage: <ancillary-dir> <network> <redb-path> <max-blocks>")?;
    let redb_path = args
        .next()
        .context("usage: <ancillary-dir> <network> <redb-path> <max-blocks>")?;
    let max_blocks: u64 = args
        .next()
        .context("usage: <ancillary-dir> <network> <redb-path> <max-blocks>")?
        .parse()
        .context("max-blocks")?;
    let vkey = match network.as_str() {
        "preprod" => &ANCILLARY_VKEY_PREPROD,
        "mainnet" => &ANCILLARY_VKEY_MAINNET,
        other => bail!("unknown network {other:?}"),
    };
    let dir = std::path::Path::new(&dir);
    let http = reqwest::Client::new();
    let schedule = preprod_schedule();

    // 1. Verify + derive the certified tip S (T4-tip): the FindIntersect point.
    let verified = verify_manifest(dir, vkey)?;
    let s_slot = verified_tables(dir, &verified)?.slot;
    let anchor = verified_anchor(dir, &verified)?;
    eprintln!(
        "certified tip: slot {s_slot} #{} {} ({:?})",
        anchor.tip.number,
        hex::encode(anchor.tip.hash),
        anchor.basis
    );

    // 2. Open the pre-loaded set at S.
    let store =
        RedbUtxoStore::open(&redb_path).map_err(|e| anyhow::anyhow!("open store: {}", e.0))?;
    let mut set = UtxoSet::with_store(store, Some(anchor.tip), DEPTH);
    let start_len = set.len().map_err(|e| anyhow::anyhow!("{}", e.0))?;
    eprintln!("opened certified set: {start_len} outpoints at slot {s_slot}");

    // 3. Connect + FindIntersect at the tip point — the relay confirming this point IS S's tip on
    //    its chain is the independent validation of the parsed tip hash.
    let mut peer = connect().await.context("connect relay")?;
    let start_point = Point::Specific(s_slot, anchor.tip.hash.to_vec());
    let (found, tip) = peer
        .chainsync()
        .find_intersect(vec![start_point])
        .await
        .context("find_intersect")?;
    match &found {
        Some(Point::Specific(slot, h)) if *slot == s_slot && h == &anchor.tip.hash.to_vec() => {
            eprintln!(
                "relay CONFIRMED intersect at S (tip validated); chain tip is slot {}",
                point_slot(&tip.0)
            );
        }
        other => bail!("relay did not intersect at S (parsed tip not on chain): {other:?}"),
    }

    // 4. Follow forward, bounded, applying each real block to the set.
    let mut staged: Vec<(u64, [u8; 32])> = Vec::new();
    let mut applied = 0u64;
    let mut rollbacks = 0u64;
    while applied < max_blocks {
        match peer
            .chainsync()
            .request_or_await_next()
            .await
            .context("request_or_await_next")?
        {
            NextResponse::RollForward(header, _tip) => {
                let point = header_point(
                    header.variant,
                    header.byron_prefix.map(|p| p.0),
                    &header.cbor,
                )?;
                let slot = point_slot(&point);
                let epoch = schedule.epoch_of(slot);
                if !staged.iter().any(|(e, _)| *e == epoch) {
                    let nonce = epoch_nonce(&http, epoch).await.context("epoch nonce")?;
                    staged.push((epoch, nonce));
                    eprintln!("staged epoch {epoch} nonce {}", hex::encode(nonce));
                }
                let eta0 = staged.iter().find(|(e, _)| *e == epoch).unwrap().1;
                let block = blockfetch_range(&mut peer, point.clone(), point)
                    .await
                    .context("blockfetch")?
                    .into_iter()
                    .next()
                    .context("empty blockfetch")?;
                match apply_block(&mut set, &block, &eta0) {
                    Ok(new_tip) => {
                        applied += 1;
                        if applied <= 3 || applied.is_multiple_of(250) {
                            eprintln!(
                                "applied #{applied}: slot {slot} -> set tip #{}",
                                new_tip.number
                            );
                        }
                    }
                    Err(e) => bail!("apply_block refused a live block at slot {slot}: {e}"),
                }
            }
            NextResponse::RollBackward(point, _tip) => {
                if let Point::Specific(_, h) = &point
                    && h.len() == 32
                {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(h);
                    // Rolling back to the intersection point (== our current tip) is a no-op.
                    set.rollback_to(&hash)
                        .map_err(|e| anyhow::anyhow!("rollback: {e:?}"))?;
                    if hash != anchor.tip.hash {
                        rollbacks += 1;
                        eprintln!("rolled back to slot {}", point_slot(&point));
                    }
                }
            }
            NextResponse::Await => {
                eprintln!("reached the live tip");
                break;
            }
        }
    }

    let end_len = set.len().map_err(|e| anyhow::anyhow!("{}", e.0))?;
    let final_tip = set.tip().expect("tip after follow");
    println!("applied_blocks: {applied}");
    println!("rollbacks: {rollbacks}");
    println!("start_len: {start_len}");
    println!("end_len: {end_len}");
    println!(
        "final_tip: #{} {}",
        final_tip.number,
        hex::encode(final_tip.hash)
    );
    Ok(())
}

fn point_slot(p: &Point) -> u64 {
    match p {
        Point::Specific(slot, _) => *slot,
        Point::Origin => 0,
    }
}
