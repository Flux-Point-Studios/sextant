//! `dump-block <slot> <hash-hex> <out-file>` — block-fetch one block by point from the preprod
//! relay, write its raw CBOR hex to `out-file`, and run `extract_block_effects` on it so a block
//! the Tier-2 follow refused can be diagnosed and frozen as a fixture. Diagnostic, not production.

use anyhow::{Context, Result, bail};
use pallas_network::miniprotocols::Point;
use sentry::transport::{blockfetch_range, connect};
use sextant::effects::extract_block_effects;
use sextant::header::HeaderView;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let slot: u64 = args
        .next()
        .context("usage: <slot> <hash-hex> <out-file>")?
        .parse()?;
    let hash_hex = args.next().context("usage: <slot> <hash-hex> <out-file>")?;
    let out = args.next().context("usage: <slot> <hash-hex> <out-file>")?;
    let hash = hex::decode(hash_hex.trim()).context("hash hex")?;

    let mut peer = connect().await.context("connect")?;
    let point = Point::Specific(slot, hash);
    let block = blockfetch_range(&mut peer, point.clone(), point)
        .await
        .context("blockfetch")?
        .into_iter()
        .next()
        .context("empty blockfetch")?;
    std::fs::write(&out, hex::encode(&block)).context("write out")?;
    eprintln!("wrote {} bytes of block to {out}", block.len());

    match HeaderView::decode_block(&block) {
        Ok((v, _)) => eprintln!(
            "header OK: #{} slot {} era {}",
            v.block_number, v.slot, v.era
        ),
        Err(e) => bail!("header decode failed: {e:?}"),
    }
    match extract_block_effects(&block) {
        Ok(eff) => {
            let (mut s, mut c) = (0, 0);
            for tx in &eff.txs {
                s += tx.spent.len();
                c += tx.created.len();
            }
            println!("extract OK: {} txs, {s} spent, {c} created", eff.txs.len());
        }
        Err(e) => println!("extract FAILED: {e:?}"),
    }
    Ok(())
}
