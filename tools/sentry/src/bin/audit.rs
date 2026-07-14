//! Tier-2 discharge audit (provenance spot-check): sample transactions from the certified UTxO
//! set@S and prove each is a real, STM-stake-quorum-certified transaction — catching a PHANTOM the
//! forward follow cannot (an outpoint the ancillary padded that no window block re-creates).
//!
//! For each sampled `tx_id`: fetch the Mithril `CardanoTransactions` inclusion proof, and RECOMPUTE
//! it on Sextant's own path ([`sextant::inclusion::verify_tx_inclusion`]) against the Merkle root of
//! a `verify_chain_anchored`-authenticated certificate (via `fetch_fresh_anchor`, genesis-anchored to
//! the pinned vkey). The aggregator supplies BYTES (the proof); Sextant supplies the verdict — a
//! phantom's `tx_id` is listed non-certified or fails the recompute, never a trusted "yes".
//!
//! This is the trustless complement to the forward subset-consistency audit (setfollow.rs). It is a
//! reservoir SAMPLE (uniform across the whole set@S, seeded from the certified root so a
//! placement-aware padder cannot predict which members are checked), NOT the full set; a full
//! `AncillarySigned → StmCertified` discharge proves every member.
//!
//! Usage: `sextant-audit <ancillary-dir> <preprod|mainnet> <sample-size>`

use anyhow::{Context, Result, bail};
use sentry::coverage::max_undetected_phantoms;
use sentry::transport::{fetch_fresh_anchor, fetch_tx_proof, load_committed_base, vectors_dir};
use sextant::ancillary::{ANCILLARY_VKEY_MAINNET, ANCILLARY_VKEY_PREPROD};
use sextant::inclusion::verify_tx_inclusion;
use snapshot::{tables::for_each_outpoint, verified_tables, verify_manifest};

/// A tiny deterministic PRNG (SplitMix64) for reservoir sampling — seeded from the certified root so
/// the sample is reproducible yet unpredictable to whoever built the ancillary.
struct SplitMix64(u64);

impl SplitMix64 {
    fn seed(root: &[u8; 32]) -> Self {
        let mut s = 0u64;
        for chunk in root.chunks_exact(8) {
            s ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        SplitMix64(s)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A value uniform in `[0, n)` (`n > 0`); the modulo skew is negligible for sampling.
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .context("usage: <ancillary-dir> <network> <sample-size>")?;
    let network = args
        .next()
        .context("usage: <ancillary-dir> <network> <sample-size>")?;
    let sample: usize = args
        .next()
        .context("usage: <ancillary-dir> <network> <sample-size>")?
        .parse()
        .context("sample-size")?;
    let vkey = match network.as_str() {
        "preprod" => &ANCILLARY_VKEY_PREPROD,
        "mainnet" => &ANCILLARY_VKEY_MAINNET,
        other => bail!("unknown network {other:?}"),
    };
    let dir = std::path::Path::new(&dir);

    // Trust the tables from the signed manifest.
    let verified = verify_manifest(dir, vkey)?;
    let tables = verified_tables(dir, &verified)?;

    // The genesis-anchored, STM-certified transaction Merkle root — the trust root the proofs are
    // recomputed against. Fetched FIRST so the sample can be seeded from it.
    let (base, genesis_vkey) = load_committed_base(&vectors_dir())?;
    let http = reqwest::Client::new();
    let anchor = fetch_fresh_anchor(&http, &base, &genesis_vkey).await?;
    let root = anchor
        .merkle_root_bytes()
        .context("certified anchor has a malformed merkle root")?;
    eprintln!(
        "certified transaction root @ epoch {} block {} (genesis-anchored)",
        anchor.epoch, anchor.block_number
    );

    // RESERVOIR-sample `sample` distinct tx_ids UNIFORMLY across the WHOLE set@S — not a low-tx_id
    // prefix a placement-aware padder could hide phantoms above. The RNG is seeded from the
    // certified root (future to whoever built the ancillary), so the sample is reproducible yet
    // unpredictable to a padder. The tables are strictly key-increasing, so equal tx_ids are
    // adjacent and distinct-counting needs no set. A real parse error propagates (never swallowed).
    let mut rng = SplitMix64::seed(&root);
    let mut prev: Option<[u8; 32]> = None;
    let mut n_distinct: u64 = 0;
    let mut tx_ids: Vec<[u8; 32]> = Vec::with_capacity(sample);
    for_each_outpoint(tables.bytes(), |o| {
        if prev != Some(o.tx_id) {
            prev = Some(o.tx_id);
            let i = n_distinct;
            n_distinct += 1;
            if (i as usize) < sample {
                tx_ids.push(o.tx_id);
            } else {
                let j = rng.below(n_distinct); // uniform in [0, i]
                if (j as usize) < sample {
                    tx_ids[j as usize] = o.tx_id;
                }
            }
        }
        Ok(())
    })?;
    eprintln!(
        "reservoir-sampled {} of {n_distinct} distinct set@S tx_ids (root-seeded, uniform)",
        tx_ids.len()
    );

    let mut certified = 0usize;
    let mut phantom = 0usize;
    for (i, tx_id) in tx_ids.iter().enumerate() {
        let hex = hex::encode(tx_id);
        match fetch_tx_proof(&http, &hex).await? {
            None => {
                phantom += 1;
                eprintln!("PHANTOM: tx {hex} is NOT in the certified set");
            }
            Some(proof) => match verify_tx_inclusion(&proof, tx_id, &root) {
                Ok(()) => {
                    certified += 1;
                    if i < 3 || (i + 1) % 25 == 0 {
                        eprintln!("verified #{}: tx {hex} STM-certified", i + 1);
                    }
                }
                Err(e) => {
                    phantom += 1;
                    eprintln!("FAILED: tx {hex} proof did not recompute to the root: {e}");
                }
            },
        }
    }

    println!("distinct_members: {n_distinct}");
    println!("sampled: {}", tx_ids.len());
    println!("certified_real: {certified}");
    println!("phantom_or_failed: {phantom}");
    if phantom > 0 {
        println!("result: FAIL ({phantom} sampled transactions are not STM-certified)");
        return Ok(());
    }
    // Quantified partial discharge: publish exactly how much this passing sample buys. At 99%
    // confidence, fewer than this many of the set's distinct tx_ids could be undetected phantoms.
    const ALPHA: f64 = 0.01;
    let max_phantoms = max_undetected_phantoms(n_distinct, certified as u32, ALPHA);
    // The shown fraction is derived from the (exhaustion-capped) count so they always agree.
    let frac = if n_distinct == 0 {
        0.0
    } else {
        max_phantoms as f64 / n_distinct as f64
    };
    println!("result: PASS ({certified} STM-certified, 0 phantom)");
    println!("confidence: 0.99");
    println!(
        "phantom_bound: < {max_phantoms} phantom tx_ids ({:.4}% of {n_distinct}) at 99% confidence",
        frac * 100.0
    );
    println!(
        "discharge: PARTIAL (sampled) — {certified} members STM-certified; a full \
         AncillarySigned->StmCertified discharge proves every member (genesis->S recompute)"
    );
    Ok(())
}
