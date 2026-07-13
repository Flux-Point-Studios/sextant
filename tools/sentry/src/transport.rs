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
/// The release-preprod Mithril aggregator (the same network the committed anchor chain
/// was harvested from) for a fresh genesis-anchored re-anchor.
pub const MITHRIL_AGG: &str = "https://aggregator.release-preprod.api.mithril.network/aggregator";
/// Cap the fresh-anchor walk: a genesis→tip CardanoTransactions chain is ~one cert/epoch
/// (the committed base is 106); refuse a runaway walk rather than hammer the aggregator.
pub const MAX_ANCHOR_HOPS: usize = 400;
/// Cap each aggregator response body before it is buffered/parsed. A real certificate is a
/// few KB (the AVK / multi-signature blobs dominate and are themselves field-capped in
/// `verify_standard`); this bound turns a hostile multi-GB body — amplified `MAX_ANCHOR_HOPS`
/// times in the walk — from a daemon OOM into a fail-closed error that keeps the anchor.
pub const MAX_AGG_BODY_BYTES: usize = 8 * 1024 * 1024;
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

/// Load the PINNED committed genesis-anchored base (`tests/vectors/`): the network genesis
/// vkey and the genesis→tip certificate chain. Both are committed, so the trust root is
/// pinned, never fetched — the aggregator is only ever asked for the SHORT extension past
/// this base ([`fetch_fresh_anchor`]). Returns the raw certs and the vkey; the caller
/// verifies (via [`anchor_from_chain`] / [`splice_anchor`]).
pub fn load_committed_base(vectors_dir: &std::path::Path) -> Result<(Vec<Certificate>, [u8; 32])> {
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
    Ok((certs, genesis_vkey))
}

/// Verify a genesis→tip certificate chain to the pinned genesis key and surface the tip's
/// certified transaction set. Fails closed if the chain is not genesis-anchored (bad
/// linkage / AVK binding / genesis signature / STM multi-signature) or the tip certifies
/// no transaction set — a caller never gets an unverified anchor.
pub fn anchor_from_chain(
    certs: &[Certificate],
    genesis_vkey: &[u8; 32],
) -> Result<CertifiedTransactions> {
    let verified = verify_chain_anchored(certs, genesis_vkey)
        .map_err(|e| anyhow!("chain not genesis-anchored: {e:?}"))?;
    verified
        .certified_transactions
        .context("tip certifies no transaction set")
}

/// Read a response body, refusing anything over [`MAX_AGG_BODY_BYTES`]. The declared
/// `Content-Length` is rejected up front, and the body is drained chunk-by-chunk so a
/// missing or lying length still can't exceed the cap — an untrusted aggregator cannot
/// force an unbounded allocation before the bytes are parsed.
async fn read_capped(resp: reqwest::Response) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length()
        && len > MAX_AGG_BODY_BYTES as u64
    {
        return Err(anyhow!(
            "aggregator body {len} B exceeds {MAX_AGG_BODY_BYTES} B cap"
        ));
    }
    let mut resp = resp;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("aggregator body chunk")? {
        if buf.len() + chunk.len() > MAX_AGG_BODY_BYTES {
            return Err(anyhow!(
                "aggregator body exceeds {MAX_AGG_BODY_BYTES} B cap"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// The certified transactions anchor from a genesis-anchored verify over the committed base
/// alone — the deterministic pin the daemon starts from before any live re-anchor.
pub fn certified_anchor(vectors_dir: &std::path::Path) -> Result<CertifiedTransactions> {
    let (certs, genesis_vkey) = load_committed_base(vectors_dir)?;
    anchor_from_chain(&certs, &genesis_vkey)
}

/// Splice a freshly-walked certificate extension (newest-first, the order a `previous_hash`
/// walk collects it) onto the committed genesis-anchored base at their common ancestor,
/// verify the whole spliced chain to the pinned genesis key, and surface the fresh tip's
/// certified transaction set. The extension's OLDEST certificate links (`previous_hash`) to
/// a certificate already in the base — the ancestor — so `base[..=ancestor] ++ extension`
/// is one contiguous genesis→fresh-tip chain. Reusing the verified base prefix means only
/// the short extension is re-verified, never the ~1-cert/epoch backbone back to genesis.
/// Fails closed if the extension does not link to the base, any fresh certificate's STM
/// multi-signature is invalid, or the tip certifies no transaction set — on any failure the
/// caller keeps its current anchor rather than trust a floating certificate.
pub fn splice_anchor(
    base: &[Certificate],
    extension_newest_first: &[Certificate],
    genesis_vkey: &[u8; 32],
) -> Result<CertifiedTransactions> {
    let oldest = extension_newest_first
        .last()
        .context("empty fresh extension")?;
    let anc_idx = base
        .iter()
        .position(|c| c.hash == oldest.previous_hash)
        .context("fresh extension does not link to the committed base (ancestor not found)")?;
    let mut chain: Vec<Certificate> = base[..=anc_idx].to_vec();
    chain.extend(extension_newest_first.iter().rev().cloned());
    anchor_from_chain(&chain, genesis_vkey)
}

/// Fetch a FRESH genesis-anchored certified anchor from the aggregator: take the newest
/// CardanoTransactions artifact's certificate, walk its `previous_hash` chain back until it
/// meets the committed base (the common ancestor — an epoch backbone certificate the base
/// already carries), then [`splice_anchor`] the short extension onto the base and verify to
/// genesis. The aggregator supplies only bytes; every certificate is hash-recomputed,
/// AVK-bound, and STM-verified by the splice, so a forged fresh anchor cannot advance the
/// daemon. Bounded by [`MAX_ANCHOR_HOPS`]; walking to genesis without meeting the base (a
/// pruned aggregator) is an error, not a slow genesis re-harvest.
pub async fn fetch_fresh_anchor(
    http: &reqwest::Client,
    base: &[Certificate],
    genesis_vkey: &[u8; 32],
) -> Result<CertifiedTransactions> {
    #[derive(Deserialize)]
    struct CtxArtifact {
        certificate_hash: String,
    }
    let list = http
        .get(format!("{MITHRIL_AGG}/artifact/cardano-transactions"))
        .header("accept", "application/json")
        .send()
        .await?
        .error_for_status()?;
    let list = read_capped(list)
        .await
        .context("aggregator cardano-transactions artifact list")?;
    let arts: Vec<CtxArtifact> =
        serde_json::from_slice(&list).context("parse cardano-transactions artifact list")?;
    let mut hash = arts
        .into_iter()
        .next()
        .context("aggregator has no cardano-transactions artifact")?
        .certificate_hash;

    let base_hashes: std::collections::HashSet<&str> =
        base.iter().map(|c| c.hash.as_str()).collect();
    let mut extension: Vec<Certificate> = Vec::new();
    for _ in 0..MAX_ANCHOR_HOPS {
        if base_hashes.contains(hash.as_str()) {
            return splice_anchor(base, &extension, genesis_vkey);
        }
        let resp = http
            .get(format!("{MITHRIL_AGG}/certificate/{hash}"))
            .header("accept", "application/json")
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("aggregator cert {hash} unavailable (pruned?)"))?;
        let body = read_capped(resp)
            .await
            .with_context(|| format!("aggregator cert {hash} body"))?;
        let cert =
            Certificate::from_json(&body).map_err(|e| anyhow!("parse fresh cert {hash}: {e}"))?;
        if cert.hash != hash {
            return Err(anyhow!("aggregator returned cert {} for {hash}", cert.hash));
        }
        let prev = cert.previous_hash.clone();
        extension.push(cert);
        if prev.is_empty() {
            return Err(anyhow!(
                "walked to genesis without meeting the committed base"
            ));
        }
        hash = prev;
    }
    Err(anyhow!(
        "fresh-anchor walk exceeded {MAX_ANCHOR_HOPS} hops without meeting the committed base"
    ))
}

/// The committed `tests/vectors` directory, relative to this crate.
pub fn vectors_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> (Vec<Certificate>, [u8; 32]) {
        load_committed_base(&vectors_dir()).expect("committed base loads")
    }

    /// The splice+verify path, end to end, offline: treat the committed tip CardanoTransactions
    /// certificate as a fresh one-hop extension onto the base prefix (it IS a sibling of a
    /// fresher live cert — same epoch-MSD parent), and confirm splicing reproduces exactly the
    /// committed anchor. This is the shape `fetch_fresh_anchor` builds for the current epoch.
    #[test]
    fn splice_reconstructs_the_committed_anchor_from_its_sibling_slot() {
        let (certs, vkey) = base();
        let (prefix, ext) = certs.split_at(certs.len() - 1);
        let spliced = splice_anchor(prefix, &ext.to_vec(), &vkey).expect("splice verifies");
        let pinned = certified_anchor(&vectors_dir()).expect("pinned anchor");
        assert_eq!(spliced.block_number, pinned.block_number);
        assert_eq!(spliced.merkle_root, pinned.merkle_root);
        assert_eq!(spliced.epoch, pinned.epoch);
    }

    /// An extension whose oldest certificate links to no base certificate cannot be anchored:
    /// the daemon keeps its current anchor rather than trust a floating certificate. Fails at
    /// the ancestor lookup, before any verify.
    #[test]
    fn splice_rejects_an_extension_that_does_not_link_to_the_base() {
        let (certs, vkey) = base();
        let mut orphan = certs.last().unwrap().clone();
        orphan.previous_hash = "de".repeat(32); // 64 hex chars matching no base cert
        let err = splice_anchor(&certs, &[orphan], &vkey).unwrap_err();
        assert!(err.to_string().contains("does not link"), "{err}");
    }

    /// A corrupted fresh certificate (tampered multi-signature) links to the base but fails
    /// the genesis-anchored verify — its recomputed content hash no longer matches, so the
    /// spliced chain is rejected. A forged fresh anchor can never advance the daemon.
    #[test]
    fn splice_rejects_a_corrupted_fresh_cert() {
        let (certs, vkey) = base();
        let (prefix, ext) = certs.split_at(certs.len() - 1);
        let mut bad = ext[0].clone();
        bad.multi_signature = "00".repeat(bad.multi_signature.len() / 2);
        let err = splice_anchor(prefix, &[bad], &vkey).unwrap_err();
        assert!(err.to_string().contains("not genesis-anchored"), "{err}");
    }

    /// An empty extension is a no-op error, not a panic — a walk that collected nothing (the
    /// artifact cert was already the base tip) leaves the current anchor in place.
    #[test]
    fn splice_rejects_an_empty_extension() {
        let (certs, vkey) = base();
        assert!(splice_anchor(&certs, &[], &vkey).is_err());
    }
}
