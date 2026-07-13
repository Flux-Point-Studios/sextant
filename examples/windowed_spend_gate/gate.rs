//! Windowed spend gate — the downstream consumer of Sextant's windowed watch verdict
//! (a Masumi-escrow / ADAM-spend-gate stand-in), the honest counterpart to the
//! single-read `verified_read_gate`.
//!
//! It runs ONE control flow over UNTRUSTED provider bytes: authenticate the Mithril
//! certificate chain back to the pinned genesis key, take the certified anchor from the
//! AUTHENTICATED tip (never a provider-supplied height), then scan a header-verified,
//! body-committed block window for any spend of the watched outpoint and make a single
//! spend decision over the three-valued verdict.
//!
//! ## Honest scope (mandatory)
//! A `PROCEED` means ONLY: no input consuming the watched outpoint appears in any body of
//! a header-verified, hash-linked, gap-free, body-committed window that observed the
//! outpoint's creation and reached the caller's `require_through` height — under the
//! surfaced assumptions, as of the verified tip. It is NOT absolute unspent, NOT eternal,
//! NOT tip state; the ledger still decides spendability atomically at submission. The gate
//! prints the basis, anchor, as-of tip, freshness lag, and assumptions on the SAME line as
//! PROCEED — there is no bare `-> PROCEED` for a windowed verdict. A definite spend
//! (`SpentObserved`) and every non-answer (`Stalled` — a gap, a truncated or stale window)
//! are both a fail-closed REFUSE.

use std::fs;
use std::path::PathBuf;

use sextant::header::HeaderView;
use sextant::mithril::{AnchoredError, Certificate, verify_chain_anchored};
use sextant::utxo::{CertifiedTransactions, OutPoint};
use sextant::window::{Freshness, WatchBasis, WatchVerdict, verify_watched_window};

/// The watched transaction, created in the window's first block (preprod 4921916).
pub const WATCHED_TX_HEX: &str = "beaa9166c061e56457b5d84de4b3d15c9386b202d2585ff247f47af0dcd32a5e";
/// The transaction that spends `beaa9166…#1` in block[1] (4921917) — the definite-refuse leg.
pub const SPENDING_TX_HEX: &str =
    "760076f24ea0a151d28a32fb627a17122c92cb7bfb02041995bc98a421687844";
/// Epoch-300 active nonce (Koios); the preprod window's shared epoch nonce (a known
/// network parameter the consumer pins, like the genesis key).
pub const EPOCH_300_ETA0_HEX: &str =
    "aa845533c5f8631a864010ae89c23ee1cee0ed7717e4ac00a25ad50f4eeb6c30";
/// The caller's required coverage floor: it declares it needs no-spend evidence through at
/// least the window tip height (4921937). A truncated window that ends earlier fails it.
pub const REQUIRE_THROUGH: u64 = 4_921_937;

/// The consumer's single decision over a windowed watch verdict. There is no third state:
/// either no spend was observed across a window that reached the caller's floor, or the
/// consumer refuses (a definite spend, or any non-answer — fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// No spend of the watched outpoint observed across the verified window under the
    /// stamped assumptions; the caller's own freshness bound was met.
    Proceed,
    /// The consumer refuses — a spend was observed, the window could not answer, or the
    /// chain did not anchor.
    Refuse,
}

/// The consumer's structured verdict for one evaluation.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The spend decision.
    pub decision: Decision,
    /// The verified tip height the no-spend evidence holds as of, when a `PROCEED`.
    pub as_of_height: Option<u64>,
    /// A short machine-readable reason tag when the decision is [`Decision::Refuse`].
    pub refuse_reason: Option<String>,
    /// The structured log lines emitted for this evaluation (the service log).
    pub log: Vec<String>,
}

/// The untrusted inputs a single windowed evaluation composes over. Only `genesis_vkey`
/// and `eta0` are pinned network parameters; the certificate chain and the block window
/// are provider bytes. There is deliberately NO `anchor_height` field — the anchor can
/// ONLY come from the authenticated certificate, so a provider cannot inject a fake
/// certified region.
pub struct Request<'a> {
    /// The Mithril genesis→tip certificate chain JSON (oldest first).
    pub anchor_chain_json: &'a [u8],
    /// The pinned per-network genesis verification key.
    pub genesis_vkey: &'a [u8; 32],
    /// The window's epoch nonce (a pinned known parameter).
    pub eta0: &'a [u8; 32],
    /// The contiguous block window (on-chain order) to scan — untrusted provider bytes.
    pub window_blocks: &'a [Vec<u8>],
    /// The outpoint the consumer watches.
    pub watched: OutPoint,
    /// The height the caller needs no-spend coverage through.
    pub require_through: u64,
    /// The caller's recency bound.
    pub freshness: Freshness,
}

/// Evaluate one windowed watch and produce the consumer's decision, composing only
/// shipped verify functions over the untrusted bytes in `req`.
///
/// Fail-closed: any step that does not yield a `no spend observed` verdict over a window
/// reaching the caller's floor returns [`Decision::Refuse`]. The certified anchor is taken
/// ONLY from the genesis-authenticated certificate ([`Request`] carries no height), so a
/// provider cannot vouch for a region Mithril did not certify.
pub fn evaluate(req: &Request) -> Outcome {
    let mut log = Vec::new();
    let reff = format!(
        "{}…{}#{}",
        &WATCHED_TX_HEX[..8],
        &WATCHED_TX_HEX[WATCHED_TX_HEX.len() - 4..],
        req.watched.index,
    );

    // 1. Parse the untrusted certificate chain (oldest first).
    let certs: Vec<Certificate> = match serde_json::from_slice(req.anchor_chain_json) {
        Ok(certs) => certs,
        Err(_) => {
            return refuse(
                log,
                &reff,
                "MalformedChain",
                "certificate chain did not parse",
            );
        }
    };

    // 2. Authenticate the chain back to the pinned genesis key.
    let verified = match verify_chain_anchored(&certs, req.genesis_vkey) {
        Ok(v) => v,
        Err(e) => {
            let reason = match &e {
                AnchoredError::Chain(_) => "Chain",
                AnchoredError::Genesis(_) => "Genesis",
                AnchoredError::Standard { .. } => "Standard",
            };
            return refuse(
                log,
                &reff,
                reason,
                &format!("chain not genesis-anchored: {e}"),
            );
        }
    };

    // 3. The certified anchor from the AUTHENTICATED tip — the completeness bound the
    //    window rests inside, never a provider-supplied height.
    let anchor: CertifiedTransactions = match verified.certified_transactions {
        Some(ct) => ct,
        None => return refuse(log, &reff, "NotATxCert", "tip certifies no transaction set"),
    };

    // 4. Scan the header-verified, body-committed window for a spend of the outpoint.
    let verdict = verify_watched_window(
        req.watched,
        &anchor,
        req.require_through,
        req.window_blocks,
        req.eta0,
        req.freshness,
    );

    // 5. SPEND GATE — the only decision, over the three-valued verdict.
    match verdict {
        WatchVerdict::Unspent { as_of, basis } => {
            let WatchBasis::WatchedWindow(a) = basis else {
                return refuse(
                    log,
                    &reff,
                    "UnknownBasis",
                    "verdict carried an unrecognized basis",
                );
            };
            let lag = req.freshness.slot_now.saturating_sub(as_of.as_of_slot);
            let assumptions = format!(
                "{}{}",
                if a.mithril_quorum {
                    "mithril_quorum"
                } else {
                    "!mithril_quorum"
                },
                if a.data_complete {
                    ",data_complete"
                } else {
                    ",!data_complete"
                },
            );
            log.push(format!(
                "INFO watch.scan {reff} basis=WatchedWindow anchor={} as_of={}@slot{} verified=header+body-committed",
                as_of.anchor_height, as_of.as_of_height, as_of.as_of_slot,
            ));
            log.push(format!(
                "INFO watch.gate {reff} -> PROCEED  basis=WatchedWindow anchor={} as_of={}@slot{} lag={}/{} assumptions={assumptions} note=no-spend-observed through the verified tip (NOT absolute; the ledger decides at submission)",
                as_of.anchor_height, as_of.as_of_height, as_of.as_of_slot, lag, req.freshness.max_lag,
            ));
            Outcome {
                decision: Decision::Proceed,
                as_of_height: Some(as_of.as_of_height),
                refuse_reason: None,
                log,
            }
        }
        WatchVerdict::SpentObserved {
            at_height,
            at_slot,
            spending_txid,
            region,
        } => {
            log.push(format!(
                "WARN watch.scan {reff} spend observed at block={at_height} slot={at_slot} by tx={} region={region:?}",
                hex::encode(spending_txid),
            ));
            log.push(format!(
                "INFO watch.gate {reff} -> REFUSE (spend observed in the verified window; spend not submitted)"
            ));
            Outcome {
                decision: Decision::Refuse,
                as_of_height: None,
                refuse_reason: Some("SpendObserved".to_string()),
                log,
            }
        }
        WatchVerdict::Stalled {
            verified_through,
            reason,
        } => {
            let tag = format!("Stall:{reason:?}");
            log.push(format!(
                "WARN watch.scan {reff} window could not answer: {reason:?} (verified_through={verified_through})"
            ));
            log.push(format!(
                "INFO watch.gate {reff} -> REFUSE (non-answer is a refuse; no false no-spend)"
            ));
            Outcome {
                decision: Decision::Refuse,
                as_of_height: None,
                refuse_reason: Some(tag),
                log,
            }
        }
    }
}

/// Build a fail-closed refusal at the pre-scan stage (chain did not anchor).
fn refuse(mut log: Vec<String>, reff: &str, reason: &str, detail: &str) -> Outcome {
    log.push(format!(
        "WARN watch.verify {reff} provider=spoofed reason={reason} ({detail})"
    ));
    log.push(format!(
        "INFO watch.gate {reff} -> REFUSE (no anchored window; spend not submitted)"
    ));
    Outcome {
        decision: Decision::Refuse,
        as_of_height: None,
        refuse_reason: Some(reason.to_string()),
        log,
    }
}

/// Run the four legs over the committed fixtures — the honest PROCEED, then the three
/// refuse evasions — print the structured log lines, and return a process exit code
/// (0 only if the never-spent outpoint proceeds AND every evasion is refused fail-closed).
pub fn run_demo() -> i32 {
    let chain = anchor_chain_json();
    let vkey = genesis_vkey();
    let eta0 = eta0();
    let window = preprod_window();

    let build = |watched: OutPoint, blocks: &[Vec<u8>]| -> Outcome {
        evaluate(&Request {
            anchor_chain_json: &chain,
            genesis_vkey: &vkey,
            eta0: &eta0,
            window_blocks: blocks,
            watched,
            require_through: REQUIRE_THROUGH,
            freshness: fresh(),
        })
    };

    // Leg 1 — the never-spent outpoint over the full window: PROCEED.
    let proceed = build(watched(0), &window);
    // Leg 2 — the spent outpoint over the full window: REFUSE (definite spend).
    let spent = build(watched(1), &window);
    // Leg 3 — the spent outpoint with a mid-window block withheld: REFUSE (broken segment).
    let mut dropped = window.clone();
    dropped.remove(dropped.len() / 2);
    let gap = build(watched(1), &dropped);
    // Leg 4 — the spent outpoint over a window truncated before the spend: REFUSE
    //         (the caller's require_through floor caught the truncation evasion).
    let truncated = vec![window[0].clone()];
    let short = build(watched(1), &truncated);

    for out in [&proceed, &spent, &gap, &short] {
        for line in &out.log {
            println!("{line}");
        }
    }

    let ok = proceed.decision == Decision::Proceed
        && proceed.as_of_height == Some(REQUIRE_THROUGH)
        && spent.decision == Decision::Refuse
        && spent.refuse_reason.as_deref() == Some("SpendObserved")
        && spent.log.iter().any(|l| l.contains(SPENDING_TX_HEX))
        && gap.decision == Decision::Refuse
        && gap.refuse_reason.as_deref() == Some("Stall:BrokenSegment")
        && short.decision == Decision::Refuse
        && short.refuse_reason.as_deref() == Some("Stall:WindowTooShort");
    if ok {
        0
    } else {
        eprintln!(
            "unexpected outcome: proceed={proceed:?} spent={spent:?} gap={gap:?} short={short:?}"
        );
        1
    }
}

/// The vectors directory, resolved from the crate manifest.
fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

/// The watched outpoint at `index` (its transaction id is [`WATCHED_TX_HEX`]).
pub fn watched(index: u16) -> OutPoint {
    OutPoint {
        tx_id: unhex(WATCHED_TX_HEX).try_into().expect("32-byte txid"),
        index,
    }
}

/// The 106-cert genesis→tip Mithril certificate chain JSON (untrusted provider bytes).
pub fn anchor_chain_json() -> Vec<u8> {
    fs::read(vectors_dir().join("mithril-anchor-chain.json")).expect("read anchor chain")
}

/// The pinned per-network genesis verification key.
pub fn genesis_vkey() -> [u8; 32] {
    let text = fs::read_to_string(vectors_dir().join("mithril-genesis.vkey")).expect("read vkey");
    let mut key = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut key).expect("genesis vkey is 32-byte hex");
    key
}

/// The pinned epoch-300 nonce shared by the window.
pub fn eta0() -> [u8; 32] {
    unhex(EPOCH_300_ETA0_HEX).try_into().expect("32-byte eta0")
}

/// The caller's freshness bound the window tip (slot 128046016) comfortably meets.
pub fn fresh() -> Freshness {
    Freshness {
        slot_now: 128_046_016 + 60,
        max_lag: 100_000,
    }
}

/// The stored contiguous preprod window: every `preprod-*.block` in on-chain order (by
/// slot), block numbers 4921916..=4921937.
pub fn preprod_window() -> Vec<Vec<u8>> {
    let mut rows: Vec<(u64, Vec<u8>)> = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with("preprod-")
            || path.extension().and_then(|e| e.to_str()) != Some("block")
        {
            continue;
        }
        let bytes = unhex(&fs::read_to_string(&path).expect("read vector"));
        let view = HeaderView::from_block_cbor(&bytes).expect("decode preprod block");
        rows.push((view.slot, bytes));
    }
    rows.sort_by_key(|r| r.0);
    rows.into_iter().map(|r| r.1).collect()
}
