//! Verified-read spend gate — the first downstream consumer of Sextant's read
//! verdict (a keeper/batcher stand-in for the out-of-scope write-path).
//!
//! It runs ONE control flow over UNTRUSTED provider bytes: authenticate the
//! Mithril certificate chain back to the pinned genesis key, take the certified
//! transaction root from the AUTHENTICATED certificate (never a provider-supplied
//! root), verify the UTxO's certified inclusion, then make a single boolean spend
//! decision over the verified output.
//!
//! ## Honest scope (mandatory)
//! This verified read proves authentic, genesis-certified transaction INCLUSION
//! (the output was created and is certified as of block `certified_at`, ~100 blocks
//! behind tip); it does NOT and cannot prove the output is currently UNSPENT — that
//! is deferred to the ledger at spend submission. The gate never reads
//! [`sextant::utxo::SpendStatus`] and never claims that a `Proceed` means the spend
//! will succeed. Only the ADA coin is checked (not any multi-asset bundle), and the
//! state is `certified_at`, not tip.

use std::fs;
use std::path::PathBuf;

use sextant::mithril::{AnchoredError, Certificate, verify_chain_anchored};
use sextant::utxo::{Datum, UtxoError, verify_utxo_read};

/// Golden preprod transaction id (`blake2b-256` of the certified body). Display-only
/// — the security binding is inside [`verify_utxo_read`], which rehashes the supplied
/// bytes and never trusts a provider-supplied hash.
pub const UTXO_TXID_HEX: &str = "242f2037b427ff20ef97a076a7d845c74530be4e5a97b59bb18a519fcfa7a636";
/// The output index the consumer reads (output 0 of the golden order transaction).
pub const OUT_INDEX: usize = 0;
/// The minimum lovelace the order output must carry for the gate to proceed.
pub const MIN_LOVELACE: u64 = 5_000_000;

/// Output 0's script address (a real on-chain order): the tamper leg flips a byte of
/// the coin that immediately follows it.
const OUT0_ADDR_HEX: &str = "7015e93b4326724b8e2d3abc3a6aaef29ce6d6877cfc815eb8f3bd3699";
/// The exact inline datum the consumer's order predicate expects on output 0.
const EXPECTED_ORDER_DATUM_HEX: &str = "d8799fbfd8799f4040ffd8799f1a09d00ed6ffd8799f581c3c0307006496e072a496c0742e55af0c64284b5bf668f2b420fe4f3540ffd8799f1a3b9aca00ffff1b0000019f53ec4417ff";

/// The consumer's single decision over a verified output. There is no third state:
/// either the composed verify path yielded an output that met the order predicate,
/// or the consumer refuses (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The output is authentic, genesis-certified, and meets the order predicate.
    Proceed,
    /// The consumer refuses — a verify step failed or the predicate was not met.
    Refuse,
}

/// The consumer's structured verdict for one evaluation: the decision, the structured
/// log lines it emitted, the certified height it read at (when a verified output
/// existed), and a short reason tag on a refusal.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The spend decision.
    pub decision: Decision,
    /// The certified height the output was attested at, when one was verified.
    pub certified_at: Option<u64>,
    /// A short machine-readable reason tag when the decision is [`Decision::Refuse`].
    pub refuse_reason: Option<String>,
    /// The structured log lines emitted for this evaluation (the DoD "service log").
    pub log: Vec<String>,
}

/// The untrusted inputs a single verified-read evaluation composes over. Only
/// `genesis_vkey` is trusted (the one pinned network anchor); everything else is
/// provider bytes. There is deliberately NO `certified_root` field — the root can
/// ONLY come from the authenticated certificate, so a provider cannot inject one.
pub struct Request<'a> {
    /// The Mithril genesis→tip certificate chain JSON (oldest first).
    pub anchor_chain_json: &'a [u8],
    /// The pinned per-network genesis verification key — the only trusted input.
    pub genesis_vkey: &'a [u8; 32],
    /// The raw transaction-body CBOR whose output is read.
    pub tx_body: &'a [u8],
    /// The aggregator inclusion proof (HEX of the JSON `MKMapProof`) for the tx.
    pub proof_hex: &'a [u8],
    /// Which output of the transaction the consumer reads.
    pub out_index: usize,
    /// The minimum lovelace the order output must carry.
    pub min_lovelace: u64,
    /// The exact datum the order output must carry.
    pub expected_datum: Datum,
}

/// Evaluate one verified read and produce the consumer's decision, composing only
/// shipped verify functions over the untrusted bytes in `req`.
///
/// The control flow is fail-closed: any verify step that rejects returns
/// [`Decision::Refuse`] before a verified output ever exists, so the spend gate is
/// never reached on a spoofed response. The certified root is taken ONLY from the
/// genesis-authenticated certificate ([`Request`] carries no root), so a provider
/// cannot substitute one.
pub fn evaluate(req: &Request) -> Outcome {
    let mut log = Vec::new();
    // The short display ref `first8…last4#index` for the log lines.
    let reff = format!(
        "{}…{}#{}",
        &UTXO_TXID_HEX[..8],
        &UTXO_TXID_HEX[UTXO_TXID_HEX.len() - 4..],
        req.out_index
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

    // 2-3. Authenticate the chain back to the pinned genesis key. The certified
    // transaction root is sourced from the AUTHENTICATED tip, never the provider.
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

    // 4. The tip's Cardano-transactions commitment — the root and certified height.
    let ct = match verified.certified_transactions {
        Some(ct) => ct,
        None => {
            return refuse(log, &reff, "NotATxCert", "tip certifies no transaction set");
        }
    };
    let mut certified_root = [0u8; 32];
    if hex::decode_to_slice(&ct.merkle_root, &mut certified_root).is_err() {
        return refuse(
            log,
            &reff,
            "MalformedRoot",
            "certified root is not 32-byte hex",
        );
    }

    // 5. Verify the UTxO's certified inclusion against the AUTHENTICATED root, then
    // decode the requested output. `verify_utxo_read` rehashes the supplied bytes,
    // so a tampered/substituted response is rejected as not-included here.
    let out = match verify_utxo_read(
        req.tx_body,
        req.out_index,
        req.proof_hex,
        &certified_root,
        ct.block_number,
    ) {
        Ok(out) => out,
        Err(e) => {
            let reason = match e {
                UtxoError::Inclusion(_) => "NotIncluded",
                UtxoError::MalformedTx => "MalformedTx",
                UtxoError::OutputIndexOutOfRange => "OutputIndexOutOfRange",
            };
            log.push(format!(
                "WARN read.verify utxo={reff} provider=spoofed reason={reason}"
            ));
            log.push(format!(
                "INFO spend.gate {reff} -> REFUSE (no verified output; spend not submitted)"
            ));
            return Outcome {
                decision: Decision::Refuse,
                certified_at: None,
                refuse_reason: Some(reason.to_string()),
                log,
            };
        }
    };

    // The verified read succeeded: authentic bytes, certified inclusion, provenance.
    let datum_kind = match &out.datum {
        Some(Datum::Inline(_)) => "inline",
        Some(Datum::Hash(_)) => "hash",
        None => "none",
    };
    log.push(format!(
        "INFO read.verify utxo={reff} certified_at={} anchored=genesis lovelace={} datum={datum_kind}",
        out.certified_at, out.lovelace
    ));

    // 8. SPEND GATE — the only decision, a boolean over the VERIFIED output. It never
    // branches on `spend_status` (unspent is undecidable on the read path).
    let proceed =
        out.lovelace >= req.min_lovelace && out.datum.as_ref() == Some(&req.expected_datum);
    if proceed {
        log.push(format!(
            "INFO spend.gate {reff} -> PROCEED  note=spend_status=NotEstablished (authenticity+inclusion proven; unspent deferred to the ledger at submission)"
        ));
        Outcome {
            decision: Decision::Proceed,
            certified_at: Some(out.certified_at),
            refuse_reason: None,
            log,
        }
    } else {
        log.push(format!(
            "INFO spend.gate {reff} -> REFUSE (verified output did not meet the order predicate)"
        ));
        Outcome {
            decision: Decision::Refuse,
            certified_at: Some(out.certified_at),
            refuse_reason: Some("OrderPredicate".to_string()),
            log,
        }
    }
}

/// Build a fail-closed refusal: a verify step rejected before any verified output
/// existed, so the spend gate is never reached. Emits the WARN read line and the
/// REFUSE gate line naming the spoofed provider.
fn refuse(mut log: Vec<String>, reff: &str, reason: &str, detail: &str) -> Outcome {
    log.push(format!(
        "WARN read.verify utxo={reff} provider=spoofed reason={reason} ({detail})"
    ));
    log.push(format!(
        "INFO spend.gate {reff} -> REFUSE (no verified output; spend not submitted)"
    ));
    Outcome {
        decision: Decision::Refuse,
        certified_at: None,
        refuse_reason: Some(reason.to_string()),
        log,
    }
}

/// Run the accept path then the spoof path over the committed fixtures, print the
/// structured log lines, and return a process exit code (0 only if the authentic
/// order proceeds AND the spoofed one is refused — fail-closed on anything else).
pub fn run_demo() -> i32 {
    let chain = anchor_chain_json();
    let vkey = genesis_vkey();
    let body = tx_body();
    let proof = proof_hex();

    let accept = evaluate(&Request {
        anchor_chain_json: &chain,
        genesis_vkey: &vkey,
        tx_body: &body,
        proof_hex: &proof,
        out_index: OUT_INDEX,
        min_lovelace: MIN_LOVELACE,
        expected_datum: expected_datum(),
    });
    for line in &accept.log {
        println!("{line}");
    }

    let tampered = tamper_output0_coin(&body);
    let spoof = evaluate(&Request {
        anchor_chain_json: &chain,
        genesis_vkey: &vkey,
        tx_body: &tampered,
        proof_hex: &proof,
        out_index: OUT_INDEX,
        min_lovelace: MIN_LOVELACE,
        expected_datum: expected_datum(),
    });
    for line in &spoof.log {
        println!("{line}");
    }

    // Fail-closed: the authentic order must proceed with a certified height, and the
    // spoofed one must be refused specifically for non-inclusion (no verified output).
    let ok = accept.decision == Decision::Proceed
        && accept.certified_at.is_some()
        && spoof.decision == Decision::Refuse
        && spoof.refuse_reason.as_deref() == Some("NotIncluded");
    if ok {
        0
    } else {
        eprintln!("unexpected outcome: accept={accept:?} spoof={spoof:?}");
        1
    }
}

/// Flip one byte of output 0's coin, changing the transaction's economic content
/// (and therefore its hash) — a spoofed provider response.
pub fn tamper_output0_coin(body: &[u8]) -> Vec<u8> {
    let addr = hex::decode(OUT0_ADDR_HEX).expect("output 0 address hex");
    let pos = body
        .windows(addr.len())
        .position(|w| w == addr.as_slice())
        .expect("output 0 address present in the body");
    // The value follows the address as `01 82 1a <coin:4>`; skip key(01) array(82)
    // uint32-tag(1a) to the first coin byte.
    let coin_byte = pos + addr.len() + 3;
    let mut t = body.to_vec();
    t[coin_byte] ^= 0x01;
    t
}

/// The vectors directory, resolved from the crate manifest (same for the example
/// binary and the integration test, whichever includes this module).
fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The 106-cert genesis→tip Mithril certificate chain JSON (untrusted provider bytes).
pub fn anchor_chain_json() -> Vec<u8> {
    fs::read(vectors_dir().join("mithril-anchor-chain.json")).expect("read anchor chain")
}

/// The pinned per-network genesis verification key (the only trusted input).
pub fn genesis_vkey() -> [u8; 32] {
    let text = fs::read_to_string(vectors_dir().join("mithril-genesis.vkey")).expect("read vkey");
    let mut key = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut key).expect("genesis vkey is 32-byte hex");
    key
}

/// The raw transaction-body CBOR (the fixture is its lowercase hex).
pub fn tx_body() -> Vec<u8> {
    let hexstr = fs::read_to_string(vectors_dir().join("mithril-tx-body.cbor")).expect("read body");
    hex::decode(hexstr.trim()).expect("body is hex")
}

/// The aggregator `proof` field (HEX of the JSON `MKMapProof`) for the golden tx.
pub fn proof_hex() -> Vec<u8> {
    let bytes = fs::read(vectors_dir().join("mithril-txproof.json")).expect("read txproof");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse txproof");
    v["certified_transactions"][0]["proof"]
        .as_str()
        .expect("proof field")
        .as_bytes()
        .to_vec()
}

/// The exact inline datum the order output must carry for the gate to proceed.
pub fn expected_datum() -> Datum {
    Datum::Inline(hex::decode(EXPECTED_ORDER_DATUM_HEX).expect("expected datum hex"))
}
