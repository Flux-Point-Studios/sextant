//! Verified-read provenance check — the body-only composition a consumer might reach for
//! before a spend decision, and why it cannot carry one.
//!
//! It runs ONE control flow over UNTRUSTED provider bytes: authenticate the Mithril
//! certificate chain back to the pinned genesis key, take the certified transaction root
//! from the AUTHENTICATED certificate (never a provider-supplied root), and verify the
//! transaction's certified inclusion.
//!
//! ## Honest scope (mandatory)
//! Inclusion is provenance: the transaction is in the genesis-certified transaction set as
//! of block `certified_at`. It establishes no output. What a transaction creates depends on
//! its phase-2 outcome, which its block records and its body does not carry, so every
//! body-only read ends in a REFUSE that names what was missing — `ValidityNotEstablished`
//! for an authentic included body, the failing step for a spoofed response. A spend
//! decision needs the output read from its creating block, as `windowed_spend_gate` does.

use std::fs;
use std::path::PathBuf;

use sextant::mithril::{AnchoredError, Certificate, verify_chain_anchored};
use sextant::utxo::{UtxoError, verify_utxo_read};

/// Golden preprod transaction id (`blake2b-256` of the certified body). Display-only
/// — the security binding is inside [`verify_utxo_read`], which rehashes the supplied
/// bytes and never trusts a provider-supplied hash.
pub const UTXO_TXID_HEX: &str = "242f2037b427ff20ef97a076a7d845c74530be4e5a97b59bb18a519fcfa7a636";
/// The output index the consumer reads (output 0 of the golden order transaction).
pub const OUT_INDEX: usize = 0;

/// Output 0's script address (a real on-chain order): the tamper leg flips a byte of
/// the coin that immediately follows it.
const OUT0_ADDR_HEX: &str = "7015e93b4326724b8e2d3abc3a6aaef29ce6d6877cfc815eb8f3bd3699";

/// The consumer's structured verdict for one evaluation. Every evaluation refuses; the
/// reason names the step that ended it.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// A short machine-readable reason tag.
    pub refuse_reason: String,
    /// The certified height the transaction was found included at, when it was.
    pub certified_at: Option<u64>,
    /// The structured log lines emitted for this evaluation (the service log).
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
}

/// Evaluate one body-only read, composing only shipped verify functions over the
/// untrusted bytes in `req`, and refuse with the reason the read ended on. The certified
/// root is taken ONLY from the genesis-authenticated certificate ([`Request`] carries no
/// root), so a provider cannot substitute one.
pub fn evaluate(req: &Request) -> Outcome {
    let log = Vec::new();
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
    let certified_root = match ct.merkle_root_bytes() {
        Some(root) => root,
        None => {
            return refuse(
                log,
                &reff,
                "MalformedRoot",
                "certified root is not 32-byte hex",
            );
        }
    };

    // 5. Verify the transaction's certified inclusion against the AUTHENTICATED root.
    // `verify_utxo_read` rehashes the supplied bytes, so a tampered/substituted response
    // is rejected as not-included here, and an included one is refused for want of its
    // phase-2 outcome.
    let (reason, detail) = match verify_utxo_read(
        req.tx_body,
        req.out_index,
        req.proof_hex,
        &certified_root,
        ct.block_number,
    ) {
        Err(UtxoError::Inclusion(_)) => ("NotIncluded", "the body is no certified transaction's"),
        Err(UtxoError::MalformedTx) => ("MalformedTx", "the output does not decode"),
        Err(UtxoError::OutputIndexOutOfRange) => {
            ("OutputIndexOutOfRange", "the index is past the outputs")
        }
        Err(UtxoError::ValidityNotEstablished) | Ok(_) => {
            return no_creation(log, &reff, ct.block_number);
        }
    };
    refuse(log, &reff, reason, detail)
}

/// The refusal for an authentic included body: the read proved provenance and stopped
/// short of an output, because the body carries no phase-2 outcome.
fn no_creation(mut log: Vec<String>, reff: &str, certified_at: u64) -> Outcome {
    log.push(format!(
        "INFO read.verify utxo={reff} certified_at={certified_at} anchored=genesis included=yes created=not-established (the phase-2 outcome is in the creating block)"
    ));
    log.push(format!(
        "INFO spend.gate {reff} -> REFUSE (inclusion is provenance, not creation; no output to gate on)"
    ));
    Outcome {
        refuse_reason: "ValidityNotEstablished".to_string(),
        certified_at: Some(certified_at),
        log,
    }
}

/// Build a fail-closed refusal: a verify step rejected the provider's bytes, so no
/// output was ever in question. Emits the WARN read line and the REFUSE gate line naming
/// the spoofed provider.
fn refuse(mut log: Vec<String>, reff: &str, reason: &str, detail: &str) -> Outcome {
    log.push(format!(
        "WARN read.verify utxo={reff} provider=spoofed reason={reason} ({detail})"
    ));
    log.push(format!(
        "INFO spend.gate {reff} -> REFUSE (no verified output; spend not submitted)"
    ));
    Outcome {
        refuse_reason: reason.to_string(),
        certified_at: None,
        log,
    }
}

/// Run the authentic path then the spoof path over the committed fixtures, print the
/// structured log lines, and return a process exit code (0 only if the authentic order
/// is found included and refused for want of its phase-2 outcome AND the spoofed one is
/// refused as not included — fail-closed on anything else).
pub fn run_demo() -> i32 {
    let chain = anchor_chain_json();
    let vkey = genesis_vkey();
    let body = tx_body();
    let proof = proof_hex();

    let authentic = evaluate(&Request {
        anchor_chain_json: &chain,
        genesis_vkey: &vkey,
        tx_body: &body,
        proof_hex: &proof,
        out_index: OUT_INDEX,
    });
    for line in &authentic.log {
        println!("{line}");
    }

    let tampered = tamper_output0_coin(&body);
    let spoof = evaluate(&Request {
        anchor_chain_json: &chain,
        genesis_vkey: &vkey,
        tx_body: &tampered,
        proof_hex: &proof,
        out_index: OUT_INDEX,
    });
    for line in &spoof.log {
        println!("{line}");
    }

    let ok = authentic.refuse_reason == "ValidityNotEstablished"
        && authentic.certified_at.is_some()
        && spoof.refuse_reason == "NotIncluded"
        && spoof.certified_at.is_none();
    if ok {
        0
    } else {
        eprintln!("unexpected outcome: authentic={authentic:?} spoof={spoof:?}");
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
