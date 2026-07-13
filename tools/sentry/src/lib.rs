//! Sans-io orchestration for the live windowed-unspent follower (BEYOND-DoD Epic F, F6).
//!
//! [`sextant::follow::WindowFollower`] is a sans-io state machine: it verifies bytes it
//! is handed (append one block, roll back to a point, re-anchor, read a verdict) and
//! holds no sockets or clock. This crate is the thin driver between a chain-sync
//! transport and that follower — the part that can be proven deterministically, without
//! a network, so a mock peer scripts the exact same event sequence the live relay would
//! produce.
//!
//! ## The two seams the driver encapsulates
//! 1. **Bootstrap.** Node-to-node chain-sync serves only the SUCCESSORS of an intersect
//!    point, so the outpoint's creating block is never delivered by the stream. The
//!    transport must block-fetch it by its own point and [`bootstrap`] appends it FIRST,
//!    before any forward event — matching the follower's "first append is the creating
//!    block" contract.
//! 2. **Event mapping.** A chain-sync `RollForward` (whose full body the transport
//!    block-fetches) becomes [`SyncEvent::Forward`]; a `RollBackward` becomes
//!    [`SyncEvent::Backward`]. [`drive`] is the ONE mapping the live transport and the
//!    mock test both call, so the wiring — including a rollback point's `(slot, hash)`
//!    orientation — is checked by the deterministic gate, not only in production.
//!
//! Re-anchoring (poll the aggregator, `verify_chain_anchored`, advance the certified
//! region) and freshness (a wall-clock slot estimate) are the transport's job and stay
//! out of this sans-io core: the follower's `re_anchor` and `verdict(freshness)` are
//! called directly with the values the transport computes.

/// Reusable node-to-node + Koios + aggregator transport primitives, shared by the demo
/// and the watch-daemon binaries. Behind the `transport` feature so the default sans-io
/// lib (and its mock gate) build with zero network deps.
#[cfg(feature = "transport")]
pub mod transport;

use sextant::follow::{AppendRefusal, Rollback, SlotSchedule, WindowFollower};
use sextant::utxo::{CertifiedTransactions, OutPoint};

/// A chain-sync event resolved to bytes. The live transport turns a node-to-node
/// `RollForward` into [`SyncEvent::Forward`] (after block-fetching the full body — N2N
/// chain-sync carries headers only) and a `RollBackward` into [`SyncEvent::Backward`];
/// a test scripts them directly.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// A full block (ledger `[era, block]` CBOR) to append to the verified window.
    Forward(Vec<u8>),
    /// Roll the window back to the block identified by `hash` at `slot`.
    Backward {
        /// The rollback point's slot (chain-sync `Point` fidelity).
        slot: u64,
        /// The rollback point's block hash — the authoritative identifier.
        hash: [u8; 32],
    },
}

/// What driving one [`SyncEvent`] did to the follower.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveOutcome {
    /// A forward block verified and advanced the tip to this block number.
    Appended(u64),
    /// A forward block was refused (left the follower untouched) for this reason.
    Refused(AppendRefusal),
    /// A rollback resolved to this arm.
    RolledBack(Rollback),
}

/// Build a follower and append the outpoint's creating block FIRST — the bootstrap the
/// transport performs before opening chain-sync at that block's point. Every epoch the
/// window will span must have its nonce supplied up front (the follower selects the
/// verifying nonce per block by slot); a missing nonce only fails a later append closed,
/// never a false accept.
///
/// Returns the follower with the creating block accepted, or the refusal if the supplied
/// creating block did not verify (a bad bootstrap fails closed — no window is started).
pub fn bootstrap(
    watch: OutPoint,
    anchor: &CertifiedTransactions,
    require_through: u64,
    schedule: SlotSchedule,
    eta0s: &[(u64, [u8; 32])],
    creating_block: &[u8],
) -> Result<WindowFollower, AppendRefusal> {
    let mut follower = WindowFollower::new(watch, anchor, require_through, schedule);
    for (epoch, eta0) in eta0s {
        follower.supply_next_eta0(*epoch, *eta0);
    }
    follower.append(creating_block)?;
    Ok(follower)
}

/// Drive one chain-sync event into the follower — the single event→follower mapping the
/// live transport and the deterministic mock-peer test share. A forward block is appended
/// (advancing or being refused fail-closed); a backward event rolls the window back.
pub fn drive(follower: &mut WindowFollower, event: SyncEvent) -> DriveOutcome {
    match event {
        SyncEvent::Forward(block) => match follower.append(&block) {
            Ok(appended) => DriveOutcome::Appended(appended.block_number),
            Err(refusal) => DriveOutcome::Refused(refusal),
        },
        SyncEvent::Backward { slot, hash } => {
            DriveOutcome::RolledBack(follower.rollback(slot, &hash))
        }
    }
}
