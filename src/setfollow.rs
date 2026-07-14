//! Tier-2 T4-follow: advance a [`UtxoSet`] by one header-verified block — the sans-io core the
//! live follow (T4-drive) drives. Given a set seeded at the certified tip S and a stream of blocks
//! from the relay, [`apply_block`] composes the already-proven primitives:
//!
//! 1. [`chain::verify_segment`] over the single block — opcert (cold→hot), leader-VRF vs the epoch
//!    nonce, and KES body signature: the block is an authentic one from an elected leader.
//! 2. [`extract_block_effects`] — binds the body to the header's commitment and decodes each
//!    transaction's consumed inputs / created outputs.
//! 3. [`UtxoSet::apply`] — enforces contiguity against the current tip and mutates the set inside
//!    one atomic transaction (a failure leaves the set exactly as it was).
//!
//! Rollback is the engine's own [`UtxoSet::rollback_to`] (the set carries a bounded undo window, so
//! the follower needs no ring of its own). No I/O — the transport lives in `tools/`, this stays
//! wasm-safe. The epoch nonce is an input: the driver stages the right `eta0` per epoch (as the
//! Tier-1 [`crate::follow::WindowFollower`] does), so a follow that crosses an epoch boundary just
//! supplies each block its own epoch's nonce.
//!
//! ## The forward follow IS a subset-consistency audit (discharge-in-miniature)
//! The anchor-basis ruling's discharge — demoting the single IOG ancillary key by RECOMPUTING the
//! set from independently-verified blocks — has a cheap forward half that falls out of the follow
//! itself: applying `(S, tip]` block-by-block — each block HEADER-vouched (opcert / leader-VRF / KES,
//! honest-majority), NOT yet STM-stake-quorum-certified — cross-checks the certified set@S against
//! the chain. An ancillary that OMITS a real pre-S outpoint fails closed when a window block spends it
//! ([`crate::utxoset::ApplyError::SpendOfUnknownOutput`]); one that PADS a phantom fails closed when
//! a window block re-creates it ([`crate::utxoset::ApplyError::DuplicateOutput`]). So a longer follow
//! is a stronger audit — my live catch-up applied 5,383 real blocks with zero such failures. The
//! full `AncillarySigned → StmCertified` discharge additionally needs the genesis→S recomputation
//! from STM-certified blocks (for a never-re-created phantom); this forward check is its miniature.

use crate::chain::{self, ChainError};
use crate::effects::{ExtractError, extract_block_effects};
use crate::utxoset::{ApplyError, SetTip, UtxoSet, UtxoStore};

/// Why a block could not advance the set. Every arm is a fail-closed refusal, never a panic — the
/// blocks arrive from an untrusted relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowError {
    /// The header failed to decode/link or its crypto (opcert / leader-VRF vs `eta0` / KES) did not
    /// verify — not an authentic block from an elected leader.
    Header(ChainError),
    /// The body does not match the header's block-body commitment, or a transaction did not decode.
    Extract(ExtractError),
    /// The block does not extend the set's current tip, or it spends an output the set does not
    /// hold (a data gap) — contiguity/consistency refused by the engine.
    Apply(ApplyError),
}

impl core::fmt::Display for FollowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FollowError::Header(e) => write!(f, "block header did not verify: {e}"),
            FollowError::Extract(e) => write!(f, "block body/effects did not extract: {e:?}"),
            FollowError::Apply(e) => write!(f, "block did not apply to the set: {e:?}"),
        }
    }
}

impl std::error::Error for FollowError {}

/// Apply one block to `set`, advancing its tip, and return the new tip. Verifies the header crypto
/// against `eta0` (the block's epoch nonce), binds the body to the header and extracts the
/// spent/created outpoints, then applies them atomically with a contiguity check. Any failure
/// leaves the set exactly as it was ([`UtxoSet::apply`] is transactional) and fails closed.
pub fn apply_block<S: UtxoStore>(
    set: &mut UtxoSet<S>,
    block: &[u8],
    eta0: &[u8; 32],
) -> Result<SetTip, FollowError> {
    // 1. Header crypto (a real block from an elected leader). A single-block segment has no
    //    inter-block link to check; the link to OUR chain is enforced by `apply` below.
    chain::verify_segment(core::slice::from_ref(&block), eta0).map_err(FollowError::Header)?;
    // 2. Body-commitment bind + per-transaction input/output decode.
    let effects = extract_block_effects(block).map_err(FollowError::Extract)?;
    // 3. Contiguity + atomic set mutation.
    set.apply(&effects).map_err(FollowError::Apply)?;
    Ok(set.tip().expect("apply sets the tip"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::HeaderView;
    use crate::utxo::OutPoint;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// The stored consecutive preprod run: every `preprod-<slot>.block` with its `.eta0` sidecar,
    /// ordered by slot — a contiguous, hash-linked, single-epoch (300) segment of real blocks.
    fn preprod_run() -> (Vec<Vec<u8>>, [u8; 32]) {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
        let mut entries: Vec<(u64, PathBuf)> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "block"))
            .filter_map(|p| {
                let slot: u64 = p
                    .file_stem()?
                    .to_str()?
                    .strip_prefix("preprod-")?
                    .parse()
                    .ok()?;
                Some((slot, p))
            })
            .collect();
        entries.sort_by_key(|(s, _)| *s);
        assert!(entries.len() >= 20, "need the full preprod run");

        let mut eta0: Option<[u8; 32]> = None;
        let blocks = entries
            .iter()
            .map(|(_, p)| {
                let hex = std::fs::read_to_string(p.with_extension("eta0")).unwrap();
                let seen: [u8; 32] = hex::decode(hex.trim()).unwrap().try_into().unwrap();
                match eta0 {
                    Some(e) => assert_eq!(e, seen, "run is one epoch (one eta0)"),
                    None => eta0 = Some(seen),
                }
                // `.block` vectors are stored as hex text.
                hex::decode(std::fs::read_to_string(p).unwrap().trim()).unwrap()
            })
            .collect();
        (blocks, eta0.unwrap())
    }

    /// A set seeded at `blocks[0]`'s parent, holding exactly the outputs the run consumes but does
    /// NOT itself create (`spent \ created`) — the pre-run UTxOs, so every in-window spend resolves.
    fn seed_for(blocks: &[Vec<u8>]) -> UtxoSet {
        let (created, spent) = run_effects(blocks);
        let pre_run: Vec<OutPoint> = spent.difference(&created).copied().collect();
        UtxoSet::from_snapshot(seed_tip_of(blocks), pre_run, 2160)
    }

    #[test]
    fn follows_a_real_preprod_run_advancing_the_set() {
        let (blocks, eta0) = preprod_run();
        let mut set = seed_for(&blocks);

        for b in &blocks {
            let v = HeaderView::from_block_cbor(b).unwrap();
            let tip = apply_block(&mut set, b, &eta0).expect("real block verifies + applies");
            assert_eq!(tip.number, v.block_number, "tip advances to the block");
            assert_eq!(tip.hash, v.block_hash, "tip hash is the block hash");
        }
        // The run created outputs, so the followed set is non-empty at the final tip.
        assert!(set.len().unwrap() > 0);
    }

    /// Collect the run's created + spent outpoint sets (for building honest / broken seeds).
    fn run_effects(blocks: &[Vec<u8>]) -> (BTreeSet<OutPoint>, BTreeSet<OutPoint>) {
        let (mut created, mut spent) = (BTreeSet::new(), BTreeSet::new());
        for b in blocks {
            for tx in &extract_block_effects(b).unwrap().txs {
                created.extend(tx.created.iter().copied());
                spent.extend(tx.spent.iter().copied());
            }
        }
        (created, spent)
    }

    fn seed_tip_of(blocks: &[Vec<u8>]) -> SetTip {
        let v0 = HeaderView::from_block_cbor(&blocks[0]).unwrap();
        SetTip {
            hash: v0.prev_hash.expect("preprod block has a parent"),
            number: v0.block_number - 1,
        }
    }

    /// The discharge-audit-in-miniature (the anchor-basis ruling's forward check): following
    /// `(S, tip]` with `apply_block` IS a subset-consistency audit of the certified set@S. A LYING
    /// ancillary that OMITS a real pre-S outpoint is caught the moment a window block spends it —
    /// the follow fails closed rather than answering against an incomplete set. (My live catch-up
    /// applied 5,383 real blocks with zero such failures: the real ancillary set@S passed.)
    #[test]
    fn an_omitted_pre_s_outpoint_is_caught_by_the_follow() {
        let (blocks, eta0) = preprod_run();
        let (created, spent) = run_effects(&blocks);
        let mut pre_run: Vec<OutPoint> = spent.difference(&created).copied().collect();
        // Drop one pre-S outpoint the run will spend — simulate an ancillary omission.
        let omitted = pre_run.pop().expect("the run spends pre-S outpoints");
        let mut set = UtxoSet::from_snapshot(seed_tip_of(&blocks), pre_run, 2160);

        let mut err = None;
        for b in &blocks {
            if let Err(e) = apply_block(&mut set, b, &eta0) {
                err = Some(e);
                break;
            }
        }
        match err {
            Some(FollowError::Apply(ApplyError::SpendOfUnknownOutput(o))) => assert_eq!(o, omitted),
            other => panic!("expected SpendOfUnknownOutput({omitted:?}), got {other:?}"),
        }
    }

    /// The converse: a PHANTOM the ancillary added — an outpoint claimed present at S but really
    /// created within the window — is caught when the window re-creates it (`DuplicateOutput`). So
    /// the forward audit catches both an incomplete set and a padded one over the window (a full
    /// `StmCertified` discharge additionally needs the genesis→S provenance for a never-re-created
    /// phantom).
    #[test]
    fn a_phantom_outpoint_is_caught_when_the_window_re_creates_it() {
        let (blocks, eta0) = preprod_run();
        let (created, spent) = run_effects(&blocks);
        let mut pre_run: Vec<OutPoint> = spent.difference(&created).copied().collect();
        // A phantom: an outpoint the run CREATES (never in `pre_run`), added as if it existed at S.
        let phantom = *created
            .difference(&spent)
            .next()
            .expect("the run creates outpoints it does not spend");
        pre_run.push(phantom);
        let mut set = UtxoSet::from_snapshot(seed_tip_of(&blocks), pre_run, 2160);

        let mut err = None;
        for b in &blocks {
            if let Err(e) = apply_block(&mut set, b, &eta0) {
                err = Some(e);
                break;
            }
        }
        match err {
            Some(FollowError::Apply(ApplyError::DuplicateOutput(o))) => assert_eq!(o, phantom),
            other => panic!("expected DuplicateOutput({phantom:?}), got {other:?}"),
        }
    }

    #[test]
    fn a_wrong_epoch_nonce_fails_closed_at_the_header() {
        let (blocks, _eta0) = preprod_run();
        let mut set = seed_for(&blocks);
        let before = set.tip().unwrap();
        // A leader-VRF checked against the wrong nonce cannot verify.
        let err = apply_block(&mut set, &blocks[0], &[0u8; 32]).unwrap_err();
        assert!(matches!(err, FollowError::Header(_)));
        assert_eq!(
            set.tip().unwrap(),
            before,
            "the set is untouched on refusal"
        );
    }

    #[test]
    fn a_non_contiguous_block_fails_closed_at_apply() {
        let (blocks, eta0) = preprod_run();
        // Seed at a tip the first block does NOT extend.
        let mut set = UtxoSet::from_snapshot(
            SetTip {
                hash: [9u8; 32],
                number: 42,
            },
            Vec::<OutPoint>::new(),
            2160,
        );
        let err = apply_block(&mut set, &blocks[0], &eta0).unwrap_err();
        assert!(matches!(err, FollowError::Apply(_)));
    }

    #[test]
    fn rollback_restores_the_tip_and_membership() {
        let (blocks, eta0) = preprod_run();
        let mut set = seed_for(&blocks);

        apply_block(&mut set, &blocks[0], &eta0).unwrap();
        let mark = set.tip().unwrap();
        let mark_len = set.len().unwrap();

        apply_block(&mut set, &blocks[1], &eta0).unwrap();
        apply_block(&mut set, &blocks[2], &eta0).unwrap();
        assert_ne!(set.tip().unwrap(), mark);

        set.rollback_to(&mark.hash).unwrap();
        assert_eq!(set.tip().unwrap(), mark, "tip restored to the mark");
        assert_eq!(
            set.len().unwrap(),
            mark_len,
            "membership restored to the mark"
        );
    }
}
