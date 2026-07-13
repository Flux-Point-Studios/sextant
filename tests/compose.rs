//! Tier-2 T-compose: the extract→apply pipeline over real contiguous chain data — the inner
//! loop T3 (certified-state bootstrap, then follow) and T4 (live follow) run at scale.
//!
//! The 22-block preprod segment (the same contiguous run `tests/chain.rs` verifies as a
//! hash-linked chain) is driven through `extract_block_effects` → `UtxoSet`: the set is seeded
//! with exactly the outpoints the segment draws on from before it (its EXTERNAL inputs — spent
//! but not created within the segment), then every block applies in order. This proves the two
//! banked primitives compose over real data: every spend resolves (external-seeded or
//! created-earlier-in-segment, including in-block chains), every surviving output becomes a
//! member, the final set size is exactly `|external| + |created| − |spent|`, and a full
//! rollback restores the seeded base outpoint-for-outpoint.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sextant::effects::extract_block_effects;
use sextant::utxo::OutPoint;
use sextant::utxoset::{BlockEffects, SetTip, UtxoSet};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// Every `preprod-*.block` vector's effects, ordered by block number (the on-chain order). The
/// preprod run is one contiguous segment; the mainnet / indefinite fixtures are named otherwise
/// and excluded.
fn segment_effects() -> Vec<BlockEffects> {
    let mut effects: Vec<BlockEffects> = Vec::new();
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
        let raw =
            hex::decode(fs::read_to_string(&path).expect("read vector").trim()).expect("valid hex");
        effects.push(extract_block_effects(&raw).unwrap_or_else(|e| panic!("{name}: {e:?}")));
    }
    effects.sort_by_key(|e| e.number);
    effects
}

fn union<'a>(effects: impl Iterator<Item = &'a BlockEffects>, spent: bool) -> BTreeSet<OutPoint> {
    effects
        .flat_map(|e| e.txs.iter())
        .flat_map(|t| if spent { &t.spent } else { &t.created })
        .copied()
        .collect()
}

#[test]
fn extract_apply_pipeline_over_the_contiguous_preprod_segment() {
    let effects = segment_effects();
    assert!(
        effects.len() >= 20,
        "expected the ≥20-block preprod segment, got {}",
        effects.len()
    );

    // The segment is contiguous (each block extends the previous by hash + number).
    for pair in effects.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash, "segment hash-links");
        assert_eq!(
            pair[1].number,
            pair[0].number + 1,
            "block numbers are consecutive"
        );
    }

    let created = union(effects.iter(), false);
    let spent = union(effects.iter(), true);
    // Outpoints the segment consumes that it did not itself create — the state it draws on from
    // before block one. Seeding these is exactly what a bootstrapped UTxOSet(S) provides.
    let external: Vec<OutPoint> = spent.difference(&created).copied().collect();
    assert!(
        !external.is_empty(),
        "the segment spends pre-existing outputs"
    );

    let first = &effects[0];
    let base = SetTip {
        number: first.number - 1,
        hash: first.prev_hash,
    };
    let mut set = UtxoSet::from_snapshot(base, external.iter().copied(), 4000);
    assert_eq!(set.len(), external.len());

    // Apply the whole segment in order — every block must succeed: contiguity holds and, because
    // the set is complete from the seed, every consumed outpoint is present (an in-block or
    // in-segment chain resolves as the creating block applies first).
    for e in &effects {
        set.apply(e)
            .unwrap_or_else(|err| panic!("apply block {}: {err:?}", e.number));
    }
    let tip = effects.last().unwrap();
    assert_eq!(
        set.tip(),
        Some(SetTip {
            number: tip.number,
            hash: tip.hash
        })
    );

    // Membership: an output created and not later spent is unspent; every spent outpoint is gone.
    let live: Vec<OutPoint> = created.difference(&spent).copied().collect();
    assert!(
        !live.is_empty(),
        "the segment creates outputs that outlive it"
    );
    for o in &live {
        assert!(
            set.is_unspent(o),
            "a created-and-unspent output must be a member"
        );
    }
    for o in &spent {
        assert!(!set.is_unspent(o), "a spent outpoint must be gone");
    }
    // (external ∪ created) \ spent, and external ∩ created = ∅, so the size is exact.
    assert_eq!(set.len(), external.len() + created.len() - spent.len());

    // A full rollback of the segment restores the seeded base, outpoint-for-outpoint.
    set.rollback_to(&base.hash)
        .expect("rollback to the seeded base");
    assert_eq!(set.tip(), Some(base));
    assert_eq!(set.len(), external.len());
    for o in &external {
        assert!(set.is_unspent(o), "a base outpoint is restored by rollback");
    }
    for o in &live {
        assert!(
            !set.is_unspent(o),
            "a segment-created outpoint is reversed by rollback"
        );
    }
}
