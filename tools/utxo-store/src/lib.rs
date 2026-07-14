//! A native, on-disk [`UtxoStore`] backed by redb (Tier-2 T3a).
//!
//! This is the host adapter that lets a `UtxoSet` hold an 11M-entry set on disk WITHOUT any
//! file I/O entering the sextant trust core: the core owns the `UtxoStore` trait and the
//! sans-io engine; this crate owns the redb dependency and the persistence. A native host
//! (the T3 certified-state bootstrap, the daemon) backs a set with
//! `UtxoSet::with_store(RedbUtxoStore::create(path)?, tip, depth)`; the wasm/mobile build never
//! links this and keeps only the in-memory `MemStore`.
//!
//! The key is the deterministic 34-byte outpoint encoding (the commitment-note §5.1 shape):
//! `tx_id` (32 bytes) ‖ big-endian `u16` output index. The value is empty — this is a set,
//! membership only; a leaf-content tier is a later concern. Each mutation is its own committed
//! transaction, so a read-your-writes view holds within a block (an output created earlier in a
//! block is visible to a later spend); batching many blocks per commit is a bootstrap-speed
//! optimisation, not a correctness one, and is left to T3.

use redb::{Database, ReadableTableMetadata, TableDefinition, WriteTransaction};
use sextant::utxo::OutPoint;
use sextant::utxoset::{StoreError, UtxoStore, UtxoTxn};

const UTXO: TableDefinition<&[u8], ()> = TableDefinition::new("utxo");

/// The 34-byte outpoint key: `tx_id` ‖ big-endian `u16` index.
fn key(o: &OutPoint) -> [u8; 34] {
    let mut k = [0u8; 34];
    k[..32].copy_from_slice(&o.tx_id);
    k[32..].copy_from_slice(&o.index.to_be_bytes());
    k
}

fn store_err(e: impl std::fmt::Display) -> StoreError {
    StoreError(e.to_string())
}

/// A redb-backed UTxO membership set.
pub struct RedbUtxoStore {
    db: Database,
}

impl RedbUtxoStore {
    /// Create a FRESH, empty store at `path`, discarding any existing file. redb's own
    /// `Database::create` OPENS an existing database rather than truncating it, so a stale file is
    /// removed first — a bootstrap must not inherit old outpoints. If the file exists but cannot be
    /// removed (a lock, an ACL, a live handle), this fails CLOSED rather than opening and appending
    /// onto the stale set: a `create` that could not guarantee an empty start is an error.
    pub fn create(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        match std::fs::remove_file(path.as_ref()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(store_err(e)),
        }
        let db = Database::create(path).map_err(store_err)?;
        // Materialise the table so later read transactions can open it.
        let txn = db.begin_write().map_err(store_err)?;
        txn.open_table(UTXO).map_err(store_err)?;
        txn.commit().map_err(store_err)?;
        Ok(RedbUtxoStore { db })
    }

    /// Open an existing store at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        let db = Database::open(path).map_err(store_err)?;
        Ok(RedbUtxoStore { db })
    }

    /// Bulk-seed the store from a bootstrap snapshot: one write transaction, one table handle, all
    /// outpoints inserted, committed atomically. This is the T3-load path for the ~millions-entry
    /// certified set — the per-op `open_table` of the [`UtxoTxn`] seam (built for block-sized
    /// batches) would be needless overhead at that scale. Returns the number of NEW outpoints
    /// (duplicates in the source do not inflate it). On any error the whole load aborts — the store
    /// is left exactly as it was.
    pub fn bulk_insert(
        &mut self,
        outpoints: impl IntoIterator<Item = OutPoint>,
    ) -> Result<usize, StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        let mut inserted = 0;
        {
            let mut table = txn.open_table(UTXO).map_err(store_err)?;
            for o in outpoints {
                if table
                    .insert(key(&o).as_slice(), ())
                    .map_err(store_err)?
                    .is_none()
                {
                    inserted += 1;
                }
            }
        }
        txn.commit().map_err(store_err)?;
        Ok(inserted)
    }
}

impl UtxoStore for RedbUtxoStore {
    type Txn<'s> = RedbTxn;

    fn transaction(&mut self) -> Result<RedbTxn, StoreError> {
        Ok(RedbTxn {
            txn: self.db.begin_write().map_err(store_err)?,
        })
    }

    fn contains(&self, o: &OutPoint) -> Result<bool, StoreError> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(UTXO).map_err(store_err)?;
        Ok(table.get(key(o).as_slice()).map_err(store_err)?.is_some())
    }

    fn len(&self) -> Result<usize, StoreError> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(UTXO).map_err(store_err)?;
        Ok(table.len().map_err(store_err)? as usize)
    }
}

/// A redb write transaction. `insert`/`remove` accumulate in the underlying `WriteTransaction`
/// (read-your-writes within it, so an in-block chain resolves); `commit` persists them all
/// atomically, and dropping without commit aborts — redb rolls the whole transaction back.
pub struct RedbTxn {
    txn: WriteTransaction,
}

impl UtxoTxn for RedbTxn {
    fn insert(&mut self, o: &OutPoint) -> Result<bool, StoreError> {
        let mut table = self.txn.open_table(UTXO).map_err(store_err)?;
        Ok(table
            .insert(key(o).as_slice(), ())
            .map_err(store_err)?
            .is_none())
    }

    fn remove(&mut self, o: &OutPoint) -> Result<bool, StoreError> {
        let mut table = self.txn.open_table(UTXO).map_err(store_err)?;
        Ok(table
            .remove(key(o).as_slice())
            .map_err(store_err)?
            .is_some())
    }

    fn commit(self) -> Result<(), StoreError> {
        self.txn.commit().map_err(store_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sextant::utxoset::{BlockEffects, SetTip, TxEffect, UtxoSet};

    fn op(tx: u8, index: u16) -> OutPoint {
        OutPoint {
            tx_id: [tx; 32],
            index,
        }
    }

    fn store() -> (RedbUtxoStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = RedbUtxoStore::create(dir.path().join("utxo.redb")).unwrap();
        (s, dir)
    }

    #[test]
    fn txn_set_semantics_match_the_trait_contract() {
        let (mut s, _dir) = store();
        {
            let mut txn = s.transaction().unwrap();
            assert!(txn.insert(&op(1, 0)).unwrap(), "newly inserted");
            assert!(!txn.insert(&op(1, 0)).unwrap(), "second insert is not new");
            // read-your-writes within the transaction:
            assert!(txn.remove(&op(1, 0)).unwrap(), "was present in-txn");
            assert!(!txn.remove(&op(1, 0)).unwrap(), "already gone in-txn");
            assert!(txn.insert(&op(2, 0)).unwrap());
            txn.commit().unwrap();
        }
        assert!(s.contains(&op(2, 0)).unwrap());
        assert!(!s.contains(&op(1, 0)).unwrap());
        assert_eq!(s.len().unwrap(), 1);
    }

    /// `create` must yield an EMPTY store even when a populated file already exists at the path —
    /// a fresh bootstrap must never inherit a prior snapshot's outpoints.
    #[test]
    fn create_truncates_a_stale_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utxo.redb");
        {
            let mut s = RedbUtxoStore::create(&path).unwrap();
            s.bulk_insert([op(1, 0), op(2, 0)]).unwrap();
            assert_eq!(s.len().unwrap(), 2);
        }
        // Re-create at the same path: the old outpoints must be gone.
        let fresh = RedbUtxoStore::create(&path).unwrap();
        assert_eq!(fresh.len().unwrap(), 0);
        assert!(!fresh.contains(&op(1, 0)).unwrap());
    }

    #[test]
    fn bulk_insert_seeds_a_set_and_backs_a_utxoset() {
        let (mut s, _dir) = store();
        // A duplicate in the source must not inflate the NEW count.
        let inserted = s
            .bulk_insert([op(1, 0), op(1, 1), op(2, 0), op(1, 0)])
            .unwrap();
        assert_eq!(inserted, 3);
        assert_eq!(s.len().unwrap(), 3);
        assert!(s.contains(&op(1, 1)).unwrap());
        assert!(!s.contains(&op(3, 0)).unwrap());

        // The seeded store backs a UtxoSet at the snapshot tip; membership answers hold.
        let tip = SetTip {
            hash: [7u8; 32],
            number: 100,
        };
        let set = UtxoSet::with_store(s, Some(tip), 2160);
        assert!(set.is_unspent(&op(2, 0)).unwrap());
        assert!(!set.is_unspent(&op(9, 0)).unwrap());
        assert_eq!(set.len().unwrap(), 3);
    }

    #[test]
    fn dropping_a_transaction_aborts_it() {
        let (mut s, _dir) = store();
        {
            let mut txn = s.transaction().unwrap();
            txn.insert(&op(9, 9)).unwrap();
            // dropped without commit -> abort, nothing persists
        }
        assert!(
            !s.contains(&op(9, 9)).unwrap(),
            "aborted insert did not persist"
        );
        assert_eq!(s.len().unwrap(), 0);
    }

    /// The redb store drives the SAME sans-io engine as `MemStore`: apply a block, membership
    /// holds, an in-block chain nets absent, and a rollback reverses it exactly — end to end
    /// through `UtxoSet::with_store`.
    #[test]
    fn drives_the_engine_end_to_end() {
        let (s, _dir) = store();
        let mut set = UtxoSet::with_store(s, None, 10);

        set.apply(&BlockEffects {
            number: 1,
            hash: [1; 32],
            prev_hash: [0; 32],
            txs: vec![TxEffect {
                spent: vec![],
                created: vec![op(1, 0), op(1, 1)],
            }],
        })
        .unwrap();
        assert!(set.is_unspent(&op(1, 0)).unwrap());
        assert_eq!(set.len().unwrap(), 2);

        // Block 2: create op(2,0) then spend it in a later tx (in-block chain) + spend op(1,0).
        set.apply(&BlockEffects {
            number: 2,
            hash: [2; 32],
            prev_hash: [1; 32],
            txs: vec![
                TxEffect {
                    spent: vec![op(1, 0)],
                    created: vec![op(2, 0)],
                },
                TxEffect {
                    spent: vec![op(2, 0)],
                    created: vec![op(3, 0)],
                },
            ],
        })
        .unwrap();
        assert!(!set.is_unspent(&op(1, 0)).unwrap(), "spent");
        assert!(
            !set.is_unspent(&op(2, 0)).unwrap(),
            "created-then-spent in one block"
        );
        assert!(set.is_unspent(&op(3, 0)).unwrap());
        assert_eq!(
            set.tip(),
            Some(SetTip {
                number: 2,
                hash: [2; 32]
            })
        );

        // Roll back block 2: op(1,0) returns, op(2,0)/op(3,0) gone.
        set.rollback_to(&[1; 32]).unwrap();
        assert!(set.is_unspent(&op(1, 0)).unwrap());
        assert!(!set.is_unspent(&op(3, 0)).unwrap());
        assert_eq!(set.len().unwrap(), 2);
    }

    #[test]
    fn fail_closed_spend_of_unknown_leaves_the_store_unchanged() {
        let (s, _dir) = store();
        let mut set = UtxoSet::with_store(s, None, 10);
        set.apply(&BlockEffects {
            number: 1,
            hash: [1; 32],
            prev_hash: [0; 32],
            txs: vec![TxEffect {
                spent: vec![],
                created: vec![op(1, 0)],
            }],
        })
        .unwrap();
        // Spend op(1,0) then op(9,9) (never created) -> the whole block reverts on disk.
        let err = set
            .apply(&BlockEffects {
                number: 2,
                hash: [2; 32],
                prev_hash: [1; 32],
                txs: vec![TxEffect {
                    spent: vec![op(1, 0), op(9, 9)],
                    created: vec![op(2, 0)],
                }],
            })
            .unwrap_err();
        assert!(
            matches!(err, sextant::utxoset::ApplyError::SpendOfUnknownOutput(o) if o == op(9, 9))
        );
        assert!(set.is_unspent(&op(1, 0)).unwrap(), "reverted on disk");
        assert!(!set.is_unspent(&op(2, 0)).unwrap());
        assert_eq!(set.len().unwrap(), 1);
    }

    /// Reopening the file recovers the persisted set — durability across process restarts.
    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utxo.redb");
        {
            let mut s = RedbUtxoStore::create(&path).unwrap();
            let mut txn = s.transaction().unwrap();
            txn.insert(&op(7, 3)).unwrap();
            txn.commit().unwrap();
        }
        let s = RedbUtxoStore::open(&path).unwrap();
        assert!(s.contains(&op(7, 3)).unwrap());
        assert_eq!(s.len().unwrap(), 1);
    }
}
