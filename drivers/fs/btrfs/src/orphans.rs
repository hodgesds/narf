//! Linux's orphan-inode lifetime: unlink changes names, final eviction frees
//! data. The on-disk record makes the same distinction survive a crash.

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::{btree, format::BtrfsKey, volume::BtrfsVolume};

pub(crate) const ORPHAN_OBJECTID: u64 = (-5i64) as u64;
pub(crate) const ORPHAN_ITEM_KEY: u8 = 48;

/// Steps of an orphan's eviction one operation takes on
/// ([`BtrfsVolume::reap_orphans`]): 64 steps of 16 extent items.
const REAP_STEP_BUDGET: usize = 64;

/// Steps of an eviction one join of the transaction takes
/// ([`BtrfsVolume::run_delayed_iputs`]).
const EVICT_STEPS_PER_JOIN: usize = 4;

pub(crate) fn key(ino: u64) -> BtrfsKey {
    BtrfsKey::new(ORPHAN_OBJECTID, ORPHAN_ITEM_KEY, ino)
}

impl<B: BlockDevice + 'static> BtrfsVolume<B> {
    /// Discover persisted orphans when opening a writable subvolume. Live
    /// nodes on other views of this core still pin their inode anchors.
    pub(crate) async fn recover_orphans(&self) -> Result<(), FsError> {
        if !self.admits_writes() {
            return Ok(());
        }
        let _op = self.begin_admin().await?;
        let (root, _) = self.fs_tree_root();
        for (key, body) in btree::collect_for(self, root, ORPHAN_OBJECTID, ORPHAN_ITEM_KEY).await? {
            if !body.is_empty() {
                return Err(FsError::InvalidData);
            }
            self.note_orphan(self.fs_tree_id(), key.offset);
        }
        let had_orphans = !self.orphan_snapshot().is_empty();
        // At mount, evict them whole, as Linux `btrfs_orphan_cleanup` does.
        self.reap_orphans_budget(usize::MAX).await?;
        if had_orphans {
            self.sync_to_disk().await?;
        }
        Ok(())
    }

    /// Caller holds the core's operation mutex. Lookups run without it and
    /// register their anchor against [`Self::claim_for_eviction`], which
    /// closes the lookup-versus-final-eviction race.
    /// The delayed iputs (Linux `btrfs_run_delayed_iputs`): evict every
    /// orphan no handle or mapping holds any more, from outside any
    /// operation — after the unlink that dropped an inode's last link, in
    /// the background reaper, and before a `syncfs`. Each eviction goes a
    /// few steps per join of the running transaction, so commits and other
    /// operations run between its steps; one evicts at a time. An eviction
    /// that fails (out of space, an error) leaves its orphan item for the
    /// next pass or the next mount.
    pub(crate) async fn run_delayed_iputs(&self) {
        let Some(_reaper) = self.try_reaper() else {
            return;
        };
        for (tree, ino) in self.orphan_snapshot() {
            let view = Self::view_for_tree(self.core(), tree);
            if !view.supports_writes() {
                continue;
            }
            // Claimed once for the whole eviction: a claim moves the counter
            // every lookup in flight restarts on (`lookup_child`), so
            // claiming per step would restart them all the way through a
            // large file's eviction. Nothing can open the inode meanwhile —
            // it has no name — but a lookup that resolved the name before
            // the unlink, which the moved counter sends back to the tree.
            if !self.claim_for_eviction(tree, ino) {
                continue;
            }
            loop {
                let step = {
                    let Ok(_joined) = view.begin_data_op().await else {
                        return;
                    };
                    if !view.admits_writes() {
                        return;
                    }
                    crate::write::reclaim_orphan_steps(&view, ino, EVICT_STEPS_PER_JOIN).await
                };
                match step {
                    Ok(true) => {
                        self.forget_orphan(tree, ino);
                        break;
                    }
                    Ok(false) => crate::write::step_break().await,
                    Err(_) => {
                        self.end_eviction(tree, ino);
                        return;
                    }
                }
            }
        }
    }

    pub(crate) async fn reap_orphans(&self) -> Result<(), FsError> {
        self.reap_orphans_budget(REAP_STEP_BUDGET).await
    }

    /// [`Self::reap_orphans`], each orphan's eviction taking at most `budget`
    /// steps that keep its inode: a large file's eviction goes on over the
    /// operations that follow, with other work between, as Linux evicts in
    /// transactions other work runs between.
    pub(crate) async fn reap_orphans_budget(&self, budget: usize) -> Result<(), FsError> {
        // Operations run side by side and each reaps on its way in; one at a
        // time evicts, and the others go on with their own work.
        let Some(_reaper) = self.try_reaper() else {
            return Ok(());
        };
        for (tree, ino) in self.orphan_snapshot() {
            if !self.claim_for_eviction(tree, ino) {
                continue;
            }
            let view = Self::view_for_tree(self.core(), tree);
            if !view.supports_writes() {
                continue;
            }
            let reclaimed = crate::write::reclaim_orphan_steps(&view, ino, budget).await;
            match reclaimed {
                Ok(true) => self.forget_orphan(tree, ino),
                Ok(false) => self.end_eviction(tree, ino),
                Err(error) => {
                    self.end_eviction(tree, ino);
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}
