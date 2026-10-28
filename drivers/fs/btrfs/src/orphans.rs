//! Linux's orphan-inode lifetime: unlink changes names, final eviction frees
//! data. The on-disk record makes the same distinction survive a crash.

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::{btree, format::BtrfsKey, volume::BtrfsVolume};

pub(crate) const ORPHAN_OBJECTID: u64 = (-5i64) as u64;
pub(crate) const ORPHAN_ITEM_KEY: u8 = 48;

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
        let _op = self.op_lock().lock().await;
        let (root, _) = self.fs_tree_root();
        for (key, body) in btree::collect_for(self, root, ORPHAN_OBJECTID, ORPHAN_ITEM_KEY).await? {
            if !body.is_empty() {
                return Err(FsError::InvalidData);
            }
            self.note_orphan(self.fs_tree_id(), key.offset);
        }
        let had_orphans = !self.orphan_snapshot().is_empty();
        self.reap_orphans().await?;
        if had_orphans {
            self.sync_to_disk().await?;
        }
        Ok(())
    }

    /// Caller holds the core's operation mutex. Lookups register their anchor
    /// under that same mutex, closing lookup-versus-final-eviction races.
    pub(crate) async fn reap_orphans(&self) -> Result<(), FsError> {
        for (tree, ino) in self.orphan_snapshot() {
            if self.inode_is_open(tree, ino) {
                continue;
            }
            let view = Self::view_for_tree(self.core(), tree);
            if !view.supports_writes() {
                continue;
            }
            crate::write::reclaim_orphan(&view, ino).await?;
            self.forget_orphan(tree, ino);
        }
        Ok(())
    }
}
