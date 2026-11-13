//! The commit hand-over (Linux `TRANS_STATE_UNBLOCKED`): a commit's trees are
//! frozen and published before its write-out, and the next transaction opens
//! while the previous one is still being written.

use super::*;

/// A frozen commit's nodes stay in the node cache as dirty entries for its
/// whole write-out ([`crate::volume::__test_node_cache_dirty_entries`]).
fn smoke_btrfs_node_cache_keeps_dirty_nodes() -> TestResult {
    match crate::volume::__test_node_cache_dirty_entries() {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/commit",
    smoke_btrfs_node_cache_keeps_dirty_nodes
);
