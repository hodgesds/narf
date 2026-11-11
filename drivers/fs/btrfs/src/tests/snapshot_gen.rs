//! A snapshot's ROOT_ITEM against the root block it names.

use super::*;
use narf_filesystem::FsInstance;

/// Right after a snapshot is created and committed, every subvolume's
/// ROOT_ITEM generation must equal its root block's header generation:
/// Linux reads a subvolume's root with `check.transid` set to that
/// generation and refuses it otherwise (Linux `create_pending_snapshot`
/// copies the source root into a new block of the transaction with
/// `btrfs_copy_root`, so the two agree). A read-only snapshot is never
/// written again, so a disagreement stays.
fn smoke_btrfs_snapshot_root_generation_matches() -> TestResult {
    let vol = match mount_writable(writable_sparse(FIXTURE_TALL_SPARSE)) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("snapgen: fixture did not mount"),
    };
    let at = crate::volume::Subvol::Name("@".into());
    if poll_once(vol.switch_to_subvol(&at)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("subvol @ did not resolve");
    }
    let root = vol.root();
    if !matches!(poll_once(root.create("before")), Some(Ok(_)))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("snapgen: setup failed");
    }
    if !matches!(
        poll_once(root.snapshot_async(root.clone(), "ro-snap", true)),
        Some(Ok(()))
    ) || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("snapgen: snapshot failed");
    }
    let root_tree = vol.superblock().root;
    let first = BtrfsKey::new(format::FIRST_FREE_OBJECTID, format::ROOT_ITEM_KEY, 0);
    let Some(Ok(mut cursor)) = poll_once(btree::Cursor::seek(&*vol, root_tree, &first)) else {
        return TestResult::Fail("snapgen: root tree did not read");
    };
    let mut checked = 0usize;
    loop {
        let (key, body) = match cursor.current() {
            Ok(Some((key, body))) => (key, body.to_vec()),
            Ok(None) => break,
            Err(_) => return TestResult::Fail("snapgen: root tree did not read"),
        };
        if key.item_type == format::ROOT_ITEM_KEY && key.objectid >= format::FIRST_FREE_OBJECTID {
            let (Ok(gen), Ok(bytenr)) = (format::le64(&body, 160), format::le64(&body, 176)) else {
                return TestResult::Fail("snapgen: a root item is short");
            };
            let Some(Ok(node)) = poll_once(vol.read_node_shared(bytenr)) else {
                return TestResult::Fail("snapgen: a subvolume root did not read");
            };
            if format::le64(&node, 80).ok() != Some(gen) {
                return TestResult::Fail(
                    "snapgen: a subvolume's root item and root block disagree on the generation",
                );
            }
            checked += 1;
        }
        if poll_once(cursor.advance()).is_none_or(|r| r.is_err()) {
            return TestResult::Fail("snapgen: root tree did not read");
        }
    }
    if checked < 2 {
        return TestResult::Fail("snapgen: the snapshot's root item was not found");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_snapshot_root_generation_matches
);
