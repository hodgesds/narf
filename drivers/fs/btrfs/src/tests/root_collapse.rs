//! A tree that loses a level: the child promoted to root must be COWed.

use super::*;
use narf_filesystem::FsInstance;

type CollapseVol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

/// Every tree whose root a commit records in a ROOT_ITEM: the item's
/// generation must be the root block's own (Linux reads the root with
/// `check.transid = btrfs_root_generation`, and `verify_parent_transid`
/// fails it otherwise). `Err` names the first tree that disagrees.
fn root_generations_agree(vol: &CollapseVol) -> Result<usize, &'static str> {
    let root_tree = vol.superblock().root;
    let mut checked = 0usize;
    for (tree, name) in [
        (format::EXTENT_TREE_OBJECTID, "extent"),
        (format::CSUM_TREE_OBJECTID, "csum"),
        (format::FREE_SPACE_TREE_OBJECTID, "free-space"),
        (format::FS_TREE_OBJECTID, "fs"),
    ] {
        let key = BtrfsKey::new(tree, format::ROOT_ITEM_KEY, 0);
        let item = match poll_once(btree::find_item(&**vol, root_tree, &key)) {
            Some(Ok(Some(item))) => item,
            Some(Ok(None)) => continue,
            _ => return Err("collapse: a root item did not read"),
        };
        let (Ok(gen), Ok(bytenr)) = (format::le64(&item, 160), format::le64(&item, 176)) else {
            return Err("collapse: a root item is short");
        };
        let Some(Ok(node)) = poll_once(vol.read_node_shared(bytenr)) else {
            return Err("collapse: a root block did not read");
        };
        if format::le64(&node, 80).ok() != Some(gen) {
            let _ = name;
            return Err(match tree {
                format::CSUM_TREE_OBJECTID => {
                    "collapse: the csum tree's root item and root block disagree on the generation"
                }
                format::EXTENT_TREE_OBJECTID => {
                    "collapse: the extent tree's root item and root block disagree on the generation"
                }
                format::FREE_SPACE_TREE_OBJECTID => {
                    "collapse: the free-space tree's root item and root block disagree on the generation"
                }
                _ => "collapse: a subvolume's root item and root block disagree on the generation",
            });
        }
        checked += 1;
    }
    Ok(checked)
}

/// When deletions leave a tree's root with one child, the child becomes the
/// root. A child the transaction had not touched was promoted as it was,
/// with the generation it was written in, while the root item took the
/// transaction's: Linux then fails to read the tree ("parent transid verify
/// failed"), which the `release` scenario showed on the csum tree after a
/// large zero-range. Linux `balance_level` COWs the child before promoting
/// it, in every tree, and so does this now.
///
/// Here two files of 12,000 single-page extents are written a page of each
/// in turn and one is evicted, which leaves the other's checksums in 12,000
/// separate items — a csum tree of three levels on the 4 KiB-node fixture
/// (adjacent extents' checksums share an item); a truncate to the
/// extent whose checksums open the root's second child then removes the
/// rest from the end, a step per commit, so the last commit collapses the
/// root onto its first child, which nothing touched. Each tree's root item
/// and root block must then agree, and the filesystem remount and write.
fn smoke_btrfs_collapsed_root_is_cowed() -> TestResult {
    let dev = writable_sparse(FIXTURE_TALL_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("collapse: fixture did not mount"),
    };
    let at = crate::volume::Subvol::Name("@".into());
    if poll_once(vol.switch_to_subvol(&at)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("subvol @ did not resolve");
    }
    for kind in [
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_METADATA,
    ] {
        if !matches!(
            poll_once(crate::write::alloc_chunk(&vol, kind)),
            Some(Ok(()))
        ) {
            return TestResult::Fail("collapse: chunk allocation failed");
        }
    }
    let (Some(Ok(file)), Some(Ok(spacer))) = (
        poll_once(vol.root().create("tall")),
        poll_once(vol.root().create("spacer")),
    ) else {
        return TestResult::Fail("collapse: create failed");
    };
    const PAGES: usize = 12_000;
    let mut page = [0u8; 4096];
    for index in 0..PAGES {
        page[..8].copy_from_slice(&(index as u64).to_le_bytes());
        for f in [&file, &spacer] {
            if !matches!(
                poll_once(f.write((index * 4096) as u64, &page)),
                Some(Ok(4096))
            ) {
                return TestResult::Fail("collapse: write failed");
            }
        }
    }
    let spacer_ino = spacer.ino();
    drop(spacer);
    // Unlinked with nothing holding it; evicted whole here (an operation
    // takes on only a bounded part of an eviction).
    if !matches!(poll_once(vol.root().unlink("spacer")), Some(Ok(())))
        || !matches!(
            poll_once(crate::write::reclaim_orphan(&vol, spacer_ino)),
            Some(Ok(()))
        )
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("collapse: removing the spacer failed");
    }
    vol.forget_orphan(vol.fs_tree_id(), spacer_ino);
    let root_tree = vol.superblock().root;
    let csum_level = match poll_once(crate::roots::find_root(
        &*vol,
        root_tree,
        format::CSUM_TREE_OBJECTID,
    )) {
        Some(Ok((_, level))) => level,
        _ => return TestResult::Fail("collapse: no csum tree"),
    };
    if csum_level < 2 {
        return TestResult::Fail("collapse: the csum tree did not reach three levels");
    }
    if let Err(e) = root_generations_agree(&vol) {
        return TestResult::Fail(e);
    }
    // Where the csum root's second child starts: the data extent whose
    // checksums it opens. Truncating the file to that extent's offset, a
    // step per commit from the end, empties every child but the first while
    // never touching it, and the last commit collapses the root onto it.
    let (csum_root, _) = match poll_once(crate::roots::find_root(
        &*vol,
        root_tree,
        format::CSUM_TREE_OBJECTID,
    )) {
        Some(Ok(root)) => root,
        _ => return TestResult::Fail("collapse: no csum tree"),
    };
    let Some(Ok(root_node)) = poll_once(vol.read_node_shared(csum_root)) else {
        return TestResult::Fail("collapse: the csum root did not read");
    };
    let Ok(second) = btree::internal_key(&root_node, 1) else {
        return TestResult::Fail("collapse: the csum root has one child");
    };
    let (fs_root, _) = vol.fs_tree_root();
    let ino = file.ino();
    let Some(Ok(items)) = poll_once(crate::write::fileops::file_items(&*vol, fs_root, ino)) else {
        return TestResult::Fail("collapse: the file's items did not read");
    };
    let Some(cut) = items
        .iter()
        .find(|item| format::le64(&item.body, 21).ok() == Some(second.offset))
        .map(|item| item.start)
    else {
        return TestResult::Fail("collapse: no extent opens the second csum subtree");
    };
    crate::write::set_dealloc_step_sync(true);
    let cut_done = poll_once(file.truncate(cut)).is_some_and(|r| r.is_ok());
    crate::write::set_dealloc_step_sync(false);
    if !cut_done || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("collapse: the truncate failed");
    }
    drop(file);
    let root_tree = vol.superblock().root;
    let csum_level_after = match poll_once(crate::roots::find_root(
        &*vol,
        root_tree,
        format::CSUM_TREE_OBJECTID,
    )) {
        Some(Ok((_, level))) => level,
        _ => return TestResult::Fail("collapse: no csum tree after"),
    };
    if csum_level_after >= csum_level {
        return TestResult::Fail("collapse: the csum tree did not lose a level");
    }
    if let Err(e) = root_generations_agree(&vol) {
        return TestResult::Fail(e);
    }
    drop(vol);
    let vol = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("collapse: the filesystem did not mount again"),
    };
    if poll_once(vol.switch_to_subvol(&at)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("subvol @ did not resolve again");
    }
    if let Err(e) = root_generations_agree(&vol) {
        return TestResult::Fail(e);
    }
    if !matches!(poll_once(vol.root().create("later")), Some(Ok(_)))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("collapse: the filesystem stopped writing");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_collapsed_root_is_cowed);
