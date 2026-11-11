//! Chunk growth over an extent tree of three levels.

use super::*;
use narf_filesystem::FsInstance;

/// `grow_add_chunk` (the growth every writable mount but `root-rw` uses)
/// repacks the extent and free-space trees whole into the new chunk. It took
/// two levels for granted — leaves plus one root — so with 4 KiB nodes (a
/// node holds about 121 pointers) an extent tree of more leaves than that
/// indexed past the blocks it had set aside and the kernel panicked. Here
/// the 4 KiB-node fixture gets some 7,000 single-page extents, enough for a
/// three-level extent tree, then grows by a chunk; the file must read back
/// and the filesystem go on writing and remount.
fn smoke_btrfs_grow_chunk_over_tall_extent_tree() -> TestResult {
    let dev = writable_sparse(FIXTURE_TALL_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("grow: fixture did not mount"),
    };
    let at = crate::volume::Subvol::Name("@".into());
    if poll_once(vol.switch_to_subvol(&at)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("subvol @ did not resolve");
    }
    for kind in [
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_METADATA,
    ] {
        if !matches!(
            poll_once(crate::write::alloc_chunk(&vol, kind)),
            Some(Ok(()))
        ) {
            return TestResult::Fail("grow: chunk allocation failed");
        }
    }
    let file = match poll_once(vol.root().create("many")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("grow: create failed"),
    };
    const PAGES: usize = 7000;
    let page = |index: usize| -> [u8; 4096] {
        let mut p = [0u8; 4096];
        p.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = (index * 13 + i) as u8);
        p
    };
    // Every other page first, then the rest: no two writes merge.
    for index in (0..PAGES).step_by(2).chain((1..PAGES).step_by(2)) {
        if !matches!(
            poll_once(file.write((index * 4096) as u64, &page(index))),
            Some(Ok(4096))
        ) {
            return TestResult::Fail("grow: write failed");
        }
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("grow: sync failed");
    }
    let Some(Ok(extent_root)) = poll_once(crate::roots::find_root(
        &*vol,
        vol.superblock().root,
        format::EXTENT_TREE_OBJECTID,
    )) else {
        return TestResult::Fail("grow: no extent tree");
    };
    if extent_root.1 < 2 {
        return TestResult::Fail("grow: the extent tree did not reach three levels");
    }
    if !matches!(poll_once(crate::write::grow_add_chunk(&vol)), Some(Ok(()))) {
        return TestResult::Fail("grow: growing by a chunk failed");
    }
    drop(file);
    drop(vol);
    let vol = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("grow: the filesystem did not mount again"),
    };
    if poll_once(vol.switch_to_subvol(&at)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("subvol @ did not resolve again");
    }
    let Some(Ok(file)) = poll_once(vol.root().lookup_async("many")) else {
        return TestResult::Fail("grow: the file is gone");
    };
    let mut got = [0u8; 4096];
    for index in [0, 1, PAGES / 2, PAGES - 1] {
        if !matches!(
            poll_once(file.read((index * 4096) as u64, &mut got)),
            Some(Ok(4096))
        ) || got != page(index)
        {
            return TestResult::Fail("grow: the file did not read back");
        }
    }
    if !matches!(poll_once(vol.root().create("after")), Some(Ok(_)))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("grow: the filesystem stopped writing");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_grow_chunk_over_tall_extent_tree
);
