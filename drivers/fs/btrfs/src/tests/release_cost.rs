//! What freeing a file's data reserves against the number of extents the
//! file has.

use super::*;
use narf_filesystem::FsInstance;

const PAGE: usize = 4096;

type ReleaseVol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

/// What one measured operation did: `Err` if it failed, else the chunks it
/// added and the most tree blocks one of its steps reserved for its extents.
type Outcome = Result<(usize, u64), &'static str>;

/// Run `op`, then commit.
fn measure(vol: &ReleaseVol, op: impl FnOnce() -> bool) -> Outcome {
    let chunks = vol.chunk_map_len();
    crate::stats::reset_max_op_reservation();
    if !op() {
        return Err("release: the operation failed");
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("release: sync failed");
    }
    Ok((
        vol.chunk_map_len() - chunks,
        crate::stats::max_op_reservation(),
    ))
}

/// Create `name` with `pages` single-page extents, committed.
fn build_pages(
    vol: &ReleaseVol,
    dir: &Arc<dyn narf_filesystem::DirOps>,
    name: &str,
    pages: usize,
) -> Option<Arc<dyn narf_filesystem::FileOps>> {
    let file = poll_once(dir.create(name))?.ok()?;
    let mut body = [0u8; PAGE];
    for index in 0..pages {
        body.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = (index * 31 + i * 7 + pages) as u8);
        if poll_once(file.write((index * PAGE) as u64, &body))?.ok()? != PAGE {
            return None;
        }
    }
    poll_once(vol.sync_to_disk())?.ok()?;
    Some(file)
}

/// Truncating or unlinking a file drops its extents a bounded number at a
/// time (Linux `btrfs_truncate` / `btrfs_evict_inode` around
/// `btrfs_truncate_inode_items`), so what one step reserves does not depend
/// on the file, the operation succeeds on a small filesystem, and no chunk
/// is allocated for it. Measured on files of 1, 1,000 and 6,000 single-page
/// extents: one is cut to half (to nothing for the one-extent file), another
/// unlinked and reclaimed. Dropping a file's extents in one operation
/// reserved some thirty tree blocks per extent, which for the largest file
/// here is more metadata space than the filesystem has: the operation was
/// refused, METADATA chunks were allocated for it four times over, and it
/// failed with `ENOSPC`.
fn smoke_btrfs_release_reserves_in_steps() -> TestResult {
    use core::fmt::Write as _;
    let vol = match mount_writable(writable_sparse(FIXTURE_TALL_SPARSE)) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("release fixture did not mount"),
    };
    if poll_once(vol.switch_to_subvol(&crate::volume::Subvol::Name("@".into())))
        .is_none_or(|r| r.is_err())
    {
        return TestResult::Fail("subvol @ did not resolve");
    }
    // Room for two 24 MiB files (16 MiB chunks on this fixture) and for
    // their items, allocated before anything is measured.
    for kind in [
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_METADATA,
        format::BLOCK_GROUP_METADATA,
    ] {
        if !matches!(
            poll_once(crate::write::alloc_chunk(&vol, kind)),
            Some(Ok(()))
        ) {
            return TestResult::Fail("release: chunk allocation failed");
        }
    }
    let dir = match poll_once(vol.root().mkdir("release")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("release: mkdir failed"),
    };
    // (pages, truncate, unlink, whether the next operation reclaimed it)
    let mut rows: Vec<(usize, Outcome, Outcome, bool)> = Vec::new();
    for pages in [1usize, 1000, 6000] {
        let (cut_name, gone_name) = (
            alloc::format!("cut-{pages}"),
            alloc::format!("gone-{pages}"),
        );
        let (Some(cut), Some(gone)) = (
            build_pages(&vol, &dir, &cut_name, pages),
            build_pages(&vol, &dir, &gone_name, pages),
        ) else {
            return TestResult::Fail("release: building the files failed");
        };
        let keep = (pages / 2 * PAGE) as u64;
        let truncated = measure(&vol, || {
            matches!(poll_once(cut.truncate(keep)), Some(Ok(())))
        });
        drop(cut);
        // The inode goes with its last reference: the handle, then the
        // name. The next operation reclaims an orphan nothing holds open;
        // one still there after it is reclaimed here, so that its steps are
        // measured either way.
        let ino = gone.ino();
        drop(gone);
        let mut by_next_operation = true;
        let unlinked = measure(&vol, || {
            if !matches!(poll_once(dir.unlink(&gone_name)), Some(Ok(())))
                || !matches!(
                    poll_once(dir.create(&alloc::format!("after-{pages}"))),
                    Some(Ok(_))
                )
            {
                return false;
            }
            let (root, _) = vol.fs_tree_root();
            match poll_once(btree::find_item(&*vol, root, &crate::orphans::key(ino))) {
                Some(Ok(None)) => true,
                Some(Ok(Some(_))) => {
                    by_next_operation = false;
                    let done = matches!(
                        poll_once(crate::write::reclaim_orphan(&vol, ino)),
                        Some(Ok(()))
                    );
                    vol.forget_orphan(vol.fs_tree_id(), ino);
                    done
                }
                _ => false,
            }
        });
        // Nothing of the file is left: no orphan item and no extent under its
        // inode number (which the file created since may have taken).
        let (fs_root, _) = vol.fs_tree_root();
        let orphan = poll_once(btree::find_item(&*vol, fs_root, &crate::orphans::key(ino)));
        let extents = poll_once(btree::collect_for(
            &*vol,
            fs_root,
            ino,
            format::EXTENT_DATA_KEY,
        ));
        if unlinked.is_ok()
            && !(matches!(orphan, Some(Ok(None)))
                && matches!(&extents, Some(Ok(items)) if items.is_empty()))
        {
            return TestResult::Fail("release: the unlinked inode was not reclaimed");
        }
        let _ = writeln!(
            narf_console::Writer,
            "btrfs-release: {pages} single-page extents: truncate to half {truncated:?}, \
             unlink {unlinked:?} (chunks allocated, most tree blocks one step reserved; \
             reclaimed by the next operation: {by_next_operation})"
        );
        rows.push((pages, truncated, unlinked, by_next_operation));
    }
    let report = |what: &str| -> &'static str {
        let mut s = alloc::string::String::from(what);
        for (pages, truncated, unlinked, by_next) in &rows {
            let _ = write!(
                s,
                " [{pages} extents: truncate {truncated:?}, unlink {unlinked:?}, by next op {by_next}]"
            );
        }
        alloc::boxed::Box::leak(s.into_boxed_str())
    };
    // A step's worth of dropped references, with room to spare, at this
    // fixture's tree heights.
    const STEP_RESERVATION_BLOCKS: u64 = 1024;
    for (_, truncated, unlinked, _) in &rows {
        for outcome in [truncated, unlinked] {
            match outcome {
                Err(_) => return TestResult::Fail(report("release: an operation failed")),
                Ok((chunks, _)) if *chunks != 0 => {
                    return TestResult::Fail(report("release: a chunk was allocated"))
                }
                Ok((_, reserved)) if *reserved > STEP_RESERVATION_BLOCKS => {
                    return TestResult::Fail(report(
                        "release: one step reserved more than a step's worth",
                    ))
                }
                Ok(_) => {}
            }
        }
    }
    // 1,000 extents or 6,000: a step reserves the same, but for a level the
    // trees it is priced against may have gained in between.
    let reserved = |outcome: &Outcome| outcome.map_or(0, |(_, reserved)| reserved);
    if reserved(&rows[2].1) > 2 * reserved(&rows[1].1)
        || reserved(&rows[2].2) > 2 * reserved(&rows[1].2)
    {
        return TestResult::Fail(report(
            "release: what a step reserves depends on the size of the file",
        ));
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_release_reserves_in_steps);
