//! What a commit costs against the size of the free-space tree.

use super::*;
use narf_filesystem::FsInstance;

type ScaleVol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

/// `(blocks, root level, free extents)` of the committed free-space tree.
fn fst_shape(vol: &ScaleVol) -> Option<(usize, u8, usize)> {
    let (root_tree, _) = vol.root_tree_root();
    let (fst_root, level) = poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::FREE_SPACE_TREE_OBJECTID,
    ))?
    .ok()?;
    let blocks = poll_once(crate::write::tree_blocks(vol, fst_root))?
        .ok()?
        .len();
    let mut cursor =
        poll_once(btree::Cursor::seek(vol, fst_root, &BtrfsKey::new(0, 0, 0)))?.ok()?;
    let mut extents = 0usize;
    while let Some((key, _)) = cursor.current().ok()? {
        if key.item_type == format::FREE_SPACE_EXTENT_KEY {
            extents += 1;
        }
        poll_once(cursor.advance())?.ok()?;
    }
    Some((blocks, level, extents))
}

/// Block groups holding at least one free extent that is not the group's
/// only one (i.e. fragmented groups).
fn fragmented_groups(vol: &ScaleVol) -> Option<usize> {
    let (root_tree, _) = vol.root_tree_root();
    let (fst_root, _) = poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::FREE_SPACE_TREE_OBJECTID,
    ))?
    .ok()?;
    let mut cursor =
        poll_once(btree::Cursor::seek(vol, fst_root, &BtrfsKey::new(0, 0, 0)))?.ok()?;
    let mut groups = 0usize;
    while let Some((key, body)) = cursor.current().ok()? {
        if key.item_type == format::FREE_SPACE_INFO_KEY
            && body.len() >= 4
            && format::le32(body, 0).ok()? > 8
        {
            groups += 1;
        }
        poll_once(cursor.advance())?.ok()?;
    }
    Some(groups)
}

/// Create one 4 KiB file and commit it, returning what that commit cost:
/// this filesystem's counters, and the node visits and writes per tree.
fn probe_commit(
    vol: &ScaleVol,
    dir: &Arc<dyn narf_filesystem::DirOps>,
    name: &str,
) -> Option<(crate::stats::CommitStatsSnapshot, crate::stats::Totals)> {
    poll_once(vol.sync_to_disk())?.ok()?;
    let before = vol.commit_stats().snapshot();
    let trees_before = crate::stats::totals();
    let file = poll_once(dir.create(name))?.ok()?;
    let written = poll_once(file.write(0, &[0x5a; 4096]))?.ok()?;
    if written != 4096 {
        return None;
    }
    poll_once(vol.sync_to_disk())?.ok()?;
    Some((
        vol.commit_stats().snapshot().since(&before),
        crate::stats::totals().since(&trees_before),
    ))
}

/// Add `count` 4 KiB preallocated files named `{prefix}{i}` and then remove
/// every other one, leaving `count / 2` single-sector holes in the data
/// block groups (one `FREE_SPACE_EXTENT` each).
fn fragment(
    dir: &Arc<dyn narf_filesystem::DirOps>,
    prefix: &str,
    count: usize,
) -> Result<(), &'static str> {
    for i in 0..count {
        let file = match poll_once(dir.create(&alloc::format!("{prefix}{i}"))) {
            Some(Ok(file)) => file,
            _ => return Err("scale: create failed"),
        };
        if !matches!(poll_once(file.fallocate(0, 0, 4096)), Some(Ok(()))) {
            return Err("scale: fallocate failed");
        }
    }
    for i in (0..count).step_by(2) {
        if !matches!(
            poll_once(dir.unlink(&alloc::format!("{prefix}{i}"))),
            Some(Ok(()))
        ) {
            return Err("scale: unlink failed");
        }
    }
    Ok(())
}

/// A commit's free-space-tree and block-group work must follow what the
/// transaction changed, not how large the trees are or how many passes the
/// commit takes: the same one-small-file commit is measured on a filesystem
/// whose free-space tree is a few blocks, and again after the tree has been
/// fragmented across several block groups into a multi-level tree many
/// times that size.
fn smoke_btrfs_commit_cost_tracks_change_not_tree_size() -> TestResult {
    use core::fmt::Write as _;
    const STEP: usize = 3000;
    let vol = match mount_writable(writable_sparse(FIXTURE_TALL_SPARSE)) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("scale fixture did not mount"),
    };
    if poll_once(vol.switch_to_subvol(&crate::volume::Subvol::Name("@".into())))
        .is_none_or(|r| r.is_err())
    {
        return TestResult::Fail("subvol @ did not resolve");
    }
    // Several data block groups, so the fragmentation below spreads over
    // more than one, and metadata room for the files that make it.
    for kind in [
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
            return TestResult::Fail("scale: chunk allocation failed");
        }
    }
    let dir = match poll_once(vol.root().mkdir("scale")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("scale: mkdir failed"),
    };
    let mut rows = Vec::new();
    for step in 0..4usize {
        if step > 0 {
            if let Err(why) = fragment(&dir, &alloc::format!("s{step}-"), STEP * step) {
                return TestResult::Fail(why);
            }
        }
        // The audit re-reads the whole tree after each commit; it is not
        // part of what a commit costs.
        crate::allocator::set_view_audit(false);
        let cost = probe_commit(&vol, &dir, &alloc::format!("probe{step}"));
        crate::allocator::set_view_audit(true);
        let Some((cost, trees)) = cost else {
            return TestResult::Fail("scale: probe commit failed");
        };
        let Some(shape) = fst_shape(&vol) else {
            return TestResult::Fail("scale: free-space tree unreadable");
        };
        let _ = writeln!(
            narf_console::Writer,
            "btrfs-scale: fst {} blocks level {} ({} free extents, {} fragmented groups): \
             small commit read {} fst nodes, wrote {} fst / {} metadata nodes, {} commit(s), \
             {} pass(es), {} allocator build(s) ({} from disk, {} us); visited extent {} \
             block-group {} csum {} root {} nodes",
            shape.0,
            shape.1,
            shape.2,
            fragmented_groups(&vol).unwrap_or(0),
            cost.fst_nodes_read,
            cost.fst_nodes_written,
            cost.meta_nodes_written,
            cost.commits,
            cost.rounds,
            cost.alloc_builds,
            cost.alloc_disk_builds,
            narf_time::wall::cycles_to_ns(cost.alloc_build_cycles) / 1000,
            trees.read.extent,
            trees.read.block_group,
            trees.read.csum,
            trees.read.root,
        );
        rows.push((shape, cost, trees));
    }
    let (small, large) = (&rows[0], &rows[rows.len() - 1]);
    if large.0 .1 == 0 || large.0 .0 < small.0 .0 * 8 {
        return TestResult::Fail("scale: the free-space tree did not grow multi-level");
    }
    if fragmented_groups(&vol).unwrap_or(0) < 3 {
        return TestResult::Fail("scale: fragmentation did not spread over block groups");
    }
    for (shape, cost, trees) in &rows {
        // Height x touched leaves: the new data extent, the new metadata
        // blocks and the freed ones land in a handful of leaves, each
        // rewritten with its ancestors once.
        let height = u64::from(shape.1) + 1;
        if cost.commits != 1 {
            return TestResult::Fail("scale: the probe did not commit exactly once");
        }
        if cost.fst_nodes_written > 8 * height {
            return TestResult::Fail(
                "scale: free-space-tree writes exceed height x touched leaves",
            );
        }
        if cost.alloc_disk_builds != 0 {
            return TestResult::Fail("scale: an allocator re-read the free-space tree");
        }
        // Reads are node visits (every descent counts its whole path). A
        // touched leaf is fetched once (one descent, and another when the
        // item before the range lives in the previous leaf) and path-COWed
        // once (one descent, and its right sibling for the density check) —
        // however many passes the commit takes to record its own blocks:
        // after the first, the leaf is the commit's own and is edited in
        // place, not read back. (When every pass recomputed the tree from
        // the committed one, this was 68 to 133 reads for the same commits.)
        if cost.fst_nodes_read > (3 * height + 1) * cost.fst_nodes_written + 4 {
            return TestResult::Fail("scale: free-space-tree reads exceed height x touched leaves");
        }
        // The commit allocates from and frees into two or three block
        // groups, and looks up and rewrites only those: not one read per
        // block group of the filesystem, twice.
        if trees.read.block_group > 12 {
            return TestResult::Fail("scale: block-group reads follow the number of groups");
        }
        // Each pass records the blocks the previous one allocated and
        // replaced, so their number is the depth of that chain, a few; far
        // from the guard that fails a commit.
        if cost.rounds > 16 {
            return TestResult::Fail("scale: recording the commit's blocks took many passes");
        }
    }
    // The tree more than doubled between the first fragmented state and
    // the last; the commit's share of it must not have followed.
    let (mid, large) = (&rows[1], &rows[rows.len() - 1]);
    if large.0 .0 < mid.0 .0 * 2 {
        return TestResult::Fail("scale: the free-space tree did not keep growing");
    }
    if large.1.fst_nodes_written > mid.1.fst_nodes_written + 6 {
        return TestResult::Fail("scale: free-space-tree writes grew with the tree");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_commit_cost_tracks_change_not_tree_size
);
