//! The incremental free-space-tree editor ([`free_space::FstEdit`]).

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

type FstItems = BTreeMap<BtrfsKey, Vec<u8>>;

/// Apply an editor's result to `items`, as the path COW would.
fn apply_fst_edits(items: &mut FstItems, edits: Vec<Edit>) {
    for edit in edits {
        match edit {
            Edit::Upsert(key, body) => {
                items.insert(key, body);
            }
            Edit::Delete(key) => {
                items.remove(&key);
            }
        }
    }
}

fn fst_info(extents: u32, bitmaps: bool) -> Vec<u8> {
    let mut info = Vec::from(extents.to_le_bytes());
    info.extend_from_slice(&u32::from(bitmaps).to_le_bytes());
    info
}

fn fst_count(items: &FstItems, start: u64, len: u64) -> Option<u32> {
    let body = items.get(&BtrfsKey::new(start, format::FREE_SPACE_INFO_KEY, len))?;
    format::le32(body, 0).ok()
}

/// Extent-form block groups: carving leaves the right remainders and counts,
/// freeing merges with both neighbours but never across a block-group
/// boundary, and an operation the tree contradicts is refused.
fn smoke_btrfs_fst_edit_extent_groups() -> TestResult {
    const SS: u64 = 4096;
    const BG: u64 = 1 << 20;
    let groups = [(BG, BG), (2 * BG, BG)];
    let extent = |start, len| BtrfsKey::new(start, format::FREE_SPACE_EXTENT_KEY, len);
    let mut items = FstItems::new();
    for &(start, len) in &groups {
        items.insert(
            BtrfsKey::new(start, format::FREE_SPACE_INFO_KEY, len),
            fst_info(1, false),
        );
        items.insert(extent(start, len), Vec::new());
    }
    let mut window = free_space::FstWindow::__test_whole_tree(items.clone());
    let mut edit = window.edit(SS);
    // The last sector of group 0, a middle range, and the first sector of
    // group 1.
    let carved = edit
        .mark_used(groups[0], 2 * BG - SS, SS)
        .and_then(|()| edit.mark_used(groups[0], BG + 16 * SS, 4 * SS))
        .and_then(|()| edit.mark_used(groups[1], 2 * BG, SS));
    if carved.is_err() {
        return TestResult::Fail("fst edit: carving free extents failed");
    }
    // Allocating what is no longer free, and freeing what still is.
    if edit.mark_used(groups[0], BG + 17 * SS, SS).is_ok()
        || edit.mark_free(groups[0], BG + 4 * SS, SS).is_ok()
        || edit.mark_free(groups[0], BG + 15 * SS, 2 * SS).is_ok()
    {
        return TestResult::Fail("fst edit: accepted an operation the tree contradicts");
    }
    let mut after = items.clone();
    apply_fst_edits(&mut after, window.take_edits(edit.into_items()));
    let want: Vec<BtrfsKey> = alloc::vec![
        extent(BG, 16 * SS),
        extent(BG + 20 * SS, BG - 21 * SS),
        extent(2 * BG + SS, BG - SS),
    ];
    let got: Vec<BtrfsKey> = after
        .keys()
        .copied()
        .filter(|k| k.item_type == format::FREE_SPACE_EXTENT_KEY)
        .collect();
    if got != want
        || fst_count(&after, BG, BG) != Some(2)
        || fst_count(&after, 2 * BG, BG) != Some(1)
    {
        return TestResult::Fail("fst edit: wrong extents or counts after carving");
    }
    // Free the last sector of group 0: it joins its left neighbour, not the
    // free extent that starts the next group. Then free the rest.
    let mut window = free_space::FstWindow::__test_whole_tree(after.clone());
    let mut edit = window.edit(SS);
    if edit.mark_free(groups[0], 2 * BG - SS, SS).is_err() {
        return TestResult::Fail("fst edit: freeing at a group boundary failed");
    }
    let mut boundary = after.clone();
    apply_fst_edits(&mut boundary, window.take_edits(edit.into_items()));
    if !boundary.contains_key(&extent(BG + 20 * SS, BG - 20 * SS))
        || !boundary.contains_key(&extent(2 * BG + SS, BG - SS))
        || fst_count(&boundary, BG, BG) != Some(2)
    {
        return TestResult::Fail("fst edit: a free extent merged across a block-group boundary");
    }
    let mut window = free_space::FstWindow::__test_whole_tree(boundary.clone());
    let mut edit = window.edit(SS);
    if edit.mark_free(groups[0], BG + 16 * SS, 4 * SS).is_err()
        || edit.mark_free(groups[1], 2 * BG, SS).is_err()
    {
        return TestResult::Fail("fst edit: freeing failed");
    }
    apply_fst_edits(&mut boundary, window.take_edits(edit.into_items()));
    if boundary != items {
        return TestResult::Fail("fst edit: an alloc/free round trip changed the tree");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/free_space",
    smoke_btrfs_fst_edit_extent_groups
);

/// A new block group arrives as one info item and one free extent, and is
/// allocatable in the same transaction.
fn smoke_btrfs_fst_edit_new_block_group() -> TestResult {
    const SS: u64 = 4096;
    const BG: u64 = 1 << 20;
    let mut items = FstItems::new();
    items.insert(
        BtrfsKey::new(BG, format::FREE_SPACE_INFO_KEY, BG),
        fst_info(0, false),
    );
    let mut window = free_space::FstWindow::__test_whole_tree(items.clone());
    let mut edit = window.edit(SS);
    if edit.add_block_group(2 * BG, BG).is_err()
        || edit.add_block_group(2 * BG, BG).is_ok()
        || edit.mark_used((2 * BG, BG), 2 * BG, 4 * SS).is_err()
    {
        return TestResult::Fail("fst edit: adding a block group failed");
    }
    apply_fst_edits(&mut items, window.take_edits(edit.into_items()));
    if fst_count(&items, 2 * BG, BG) != Some(1)
        || !items.contains_key(&BtrfsKey::new(
            2 * BG + 4 * SS,
            format::FREE_SPACE_EXTENT_KEY,
            BG - 4 * SS,
        ))
        || items.len() != 3
    {
        return TestResult::Fail("fst edit: wrong items for a new block group");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/free_space",
    smoke_btrfs_fst_edit_new_block_group
);

/// The incremental editor against the whole-leaf helpers it replaces in
/// `commit_txn`, over a few hundred random allocations and frees in extent
/// and bitmap block groups: both must produce the same items, and the
/// editor's `extent_count` deltas must equal a recount of the model.
fn smoke_btrfs_fst_edit_matches_whole_leaf_helpers() -> TestResult {
    const SS: u64 = 4096;
    const MAP_LEN: u64 = SS * 8 * 256;
    const BG_LEN: u64 = 4 * MAP_LEN;
    const SECTORS: usize = (BG_LEN / SS) as usize;
    const GROUPS: usize = 4;
    let group = |g: usize| ((g as u64 + 1) * (1 << 30), BG_LEN);
    let bitmap_group = |g: usize| g % 2 == 1;
    let mut items = FstItems::new();
    for g in 0..GROUPS {
        let (start, len) = group(g);
        items.insert(
            BtrfsKey::new(start, format::FREE_SPACE_INFO_KEY, len),
            fst_info(1, bitmap_group(g)),
        );
        if bitmap_group(g) {
            for map in 0..4 {
                items.insert(
                    BtrfsKey::new(
                        start + map * MAP_LEN,
                        format::FREE_SPACE_BITMAP_KEY,
                        MAP_LEN,
                    ),
                    alloc::vec![0xff; 256],
                );
            }
        } else {
            items.insert(
                BtrfsKey::new(start, format::FREE_SPACE_EXTENT_KEY, len),
                Vec::new(),
            );
        }
    }
    let refs: Vec<_> = items.iter().map(|(k, b)| (*k, b.as_slice())).collect();
    let mut leaf = pack_leaf(&[0; HEADER_SIZE], &refs, 1 << 20);
    // The model: one flag per sector, true = allocated.
    let mut used: Vec<Vec<bool>> = alloc::vec![alloc::vec![false; SECTORS]; GROUPS];
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut total_ops = 0usize;
    for _batch in 0..60 {
        // One batch is one commit: its allocations are applied first, then
        // its frees, so neither may touch a sector the other did.
        let mut allocs: Vec<(usize, usize, usize)> = Vec::new();
        let mut frees: Vec<(usize, usize, usize)> = Vec::new();
        for _ in 0..12 {
            let g = (next() % GROUPS as u64) as usize;
            // Cluster around bitmap-item boundaries half the time.
            let at = if next() % 2 == 0 {
                let boundary = (1 + next() % 3) as usize * (MAP_LEN / SS) as usize;
                boundary - 1 - (next() % 6) as usize
            } else {
                (next() % SECTORS as u64) as usize
            };
            let want = 1 + (next() % 40) as usize;
            let overlaps = |ops: &[(usize, usize, usize)], n: usize| {
                ops.iter()
                    .any(|&(og, oat, on)| og == g && oat <= at + n && at <= oat + on)
            };
            let run = |state: bool, used: &[bool]| {
                let mut n = 0;
                while n < want && at + n < SECTORS && used[at + n] == state {
                    n += 1;
                }
                n
            };
            let free_run = run(false, &used[g]);
            if free_run > 0 {
                if !overlaps(&frees, free_run) {
                    used[g][at..at + free_run].fill(true);
                    allocs.push((g, at, free_run));
                }
                continue;
            }
            let used_run = run(true, &used[g]);
            if used_run > 0 && !overlaps(&allocs, used_run) {
                used[g][at..at + used_run].fill(false);
                frees.push((g, at, used_run));
            }
        }
        let range = |&(g, at, n): &(usize, usize, usize)| {
            let (start, len) = group(g);
            ((start, len), start + at as u64 * SS, n as u64 * SS)
        };
        let mut window = free_space::FstWindow::__test_whole_tree(items.clone());
        let mut edit = window.edit(SS);
        let mut dirty = BTreeSet::new();
        for op in &allocs {
            let (bg, start, len) = range(op);
            if edit.mark_used(bg, start, len).is_err()
                || fst_mark_used(&mut leaf, SS, bg.0, bg.1, start, len, &mut dirty).is_err()
            {
                return TestResult::Fail("fst edit: a random allocation failed");
            }
        }
        for op in &frees {
            let (bg, start, len) = range(op);
            if edit.mark_free(bg, start, len).is_err()
                || fst_mark_free(&mut leaf, SS, bg.0, bg.1, start, len, &mut dirty).is_err()
            {
                return TestResult::Fail("fst edit: a random free failed");
            }
        }
        total_ops += allocs.len() + frees.len();
        if fst_finish_bitmaps(&mut leaf, SS, &dirty).is_err() {
            return TestResult::Fail("fst edit: whole-leaf recount failed");
        }
        apply_fst_edits(&mut items, window.take_edits(edit.into_items()));
        let Ok(reference) = leaf_items(&leaf) else {
            return TestResult::Fail("fst edit: reference leaf unreadable");
        };
        let ours: Vec<(BtrfsKey, Vec<u8>)> = items.iter().map(|(k, b)| (*k, b.clone())).collect();
        if ours != reference {
            return TestResult::Fail("fst edit: items differ from the whole-leaf helpers'");
        }
    }
    if total_ops < 300 {
        return TestResult::Fail("fst edit: the random workload was too small");
    }
    // And against the model: runs of free sectors per group.
    for (g, sectors) in used.iter().enumerate() {
        let (start, len) = group(g);
        let mut runs = 0u32;
        let mut prev_free = false;
        for &allocated in sectors.iter() {
            if !allocated && !prev_free {
                runs += 1;
            }
            prev_free = !allocated;
        }
        if fst_count(&items, start, len) != Some(runs) {
            return TestResult::Fail("fst edit: extent_count differs from the model");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/free_space",
    smoke_btrfs_fst_edit_matches_whole_leaf_helpers
);
