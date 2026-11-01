//! Free-space accounting with the record counts of an installed desktop root.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_btrfs_large_bitmap_free_space_updates() -> TestResult {
    const SS: u64 = 4096;
    const BG_LEN: u64 = 1 << 30;
    const MAP_LEN: u64 = SS * 8 * 256;
    const GROUPS: usize = 597;
    const EXTENT_GROUPS: usize = GROUPS - 5;
    let mut items: Vec<(BtrfsKey, Vec<u8>)> = Vec::new();
    for group in 0..GROUPS {
        let start = (group as u64 + 1) * BG_LEN;
        let bitmap = group >= EXTENT_GROUPS;
        let extents = if bitmap {
            1u32
        } else {
            81 + u32::from(group < 237)
        };
        let mut info = Vec::from(extents.to_le_bytes());
        info.extend_from_slice(&u32::from(bitmap).to_le_bytes());
        items.push((
            BtrfsKey::new(start, format::FREE_SPACE_INFO_KEY, BG_LEN),
            info,
        ));
        if bitmap {
            for map in 0..128 {
                items.push((
                    BtrfsKey::new(
                        start + map * MAP_LEN,
                        format::FREE_SPACE_BITMAP_KEY,
                        MAP_LEN,
                    ),
                    alloc::vec![0xff; 256],
                ));
            }
        } else {
            for extent in 0..extents {
                items.push((
                    BtrfsKey::new(
                        start + u64::from(extent) * SS * 2,
                        format::FREE_SPACE_EXTENT_KEY,
                        SS,
                    ),
                    Vec::new(),
                ));
            }
        }
    }
    items.sort_unstable_by_key(|(key, _)| *key);
    if items.len() != 49_426 {
        return TestResult::Fail("installed-root free-space fixture has the wrong record count");
    }
    let refs: Vec<_> = items
        .iter()
        .map(|(key, body)| (*key, body.as_slice()))
        .collect();
    let capacity = HEADER_SIZE
        + refs.len() * LEAF_ITEM_SIZE
        + items.iter().map(|(_, body)| body.len()).sum::<usize>()
        + 4096;
    let original = pack_leaf(&[0; HEADER_SIZE], &refs, capacity);
    let mut leaf = original.clone();
    let mut dirty_bitmaps = BTreeSet::new();
    for group in EXTENT_GROUPS..GROUPS {
        let start = (group as u64 + 1) * BG_LEN;
        // Each 16 KiB reservation crosses a bitmap-item boundary. These
        // separate holes split the initially single free run into 26 runs.
        for hole in 1..=25 {
            if fst_mark_used(
                &mut leaf,
                SS,
                start,
                BG_LEN,
                start + hole * MAP_LEN - 2 * SS,
                4 * SS,
                &mut dirty_bitmaps,
            )
            .is_err()
            {
                return TestResult::Fail("large-tree bitmap reservation failed");
            }
        }
    }
    if fst_finish_bitmaps(&mut leaf, SS, &dirty_bitmaps).is_err() {
        return TestResult::Fail("large-tree bitmap allocation counts failed");
    }
    dirty_bitmaps.clear();
    for group in EXTENT_GROUPS..GROUPS {
        let start = (group as u64 + 1) * BG_LEN;
        let key = BtrfsKey::new(start, format::FREE_SPACE_INFO_KEY, BG_LEN);
        let count = leaf_find(&leaf, &key).and_then(|slot| {
            let body = leaf_item_data(&leaf, slot.ok_or(FsError::NotFound)?)?;
            format::le32(body, 0)
        });
        if count != Ok(26) {
            return TestResult::Fail("cross-bitmap holes have the wrong free-run count");
        }
    }
    for group in EXTENT_GROUPS..GROUPS {
        let start = (group as u64 + 1) * BG_LEN;
        for hole in (1..=25).rev() {
            if fst_mark_free(
                &mut leaf,
                SS,
                start,
                BG_LEN,
                start + hole * MAP_LEN - 2 * SS,
                4 * SS,
                &mut dirty_bitmaps,
            )
            .is_err()
            {
                return TestResult::Fail("large-tree bitmap release failed");
            }
        }
    }
    if fst_finish_bitmaps(&mut leaf, SS, &dirty_bitmaps).is_err() {
        return TestResult::Fail("large-tree bitmap release counts failed");
    }
    if leaf != original {
        return TestResult::Fail(
            "bitmap round trip changed free-space records or neighbouring groups",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/free_space",
    smoke_btrfs_large_bitmap_free_space_updates
);
