//! What a small overwrite costs against the number of extent items the
//! file already has.

use super::*;
use narf_filesystem::FsInstance;

const PAGE: usize = 4096;

/// A page of bytes that differ for every `seed`.
fn page(seed: u64) -> [u8; PAGE] {
    let mut x = (seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut out = [0u8; PAGE];
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    out
}

/// What a run of single-page writes cost: fs-tree node visits and nodes read
/// from the device per hundred writes, and microseconds per write.
#[derive(Clone, Copy)]
struct Cost {
    fs_visits_x100: u64,
    device_reads_x100: u64,
    micros: u64,
}

/// Write `pages[..]` of `file`, one `write` per page, and report the cost.
fn write_pages(
    file: &Arc<dyn narf_filesystem::FileOps>,
    pages: impl Iterator<Item = usize>,
    salt: u64,
) -> Option<Cost> {
    let before = crate::stats::totals();
    let started = narf_time::now_cycles();
    let mut writes = 0u64;
    for index in pages {
        let body = page(salt.wrapping_mul(1_000_003).wrapping_add(index as u64));
        if poll_once(file.write((index * PAGE) as u64, &body))?.ok()? != PAGE {
            return None;
        }
        writes += 1;
    }
    let cycles = narf_time::now_cycles().saturating_sub(started);
    let cost = crate::stats::totals().since(&before);
    Some(Cost {
        fs_visits_x100: cost.read.other * 100 / writes,
        device_reads_x100: cost.device_reads * 100 / writes,
        micros: narf_time::wall::cycles_to_ns(cycles / writes) / 1000,
    })
}

/// Overwriting one page costs a lookup of the extent items its range
/// overlaps and a path COW (Linux `btrfs_drop_extents` from a
/// `btrfs_lookup_file_extent` at the range's start), whatever the number of
/// extent items the file has. Measured on a file of 400 single-page extents,
/// on one of 6,000 written in file order (a journal appended in small
/// pieces) and on one of 2,000 written in a scattered order (a sparse mapped
/// file written back page by page), for overwrites in a scattered order and
/// in file order. The file's extent items are checked afterwards: still one
/// per page, each read back with the bytes last written.
///
/// The scattered file is also the one whose walk used to outgrow the node
/// cache (256 nodes in this build, 4,096 in production): its extent items
/// sat a handful to a leaf, every write read all of them, and the cache —
/// emptied whenever it filled — served none of it, so each overwrite read
/// hundreds of nodes from the device.
fn smoke_btrfs_overwrite_cost_tracks_range_not_extent_count() -> TestResult {
    use core::fmt::Write as _;
    const OVERWRITES: usize = 256;
    let vol = match mount_writable(writable_sparse(FIXTURE_TALL_SPARSE)) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("overwrite fixture did not mount"),
    };
    if poll_once(vol.switch_to_subvol(&crate::volume::Subvol::Name("@".into())))
        .is_none_or(|r| r.is_err())
    {
        return TestResult::Fail("subvol @ did not resolve");
    }
    // Room for the 33 MiB of pages (16 MiB chunks on this fixture) and for
    // their items.
    for kind in [
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_DATA,
        format::BLOCK_GROUP_METADATA,
        format::BLOCK_GROUP_METADATA,
        format::BLOCK_GROUP_METADATA,
    ] {
        if !matches!(
            poll_once(crate::write::alloc_chunk(&vol, kind)),
            Some(Ok(()))
        ) {
            return TestResult::Fail("overwrite: chunk allocation failed");
        }
    }
    let dir = match poll_once(vol.root().mkdir("overwrite")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("overwrite: mkdir failed"),
    };
    let mut rows = Vec::new();
    for (salt, pages, stride) in [(1u64, 400usize, 1usize), (2, 6000, 1), (3, 2000, 1237)] {
        let file = match poll_once(dir.create(&alloc::format!("pages-{pages}-{stride}"))) {
            Some(Ok(file)) => file,
            _ => return TestResult::Fail("overwrite: create failed"),
        };
        // One `write` per page: one extent item each. A stride coprime to
        // the page count visits every page once, out of order.
        if write_pages(&file, (0..pages).map(|k| k * stride % pages), salt).is_none() {
            return TestResult::Fail("overwrite: building the file failed");
        }
        if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return TestResult::Fail("overwrite: sync failed");
        }
        // Scattered: a stride coprime to both page counts.
        let scattered = (0..OVERWRITES).map(|k| k * 7919 % pages);
        let Some(random) = write_pages(&file, scattered, salt + 10) else {
            return TestResult::Fail("overwrite: scattered overwrites failed");
        };
        let Some(in_order) = write_pages(&file, 0..OVERWRITES, salt + 20) else {
            return TestResult::Fail("overwrite: in-order rewrite failed");
        };
        if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return TestResult::Fail("overwrite: sync failed");
        }
        // Still one extent item per page, and the last bytes written.
        let (fs_root, _) = vol.fs_tree_root();
        let items = poll_once(btree::collect_for(
            &*vol,
            fs_root,
            file.ino(),
            format::EXTENT_DATA_KEY,
        ));
        if !matches!(&items, Some(Ok(items)) if items.len() == pages) {
            return TestResult::Fail("overwrite: the file is not one extent item per page");
        }
        for index in [0usize, OVERWRITES - 1, OVERWRITES, pages - 1] {
            // Pages below OVERWRITES were last written by the in-order pass;
            // above it, by the scattered pass when the stride reached them.
            let scattered_hit = (0..OVERWRITES).any(|k| k * 7919 % pages == index);
            let want = if index < OVERWRITES {
                page(
                    (salt + 20)
                        .wrapping_mul(1_000_003)
                        .wrapping_add(index as u64),
                )
            } else if scattered_hit {
                page(
                    (salt + 10)
                        .wrapping_mul(1_000_003)
                        .wrapping_add(index as u64),
                )
            } else {
                page(salt.wrapping_mul(1_000_003).wrapping_add(index as u64))
            };
            let mut got = [0u8; PAGE];
            if !matches!(
                poll_once(file.read((index * PAGE) as u64, &mut got)),
                Some(Ok(PAGE))
            ) || got != want
            {
                return TestResult::Fail("overwrite: a page does not read back as written");
            }
        }
        let _ = writeln!(
            narf_console::Writer,
            "btrfs-overwrite: {pages} single-page extents (written with stride {stride}): scattered overwrite visits {}.{:02} \
             fs-tree nodes, reads {}.{:02} from the device, {} us; in-order rewrite visits \
             {}.{:02}, reads {}.{:02}, {} us",
            random.fs_visits_x100 / 100,
            random.fs_visits_x100 % 100,
            random.device_reads_x100 / 100,
            random.device_reads_x100 % 100,
            random.micros,
            in_order.fs_visits_x100 / 100,
            in_order.fs_visits_x100 % 100,
            in_order.device_reads_x100 / 100,
            in_order.device_reads_x100 % 100,
            in_order.micros,
        );
        rows.push((random, in_order));
    }
    // The larger files' extent items span many times the leaves; an
    // overwrite still descends to one of them. Their tree may be a level
    // taller, which each of an overwrite's descents pays once.
    let small = rows[0];
    for large in &rows[1..] {
        for (a, b) in [(small.0, large.0), (small.1, large.1)] {
            if b.fs_visits_x100 > a.fs_visits_x100 * 3 / 2 + 400 {
                return TestResult::Fail(leak_cost(
                    "overwrite: fs-tree visits per overwrite follow the file's extent count",
                    &rows,
                ));
            }
            // A few nodes per overwrite: the path it replaces, when a commit
            // has pushed it out of this build's small cache.
            if b.device_reads_x100 > a.device_reads_x100 + 400 {
                return TestResult::Fail(leak_cost(
                    "overwrite: nodes read from the device per overwrite follow the file's extent count",
                    &rows,
                ));
            }
        }
    }
    TestResult::Pass
}

/// `what`, with the measured rows, as the failure message.
fn leak_cost(what: &str, rows: &[(Cost, Cost)]) -> &'static str {
    use core::fmt::Write as _;
    let mut s = alloc::string::String::from(what);
    for (random, in_order) in rows {
        let _ = write!(
            s,
            " [scattered {} visits/100 writes, {} device reads/100, {} us; in order {} / {} / {} us]",
            random.fs_visits_x100,
            random.device_reads_x100,
            random.micros,
            in_order.fs_visits_x100,
            in_order.device_reads_x100,
            in_order.micros
        );
    }
    alloc::boxed::Box::leak(s.into_boxed_str())
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_overwrite_cost_tracks_range_not_extent_count
);

/// The node cache keeps a node that is still being used across any number
/// of other fills, stays within its bound, and forgets what an invalidation
/// or `forget_node` names from both of its generations.
fn smoke_btrfs_node_cache_keeps_what_is_used() -> TestResult {
    if crate::volume::__test_node_cache_keeps_what_is_used() {
        TestResult::Pass
    } else {
        TestResult::Fail(
            "the node cache dropped a node in use, outgrew its bound or kept a stale node",
        )
    }
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_node_cache_keeps_what_is_used
);

/// The eight-bytes-a-step CRC32C equals the byte-at-a-time definition for
/// every length and alignment around its word size and for whole tree
/// blocks, and matches the standard check value.
fn smoke_btrfs_crc32c_sliced_matches_bytewise() -> TestResult {
    use crate::checksum::{__test_crc32c_bytewise, crc32c};
    // CRC-32C("123456789") = 0xE3069283 (RFC 3720 appendix B.4).
    if !crc32c(!0, b"123456789") != 0xE306_9283 {
        return TestResult::Fail("crc32c: wrong check value");
    }
    let mut data = alloc::vec![0u8; 16384 + 64];
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for b in data.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    for start in 0..9 {
        for len in (0..80).chain([4096 - 32, 4096, 16384 - 32, 16384]) {
            let slice = &data[start..start + len];
            for seed in [0u32, !0, 0x1234_5678] {
                if crc32c(seed, slice) != __test_crc32c_bytewise(seed, slice) {
                    return TestResult::Fail("crc32c: sliced and bytewise results differ");
                }
            }
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_crc32c_sliced_matches_bytewise
);

/// Replacing items by bodies of the same length patches the leaf in place
/// with the same result as re-tiling it; anything that inserts, deletes or
/// resizes an item is left to the re-tiling.
fn smoke_btrfs_patch_leaf_matches_retile() -> TestResult {
    use crate::write::{Edit, __test_patch_leaf, cow_leaf_apply};
    let vol = match mount_writable(writable_sparse(FIXTURE_TALL_SPARSE)) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("patch fixture did not mount"),
    };
    // Any leaf with several items: the leftmost of the root tree.
    let (root_tree, _) = vol.root_tree_root();
    let Some(Ok(cursor)) = poll_once(btree::Cursor::seek(
        &*vol,
        root_tree,
        &BtrfsKey::new(0, 0, 0),
    )) else {
        return TestResult::Fail("patch: root tree unreadable");
    };
    let Ok(Some((items, _))) = cursor.leaf() else {
        return TestResult::Fail("patch: empty root tree");
    };
    if items.len() < 3 {
        return TestResult::Fail("patch: leaf too small");
    }
    // The same items in a leaf of this driver's own packing.
    let nodesize = vol.nodesize();
    let build: Vec<Edit> = items
        .iter()
        .map(|(key, body)| Edit::Upsert(*key, body.clone()))
        .collect();
    let leaf = match cow_leaf_apply(&alloc::vec![0u8; nodesize], &build, nodesize) {
        Ok(mut leaves) if leaves.len() == 1 => leaves.remove(0),
        _ => return TestResult::Fail("patch: could not build the leaf"),
    };
    let flipped = |body: &[u8]| body.iter().map(|b| !b).collect::<Vec<u8>>();
    let (first, last) = (&items[0], &items[items.len() - 1]);
    let same_size = [
        Edit::Upsert(first.0, flipped(&first.1)),
        Edit::Upsert(last.0, flipped(&last.1)),
    ];
    let retiled = match cow_leaf_apply(&leaf, &same_size, nodesize) {
        Ok(mut leaves) if leaves.len() == 1 => leaves.remove(0),
        _ => return TestResult::Fail("patch: re-tiling failed"),
    };
    match __test_patch_leaf(&leaf, &same_size) {
        Ok(Some(patched)) if patched == retiled => {}
        _ => return TestResult::Fail("patch: patched leaf differs from the re-tiled one"),
    }
    let mut longer = first.1.clone();
    longer.push(0);
    let absent = BtrfsKey::new(u64::MAX - 1, 1, 0);
    for edits in [
        alloc::vec![Edit::Upsert(first.0, longer)],
        alloc::vec![Edit::Upsert(absent, alloc::vec![0u8; 4])],
        alloc::vec![Edit::Delete(first.0)],
    ] {
        if !matches!(__test_patch_leaf(&leaf, &edits), Ok(None)) {
            return TestResult::Fail("patch: a resize, insert or delete was patched in place");
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_patch_leaf_matches_retile);
