//! Write-safety regressions found reviewing the writer before it is let loose
//! on a real CachyOS root: shared tree blocks, torn superblocks, reused blocks
//! under lock-free readers, ungated admin writers, chunk growth on a
//! production root, logical-leaf headroom, test-workload targeting, unmount
//! durability and the superblock backup roots.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::{FsError, FsInstance};
use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    mount_recording, mount_writable, poll_once, read_all, read_super_at, recording,
    writable_sparse, DevOp, WritableSparseDevice, FIXTURE_BGT_SPARSE, FIXTURE_MANYFILES_SPARSE,
    FIXTURE_MIRROR_SPARSE,
};
use crate::btree::{self, internal_blockptr, internal_child_slot, level, nritems};
use crate::format::{self, le64, BtrfsKey};
use crate::volume::BtrfsVolume;

type Vol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

// ── Helpers ─────────────────────────────────────────────────────────

/// The address of the leaf of tree `root` that holds (or would hold) `key`.
fn leaf_holding(vol: &Vol, root: u64, key: &BtrfsKey) -> Option<u64> {
    let mut addr = root;
    loop {
        let node = poll_once(vol.read_node(addr))?.ok()?;
        if level(&node).ok()? == 0 {
            return Some(addr);
        }
        let n = nritems(&node).ok()? as usize;
        let slot = internal_child_slot(&node, n, key).ok()?;
        addr = internal_blockptr(&node, slot).ok()?;
    }
}

/// Rewrite, in place and behind the writer's back, the body of item `key` in
/// tree `root` with `edit`, restamping the leaf: the on-disk state another
/// kernel (a snapshot, a relocation) would have left.
fn poke_item(vol: &Vol, root: u64, key: &BtrfsKey, edit: impl FnOnce(&mut [u8])) -> bool {
    let Some(addr) = leaf_holding(vol, root, key) else {
        return false;
    };
    let Some(Ok(mut leaf)) = poll_once(vol.read_node(addr)) else {
        return false;
    };
    let n = nritems(&leaf).unwrap_or(0) as usize;
    let Some(slot) = (0..n).find(|&i| btree::leaf_item_key(&leaf, i).ok() == Some(*key)) else {
        return false;
    };
    let Ok((off, size)) = btree::leaf_item_span(&leaf, slot) else {
        return false;
    };
    let start = btree::HEADER_SIZE + off;
    edit(&mut leaf[start..start + size]);
    let gen = le64(&leaf, 80).unwrap_or(0);
    if crate::write::stamp_node(&mut leaf, addr, gen, vol.csum_type()).is_err() {
        return false;
    }
    matches!(poll_once(vol.write_node(addr, &leaf)), Some(Ok(())))
}

fn extent_root(vol: &Vol) -> u64 {
    let (root_tree, _) = vol.root_tree_root();
    poll_once(crate::roots::find_root(
        &**vol,
        root_tree,
        format::EXTENT_TREE_OBJECTID,
    ))
    .and_then(Result::ok)
    .map(|(r, _)| r)
    .unwrap_or(0)
}

/// The first child of the (multi-level) mounted fs tree — the block on the
/// path to the root directory's own items.
fn first_fs_child(vol: &Vol) -> Option<(u64, u8)> {
    let (root, lvl) = vol.fs_tree_root();
    if lvl == 0 {
        return None;
    }
    let node = poll_once(vol.read_node(root))?.ok()?;
    Some((internal_blockptr(&node, 0).ok()?, lvl - 1))
}

fn super_generation(dev: &WritableSparseDevice) -> u64 {
    le64(&read_super_at(dev, format::SUPERBLOCK_OFFSET), 72).unwrap_or(0)
}

// ── Finding 1(a): never free a block anything else references ───────

/// Pure: what may be freed outright.
fn smoke_btrfs_freeable_tree_block_rules() -> TestResult {
    use crate::write::check_freeable_tree_block as check;
    let mut header = alloc::vec![0u8; btree::HEADER_SIZE];
    header[56..64].copy_from_slice(&(1u64 << 56).to_le_bytes()); // mixed backref rev
    header[88..96].copy_from_slice(&5u64.to_le_bytes());
    let item = |refs: u64, flags: u64, refs_bytes: &[u8]| {
        let mut v = alloc::vec![0u8; 24];
        v[0..8].copy_from_slice(&refs.to_le_bytes());
        v[16..24].copy_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(refs_bytes);
        v
    };
    let tree_ref = |root: u64| {
        let mut r = alloc::vec![176u8];
        r.extend_from_slice(&root.to_le_bytes());
        r
    };
    let shared_ref = |parent: u64| {
        let mut r = alloc::vec![182u8];
        r.extend_from_slice(&parent.to_le_bytes());
        r
    };
    if check(&item(1, 2, &tree_ref(5)), false, &header, false).is_err() {
        return TestResult::Fail("an exclusive tree block was refused");
    }
    let mut two = tree_ref(5);
    two.extend_from_slice(&tree_ref(257));
    if check(&item(2, 2, &two), false, &header, false).is_ok() {
        return TestResult::Fail("a block referenced twice was freeable");
    }
    if check(&item(1, 2 | (1 << 8), &tree_ref(5)), false, &header, false).is_ok() {
        return TestResult::Fail("a FULL_BACKREF block was freeable");
    }
    if check(&item(1, 2 | (1 << 8), &tree_ref(5)), false, &header, true).is_err() {
        return TestResult::Fail("a FULL_BACKREF block whose children moved was refused");
    }
    if check(&item(1, 2, &shared_ref(4096)), false, &header, false).is_ok() {
        return TestResult::Fail("a block held by a SHARED_BLOCK_REF was freeable");
    }
    if check(&item(1, 2, &[]), false, &header, false).is_ok() {
        return TestResult::Fail("a block with only keyed refs was freeable");
    }
    let mut reloc = header.clone();
    reloc[56..64].copy_from_slice(&((1u64 << 56) | 2).to_le_bytes());
    if check(&item(1, 2, &tree_ref(5)), false, &reloc, false).is_ok() {
        return TestResult::Fail("a relocation-written block was freeable");
    }
    let mut old_rev = header.clone();
    old_rev[56..64].copy_from_slice(&0u64.to_le_bytes());
    if check(&item(1, 2, &tree_ref(5)), false, &old_rev, false).is_ok() {
        return TestResult::Fail("an old-backref-revision block was freeable");
    }
    let mut fat = item(1, 2, &[0u8; 18]);
    fat.extend_from_slice(&tree_ref(5));
    if check(&fat, true, &header, false).is_err() {
        return TestResult::Fail("a non-skinny exclusive tree block was refused");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_freeable_tree_block_rules);

/// Mark the root tree's root block as shared (refs 2, as if another tree
/// referenced it) or `FULL_BACKREF` in the extent tree, then commit. The root
/// tree is not reference counted, so its COW frees the block outright — the
/// path the pre-write audit guards. The commit must abort read-only with
/// nothing written: the superblock keeps its generation and the block's
/// extent item survives. (Subvolume trees take the snapshot-aware COW
/// instead; see `tests/snapshots.rs`.)
fn shared_block_aborts(set_full_backref: bool) -> TestResult {
    let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("manyfiles fixture did not mount writable"),
    };
    let (target, target_level) = vol.root_tree_root();
    let ext = extent_root(&vol);
    let key = BtrfsKey::new(target, format::METADATA_ITEM_KEY, u64::from(target_level));
    let poked = poke_item(&vol, ext, &key, |body| {
        if set_full_backref {
            let flags = u64::from_le_bytes(body[16..24].try_into().unwrap()) | (1 << 8);
            body[16..24].copy_from_slice(&flags.to_le_bytes());
        } else {
            body[0..8].copy_from_slice(&2u64.to_le_bytes());
        }
    });
    if !poked {
        return TestResult::Fail("could not mark the root-tree block shared");
    }
    let gen_before = super_generation(&dev);
    let root = vol.root();
    let created = poll_once(root.create("after-snapshot.txt"));
    let synced = poll_once(vol.sync_to_disk());
    let committed = matches!(created, Some(Ok(_))) && matches!(synced, Some(Ok(())));
    if committed {
        return TestResult::Fail("a commit freed a block another tree references");
    }
    if !vol.transaction_aborted() || vol.supports_writes() {
        return TestResult::Fail("the refused commit did not abort the transaction read-only");
    }
    if super_generation(&dev) != gen_before {
        return TestResult::Fail("the aborted commit still wrote a superblock");
    }
    match poll_once(btree::find_item(&*vol, ext, &key)) {
        Some(Ok(Some(_))) => {}
        _ => return TestResult::Fail("the shared block's extent item was deleted"),
    }
    TestResult::Pass
}

fn smoke_btrfs_shared_tree_block_aborts_commit() -> TestResult {
    shared_block_aborts(false)
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_shared_tree_block_aborts_commit
);

fn smoke_btrfs_full_backref_block_aborts_commit() -> TestResult {
    shared_block_aborts(true)
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_full_backref_block_aborts_commit
);

// ── Finding 1(b), gate: refuse rw while anything may be shared ──────

/// Pure: root items.
fn smoke_btrfs_rw_gate_root_item_rules() -> TestResult {
    use crate::rw_gate::{check_root_item, Refusal};
    let mut item = alloc::vec![0u8; 439];
    item[216..220].copy_from_slice(&1u32.to_le_bytes());
    if check_root_item(256, &item).is_err() {
        return TestResult::Fail("a plain subvolume root item was refused");
    }
    let mut snapped = item.clone();
    snapped[200..208].copy_from_slice(&42u64.to_le_bytes());
    if crate::rw_gate::WRITER_HANDLES_SHARED_TREES {
        if check_root_item(256, &snapped).is_err() {
            return TestResult::Fail("a snapshotted subvolume was refused");
        }
    } else if !matches!(
        check_root_item(256, &snapped),
        Err(Refusal::Snapshotted {
            root: 256,
            last_snapshot: 42
        })
    ) {
        return TestResult::Fail("a snapshotted subvolume was not refused");
    }
    let mut dead = item.clone();
    dead[216..220].copy_from_slice(&0u32.to_le_bytes());
    if !matches!(check_root_item(257, &dead), Err(Refusal::DeadRoot(257))) {
        return TestResult::Fail("a refs==0 root item was not refused");
    }
    let mut dropping = item.clone();
    dropping[220..228].copy_from_slice(&300u64.to_le_bytes());
    if !matches!(check_root_item(258, &dropping), Err(Refusal::DeadRoot(258))) {
        return TestResult::Fail("a half-dropped root item was not refused");
    }
    // Non-subvolume trees never carry snapshots.
    if check_root_item(format::EXTENT_TREE_OBJECTID, &snapped).is_err() {
        return TestResult::Fail("a non-subvolume root item was judged");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rw_gate_root_item_rules);

/// Pure: tree-block extent items.
fn smoke_btrfs_rw_gate_tree_block_rules() -> TestResult {
    use crate::rw_gate::check_tree_block_item as check;
    if crate::rw_gate::WRITER_HANDLES_SHARED_TREES {
        return TestResult::Pass;
    }
    let tree_ref = |root: u64| {
        let mut r = alloc::vec![176u8];
        r.extend_from_slice(&root.to_le_bytes());
        r
    };
    if check(4096, 1, 2, &tree_ref(5), 0).is_err() {
        return TestResult::Fail("an exclusive block was refused");
    }
    let mut two = tree_ref(5);
    two.extend_from_slice(&tree_ref(257));
    if check(4096, 2, 2, &two, 0).is_ok() {
        return TestResult::Fail("a block shared below a subvolume root was accepted");
    }
    if check(4096, 2, 2, &two, 2).is_err() {
        return TestResult::Fail("NARF's shared subvolume root block was refused");
    }
    if check(4096, 1, 2 | (1 << 8), &tree_ref(5), 0).is_ok() {
        return TestResult::Fail("a FULL_BACKREF block was accepted");
    }
    let mut shared = alloc::vec![182u8];
    shared.extend_from_slice(&8192u64.to_le_bytes());
    if check(4096, 1, 2, &shared, 0).is_ok() {
        return TestResult::Fail("a shared-block backref was accepted");
    }
    if check(4096, 2, 2, &tree_ref(5), 1).is_ok() {
        return TestResult::Fail("a keyed backref was accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rw_gate_tree_block_rules);

/// The gate on real images: a fs-tree block marked shared, or a subvolume
/// marked snapshotted, is refused read-write at mount (and the refusal is
/// named); the unmodified image is accepted.
fn smoke_btrfs_rw_gate_refuses_shared_images() -> TestResult {
    if crate::rw_gate::WRITER_HANDLES_SHARED_TREES {
        // Sharing is handled; a subvolume Linux is still dropping is not.
        let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
        {
            let vol = match mount_writable(dev.clone()) {
                Ok(v) if v.supports_writes() => v,
                _ => return TestResult::Fail("pristine manyfiles fixture was refused"),
            };
            let (root_tree, _) = vol.root_tree_root();
            let key = BtrfsKey::new(format::FS_TREE_OBJECTID, format::ROOT_ITEM_KEY, 0);
            if !poke_item(&vol, root_tree, &key, |body| {
                body[220..228].copy_from_slice(&300u64.to_le_bytes())
            }) {
                return TestResult::Fail("could not mark FS_TREE half-dropped");
            }
        }
        return match mount_writable(dev) {
            Ok(v) if !v.supports_writes() => match v.rw_refusal() {
                Some(crate::rw_gate::Refusal::DeadRoot(5)) => TestResult::Pass,
                _ => TestResult::Fail("half-dropped subvolume refused for the wrong reason"),
            },
            Ok(_) => TestResult::Fail("an image with a half-dropped subvolume mounted writable"),
            Err(_) => TestResult::Fail("the half-dropped image did not mount at all"),
        };
    }
    // Shared interior block.
    let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
    {
        let vol = match mount_writable(dev.clone()) {
            Ok(v) if v.supports_writes() => v,
            _ => return TestResult::Fail("pristine manyfiles fixture was refused"),
        };
        let Some((child, child_level)) = first_fs_child(&vol) else {
            return TestResult::Fail("manyfiles fs tree is a single leaf");
        };
        let ext = extent_root(&vol);
        let key = BtrfsKey::new(child, format::METADATA_ITEM_KEY, u64::from(child_level));
        if !poke_item(&vol, ext, &key, |body| {
            body[0..8].copy_from_slice(&2u64.to_le_bytes())
        }) {
            return TestResult::Fail("could not mark the block shared");
        }
    }
    match mount_writable(dev) {
        Ok(v) if !v.supports_writes() => {
            if !matches!(
                v.rw_refusal(),
                Some(crate::rw_gate::Refusal::SharedTreeBlock { .. })
            ) {
                return TestResult::Fail("shared block refused for the wrong reason");
            }
        }
        Ok(_) => return TestResult::Fail("an image with a shared tree block mounted writable"),
        Err(_) => return TestResult::Fail("the shared-block image did not mount at all"),
    }

    // Snapshotted subvolume (`last_snapshot` set on FS_TREE).
    let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
    {
        let vol = match mount_writable(dev.clone()) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("manyfiles fixture did not mount"),
        };
        let (root_tree, _) = vol.root_tree_root();
        let key = BtrfsKey::new(format::FS_TREE_OBJECTID, format::ROOT_ITEM_KEY, 0);
        if !poke_item(&vol, root_tree, &key, |body| {
            body[200..208].copy_from_slice(&3u64.to_le_bytes())
        }) {
            return TestResult::Fail("could not mark FS_TREE snapshotted");
        }
    }
    match mount_writable(dev) {
        Ok(v) if !v.supports_writes() => match v.rw_refusal() {
            Some(crate::rw_gate::Refusal::Snapshotted { root: 5, .. }) => TestResult::Pass,
            _ => TestResult::Fail("snapshotted subvolume refused for the wrong reason"),
        },
        Ok(_) => TestResult::Fail("a snapshotted image mounted writable"),
        Err(_) => TestResult::Fail("the snapshotted image did not mount at all"),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_rw_gate_refuses_shared_images
);

/// NARF's own snapshot ioctl is refused under `narf.disks=root-rw` (it
/// would create a shape Linux mis-handles), with nothing created.
fn smoke_btrfs_snapshot_refused_under_root_rw() -> TestResult {
    if crate::write::SNAPSHOTS_LINUX_SHAPED {
        return TestResult::Pass;
    }
    let dev = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = match mount_writable(dev) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("bgt fixture did not mount writable"),
    };
    let root = vol.root();
    narf_block::disk_policy::__set_policy_for_test(Some(
        narf_block::disk_policy::DiskPolicy::RootRw,
    ));
    let result = poll_once(root.snapshot_async(root.clone(), "snap", false));
    narf_block::disk_policy::__set_policy_for_test(None);
    if !matches!(result, Some(Err(FsError::Unsupported))) {
        return TestResult::Fail("snapshot creation was not refused under root-rw");
    }
    if poll_once(root.lookup_async("snap")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("a refused snapshot left a directory entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_snapshot_refused_under_root_rw
);

// ── Finding 2: one request per superblock copy ──────────────────────

fn smoke_btrfs_io_run_shapes() -> TestResult {
    use crate::volume::io_run;
    // A 4 KiB superblock at 64 KiB on 512-byte blocks: one 8-block run.
    if io_run(65536, 4096, 512, 65536) != (128, 8, 0, 4096) {
        return TestResult::Fail("superblock is not one 8-block run");
    }
    // A 16 KiB node: one 32-block run.
    if io_run(1 << 20, 16384, 512, 65536) != (2048, 32, 0, 16384) {
        return TestResult::Fail("tree node is not one run");
    }
    // Unaligned range: starts inside a block and spills into the next.
    if io_run(1000, 100, 512, 65536) != (1, 2, 488, 100) {
        return TestResult::Fail("unaligned range shape wrong");
    }
    // Larger than the scratch: capped at the scratch size.
    if io_run(0, 200_000, 4096, 65536) != (0, 16, 0, 65536) {
        return TestResult::Fail("long range not capped at the scratch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_io_run_shapes);

/// On a 512-byte-LBA device the primary superblock goes out as ONE FUA write
/// of all eight blocks (and the mirror as one plain write), never eight.
fn smoke_btrfs_superblock_single_request() -> TestResult {
    let dev = recording(FIXTURE_MIRROR_SPARSE);
    let vol = match mount_recording(&dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("mirror fixture did not mount"),
    };
    let f = match poll_once(vol.root().create("single.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    if !matches!(poll_once(f.write(0, &[7u8; 5000])), Some(Ok(5000))) {
        return TestResult::Fail("write failed");
    }
    dev.log.lock().clear();
    if !matches!(poll_once(f.fsync(false)), Some(Ok(()))) {
        return TestResult::Fail("fsync failed");
    }
    let log = dev.log.lock().clone();
    let primary = format::SUPERBLOCK_OFFSET / 512;
    let mirror = (64u64 << 20) / 512;
    let fua: Vec<DevOp> = log
        .iter()
        .copied()
        .filter(|op| matches!(op, DevOp::WriteFua { .. }))
        .collect();
    if fua != [DevOp::WriteFua { lba: primary, n: 8 }] {
        return TestResult::Fail("primary superblock was not exactly one 8-block FUA write");
    }
    if !log.contains(&DevOp::Write { lba: mirror, n: 8 }) {
        return TestResult::Fail("mirror superblock was not one 8-block write");
    }
    // Tree nodes go out whole too (4 KiB nodes = 8 blocks).
    if log
        .iter()
        .any(|op| matches!(op, DevOp::Write { n, .. } if *n == 1))
    {
        return TestResult::Fail("a commit still issued single-block writes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_superblock_single_request);

// ── Finding 3: a reused block is detected against its parent ────────

fn smoke_btrfs_verify_child_against_parent() -> TestResult {
    use crate::btree::verify_child;
    let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
    let vol = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("manyfiles fixture did not mount"),
    };
    let (root, _) = vol.fs_tree_root();
    let Some(Ok(parent)) = poll_once(vol.read_node(root)) else {
        return TestResult::Fail("fs root unreadable");
    };
    let Some(Ok(child)) = poll_once(vol.read_node(internal_blockptr(&parent, 0).unwrap())) else {
        return TestResult::Fail("fs child unreadable");
    };
    if verify_child(&parent, 0, &child).is_err() {
        return TestResult::Fail("a genuine child failed verification");
    }
    let mut stale_gen = child.clone();
    stale_gen[80..88].copy_from_slice(&(le64(&child, 80).unwrap() + 1).to_le_bytes());
    if verify_child(&parent, 0, &stale_gen).is_ok() {
        return TestResult::Fail("a child with the wrong generation passed");
    }
    let mut wrong_level = child.clone();
    wrong_level[100] = 3;
    if verify_child(&parent, 0, &wrong_level).is_ok() {
        return TestResult::Fail("a child at the wrong level passed");
    }
    // Another child of the same parent: right generation and level, wrong
    // first key — exactly what a reused block looks like.
    if nritems(&parent).unwrap_or(0) > 1 {
        let Some(Ok(other)) = poll_once(vol.read_node(internal_blockptr(&parent, 1).unwrap()))
        else {
            return TestResult::Fail("second child unreadable");
        };
        if verify_child(&parent, 0, &other).is_ok() {
            return TestResult::Fail("a child with the wrong first key passed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_verify_child_against_parent);

/// A reader holding a node whose pinned root went stale retries from the
/// live root: after many commits free and reuse the old tree's blocks, a
/// lookup through the old root still answers correctly (or from the live one).
fn smoke_btrfs_reader_retries_from_live_root() -> TestResult {
    let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
    let vol = match mount_writable(dev) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("manyfiles fixture did not mount writable"),
    };
    let root = vol.root();
    // Churn: every commit frees the previous fs-tree path and later ones
    // reuse that space.
    for i in 0..48 {
        let name = alloc::format!("churn-{i}");
        if !matches!(poll_once(root.create(&name)), Some(Ok(_))) {
            return TestResult::Fail("churn create failed");
        }
        if i % 4 == 0 && !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return TestResult::Fail("churn sync failed");
        }
    }
    for i in 0..48 {
        let name = alloc::format!("churn-{i}");
        if !matches!(poll_once(root.lookup_async(&name)), Some(Ok(_))) {
            return TestResult::Fail("a lookup after churn failed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_reader_retries_from_live_root
);

// ── Finding 4: admin writers honour read-only and aborted state ─────

fn smoke_btrfs_admin_writes_gated() -> TestResult {
    use crate::node::BTRFS_IOC_SUBVOL_SETFLAGS;
    let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("manyfiles fixture did not mount writable"),
    };
    vol.abort_transaction();
    let gen_before = super_generation(&dev);
    let root = vol.root();
    let flags = 1u64 << 1; // BTRFS_SUBVOL_RDONLY
    let setflags =
        poll_once(root.ioctl_async(BTRFS_IOC_SUBVOL_SETFLAGS, 0, &flags.to_ne_bytes(), 0));
    if !matches!(setflags, Some(Err(FsError::ReadOnly))) {
        return TestResult::Fail("SUBVOL_SETFLAGS ran on an aborted filesystem");
    }
    let Some(Ok(node)) = poll_once(vol.read_node(vol.fs_tree_root().0)) else {
        return TestResult::Fail("fs root unreadable");
    };
    if !matches!(
        poll_once(vol.write_node_root_admin(1 << 20, &node)),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("root-admin node write ran on an aborted filesystem");
    }
    let raw = match poll_once(vol.read_raw_superblock()) {
        Some(Ok(raw)) => raw,
        _ => return TestResult::Fail("superblock unreadable"),
    };
    if !matches!(
        poll_once(vol.write_superblock_root_admin(&raw)),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("root-admin superblock write ran on an aborted filesystem");
    }
    if super_generation(&dev) != gen_before {
        return TestResult::Fail("something reached the superblock");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_admin_writes_gated);

/// A read-only core refuses the root-admin node writer too.
fn smoke_btrfs_root_admin_refused_read_only() -> TestResult {
    let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
    let vol = match mount_writable(dev) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("manyfiles fixture did not mount writable"),
    };
    if !matches!(poll_once(vol.remount_read_only()), Some(Ok(()))) {
        return TestResult::Fail("remount read-only failed");
    }
    let Some(Ok(node)) = poll_once(vol.read_node(vol.fs_tree_root().0)) else {
        return TestResult::Fail("fs root unreadable");
    };
    if !matches!(
        poll_once(vol.write_node_root_admin(1 << 20, &node)),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("root-admin node write ran on a read-only filesystem");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_root_admin_refused_read_only);

// ── Finding 5: no chunk growth on a production root; dev size cap ───

fn smoke_btrfs_root_rw_never_grows() -> TestResult {
    let dev = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = match mount_writable(dev) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("bgt fixture did not mount writable"),
    };
    narf_block::disk_policy::__set_policy_for_test(Some(
        narf_block::disk_policy::DiskPolicy::RootRw,
    ));
    let grow = poll_once(crate::write::grow_add_chunk(&vol));
    let balance = poll_once(vol.balance_profiles(crate::volume::BalanceProfiles {
        data: Some(crate::chunk::ChunkProfile::Dup),
        ..Default::default()
    }));
    narf_block::disk_policy::__set_policy_for_test(None);
    // The whole-tree-repacking grow and balance never run on a production
    // root (`alloc_chunk` grows it instead).
    if !matches!(grow, Some(Err(FsError::NoSpace))) {
        return TestResult::Fail("whole-tree chunk growth ran under root-rw");
    }
    if !matches!(balance, Some(Err(FsError::Unsupported))) {
        return TestResult::Fail("balance ran under root-rw");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_root_rw_never_grows);

/// On a device larger than the btrfs `total_bytes`, grown chunks stay inside
/// `total_bytes`: the partition's spare tail is never allocated.
fn smoke_btrfs_growth_capped_at_device_total_bytes() -> TestResult {
    let base = writable_sparse(FIXTURE_MIRROR_SPARSE);
    let dev = Arc::new(WritableSparseDevice {
        runs: base.runs.clone(),
        total: base.total + (64 << 20),
        lba_size: base.lba_size,
        overlay: narf_lib::sync::IrqSafeSpinLock::new(alloc::collections::BTreeMap::new()),
    });
    let vol = match mount_writable(dev) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("mirror fixture did not mount writable"),
    };
    let dev_total = vol.total_bytes();
    for _ in 0..64 {
        if poll_once(crate::write::grow_add_chunk(&vol)).is_none_or(|r| r.is_err()) {
            break;
        }
    }
    let ranges = match poll_once(crate::write::device_extent_ranges(&vol, 1)) {
        Some(Ok(r)) => r,
        _ => return TestResult::Fail("device extents unreadable"),
    };
    if ranges.iter().any(|&(start, len)| start + len > dev_total) {
        return TestResult::Fail("a chunk was placed beyond the device's btrfs total_bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_growth_capped_at_device_total_bytes
);

// ── Finding 6: logical leaves grow instead of failing a commit ──────

fn smoke_btrfs_logical_leaf_grows() -> TestResult {
    let dev = writable_sparse(FIXTURE_MANYFILES_SPARSE);
    let vol = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("manyfiles fixture did not mount"),
    };
    let (root, _) = vol.fs_tree_root();
    let mut logical = match poll_once(crate::write::__test_read_oversized(&vol, root)) {
        Some(Ok(l)) => l,
        _ => return TestResult::Fail("fs tree unreadable"),
    };
    let start = logical.len();
    // Far more than the fixed 64 KiB headroom.
    for i in 0..8000u64 {
        let key = BtrfsKey::new(u64::MAX - 1, 199, i);
        if crate::write::__test_leaf_insert_sorted(&mut logical, &key, &[0u8; 16]).is_err() {
            return TestResult::Fail("an insert into a full logical leaf failed");
        }
    }
    if logical.len() <= start || nritems(&logical).unwrap_or(0) < 8000 {
        return TestResult::Fail("the logical leaf did not grow");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_logical_leaf_grows);

// ── Finding 7: test workloads touch only harness images ─────────────

fn smoke_btrfs_harness_marker_rules() -> TestResult {
    use crate::harness::check_disposable;
    let host_root = "653602c3-cd42-420e-95ef-4c4033d17b56";
    let interop = "c4c405ee-0000-4a11-9e57-0000000a7e57";
    let fixture = "78fa8eab-8bfc-4252-b88b-aa552ffa3e01";
    if check_disposable(host_root, Some(host_root), false).is_ok()
        || check_disposable(host_root, None, true).is_ok()
        || check_disposable(host_root, None, false).is_ok()
    {
        return TestResult::Fail("the host root counted as disposable");
    }
    if check_disposable(fixture, None, false).is_err() {
        return TestResult::Fail("the smoke fixture was refused");
    }
    if check_disposable(fixture, Some(fixture), false).is_ok() {
        return TestResult::Fail("a smoke ran on the cmdline root");
    }
    if check_disposable(interop, Some(interop), true).is_err() {
        return TestResult::Fail("the interop image root was refused");
    }
    if check_disposable("c4c405ee-0000-4a11-0000-000000000000", None, false).is_ok() {
        return TestResult::Fail("a look-alike fsid counted as a harness image");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_harness_marker_rules);

// ── Last unmount commits ────────────────────────────────────────────

/// Dropping the last mount of a writable filesystem with an open batch
/// commits it: a remount of the device finds the file.
fn smoke_btrfs_last_unmount_commits() -> TestResult {
    let dev = writable_sparse(FIXTURE_MIRROR_SPARSE);
    let gen_before = super_generation(&dev);
    {
        let vol = match mount_writable(dev.clone()) {
            Ok(v) if v.supports_writes() => v,
            _ => return TestResult::Fail("mirror fixture did not mount writable"),
        };
        let f = match poll_once(vol.root().create("unmount.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("create failed"),
        };
        if !matches!(
            poll_once(f.write(0, b"made durable by unmount")),
            Some(Ok(23))
        ) {
            return TestResult::Fail("write failed");
        }
        drop(f);
        drop(vol);
    }
    if super_generation(&dev) == gen_before {
        return TestResult::Fail("the last unmount discarded the open transaction");
    }
    let vol = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount failed"),
    };
    let f = match poll_once(vol.root().lookup_async("unmount.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("the file did not survive unmount"),
    };
    match read_all(&f, 64) {
        Some(got) if got == b"made durable by unmount" => TestResult::Pass,
        _ => TestResult::Fail("the file's data did not survive unmount"),
    }
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_last_unmount_commits);

// ── Finding 8: superblock backup roots and uuid_tree_generation ─────

fn smoke_btrfs_commit_updates_backup_roots() -> TestResult {
    let dev = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("bgt fixture did not mount writable"),
    };
    let before = read_super_at(&dev, format::SUPERBLOCK_OFFSET);
    let uuid_current = le64(&before, 563).ok() == le64(&before, 72).ok();
    for round in 0..3 {
        let name = alloc::format!("backup-{round}");
        if !matches!(poll_once(vol.root().create(&name)), Some(Ok(_)))
            || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
        {
            return TestResult::Fail("commit failed");
        }
        let sb = read_super_at(&dev, format::SUPERBLOCK_OFFSET);
        let gen = le64(&sb, 72).unwrap();
        let root = le64(&sb, 80).unwrap();
        let base = format::SYS_CHUNK_ARRAY_OFFSET + 2048;
        let slot = (0..4).find(|i| le64(&sb, base + i * 168 + 8).ok() == Some(gen));
        let Some(slot) = slot else {
            return TestResult::Fail("no backup slot carries the committed generation");
        };
        let at = base + slot * 168;
        if le64(&sb, at).ok() != Some(root) || sb[at + 152] != sb[format::OFF_ROOT_LEVEL] {
            return TestResult::Fail("the backup slot does not name the committed root tree");
        }
        if le64(&sb, at + 32).unwrap_or(0) == 0 || le64(&sb, at + 48).unwrap_or(0) == 0 {
            return TestResult::Fail("the backup slot lacks the extent or fs root");
        }
        if uuid_current && le64(&sb, 563).ok() != Some(gen) {
            return TestResult::Fail("uuid_tree_generation did not advance with the generation");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_commit_updates_backup_roots);

// ── Regressions from the CachyOS gate ───────────────────────────────

/// Every ROOT_ITEM's generation must equal its root block's header
/// generation (`verify_parent_transid` on the root).
fn root_items_match_root_blocks(vol: &Vol) -> Result<(), &'static str> {
    let (root_tree, _) = vol.root_tree_root();
    let Some(Ok(mut cursor)) = poll_once(btree::Cursor::seek(
        &**vol,
        root_tree,
        &BtrfsKey::new(0, 0, 0),
    )) else {
        return Err("root tree unreadable");
    };
    let mut checks = Vec::new();
    while let Ok(Some((key, body))) = cursor.current() {
        if key.item_type == format::ROOT_ITEM_KEY && body.len() >= 239 {
            checks.push((le64(body, 176).unwrap(), le64(body, 160).unwrap()));
        }
        if poll_once(cursor.advance()).is_none_or(|r| r.is_err()) {
            return Err("root tree walk failed");
        }
    }
    for (bytenr, gen) in checks {
        let Some(Ok(node)) = poll_once(vol.read_node(bytenr)) else {
            return Err("a root block is unreadable");
        };
        if le64(&node, 80).ok() != Some(gen) {
            return Err("a ROOT_ITEM generation does not match its root block");
        }
    }
    Ok(())
}

/// Releasing a data extent with no checksums (preallocated space) path-COWs
/// the csum tree with nothing to edit: its root does not move, so its
/// ROOT_ITEM must keep its generation. Bumping it alone produced a
/// `parent transid verify failed` image in the root-rw interop run.
fn smoke_btrfs_unmoved_root_keeps_generation() -> TestResult {
    let dev = writable_sparse(FIXTURE_MIRROR_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("mirror fixture did not mount writable"),
    };
    let root = vol.root();
    let f = match poll_once(root.create("prealloc.bin")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    if !matches!(
        poll_once(f.fallocate(crate::write::FALLOC_FL_KEEP_SIZE, 0, 256 * 1024)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("fallocate failed");
    }
    drop(f);
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("first sync failed");
    }
    if !matches!(poll_once(root.unlink("prealloc.bin")), Some(Ok(()))) {
        return TestResult::Fail("unlink failed");
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("second sync failed");
    }
    if let Err(why) = root_items_match_root_blocks(&vol) {
        return TestResult::Fail(why);
    }
    // And from disk, through a fresh mount.
    drop(root);
    drop(vol);
    match mount_writable(dev) {
        Ok(v) => match root_items_match_root_blocks(&v) {
            Ok(()) => TestResult::Pass,
            Err(why) => TestResult::Fail(why),
        },
        Err(_) => TestResult::Fail("remount failed"),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_unmoved_root_keeps_generation
);

/// `O_TRUNC` of a small file Linux stored inline (most of a real root's
/// small files) must succeed: the inline item is deleted, never carved.
fn smoke_btrfs_truncate_inline_file_to_zero() -> TestResult {
    let dev = writable_sparse(FIXTURE_MIRROR_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("mirror fixture did not mount writable"),
    };
    let f = match poll_once(vol.root().lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("hello.txt missing"),
    };
    if !matches!(poll_once(f.truncate(0)), Some(Ok(()))) {
        return TestResult::Fail("truncating an inline file to zero failed");
    }
    if !matches!(poll_once(f.write(0, b"rewritten\n")), Some(Ok(10))) {
        return TestResult::Fail("rewrite after truncate failed");
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("sync failed");
    }
    drop(f);
    drop(vol);
    let vol = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount failed"),
    };
    let f = match poll_once(vol.root().lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("hello.txt gone after remount"),
    };
    match read_all(&f, 64) {
        Some(got) if got == b"rewritten\n" => TestResult::Pass,
        _ => TestResult::Fail("rewritten content lost"),
    }
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_truncate_inline_file_to_zero);

// ── Incremental chunk allocation (root-rw growth) ───────────────────

/// Sum of the device's DEV_EXTENT lengths, the dev_item's `bytes_used`, and
/// the number of chunks / block groups, through the live trees.
fn chunk_accounting(vol: &Vol) -> Result<(u64, u64, usize, usize), &'static str> {
    let sb = vol.superblock();
    let mut chunks = 0usize;
    let mut dev_used = 0u64;
    let Some(Ok(mut c)) = poll_once(btree::Cursor::seek(
        &**vol,
        sb.chunk_root,
        &BtrfsKey::new(0, 0, 0),
    )) else {
        return Err("chunk tree unreadable");
    };
    while let Ok(Some((key, body))) = c.current() {
        if key.item_type == format::CHUNK_ITEM_KEY {
            chunks += 1;
        }
        if key.item_type == format::DEV_ITEM_KEY {
            dev_used = le64(body, 16).unwrap_or(0);
        }
        if poll_once(c.advance()).is_none_or(|r| r.is_err()) {
            return Err("chunk tree walk");
        }
    }
    let (root_tree, _) = vol.root_tree_root();
    let Some(Ok((dev_root, _))) = poll_once(crate::roots::find_root(
        &**vol,
        root_tree,
        format::DEV_TREE_OBJECTID,
    )) else {
        return Err("dev tree");
    };
    let mut extents = 0u64;
    let Some(Ok(mut c)) = poll_once(btree::Cursor::seek(
        &**vol,
        dev_root,
        &BtrfsKey::new(0, 0, 0),
    )) else {
        return Err("dev tree unreadable");
    };
    while let Ok(Some((key, body))) = c.current() {
        if key.item_type == format::DEV_EXTENT_KEY {
            extents += le64(body, 24).unwrap_or(0);
        }
        if poll_once(c.advance()).is_none_or(|r| r.is_err()) {
            return Err("dev tree walk");
        }
    }
    let groups = match poll_once(crate::block_group::live_block_groups(&**vol)) {
        Some(Ok(g)) => g.len(),
        _ => return Err("block groups unreadable"),
    };
    Ok((extents, dev_used, chunks, groups))
}

/// `write::alloc_chunk` adds a DATA and a METADATA chunk by path COW: chunk
/// item + dev_item bytes_used in the chunk tree, dev extents, block group,
/// free space; the new space is then usable and everything survives a
/// remount with consistent accounting and references.
fn smoke_btrfs_incremental_chunk_alloc() -> TestResult {
    let dev = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("bgt fixture did not mount writable"),
    };
    let Ok((ext0, used0, chunks0, groups0)) = chunk_accounting(&vol) else {
        return TestResult::Fail("accounting unreadable");
    };
    if ext0 != used0 {
        return TestResult::Fail("fixture's dev_item bytes_used differs from its extents");
    }
    for kind in [format::BLOCK_GROUP_DATA, format::BLOCK_GROUP_METADATA] {
        if !matches!(
            poll_once(crate::write::alloc_chunk(&vol, kind)),
            Some(Ok(()))
        ) {
            return TestResult::Fail("alloc_chunk failed");
        }
    }
    match chunk_accounting(&vol) {
        Ok((ext, used, chunks, groups))
            if ext == used && chunks == chunks0 + 2 && groups == groups0 + 2 && ext > ext0 => {}
        Ok(_) => return TestResult::Fail("chunk/dev/block-group accounting is inconsistent"),
        Err(why) => return TestResult::Fail(why),
    }
    // Fill well past the space the fixture had.
    let f = match poll_once(vol.root().create("grown.bin")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let data: Vec<u8> = (0..24u32 << 20).map(|i| (i % 251) as u8).collect();
    if !matches!(poll_once(f.write(0, &data)), Some(Ok(n)) if n == data.len()) {
        return TestResult::Fail("write into the new chunk failed");
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("sync failed");
    }
    drop(f);
    drop(vol);
    let vol = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount after chunk allocation failed"),
    };
    if let Err(why) = super::snapshots::check_ref_counts(&vol) {
        return TestResult::Fail(why);
    }
    match chunk_accounting(&vol) {
        Ok((ext, used, chunks, _)) if ext == used && chunks == chunks0 + 2 => {}
        _ => return TestResult::Fail("accounting lost across the remount"),
    }
    let f = match poll_once(vol.root().lookup_async("grown.bin")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("grown.bin lost"),
    };
    match read_all(&f, data.len() + 1) {
        Some(got) if got == data => TestResult::Pass,
        _ => TestResult::Fail("grown.bin content wrong"),
    }
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_incremental_chunk_alloc);

/// Under root-rw a full data space grows by `alloc_chunk` (never the
/// whole-tree grow): a write larger than the free data space succeeds.
fn smoke_btrfs_root_rw_write_allocates_chunk() -> TestResult {
    let dev = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = match mount_writable(dev) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("bgt fixture did not mount writable"),
    };
    let Ok((_, _, chunks0, _)) = chunk_accounting(&vol) else {
        return TestResult::Fail("accounting unreadable");
    };
    narf_block::disk_policy::__set_policy_for_test(Some(
        narf_block::disk_policy::DiskPolicy::RootRw,
    ));
    let result = (|| {
        let f = poll_once(vol.root().create("big-under-root-rw.bin"))
            .and_then(Result::ok)
            .ok_or("create failed")?;
        let chunk: Vec<u8> = alloc::vec![0x5a; 1 << 20];
        for i in 0..96u64 {
            match poll_once(f.write(i << 20, &chunk)) {
                Some(Ok(n)) if n == chunk.len() => {}
                Some(Err(FsError::NoSpace)) => return Err("ENOSPC although the device has room"),
                _ => return Err("write failed"),
            }
        }
        match poll_once(vol.sync_to_disk()) {
            Some(Ok(())) => Ok(()),
            _ => Err("sync failed"),
        }
    })();
    narf_block::disk_policy::__set_policy_for_test(None);
    if let Err(why) = result {
        return TestResult::Fail(why);
    }
    match chunk_accounting(&vol) {
        Ok((ext, used, chunks, _)) if ext == used && chunks > chunks0 => {}
        Ok(_) => return TestResult::Fail("no chunk allocated, or accounting inconsistent"),
        Err(why) => return TestResult::Fail(why),
    }
    match super::snapshots::check_ref_counts(&vol) {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_root_rw_write_allocates_chunk
);

/// Metadata-heavy writes under `root-rw` until the 32 MiB metadata group
/// would run out: the batch must keep back what its own commit needs, so the
/// operation that would eat into it fails *before* staging, a METADATA chunk
/// is allocated, and no commit ever fails for space. (Before the reserve, a
/// commit found the metadata groups full and aborted the filesystem with
/// operations it had already acknowledged.)
fn smoke_btrfs_root_rw_metadata_reserve() -> TestResult {
    let dev = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = match mount_writable(dev) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("bgt fixture did not mount writable"),
    };
    let Ok((_, _, chunks0, _)) = chunk_accounting(&vol) else {
        return TestResult::Fail("accounting unreadable");
    };
    narf_block::disk_policy::__set_policy_for_test(Some(
        narf_block::disk_policy::DiskPolicy::RootRw,
    ));
    let result = (|| {
        let body: Vec<u8> = alloc::vec![0x6d; 3000];
        for i in 0..9000u32 {
            let name = alloc::format!("m{i}");
            let f = match poll_once(vol.root().create(&name)) {
                Some(Ok(f)) => f,
                Some(Err(FsError::NoSpace)) => return Err("ENOSPC although the device has room"),
                _ => return Err("create failed (aborted?)"),
            };
            match poll_once(f.write(0, &body)) {
                Some(Ok(n)) if n == body.len() => {}
                Some(Err(FsError::NoSpace)) => return Err("ENOSPC although the device has room"),
                _ => return Err("write failed (aborted?)"),
            }
        }
        match poll_once(vol.sync_to_disk()) {
            Some(Ok(())) => Ok(()),
            _ => Err("sync failed"),
        }
    })();
    narf_block::disk_policy::__set_policy_for_test(None);
    if let Err(why) = result {
        return TestResult::Fail(why);
    }
    if !vol.admits_writes() {
        return TestResult::Fail("the filesystem aborted");
    }
    match chunk_accounting(&vol) {
        Ok((ext, used, chunks, _)) if ext == used && chunks > chunks0 => {}
        Ok(_) => return TestResult::Fail("no chunk allocated, or accounting inconsistent"),
        Err(why) => return TestResult::Fail(why),
    }
    match super::snapshots::check_ref_counts(&vol) {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_root_rw_metadata_reserve);

/// The free-space tree's leaf count is made monotone late in the commit fixed
/// point by padding its tiling: the padded groups still cover every item, in
/// order, with no empty leaf, and a tiling of single items cannot be padded.
fn smoke_btrfs_fst_pad_groups() -> TestResult {
    let mut g = alloc::vec![(0usize, 7usize), (7, 9), (9, 30)];
    crate::write::pad_groups(&mut g, 6);
    let contiguous = g.windows(2).all(|w| w[0].1 == w[1].0);
    if g.len() != 6 || g[0].0 != 0 || g[5].1 != 30 || !contiguous || g.iter().any(|&(s, e)| e <= s)
    {
        return TestResult::Fail("padded tiling is not a cover of the items");
    }
    let mut ones = alloc::vec![(0usize, 1usize), (1, 2)];
    crate::write::pad_groups(&mut ones, 5);
    if ones != [(0, 1), (1, 2)] {
        return TestResult::Fail("single-item groups were split");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_fst_pad_groups);
