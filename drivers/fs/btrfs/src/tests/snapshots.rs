//! Writing subvolumes that share tree blocks and data with Linux-made
//! snapshots (`testdata/regen_snapshot_fixture.sh`: snapper-style nested
//! `.snapshots`, divergent rounds, a top-level snapshot, a reflink, and a
//! metadata + data balance, so FULL_BACKREF blocks and shared-block /
//! shared-data refs are on disk).
//!
//! Every test checks two things after NARF writes: each snapshot reads back
//! byte-identical, and the extent tree's reference counts equal what the
//! trees actually reference ([`check_ref_counts`], the backref half of
//! `btrfs check`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::{DirOps, FileType, FsError, FsInstance};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use super::{poll_once, read_all, writable_sparse, WritableSparseDevice};
use crate::btree::{self, internal_blockptr, level, nritems};
use crate::format::{self, le32, le64, BtrfsKey};
use crate::volume::{BtrfsVolume, Subvol};

const FIXTURE_SNAPSHOTS_SPARSE: &[u8] =
    include_bytes!("../../testdata/fixture-snapshots.img.sparse");

/// Subvolume ids in the fixture.
const ROOT_SV: u64 = 256; // @
const HOME_SV: u64 = 257; // @home
const SNAPSHOTS: &[u64] = &[259, 260, 261, 262, 263];

type Vol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

fn mount_id(dev: &Arc<WritableSparseDevice>, id: u64) -> Result<Vol, FsError> {
    let async_dev = narf_block::SyncBlock::new(dev.clone() as Arc<dyn narf_block::BlockDeviceSync>);
    poll_once(BtrfsVolume::mount_subvol(
        async_dev,
        DomainId::DRIVER_0,
        true,
        Some(Subvol::Id(id)),
    ))
    .ok_or(FsError::InvalidData)?
}

/// Every regular file under `dir` (not crossing into nested subvolumes,
/// which `lookup_dir` reaches as a different tree), path → content.
fn collect(dir: &Arc<dyn DirOps>, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) -> bool {
    let mut cursor = 0usize;
    loop {
        let Some(Ok(batch)) = poll_once(dir.enumerate_async(cursor, 256)) else {
            return false;
        };
        if batch.is_empty() {
            return true;
        }
        cursor += batch.len();
        for (name, ft) in batch {
            if name == "." || name == ".." {
                continue;
            }
            let path = alloc::format!("{prefix}/{name}");
            match ft {
                FileType::Dir => {
                    // `.snapshots` and the snapshots under it are other trees.
                    if name == ".snapshots" {
                        continue;
                    }
                    let Some(Ok(sub)) = poll_once(dir.lookup_dir_async(&name)) else {
                        return false;
                    };
                    if !collect(&sub, &path, out) {
                        return false;
                    }
                }
                FileType::File => {
                    let Some(Ok(file)) = poll_once(dir.lookup_async(&name)) else {
                        return false;
                    };
                    let size = file.stat().size as usize;
                    let Some(bytes) = read_all(&file, size + 1) else {
                        return false;
                    };
                    out.insert(path, bytes);
                }
                _ => {}
            }
        }
    }
}

fn contents(dev: &Arc<WritableSparseDevice>, id: u64) -> Option<BTreeMap<String, Vec<u8>>> {
    let vol = mount_id(dev, id).ok()?;
    let mut out = BTreeMap::new();
    collect(&vol.root(), "", &mut out).then_some(out)
}

/// The backref half of `btrfs check`: walk every tree from the superblock and
/// every ROOT_ITEM; count, per tree block, the distinct parents (and root
/// items) pointing at it, and per data extent, the file-extent items (in
/// distinct leaves) naming it. Every extent item's `refs` — and the sum of
/// its inline and keyed backrefs — must equal that count, and every counted
/// extent must have an item.
pub(super) fn check_ref_counts(vol: &Vol) -> Result<(), &'static str> {
    let sb = vol.superblock();
    let (root_tree, _) = vol.root_tree_root();
    let mut tree_refs: BTreeMap<u64, u64> = BTreeMap::new();
    let mut data_refs: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    let mut todo: Vec<u64> = alloc::vec![root_tree, sb.chunk_root];
    *tree_refs.entry(root_tree).or_insert(0) += 1;
    *tree_refs.entry(sb.chunk_root).or_insert(0) += 1;
    {
        let Some(Ok(mut c)) = poll_once(btree::Cursor::seek(
            &**vol,
            root_tree,
            &BtrfsKey::new(0, 0, 0),
        )) else {
            return Err("root tree unreadable");
        };
        while let Ok(Some((key, body))) = c.current() {
            if key.item_type == format::ROOT_ITEM_KEY && body.len() >= 239 {
                let at = le64(body, 176).map_err(|_| "root item")?;
                *tree_refs.entry(at).or_insert(0) += 1;
                todo.push(at);
            }
            if poll_once(c.advance()).is_none_or(|r| r.is_err()) {
                return Err("root tree walk");
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut levels: BTreeMap<u64, u8> = BTreeMap::new();
    while let Some(addr) = todo.pop() {
        if !seen.insert(addr) {
            continue;
        }
        let Some(Ok(node)) = poll_once(vol.read_node(addr)) else {
            return Err("tree block unreadable");
        };
        let lvl = level(&node).map_err(|_| "level")?;
        levels.insert(addr, lvl);
        let n = nritems(&node).map_err(|_| "nritems")? as usize;
        if lvl > 0 {
            for i in 0..n {
                let child = internal_blockptr(&node, i).map_err(|_| "ptr")?;
                *tree_refs.entry(child).or_insert(0) += 1;
                todo.push(child);
            }
            continue;
        }
        for i in 0..n {
            let key = btree::leaf_item_key(&node, i).map_err(|_| "key")?;
            if key.item_type != format::EXTENT_DATA_KEY {
                continue;
            }
            let body = btree::leaf_item_data(&node, i).map_err(|_| "item")?;
            if body.get(20).copied().unwrap_or(0) == 0 {
                continue;
            }
            let bytenr = le64(body, 21).map_err(|_| "fe")?;
            if bytenr == 0 {
                continue;
            }
            let len = le64(body, 29).map_err(|_| "fe")?;
            *data_refs.entry((bytenr, len)).or_insert(0) += 1;
        }
    }
    // Every extent item and keyed backref.
    let Ok((ext, _)) = poll_once(crate::roots::find_root(
        &**vol,
        root_tree,
        format::EXTENT_TREE_OBJECTID,
    ))
    .ok_or("extent root")?
    else {
        return Err("extent root");
    };
    let mut item_refs: BTreeMap<u64, (u64, u64, bool)> = BTreeMap::new(); // bytenr -> (refs, inline sum, data)
    let mut keyed: BTreeMap<u64, u64> = BTreeMap::new();
    let mut data_len: BTreeMap<u64, u64> = BTreeMap::new();
    let Some(Ok(mut c)) = poll_once(btree::Cursor::seek(&**vol, ext, &BtrfsKey::new(0, 0, 0)))
    else {
        return Err("extent tree unreadable");
    };
    while let Ok(Some((key, body))) = c.current() {
        match key.item_type {
            format::METADATA_ITEM_KEY | format::EXTENT_ITEM_KEY => {
                let refs = le64(body, 0).map_err(|_| "ei")?;
                let flags = le64(body, 16).map_err(|_| "ei")?;
                let data = flags & 1 != 0;
                let mut at = if key.item_type == format::EXTENT_ITEM_KEY && !data {
                    24 + format::DISK_KEY_SIZE + 1
                } else {
                    24
                };
                let mut sum = 0u64;
                while at < body.len() {
                    let (size, count) =
                        crate::backref::inline_ref_shape(body, at).map_err(|_| "inline ref")?;
                    sum += count;
                    at += size;
                }
                if data {
                    data_len.insert(key.objectid, key.offset);
                }
                item_refs.insert(key.objectid, (refs, sum, data));
            }
            176 | 182 => *keyed.entry(key.objectid).or_insert(0) += 1,
            178 => {
                *keyed.entry(key.objectid).or_insert(0) +=
                    u64::from(le32(body, 24).map_err(|_| "keyed")?)
            }
            184 => {
                *keyed.entry(key.objectid).or_insert(0) +=
                    u64::from(le32(body, 0).map_err(|_| "keyed")?)
            }
            _ => {}
        }
        if poll_once(c.advance()).is_none_or(|r| r.is_err()) {
            return Err("extent tree walk");
        }
    }
    for (&bytenr, &(refs, inline, _)) in &item_refs {
        if inline + keyed.get(&bytenr).copied().unwrap_or(0) != refs {
            return Err("an extent item's backrefs do not add up to its refs");
        }
    }
    for (&addr, &want) in &tree_refs {
        match item_refs.get(&addr) {
            Some(&(refs, _, false)) if refs == want => {}
            Some(&(_, _, false)) => return Err("a tree block's refs differ from its parents"),
            _ => return Err("a referenced tree block has no extent item"),
        }
    }
    for (&(bytenr, len), &want) in &data_refs {
        match item_refs.get(&bytenr) {
            Some(&(refs, _, true)) if refs == want && data_len.get(&bytenr) == Some(&len) => {}
            Some(&(_, _, true)) => return Err("a data extent's refs differ from its file items"),
            _ => return Err("a referenced data extent has no extent item"),
        }
    }
    for (&bytenr, &(_, _, data)) in &item_refs {
        let counted = if data {
            data_len
                .get(&bytenr)
                .is_some_and(|len| data_refs.contains_key(&(bytenr, *len)))
        } else {
            tree_refs.contains_key(&bytenr)
        };
        if !counted {
            return Err("an extent item nothing references (leak)");
        }
    }
    Ok(())
}

fn workload(root: &Arc<dyn DirOps>) -> Result<(), &'static str> {
    let pkg = poll_once(root.lookup_dir_async("usr"))
        .and_then(Result::ok)
        .and_then(|usr| poll_once(usr.lookup_dir_async("lib")).and_then(Result::ok))
        .ok_or("usr/lib missing")?;
    let files = poll_once(pkg.lookup_dir_async("pkg"))
        .and_then(Result::ok)
        .ok_or("usr/lib/pkg missing")?;
    for i in (0..900).step_by(3) {
        let name = alloc::format!("f{i}");
        let f = match poll_once(files.lookup_async(&name)) {
            Some(Ok(f)) => f,
            _ => match poll_once(files.create(&name)) {
                Some(Ok(f)) => f,
                _ => return Err("create in a shared directory"),
            },
        };
        if !matches!(poll_once(f.truncate(0)), Some(Ok(()))) {
            return Err("truncate of a shared file");
        }
        let body = alloc::format!("narf rewrote {i}\n");
        if !matches!(poll_once(f.write(0, body.as_bytes())), Some(Ok(_))) {
            return Err("write of a shared file");
        }
    }
    for i in (2..900).step_by(10) {
        let _ = poll_once(files.unlink(&alloc::format!("f{i}")));
    }
    for i in 0..40 {
        let name = alloc::format!("data{i}.txt");
        let Some(Ok(f)) = poll_once(pkg.lookup_async(&name)) else {
            return Err("data file missing");
        };
        let size = f.stat().size;
        if !matches!(poll_once(f.write(size, b"narf append\n")), Some(Ok(_))) {
            return Err("append to a shared extent's file");
        }
    }
    for (name, len) in [("data5.txt", 100u64), ("blob-reflink.bin", 4096)] {
        let Some(Ok(f)) = poll_once(pkg.lookup_async(name)) else {
            return Err("file missing");
        };
        if !matches!(poll_once(f.truncate(len)), Some(Ok(()))) {
            return Err("truncate of a shared extent");
        }
    }
    let Some(Ok(blob)) = poll_once(pkg.lookup_async("blob.bin")) else {
        return Err("blob missing");
    };
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7) as u8).collect();
    if !matches!(poll_once(blob.write(0, &data)), Some(Ok(_))) {
        return Err("overwrite of a reflinked, snapshotted extent");
    }
    Ok(())
}

/// Write `@` while five snapshots and the balance's FULL_BACKREF blocks
/// share it; every snapshot must read back unchanged and the extent tree
/// must account for every reference.
fn smoke_btrfs_write_shared_with_linux_snapshots() -> TestResult {
    let dev = writable_sparse(FIXTURE_SNAPSHOTS_SPARSE);
    let mut before = BTreeMap::new();
    for &id in SNAPSHOTS {
        match contents(&dev, id) {
            Some(c) if !c.is_empty() => {
                before.insert(id, c);
            }
            _ => return TestResult::Fail("a snapshot of the fixture is unreadable"),
        }
    }
    {
        let vol = match mount_id(&dev, ROOT_SV) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("@ did not mount"),
        };
        if !vol.supports_writes() {
            return TestResult::Fail("@ with Linux snapshots was refused read-write");
        }
        if let Err(why) = check_ref_counts(&vol) {
            return TestResult::Fail(why);
        }
        let root = vol.root();
        if let Err(why) = workload(&root) {
            return TestResult::Fail(why);
        }
        if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return TestResult::Fail("commit of writes over shared blocks failed");
        }
        if vol.transaction_aborted() {
            return TestResult::Fail("the transaction aborted");
        }
        // A second round, now over blocks NARF itself made shared/unshared.
        if let Err(why) = workload(&root) {
            return TestResult::Fail(why);
        }
        if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return TestResult::Fail("second commit failed");
        }
        // Then empty the big directory: the tree shrinks, merging and
        // collapsing nodes whose children the snapshots still share.
        let pkg = poll_once(root.lookup_dir_async("usr"))
            .and_then(Result::ok)
            .and_then(|usr| poll_once(usr.lookup_dir_async("lib")).and_then(Result::ok))
            .and_then(|lib| poll_once(lib.lookup_dir_async("pkg")).and_then(Result::ok));
        let Some(pkg) = pkg else {
            return TestResult::Fail("usr/lib/pkg missing");
        };
        for i in 0..900 {
            let _ = poll_once(pkg.unlink(&alloc::format!("f{i}")));
        }
        if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return TestResult::Fail("commit after emptying the directory failed");
        }
        if let Err(why) = check_ref_counts(&vol) {
            return TestResult::Fail(why);
        }
    }
    let vol = match mount_id(&dev, ROOT_SV) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("@ did not remount"),
    };
    if let Err(why) = check_ref_counts(&vol) {
        return TestResult::Fail(why);
    }
    let Some(after) = contents(&dev, ROOT_SV) else {
        return TestResult::Fail("@ unreadable after the writes");
    };
    if after.keys().any(|k| k.starts_with("/usr/lib/pkg/"))
        || after.get("/usr/lib/data5.txt").map(Vec::len) != Some(100)
    {
        return TestResult::Fail("@ does not hold what NARF wrote");
    }
    for (&id, want) in &before {
        match contents(&dev, id) {
            Some(got) if &got == want => {}
            Some(_) => return TestResult::Fail("a snapshot's content changed"),
            None => return TestResult::Fail("a snapshot became unreadable"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_write_shared_with_linux_snapshots
);

/// The same through `@home`, under `narf.disks=root-rw` (whose gate must now
/// accept a snapshotted root).
fn smoke_btrfs_write_home_shared_under_root_rw() -> TestResult {
    let dev = writable_sparse(FIXTURE_SNAPSHOTS_SPARSE);
    let Some(snap) = contents(&dev, 260) else {
        return TestResult::Fail("@home snapshot unreadable");
    };
    narf_block::disk_policy::__set_policy_for_test(Some(
        narf_block::disk_policy::DiskPolicy::RootRw,
    ));
    let result = (|| {
        let vol = mount_id(&dev, HOME_SV).map_err(|_| "@home did not mount")?;
        if !vol.supports_writes() {
            return Err("snapshotted @home refused read-write under root-rw");
        }
        let root = vol.root();
        let narf = poll_once(root.lookup_dir_async("narf"))
            .and_then(Result::ok)
            .ok_or("narf dir")?;
        for i in 0..200 {
            let name = alloc::format!("h{i}");
            let f = poll_once(narf.lookup_async(&name))
                .and_then(Result::ok)
                .ok_or("h file")?;
            if !matches!(poll_once(f.truncate(0)), Some(Ok(())))
                || !matches!(poll_once(f.write(0, b"home rewritten\n")), Some(Ok(_)))
            {
                return Err("rewrite in @home");
            }
        }
        for i in (0..200).step_by(4) {
            let _ = poll_once(narf.unlink(&alloc::format!("h{i}")));
        }
        if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return Err("commit failed");
        }
        check_ref_counts(&vol)
    })();
    narf_block::disk_policy::__set_policy_for_test(None);
    if let Err(why) = result {
        return TestResult::Fail(why);
    }
    match contents(&dev, 260) {
        Some(got) if got == snap => TestResult::Pass,
        _ => TestResult::Fail("the @home snapshot changed"),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_write_home_shared_under_root_rw
);

/// The fixture as Linux left it is self-consistent by the same oracle (so a
/// failure above is NARF's, not the checker's).
fn smoke_btrfs_snapshot_fixture_refs_consistent() -> TestResult {
    let dev = writable_sparse(FIXTURE_SNAPSHOTS_SPARSE);
    match mount_id(&dev, ROOT_SV) {
        Ok(vol) => match check_ref_counts(&vol) {
            Ok(()) => TestResult::Pass,
            Err(why) => TestResult::Fail(why),
        },
        Err(_) => TestResult::Fail("fixture did not mount"),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_snapshot_fixture_refs_consistent
);

/// Full qgroups on a filesystem with snapshots are not recounted (the walk
/// would charge shared blocks to every referencing tree): enabling them and
/// writing leaves the status INCONSISTENT with a rescan pending, so Linux
/// rescans instead of trusting wrong numbers.
fn smoke_btrfs_qgroups_on_snapshotted_fs_marked_inconsistent() -> TestResult {
    const STATUS_INCONSISTENT: u64 = 1 << 2;
    let dev = writable_sparse(FIXTURE_SNAPSHOTS_SPARSE);
    let vol = match mount_id(&dev, ROOT_SV) {
        Ok(v) if v.supports_writes() => v,
        _ => return TestResult::Fail("@ did not mount writable"),
    };
    if !matches!(poll_once(crate::write::quota_enable(&*vol)), Some(Ok(()))) {
        return TestResult::Fail("quota enable failed");
    }
    let root = vol.root();
    let Some(Ok(f)) = poll_once(root.create("after-quota.txt")) else {
        return TestResult::Fail("create failed");
    };
    if !matches!(poll_once(f.write(0, b"q\n")), Some(Ok(2)))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("write/sync under qgroups failed");
    }
    let (root_tree, _) = vol.root_tree_root();
    let Some(Ok((quota_root, _))) = poll_once(crate::roots::find_root(
        &*vol,
        root_tree,
        format::QUOTA_TREE_OBJECTID,
    )) else {
        return TestResult::Fail("no quota tree");
    };
    let key = BtrfsKey::new(0, format::QGROUP_STATUS_KEY, 0);
    match poll_once(btree::find_item(&*vol, quota_root, &key)) {
        Some(Ok(Some(status))) if le64(&status, 16).unwrap_or(0) & STATUS_INCONSISTENT != 0 => {
            TestResult::Pass
        }
        Some(Ok(Some(_))) => TestResult::Fail("qgroups recounted on a snapshotted filesystem"),
        _ => TestResult::Fail("no qgroup status item"),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_qgroups_on_snapshotted_fs_marked_inconsistent
);

/// A read-only mount skips the gate's sharing walk (every metadata extent
/// item: slow on a root with many snapshots); the first read-write request
/// runs it before the core can write.
fn smoke_btrfs_sharing_walk_deferred_for_read_only() -> TestResult {
    let dev = writable_sparse(FIXTURE_SNAPSHOTS_SPARSE);
    let async_dev = narf_block::SyncBlock::new(dev.clone() as Arc<dyn narf_block::BlockDeviceSync>);
    let vol = match poll_once(BtrfsVolume::mount_devices_read_only(
        alloc::vec![async_dev],
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("read-only mount failed"),
    };
    if !vol.is_read_only() || vol.__test_sharing_checked() {
        return TestResult::Fail("a read-only mount ran the sharing walk");
    }
    if !matches!(poll_once(vol.ensure_sharing_checked()), Some(Ok(())))
        || !vol.__test_sharing_checked()
    {
        return TestResult::Fail("the deferred sharing walk did not run");
    }
    if vol.remount_read_write().is_err() || !vol.supports_writes() {
        return TestResult::Fail("remount rw after the walk failed");
    }
    let rw = match mount_id(&dev, ROOT_SV) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("read-write mount failed"),
    };
    if !rw.__test_sharing_checked() {
        return TestResult::Fail("a read-write mount skipped the sharing walk");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_sharing_walk_deferred_for_read_only
);
