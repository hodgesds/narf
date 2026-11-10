use super::*;
use core::sync::atomic::Ordering;
use narf_filesystem::FsInstance;

fn cache_handle(vol: &BtrfsVolume<narf_block::SyncBlock>) -> crate::decompress_cache::VolumeRef {
    let core = Arc::downgrade(vol.core());
    crate::decompress_cache::VolumeRef::new(core)
}

/// A warm uncompressed window must perform no further device reads. Check
/// both a complete fixture file and an unaligned, multi-sector subrange.
fn smoke_btrfs_plain_cache_avoids_repeated_device_reads() -> TestResult {
    let dev = writable_sparse(FIXTURE_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        _ => return TestResult::Fail("plain fixture mount failed"),
    };
    let file = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("plain file lookup failed"),
    };
    let expected = expected_big();
    for (offset, length) in [(0, expected.len()), (117, 8873)] {
        let mut bytes = alloc::vec![0; length];
        if poll_once(file.read(offset as u64, &mut bytes)) != Some(Ok(length))
            || bytes != expected[offset..offset + length]
        {
            return TestResult::Fail("cold plain window returned wrong bytes");
        }
        let before = dev.reads.load(Ordering::Relaxed);
        bytes.fill(0);
        if poll_once(file.read(offset as u64, &mut bytes)) != Some(Ok(length))
            || bytes != expected[offset..offset + length]
        {
            return TestResult::Fail("warm plain window returned wrong bytes");
        }
        if dev.reads.load(Ordering::Relaxed) != before {
            return TestResult::Fail("warm plain window still issued device reads");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_plain_cache_avoids_repeated_device_reads
);

fn smoke_btrfs_plain_cache_observes_alias_write_and_truncate() -> TestResult {
    let vol = match mount_writable(writable_sparse(FIXTURE_SPARSE)) {
        Ok(v) => v,
        _ => return TestResult::Fail("plain fixture mount failed"),
    };
    let root = vol.root();
    if poll_once(root.link("big.dat", "alias")) != Some(Ok(())) {
        return TestResult::Fail("hard link failed");
    }
    let (Some(Ok(file)), Some(Ok(alias))) = (
        poll_once(root.lookup_async("big.dat")),
        poll_once(root.lookup_async("alias")),
    ) else {
        return TestResult::Fail("alias lookup failed");
    };
    let mut expected = expected_big();
    let mut bytes = alloc::vec![0; expected.len()];
    if poll_once(file.read(0, &mut bytes)) != Some(Ok(expected.len())) || bytes != expected {
        return TestResult::Fail("plain warmup failed");
    }
    let patch = [b'Z'; 128];
    if poll_once(alias.write(117, &patch)) != Some(Ok(patch.len())) {
        return TestResult::Fail("alias overwrite failed");
    }
    expected[117..117 + patch.len()].copy_from_slice(&patch);
    if poll_once(file.read(0, &mut bytes)) != Some(Ok(expected.len())) || bytes != expected {
        return TestResult::Fail("alias overwrite left stale cached bytes");
    }
    if poll_once(alias.truncate(8192)) != Some(Ok(()))
        || poll_once(file.read(0, &mut bytes)) != Some(Ok(8192))
        || bytes[..8192] != expected[..8192]
    {
        return TestResult::Fail("cached read did not observe truncate EOF");
    }
    if poll_once(alias.truncate(expected.len() as u64)) != Some(Ok(())) {
        return TestResult::Fail("re-extension failed");
    }
    expected[8192..].fill(0);
    if poll_once(file.read(0, &mut bytes)) != Some(Ok(expected.len())) || bytes != expected {
        return TestResult::Fail("re-extension returned stale cached tail bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_plain_cache_observes_alias_write_and_truncate
);

/// A raw logical overwrite invalidates a cached range. The deliberately bad
/// data must then fail its old checksum, and the failed read must stay uncached.
fn smoke_btrfs_plain_cache_preserves_checksum_errors() -> TestResult {
    let vol = match mount_writable(writable_sparse(FIXTURE_SPARSE)) {
        Ok(v) => v,
        _ => return TestResult::Fail("plain fixture mount failed"),
    };
    let file = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("plain lookup failed"),
    };
    let mut bytes = alloc::vec![0; 8192];
    if poll_once(file.read(0, &mut bytes)) != Some(Ok(bytes.len())) {
        return TestResult::Fail("plain warmup failed");
    }
    let body = match poll_once(btree::find_item(
        &vol,
        vol.fs_tree_root().0,
        &BtrfsKey::new(file.ino(), format::EXTENT_DATA_KEY, 0),
    )) {
        Some(Ok(Some(body))) => body,
        _ => return TestResult::Fail("file extent not found"),
    };
    let logical = match (format::le64(&body, 21), format::le64(&body, 37)) {
        (Ok(base), Ok(offset)) => base + offset,
        _ => return TestResult::Fail("file extent invalid"),
    };
    // Starts inside the second sector of the cached window.
    let poison = alloc::vec![0xa5; vol.sectorsize() as usize];
    if poll_once(vol.write_logical(logical + u64::from(vol.sectorsize()), &poison)) != Some(Ok(()))
    {
        return TestResult::Fail("could not inject bad data");
    }
    let handle = cache_handle(&vol);
    for _ in 0..2 {
        if poll_once(file.read(0, &mut bytes)) != Some(Err(FsError::InvalidData)) {
            return TestResult::Fail("cache hid a checksum failure");
        }
        if crate::decompress_cache::cached_bytes_for(&handle) != 0 {
            return TestResult::Fail("checksum-failing window entered cache");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_plain_cache_preserves_checksum_errors
);

fn smoke_btrfs_plain_cache_bypasses_unverified_views() -> TestResult {
    let dev = writable_sparse(FIXTURE_SPARSE);
    let block = narf_block::SyncBlock::new(dev.clone() as Arc<dyn narf_block::BlockDeviceSync>);
    let vol = match poll_once(BtrfsVolume::mount_opts(block, DomainId::DRIVER_0, false)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("unverified fixture mount failed"),
    };
    let file = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("plain lookup failed"),
    };
    let mut bytes = [0; 4096];
    for _ in 0..2 {
        let before = dev.reads.load(Ordering::Relaxed);
        if poll_once(file.read(0, &mut bytes)) != Some(Ok(bytes.len()))
            || bytes[..] != expected_big()[..bytes.len()]
            || dev.reads.load(Ordering::Relaxed) <= before
        {
            return TestResult::Fail("unverified read used the verified cache");
        }
    }
    let handle = cache_handle(&vol);
    if crate::decompress_cache::cached_bytes_for(&handle) != 0 {
        return TestResult::Fail("unverified bytes populated shared cache");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_plain_cache_bypasses_unverified_views
);

/// Pending data has no committed checksum yet. An unchecked read must not
/// become a trusted cache hit after that checksum is installed at fsync.
fn smoke_btrfs_plain_cache_does_not_trust_missing_checksums() -> TestResult {
    let vol = match mount_writable(writable_sparse(FIXTURE_SPARSE)) {
        Ok(v) => v,
        _ => return TestResult::Fail("plain fixture mount failed"),
    };
    let file = match poll_once(vol.root().create("pending")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("pending create failed"),
    };
    let payload = alloc::vec![0x6d; 8192];
    if poll_once(file.write(0, &payload)) != Some(Ok(payload.len())) {
        return TestResult::Fail("pending write failed");
    }
    let body = match poll_once(btree::find_item(
        &vol,
        vol.fs_tree_root().0,
        &BtrfsKey::new(file.ino(), format::EXTENT_DATA_KEY, 0),
    )) {
        Some(Ok(Some(body))) => body,
        _ => return TestResult::Fail("pending extent not found"),
    };
    let logical = match (format::le64(&body, 21), format::le64(&body, 37)) {
        (Ok(base), Ok(offset)) => base + offset,
        _ => return TestResult::Fail("pending extent invalid"),
    };
    let csum_root = match poll_once(crate::roots::find_root(
        &vol,
        vol.root_tree_root().0,
        format::CSUM_TREE_OBJECTID,
    )) {
        Some(Ok((root, _))) => root,
        _ => return TestResult::Fail("checksum root missing"),
    };
    if !matches!(
        poll_once(crate::csum::find_csum(
            &vol,
            csum_root,
            logical,
            u64::from(vol.sectorsize())
        )),
        Some(Ok(None))
    ) {
        return TestResult::Fail("test needs an uncommitted data checksum");
    }
    let mut poison = payload.clone();
    poison[0] ^= 1;
    if poll_once(vol.write_logical(logical, &poison)) != Some(Ok(())) {
        return TestResult::Fail("pending data fault injection failed");
    }
    let mut bytes = alloc::vec![0; payload.len()];
    if poll_once(file.read(0, &mut bytes)) != Some(Ok(bytes.len())) || bytes != poison {
        return TestResult::Fail("existing missing-checksum read policy changed");
    }
    if crate::decompress_cache::cached_bytes_for(&cache_handle(&vol)) != 0 {
        return TestResult::Fail("unchecked pending bytes entered the verified cache");
    }
    if poll_once(file.fsync(false)) != Some(Ok(())) {
        return TestResult::Fail("pending checksum commit failed");
    }
    if poll_once(file.read(0, &mut bytes)) != Some(Err(FsError::InvalidData)) {
        return TestResult::Fail("unchecked cache fill hid the newly committed checksum");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_plain_cache_does_not_trust_missing_checksums
);

fn smoke_btrfs_plain_cache_bounds_and_epoch() -> TestResult {
    use crate::decompress_cache::{self as cache, ExtentId, VolumeRef};
    let owner: Arc<dyn core::any::Any + Send + Sync> = Arc::new(0u64);
    let handle = VolumeRef::new(Arc::downgrade(&owner));
    let key = VolumeRef::key_of(Arc::as_ptr(&owner) as *const u8);
    let id = ExtentId {
        disk_bytenr: 1 << 20,
        disk_num_bytes: cache::MAX_DISK_BYTES,
        compression: format::COMPRESS_NONE,
        generation: 7,
    };
    let bytes = Arc::new(alloc::vec![0x5a; id.disk_num_bytes as usize]);
    cache::insert(&handle, id, cache::epoch(&handle), bytes.clone());
    if cache::get(&handle, id).is_none() {
        return TestResult::Fail("maximal window not cached");
    }
    cache::invalidate(key, id.disk_bytenr + id.disk_num_bytes - 1, 1);
    if cache::get(&handle, id).is_some() {
        return TestResult::Fail("tail overwrite left maximal window cached");
    }
    let epoch = cache::epoch(&handle);
    cache::invalidate(key, 1 << 30, 1);
    cache::insert(&handle, id, epoch, bytes.clone());
    if cache::get(&handle, id).is_some() {
        return TestResult::Fail("fill crossed a write epoch");
    }
    let oversized = ExtentId {
        disk_num_bytes: id.disk_num_bytes + 1,
        ..id
    };
    cache::insert(&handle, oversized, cache::epoch(&handle), bytes.clone());
    let short = ExtentId {
        disk_num_bytes: 4096,
        ..id
    };
    cache::insert(&handle, short, cache::epoch(&handle), bytes);
    if cache::get(&handle, oversized).is_some() || cache::get(&handle, short).is_some() {
        return TestResult::Fail("invalid span/length window cached");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_plain_cache_bounds_and_epoch
);
