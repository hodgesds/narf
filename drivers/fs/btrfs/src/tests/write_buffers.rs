//! What a large single `write` asks of the kernel heap, and what the write
//! path does when the heap says no.

use super::*;
use narf_filesystem::FsInstance;

type BufVol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

/// A mounted `@` of the tall fixture with room for 64 MiB of data.
fn roomy_volume() -> Result<BufVol, &'static str> {
    let vol = mount_writable(writable_sparse(FIXTURE_TALL_SPARSE))
        .map_err(|_| "buffers: fixture did not mount")?;
    if poll_once(vol.switch_to_subvol(&crate::volume::Subvol::Name("@".into())))
        .is_none_or(|r| r.is_err())
    {
        return Err("buffers: subvol @ did not resolve");
    }
    for _ in 0..5 {
        if !matches!(
            poll_once(crate::write::alloc_chunk(&vol, format::BLOCK_GROUP_DATA)),
            Some(Ok(()))
        ) {
            return Err("buffers: chunk allocation failed");
        }
    }
    Ok(vol)
}

/// `len` bytes of a pattern, or `None` if the test's own heap cannot hold
/// them in one piece.
fn pattern(len: usize, seed: u8) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).ok()?;
    v.extend((0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 12) as u8));
    Some(v)
}

/// A write of 1, 8 or 64 MiB in one call builds no data buffer larger than
/// one extent, 128 KiB: the write path lays the call down an extent at a
/// time (Linux works folio by folio). One that held the whole call in one
/// buffer needed a contiguous heap block the size of the write, and the
/// kernel aborted when a fragmented heap had none. Each file reads back as
/// written, its middle overwritten by a second large write that starts and
/// ends inside sectors.
fn smoke_btrfs_large_write_buffers_bounded() -> TestResult {
    let vol = match roomy_volume() {
        Ok(vol) => vol,
        Err(e) => return TestResult::Fail(e),
    };
    let dir = match poll_once(vol.root().mkdir("big")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("buffers: mkdir failed"),
    };
    const MIB: usize = 1 << 20;
    for (index, mib) in [1usize, 8, 64].into_iter().enumerate() {
        let len = mib * MIB;
        // The test's own data is one heap block of the write's size; past
        // a few MiB the test heap may not have one (the very fragmentation
        // the driver no longer depends on). The host harness's `overwrite`
        // scenario writes 64 MiB in one call regardless.
        let Some(body) = pattern(len, index as u8) else {
            if mib > 8 {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "btrfs-buffers: no {mib} MiB block in the test heap for the test's own data; that size is left to the host harness"
                );
                continue;
            }
            return TestResult::Fail("buffers: the test could not allocate its own data");
        };
        let name = alloc::format!("f{mib}");
        let file = match poll_once(dir.create(&name)) {
            Some(Ok(file)) => file,
            _ => return TestResult::Fail("buffers: create failed"),
        };
        crate::databuf::reset_largest();
        if !matches!(poll_once(file.write(0, &body)), Some(Ok(n)) if n == len) {
            return TestResult::Fail("buffers: the large write failed");
        }
        // Over the middle, starting and ending inside sectors, with bytes
        // from elsewhere in the same buffer.
        let (at, over) = (len / 4 + 1000, len / 2);
        let patch = &body[len / 8 + 7..len / 8 + 7 + over];
        if !matches!(poll_once(file.write(at as u64, patch)), Some(Ok(n)) if n == over) {
            return TestResult::Fail("buffers: the overwrite failed");
        }
        if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return TestResult::Fail("buffers: sync failed");
        }
        let largest = crate::databuf::largest();
        if largest > 128 * 1024 {
            return TestResult::Fail("buffers: a write built a data buffer larger than 128 KiB");
        }
        // Read back a page at a time with a stride, plus both seams.
        let mut got = [0u8; 4096];
        let want = |pos: usize| -> u8 {
            if pos >= at && pos < at + over {
                patch[pos - at]
            } else {
                body[pos]
            }
        };
        let mut pos = 0usize;
        let mut checks: Vec<usize> = Vec::new();
        while pos + 4096 <= len {
            checks.push(pos);
            pos += 64 * 1024 + 4096;
        }
        checks.extend([at - 2048, at + over - 2048]);
        for start in checks {
            if !matches!(poll_once(file.read(start as u64, &mut got)), Some(Ok(4096))) {
                return TestResult::Fail("buffers: read failed");
            }
            if (0..4096).any(|i| got[i] != want(start + i)) {
                return TestResult::Fail("buffers: a large write did not read back");
            }
        }
        drop(file);
        if !matches!(poll_once(dir.unlink(&name)), Some(Ok(())))
            || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
        {
            return TestResult::Fail("buffers: unlink failed");
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_large_write_buffers_bounded);

/// A write whose data buffer cannot be allocated fails with `OutOfMemory`
/// (ENOMEM) and changes nothing: the file reads as before and the
/// filesystem goes on writing, also after a remount.
fn smoke_btrfs_write_buffer_failure_is_enomem() -> TestResult {
    let dev = writable_sparse(FIXTURE_TALL_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("enomem: fixture did not mount"),
    };
    let at = crate::volume::Subvol::Name("@".into());
    if poll_once(vol.switch_to_subvol(&at)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("subvol @ did not resolve");
    }
    let file = match poll_once(vol.root().create("kept")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("enomem: create failed"),
    };
    let old = [0x33u8; 8192];
    if !matches!(poll_once(file.write(0, &old)), Some(Ok(8192)))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("enomem: write failed");
    }
    let new = [0x77u8; 256 * 1024];
    // Data buffers of 32 KiB and more fail; tree nodes are smaller.
    crate::databuf::fail_from(Some(32 * 1024));
    let refused = poll_once(file.write(4096, &new));
    crate::databuf::fail_from(None);
    if !matches!(refused, Some(Err(FsError::OutOfMemory))) {
        return TestResult::Fail("enomem: the write was not refused with OutOfMemory");
    }
    let mut got = [0u8; 8192];
    let stat = poll_once(file.stat_async()).and_then(|r| r.ok());
    if stat.map(|s| s.size) != Some(8192)
        || !matches!(poll_once(file.read(0, &mut got)), Some(Ok(8192)))
        || got != old
    {
        return TestResult::Fail("enomem: the refused write changed the file");
    }
    if !matches!(poll_once(file.write(4096, &new)), Some(Ok(n)) if n == new.len())
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("enomem: the filesystem stopped writing");
    }
    drop(file);
    drop(vol);
    let vol = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("enomem: the filesystem did not mount again"),
    };
    if poll_once(vol.switch_to_subvol(&at)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("subvol @ did not resolve again");
    }
    let Some(Ok(file)) = poll_once(vol.root().lookup_async("kept")) else {
        return TestResult::Fail("enomem: the file is gone after a remount");
    };
    let mut tail = [0u8; 4096];
    if !matches!(
        poll_once(file.read(4096 + 128 * 1024, &mut tail)),
        Some(Ok(4096))
    ) || tail.iter().any(|&b| b != 0x77)
    {
        return TestResult::Fail("enomem: the later write did not survive a remount");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_write_buffer_failure_is_enomem
);
