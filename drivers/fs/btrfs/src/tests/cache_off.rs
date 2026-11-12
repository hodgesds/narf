//! `btrfs.data_cache=0`: every extent-data lookup misses. A miss must only
//! cost time — the read decompresses or re-reads what the cache would have
//! held — and never leave a read waiting.

use super::*;
use narf_filesystem::FsInstance;

/// Read `file` a page at a time, as demand paging does; `None` if a read
/// did not complete or came back short.
fn read_by_pages(file: &Arc<dyn narf_filesystem::FileOps>, len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    let mut page = [0u8; 4096];
    while out.len() < len {
        let n = match poll_once(file.read(out.len() as u64, &mut page)) {
            Some(Ok(n)) => n,
            _ => return None,
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&page[..n]);
    }
    Some(out)
}

fn check() -> Result<(), &'static str> {
    use core::fmt::Write as _;
    let vol = mount_sparse(FIXTURE_ZSTD_SPARSE).map_err(|_| "zstd fixture failed to mount")?;
    let big = poll_once(vol.root().lookup_async("big.dat"))
        .and_then(|r| r.ok())
        .ok_or("lookup big.dat failed")?;
    let want = expected_big();
    let (_, misses_before) = crate::decompress_cache::stats();
    let started = narf_time::now_cycles();
    let paged =
        read_by_pages(&big, want.len()).ok_or("a page read with the cache off did not complete")?;
    let off_cycles = narf_time::now_cycles().saturating_sub(started);
    if paged != want {
        return Err("page reads with the cache off returned the wrong bytes");
    }
    if read_all(&big, want.len() + 16).as_deref() != Some(&want[..]) {
        return Err("a whole read with the cache off returned the wrong bytes");
    }
    let (hits_off, misses_after) = crate::decompress_cache::stats();
    if misses_after <= misses_before {
        return Err("the reads did not go past the disabled cache");
    }
    // Every file of the fixture, a page at a time.
    let entries = poll_once(vol.root().enumerate_async(0, 4096))
        .and_then(|r| r.ok())
        .ok_or("enumerate failed")?;
    for (name, _) in &entries {
        if let Some(Ok(file)) = poll_once(vol.root().lookup_async(name)) {
            let size = poll_once(file.stat_async())
                .and_then(|r| r.ok())
                .map_or(0, |s| s.size as usize);
            if read_by_pages(&file, size).is_none_or(|b| b.len() != size) {
                return Err("a file read a page at a time with the cache off did not complete");
            }
        }
    }
    // The same page reads with the cache on, for the cost of a miss.
    crate::decompress_cache::set_enabled_for_test(true);
    let started = narf_time::now_cycles();
    let paged = read_by_pages(&big, want.len());
    let on_cycles = narf_time::now_cycles().saturating_sub(started);
    let (hits_on, _) = crate::decompress_cache::stats();
    if paged.as_deref() != Some(&want[..]) || hits_on <= hits_off {
        return Err("page reads with the cache back on were wrong or missed");
    }
    let _ = writeln!(
        narf_console::Writer,
        "btrfs data cache off: {} page reads of a zstd file took {off_cycles} cycles, {on_cycles} with the cache",
        want.len().div_ceil(4096)
    );
    Ok(())
}

/// The zstd fixture read with the extent-data cache disabled: page reads,
/// whole reads and every file of the image complete with the right bytes.
fn smoke_btrfs_reads_complete_with_the_data_cache_off() -> TestResult {
    crate::decompress_cache::set_enabled_for_test(false);
    let result = check();
    crate::decompress_cache::set_enabled_for_test(true);
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_reads_complete_with_the_data_cache_off
);
