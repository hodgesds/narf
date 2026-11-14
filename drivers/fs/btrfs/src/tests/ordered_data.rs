//! Data written outside the transaction (Linux ordered extents): a write
//! carves its extents, writes the data holding no transaction lock, and only
//! then stages the file-extent items — so other operations and commits never
//! queue behind its I/O, and nothing records an extent whose data is not on
//! the device.

use super::commit_handover::{crash_image, poll_n};
use super::*;

/// Hold the next data write before its device write until the guard drops.
struct HoldDataWrite;

impl HoldDataWrite {
    fn new() -> Self {
        use core::sync::atomic::Ordering;
        crate::volume::DATA_WRITE_HELD.store(false, Ordering::Release);
        crate::volume::DATA_WRITE_HOLD.store(true, Ordering::Release);
        HoldDataWrite
    }

    fn held() -> bool {
        crate::volume::DATA_WRITE_HELD.load(core::sync::atomic::Ordering::Acquire)
    }
}

impl Drop for HoldDataWrite {
    fn drop(&mut self) {
        crate::volume::DATA_WRITE_HOLD.store(false, core::sync::atomic::Ordering::Release);
    }
}

fn pattern(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| tag ^ (i as u8).wrapping_mul(29) ^ (i >> 9) as u8)
        .collect()
}

fn reads_back(vol: &Arc<BtrfsVolume<narf_block::SyncBlock>>, name: &str, want: &[u8]) -> bool {
    use narf_filesystem::FsInstance;
    match poll_once(vol.root().lookup_async(name)) {
        Some(Ok(file)) => read_all(&file, want.len() + 16).as_deref() == Some(want),
        _ => false,
    }
}

/// While one file's data write is in flight (held before its device write):
/// another file's write and a namespace operation complete, a commit
/// completes and is durable, and a crash image cut then shows the held file
/// with its old data — never an extent recorded before its data was
/// written. The held write's extent is withheld from every allocator meanwhile
/// (the other write lands elsewhere). Released, the write stages into the
/// open transaction, and after a sync both files hold their new data.
fn write_outside_txn() -> Result<(), &'static str> {
    use narf_filesystem::FsInstance;
    let device = writable_sparse(FIXTURE_FST_SPARSE);
    let vol = mount_writable(device.clone()).map_err(|_| "fixture did not mount")?;
    let root = vol.root();
    let (old_a, new_a, new_b) = (
        pattern(1, 96 * 1024),
        pattern(2, 96 * 1024),
        pattern(3, 80 * 1024),
    );
    let a = match poll_once(root.create("a")) {
        Some(Ok(file)) => file,
        _ => return Err("create a failed"),
    };
    let b = match poll_once(root.create("b")) {
        Some(Ok(file)) => file,
        _ => return Err("create b failed"),
    };
    if !matches!(poll_once(a.write(0, &old_a)), Some(Ok(n)) if n == old_a.len())
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return Err("seeding a failed");
    }
    let base = vol.superblock().generation;
    let hold = HoldDataWrite::new();
    let mut writing = alloc::boxed::Box::pin(a.write(0, &new_a));
    if poll_n(writing.as_mut(), 64).is_some() || !HoldDataWrite::held() {
        return Err("the data write was not held before its device write");
    }
    let carved = vol.inflight_data();
    if carved.is_empty() {
        return Err("the held write's extent is not withheld from allocation");
    }
    // Other operations do not queue behind the held data I/O.
    match poll_once(b.write(0, &new_b)) {
        Some(Ok(n)) if n == new_b.len() => {}
        Some(_) => return Err("a write beside a held data write failed"),
        None => return Err("a write queued behind another file's data I/O"),
    }
    if !matches!(poll_once(root.create("c")), Some(Ok(_))) {
        return Err("a namespace operation queued behind another file's data I/O");
    }
    match poll_once(crate::write::flush_batch(&vol)) {
        Some(Ok(())) => {}
        Some(Err(_)) => return Err("a commit beside a held data write failed"),
        None => return Err("a commit waited for another operation's data I/O"),
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) || vol.durable_gen() <= base {
        return Err("the commit beside a held data write was not made durable");
    }
    // Crash now: the held file is whole, with its old data.
    let cut = mount_writable(crash_image(&device)).map_err(|_| "crash image did not mount")?;
    if !reads_back(&cut, "a", &old_a) {
        return Err("a crash during a data write did not leave the old data");
    }
    if !reads_back(&cut, "b", &new_b) {
        return Err("the committed write beside it is missing after a crash");
    }
    drop(cut);
    // The other write's extents did not take the held one's space.
    let b_extent = file_data_extent(&vol, b.ino()).ok_or("b has no extent")?;
    if carved
        .iter()
        .any(|&(start, len)| b_extent.0 < start + len && start < b_extent.0 + b_extent.1)
    {
        return Err("another write was given the extent of a write in flight");
    }
    drop(hold);
    match poll_n(writing.as_mut(), 1 << 22) {
        Some(Ok(n)) if n == new_a.len() => {}
        Some(_) => return Err("the released data write failed"),
        None => return Err("the released data write never finished"),
    }
    drop(writing);
    if !vol.inflight_data().is_empty() {
        return Err("a staged write's extent stayed withheld");
    }
    if !reads_back(&vol, "a", &new_a) {
        return Err("the released write does not read back");
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("the final sync failed");
    }
    let after = mount_writable(crash_image(&device)).map_err(|_| "remount failed")?;
    if !reads_back(&after, "a", &new_a) || !reads_back(&after, "b", &new_b) {
        return Err("a data write staged after a commit was lost");
    }
    Ok(())
}

fn smoke_btrfs_data_write_holds_no_transaction_lock() -> TestResult {
    match write_outside_txn() {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/commit",
    smoke_btrfs_data_write_holds_no_transaction_lock
);

/// A data write abandoned during its I/O (its future dropped — a killed
/// task's write is handed off and finishes instead) records nothing and
/// gives its carve back: the file keeps its old data, in memory and after a
/// commit and a remount, and the extent is no longer withheld.
fn abandoned_write() -> Result<(), &'static str> {
    use narf_filesystem::FsInstance;
    let device = writable_sparse(FIXTURE_FST_SPARSE);
    let vol = mount_writable(device.clone()).map_err(|_| "fixture did not mount")?;
    let old = pattern(4, 70 * 1024);
    let file = match poll_once(vol.root().create("kept")) {
        Some(Ok(file)) => file,
        _ => return Err("create failed"),
    };
    if !matches!(poll_once(file.write(0, &old)), Some(Ok(n)) if n == old.len()) {
        return Err("seeding failed");
    }
    {
        let _hold = HoldDataWrite::new();
        let new = pattern(5, 70 * 1024);
        let mut writing = alloc::boxed::Box::pin(file.write(0, &new));
        if poll_n(writing.as_mut(), 64).is_some() || !HoldDataWrite::held() {
            return Err("the data write was not held");
        }
        drop(writing);
    }
    if !vol.inflight_data().is_empty() {
        return Err("an abandoned write's extent stayed withheld");
    }
    if vol.txn_joined() {
        return Err("an abandoned write left a join behind");
    }
    if !reads_back(&vol, "kept", &old) {
        return Err("an abandoned write changed the file");
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("the sync after an abandoned write failed");
    }
    let after = mount_writable(crash_image(&device)).map_err(|_| "remount failed")?;
    if !reads_back(&after, "kept", &old) {
        return Err("an abandoned write reached the device");
    }
    Ok(())
}

fn smoke_btrfs_abandoned_data_write_returns_its_extent() -> TestResult {
    match abandoned_write() {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/commit",
    smoke_btrfs_abandoned_data_write_returns_its_extent
);
