#[allow(unused_imports)]
use super::*;

/// `sync()` — Linux `fs/sync.c::ksys_sync`: `syncfs` every mounted
/// filesystem (every superblock once, whichever mount namespace holds it),
/// then flush the write cache of every disk this boot may have written. It
/// returns 0 whatever the per-filesystem results were, as Linux's does
/// (`SYSCALL_DEFINE0(sync)` has no error path).
///
/// LINUX-GAP: dirty `MAP_SHARED` file pages that NARF tracks for explicit
/// writeback (`mapped_file::flush_current_file`) are committed by
/// `fsync`/`msync` on the mapping, not by this global walk.
pub(crate) fn sys_sync(ctx: &mut dyn TrapContext) {
    let _ = sync_all_blocking();
    ctx.set_return(SyscallReturn::ok(0));
}

/// Drive [`narf_filesystem::sync_all::sync_all`] to completion from a
/// synchronous context: a syscall (the stackful task parks on the
/// filesystems' wakers) or, outside a user task, the bounded spin fallback of
/// [`poll_blocking`]. `None` means the fallback gave up before the sync
/// finished.
pub fn sync_all_blocking() -> Option<narf_filesystem::sync_all::SyncReport> {
    poll_blocking(narf_filesystem::sync_all::sync_all())
}

/// The `narf_power::system` pre-shutdown sync hook: every reboot, power-off
/// and halt syncs every filesystem before the device shutdown hooks (NVMe
/// Flush + CC.SHN) run. Installed by [`super::wait_init`].
pub(crate) fn pre_shutdown_sync() {
    use core::fmt::Write as _;
    match sync_all_blocking() {
        Some(r) => {
            let _ = writeln!(
                narf_console::Writer,
                "reboot: synced {} filesystem(s) ({} failed), flushed {} disk(s) ({} failed)",
                r.filesystems,
                r.fs_errors,
                r.disks_flushed,
                r.flush_errors
            );
        }
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "reboot: WARNING: filesystem sync did not complete before shutdown"
            );
        }
    }
}
