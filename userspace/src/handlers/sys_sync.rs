#[allow(unused_imports)]
use super::*;

/// `sync()` — Linux `fs/sync.c::ksys_sync`: `syncfs` every mounted
/// filesystem (every superblock once, whichever mount namespace holds it),
/// then flush the write cache of every disk this boot may have written. It
/// returns 0 whatever the per-filesystem results were, as Linux's does
/// (`SYSCALL_DEFINE0(sync)` has no error path).
///
/// Dirty `MAP_SHARED` file pages are committed first, for every file that
/// has any — including files no process has open or mapped any more: the
/// file cache, not any one process's fsync/msync, is what can reach them.
pub(crate) fn sys_sync(ctx: &mut dyn TrapContext) {
    let _ = crate::mapped_file::sync_all_files(None);
    // A fatal signal ends the wait; the sync finishes without this task.
    // `sync(2)` reports nothing either way.
    let _ = crate::killable_wait::sync_all();
    ctx.set_return(SyscallReturn::ok(0));
}
