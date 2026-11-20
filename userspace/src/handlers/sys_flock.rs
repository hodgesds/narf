#[allow(unused_imports)]
use super::*;

/// `flock(fd, operation)` — `fs/locks.c::SYSCALL_DEFINE2(flock)`:
///
/// ```text
///   if (cmd & LOCK_MAND) return 0;                  /* removed in 5.15 */
///   type = flock_translate_cmd(cmd & ~LOCK_NB);
///   if (type < 0) return type;                      /* -EINVAL */
///   f = fdget(fd); if (fd_empty(f)) return -EBADF;
///   ... locks_lock_file_wait() -> -EWOULDBLOCK when LOCK_NB conflicts
/// ```
///
/// The `-1` sentinel used to cover all three, so the canonical single-instance
/// idiom — `flock(lockfd, LOCK_EX | LOCK_NB)` and treat EWOULDBLOCK as
/// "another copy is already running" — saw EPERM and aborted instead.
pub(crate) fn sys_flock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let op = args.arg1 as u32;
    let task = current_task_id();
    // LOCK_MAND lost its meaning in 5.15; the syscall now warns once and
    // reports success without taking anything.
    const LOCK_MAND: u32 = 32;
    if op & LOCK_MAND != 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // `flock_translate_cmd(cmd & ~LOCK_NB)` runs BEFORE the fd lookup, so a
    // malformed operation outranks a closed descriptor: exactly one of
    // LOCK_SH / LOCK_EX / LOCK_UN, optionally OR'd with LOCK_NB.
    if !matches!(op & !LOCK_NB, LOCK_SH | LOCK_EX | LOCK_UN) {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `CLASS(fd, f)(fd)` is `fdget`, which does not see O_PATH descriptors:
    // an O_PATH fd is -EBADF here, as for read/write.
    // A legacy park abandons these syscall frames with longjmp. Finish the
    // attempt and drop its owned references before either waiting path.
    let acquired = {
        let Some(file) = copy_fd_endpoint(task, fd) else {
            ctx.set_return(errno_ret(EBADF));
            return;
        };
        let arc_ops = &file.ops;
        let file_ptr = alloc::sync::Arc::as_ptr(arc_ops) as *const () as usize;
        // The lock is owned by the open file description (`fl_file`), not the
        // task: dup/fork aliases share one lock, and two independent opens in
        // one process must conflict. Resolve operations and owner together,
        // retaining the description through this attempt even on a close race.
        let owner = file.description.lock_owner();
        let (dev, ino) = (arc_ops.inode_attrs().dev, arc_ops.ino());
        flock_try(file_ptr, op, owner, dev, ino).is_ok()
    };
    if acquired {
        ctx.set_return(SyscallReturn::ok(0));
    } else if op & LOCK_NB != 0 {
        ctx.set_return(errno_ret(EAGAIN));
    } else if has_interrupting_signal(task) {
        ctx.set_return(errno_ret(EINTR));
    } else if !park_reexecute_on_io(ctx) {
        // Synchronous syscall tests have no executor to park.
        ctx.set_return(errno_ret(EAGAIN));
    }
}
