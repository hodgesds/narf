#[allow(unused_imports)]
use super::*;

/// `fs/eventfd.c`: `EFD_SEMAPHORE` is bit 0, and the other two alias the
/// open flags they are named after — `BUILD_BUG_ON(EFD_CLOEXEC != O_CLOEXEC)`
/// and `BUILD_BUG_ON(EFD_NONBLOCK != O_NONBLOCK)`.
const EFD_SEMAPHORE: u32 = 1;

fn eventfd_flags_set() -> u32 {
    EFD_SEMAPHORE | crate::fd::O_CLOEXEC | crate::fd::O_NONBLOCK
}

/// Shared body for both entry points. `flags` is whatever the caller's
/// syscall number actually carries — see [`sys_eventfd`] for why the legacy
/// form must not read one.
fn create_eventfd(ctx: &mut dyn TrapContext, initval: u64, flags: u32) {
    // `do_eventfd`: `if (flags & ~EFD_FLAGS_SET) return -EINVAL;`. Accepting
    // an unknown bit silently hands back a descriptor that does not have the
    // semantics the caller asked for — the failure then shows up much later,
    // as a counter that never behaves like a semaphore.
    if flags & !eventfd_flags_set() != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let efd = crate::io_mux::EventFd::new(initval, flags);
    let task = current_task_id();
    let new_fd = fd::install(task, crate::fd::FdEntry {
            ops: efd,
            offset: 0,
            flags: if flags & crate::fd::O_CLOEXEC != 0 {
                crate::fd::FD_CLOEXEC
            } else {
                0
            },
            status_flags: crate::fd::O_RDWR
                | if flags & crate::fd::O_NONBLOCK != 0 {
                    crate::fd::O_NONBLOCK
                } else {
                    0
                },
        });
    match new_fd {
        // LINUX-GAP: a table that cannot allocate is -EMFILE, not -EINVAL.
        // NARF's fd table grows without bound today, so this arm is
        // unreachable; RLIMIT_NOFILE enforcement is its own change.
        None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
        Some(fd) => ctx.set_return(SyscallReturn::ok(fd as u64)),
    }
}

/// `eventfd2(initval, flags)` — x86_64 290, aarch64 19. The form every libc
/// `eventfd()` wrapper actually issues.
///
/// `SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags)`: the initial
/// counter is a 32-BIT argument. Reading the register as a full u64 seeded a
/// counter Linux would have truncated — `eventfd2(1 << 32, 0)` starts at zero
/// there and at 4294967296 here, so the first read returns a value that never
/// existed and the semaphore drains 2^32 times instead of not at all.
pub(crate) fn sys_eventfd2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    create_eventfd(ctx, u64::from(args.arg0 as u32), args.arg1 as u32);
}

/// `eventfd(initval)` — the original one-argument call, x86_64 284 only.
///
/// `SYSCALL_DEFINE1(eventfd, unsigned int, count)` is
/// `return do_eventfd(count, 0);` — there is no flag word, so arg1 holds
/// whatever the caller left in `rsi`. Reading it as flags (which this handler
/// did while both numbers shared one implementation) gave a caller a
/// CLOEXEC or NONBLOCK descriptor it never asked for, or -EINVAL, entirely
/// according to register garbage.
pub(crate) fn sys_eventfd(ctx: &mut dyn TrapContext) {
    // `SYSCALL_DEFINE1(eventfd, unsigned int, count)` — 32-bit, as above.
    let initval = u64::from(ctx.args().arg0 as u32);
    create_eventfd(ctx, initval, 0);
}
