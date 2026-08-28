#[allow(unused_imports)]
use super::*;

/// `tcgetattr` ≡ `ioctl(fd, TCGETS, termios)`. Linux `get_termios` copies the
/// ktermios out with `kernel_termios_to_user_termios` → -EFAULT on a faulting
/// (or NULL) destination.
/// NOT a Linux syscall. `Syscall::Tcgetattr` is NARF-native (0x4050) and
/// libc's `tcgetattr(3)` reaches the kernel as `ioctl(fd, TCGETS, …)`, so
/// no Linux-ABI program arrives here — which is why `_fd` being ignored is
/// a design choice about a NARF-only entry point rather than a conformance
/// gap. (It was previously filed as a LINUX-GAP, implying an errno a real
/// caller could observe.) The ioctl path is where -EBADF / -ENOTTY belong.
pub(crate) fn sys_tcgetattr(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _fd = args.arg0;
    let out = args.arg1;
    if out == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    let task = current_task_id();
    let t = termios_of_task(task);
    // Copy KTermios struct to user space under the SMAP bracket.
    // SAFETY: KTermios is repr(C) of POD ints + byte arrays (no padding-sensitive or
    // niche fields); transmuting it to `[u8; size_of::<KTermios>()]` is a 1:1 byte view.
    // SAFETY: Valid memory or trusted environment
    let bytes: [u8; core::mem::size_of::<KTermios>()] = unsafe { core::mem::transmute(t) };
    // SAFETY: `out` is the user termios pointer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out, &bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
