#[allow(unused_imports)]
use super::*;

/// `tcsetattr` ≡ `ioctl(fd, TCSETS, termios)`. Linux `set_termios` copies the
/// termios in with `user_termios_to_kernel_termios` → -EFAULT on a faulting
/// (or NULL) source.
/// NOT a Linux syscall — `Syscall::Tcsetattr` is NARF-native (0x4051), and
/// libc's `tcsetattr(3)` reaches the kernel as `ioctl(fd, TCSETS…)`. No
/// Linux-ABI program arrives here, so ignoring `_fd` / `_action` is a
/// design choice about a NARF-only entry point rather than an observable
/// conformance gap. (It was previously filed as a LINUX-GAP, which implied
/// an errno a real caller could see.) -EBADF, -ENOTTY and the unknown
/// TCSETS/TCSETSW/TCSETSF rejection belong on the ioctl path.
pub(crate) fn sys_tcsetattr(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _fd = args.arg0;
    let _action = args.arg1;
    let in_ptr = args.arg2;
    if in_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    let task = current_task_id();
    let mut bytes = [0u8; core::mem::size_of::<KTermios>()];
    // SAFETY: `in_ptr` is the user termios pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the read into `bytes`.
    if unsafe { copy_from_user(&mut bytes, in_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // SAFETY: `bytes` is `size_of::<KTermios>()` bytes; KTermios is repr(C) of POD
    // ints + byte arrays, so any bit pattern is a valid value — transmute is a 1:1 view.
    // SAFETY: Valid memory or trusted environment
    let t: KTermios = unsafe { core::mem::transmute(bytes) };
    set_termios_of_task(task, t);
    ctx.set_return(SyscallReturn::ok(0));
}
