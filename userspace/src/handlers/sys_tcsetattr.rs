#[allow(unused_imports)]
use super::*;

/// `tcsetattr` ≡ `ioctl(fd, TCSETS, termios)`. Linux `set_termios` copies the
/// termios in with `user_termios_to_kernel_termios` → -EFAULT on a faulting
/// (or NULL) source.
/// LINUX-GAP: the ioctl path first validates the fd (-EBADF) and that it is a
/// tty (-ENOTTY), and rejects an unknown TCSETS/TCSETSW/TCSETSF action; this
/// NARF shim writes the task's termios and ignores `_fd` / `_action`.
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
