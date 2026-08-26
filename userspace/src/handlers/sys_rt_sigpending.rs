#[allow(unused_imports)]
use super::*;

/// `rt_sigpending(set_out, sigsetsize)` — Linux `rt_sigpending(2)`.
/// Write the (pending & mask) set to `*set_out` so the caller sees
/// which signals were delivered while blocked.
///
/// arg0 = set out ptr (writable — sigset_t is 8 bytes on
/// glibc x86_64 / aarch64).  arg1 = sigsetsize.
///
/// Error order follows `SYSCALL_DEFINE2(rt_sigpending)` (kernel/signal.c,
/// Linux 7.0):
///   - `sigsetsize > sizeof(sigset_t)` → -EINVAL (a SMALLER size is legal —
///     the kernel copies only that many low bytes of the set),
///   - `copy_to_user` failure (a faulting or NULL `set_out`) → -EFAULT.
pub(crate) fn sys_rt_sigpending(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let set_out = args.arg0;
    let sigsetsize = args.arg1 as usize;
    if sigsetsize > 8 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let task = current_task_id();
    let pending = signal_pending_of(task);
    let mask = signal_mask_of(task);
    // NARF's pending layout == userspace sigset_t (both bit N-1), so the
    // set copies out verbatim — through the SMAP bracket (a raw
    // write_unaligned to the user pointer #PF's under SMAP). Copy exactly
    // `sigsetsize` low bytes, as Linux does (NULL/faulting → -EFAULT).
    let user_bits = (pending & mask).to_ne_bytes();
    if unsafe { copy_to_user(set_out, &user_bits[..sigsetsize]) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
