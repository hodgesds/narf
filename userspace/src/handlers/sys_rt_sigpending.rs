#[allow(unused_imports)]
use super::*;

/// `rt_sigpending(set_out, sigsetsize)` — Linux `rt_sigpending(2)`.
/// Write the (pending & mask) set to `*set_out` so the caller sees
/// which signals were delivered while blocked.
///
/// arg0 = set out ptr (writable u64 — sigset_t is 8 bytes on
/// glibc x86_64 / aarch64).  arg1 = sigsetsize (must be 8).
pub(crate) fn sys_rt_sigpending(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let set_out = args.arg0;
    let sigsetsize = args.arg1;
    if sigsetsize != 8 || set_out == 0 {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    let task = current_task_id();
    let pending = signal_pending_of(task);
    let mask = signal_mask_of(task);
    // NARF's pending layout == userspace sigset_t (both bit N-1), so the
    // set copies out verbatim — through the SMAP bracket (a raw
    // write_unaligned to the user pointer #PF's under SMAP).
    let user_bits = pending & mask;
    // SAFETY: set_out != 0 checked above; copy_to_user range-validates and
    // SMAP-brackets the 8-byte write.
    if unsafe { copy_to_user(set_out, &user_bits.to_ne_bytes()) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
