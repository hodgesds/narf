#[allow(unused_imports)]
use super::*;

/// `sigaltstack(ss, old_ss)` — Linux `sigaltstack(2)`.
///
/// `arg0 = ss_in_ptr` (may be 0 — query-only),
/// `arg1 = ss_out_ptr` (may be 0 — install-only).
/// Each `stack_t` is the Linux shape:
///   `{ void *ss_sp; int ss_flags; size_t ss_size }` →
///   `[u64 sp][u32 flags][u32 pad][u64 size]` = 24 bytes.
///
/// Error order follows `do_sys_sigaltstack` + `do_sigaltstack`
/// (kernel/signal.c, Linux 7.0):
///   1. `copy_from_user(&new, uss)` — -EFAULT. The input is read FIRST, so a
///      faulting `ss_in` is -EFAULT even when `ss_out` is valid.
///   2. validate the new stack — -EINVAL for an unknown `ss_mode`
///      (`ss_flags & ~SS_FLAG_BITS` outside {SS_DISABLE, SS_ONSTACK, 0}),
///      then -ENOMEM for `ss_size < MINSIGSTKSZ` unless SS_DISABLE.
///   3. `copy_to_user(uoss, &old)` — -EFAULT, and ONLY when the install did
///      not error (`if (!err && uoss)`): a rejected install never writes the
///      old-stack out-param, and the snapshot is the PRE-install state.
///
/// LINUX-GAP: `on_sig_stack(sp)` → -EPERM (changing the altstack while
/// executing on it) is not enforced — NARF does not track the faulting user
/// sp relative to the active altstack here.
pub(crate) fn sys_sigaltstack(ctx: &mut dyn TrapContext) {
    sigaltstack_table_init();
    let args = *ctx.args();
    let ss_in = args.arg0;
    let ss_out = args.arg1;
    let task = current_task_id();

    // (1) Read the new stack FIRST — Linux copies `uss` in before it touches
    // `uoss`, so a faulting `ss_in` is -EFAULT even when `ss_out` is valid.
    let new_entry = if ss_in != 0 {
        let mut buf = [0u8; 24];
        // SAFETY: `ss_in` is the user new `stack_t` pointer (non-zero, checked);
        // copy_from_user range-validates it and SMAP-brackets the 24-byte read.
        if unsafe { copy_from_user(&mut buf, ss_in) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
        let sp = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let flags = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        let size = u64::from_ne_bytes(buf[16..24].try_into().unwrap());

        // (2) Validate before any state change. `ss_mode` is the flag word
        // minus SS_FLAG_BITS; it must be exactly SS_DISABLE, SS_ONSTACK, or 0.
        if (flags & !(SS_DISABLE | SS_ONSTACK)) != 0 {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
        if (flags & SS_DISABLE) == 0 && size < MIN_SIGSTKSZ {
            ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // -ENOMEM
            return;
        }
        Some(SigAltStack { sp, flags, size })
    } else {
        None
    };

    // The old-stack snapshot is the PRE-install state (Linux fills `oss` at the
    // top of do_sigaltstack, before the install).
    let current = sigaltstack_of(task);

    // (3) Install the validated new stack. Only after validation succeeds may
    // the out-param be written (Linux `if (!err && uoss)`); a committed install
    // then a faulting copy-out still returns -EFAULT, matching Linux.
    if let Some(entry) = new_entry {
        let mut g = SIG_ALTSTACK.lock();
        if let Some(map) = g.as_mut() {
            map.insert(task, entry);
        }
    }

    if ss_out != 0 {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&current.sp.to_ne_bytes());
        buf[8..12].copy_from_slice(&current.flags.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        buf[16..24].copy_from_slice(&current.size.to_ne_bytes());
        // SAFETY: `ss_out` is the user old `stack_t` pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 24-byte write.
        if unsafe { copy_to_user(ss_out, &buf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
