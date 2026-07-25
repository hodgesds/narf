#[allow(unused_imports)]
use super::*;

/// `sigaltstack(ss, old_ss)` — Linux `sigaltstack(2)`.
///
/// `arg0 = ss_in_ptr` (may be 0 — query-only),
/// `arg1 = ss_out_ptr` (may be 0 — install-only).
/// Each `stack_t` is the Linux shape:
///   `{ void *ss_sp; int ss_flags; size_t ss_size }` →
///   `[u64 sp][u32 flags][u32 pad][u64 size]` = 24 bytes.
/// Returns 0 on success, -1 on rejection (size < MIN_SIGSTKSZ,
/// unknown flag bits, or both pointers 0 and no current entry).
pub(crate) fn sys_sigaltstack(ctx: &mut dyn TrapContext) {
    sigaltstack_table_init();
    let args = *ctx.args();
    let ss_in = args.arg0;
    let ss_out = args.arg1;
    let task = current_task_id();

    let current = sigaltstack_of(task);

    // Write the prior entry to *ss_out first (Linux semantics:
    // even if the *ss_in install fails, the query result is the
    // pre-install state).
    if ss_out != 0 {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&current.sp.to_ne_bytes());
        buf[8..12].copy_from_slice(&current.flags.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        buf[16..24].copy_from_slice(&current.size.to_ne_bytes());
        // SAFETY: `ss_out` is the user old `stack_t` pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 24-byte write.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_to_user(ss_out, &buf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    }

    if ss_in != 0 {
        let mut buf = [0u8; 24];
        // SAFETY: `ss_in` is the user new `stack_t` pointer (non-zero, checked);
        // copy_from_user range-validates it and SMAP-brackets the 24-byte read.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_from_user(&mut buf, ss_in) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        let sp = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let flags = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        let size = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
        // Validate: flags must be a subset of {SS_DISABLE, SS_ONSTACK},
        // and if not SS_DISABLE the size must meet MIN_SIGSTKSZ.
        if (flags & !(SS_DISABLE | SS_ONSTACK)) != 0 {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        if (flags & SS_DISABLE) == 0 && size < MIN_SIGSTKSZ {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        let mut g = SIG_ALTSTACK.lock();
        if let Some(map) = g.as_mut() {
            map.insert(task, SigAltStack { sp, flags, size });
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
