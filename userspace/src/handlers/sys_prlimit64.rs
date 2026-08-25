#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_prlimit64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let resource = args.arg1 as usize;
    let new_ptr = args.arg2;
    let old_ptr = args.arg3;
    // Linux copies the proposed value before PID lookup, permission checks, or
    // resource validation, so an unreadable `new` pointer has EFAULT
    // precedence over ESRCH/EPERM/EINVAL.
    let new_value = if new_ptr != 0 {
        // Read two u64s from user buffer under the SMAP bracket.
        let mut buf = [0u8; 16];
        // SAFETY: `new_ptr` is the user new-rlimit pointer (non-zero, checked);
        // copy_from_user range-validates it and SMAP-brackets the 16-byte read.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_from_user(&mut buf, new_ptr) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
        let cur = u64::from_ne_bytes(buf[..8].try_into().unwrap());
        let max = u64::from_ne_bytes(buf[8..].try_into().unwrap());
        Some(RLimitPair { cur, max })
    } else {
        None
    };

    let caller = current_task_id();
    let Some(task) = prlimit_target_task(caller, pid) else {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
        return;
    };
    if !prlimit_permission(caller, task.tid) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }

    // Snapshot/validate/publish under one process-row transaction. The prior
    // value is what Linux copies out even when a new value is installed.
    let prior = match update_rlimit_atomic(task.tid, resource, new_value) {
        Ok(prior) => prior,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    if old_ptr != 0 {
        // Write two u64s to user buffer under the SMAP bracket.
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&prior.cur.to_ne_bytes());
        buf[8..].copy_from_slice(&prior.max.to_ne_bytes());
        // SAFETY: `old_ptr` is the user old-rlimit pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 16-byte write.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_to_user(old_ptr, &buf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
