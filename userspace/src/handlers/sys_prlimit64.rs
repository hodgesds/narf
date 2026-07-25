#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_prlimit64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let resource = args.arg1 as usize;
    let new_ptr = args.arg2;
    let old_ptr = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    // pid = 0 means "self"; non-zero pids are routed to that task
    // unconditionally (no permission check today — capabilities
    // would gate cross-task rlimit mutation in a real model).
    let task = if pid == 0 { current_task_id() } else { pid };

    // Validate resource bound up-front so the read+write is atomic
    // from the user's perspective.
    if resource >= RLIMIT_COUNT {
        ctx.set_return(fail);
        return;
    }

    // Snapshot prior so we can write `*old` *after* the update.
    let prior = read_rlimit(task, resource).unwrap_or_default();

    if new_ptr != 0 {
        // Read two u64s from user buffer under the SMAP bracket.
        let mut buf = [0u8; 16];
        // SAFETY: `new_ptr` is the user new-rlimit pointer (non-zero, checked);
        // copy_from_user range-validates it and SMAP-brackets the 16-byte read.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_from_user(&mut buf, new_ptr) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        let cur = u64::from_ne_bytes(buf[..8].try_into().unwrap());
        let max = u64::from_ne_bytes(buf[8..].try_into().unwrap());
        if !write_rlimit(task, resource, RLimitPair { cur, max }) {
            ctx.set_return(fail);
            return;
        }
    }
    if old_ptr != 0 {
        // Write two u64s to user buffer under the SMAP bracket.
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&prior.cur.to_ne_bytes());
        buf[8..].copy_from_slice(&prior.max.to_ne_bytes());
        // SAFETY: `old_ptr` is the user old-rlimit pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 16-byte write.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_to_user(old_ptr, &buf) }.is_err() {
            ctx.set_return(fail);
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
