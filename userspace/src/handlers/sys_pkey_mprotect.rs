#[allow(unused_imports)]
use super::*;

/// `pkey_mprotect(addr, len, prot, pkey)` — mprotect tagging a range
/// with `pkey`. The key must be -1 (none), 0 (default), or an allocated
/// key; the prot change is applied via the shared mprotect core.
pub(crate) fn sys_pkey_mprotect(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let pkey = a.arg3 as i64;
    if pkey != -1 && pkey != 0 {
        if !(0..16).contains(&pkey) {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
        let task = current_task_id();
        let allocated = PKEY_TABLE
            .lock()
            .as_ref()
            .and_then(|m| m.get(&task).copied())
            .map(|bits| bits & (1 << pkey) != 0)
            .unwrap_or(false);
        if !allocated {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match mprotect_core(&as_ref, VirtAddr::new(a.arg0), a.arg1, a.arg2 as u32) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(()) => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // EINVAL
    }
}
