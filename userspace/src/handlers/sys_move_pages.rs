#[allow(unused_imports)]
use super::*;

/// `move_pages(pid, count, pages, nodes, status, flags)` — query or move
/// pages across NUMA nodes. NARF places everything on node 0, so a status
/// query (or a move) reports node 0 for every page.
pub(crate) fn sys_move_pages(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let count = a.arg1 as usize;
    let status_ptr = a.arg4;
    if count > (1 << 20) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if status_ptr != 0 && count != 0 {
        // i32 zeros => node 0 for each page.
        let zeros = alloc::vec![0u8; count * 4];
        // SAFETY: status_ptr is the user int[count] out-array; copy_to_user
        // range-validates the write.
        if unsafe { copy_to_user(status_ptr, &zeros) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
