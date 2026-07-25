#[allow(unused_imports)]
use super::*;

/// `move_pages(pid, count, pages, nodes, status, flags)` — query or move
/// pages across NUMA nodes. A null `nodes` array is the Linux query form:
/// each status entry reports the SRAT node backing that virtual page.
pub(crate) fn sys_move_pages(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let count = a.arg1 as usize;
    let pages_ptr = a.arg2;
    let nodes_ptr = a.arg3;
    let status_ptr = a.arg4;
    let flags = a.arg5;
    if count > (1 << 20) || flags != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if pages_ptr == 0 || status_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    // Page migration needs an atomic backing-frame replacement in
    // AddressSpace. Until that primitive exists, reject the move form
    // instead of claiming success without moving anything.
    if nodes_ptr != 0 {
        ctx.set_return(SyscallReturn::ok((-38i64) as u64)); // ENOSYS
        return;
    }
    let Some(as_ref) = current_address_space() else {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    };

    let mut page_bytes = alloc::vec![0u8; count * 8];
    // SAFETY: copy_from_user range-validates the pointer array.
    if unsafe { copy_from_user(&mut page_bytes, pages_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let mut statuses = alloc::vec![0u8; count * 4];
    for i in 0..count {
        let off = i * 8;
        let va = u64::from_ne_bytes(page_bytes[off..off + 8].try_into().unwrap());
        let status: i32 = mapped_phys(&as_ref, va)
            .map(|phys| numa_node_for_phys(phys) as i32)
            .unwrap_or(-2); // ENOENT: page is not present.
        statuses[i * 4..i * 4 + 4].copy_from_slice(&status.to_ne_bytes());
    }
    // SAFETY: copy_to_user range-validates the status array.
    if unsafe { copy_to_user(status_ptr, &statuses) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
