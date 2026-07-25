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
    const MPOL_MF_MOVE: u64 = 1 << 1;
    const MPOL_MF_MOVE_ALL: u64 = 1 << 2;
    if count > (1 << 20) || flags & !(MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if flags & MPOL_MF_MOVE_ALL != 0 {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM: no root/ambient privilege.
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
    let task = current_task_id();
    let visible_pid = task_to_pid_raw(task).unwrap_or(task);
    let requested_pid = a.arg0;
    if requested_pid != 0 && requested_pid != task && requested_pid != visible_pid {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM: foreign process.
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
    let mut node_bytes = if nodes_ptr != 0 {
        let mut bytes = alloc::vec![0u8; count * 4];
        // SAFETY: copy_from_user range-validates the target-node array.
        if unsafe { copy_from_user(&mut bytes, nodes_ptr) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
        Some(bytes)
    } else {
        None
    };
    let mut statuses = alloc::vec![0u8; count * 4];
    let mut not_moved = 0u64;
    for i in 0..count {
        let off = i * 8;
        let va = u64::from_ne_bytes(page_bytes[off..off + 8].try_into().unwrap());
        let status: i32 = if let Some(nodes) = node_bytes.as_mut() {
            let noff = i * 4;
            let target = i32::from_ne_bytes(nodes[noff..noff + 4].try_into().unwrap());
            if target < 0 || target as u32 >= numa_node_count() {
                not_moved += 1;
                -22 // EINVAL
            } else {
                // SAFETY: the live current AS owns its root and backing list.
                match unsafe { as_ref.migrate_page_to_node(VirtAddr::new(va), target as usize) } {
                    Ok(_) => target,
                    Err(narf_memory::AddressSpaceError::Unmapped) => {
                        not_moved += 1;
                        -2 // ENOENT
                    }
                    Err(narf_memory::AddressSpaceError::SharedMapping) => {
                        not_moved += 1;
                        -13 // EACCES
                    }
                    Err(narf_memory::AddressSpaceError::InvalidNode) => {
                        not_moved += 1;
                        -22 // EINVAL
                    }
                    Err(_) => {
                        not_moved += 1;
                        -12 // ENOMEM / replacement failure
                    }
                }
            }
        } else {
            mapped_phys(&as_ref, va)
                .map(|phys| numa_node_for_phys(phys) as i32)
                .unwrap_or(-2) // ENOENT: page is not present.
        };
        statuses[i * 4..i * 4 + 4].copy_from_slice(&status.to_ne_bytes());
    }
    // SAFETY: copy_to_user range-validates the status array.
    if unsafe { copy_to_user(status_ptr, &statuses) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(not_moved));
}
