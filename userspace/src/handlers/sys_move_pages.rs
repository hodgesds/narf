#[allow(unused_imports)]
use super::*;

fn migrate_registry_shared_page(
    current: &Arc<AddressSpace>,
    va: u64,
    target: usize,
) -> Result<(), narf_memory::AddressSpaceError> {
    let vtable = shmem_vtable().ok_or(narf_memory::AddressSpaceError::SharedMapping)?;

    narf_memory::with_shared_mapping_transaction(|| {
        let old_phys = mapped_phys(current, va).ok_or(narf_memory::AddressSpaceError::Unmapped)?;
        if !(vtable.owns_frame)(old_phys) {
            // Device/DMA frames require their owner's quiesce/remap protocol.
            return Err(narf_memory::AddressSpaceError::SharedMapping);
        }
        if (vtable.frame_locked)(old_phys) {
            return Err(narf_memory::AddressSpaceError::LockFailed);
        }
        let old = narf_memory::PhysAddr::new(old_phys);
        if numa_node_for_phys(old_phys) as usize == target {
            return Ok(());
        }
        let new_frame = narf_memory::alloc_frame_on_strict(target)
            .map_err(|_| narf_memory::AddressSpaceError::OutOfRange)?;
        let new = new_frame.start_address();
        // SAFETY: owner validation and copy are serialized with replacement;
        // new is a distinct owned frame.
        unsafe {
            core::ptr::copy_nonoverlapping(
                old.kernel_ptr::<u8>(),
                new.kernel_mut_ptr::<u8>(),
                narf_memory::PAGE_SIZE as usize,
            );
        }
        let mut spaces = all_address_spaces();
        if !spaces
            .iter()
            .any(|candidate| Arc::ptr_eq(candidate, current))
        {
            spaces.push(current.clone());
        }
        let mut changed: alloc::vec::Vec<Arc<AddressSpace>> = alloc::vec::Vec::new();
        for address_space in spaces {
            // SAFETY: the transaction lock excludes new shared aliases and
            // both frames remain live until owner commit.
            match unsafe { address_space.replace_shared_frame(old, new) } {
                Ok(0) => {}
                Ok(_) => changed.push(address_space),
                Err(error) => {
                    for prior in changed.iter().rev() {
                        // SAFETY: exact inverse while both frames remain live.
                        let _ = unsafe { prior.replace_shared_frame(new, old) };
                    }
                    narf_memory::free_frame(new_frame);
                    return Err(error);
                }
            }
        }
        if !(vtable.replace_frame)(old_phys, new.raw()) {
            for prior in changed.iter().rev() {
                // SAFETY: registry rejected commit; restore every alias.
                let _ = unsafe { prior.replace_shared_frame(new, old) };
            }
            narf_memory::free_frame(new_frame);
            return Err(narf_memory::AddressSpaceError::SharedMapping);
        }
        narf_memory::free_frame(narf_memory::PhysFrame::new(old));
        Ok(())
    })
}

/// `move_pages(pid, count, pages, nodes, status, flags)` — query or move
/// pages across NUMA nodes. A null `nodes` array is the Linux query form:
/// each status entry reports the SRAT node backing that virtual page.
///
/// `mm/migrate.c::kernel_move_pages`, then `find_mm_struct`:
///
/// ```text
///     if (flags & ~(MPOL_MF_MOVE|MPOL_MF_MOVE_ALL))        return -EINVAL;
///     if ((flags & MPOL_MF_MOVE_ALL) && !capable(CAP_SYS_NICE)) return -EPERM;
///     mm = find_mm_struct(pid, &task_nodes);
///         if (!pid) return current->mm;
///         task = find_get_task_by_vpid(pid);
///         if (!task)                          return ERR_PTR(-ESRCH);
///         if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
///                                             mm = ERR_PTR(-EPERM);
///     ... then do_pages_move()/do_pages_stat() read `pages`/`status`  /* -EFAULT */
/// ```
///
/// Two things follow that this handler used to get wrong.
///
/// **ESRCH vs EPERM for an unresolvable pid.** `numactl`, `migratepages`, and
/// every NUMA autobalancer scanning `/proc` hit dead pids constantly; ESRCH is
/// "skip it", EPERM is "you lack CAP_SYS_NICE" and aborts the sweep.
///
/// **The target task is resolved before the page/status arrays are touched**,
/// so a stale pid beats a null `pages` pointer. Checking the pointers first
/// answered EFAULT for a request Linux answers ESRCH.
///
/// `flags` is an `int`: only the low 32 bits are the caller's request, so a
/// caller whose libc wrapper leaves junk in the high half of `r9` must not be
/// told its flags are invalid.
pub(crate) fn sys_move_pages(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let count = a.arg1 as usize;
    let pages_ptr = a.arg2;
    let nodes_ptr = a.arg3;
    let status_ptr = a.arg4;
    let flags = a.arg5 as u32;
    const MPOL_MF_MOVE: u32 = 1 << 1;
    const MPOL_MF_MOVE_ALL: u32 = 1 << 2;
    // LINUX-GAP: Linux has no cap on `count` (it chunks the arrays); NARF
    // bounds it so one call cannot ask for an unbounded kernel allocation.
    if count > (1 << 20) || flags & !(MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    if flags & MPOL_MF_MOVE_ALL != 0 {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    // `find_mm_struct` (mm/migrate.c:2534-2552): pid 0 is current->mm;
    // otherwise `find_get_task_by_vpid(pid)` in the CALLER's pid namespace —
    // any thread, a non-leader's tid included — else -ESRCH; then
    // ptrace_may_access, else -EPERM.
    if let Err(errno) = resolve_mm_target(current_task_id(), a.arg0 as i32) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if pages_ptr == 0 || status_ptr == 0 {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let Some(as_ref) = current_address_space() else {
        ctx.set_return(no_address_space());
        return;
    };

    let mut page_bytes = alloc::vec![0u8; count * 8];
    // SAFETY: copy_from_user range-validates the pointer array.
    if unsafe { copy_from_user(&mut page_bytes, pages_ptr) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let mut node_bytes = if nodes_ptr != 0 {
        let mut bytes = alloc::vec![0u8; count * 4];
        // SAFETY: copy_from_user range-validates the target-node array.
        if unsafe { copy_from_user(&mut bytes, nodes_ptr) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
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
                -EINVAL as i32
            } else {
                // SAFETY: the live current AS owns its root and backing list.
                match unsafe { as_ref.migrate_page_to_node(VirtAddr::new(va), target as usize) } {
                    Ok(_) => target,
                    Err(narf_memory::AddressSpaceError::Unmapped) => {
                        not_moved += 1;
                        -ENOENT as i32
                    }
                    Err(narf_memory::AddressSpaceError::SharedMapping) => {
                        match migrate_registry_shared_page(&as_ref, va, target as usize) {
                            Ok(()) => target,
                            Err(narf_memory::AddressSpaceError::Pinned) => {
                                not_moved += 1;
                                -EBUSY as i32
                            }
                            Err(_) => {
                                not_moved += 1;
                                -EACCES as i32
                            }
                        }
                    }
                    Err(narf_memory::AddressSpaceError::InvalidNode) => {
                        not_moved += 1;
                        -EINVAL as i32
                    }
                    Err(narf_memory::AddressSpaceError::Pinned) => {
                        not_moved += 1;
                        -EBUSY as i32
                    }
                    Err(_) => {
                        not_moved += 1;
                        -ENOMEM as i32
                    }
                }
            }
        } else {
            mapped_phys(&as_ref, va)
                .map(|phys| numa_node_for_phys(phys) as i32)
                .unwrap_or(-ENOENT as i32)
        };
        statuses[i * 4..i * 4 + 4].copy_from_slice(&status.to_ne_bytes());
    }
    // SAFETY: copy_to_user range-validates the status array.
    if unsafe { copy_to_user(status_ptr, &statuses) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(not_moved));
}
