#[allow(unused_imports)]
use super::*;

/// `shmdt(shmaddr)` — detach the logical System V attachment whose original
/// attach address is exactly `shmaddr`.
///
/// `ipc/shm.c::ksys_shmdt` has exactly one failure code, and it is reached
/// two ways:
///
/// ```text
///   int retval = -EINVAL;
///   if (addr & ~PAGE_MASK) return retval;
///   ...
///   for_each_vma(vmi, vma) {
///       if ((vma->vm_ops == &shm_vm_ops) &&
///           (vma->vm_start - addr)/PAGE_SIZE == vma->vm_pgoff) {
///               ... retval = 0; break;
///       }
///   }
///   return retval;
/// ```
///
/// `retval` only ever leaves as 0 or -EINVAL: a misaligned address and an
/// address that names no SysV attachment are indistinguishable to the
/// caller, and detaching a segment that was already IPC_RMID'd is a plain
/// success, not -EIDRM. Every failure exit below therefore reports -EINVAL
/// deliberately — none of them is a stand-in for an unwritten errno.
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_shmdt(ctx: &mut dyn TrapContext) {
    // `shmaddr` is a `char __user *`, so unlike shmid/shmflg it really is the
    // whole register.
    let addr = ctx.args().arg0;
    if addr & 0xFFF != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let Some(as_ref) = current_address_space() else {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    };
    let as_key = shm_as_key(&as_ref);
    let mapping_transaction = shm_mapping_transaction(as_key);
    let _mapping_guard = mapping_transaction.lock();
    let attachment = {
        let mut attachments = SHM_ATTACHMENTS.lock();
        attachments
            .get_or_insert_with(ShmAttachmentRegistry::new)
            .get(&(as_key, addr))
            .and_then(|entries| {
                // Linux scans VMAs upward from `addr`; if SHM_REMAP left an
                // older attachment's suffix behind the new mapping, detach
                // the logical attachment owning the lowest matching VMA.
                entries
                    .iter()
                    .min_by_key(|entry| {
                        entry
                            .fragments
                            .iter()
                            .map(|(base, _)| *base)
                            .min()
                            .unwrap_or(u64::MAX)
                    })
                    .cloned()
            })
    };
    let Some(attachment) = attachment else {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    };
    debug_assert_eq!(attachment.base, addr);

    // Resolve each logical fragment into its current VMAs before changing the
    // first one. `mprotect` may split a SysV VMA without changing the logical
    // attachment; Linux shmdt removes every such fragment in one call.
    let mut live_regions = alloc::vec::Vec::new();
    for &(base, len) in &attachment.fragments {
        let Some(end) = base.checked_add(len) else {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        };
        let mut cursor = base;
        while cursor < end {
            let Some(region) = as_ref.lookup(VirtAddr::new(cursor)) else {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                return;
            };
            let Some(region_end) = cursor.checked_add(region.len) else {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                return;
            };
            if region.base.as_u64() != cursor || region.len == 0 || region_end > end {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                return;
            }
            live_regions.push((cursor, region.len));
            cursor = region_end;
        }
    }
    for &(base, _) in &live_regions {
        if as_ref.unmap_region(VirtAddr::new(base)).is_err() {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        }
    }
    {
        let mut attachments = SHM_ATTACHMENTS.lock();
        let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
        let remove_key = if let Some(entries) = map.get_mut(&(as_key, addr)) {
            if let Some(index) = entries.iter().position(|entry| {
                entry.shmid == attachment.shmid && entry.fragments == attachment.fragments
            }) {
                entries.remove(index);
            }
            entries.is_empty()
        } else {
            false
        };
        if remove_key {
            map.remove(&(as_key, addr));
        }
    }

    let caller = current_task_id();
    let lpid = task_to_pid_raw(caller).unwrap_or(caller);
    let now = shm_now_seconds();
    let destroy = {
        let mut segments = SHM_SEGMENTS.lock();
        let map = segments.get_or_insert_with(alloc::collections::BTreeMap::new);
        let object = (attachment.ipc_ns, attachment.shmid);
        let Some(seg) = map.get_mut(&object) else {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        };
        seg.nattch = seg.nattch.saturating_sub(1);
        seg.lpid = lpid;
        seg.dtime = now;
        if seg.removed && seg.nattch == 0 {
            map.remove(&object).map(|seg| seg.handle)
        } else {
            None
        }
    };
    if let (Some(handle), Some(vtable)) = (destroy, shmem_vtable()) {
        if handle != 0 {
            (vtable.destroy)(handle);
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
