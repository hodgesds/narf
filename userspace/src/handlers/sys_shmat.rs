#[allow(unused_imports)]
use super::*;

/// `shmat(shmid, shmaddr, shmflg)` — attach a System V segment.
///
/// Validation follows Linux `ipc/shm.c::do_shmat`: signed-id and address
/// shape first, access permission next, then overlap/replacement and mapping.
/// Unknown `shmflg` bits are ignored by Linux and therefore by NARF.
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_shmat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let signed_shmid = a.arg0 as u32 as i32;
    let shmid = signed_shmid as u32 as u64;
    let mut base = a.arg1;
    let flg = a.arg2 as u32 as u64;
    #[cfg(feature = "container")]
    let ipc_namespace = current_shm_ipc_ns();
    #[cfg(feature = "container")]
    let ipc_ns = ipc_namespace.id();
    #[cfg(not(feature = "container"))]
    let ipc_ns = current_shm_ipc_ns_id();
    let object = (ipc_ns, shmid);

    if signed_shmid < 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if base != 0 {
        if base & (SHMLBA - 1) != 0 {
            if flg & SHM_RND != 0 {
                base &= !(SHMLBA - 1);
                if base == 0 && flg & SHM_REMAP != 0 {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                }
            } else if base & 0xFFF != 0 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                return;
            }
        }
    } else if flg & SHM_REMAP != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }

    let request = 0o4
        | if flg & SHM_RDONLY == 0 { 0o2 } else { 0 }
        | if flg & SHM_EXEC != 0 { 0o1 } else { 0 };
    let (handle, len) = {
        let mut segments = SHM_SEGMENTS.lock();
        let Some(seg) = segments
            .as_mut()
            .and_then(|map| map.get_mut(&object))
            .filter(|seg| !seg.removed)
        else {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        };
        if !shm_ipc_allowed(seg, request) {
            ctx.set_return(SyscallReturn::ok((-13i64) as u64));
            return;
        }
        // Reserve backing lifetime against a racing IPC_RMID.
        seg.nattch = seg.nattch.saturating_add(1);
        (seg.handle, seg.len)
    };

    let reserve_len = match len.checked_add(0xFFF) {
        Some(value) => value & !0xFFF,
        None => {
            shm_cancel_attach(object);
            ctx.set_return(SyscallReturn::ok((-12i64) as u64));
            return;
        }
    };
    if base != 0 && flg & SHM_REMAP == 0 && base.checked_add(reserve_len).is_none() {
        shm_cancel_attach(object);
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }

    let vtable = match shmem_vtable() {
        Some(vtable) => vtable,
        None => {
            shm_cancel_attach(object);
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let as_ref = match current_address_space() {
        Some(as_ref) => as_ref,
        None => {
            shm_cancel_attach(object);
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    if base == 0 {
        base = as_ref.reserve_mmap_va_aligned(reserve_len, SHMLBA);
        if base == 0 {
            shm_cancel_attach(object);
            ctx.set_return(SyscallReturn::ok((-12i64) as u64));
            return;
        }
    }

    let caller = current_task_id();
    let lpid = task_to_pid_raw(caller).unwrap_or(caller);
    let as_key = shm_as_key(&as_ref);
    // Serialize every address-space mutation that can create, punch, or detach
    // a SysV VMA with SHM_ATTACHMENTS/nattch publication. This is the
    // userspace equivalent of Linux's mmap write lock plus shm ids lock for
    // CLONE_VM siblings sharing this address space.
    shm_register_as_owner(as_key, lpid);
    let mapping_transaction = shm_mapping_transaction(as_key);
    let _mapping_guard = mapping_transaction.lock();

    let mut perms = RegionPerms::READ | RegionPerms::SHARED;
    if flg & SHM_RDONLY == 0 {
        perms = perms | RegionPerms::WRITE;
    }
    if flg & SHM_EXEC != 0 {
        perms = perms | RegionPerms::EXEC;
    }
    let authority = current_mlock_authority();
    let mapped = as_ref.with_vma_transaction(|| {
        narf_memory::with_shared_mapping_transaction(|| {
            let mut frames_raw = alloc::vec::Vec::new();
            if !(vtable.frames)(handle, &mut frames_raw) {
                return Err(narf_memory::AddressSpaceError::Unmapped);
            }
            let map_len = (frames_raw.len() as u64) << 12;
            if map_len != reserve_len {
                return Err(narf_memory::AddressSpaceError::AlignmentMismatch);
            }
            let phys = frames_raw
                .into_iter()
                .map(narf_memory::PhysAddr::new)
                .collect();
            let region = Region {
                base: VirtAddr::new(base),
                len: map_len,
                perms,
                phys,
            };
            // SAFETY: VMA -> shared-owner transactions cover the stable
            // registry snapshot and alias publication.
            unsafe {
                if flg & SHM_REMAP != 0 {
                    as_ref.replace_shared_region_locked_limited(
                        region,
                        false,
                        authority.limit_bytes,
                        authority.bypass_limit,
                    )?;
                } else {
                    as_ref.map_shared_region_locked_limited(
                        region,
                        false,
                        authority.limit_bytes,
                        authority.bypass_limit,
                    )?;
                }
            }
            Ok(map_len)
        })
    });
    let map_len = match mapped {
        Ok(map_len) => map_len,
        Err(narf_memory::AddressSpaceError::Overlap) if flg & SHM_REMAP == 0 => {
            shm_cancel_attach(object);
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        }
        Err(narf_memory::AddressSpaceError::LockLimit) => {
            shm_cancel_attach(object);
            ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // EAGAIN
            return;
        }
        Err(_) => {
            shm_cancel_attach(object);
            ctx.set_return(SyscallReturn::ok((-12i64) as u64));
            return;
        }
    };
    if flg & SHM_REMAP != 0 {
        // The memory transaction has committed target replacement; keep the
        // SysV attachment index synchronized before adding this attachment.
        shm_record_fixed_punch(as_key, base, base + map_len, lpid);
    }

    // SAFETY: the region was just registered in this live address space.
    if unsafe { as_ref.materialize_range(VirtAddr::new(base), map_len) }.is_err() {
        let _ = as_ref.unmap_region(VirtAddr::new(base));
        shm_cancel_attach(object);
        ctx.set_return(SyscallReturn::ok((-12i64) as u64));
        return;
    }

    {
        let mut attachments = SHM_ATTACHMENTS.lock();
        let map = attachments.get_or_insert_with(alloc::collections::BTreeMap::new);
        map.entry((as_key, base))
            .or_default()
            .push(ShmAttachment {
                ipc_ns,
                shmid,
                base,
                fragments: alloc::vec![(base, map_len)],
            });
    }
    let now = shm_now_seconds();
    if let Some(seg) = SHM_SEGMENTS
        .lock()
        .as_mut()
        .and_then(|map| map.get_mut(&object))
    {
        seg.lpid = lpid;
        seg.atime = now;
    }
    ctx.set_return(SyscallReturn::ok(base));
}
