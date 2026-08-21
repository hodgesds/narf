#[allow(unused_imports)]
use super::*;

/// `shmat(shmid, shmaddr, shmflg)` — map the segment's frames into the AS.
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_shmat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let shmid = a.arg0;
    let flg = a.arg2;
    let (handle, len) = {
        let g = SHM_SEGMENTS.lock();
        match g.as_ref().and_then(|m| m.get(&shmid)) {
            Some(s) => (s.handle, s.len),
            None => {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
        }
    };
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // SHARED marks the frames as borrowed (narf-shmem owns them), so a
    // second shmat of the same segment may alias them and neither unmap
    // nor AS-drop frees them.
    let mut perms = RegionPerms::READ | RegionPerms::SHARED;
    if flg & SHM_RDONLY == 0 {
        perms = perms | RegionPerms::WRITE;
    }
    let base = as_ref.reserve_mmap_va(len);
    if base == 0 {
        // mmap arena exhausted (cursor at MMAP_WINDOW_TOP) — fail closed.
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    let mapped = narf_memory::with_shared_mapping_transaction(|| {
        let mut frames_raw = alloc::vec::Vec::new();
        if !(v.frames)(handle, &mut frames_raw) {
            return Err(narf_memory::AddressSpaceError::Unmapped);
        }
        let phys_list = frames_raw
            .into_iter()
            .map(narf_memory::PhysAddr::new)
            .collect();
        // SAFETY: registry snapshot and alias insertion share one transaction.
        unsafe {
            as_ref.map_shared_region_locked(Region {
                base: VirtAddr::new(base),
                len,
                perms,
                phys: phys_list,
            })
        }
    });
    if mapped.is_err() {
        // Backing frames unavailable / could not be aliased → ENOMEM.
        ctx.set_return(SyscallReturn::ok((-12i64) as u64));
        return;
    }
    // SAFETY: `as_ref` is the calling task's AddressSpace (valid root); the
    // region was just registered, so materialize installs only its PTEs.
    if unsafe { as_ref.materialize() }.is_err() {
        // PTE installation failed after the region was registered → ENOMEM.
        ctx.set_return(SyscallReturn::ok((-12i64) as u64));
        return;
    }
    // Record the attaching process as the segment's last-op pid (shm_lpid).
    let caller = current_task_id();
    let lpid = task_to_pid_raw(caller).unwrap_or(caller);
    if let Some(m) = SHM_SEGMENTS.lock().as_mut() {
        if let Some(seg) = m.get_mut(&shmid) {
            seg.lpid = lpid;
        }
    }
    ctx.set_return(SyscallReturn::ok(base));
}
