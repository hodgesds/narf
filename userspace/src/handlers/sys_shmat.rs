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
    // Reserve a page-aligned VA window: the segment maps one PTE per
    // page-granular backing frame, so a sub-page `len` still consumes a
    // whole page (matching the region registered below).
    let reserve_len = (len + 0xFFF) & !0xFFF;
    let base = as_ref.reserve_mmap_va(reserve_len);
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
        let phys_list: alloc::vec::Vec<_> = frames_raw
            .into_iter()
            .map(narf_memory::PhysAddr::new)
            .collect();
        // The backing frames are page-granular, so the mapped region spans
        // exactly one PTE per shared frame. `map_region_inner` requires a
        // page-aligned `len` that matches the scatter list one-to-one, so
        // derive it from the frame count rather than the raw (possibly
        // sub-page) segment size.
        let map_len = (phys_list.len() as u64) << 12;
        // SAFETY: registry snapshot and alias insertion share one transaction.
        unsafe {
            as_ref.map_shared_region_locked(Region {
                base: VirtAddr::new(base),
                len: map_len,
                perms,
                phys: phys_list,
            })?;
        }
        Ok(map_len)
    });
    let map_len = match mapped {
        Ok(map_len) => map_len,
        Err(_) => {
            // Backing frames unavailable / could not be aliased → ENOMEM.
            ctx.set_return(SyscallReturn::ok((-12i64) as u64));
            return;
        }
    };
    // Install PTEs for ONLY the just-attached segment's VA window
    // `[base, base + map_len)` instead of re-walking every VMA in the AS.
    // shmget/shmat/shmdt in a tight loop otherwise re-materialized the whole
    // address space per attach (the shm-sysv hot path). `map_len` matches the
    // page-aligned span registered above.
    //
    // SAFETY: `as_ref` is the calling task's AddressSpace (valid root); the
    // region was just registered, so this installs only its PTEs.
    if unsafe { as_ref.materialize_range(VirtAddr::new(base), map_len) }.is_err() {
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
