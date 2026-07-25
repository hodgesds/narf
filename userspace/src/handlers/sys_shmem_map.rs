#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_shmem_map(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Cross-pid auth: the calling task must own this region. The
    // future cross-process sharing path adds an explicit grant /
    // attach syscall; today, foreign maps are rejected outright.
    let pid = current_task_id();
    if (v.pid_of)(handle) != pid {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let len = (v.len_of)(handle);
    if len == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = MMAP_CURSOR.fetch_add(len, Ordering::Relaxed);
    let mapped = narf_memory::with_shared_mapping_transaction(|| {
        let mut frames_raw: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        if !(v.frames)(handle, &mut frames_raw) {
            return Err(narf_memory::AddressSpaceError::Unmapped);
        }
        let phys_list = frames_raw
            .into_iter()
            .map(narf_memory::PhysAddr::new)
            .collect();
        // SAFETY: the transaction covers both registry snapshot and insertion.
        unsafe {
            as_ref.map_shared_region_locked(Region {
                base: VirtAddr::new(base),
                len,
                // SHARED is load-bearing, not advisory: `phys_list` is the
                // shmem registry's persistent backing frames (allocated once
                // by `narf_shmem::create`, owned by the registry for the
                // segment's life — `destroy` never frees them). Without the
                // SHARED flag the AS teardown paths (`unmap_region_pages` /
                // `unmap_free_page` / `Drop` / `madvise_dontneed`, which all
                // special-case SHARED) treat these BORROWED frames as
                // AS-owned and `free_frame` them on munmap/exit — returning a
                // live, registry-owned (and not COW-refcounted) frame to the
                // buddy, which re-hands it out as a page-table page → the
                // cross-AS "marginal-buddy" double-free. The SysV `sys_shmat`
                // twin already sets SHARED for the identical frames.
                perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
                phys: phys_list,
            })
        }
    });
    if mapped.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // SAFETY: `as_ref` is the calling task's AddressSpace (valid root); the region
    // was just registered via `map_region`, so materialize installs only its PTEs.
    // SAFETY: Valid memory or trusted environment
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(base));
}
