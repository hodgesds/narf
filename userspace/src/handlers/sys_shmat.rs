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
    let mut frames_raw: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    if !(v.frames)(handle, &mut frames_raw) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let phys_list: alloc::vec::Vec<narf_memory::PhysAddr> = frames_raw
        .into_iter()
        .map(narf_memory::PhysAddr::new)
        .collect();
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
    if as_ref
        .map_region(Region {
            base: VirtAddr::new(base),
            len,
            perms,
            phys: phys_list,
        })
        .is_err()
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // SAFETY: `as_ref` is the calling task's AddressSpace (valid root); the
    // region was just registered, so materialize installs only its PTEs.
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(base));
}
