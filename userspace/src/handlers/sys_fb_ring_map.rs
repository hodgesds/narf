#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fb_ring_map(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let phys = (v.ring_map)(handle);
    if phys == 0 {
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
    let len = 4096u64;
    let base = MMAP_CURSOR.fetch_add(len, Ordering::Relaxed);
    if as_ref
        .map_region(Region {
            base: VirtAddr::new(base),
            len,
            // SHARED: `phys` is the framebuffer subsystem's ring-buffer
            // frame, owned externally and never allocated by this AS.
            // Without SHARED the teardown paths would `free_frame` this
            // borrowed frame on munmap/exit and return it to the buddy —
            // the same double-free class as `sys_shmem_map`.
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
            phys: alloc::vec![narf_memory::PhysAddr::new(phys)],
        })
        .is_err()
    {
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
