#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_bootstrap(ctx: &mut dyn TrapContext) {
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let task = current_task_id();
    let authority = crate::user_task::with_current_task_owner(|owner| owner.authority.clone());
    #[cfg(feature = "kernel-test")]
    let authority = authority.or_else(|| {
        narf_scheduler::__set_task_active_domain_for_test(
            narf_scheduler::TaskId(task),
            narf_lib::id::DomainId::USERSPACE_K,
        );
        narf_scheduler::task_authority(narf_scheduler::TaskId(task))
    });
    let Some(authority) = authority else {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    };
    let Ok(image) = authority.image() else {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    };

    // Allocate a phys frame, zero it, install at a fresh user vaddr
    // (mmap-cursor-style — same scheme `sys_mmap` uses).
    let phys = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // SAFETY: this fresh allocator frame is still exclusively owned here.
    // A sibling sharing this MM may unmap its VMA before header writes finish.
    let _header_pin = unsafe { narf_memory::address_space::UserPagePin::retain_ram(phys) };
    // SAFETY: identity-mapped low 4 GiB; phys is page-aligned.
    unsafe {
        core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
    }
    let user_vaddr = MMAP_CURSOR.fetch_add(0x1000, Ordering::Relaxed);

    if as_ref
        .map_region(Region {
            base: VirtAddr::new(user_vaddr),
            len: 0x1000,
            // Stage-4 first cut: writable. Future revision flips the
            // page to R-only after the kernel populates it; the user
            // ring builders read from it but don't write.
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![phys].into(),
        })
        .is_err()
    {
        narf_memory::free_frame(narf_memory::frame::PhysFrame::new(phys));
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // SAFETY: `as_ref` is the calling task's freshly-built AddressSpace with a
    // valid root and the region just registered via `map_region`; materialize
    // only installs PTEs for those recorded regions.
    // SAFETY: Valid memory or trusted environment
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    // Mint the SQ + CQ ring pair. Kernel-side halves go into
    // BOOTSTRAP_TABLE keyed by task id; user-side halves are
    // tagged with newly-allocated cap-slot ids and stored beside
    // them so the dispatcher knows who to talk to.
    let (sq_prod, sq_drain) = submission_channel::<64>();
    let (cq_prod, cq_drain) = completion_channel::<64>();
    let sq_cap_id = NEXT_CAP_ID.fetch_add(1, Ordering::Relaxed);
    let cq_cap_id = NEXT_CAP_ID.fetch_add(1, Ordering::Relaxed);

    // Mint the user-mappable SharedRing pair. Two phys frames; both
    // mapped into the user AS at successive vaddrs after the config
    // page so the user runtime can build SharedProducer/Consumer
    // halves directly against the shared backing.
    // SAFETY: `as_ref` is the calling task's valid AddressSpace; `mint_shared_ring_pair`
    // allocates fresh frames, maps them into it, and materializes them under that AS.
    // SAFETY: Valid memory or trusted environment
    let (shared, ring_pages) = match unsafe { mint_shared_ring_pair(&as_ref) } {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    let session = Arc::new(NativeSession {
        shared,
        authority,
        image,
        closed: Arc::new(AtomicBool::new(false)),
        _ring_pages: ring_pages,
        _address_space: as_ref.clone(),
    });
    let entry = PerTaskBootstrap {
        kernel: Some(TaskRings { sq_drain, cq_prod }),
        user: Some(UserRingEnds { sq_prod, cq_drain }),
        shared: Some(shared),
        session: session.clone(),
        sq_cap_id,
        cq_cap_id,
    };
    let previous = {
        let mut g = BOOTSTRAP_TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        };
        // Replace any prior bootstrap state for this task.
        map.insert(task, entry)
    };
    if let Some(previous) = previous {
        previous.session.close();
    }
    let _ = crate::user_task::with_current_task_owner(|owner| {
        // SAFETY: Bootstrap executes on this owner's sole continuation. No
        // RingKick session borrow exists during a Bootstrap call.
        unsafe { owner.native_session.replace(session.clone()) };
    });

    // Write the header. Capslot ids land in `sq_cap`/`cq_cap` so
    // the user runtime can name the rings.
    // SAFETY: identity-mapped low 4 GiB; aligned u64 + u32 stores.
    unsafe {
        let header = phys.kernel_mut_ptr::<BootstrapHeader>();
        (*header).magic = ABI_BOOTSTRAP_MAGIC;
        (*header).version = ABI_BOOTSTRAP_VERSION;
        (*header).task_id = task;
        (*header).sq_cap = sq_cap_id;
        (*header).cq_cap = cq_cap_id;
        (*header).sq_depth = BOOTSTRAP_RING_DEPTH as u32;
        (*header).cq_depth = BOOTSTRAP_RING_DEPTH as u32;
        (*header).shared_sq_vaddr = shared.sq_user_vaddr;
        (*header).shared_cq_vaddr = shared.cq_user_vaddr;
        (*header).shared_depth = BOOTSTRAP_SHARED_RING_DEPTH as u32;
        (*header)._pad = 0;
    }

    ctx.set_return(SyscallReturn::ok(user_vaddr));
}
