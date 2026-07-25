#[allow(unused_imports)]
use super::*;

/// Read `len` bytes of an fd starting at `offset` into a fresh buffer,
/// zero-padding past EOF (the BSS tail of a file-backed segment).
pub(crate) fn sys_mmap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let hint = args.arg0;
    // Standard 6-arg mmap ABI: arg2 prot, arg3 flags, arg4 fd, arg5 offset.
    // narf_user_runtime::mmap issues this same shape for NARF-native
    // anonymous maps (prot=RW, fd=-1), so the kernel decodes one layout.
    let prot = args.arg2 as u32;
    let flags = args.arg3 as u32;
    let fd = args.arg4 as i64 as i32;
    let offset = args.arg5;
    const MAP_HUGETLB: u32 = 0x0004_0000;
    const MAP_HUGE_SHIFT: u32 = 26;
    const MAP_HUGE_MASK: u32 = 0x3f;
    let huge_size = if flags & MAP_HUGETLB != 0 {
        match (flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK {
            0 | 21 => Some(narf_memory::hugepage::HugeSize::M2),
            30 => Some(narf_memory::hugepage::HugeSize::G1),
            _ => {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
        }
    } else {
        None
    };
    let page_size = huge_size.map_or(4096, |size| match size {
        narf_memory::hugepage::HugeSize::M2 => narf_memory::hugepage::HUGEPAGE_2M_BYTES,
        narf_memory::hugepage::HugeSize::G1 => narf_memory::hugepage::HUGEPAGE_1G_BYTES,
    });
    let len = match args.arg1.checked_add(page_size - 1) {
        Some(v) => (v & !(page_size - 1)).max(page_size),
        None => {
            ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
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

    const MAP_FIXED: u32 = 0x10;
    const MAP_ANONYMOUS: u32 = 0x20;
    let pages = (len >> 12) as usize;
    let perms = perms_of_prot(prot);

    // Base selection. MAP_FIXED uses `hint` and REPLACES any overlapping
    // mappings (POSIX semantics) — the dynamic linker reserves a DSO range
    // PROT_NONE then MAP_FIXED-maps each segment over it. Otherwise bump the
    // per-AS mmap cursor.
    let base = if flags & MAP_FIXED != 0 {
        if hint == 0 || hint & (page_size - 1) != 0 {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
        // The fixed hint is fully user-controlled — bound it to the
        // user-mappable window [USER_FIXED_FLOOR, USER_HALF_END) before
        // touching the region table. Above the ceiling the VA is
        // non-canonical / kernel-half (x86_64 map_4kb returns
        // NonCanonical — pre-check, materialize() PANICKED on it, which
        // is how stress-ng --mmapfixed wedged the whole VM: it walks
        // MAP_FIXED|MAP_SHARED hints down from 1 << 63). Below the
        // floor lies PML4[0], the kernel low-identity window every user
        // PML4 shares — mapping there would plant user PTEs in
        // kernel-shared page tables (visible to every process) or trip
        // its huge pages. Linux answers an out-of-range MAP_FIXED addr
        // with -ENOMEM; do the same.
        let fixed_ok = hint
            .checked_add(len)
            .map(|end| hint >= AddressSpace::USER_FIXED_FLOOR && end <= AddressSpace::USER_HALF_END)
            .unwrap_or(false);
        if !fixed_ok {
            const ENOMEM: i64 = 12;
            ctx.set_return(SyscallReturn::ok((-ENOMEM) as u64));
            return;
        }
        // Punch out exactly [hint, hint+len), splitting (not destroying)
        // any region it overlaps so the non-replaced pages survive — the
        // dynamic linker overlays DSO segments onto its whole-file mapping
        // this way, and the ELF-header page between them must stay mapped.
        if as_ref.punch_fixed(VirtAddr::new(hint), len).is_ok() {
            crate::mapped_file::punch_current(hint, len);
        }
        hint
    } else {
        as_ref.reserve_mmap_va_aligned(len, page_size)
    };
    // reserve_mmap_va returns 0 when the no-hint mmap arena is exhausted
    // (the bump cursor would cross MMAP_WINDOW_TOP into the stack reserve).
    // Fail closed with -ENOMEM rather than mapping at a bogus base.
    // (MAP_FIXED takes the `hint` arm above, which is non-zero.)
    if base == 0 {
        const ENOMEM: i64 = 12;
        ctx.set_return(SyscallReturn::ok((-ENOMEM) as u64));
        return;
    }

    const MAP_SHARED: u32 = 0x01;
    if let Some(size) = huge_size {
        if flags & MAP_SHARED != 0 {
            ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP: no shared huge refs.
            return;
        }
        if flags & MAP_ANONYMOUS == 0 && fd >= 0 {
            ctx.set_return(SyscallReturn::ok((-19i64) as u64)); // ENODEV: no hugetlbfs.
            return;
        }
        let task = current_task_id();
        let stored = resolve_policy(task, base);
        let allowed = narf_scheduler::task_mems_allowed(task);
        let mut policy = narf_memory::Mempolicy {
            mode: stored.mode & !MPOL_MODE_FLAGS,
            nodemask: mpol_effective_nodemask(stored, allowed),
            allowed,
            home_node: stored.home_node,
            interleave_index: 0,
        };
        let mut frames = alloc::vec::Vec::with_capacity((len / page_size) as usize);
        for _ in 0..(len / page_size) {
            if matches!(
                policy.mode,
                narf_memory::MPOL_INTERLEAVE | narf_memory::MPOL_WEIGHTED_INTERLEAVE
            ) {
                policy.interleave_index = task_interleave_index(task, true);
            }
            let frame = match narf_memory::hugepage::alloc_hugepage_with(
                size,
                policy,
                narf_memory::frame::local_node(),
            ) {
                Ok(frame) => frame,
                Err(_) => {
                    for frame in frames {
                        narf_memory::hugepage::free_hugepage(frame);
                    }
                    ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
                    return;
                }
            };
            // SAFETY: a newly allocated huge frame is exclusively owned and
            // identity-reachable under the kernel's direct mapping.
            unsafe {
                core::ptr::write_bytes(frame.phys() as *mut u8, 0, frame.size_bytes() as usize);
            }
            frames.push(frame);
        }
        // SAFETY: `as_ref` is the caller's live root; frames are owned and
        // aligned for the selected hardware leaf size.
        let mapped = unsafe {
            as_ref.map_huge_region(HugeRegion {
                base: VirtAddr::new(base),
                len,
                perms,
                size,
                frames,
            })
        };
        match mapped {
            Ok(()) => ctx.set_return(SyscallReturn::ok(base)),
            Err(_) => ctx.set_return(SyscallReturn::ok((-12i64) as u64)),
        }
        return;
    }

    // Device-backed shared mapping — the keystone for graphics. A
    // `/dev/fb0` framebuffer (or a DRM dumb buffer) returns the
    // physical frames of its scanout buffer from `FileOps::mmap_frames`;
    // we alias (borrow) those frames into the caller's AS so userspace
    // gets a direct CPU-drawable pointer. RegionPerms::SHARED keeps the
    // teardown paths from `free_frame`-ing device-owned frames on
    // munmap/exit — same borrowed-frame contract as `sys_shmem_map` /
    // `sys_fb_ring_map`. A device that doesn't support mmap returns
    // Unsupported and we fall through to the regular file path.
    if fd >= 0 && flags & MAP_SHARED != 0 {
        let task = current_task_id();
        let ops = fd::with_table(task, |t| t.get(fd as u32).map(|e| e.ops.clone())).flatten();
        if let Some(ops) = ops {
            // On Err (unsupported, or any device error) we fall through to the
            // regular file-backed path below, unchanged from before.
            if let Ok(frames) = ops.mmap_frames(offset, len as usize) {
                if frames.len() != pages {
                    const EINVAL: i64 = 22;
                    ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
                    return;
                }
                let phys: alloc::vec::Vec<narf_memory::PhysAddr> = frames
                    .iter()
                    .map(|&p| narf_memory::PhysAddr::new(p))
                    .collect();
                if as_ref
                    .map_region(Region {
                        base: VirtAddr::new(base),
                        len,
                        perms: perms | RegionPerms::SHARED,
                        phys,
                    })
                    .is_err()
                {
                    ctx.set_return(SyscallReturn::invalid_op());
                    return;
                }
                // SAFETY: `as_ref` is the calling task's AddressSpace (valid
                // root); the region was just registered via map_region, so
                // materialize installs only its PTEs over borrowed frames.
                if unsafe { as_ref.materialize() }.is_err() {
                    // Roll back so the failed region can't poison later
                    // materialize() calls (SHARED → PTE-clear only, the
                    // device keeps its frames).
                    let _ = as_ref.unmap_region(VirtAddr::new(base));
                    ctx.set_return(SyscallReturn::invalid_op());
                    return;
                }
                crate::mapped_file::register_current(base, len, ops);
                crate::perf_event::on_mmap(current_task_id(), fd, base, len, offset, prot, flags);
                ctx.set_return(SyscallReturn::ok(base));
                return;
            }
        }
    }

    // Anonymous MAP_SHARED — Linux makes this a refcounted anonymous shared
    // object that survives fork: parent and child map the SAME frames and see
    // each other's writes. NARF backs it with the narf-shmem frame registry
    // (reached via the syscall vtable, exactly like System V shmat): the frames
    // are zeroed, registry-owned (reaped by the shmem process-exit observer),
    // and RegionPerms::SHARED makes `clone_for_fork` ALIAS them into the child
    // rather than COW-splitting a private copy the parent never sees. Without
    // this a child's writes — e.g. stress-ng's shared bogo-op counters, which
    // live in a MAP_SHARED|MAP_ANONYMOUS page mmap'd before each worker fork —
    // vanish from the parent's view (every counter reads back 0). Degrades to
    // the private-anonymous path below if the registry is unavailable or the
    // segment exceeds the per-handle cap (1 MiB); never a hard failure.
    if flags & MAP_SHARED != 0 && (flags & MAP_ANONYMOUS != 0 || fd < 0) {
        if let Some(v) = shmem_vtable() {
            let handle = (v.create)(current_task_id(), len);
            if handle != 0 {
                let mapped = narf_memory::with_shared_mapping_transaction(|| {
                    let mut frames_raw = alloc::vec::Vec::new();
                    if !(v.frames)(handle, &mut frames_raw) || frames_raw.len() != pages {
                        return Err(narf_memory::AddressSpaceError::Unmapped);
                    }
                    let phys = frames_raw
                        .into_iter()
                        .map(narf_memory::PhysAddr::new)
                        .collect();
                    // SAFETY: registry snapshot and alias insertion share one
                    // transaction.
                    unsafe {
                        as_ref.map_shared_region_locked(Region {
                            base: VirtAddr::new(base),
                            len,
                            perms: perms | RegionPerms::SHARED,
                            phys,
                        })
                    }
                });
                if mapped.is_ok() {
                    // SAFETY: `as_ref` is the calling task's AddressSpace
                    // (valid root); the region was just registered, so
                    // materialize installs only its PTEs over the registry
                    // frames.
                    if unsafe { as_ref.materialize() }.is_ok() {
                        crate::perf_event::on_mmap(
                            current_task_id(),
                            -1,
                            base,
                            len,
                            0,
                            prot,
                            flags,
                        );
                        ctx.set_return(SyscallReturn::ok(base));
                        return;
                    }
                    // Mapped but materialize failed (e.g. the fixed hint
                    // hits a kernel huge page): ROLL BACK. Leaving the
                    // region registered poisons the AS — every later
                    // materialize() re-walks it, hits the same error, and
                    // every subsequent mmap in the process fails. The
                    // region is SHARED so unmap_region only clears PTEs
                    // (frames stay registry-owned), then destroy reaps
                    // the now-unreferenced segment.
                    let _ = as_ref.unmap_region(VirtAddr::new(base));
                    (v.destroy)(handle);
                    ctx.set_return(SyscallReturn::invalid_op());
                    return;
                }
                // Not mapped (frames lookup / page-count mismatch / map_region
                // failed) — no region references the frames, so reap the
                // just-created segment now, then fall through to private anon.
                (v.destroy)(handle);
            }
        }
        // Registry unavailable or create failed: degrade to private anonymous.
    }

    let anonymous = flags & MAP_ANONYMOUS != 0 || fd < 0;
    let phys_list: alloc::vec::Vec<narf_memory::PhysAddr> = if anonymous {
        // Lazy-back: phys[i] == 0; the #PF handler demand-allocates + zeros
        // each page on first access.
        alloc::vec![narf_memory::PhysAddr::new(0); pages]
    } else {
        // File-backed MAP_PRIVATE: stream the file's [offset, offset+len)
        // bytes straight into per-page private frames (zero past EOF),
        // reading ONE page at a time. Slurping the whole region into a single
        // intermediate Vec OOMs the kernel for big DSOs: ld-musl mmaps Mesa's
        // libgallium (~40 MiB) and libLLVM (~161 MiB) in a single call, and a
        // lone 40 MiB+ allocation fails even with GiBs of guest RAM. Per-page
        // frames are a scatter list, so no large contiguous allocation is
        // needed.
        let len_bytes = len as usize;
        let ops = match fd::with_table(current_task_id(), |t| {
            t.get(fd as u32).map(|e| e.ops.clone())
        })
        .flatten()
        {
            Some(o) => o,
            None => {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        };
        let mut frames = alloc::vec::Vec::with_capacity(pages);
        for i in 0..pages {
            let frame = match narf_memory::alloc_frame() {
                Ok(f) => f.start_address(),
                Err(_) => {
                    ctx.set_return(SyscallReturn::invalid_op());
                    return;
                }
            };
            let off = i * 4096;
            let want = core::cmp::min(4096, len_bytes - off);
            // SAFETY: freshly-allocated identity-mapped frame; zero the whole
            // page first so any tail past `want` (and past EOF) reads as zero.
            unsafe {
                core::ptr::write_bytes(frame.raw() as *mut u8, 0, 4096);
            }
            // SAFETY: `frame` is identity-mapped in the low 4 GiB and `want`
            // is <= 4096, so the slice stays within the page.
            let dst = unsafe { core::slice::from_raw_parts_mut(frame.raw() as *mut u8, want) };
            let mut done = 0usize;
            while done < want {
                // Poll each read to COMPLETION, keeping the one future alive for
                // the whole wait (`poll_io_to_completion`, huge backstop) — never
                // drop it mid-request. The old code used `poll_blocking` (a small
                // 4M budget) and treated its timeout (`None`) as EOF, silently
                // zero-filling the page tail under a concurrent-execve storm (KDE
                // launching dozens of procs): that truncated a mmap'd DSO — it
                // lopped a libdbus `.rodata` string "/org/freedesktop/DBus" → "/",
                // so every forked dbus client sent a malformed Hello, killing the
                // session bus and stalling Plasma. Dropping a read future mid-DMA
                // ALSO left an in-flight virtio-blk request writing into a scratch
                // buffer that had been returned to the pool and reused → garbage.
                // Holding the future to completion fixes both: the scratch buffer
                // is released only after its DMA finishes.
                match poll_io_to_completion(
                    ops.read(offset + off as u64 + done as u64, &mut dst[done..]),
                ) {
                    Some(Ok(0)) | None => break, // real EOF (or wedged device) — rest stays zero
                    Some(Ok(n)) => done += n,
                    Some(Err(_)) => break, // read error — rest stays zero
                }
            }
            frames.push(frame);
        }
        frames
    };

    if as_ref
        .map_region(Region {
            base: VirtAddr::new(base),
            len,
            perms,
            phys: phys_list,
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
        // Roll the region back — leaving it registered poisons every
        // later materialize() in this AS (each re-walks the region,
        // hits the same map error, and the whole mmap surface goes
        // dark for the process). unmap_region frees any file-read
        // frames via the region's own phys list.
        let _ = as_ref.unmap_region(VirtAddr::new(base));
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    crate::perf_event::on_mmap(
        current_task_id(),
        if anonymous { -1 } else { fd },
        base,
        len,
        if anonymous { 0 } else { offset },
        prot,
        flags,
    );
    ctx.set_return(SyscallReturn::ok(base));
}
