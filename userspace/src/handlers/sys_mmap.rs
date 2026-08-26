#[allow(unused_imports)]
use super::*;

fn finish_nonfixed_private_file_mapping(
    as_ref: &AddressSpace,
    receipt: narf_memory::MappingReceipt,
) -> Result<narf_memory::MappingReceipt, narf_memory::AddressSpaceError> {
    // SAFETY: the syscall owns a live address-space reference. A stale result
    // means publication already linearized and a CLONE_VM peer subsequently
    // replaced the VMA; Linux still returns the selected base in that race.
    match unsafe { as_ref.materialize_mapping(receipt) } {
        Ok(()) | Err(narf_memory::AddressSpaceError::StaleMapping) => Ok(receipt),
        Err(error) => {
            let _ = as_ref.rollback_mapping(receipt);
            Err(error)
        }
    }
}

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
    const MAP_FIXED: u32 = 0x10;
    const MAP_ANONYMOUS: u32 = 0x20;
    const MAP_SHARED: u32 = 0x01;
    const MAP_LOCKED: u32 = 0x2000;
    const MAP_HUGETLB: u32 = 0x0004_0000;
    const MAP_HUGE_SHIFT: u32 = 26;
    const MAP_HUGE_MASK: u32 = 0x3f;
    let anonymous = flags & MAP_ANONYMOUS != 0;

    // Both x86_64 and AArch64 reject a non-page-aligned byte offset in the
    // architecture syscall wrapper before fd lookup or any mmap work.
    if offset & 0xFFF != 0 {
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
    // ksys_mmap_pgoff resolves a non-anonymous fd before huge-flag and
    // do_mmap length/address validation. Thus EBADF wins over a zero length or
    // malformed MAP_FIXED address (but not over the arch offset check above).
    if !anonymous
        && (fd < 0
            || fd::with_table(current_task_id(), |table| table.get(fd as u32).is_some())
                != Some(true))
    {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
        return;
    }

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
    // Linux do_mmap rejects an exact zero length before rounding and before
    // get_unmapped_area validates MAP_FIXED. Never promote it to one page.
    if args.arg1 == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let len = match args.arg1.checked_add(page_size - 1) {
        Some(v) => v & !(page_size - 1),
        None => {
            ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
            return;
        }
    };

    // Semantic failures must precede MAP_FIXED replacement: an invalid new
    // mapping never destroys the old one on Linux.
    if huge_size.is_some() && flags & MAP_SHARED != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }
    if huge_size.is_some() && flags & MAP_ANONYMOUS == 0 && fd >= 0 {
        ctx.set_return(SyscallReturn::ok((-19i64) as u64)); // ENODEV
        return;
    }

    // __get_unmapped_area rejects fixed misalignment with EINVAL, range
    // overflow with ENOMEM, then security_mmap_addr applies the low-address
    // policy. NARF's USER_FIXED_FLOOR is that policy boundary.
    if flags & MAP_FIXED != 0 {
        if hint & (page_size - 1) != 0 {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
        let fixed_in_range = hint
            .checked_add(len)
            .map(|end| end <= AddressSpace::USER_HALF_END)
            .unwrap_or(false);
        if !fixed_in_range {
            ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
            return;
        }
        if hint < AddressSpace::USER_FIXED_FLOOR {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
            return;
        }
    }
    let mlock_authority = current_mlock_authority();
    let explicit_lock = flags & MAP_LOCKED != 0;
    if explicit_lock && !can_do_mlock(mlock_authority) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }

    let pages = (len >> 12) as usize;
    let perms = perms_of_prot(prot);
    #[cfg(feature = "linux-compat")]
    let task = current_task_id();
    #[cfg(feature = "linux-compat")]
    let lpid = task_to_pid_raw(task).unwrap_or(task);
    #[cfg(feature = "linux-compat")]
    let as_key = shm_as_key(&as_ref);
    #[cfg(feature = "linux-compat")]
    if flags & MAP_FIXED != 0 {
        shm_register_as_owner(as_key, lpid);
    }
    #[cfg(feature = "linux-compat")]
    let shm_transaction =
        (flags & MAP_FIXED != 0).then(|| shm_mapping_transaction(as_key));
    #[cfg(feature = "linux-compat")]
    let _shm_guard = shm_transaction
        .as_ref()
        .map(|transaction| transaction.lock());

    // Base selection. Destructive MAP_FIXED replacement is deferred until the
    // requested mapping's semantic, backing, and lock-limit checks pass.
    let base = if flags & MAP_FIXED != 0 {
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

    macro_rules! record_fixed_replacement_owner_committed {
        () => {
            if flags & MAP_FIXED != 0 {
                // `mapped_file::publish_current_mapping` updated the file
                // owner table under the VMA transaction. Only the independent
                // SysV attachment index remains to mirror here.
                #[cfg(feature = "linux-compat")]
                {
                    shm_record_fixed_punch(as_key, hint, hint + len, lpid);
                }
            }
        };
    }

    if let Some(size) = huge_size {
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
        let count = (len / page_size) as usize;
        let mut policies = alloc::vec::Vec::with_capacity(count);
        for _ in 0..(len / page_size) {
            if matches!(
                policy.mode,
                narf_memory::MPOL_INTERLEAVE | narf_memory::MPOL_WEIGHTED_INTERLEAVE
            ) {
                policy.interleave_index = task_interleave_index(task, true);
            }
            policies.push(policy);
        }
        let frames = match narf_memory::hugepage::alloc_hugepages_with(
            size,
            &policies,
            narf_memory::frame::local_node(),
        ) {
            Ok(frames) => frames,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
                return;
            }
        };
        for frame in &frames {
            // SAFETY: a newly allocated huge frame is exclusively owned and
            // identity-reachable under the kernel's direct mapping.
            unsafe {
                core::ptr::write_bytes(frame.phys() as *mut u8, 0, frame.size_bytes() as usize);
            }
        }
        let mapped = as_ref.with_vma_transaction(|| {
            crate::mapped_file::publish_current_unowned_mapping(
                base,
                len,
                flags & MAP_FIXED != 0,
                || {
                    // SAFETY: the VMA transaction is held and the freshly
                    // allocated aligned huge frames remain owned by this call.
                    unsafe {
                        as_ref.map_huge_region_locked_limited(
                            HugeRegion {
                                base: VirtAddr::new(base),
                                len,
                                perms,
                                size,
                                frames,
                            },
                            flags & MAP_FIXED != 0,
                            explicit_lock,
                            mlock_authority.limit_bytes,
                            mlock_authority.bypass_limit,
                        )
                    }
                },
                |()| Ok(()),
            )
        });
        match mapped {
            Ok(()) => {
                record_fixed_replacement_owner_committed!();
                ctx.set_return(SyscallReturn::ok(base));
            }
            Err(narf_memory::AddressSpaceError::LockLimit) => {
                ctx.set_return(SyscallReturn::ok((-11i64) as u64))
            }
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
            // Acquire any per-object owner BEFORE resolving raw frames. A
            // concurrent handle close may remove the lookup-table entry after
            // this point, but it cannot recycle the backing while this Arc is
            // held and then transferred into the mapping-owner table.
            let mmap_lifetime = ops.mmap_lifetime(offset, len as usize);
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
                let region = Region {
                        base: VirtAddr::new(base),
                        len,
                        perms: perms | RegionPerms::SHARED | RegionPerms::LOCK_EXEMPT,
                        phys,
                    };
                let mapped = as_ref.with_vma_transaction(|| {
                    narf_memory::with_shared_mapping_transaction(|| {
                        crate::mapped_file::publish_current_mapping(
                            crate::mapped_file::MappingOwnerRegistration {
                                base,
                                len,
                                file_offset: offset,
                                ops: Arc::clone(&ops),
                                lifetime: mmap_lifetime.clone(),
                                writeback_phys: None,
                                replace: flags & MAP_FIXED != 0,
                            },
                            || {
                                // SAFETY: VMA -> shared transactions are held;
                                // the file owner lock stays held until the VMA
                                // has its external lifetime registered.
                                unsafe {
                                    if flags & MAP_FIXED != 0 {
                                        as_ref.replace_shared_region_locked_limited_receipt(
                                            region,
                                            explicit_lock,
                                            mlock_authority.limit_bytes,
                                            mlock_authority.bypass_limit,
                                        )
                                    } else {
                                        as_ref.map_shared_region_locked_limited_receipt(
                                            region,
                                            explicit_lock,
                                            mlock_authority.limit_bytes,
                                            mlock_authority.bypass_limit,
                                        )
                                    }
                                }
                            },
                            |receipt| {
                                // SAFETY: same live root and VMA transaction;
                                // rollback is receipt-scoped if PTE install
                                // fails.
                                match unsafe { as_ref.materialize_mapping_locked(receipt) } {
                                    Ok(()) => Ok(()),
                                    Err(error) => {
                                        // SAFETY: VMA -> shared transactions
                                        // remain held by the enclosing scopes.
                                        let _ = unsafe {
                                            as_ref.rollback_mapping_locked(receipt)
                                        };
                                        Err(error)
                                    }
                                }
                            },
                        )
                    })
                });
                if let Err(error) = mapped {
                    let errno = if error == narf_memory::AddressSpaceError::LockLimit {
                        11i64 // EAGAIN
                    } else {
                        12i64 // ENOMEM
                    };
                    ctx.set_return(SyscallReturn::ok((-errno) as u64));
                    return;
                }
                record_fixed_replacement_owner_committed!();
                #[cfg(feature = "linux-compat")]
                crate::perf_event::on_mmap(current_task_id(), fd, base, len, offset, prot, flags);
                ctx.set_return(SyscallReturn::ok(base));
                return;
            }
            // Demand-paged device mapping. `mmap_frames` is answered once, so
            // a file that can grow behind a live mapping cannot use it — a page
            // backed after this call would never appear. Such files implement
            // `mmap_fault` instead and are mapped with every slot unbacked;
            // each page's first touch routes through `mapped_file::demand_frame`
            // to the file. A BPF arena is the first of these.
            //
            // The probe *is* the first fault: `mmap_fault` is idempotent per
            // offset, so asking here costs nothing beyond backing a page the
            // caller is about to touch anyway, and it means no second trait
            // method exists purely to answer "do you support this?".
            if ops.mmap_fault(offset).is_ok() {
                // Installed here rather than at boot: a FILE_DEMAND region
                // cannot exist before this line has run, so there is no window
                // in which a fault could find the hook missing, and no
                // boot-order constraint of the kind §4.1 imposes on the BPF
                // page-table slots.
                narf_memory::install_file_fault_hook(crate::mapped_file::demand_frame);
                let region = Region {
                        base: VirtAddr::new(base),
                        len,
                        // SHARED: the frames belong to the file, so teardown
                        // clears PTEs and frees nothing. FILE_DEMAND: an
                        // unbacked slot means "ask the file", not "allocate an
                        // anonymous zero page".
                        perms: perms
                            | RegionPerms::SHARED
                            | RegionPerms::FILE_DEMAND
                            | RegionPerms::LOCK_EXEMPT,
                        phys: alloc::vec![narf_memory::PhysAddr::new(0); pages],
                    };
                let mapped = as_ref.with_vma_transaction(|| {
                    narf_memory::with_shared_mapping_transaction(|| {
                        crate::mapped_file::publish_current_mapping(
                            crate::mapped_file::MappingOwnerRegistration {
                                base,
                                len,
                                file_offset: offset,
                                ops: Arc::clone(&ops),
                                lifetime: None,
                                writeback_phys: None,
                                replace: flags & MAP_FIXED != 0,
                            },
                            || {
                                // SAFETY: VMA -> shared transactions are held
                                // while the owner lock prevents a racing fault
                                // from observing an ownerless FILE_DEMAND VMA.
                                unsafe {
                                    if flags & MAP_FIXED != 0 {
                                        as_ref.replace_shared_region_locked_limited_receipt(
                                            region,
                                            explicit_lock,
                                            mlock_authority.limit_bytes,
                                            mlock_authority.bypass_limit,
                                        )
                                    } else {
                                        as_ref.map_shared_region_locked_limited_receipt(
                                            region,
                                            explicit_lock,
                                            mlock_authority.limit_bytes,
                                            mlock_authority.bypass_limit,
                                        )
                                    }
                                }
                            },
                            |_receipt| Ok(()),
                        )
                    })
                });
                if let Err(error) = mapped {
                    let errno = if error == narf_memory::AddressSpaceError::LockLimit {
                        11i64
                    } else {
                        12i64
                    };
                    ctx.set_return(SyscallReturn::ok((-errno) as u64));
                    return;
                }
                record_fixed_replacement_owner_committed!();
                // No `materialize` call: every slot is unbacked, so it would
                // install nothing. The PTEs arrive one demand fault at a time.
                //
                // Registering the mapping is what keeps `ops` alive, and it is
                // load-bearing twice over: `demand_frame` finds the file
                // through this table, and the frames the file hands out must
                // not be returned to the allocator while this mapping can
                // still reach them.
                // Registration was committed atomically with VMA publication
                // by `publish_current_mapping` above.
                #[cfg(feature = "linux-compat")]
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
    if flags & MAP_SHARED != 0 && anonymous {
        if let Some(v) = shmem_vtable() {
            let handle = (v.create)(current_task_id(), len);
            if handle != 0 {
                let mapped = as_ref.with_vma_transaction(|| {
                    narf_memory::with_shared_mapping_transaction(|| {
                        let mut frames_raw = alloc::vec::Vec::new();
                        if !(v.frames)(handle, &mut frames_raw) || frames_raw.len() != pages {
                            return Err(narf_memory::AddressSpaceError::Unmapped);
                        }
                        let phys = frames_raw
                            .into_iter()
                            .map(narf_memory::PhysAddr::new)
                            .collect();
                        let region = Region {
                            base: VirtAddr::new(base),
                            len,
                            perms: perms | RegionPerms::SHARED,
                            phys,
                        };
                        crate::mapped_file::publish_current_unowned_mapping(
                            base,
                            len,
                            flags & MAP_FIXED != 0,
                            || {
                                // SAFETY: VMA -> shared-owner transactions
                                // cover the backing snapshot and alias
                                // publication.
                                unsafe {
                                    if flags & MAP_FIXED != 0 {
                                        as_ref.replace_shared_region_locked_limited_receipt(
                                            region,
                                            explicit_lock,
                                            mlock_authority.limit_bytes,
                                            mlock_authority.bypass_limit,
                                        )
                                    } else {
                                        as_ref.map_shared_region_locked_limited_receipt(
                                            region,
                                            explicit_lock,
                                            mlock_authority.limit_bytes,
                                            mlock_authority.bypass_limit,
                                        )
                                    }
                                }
                            },
                            |receipt| {
                                // SAFETY: root plus VMA/shared transactions
                                // remain live through completion.
                                match unsafe { as_ref.materialize_mapping_locked(receipt) } {
                                    Ok(()) => Ok(()),
                                    Err(error) => {
                                        // SAFETY: both structural
                                        // transactions remain held.
                                        let _ = unsafe {
                                            as_ref.rollback_mapping_locked(receipt)
                                        };
                                        Err(error)
                                    }
                                }
                            },
                        )
                    })
                });
                if let Ok(receipt) = mapped {
                    record_fixed_replacement_owner_committed!();
                    // This handle is an implementation detail, not a name
                    // userspace can ever attach again. Remove it as soon as
                    // the VMA has retained every frame.
                    if !(v.destroy)(handle) {
                        let _ = as_ref.rollback_mapping(receipt);
                        // Segment teardown failed after mapping → ENOMEM.
                        ctx.set_return(SyscallReturn::ok((-12i64) as u64));
                        return;
                    }
                    #[cfg(feature = "linux-compat")]
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
                let map_error = mapped.expect_err("mapped success returned above");
                (v.destroy)(handle);
                if map_error == narf_memory::AddressSpaceError::LockLimit {
                    ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // EAGAIN
                    return;
                }
                if flags & MAP_FIXED != 0 {
                    ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
                    return;
                }
                // Registry lookup/insertion failure for an ordinary anonymous
                // shared mapping may still degrade to private anonymous.
            }
        }
        // Registry unavailable or create failed: degrade to private anonymous.
    }

    if as_ref
        .check_locked_mapping_limit(
            len,
            explicit_lock,
            mlock_authority.limit_bytes,
            mlock_authority.bypass_limit,
        )
        .is_err()
    {
        ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // EAGAIN
        return;
    }
    let shared_file_fallback = !anonymous && flags & MAP_SHARED != 0;
    let mut shared_file_ops = None;
    let mut phys_list: alloc::vec::Vec<narf_memory::PhysAddr> = if anonymous {
        // Lazy-back: phys[i] == 0; the #PF handler demand-allocates + zeros
        // each page on first access.
        //
        // Allocate the per-page slot vector FALLIBLY. A userspace mmap of an
        // absurd length — e.g. baloo's LMDB opens with a ~256 GiB map size, so
        // `pages` is ~64M and this vector is ~512 MiB — must never panic the
        // kernel: the infallible `vec![_; n]` calls `handle_alloc_error` on OOM,
        // which is a kernel panic. `try_reserve_exact` + `resize` returns
        // -ENOMEM to the process instead (a normal mmap failure).
        let mut v = alloc::vec::Vec::new();
        if v.try_reserve_exact(pages).is_err() {
            ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // -ENOMEM
            return;
        }
        v.resize(pages, narf_memory::PhysAddr::new(0));
        v
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
                // File-backed mapping with an fd not in the fd table → EBADF.
                ctx.set_return(SyscallReturn::ok((-9i64) as u64));
                return;
            }
        };
        if shared_file_fallback {
            shared_file_ops = Some(Arc::clone(&ops));
        }
        // Fallible per-page frame list — see the anonymous branch: never panic
        // the kernel on an oversized userspace mmap; return -ENOMEM. (The frame
        // loop below is already fallible; only this capacity reservation could
        // panic on a huge `pages`.)
        let mut frames = alloc::vec::Vec::new();
        if frames.try_reserve_exact(pages).is_err() {
            ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // -ENOMEM
            return;
        }
        for i in 0..pages {
            let frame = match narf_memory::alloc_frame() {
                Ok(f) => f.start_address(),
                Err(_) => {
                    // Frame allocator exhausted → ENOMEM.
                    ctx.set_return(SyscallReturn::ok((-12i64) as u64));
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

    let mut shared_publication = None;
    if let Some(ops) = shared_file_ops.as_ref() {
        let (canonical, publication) =
            crate::mapped_file::publish_shared_file_pages(ops, offset, phys_list);
        phys_list = canonical;
        shared_publication = Some(publication);
    }
    let writeback_phys = shared_file_ops.as_ref().map(|_| phys_list.clone());
    let region = Region {
            base: VirtAddr::new(base),
            len,
            // Generic MAP_SHARED file mappings borrow a frame from the
            // userspace file-page cache. RegionPerms::SHARED lets multiple
            // VMAs alias one page and delegates lifetime to the cache through
            // memory's shared-frame hooks.
            perms: if shared_file_ops.is_some() {
                perms | RegionPerms::SHARED
            } else {
                perms
            },
            phys: phys_list,
        };
    let map_result = if let Some(ops) = shared_file_ops.as_ref() {
        as_ref.with_vma_transaction(|| {
            narf_memory::with_shared_mapping_transaction(|| {
                crate::mapped_file::publish_current_mapping(
                    crate::mapped_file::MappingOwnerRegistration {
                        base,
                        len,
                        file_offset: offset,
                        ops: Arc::clone(ops),
                        lifetime: None,
                        writeback_phys,
                        replace: flags & MAP_FIXED != 0,
                    },
                    || {
                        // SAFETY: VMA -> shared transactions are held and the
                        // canonical page cache owns every nonzero frame.
                        unsafe {
                            if flags & MAP_FIXED != 0 {
                                as_ref.replace_shared_region_locked_limited_receipt(
                                    region,
                                    explicit_lock,
                                    mlock_authority.limit_bytes,
                                    mlock_authority.bypass_limit,
                                )
                            } else {
                                as_ref.map_shared_region_locked_limited_receipt(
                                    region,
                                    explicit_lock,
                                    mlock_authority.limit_bytes,
                                    mlock_authority.bypass_limit,
                                )
                            }
                        }
                    },
                    |receipt| {
                        // SAFETY: the root and VMA transaction remain live.
                        match unsafe { as_ref.materialize_mapping_locked(receipt) } {
                            Ok(()) => Ok(()),
                            Err(error) => {
                                // SAFETY: VMA -> shared transactions remain
                                // held; rollback cannot target a replacement.
                                let _ = unsafe { as_ref.rollback_mapping_locked(receipt) };
                                Err(error)
                            }
                        }
                    },
                )
            })
        })
    } else if flags & MAP_FIXED != 0 {
        as_ref.with_vma_transaction(|| {
            crate::mapped_file::publish_current_unowned_mapping(
                base,
                len,
                true,
                || {
                    // SAFETY: the VMA transaction is held. This mapping is
                    // private, so no shared transaction is required.
                    unsafe {
                        as_ref.replace_region_locked_limited_receipt(
                            region,
                            explicit_lock,
                            mlock_authority.limit_bytes,
                            mlock_authority.bypass_limit,
                        )
                    }
                },
                |receipt| {
                    if anonymous {
                        return Ok(());
                    }
                    // SAFETY: the root and VMA transaction remain live.
                    match unsafe { as_ref.materialize_mapping_locked(receipt) } {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            // SAFETY: the VMA transaction remains held and the
                            // receipt names a private mapping.
                            let _ = unsafe { as_ref.rollback_mapping_locked(receipt) };
                            Err(error)
                        }
                    }
                },
            )
        })
    } else {
        let receipt = as_ref.map_region_limited_receipt(
            region,
            explicit_lock,
            mlock_authority.limit_bytes,
            mlock_authority.bypass_limit,
        );
        receipt.and_then(|receipt| {
            if anonymous {
                return Ok(receipt);
            }
            finish_nonfixed_private_file_mapping(&as_ref, receipt)
        })
    };
    if let Err(error) = map_result {
        // Drop releases only this attempt's pending cache holds. A concurrent
        // mapper selecting the same canonical page retains its own hold.
        drop(shared_publication);
        let errno = if error == narf_memory::AddressSpaceError::LockLimit {
            11i64 // EAGAIN: a CLONE_VM peer consumed the limit after preflight.
        } else {
            12i64 // ENOMEM
        };
        ctx.set_return(SyscallReturn::ok((-errno) as u64));
        return;
    }
    if let Some(publication) = shared_publication.take() {
        // map_region retained every SHARED frame before returning. Convert
        // this attempt's pending holds into those committed mapping refs.
        publication.commit();
    }
    if shared_file_ops.is_some() {
        record_fixed_replacement_owner_committed!();
    } else if flags & MAP_FIXED != 0 {
        // The unowned publication helper already retired overlapping mapped
        // file owners under the VMA transaction.
        record_fixed_replacement_owner_committed!();
    }

    #[cfg(feature = "linux-compat")]
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

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Mode, Stat};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    use narf_memory::AddressSpace;

    static USER_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);
    const TASK: u64 = 0x4d4d_4150;
    const WORKER_TASK: u64 = TASK + 1;
    const PROCESS: u64 = 0x4d4d_4152;
    static CURRENT_TASK: AtomicU64 = AtomicU64::new(TASK);

    fn address_space() -> Option<Arc<AddressSpace>> {
        USER_AS.lock().clone()
    }

    fn task() -> u64 {
        CURRENT_TASK.load(Ordering::Relaxed)
    }

    struct TestFile {
        bytes: IrqSafeSpinLock<alloc::vec::Vec<u8>>,
        writes: AtomicUsize,
    }

    impl FileOps for TestFile {
        fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move {
                let bytes = self.bytes.lock();
                let start = offset as usize;
                if start >= bytes.len() {
                    return Ok(0);
                }
                let count = (bytes.len() - start).min(buf.len());
                buf[..count].copy_from_slice(&bytes[start..start + count]);
                Ok(count)
            })
        }

        fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move {
                self.writes.fetch_add(1, Ordering::Relaxed);
                let start = offset as usize;
                let end = start + buf.len();
                let mut bytes = self.bytes.lock();
                if bytes.len() < end {
                    bytes.resize(end, 0);
                }
                bytes[start..end].copy_from_slice(buf);
                Ok(buf.len())
            })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: self.bytes.lock().len() as u64,
                blocks: 8,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    struct TestCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }

    impl TrapContext for TestCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }

        fn set_return(&mut self, ret: SyscallReturn) {
            self.ret = Some(ret);
        }

        fn user_rsp(&self) -> u64 {
            0
        }

        fn rip(&self) -> u64 {
            0
        }

        fn set_rip(&mut self, _rip: u64) {}

        fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
            false
        }
    }

    fn mmap_errno(args: SyscallArgs) -> Option<i64> {
        let mut ctx = TestCtx { args, ret: None };
        sys_mmap(&mut ctx);
        ctx.ret
            .filter(|ret| ret.status == SyscallReturn::OK)
            .map(|ret| -(ret.value as i64))
    }

    fn smoke_mmap_linux_validation_errno_order() -> TestResult {
        let aspace = Arc::new(AddressSpace::empty());
        *USER_AS.lock() = Some(aspace);
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);

        let unaligned_offset = mmap_errno(SyscallArgs {
            arg1: 0,
            arg3: 0x10, // MAP_FIXED, file-backed
            arg4: u64::MAX,
            arg5: 1,
            ..SyscallArgs::default()
        });
        let bad_fd_precedes_zero_len = mmap_errno(SyscallArgs {
            arg0: AddressSpace::USER_FIXED_FLOOR + 1,
            arg1: 0,
            arg3: 0x10, // MAP_FIXED, file-backed
            arg4: u64::MAX,
            ..SyscallArgs::default()
        });
        let zero_len_precedes_fixed_alignment = mmap_errno(SyscallArgs {
            arg0: AddressSpace::USER_FIXED_FLOOR + 1,
            arg1: 0,
            arg3: 0x32, // MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS
            arg4: u64::MAX,
            ..SyscallArgs::default()
        });
        let unaligned_fixed = mmap_errno(SyscallArgs {
            arg0: AddressSpace::USER_FIXED_FLOOR + 1,
            arg1: 0x1000,
            arg3: 0x32,
            arg4: u64::MAX,
            ..SyscallArgs::default()
        });
        let below_security_floor = mmap_errno(SyscallArgs {
            arg0: 0,
            arg1: 0x1000,
            arg3: 0x32,
            arg4: u64::MAX,
            ..SyscallArgs::default()
        });
        *USER_AS.lock() = None;

        if unaligned_offset != Some(22)
            || bad_fd_precedes_zero_len != Some(9)
            || zero_len_precedes_fixed_alignment != Some(22)
            || unaligned_fixed != Some(22)
            || below_security_floor != Some(1)
        {
            return TestResult::Fail("mmap validation errno/order diverged from Linux");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_mmap_linux_validation_errno_order);

    fn smoke_nonfixed_file_mmap_stale_completion_is_success() -> TestResult {
        const BASE: u64 = 0x0000_3f00_0000_0000;
        let aspace = AddressSpace::empty();
        let first = Region {
            base: VirtAddr::new(BASE),
            len: 4096,
            perms: RegionPerms::READ,
            phys: vec![PhysAddr::new(0)],
        };
        let receipt = match aspace.map_region_limited_receipt(first, false, u64::MAX, false) {
            Ok(receipt) => receipt,
            Err(_) => return TestResult::Fail("initial file VMA publication failed"),
        };
        let successor = Region {
            base: VirtAddr::new(BASE),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: vec![PhysAddr::new(0)],
        };
        if aspace
            .replace_region_limited_receipt(successor, false, u64::MAX, false)
            .is_err()
        {
            return TestResult::Fail("racing replacement publication failed");
        }
        if finish_nonfixed_private_file_mapping(&aspace, receipt).is_err() {
            return TestResult::Fail("stale completion turned successful mmap into ENOMEM");
        }
        if aspace
            .lookup(VirtAddr::new(BASE))
            .is_none_or(|region| !region.perms.contains(RegionPerms::WRITE))
        {
            return TestResult::Fail("stale completion touched the racing replacement");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_nonfixed_file_mmap_stale_completion_is_success
    );

    /// The syscall must materialize only the VMA it just registered. A full
    /// address-space walk would revisit this deliberately conflicting VMA,
    /// fail on its test-owned huge leaf, and reject an otherwise independent
    /// anonymous mmap.
    fn smoke_sys_mmap_does_not_revisit_unrelated_vmas() -> TestResult {
        // SAFETY: paging is active; the root remains owned by this test.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };
        let conflict = narf_memory::VirtAddr::new(0x0000_3000_0000_0000);
        // SAFETY: this inactive root belongs exclusively to the test. Physical
        // zero is never accessed; the leaf creates only a structural conflict.
        if unsafe {
            narf_memory::x86_64::paging::map_2mb(
                aspace.root,
                conflict,
                narf_memory::PhysAddr::new(0),
                narf_memory::x86_64::paging::PtFlags::USER
                    | narf_memory::x86_64::paging::PtFlags::NO_EXEC,
            )
        }
        .is_err()
        {
            return TestResult::Fail("could not install structural conflict leaf");
        }
        let low_frame = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Fail("frame allocation failed"),
        };
        if aspace
            .map_region(narf_memory::Region {
                base: conflict,
                len: 4096,
                perms: narf_memory::RegionPerms::READ,
                phys: vec![low_frame],
            })
            .is_err()
        {
            return TestResult::Fail("could not register the unrelated VMA");
        }
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);

        let mut mmap = TestCtx {
            args: SyscallArgs {
                arg1: 4096,
                arg2: 3,    // PROT_READ | PROT_WRITE
                arg3: 0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                arg4: u64::MAX,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut mmap);
        let base = match mmap.ret {
            Some(ret) if ret.status == SyscallReturn::OK && (ret.value as i64) > 0 => ret.value,
            _ => {
                *USER_AS.lock() = None;
                return TestResult::Fail("an unrelated VMA poisoned sys_mmap");
            }
        };
        if aspace.lookup(narf_memory::VirtAddr::new(base)).is_none() {
            *USER_AS.lock() = None;
            return TestResult::Fail("sys_mmap returned an unregistered range");
        }
        // The control proves why this catches a regression to `materialize()`.
        // SAFETY: the test-owned user root is still live.
        if unsafe { aspace.materialize() } != Err(narf_memory::AddressSpaceError::Overlap) {
            *USER_AS.lock() = None;
            return TestResult::Fail("control VMA no longer rejects a full materialization");
        }
        *USER_AS.lock() = None;
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_sys_mmap_does_not_revisit_unrelated_vmas);

    /// Anonymous shared mappings have no userspace-visible shmem handle. The
    /// backing entry must therefore be name-removed after the first VMA has
    /// retained it, and reclaimed by that VMA's final unmap rather than being
    /// kept in the global registry until process exit.
    fn smoke_mmap_shared_anon_retires_hidden_handle_on_success() -> TestResult {
        // SAFETY: paging and the frame allocator are live in the kernel-test
        // harness; this test owns the new root until `aspace` is dropped.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);

        let Some(vtable) = shmem_vtable() else {
            *USER_AS.lock() = None;
            return TestResult::Fail("shmem vtable is not installed");
        };
        let mut mmap = TestCtx {
            args: SyscallArgs {
                arg1: 4096,
                arg2: 3,    // PROT_READ | PROT_WRITE
                arg3: 0x21, // MAP_SHARED | MAP_ANONYMOUS
                arg4: u64::MAX,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut mmap);
        let base = match mmap.ret {
            Some(ret) if ret.status == SyscallReturn::OK && (ret.value as i64) > 0 => ret.value,
            _ => {
                *USER_AS.lock() = None;
                return TestResult::Fail("anonymous MAP_SHARED mmap failed");
            }
        };
        let region = match aspace.lookup(VirtAddr::new(base)) {
            Some(region)
                if region.perms.contains(RegionPerms::SHARED)
                    && region.phys.len() == 1
                    && region.phys[0].raw() != 0 =>
            {
                region
            }
            _ => {
                *USER_AS.lock() = None;
                return TestResult::Fail("anonymous MAP_SHARED has no retained frame");
            }
        };

        // NEXT_HANDLE is monotonic and kernel tests are serialized. Creating
        // one probe handle reveals the immediately preceding hidden handle
        // without adding a registry-enumeration API solely for this test.
        let probe = (vtable.create)(TASK, 4096);
        if probe == 0 {
            *USER_AS.lock() = None;
            return TestResult::Fail("could not allocate probe shmem handle");
        }
        let hidden = probe - 1;
        let hidden_is_public = (vtable.pid_of)(hidden) != 0;
        let backing_live = (vtable.owns_frame)(region.phys[0].raw());
        let _ = (vtable.destroy)(probe);
        if hidden_is_public || !backing_live {
            let _ = aspace.unmap_region(VirtAddr::new(base));
            *USER_AS.lock() = None;
            return TestResult::Fail("hidden handle lifecycle is not remove-then-retain");
        }

        if aspace.unmap_region(VirtAddr::new(base)).is_err()
            || (vtable.owns_frame)(region.phys[0].raw())
        {
            *USER_AS.lock() = None;
            return TestResult::Fail("final anonymous shared unmap did not reclaim backing");
        }
        *USER_AS.lock() = None;
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mmap_shared_anon_retires_hidden_handle_on_success
    );

    // `MAP_SHARED` promises that modifications become file data once the
    // caller synchronizes the mapped file. The synchronizing thread need not
    // be the thread that created the mapping: journald's offlining worker
    // maps the header in one thread and fsyncs it from another in the same
    // thread group.
    fn smoke_mmap_shared_file_fsync_writes_back_from_thread_group_peer() -> TestResult {
        // SAFETY: the syscall runs with paging active; this allocates an
        // independent user address space without switching the active one.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
        crate::fd::__test_reset();
        crate::handlers::register_task_to_pid(TASK, PROCESS);
        crate::handlers::register_task_to_pid(WORKER_TASK, PROCESS);

        let file = Arc::new(TestFile {
            bytes: IrqSafeSpinLock::new(vec![0; 4096]),
            writes: AtomicUsize::new(0),
        });
        let fd = crate::fd::install(TASK, crate::fd::FdEntry {
                ops: Arc::clone(&file) as Arc<dyn FileOps>,
                offset: 0,
                flags: 0,
                status_flags: 0,
            })
        .unwrap_or(u32::MAX);
        if fd == u32::MAX {
            return TestResult::Fail("could not install test file fd");
        }
        crate::fd::share(TASK, WORKER_TASK);

        let mut mmap = TestCtx {
            args: SyscallArgs {
                arg1: 4096,
                arg2: 3,    // PROT_READ | PROT_WRITE
                arg3: 0x01, // MAP_SHARED
                arg4: fd as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut mmap);
        let base = match mmap.ret {
            Some(ret) if ret.status == SyscallReturn::OK && (ret.value as i64) > 0 => ret.value,
            _ => return TestResult::Fail("MAP_SHARED file mmap failed"),
        };
        let region = match aspace.lookup(narf_memory::VirtAddr::new(base)) {
            Some(region) if region.phys.len() == 1 && region.phys[0].raw() != 0 => region,
            _ => return TestResult::Fail("file mapping has no physical page"),
        };
        // SAFETY: the syscall allocated this page exclusively for the test
        // mapping and all physical memory is kernel identity-mapped.
        unsafe {
            core::ptr::copy_nonoverlapping(
                c"JOURNAL".as_ptr().cast(),
                region.phys[0].raw() as *mut u8,
                8,
            );
        }

        // A second MAP_SHARED mapping of the same file range must alias the
        // original page, not obtain another private fallback copy. Journald
        // keeps a 4 KiB header mapping alongside a whole-file mapping; two
        // copies would let the stale whole-file page overwrite the header on
        // fsync.
        let mut second_mmap = TestCtx {
            args: SyscallArgs {
                arg1: 4096,
                arg2: 3,    // PROT_READ | PROT_WRITE
                arg3: 0x01, // MAP_SHARED
                arg4: fd as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut second_mmap);
        let second_base = match second_mmap.ret {
            Some(ret) if ret.status == SyscallReturn::OK && (ret.value as i64) > 0 => ret.value,
            _ => return TestResult::Fail("second MAP_SHARED file mmap failed"),
        };
        let second_region = match aspace.lookup(narf_memory::VirtAddr::new(second_base)) {
            Some(region) if region.phys.len() == 1 && region.phys[0].raw() != 0 => region,
            _ => return TestResult::Fail("second file mapping has no physical page"),
        };
        if second_region.phys[0] != region.phys[0] {
            return TestResult::Fail("same-range MAP_SHARED mappings did not alias one file page");
        }
        // SAFETY: both mappings resolve to the same identity-mapped page.
        if unsafe { core::slice::from_raw_parts(second_region.phys[0].raw() as *const u8, 8) }
            != b"JOURNAL\0"
        {
            return TestResult::Fail(
                "second MAP_SHARED mapping did not observe the first mapping's write",
            );
        }

        // Switch to a CLONE_THREAD peer. It has the same process-visible PID
        // and shared fd table, but a distinct scheduler TaskId.
        CURRENT_TASK.store(WORKER_TASK, Ordering::Relaxed);
        let mut fsync = TestCtx {
            args: SyscallArgs {
                arg0: fd as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        crate::handlers::sys_fsync(&mut fsync);
        if !matches!(fsync.ret, Some(ret) if ret.status == SyscallReturn::OK && ret.value == 0) {
            return TestResult::Fail("fsync on the mapped file failed");
        }
        if &file.bytes.lock()[..8] != b"JOURNAL\0" {
            return TestResult::Fail("MAP_SHARED file data was not written back by fsync");
        }
        if file.writes.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("aliased MAP_SHARED page was written more than once");
        }

        // A second fsync with no intervening mapped write must not rewrite the
        // entire fallback mapping. Journald keeps multi-megabyte sparse
        // mappings, so clean-page suppression is required for usable boot
        // latency rather than merely being an optimization detail.
        crate::handlers::sys_fsync(&mut fsync);
        if file.writes.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("fsync rewrote a clean MAP_SHARED page");
        }

        // SAFETY: both mappings still retain the identity-mapped page.
        unsafe {
            *(second_region.phys[0].raw() as *mut u8).add(8) = b'!';
        }
        crate::handlers::sys_fsync(&mut fsync);
        if file.writes.load(Ordering::Relaxed) != 2 || file.bytes.lock()[8] != b'!' {
            return TestResult::Fail("a MAP_SHARED write after fsync was not persisted");
        }

        let _ = aspace.unmap_region(narf_memory::VirtAddr::new(second_base));
        crate::mapped_file::unmap_current(second_base);
        let _ = aspace.unmap_region(narf_memory::VirtAddr::new(base));
        crate::mapped_file::unmap_current(base);
        crate::fd::__test_reset();
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mmap_shared_file_fsync_writes_back_from_thread_group_peer
    );

    // ── demand-paged device mappings, through a BPF arena ──────────────
    //
    // The arena is the first `FileOps` that both grows behind a live mapping
    // and owns frames the buddy will hand out again, so it is where the two
    // properties this section pins are reachable at all. Both tests drive the
    // real `sys_mmap`, then call `demand_alloc_page` directly for the faults —
    // the same shape `memory/src/tests.rs` uses, because the trap handler's own
    // plumbing (CR2, the user-mode entry) is not reproducible from a kernel
    // test and is not what is under test here.

    const ARENA_TASK: u64 = 0x4152_454e;
    const ARENA_PROCESS: u64 = 0x4152_4550;

    /// Stand up a fresh user AS owned by `ARENA_TASK` and make the syscall
    /// layer see it as current.
    fn arena_test_setup() -> Option<Arc<AddressSpace>> {
        // SAFETY: the syscall runs with paging active; this allocates an
        // independent user address space without switching the active one.
        let aspace = Arc::new(unsafe { AddressSpace::new_for_user() }.ok()?);
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(ARENA_TASK, Ordering::Relaxed);
        crate::fd::__test_reset();
        crate::handlers::register_task_to_pid(ARENA_TASK, ARENA_PROCESS);
        Some(aspace)
    }

    fn arena_test_teardown() {
        crate::fd::__test_reset();
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
        *USER_AS.lock() = None;
    }

    fn install_fd(ops: Arc<dyn FileOps>) -> Option<u32> {
        crate::fd::install(ARENA_TASK, crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: 0,
            })
    }

    fn mmap_shared(fd: u32, len: u64) -> Option<u64> {
        let mut call = TestCtx {
            args: SyscallArgs {
                arg1: len,
                arg2: 3,    // PROT_READ | PROT_WRITE
                arg3: 0x01, // MAP_SHARED
                arg4: u64::from(fd),
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut call);
        match call.ret {
            Some(ret) if ret.status == SyscallReturn::OK && (ret.value as i64) > 0 => {
                Some(ret.value)
            }
            _ => None,
        }
    }

    /// **The feature.** A page populated *after* `mmap` appears in the existing
    /// mapping, in both directions: the kernel side grows the arena and
    /// userspace sees the new page, and userspace faults a page the kernel had
    /// not backed and the arena grows to cover it.
    ///
    /// Under `FileOps::mmap_frames` neither was possible. That hook is answered
    /// once, at `mmap` time, so the mapping was a snapshot — which is why
    /// `Arena::populate` used to refuse to grow at all once the frames had been
    /// handed out (`ArenaError::SnapshotTaken`). The kernel-side half of this
    /// lives in `bpf/src/arena.rs`
    /// (`smoke_bpf_arena_grows_under_a_live_mapping`); what *this* one adds is
    /// the clause that matters — that a real `MAP_SHARED` mapping's page faults
    /// route to the file and land the arena's own frame in the user region.
    fn smoke_bpf_arena_demand_population_is_visible_in_a_live_mapping() -> TestResult {
        use narf_bpf::arena::{ArenaFile, ArenaGroup};

        let Some(aspace) = arena_test_setup() else {
            return TestResult::Fail("new_for_user failed");
        };
        let cap = narf_bpf::arena::kernel_arena_cap();
        let mut group = match ArenaGroup::new(cap) {
            Ok(g) => g,
            Err(_) => return TestResult::Fail("ArenaGroup::new failed"),
        };
        // Nothing live, room for three pages: every page in the mapping has to
        // be demand-populated, so a regression to eager backing cannot hide.
        let arena = match group.add_reserved(cap, 0, 3) {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("add_reserved failed"),
        };
        let file: Arc<dyn FileOps> = Arc::new(ArenaFile::new(Arc::clone(&arena)));
        let Some(fd) = install_fd(Arc::clone(&file)) else {
            return TestResult::Fail("could not install the arena fd");
        };
        let Some(base) = mmap_shared(fd, 3 * 4096) else {
            arena_test_teardown();
            return TestResult::Fail("MAP_SHARED mmap of the arena failed");
        };

        let unbacked = |page: usize| -> Option<bool> {
            Some(
                aspace
                    .lookup(narf_memory::VirtAddr::new(base))?
                    .phys
                    .get(page)?
                    .raw()
                    == 0,
            )
        };
        // `sys_mmap` probes support by faulting the first page, so page 0 is
        // backed in the *arena* — but nothing is backed in the *region*, which
        // is the point: the region is entirely demand-paged.
        if unbacked(0) != Some(true) || unbacked(2) != Some(true) {
            arena_test_teardown();
            return TestResult::Fail("the arena mapping was eagerly backed");
        }
        if arena.len_bytes() != 4096 {
            arena_test_teardown();
            return TestResult::Fail("the mmap probe did not back exactly the first page");
        }

        // ── direction 1: the kernel grows the arena under the live mapping ──
        if arena.populate_through(1).is_err() {
            arena_test_teardown();
            return TestResult::Fail("growing the arena under a live mapping failed");
        }
        // Stand in for a program's store — same kernel VA the interpreter uses.
        // SAFETY: `populate_through(1)` just mapped this page RW in the arena
        // window, and this test owns the arena.
        unsafe {
            ((arena.kva() + 4096) as *mut u64).write_volatile(0xFEED_FACE_0000_0001);
        }
        // SAFETY: `aspace` is a live user root built by `new_for_user`; the
        // identity map is up (we are running with paging active).
        if unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(base + 4096)) }.is_err() {
            arena_test_teardown();
            return TestResult::Fail("the mapping could not fault in a page the arena had grown");
        }
        let Some(region) = aspace.lookup(narf_memory::VirtAddr::new(base)) else {
            arena_test_teardown();
            return TestResult::Fail("the arena mapping vanished");
        };
        if region.phys.get(1).map(|p| Some(*p)) != Some(arena.frame_at(1)) {
            arena_test_teardown();
            return TestResult::Fail("the fault did not install the arena's own frame");
        }
        // What userspace reads through that mapping is what the kernel wrote.
        // SAFETY: the frame is one the arena owns and holds for its whole life;
        // `kernel_ptr` is the direct-map view of it.
        let seen = unsafe { region.phys[1].kernel_ptr::<u64>().read_volatile() };
        if seen != 0xFEED_FACE_0000_0001 {
            arena_test_teardown();
            return TestResult::Fail("the mapping did not show the bytes written after the mmap");
        }

        // ── direction 2: userspace faults a page the arena had not backed ──
        if arena.frame_at(2).is_some() {
            arena_test_teardown();
            return TestResult::Fail("page 2 was backed before anything touched it");
        }
        // SAFETY: as above.
        if unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(base + 2 * 4096)) }.is_err()
        {
            arena_test_teardown();
            return TestResult::Fail("a first touch of an unpopulated arena page did not back it");
        }
        if arena.len_bytes() != 3 * 4096 {
            arena_test_teardown();
            return TestResult::Fail("a userspace fault did not grow the arena's live extent");
        }
        let Some(region) = aspace.lookup(narf_memory::VirtAddr::new(base)) else {
            arena_test_teardown();
            return TestResult::Fail("the arena mapping vanished");
        };
        if region.phys.get(2).map(|p| Some(*p)) != Some(arena.frame_at(2)) {
            arena_test_teardown();
            return TestResult::Fail("the second fault did not install the arena's own frame");
        }
        // A freshly populated page must be zeroed — arena memory is
        // program-visible and must never carry the previous owner's bytes into
        // a userspace mapping.
        // SAFETY: as above.
        if unsafe { region.phys[2].kernel_ptr::<u64>().read_volatile() } != 0 {
            arena_test_teardown();
            return TestResult::Fail("a demand-populated arena page reached userspace unzeroed");
        }
        // And the two pages are distinct frames, so neither read above was
        // accidentally the other page.
        if region.phys[1] == region.phys[2] {
            arena_test_teardown();
            return TestResult::Fail("two pages of the mapping resolved to one frame");
        }

        let _ = aspace.unmap_region(narf_memory::VirtAddr::new(base));
        crate::mapped_file::unmap_current(base);
        arena_test_teardown();
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_bpf_arena_demand_population_is_visible_in_a_live_mapping
    );

    /// **The lifetime fix.** An arena's frames go back to the buddy exactly
    /// when no mapping remains: not while one is live, and immediately once
    /// `munmap` releases it.
    ///
    /// This replaces `smoke_bpf_arena_exposed_frames_are_not_returned_to_the_buddy`,
    /// which pinned a deliberate leak — at the time a mapping kept nothing
    /// alive, so freeing on drop handed userspace a writable window onto
    /// whatever the buddy allocated next, and losing the memory was the
    /// least-bad answer. The mapping now owns the `Arc<dyn FileOps>`, so the
    /// leak is deleted and this is what has to hold instead.
    ///
    /// Asserted through the frame allocator, not through a flag: a test reading
    /// a flag would pass even if `Arena::drop` ignored it. Both deltas are
    /// measured across the drop that could return the frames and nothing else —
    /// sampling before the allocation and expecting a rise afterwards is wrong
    /// arithmetic, since allocate-then-free returns to the original count.
    ///
    /// Neither half is sufficient alone. An implementation that never frees
    /// passes the first and fails the second; one that always frees passes the
    /// second and fails the first.
    fn smoke_bpf_arena_mapping_keeps_frames_alive_until_munmap() -> TestResult {
        use narf_bpf::arena::{ArenaFile, ArenaGroup};
        // Large enough that the assertions cannot be satisfied by unrelated
        // frame traffic in either direction: a stray free during the live
        // window has 15 frames of headroom, and 16 is far more than the noise
        // a single-threaded kernel test sees between two adjacent samples.
        const PAGES: usize = 16;

        let Some(aspace) = arena_test_setup() else {
            return TestResult::Fail("new_for_user failed");
        };
        let cap = narf_bpf::arena::kernel_arena_cap();
        let mut group = match ArenaGroup::new(cap) {
            Ok(g) => g,
            Err(_) => return TestResult::Fail("ArenaGroup::new failed"),
        };
        let arena = match group.add(cap, PAGES) {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("adding the arena failed"),
        };
        let file: Arc<dyn FileOps> = Arc::new(ArenaFile::new(Arc::clone(&arena)));
        let Some(fd) = install_fd(Arc::clone(&file)) else {
            return TestResult::Fail("could not install the arena fd");
        };
        let Some(base) = mmap_shared(fd, PAGES as u64 * 4096) else {
            arena_test_teardown();
            return TestResult::Fail("MAP_SHARED mmap of the arena failed");
        };

        // Everything userspace would do to strand the arena: close the fd, and
        // let every kernel-side handle go. What remains is the mapping.
        crate::fd::with_table(ARENA_TASK, |table| table.close(fd));
        drop(file);
        drop(arena);
        let before = narf_memory::frame::stats().free;
        drop(group);
        let while_mapped = narf_memory::frame::stats().free.saturating_sub(before);
        if while_mapped >= PAGES {
            arena_test_teardown();
            return TestResult::Fail(
                "arena frames went back to the buddy while a userspace mapping still had them",
            );
        }

        // Now release the mapping. Its `Arc<dyn FileOps>` was the last
        // reference, so this is the drop that must free them.
        let before = narf_memory::frame::stats().free;
        let mut call = TestCtx {
            args: SyscallArgs {
                arg0: base,
                arg1: PAGES as u64 * 4096,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        crate::handlers::sys_munmap(&mut call);
        if !matches!(call.ret, Some(ret) if ret.status == SyscallReturn::OK && ret.value == 0) {
            arena_test_teardown();
            return TestResult::Fail("munmap of the arena mapping failed");
        }
        let after_munmap = narf_memory::frame::stats().free.saturating_sub(before);
        if after_munmap < PAGES {
            arena_test_teardown();
            return TestResult::Fail("munmap did not return the arena's frames to the buddy");
        }
        // The region is gone too, so a later fault cannot reach the freed
        // frames through a stale mapping.
        if aspace.lookup(narf_memory::VirtAddr::new(base)).is_some() {
            arena_test_teardown();
            return TestResult::Fail("munmap left the arena region registered");
        }
        arena_test_teardown();
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_bpf_arena_mapping_keeps_frames_alive_until_munmap
    );
}
