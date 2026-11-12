#[allow(unused_imports)]
use super::*;

/// Build sparse VMA backing without routing allocation failure through
/// `FromIterator`'s infallible `RegionBacking::push` path.
fn try_raw_region_backing(
    frames: &[u64],
) -> Result<narf_memory::region_backing::RegionBacking, ()> {
    let mut backing = narf_memory::region_backing::RegionBacking::new();
    backing.resize(frames.len(), narf_memory::PhysAddr::new(0));
    for (index, &raw) in frames.iter().enumerate() {
        if raw == 0 {
            continue;
        }
        backing.reserve_slot(index).map_err(|_| ())?;
        *backing
            .get_mut(index)
            .expect("reserved region-backing slot disappeared") =
            narf_memory::PhysAddr::new(raw);
    }
    Ok(backing)
}

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

/// Best-effort anonymous `MAP_POPULATE` backing. Frames stay privately owned
/// by `owned` until the VMA publication succeeds; the caller returns them in
/// one batch if a later admission or replacement step fails.
fn prepare_anonymous_population(
    base: u64,
    phys: &mut [narf_memory::PhysAddr],
    owned: &mut alloc::vec::Vec<narf_memory::PhysFrame>,
) {
    if owned.try_reserve_exact(phys.len()).is_err() {
        return;
    }
    for (index, slot) in phys.iter_mut().enumerate() {
        let va = base.saturating_add((index as u64) << 12);
        publish_mempolicy_for_fault(va);
        let allocated = narf_memory::alloc_frame_policied(narf_memory::frame::local_node());
        clear_mempolicy_for_fault();
        let Ok(frame) = allocated else {
            break;
        };
        let frame_phys = frame.start_address();
        // SAFETY: this freshly allocated frame is exclusively owned by this
        // population attempt and reachable through the kernel direct map.
        unsafe {
            core::ptr::write_bytes(frame_phys.kernel_mut_ptr::<u8>(), 0, 4096);
        }
        *slot = frame_phys;
        owned.push(frame);
    }
}

/// Populate the fallback backing for a file mapping one page at a time.
///
/// The returned physical addresses remain owned by the caller until they are
/// either published into a VMA or the shared-file cache. Allocation failure
/// releases every page already prepared by this attempt.
pub(crate) fn load_file_mapping_pages(
    ops: &Arc<dyn narf_filesystem::FileOps>,
    offset: u64,
    len_bytes: usize,
    pages: usize,
) -> Result<alloc::vec::Vec<narf_memory::PhysAddr>, ()> {
    let mut frames = alloc::vec::Vec::new();
    if frames.try_reserve_exact(pages).is_err() {
        return Err(());
    }
    let epoch = crate::mapped_file::read_epoch();
    for i in 0..pages {
        let frame = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => {
                for frame in frames {
                    narf_memory::free_frame(narf_memory::PhysFrame::new(frame));
                }
                return Err(());
            }
        };
        let off = i * 4096;
        let want = core::cmp::min(4096, len_bytes - off);
        // SAFETY: freshly-allocated identity-mapped frame; zero the whole
        // page first so any tail past `want` (and past EOF) reads as zero.
        unsafe {
            core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
        }
        // SAFETY: `frame` is identity-mapped in the low 4 GiB and `want` is
        // at most one page, so this slice stays within the allocation.
        let dst = unsafe { core::slice::from_raw_parts_mut(frame.kernel_mut_ptr::<u8>(), want) };
        let mut done = 0usize;
        while done < want {
            // Keep one future alive through completion. Dropping a pending
            // driver read could let DMA target a recycled scratch buffer.
            match poll_io_to_completion(
                ops.read(offset + off as u64 + done as u64, &mut dst[done..]),
            ) {
                Some(Ok(0)) | None => break,
                Some(Ok(n)) => done += n,
                Some(Err(_)) => break,
            }
        }
        // A store through another `MAP_SHARED` mapping that has not been
        // written back yet is part of the file this mapping copies.
        let done = done.min(want);
        crate::mapped_file::overlay_dirty(ops, offset + off as u64, &mut dst[..done], epoch);
        frames.push(frame);
    }
    Ok(frames)
}

/// Load one faulted file page into a fresh private frame.
///
/// Unlike the historical eager mmap fallback, a demand fault must not turn an
/// I/O error into a readable zero page. Bytes after the current EOF within the
/// final page remain zero, while an offset wholly beyond EOF or a failed read
/// rejects the fault and returns the frame to the allocator.
///
/// The error says why, for `vmf_error`: `OutOfMemory` when no frame could be
/// had (the fault waits for reclaim and retries), anything else — past EOF, a
/// failed read — is SIGBUS.
pub(crate) fn load_file_demand_page(
    ops: &Arc<dyn narf_filesystem::FileOps>,
    offset: u64,
) -> Result<narf_memory::PhysAddr, narf_filesystem::FsError> {
    let file_size = ops.stat().size;
    if offset >= file_size {
        return Err(narf_filesystem::FsError::BadAddress);
    }
    let frame = narf_memory::alloc_frame()
        .map_err(|_| narf_filesystem::FsError::OutOfMemory)?
        .start_address();
    // SAFETY: `frame` is a fresh exclusively-owned direct-mapped frame.
    unsafe {
        core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
    }
    let want = (file_size - offset).min(4096) as usize;
    let epoch = crate::mapped_file::read_epoch();
    // The fill owns the frame from here: it is handed back on success and
    // freed on every other outcome. `filemap_fault` sleeps killably
    // (`__folio_lock_or_retry` under `FAULT_FLAG_KILLABLE`), so a fatal
    // signal ends this park; the read finishes without the task, and the
    // trap handler delivers the pending signal when this fault fails.
    match crate::killable_wait::fill_frame(ops, offset, frame, want) {
        Ok(Some(Ok(filled))) => {
            // A private copy is a copy of the file as a mapping of it shows
            // it now: a `MAP_SHARED` store not written back yet is part of
            // that (Linux copies from the same folio the store went to).
            // SAFETY: the fill returned the frame to this fault; nothing
            // else can reach it until this returns, and `want <= 4096`.
            let page =
                unsafe { core::slice::from_raw_parts_mut(filled.kernel_mut_ptr::<u8>(), want) };
            crate::mapped_file::overlay_dirty(ops, offset, page, epoch);
            Ok(filled)
        }
        Ok(Some(Err(error))) => Err(error),
        Ok(None) | Err(crate::killable_wait::Killed) => {
            Err(narf_filesystem::FsError::Io(narf_block::BlockError::IOError))
        }
    }
}

/// Read `len` bytes of an fd starting at `offset` into a fresh buffer,
/// zero-padding past EOF (the BSS tail of a file-backed segment).
pub(crate) fn sys_mmap(ctx: &mut dyn TrapContext) {
    const PROT_READ: u32 = 0x1;
    const PROT_WRITE: u32 = 0x2;
    const PROT_EXEC: u32 = 0x4;
    let args = *ctx.args();
    let hint = args.arg0;
    // Standard 6-arg mmap ABI: arg2 prot, arg3 flags, arg4 fd, arg5 offset.
    // narf_user_runtime::mmap issues this same shape for NARF-native
    // anonymous maps (prot=RW, fd=-1), so the kernel decodes one layout.
    let mut prot = args.arg2 as u32;
    let flags = args.arg3 as u32;
    let fd = args.arg4 as i64 as i32;
    let offset = args.arg5;
    const MAP_FIXED: u32 = 0x10;
    const MAP_ANONYMOUS: u32 = 0x20;
    const MAP_SHARED: u32 = 0x01;
    const MAP_PRIVATE: u32 = 0x02;
    const MAP_TYPE: u32 = 0x0f;
    const MAP_SHARED_VALIDATE: u32 = 0x03;
    const MAP_LOCKED: u32 = 0x2000;
    const MAP_POPULATE: u32 = 0x8000;
    const MAP_NONBLOCK: u32 = 0x1_0000;
    const MAP_HUGETLB: u32 = 0x0004_0000;
    const MAP_FIXED_NOREPLACE: u32 = 0x0010_0000;
    const MAP_HUGE_SHIFT: u32 = 26;
    const MAP_HUGE_MASK: u32 = 0x3f;
    // do_mmap: "force arch specific MAP_FIXED handling in get_unmapped_area".
    // MAP_FIXED_NOREPLACE is MAP_FIXED plus "fail instead of replacing"; used
    // to be ignored outright here, so a loader asking for an exact base got a
    // *different* base back with a success return, and — worse — a plain
    // MAP_FIXED_NOREPLACE at an occupied address silently destroyed the
    // mapping it was explicitly asking not to touch.
    let fixed_noreplace = flags & MAP_FIXED_NOREPLACE != 0;
    let flags = if fixed_noreplace {
        flags | MAP_FIXED
    } else {
        flags
    };
    let fixed = flags & MAP_FIXED != 0;
    let destructive_fixed = fixed && !fixed_noreplace;
    let anonymous = flags & MAP_ANONYMOUS != 0;

    // Both x86_64 and AArch64 reject a non-page-aligned byte offset in the
    // architecture syscall wrapper before fd lookup or any mmap work.
    if offset & 0xFFF != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(no_address_space());
            return;
        }
    };
    // `mm/vma.c`: a MAP_FIXED that would replace a sealed mapping is -EPERM.
    // Only the DESTRUCTIVE form — MAP_FIXED_NOREPLACE fails with -EEXIST on
    // its own and never replaces anything, so it has nothing to defeat.
    // This is the arm sealing exists for: "Modifying a VMA via
    // mmap(MAP_FIXED)" is listed alongside munmap and mremap as an operation
    // that can put different contents at an address the caller trusted.
    if destructive_fixed
        && handler_sys_mseal::range_is_sealed(as_ref.identity(), args.arg0, args.arg1)
    {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    // ksys_mmap_pgoff resolves a non-anonymous fd before huge-flag and
    // do_mmap length/address validation. Thus EBADF wins over a zero length or
    // malformed MAP_FIXED address (but not over the arch offset check above).
    //
    //     file = fget(fd);
    //     if (!file) return -EBADF;
    //
    // `fget` masks out FMODE_PATH, so an O_PATH descriptor is "not a file" for
    // mmap and reports EBADF — not EACCES/EINVAL. A caller that opened O_PATH
    // to inspect a path and then tried to map it must be told the descriptor
    // is unusable, which is what sends it back through a real open(2).
    let file = if !anonymous {
        // This is NARF's `fget`: retain the open-file description once and
        // carry that exact object through validation and VMA publication. A
        // later close or fd-number reuse must not change either the access
        // mode just authorized or the FileOps object ultimately mapped.
        let Some((ops, status_flags)) = (if fd >= 0 {
            fd::with_table(current_task_id(), |table| {
                table
                    .get(fd as u32)
                    .map(|entry| (Arc::clone(&entry.ops), entry.status_flags))
            })
            .flatten()
        } else {
            None
        })
        else {
            ctx.set_return(errno_ret(EBADF));
            return;
        };
        // `fget` masks out FMODE_PATH. An O_PATH description has neither
        // read nor write mapping authority, so it remains EBADF rather than
        // being misreported as an ordinary EACCES denial.
        if status_flags & crate::fd::O_PATH != 0 {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
        // ksys_mmap_pgoff, immediately after fget:
        //
        //     if (is_file_hugepages(file)) { ... }
        //     else if (unlikely(flags & MAP_HUGETLB)) { retval = -EINVAL; goto out_fput; }
        //
        // NARF has no hugetlbfs, so every fd takes the else branch. EINVAL
        // ("MAP_HUGETLB needs an anonymous mapping or a hugetlbfs file") is a
        // fixable-argument answer; the ENODEV this used to return means "the
        // filesystem cannot be mapped at all" and makes a caller give up on
        // the file rather than retry without MAP_HUGETLB.
        if flags & MAP_HUGETLB != 0 {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
        Some((ops, status_flags))
    } else {
        None
    };

    let huge_size = if flags & MAP_HUGETLB != 0 {
        match (flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK {
            0 | 21 => Some(narf_memory::hugepage::HugeSize::M2),
            30 => Some(narf_memory::hugepage::HugeSize::G1),
            _ => {
                ctx.set_return(errno_ret(EINVAL));
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
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let len = match args.arg1.checked_add(page_size - 1) {
        Some(v) => v & !(page_size - 1),
        None => {
            ctx.set_return(errno_ret(ENOMEM));
            return;
        }
    };

    // Whether the backing object would allow an execute mapping at all —
    // NARF's `path_noexec` (see the READ_IMPLIES_EXEC block below). Anonymous
    // memory always would.
    let mut file_allows_exec = true;
    if let Some((ops, _)) = file.as_ref() {
        file_allows_exec = ops.mmap_max_prot(offset) & PROT_EXEC != 0;
        match ops.validate_mmap(offset, len as usize, prot, flags) {
            Ok(adjusted) => {
                if adjusted & 7 & !ops.mmap_max_prot(offset) != 0 {
                    ctx.set_return(errno_ret(EACCES));
                    return;
                }
                prot = adjusted;
            }
            Err(error) => {
                ctx.set_return(errno_ret(copy_fs_errno(error)));
                return;
            }
        }
    }

    // do_mmap's `if ((pgoff + (len >> PAGE_SHIFT)) < pgoff) return -EOVERFLOW;`
    // has no reachable counterpart on this entry point: both x86_64 and
    // AArch64 reach mmap through the byte-offset wrapper, which derives
    // `pgoff = off >> PAGE_SHIFT` and so caps it at 2^52. The sum with
    // `len >> PAGE_SHIFT` (also <= 2^52) cannot wrap an unsigned long. Only
    // the raw-pgoff entry points (mmap2/mmap_pgoff) can reach it, and NARF
    // exposes none.

    // Semantic failures must precede MAP_FIXED replacement: an invalid new
    // mapping never destroys the old one on Linux.
    //
    // __get_unmapped_area, in this order:
    //
    //     if (addr > TASK_SIZE - len)  return -ENOMEM;
    //     if (offset_in_page(addr))    return -EINVAL;
    //     error = security_mmap_addr(addr);   /* cap_mmap_addr => -EPERM */
    //
    // The range test wins over the alignment test. That is not cosmetic: a
    // MAP_FIXED probe that walks candidate bases upward (JITs and sandboxes
    // that place a fixed-address arena do exactly this) uses ENOMEM as "past
    // the end, stop walking" and EINVAL as "my alignment arithmetic is
    // broken, abort". Reporting EINVAL for a well-formed base that merely sat
    // above the user half turned the first into the second.
    if fixed {
        let fixed_in_range = hint
            .checked_add(len)
            .map(|end| end <= AddressSpace::USER_HALF_END)
            .unwrap_or(false);
        if !fixed_in_range {
            ctx.set_return(errno_ret(ENOMEM));
            return;
        }
        if hint & (page_size - 1) != 0 {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
        // security_mmap_addr -> cap_mmap_addr: below mmap_min_addr this needs
        // CAP_SYS_RAWIO, and the denial is EPERM. NARF's USER_FIXED_FLOOR is
        // that policy boundary.
        if hint < AddressSpace::USER_FIXED_FLOOR {
            ctx.set_return(errno_ret(EPERM));
            return;
        }
        //     if (flags & MAP_FIXED_NOREPLACE) {
        //             if (find_vma_intersection(mm, addr, addr + len))
        //                     return -EEXIST;
        //     }
        //
        // EEXIST is the whole point of the flag: ld.so and the Go/Rust runtime
        // reservation code use it to claim a specific base *without* the
        // destructive replacement MAP_FIXED implies, and treat EEXIST as
        // "someone else owns that base, pick another". Ignoring it made the
        // probe destroy the mapping it was probing for.
        //
        // Huge mappings live in their own vector, so `perms_intersecting`
        // alone answers "nothing is here" over a hugetlb mapping and the
        // probe destroys the very thing it was probing for. Both sets have
        // to be consulted.
        if fixed_noreplace
            && (!as_ref
                .perms_intersecting(VirtAddr::new(hint), len)
                .is_empty()
                || as_ref.huge_intersects(VirtAddr::new(hint), len))
        {
            ctx.set_return(errno_ret(EEXIST));
            return;
        }
    }
    let mlock_authority = current_mlock_authority();
    let explicit_lock = flags & MAP_LOCKED != 0;
    if explicit_lock && !can_do_mlock(mlock_authority) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    // do_mmap's `switch (flags & MAP_TYPE)` — for both the file and the
    // anonymous arm — ends in `default: return -EINVAL`. Only MAP_SHARED(1),
    // MAP_PRIVATE(2) and MAP_SHARED_VALIDATE(3) are mapping types; anything
    // else (including *no* type bit at all, the classic
    // `mmap(NULL, n, prot, MAP_ANONYMOUS, -1, 0)` typo) is rejected.
    //
    // NARF used to treat every unrecognised type as private, so that typo
    // produced a working private mapping here and a hard EINVAL on Linux —
    // the divergence only shows up when the code is finally run on Linux.
    //
    // MAP_DROPPABLE (MAP_TYPE 0x08) became a valid type in Linux 6.11. NARF
    // has no droppable backing — pages that the kernel may reclaim without
    // swapping and that read back as zeroes — so it lands in this EINVAL.
    //
    // That is not a divergence to fix by accepting the flag: -EINVAL is
    // exactly what every pre-6.11 kernel returns for it, so a caller
    // probing for support gets a true answer and falls back. Accepting it
    // and handing back an ordinary private mapping would tell that caller
    // its pages are droppable when they are pinned for the process's life —
    // the failure would surface as memory never being reclaimed under
    // pressure, far from here. Implementing it means the reclaim path,
    // not this line.
    let map_type = flags & MAP_TYPE;
    if map_type != MAP_SHARED && map_type != MAP_PRIVATE && map_type != MAP_SHARED_VALIDATE {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    if let Some((_, status_flags)) = file.as_ref() {
        let access_mode = *status_flags & crate::fd::O_ACCMODE;
        // Linux `do_mmap` first requires FMODE_WRITE for a shared writable
        // VMA, then falls through to require FMODE_READ for every file VMA.
        // The access bits in an open-file description are immutable, so this
        // one snapshot remains valid for all later demand faults.
        if (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE)
            && prot & PROT_WRITE != 0
            && access_mode != crate::fd::O_RDWR
        {
            ctx.set_return(errno_ret(EACCES));
            return;
        }
        if access_mode != crate::fd::O_RDONLY && access_mode != crate::fd::O_RDWR {
            ctx.set_return(errno_ret(EACCES));
            return;
        }
    }

    // The file a mapping faults from is chosen here, once. Linux pins the
    // real file in the VMA (`ovl_mmap` calls `vma_set_file` with the
    // overlay's current real file), so a later overlay copy-up changes
    // what *new* mappings see but never retargets an existing VMA.
    // Resolve that pin now — outside every VMA/owner lock — and let the
    // already-validated description carry the pinned object into
    // provenance and every publication branch below, so demand faults,
    // the shared-page cache and `truncate_file_mappings`' identity match
    // all name the one file this mapping will ever fault from. Files
    // that are not switchable wrappers return their own reference.
    let file = file.map(|(ops, status_flags)| {
        let pinned = ops.mmap_pinned_file(Arc::clone(&ops));
        (pinned, status_flags)
    });

    // `fs/proc/task_mmu.c::show_map_vma` prints, for every VMA with a
    // `vm_file`, the inode's `i_sb->s_dev` and `i_ino` and the file's path.
    // Capture that identity here, outside every VMA/owner lock, and let the
    // file-owner row carry it through splits, mremap and fork. Crashpad groups
    // a DSO's VMAs by `(dev, ino)` and reads the ELF header at the offset-0
    // one, so ld.so's mappings must not look anonymous.
    //
    // LINUX-GAP: the eager private-file copy (MAP_POPULATE / MAP_LOCKED
    // without MAP_NONBLOCK) registers no file owner and therefore still
    // renders as `00:00 0` with no path; Linux keeps `vm_file` there too.
    // A memfd has no open path; `show_map_vma` prints its `d_path`,
    // `/memfd:<name> (deleted)`.
    // `VM_MAYWRITE` of a shared file mapping: only a descriptor open for
    // writing lets the mapping (now, or after an `mprotect`) store to the
    // file's pages.
    let shared = map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE;
    let fd_writable = file.as_ref().is_some_and(|(_, status_flags)| {
        *status_flags & crate::fd::O_ACCMODE == crate::fd::O_RDWR
    });
    let provenance = file.as_ref().map(|(ops, _)| {
        Arc::new(crate::mapped_file::MappingProvenance {
            device: ops.inode_attrs().dev,
            inode: ops.ino(),
            // `d_path`, as it reads when the mapping is made.
            pathname: crate::mqueue::fd_name(current_task_id(), fd as u32)
                .map(|name| {
                    if name.deleted {
                        alloc::format!("{} (deleted)", name.path)
                    } else {
                        alloc::string::String::from(&*name.path)
                    }
                })
                .or_else(|| internal_file_path(&**ops)),
            writable: shared && fd_writable,
        })
    });

    // `mm/mmap.c::do_mmap`:
    //
    // ```text
    // /*
    //  * Does the application expect PROT_READ to imply PROT_EXEC?
    //  *
    //  * (the exception is when the underlying filesystem is noexec
    //  *  mounted, in which case we don't add PROT_EXEC.)
    //  */
    // if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
    //         if (!(file && path_noexec(&file->f_path)))
    //                 prot |= PROT_EXEC;
    // ```
    //
    // The personality flag was stored nowhere and consulted nowhere, so a
    // task that asked for it got W^X-style protections anyway — and the
    // ancient toolchains that need it (a missing PT_GNU_STACK, trampolines on
    // the stack) fault instead of running. The noexec exception is kept: it is
    // what stops this flag from turning every readable mapping of a
    // non-executable object into an EACCES.
    if prot & PROT_READ != 0 && current_personality() & READ_IMPLIES_EXEC != 0 && file_allows_exec {
        prot |= PROT_EXEC;
    }

    let pages = (len >> 12) as usize;
    let perms = perms_of_prot(prot);
    // Only a destructive fixed mapping can close a displaced SysV VMA.
    // Ordinary mmap therefore has no reason to translate task->pid, derive
    // the mm key, materialize an owner row, or allocate/lock a SysV mapping
    // transaction. Linux likewise reaches SysV state only through the close
    // callback of an actually displaced shm VMA.
    let fixed_shm = destructive_fixed.then(|| {
        let task = current_task_id();
        let lpid = task_to_pid_raw(task).unwrap_or(task);
        let as_key = shm_as_key(&as_ref);
        shm_register_as_owner(as_key, lpid);
        (as_key, lpid, shm_mapping_transaction(as_key))
    });
    let _shm_guard = fixed_shm
        .as_ref()
        .map(|(_, _, transaction)| transaction.lock());

    // Base selection. Destructive MAP_FIXED replacement is deferred until the
    // requested mapping's semantic, backing, and lock-limit checks pass.
    let defer_private_anonymous_placement = !fixed
        && anonymous
        && map_type == MAP_PRIVATE
        && huge_size.is_none()
        && !(flags & MAP_POPULATE != 0
            && flags & MAP_NONBLOCK == 0
            && (prot & 0b111) != 0);
    let mut base = if fixed {
        hint
    } else if defer_private_anonymous_placement {
        // The ordinary lazy private-anonymous path selects and publishes a
        // reusable Linux-style VMA gap atomically after its fallible backing
        // metadata has been prepared.
        0
    } else {
        as_ref.reserve_mmap_va_aligned(len, page_size)
    };
    // reserve_mmap_va returns 0 when the no-hint mmap arena is exhausted
    // (the bump cursor would cross MMAP_WINDOW_TOP into the stack reserve).
    // Fail closed with -ENOMEM rather than mapping at a bogus base.
    // (MAP_FIXED takes the `hint` arm above, which is non-zero.)
    if base == 0 && !defer_private_anonymous_placement {
        ctx.set_return(errno_ret(ENOMEM));
        return;
    }

    macro_rules! record_fixed_replacement_owner_committed {
        () => {
            if let Some((as_key, lpid, _)) = fixed_shm.as_ref() {
                // `mapped_file::publish_current_mapping` updated the file
                // owner table under the VMA transaction. Only the independent
                // SysV attachment index remains to mirror here.
                {
                    shm_record_fixed_punch(*as_key, hint, hint + len, *lpid);
                }
            }
        };
    }

    if let Some(size) = huge_size {
        // `MAP_SHARED | MAP_HUGETLB` is served from hugetlbfs on Linux, and
        // MAP_SHARED on an anonymous mapping means one object mapped twice:
        // fork must alias the frames rather than copy them, and the last
        // address space to drop them is what returns them to the pool. Both
        // are keyed off this bit — see `clone_for_fork`'s huge arm and the
        // hugepage refcount. Without it a forked child got a private snapshot
        // that diverged from the parent on the first write.
        let perms = if flags & MAP_SHARED != 0 {
            perms | narf_memory::RegionPerms::SHARED
        } else {
            perms
        };
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
                ctx.set_return(errno_ret(ENOMEM));
                return;
            }
        };
        for frame in &frames {
            // SAFETY: a newly allocated huge frame is exclusively owned and
            // reached through the kernel's direct mapping.
            unsafe {
                core::ptr::write_bytes(
                    narf_memory::PhysAddr::new(frame.phys()).kernel_mut_ptr::<u8>(),
                    0,
                    frame.size_bytes() as usize,
                );
            }
        }
        let mapped = as_ref.with_vma_transaction(|| {
            crate::mapped_file::publish_current_unowned_mapping(
                as_ref.identity(),
                base,
                len,
                destructive_fixed,
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
                            destructive_fixed,
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
                ctx.set_return(errno_ret(EAGAIN))
            }
            Err(narf_memory::AddressSpaceError::Overlap) if fixed_noreplace => {
                ctx.set_return(errno_ret(EEXIST))
            }
            Err(_) => ctx.set_return(errno_ret(ENOMEM)),
        }
        return;
    }

    // A driver's read-only private PFN mapping, as `xe_oa_mmap` builds with
    // `vm_flags_mod(VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY,
    // VM_MAYWRITE | VM_MAYEXEC)` and `remap_pfn_range`. The driver's own pages
    // are aliased read-only and borrowed (`SHARED` frame ownership), never
    // copied through `read()`; the owner row records the VMA flags so mremap
    // refuses growth and fork leaves the range out of the child. The mapping
    // retains the file and the driver's lifetime token until munmap or exit,
    // as the VMA's `vm_file` does.
    if map_type == MAP_PRIVATE {
        if let Some((ops, _)) = file.as_ref() {
            if let Some(pfn) = ops.mmap_private_pfn(offset) {
                // No copy-on-write exists over borrowed frames: a provider
                // that admits write or exec now or through mprotect is a
                // contract violation, refused before any VMA mutation.
                if prot & (PROT_WRITE | PROT_EXEC) != 0
                    || ops.mmap_max_prot(offset) & (PROT_WRITE | PROT_EXEC) != 0
                {
                    ctx.set_return(errno_ret(ENODEV));
                    return;
                }
                let narf_filesystem::MmapBacking {
                    frames,
                    lifetime: mmap_lifetime,
                    memory_type,
                } = match ops.mmap_backing(offset, len as usize) {
                    Ok(backing) => backing,
                    Err(error) => {
                        ctx.set_return(errno_ret(copy_fs_errno(error)));
                        return;
                    }
                };
                if frames.len() != pages || frames.contains(&0) {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
                let phys = match try_raw_region_backing(&frames) {
                    Ok(backing) => backing,
                    Err(()) => {
                        ctx.set_return(errno_ret(ENOMEM));
                        return;
                    }
                };
                // LOCK_EXEMPT is VM_SPECIAL: no mlock population, and a
                // SHARED non-FILE_DEMAND VMA cannot grow by mremap (EFAULT).
                let region = Region {
                    base: VirtAddr::new(base),
                    len,
                    perms: (perms | RegionPerms::SHARED | RegionPerms::LOCK_EXEMPT)
                        .with_memory_type(memory_type),
                    phys,
                };
                let mapped = as_ref.with_vma_transaction(|| {
                    narf_memory::with_address_space_shared_mapping_transaction(
                        as_ref.identity(),
                        || {
                            crate::mapped_file::publish_current_pfn_mapping(
                                as_ref.identity(),
                                crate::mapped_file::MappingOwnerRegistration {
                                    base,
                                    len,
                                    file_offset: offset,
                                    ops: Arc::clone(ops),
                                    lifetime: mmap_lifetime.clone(),
                                    writeback_phys: None,
                                    private_copy: false,
                                    replace: destructive_fixed,
                                    zero_from: None,
                                    provenance: provenance.clone(),
                                },
                                pfn,
                                || {
                                    // SAFETY: VMA -> shared transactions are
                                    // held; the owner lock stays held until the
                                    // VMA has its lifetime registered.
                                    unsafe {
                                        if destructive_fixed {
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
                                    // SAFETY: same live root and VMA
                                    // transaction; rollback is receipt-scoped.
                                    match unsafe { as_ref.materialize_mapping_locked(receipt) } {
                                        Ok(()) => {
                                            ops.mmap_published(mmap_lifetime.as_ref());
                                            Ok(())
                                        }
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
                        },
                    )
                });
                if let Err(error) = mapped {
                    let errno = match error {
                        narf_memory::AddressSpaceError::LockLimit => EAGAIN,
                        narf_memory::AddressSpaceError::Overlap if fixed_noreplace => EEXIST,
                        _ => ENOMEM,
                    };
                    ctx.set_return(errno_ret(errno));
                    return;
                }
                record_fixed_replacement_owner_committed!();
                crate::perf_event::on_mmap(current_task_id(), fd, base, len, offset, prot, flags);
                ctx.set_return(SyscallReturn::ok(base));
                return;
            }
        }
    }

    let mut fallback_file_ops: Option<Arc<dyn narf_filesystem::FileOps>> = None;
    // Device-backed shared mapping — the keystone for graphics. A
    // `/dev/fb0` framebuffer (or a DRM dumb buffer) returns the
    // physical frames of its scanout buffer from `FileOps::mmap_frames`;
    // we alias (borrow) those frames into the caller's AS so userspace
    // gets a direct CPU-drawable pointer. RegionPerms::SHARED keeps the
    // teardown paths from `free_frame`-ing device-owned frames on
    // munmap/exit — same borrowed-frame contract as `sys_shmem_map` /
    // `sys_fb_ring_map`. A device that doesn't support mmap returns
    // Unsupported and we fall through to the regular file path.
    if flags & MAP_SHARED != 0 {
        if let Some((ops, _)) = file.as_ref() {
            // A coherent cache generation is the generic-file contract. It
            // cannot also expose device-owned mmap frames, so skip three
            // virtual capability probes and carry this already-retained file
            // reference directly into the fallback path below.
            if ops.mmap_cache_generation().is_none() {
            // Acquire any per-object owner BEFORE resolving raw frames. A
            // concurrent handle close may remove the lookup-table entry after
            // this point, but it cannot recycle the backing while this Arc is
            // held and then transferred into the mapping-owner table.
            narf_filesystem::mmap_relocation::install(crate::mapped_file::relocate_device_frames);
            narf_filesystem::mmap_relocation::install_revocation(
                crate::mapped_file::revoke_device_frames,
            );
            crate::mapped_file::install_device_refault_wait();
            let backing = match ops.mmap_backing(offset, len as usize) {
                Ok(backing) => Some(backing),
                Err(narf_filesystem::FsError::Unsupported) => None,
                Err(error) => {
                    ctx.set_return(errno_ret(copy_fs_errno(error)));
                    return;
                }
            };
            if let Some(narf_filesystem::MmapBacking {
                frames,
                lifetime: mmap_lifetime,
                memory_type,
            }) = backing
            {
                if frames.len() != pages {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
                let phys = match try_raw_region_backing(&frames) {
                    Ok(backing) => backing,
                    Err(()) => {
                        ctx.set_return(errno_ret(ENOMEM));
                        return;
                    }
                };
                let region = Region {
                    base: VirtAddr::new(base),
                    len,
                    // The device's memory-type request rides in the VMA like
                    // Linux's `vm_page_prot`; the address space applies it
                    // per frame and refuses it on System RAM.
                    perms: (perms
                        | RegionPerms::SHARED
                        | RegionPerms::EXTERNAL_REFS
                        | RegionPerms::LOCK_EXEMPT
                        | if ops.mmap_is_ram() { RegionPerms::PINNABLE_RAM } else { RegionPerms(0) })
                        .with_memory_type(memory_type),
                    phys,
                };
                let mapped = as_ref.with_vma_transaction(|| {
                    narf_memory::with_address_space_shared_mapping_transaction(
                        as_ref.identity(),
                        || {
                            crate::mapped_file::publish_current_mapping(
                                as_ref.identity(),
                                crate::mapped_file::MappingOwnerRegistration {
                                    base,
                                    len,
                                    file_offset: offset,
                                    ops: Arc::clone(ops),
                                    lifetime: mmap_lifetime.clone(),
                                    writeback_phys: None,
                                    private_copy: false,
                                    replace: destructive_fixed,
                                    zero_from: None,
                                    provenance: provenance.clone(),
                                },
                                || {
                                    // SAFETY: VMA -> shared transactions are held;
                                    // the file owner lock stays held until the VMA
                                    // has its external lifetime registered.
                                    unsafe {
                                        if destructive_fixed {
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
                                        Ok(()) => {
                                            ops.mmap_published(mmap_lifetime.as_ref());
                                            Ok(())
                                        },
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
                        },
                    )
                });
                if let Err(error) = mapped {
                    let errno = match error {
                        narf_memory::AddressSpaceError::LockLimit => EAGAIN,
                        narf_memory::AddressSpaceError::Overlap if fixed_noreplace => EEXIST,
                        _ => ENOMEM,
                    };
                    ctx.set_return(errno_ret(errno));
                    return;
                }
                record_fixed_replacement_owner_committed!();
                crate::perf_event::on_mmap(current_task_id(), fd, base, len, offset, prot, flags);
                ctx.set_return(SyscallReturn::ok(base));
                return;
            }
            // Demand-paged device/file mapping. `mmap_frames` is answered once, so
            // a file that can grow behind a live mapping cannot use it — a page
            // backed after this call would never appear. Such files implement
            // `mmap_fault` instead and are mapped with every slot unbacked;
            // each page's first touch routes through `mapped_file::demand_frame`
            // to the file. A BPF arena is the first of these.
            //
            // Capability discovery must be side-effect free. A valid direct
            // file mapping can begin beyond today's EOF and fault with SIGBUS
            // until the file grows; probing that offset here would wrongly
            // route the whole VMA through the generic-copy fallback.
            if ops.supports_mmap_fault() {
                // Installed here rather than at boot: a FILE_DEMAND region
                // cannot exist before this line has run, so there is no window
                // in which a fault could find the hook missing, and no
                // boot-order constraint of the kind §4.1 imposes on the BPF
                // page-table slots.
                narf_memory::install_file_fault_hook(crate::mapped_file::demand_frame);
                narf_memory::install_file_batch_fault_hook(crate::mapped_file::demand_frames_batch);
                narf_filesystem::install_mmap_truncate_hook(
                    crate::mapped_file::truncate_file_mappings,
                );
                let region = Region {
                    base: VirtAddr::new(base),
                    len,
                    // SHARED: the frames belong to the file, so teardown
                    // clears PTEs and frees nothing. FILE_DEMAND: an
                    // unbacked slot means "ask the file", not "allocate an
                    // anonymous zero page".
                    perms: perms
                        | RegionPerms::SHARED
                        | RegionPerms::EXTERNAL_REFS
                        | RegionPerms::FILE_DEMAND
                        | RegionPerms::LOCK_EXEMPT
                        | if ops.mmap_is_ram() { RegionPerms::PINNABLE_RAM } else { RegionPerms(0) },
                    phys: {
                        let mut backing = narf_memory::region_backing::RegionBacking::new();
                        backing.resize(pages, narf_memory::PhysAddr::new(0));
                        backing
                    },
                };
                let mapped = as_ref.with_vma_transaction(|| {
                    narf_memory::with_address_space_shared_mapping_transaction(
                        as_ref.identity(),
                        || {
                            crate::mapped_file::publish_current_mapping(
                                as_ref.identity(),
                                crate::mapped_file::MappingOwnerRegistration {
                                    base,
                                    len,
                                    file_offset: offset,
                                    ops: Arc::clone(ops),
                                    lifetime: None,
                                    writeback_phys: None,
                                    private_copy: false,
                                    replace: destructive_fixed,
                                    zero_from: None,
                                    provenance: provenance.clone(),
                                },
                                || {
                                    // SAFETY: VMA -> shared transactions are held
                                    // while the owner lock prevents a racing fault
                                    // from observing an ownerless FILE_DEMAND VMA.
                                    unsafe {
                                        if destructive_fixed {
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
                        },
                    )
                });
                if let Err(error) = mapped {
                    let errno = match error {
                        narf_memory::AddressSpaceError::LockLimit => EAGAIN,
                        narf_memory::AddressSpaceError::Overlap if fixed_noreplace => EEXIST,
                        _ => ENOMEM,
                    };
                    ctx.set_return(errno_ret(errno));
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
                crate::perf_event::on_mmap(current_task_id(), fd, base, len, offset, prot, flags);
                ctx.set_return(SyscallReturn::ok(base));
                return;
            }
            }
            fallback_file_ops = Some(Arc::clone(ops));
        }
    }

    // Linux implements MAP_SHARED|MAP_ANONYMOUS as an unlinked shmem file.
    // Keep the same shape here: VMA publication allocates only the small file
    // owner, while each page is allocated and zeroed on its first fault. The
    // mapping-held Arc is cloned by fork and VMA splits, so every alias faults
    // the same page at a given offset and the last owner drop frees it.
    let anonymous_shared_ops = if flags & MAP_SHARED != 0 && anonymous {
        match crate::mapped_file::new_anonymous_shared_file(len) {
            Ok(ops) => {
                narf_memory::install_file_fault_hook(crate::mapped_file::demand_frame);
                narf_memory::install_file_batch_fault_hook(crate::mapped_file::demand_frames_batch);
                // Truncate hook: paired with the fault hooks (see
                // the deferred-shared branch for why).
                narf_filesystem::install_mmap_truncate_hook(
                    crate::mapped_file::truncate_file_mappings,
                );
                Some(ops)
            }
            Err(_) => {
                ctx.set_return(errno_ret(ENOMEM));
                return;
            }
        }
    } else {
        None
    };

    if as_ref
        .check_locked_mapping_limit(
            len,
            explicit_lock,
            mlock_authority.limit_bytes,
            mlock_authority.bypass_limit,
        )
        .is_err()
    {
        ctx.set_return(errno_ret(EAGAIN));
        return;
    }
    let shared_file_fallback = !anonymous && flags & MAP_SHARED != 0;
    let private_file_fallback = !anonymous && map_type == MAP_PRIVATE;
    // Linux generic_file_mmap installs fault operations and obtains a
    // page-cache folio only on first access. NARF likewise leaves a cache
    // miss absent, but may install an already-resident canonical page here:
    // unlike Linux, NARF does not yet have a multi-page filemap fault-around
    // path, so needlessly faulting an existing page costs an extra trap and
    // owner-table lookup without changing observable semantics.
    let may_defer_shared_file = shared_file_fallback
        && !explicit_lock
        && (flags & MAP_POPULATE == 0 || flags & MAP_NONBLOCK != 0);
    let may_defer_private_file = private_file_fallback
        && !explicit_lock
        && (flags & MAP_POPULATE == 0 || flags & MAP_NONBLOCK != 0);
    let direct_shared_file = anonymous_shared_ops.is_some();
    let mut lazy_shared_file = direct_shared_file;
    let mut lazy_private_file = false;
    let mut shared_file_ops = anonymous_shared_ops;
    let mut private_file_ops = None;
    let mut shared_publication = None;
    let mut shared_cache_generation = None;
    let populate_anonymous = anonymous
        && flags & MAP_POPULATE != 0
        && flags & MAP_NONBLOCK == 0
        && (perms.contains(RegionPerms::READ)
            || perms.contains(RegionPerms::WRITE)
            || perms.contains(RegionPerms::EXEC));
    let mut population_frames = alloc::vec::Vec::new();
    let mut phys_list: alloc::vec::Vec<narf_memory::PhysAddr> = if anonymous {
        if direct_shared_file || map_type == MAP_PRIVATE && !populate_anonymous {
            // Linux publishes a lazy anonymous VMA without one descriptor per
            // virtual page. NARF represents the same demand-zero tail as an
            // implicit run after the materialized `Region::phys` prefix; the
            // fault path grows that prefix only through the page actually
            // touched. This keeps an untouched multi-gigabyte reservation O(1)
            // while preserving zero-on-first-access and all normal admission.
            alloc::vec::Vec::new()
        } else {
            // Eagerly populated private mappings still need an explicit slot
            // for every page before their backing transaction begins.
            // Reserve fallibly so a huge userspace request returns ENOMEM
            // rather than entering the kernel allocator's abort path.
            let mut v = alloc::vec::Vec::new();
            if v.try_reserve_exact(pages).is_err() {
                ctx.set_return(errno_ret(ENOMEM));
                return;
            }
            v.resize(pages, narf_memory::PhysAddr::new(0));
            v
        }
    } else {
        // Generic file mappings normally publish only VMA/owner metadata and
        // read one page on first fault. Explicit locking/prefault requests keep
        // the eager fallback, streaming into scatter frames one page at a time
        // so a large DSO never requires one contiguous kernel allocation.
        let len_bytes = len as usize;
        let ops = match fallback_file_ops
            .take()
            .or_else(|| file.as_ref().map(|(ops, _)| Arc::clone(ops)))
        {
            Some(o) => o,
            None => {
                // File-backed mapping with an fd not in the fd table → EBADF.
                ctx.set_return(errno_ret(EBADF));
                return;
            }
        };
        // Generic mappings need EOF revocation just as direct page-cache
        // mappings do. Install before publishing any generic owner, even
        // when all its pages are already cached or eagerly populated.
        narf_filesystem::install_mmap_truncate_hook(
            crate::mapped_file::truncate_file_mappings,
        );
        if shared_file_fallback {
            shared_cache_generation = ops.mmap_cache_generation();
            shared_file_ops = Some(Arc::clone(&ops));
        }
        if may_defer_shared_file {
            if let Some((frames, publication)) =
                crate::mapped_file::reserve_cached_shared_file_pages(&ops, offset, pages)
            {
                shared_publication = Some(publication);
                frames
            } else {
                lazy_shared_file = true;
                narf_memory::install_file_fault_hook(crate::mapped_file::demand_frame);
                narf_memory::install_file_batch_fault_hook(crate::mapped_file::demand_frames_batch);
                // The truncate hook is installed beside the fault
                // hooks at every site that installs them. It used to
                // be installed only on the `supports_mmap_fault`
                // branch above, so in a boot whose mappings were all
                // generic-fallback, a filesystem shrink's
                // `unmap_mapping_range` was a no-op: past-EOF pages
                // were never punched and recorded batches (#737
                // step 2) were never dropped — the batch_restore
                // truncate smoke caught exactly that (a post-shrink
                // fault restored the whole recorded range). A
                // filesystem can only call the hook once a mapping
                // exists, and every mapping path installs it, so the
                // pairing leaves no such window.
                narf_filesystem::install_mmap_truncate_hook(
                    crate::mapped_file::truncate_file_mappings,
                );
                // Linux installs only VMA metadata here. An empty sparse
                // prefix represents every page as absent until FILE_DEMAND
                // grows through the first touched slot.
                alloc::vec::Vec::new()
            }
        } else if shared_file_fallback {
            if let Some((frames, publication)) =
                crate::mapped_file::reserve_cached_shared_file_pages(&ops, offset, pages)
            {
                shared_publication = Some(publication);
                frames
            } else {
                match load_file_mapping_pages(&ops, offset, len_bytes, pages) {
                    Ok(frames) => frames,
                    Err(()) => {
                        ctx.set_return(errno_ret(ENOMEM));
                        return;
                    }
                }
            }
        } else if may_defer_private_file {
            lazy_private_file = true;
            private_file_ops = Some(Arc::clone(&ops));
            narf_memory::install_file_fault_hook(crate::mapped_file::demand_frame);
            narf_memory::install_file_batch_fault_hook(crate::mapped_file::demand_frames_batch);
            // Truncate hook: paired with the fault hooks (see the
            // deferred-shared branch for why).
            narf_filesystem::install_mmap_truncate_hook(
                crate::mapped_file::truncate_file_mappings,
            );
            // As with Linux's file-backed VMA, mmap publishes no resident pages.
            // Each first touch reads exactly that file page into a private frame.
            alloc::vec::Vec::new()
        } else {
            match load_file_mapping_pages(&ops, offset, len_bytes, pages) {
                Ok(frames) => frames,
                Err(()) => {
                    ctx.set_return(errno_ret(ENOMEM));
                    return;
                }
            }
        }
    };
    if populate_anonymous {
        prepare_anonymous_population(base, &mut phys_list, &mut population_frames);
    }

    if let Some(ops) = shared_file_ops
        .as_ref()
        .filter(|_| !lazy_shared_file && shared_publication.is_none())
    {
        let (canonical, publication) = crate::mapped_file::publish_shared_file_pages(
            ops,
            offset,
            phys_list,
            shared_cache_generation,
        );
        phys_list = canonical;
        shared_publication = Some(publication);
    }
    if let Some(ops) = shared_file_ops
        .as_ref()
        .filter(|_| fd_writable && !direct_shared_file)
    {
        // Stores through this mapping will dirty pages of the file cache:
        // see `mapped_file::writable_mapping`.
        crate::mapped_file::writable_mapping(ops);
    }
    let backing = match narf_memory::region_backing::RegionBacking::try_from_slice(&phys_list) {
        Ok(backing) => backing,
        Err(_) => {
            if shared_file_ops.is_none() {
                narf_memory::frame::free_phys_batch(&phys_list);
            }
            drop(shared_publication);
            ctx.set_return(errno_ret(ENOMEM));
            return;
        }
    };
    let writeback_phys = shared_file_ops
        .as_ref()
        .filter(|_| !direct_shared_file)
        .map(|_| phys_list.clone());
    let region = Region {
        base: VirtAddr::new(base),
        len,
        // Generic MAP_SHARED file mappings borrow a frame from the userspace
        // file-page cache. SHARED lets multiple VMAs alias one page;
        // EXTERNAL_REFS delegates per-frame lifetime to that cache. Anonymous
        // shared backing is instead pinned by the VMA's file Arc.
        perms: if shared_file_ops.is_some() {
            perms
                | RegionPerms::SHARED
                | if direct_shared_file {
                    RegionPerms(0)
                } else {
                    RegionPerms::EXTERNAL_REFS
                }
                | if lazy_shared_file {
                    RegionPerms::FILE_DEMAND
                } else {
                    RegionPerms(0)
                }
        } else if lazy_private_file {
            perms | RegionPerms::FILE_DEMAND
        } else {
            perms
        },
        phys: backing,
    };
    let mut eager_file_population = false;
    let map_result = if let Some(ops) = shared_file_ops.as_ref() {
        as_ref.with_vma_transaction(|| {
            narf_memory::with_address_space_shared_mapping_transaction(as_ref.identity(), || {
                crate::mapped_file::publish_current_mapping(
                    as_ref.identity(),
                    crate::mapped_file::MappingOwnerRegistration {
                        base,
                        len,
                        file_offset: offset,
                        ops: Arc::clone(ops),
                        lifetime: None,
                        writeback_phys,
                        private_copy: false,
                        replace: destructive_fixed,
                        zero_from: None,
                        provenance: provenance.clone(),
                    },
                    || {
                        // SAFETY: VMA -> shared transactions are held and the
                        // canonical page cache owns every nonzero frame.
                        unsafe {
                            if destructive_fixed {
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
                        if lazy_shared_file {
                            eager_file_population = populate_anonymous
                                || as_ref
                                .perms_covering(receipt.base(), receipt.len())
                                .is_some_and(|perms| {
                                    perms.contains(RegionPerms::LOCKED)
                                        && !perms.contains(RegionPerms::LOCK_ONFAULT)
                                        && perms.prot_only().0 != 0
                                });
                            // The complete sparse tail is intentionally absent.
                            // First access publishes a cache-owned page through
                            // the FILE_DEMAND hook.
                            return Ok(());
                        }
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
        .map(|_| ())
    } else if let Some(ops) = private_file_ops.as_ref() {
        as_ref
            .with_vma_transaction(|| {
                crate::mapped_file::publish_current_mapping(
                    as_ref.identity(),
                    crate::mapped_file::MappingOwnerRegistration {
                        base,
                        len,
                        file_offset: offset,
                        ops: Arc::clone(ops),
                        lifetime: None,
                        writeback_phys: None,
                        private_copy: true,
                        replace: destructive_fixed,
                        zero_from: None,
                        provenance: provenance.clone(),
                    },
                    || {
                        // SAFETY: the VMA transaction and owner bucket remain
                        // locked until the private FILE_DEMAND owner is visible.
                        unsafe {
                            if destructive_fixed {
                                as_ref.replace_region_locked_limited_receipt(
                                    region,
                                    explicit_lock,
                                    mlock_authority.limit_bytes,
                                    mlock_authority.bypass_limit,
                                )
                            } else {
                                as_ref.map_region_locked_limited_receipt(
                                    region,
                                    explicit_lock,
                                    mlock_authority.limit_bytes,
                                    mlock_authority.bypass_limit,
                                )
                            }
                        }
                    },
                    |receipt| {
                        eager_file_population = as_ref
                            .perms_covering(receipt.base(), receipt.len())
                            .is_some_and(|perms| {
                                perms.contains(RegionPerms::LOCKED)
                                    && !perms.contains(RegionPerms::LOCK_ONFAULT)
                                    && perms.prot_only().0 != 0
                            });
                        Ok(())
                    },
                )
            })
            .map(|_| ())
    } else if fixed {
        as_ref.with_vma_transaction(|| {
            crate::mapped_file::publish_current_unowned_mapping(
                as_ref.identity(),
                base,
                len,
                destructive_fixed,
                || {
                    // SAFETY: the VMA transaction is held. This mapping is
                    // private, so no shared transaction is required. The
                    // file-owner and SysV transactions remain locked until
                    // their corresponding target punches commit.
                    unsafe {
                        if anonymous {
                            if destructive_fixed {
                                as_ref.replace_private_anonymous_region_locked_limited(
                                    region,
                                    explicit_lock,
                                    mlock_authority.limit_bytes,
                                    mlock_authority.bypass_limit,
                                )
                            } else {
                                as_ref.map_private_anonymous_region_locked_limited(
                                    region,
                                    explicit_lock,
                                    mlock_authority.limit_bytes,
                                    mlock_authority.bypass_limit,
                                )
                            }
                            .map(|()| None)
                        } else if destructive_fixed {
                            as_ref
                                .replace_region_locked_limited_receipt(
                                    region,
                                    explicit_lock,
                                    mlock_authority.limit_bytes,
                                    mlock_authority.bypass_limit,
                                )
                                .map(Some)
                        } else {
                            as_ref
                                .map_region_locked_limited_receipt(
                                    region,
                                    explicit_lock,
                                    mlock_authority.limit_bytes,
                                    mlock_authority.bypass_limit,
                                )
                                .map(Some)
                        }
                    }
                },
                |receipt| {
                    let Some(receipt) = receipt else {
                        return Ok(());
                    };
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
        .map(|_| ())
    } else if anonymous && flags & MAP_PRIVATE != 0 {
        if defer_private_anonymous_placement {
            as_ref
                .map_private_anonymous_region_anywhere_limited(
                    region,
                    VirtAddr::new(hint),
                    page_size,
                    explicit_lock,
                    mlock_authority.limit_bytes,
                    mlock_authority.bypass_limit,
                )
                .map(|selected| base = selected.as_u64())
        } else {
            as_ref.map_private_anonymous_region_limited(
                region,
                explicit_lock,
                mlock_authority.limit_bytes,
                mlock_authority.bypass_limit,
            )
        }
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
        .map(|_| ())
    };
    if let Err(error) = map_result {
        // The Region never took ownership when publication failed. Return the
        // best-effort prefault frames through the allocator's batched path.
        narf_memory::frame::free_frame_batch(&population_frames);
        // Drop releases only this attempt's pending cache holds. A concurrent
        // mapper selecting the same canonical page retains its own hold.
        drop(shared_publication);
        let errno = match error {
            narf_memory::AddressSpaceError::LockLimit => EAGAIN,
            narf_memory::AddressSpaceError::Overlap if fixed_noreplace => EEXIST,
            _ => ENOMEM,
        };
        ctx.set_return(errno_ret(errno));
        return;
    }
    if eager_file_population {
        let end = base.saturating_add(len);
        let mut page = base;
        while page < end {
            // SAFETY: the successful mapping owns a live user root. Population
            // is best-effort, as Linux specifies for MAP_LOCKED/MCL_FUTURE;
            // a racing unmap or file fault refusal simply leaves the page lazy.
            let _ = unsafe { as_ref.demand_alloc_page(VirtAddr::new(page)) };
            page = page.saturating_add(4096);
        }
    }
    if let Some(publication) = shared_publication.take() {
        // map_region retained every SHARED frame before returning. Convert
        // this attempt's pending holds into those committed mapping refs.
        publication.commit();
    }
    if !population_frames.is_empty() {
        // The VMA now owns every prepared frame. Install the populated prefix
        // with the existing batched page-table path; failure is best-effort
        // and later access repairs any still-absent backed leaf.
        // SAFETY: `as_ref` owns a live user root and this successful mmap's
        // page-aligned range remains registered.
        let _ = unsafe { as_ref.materialize_range(VirtAddr::new(base), len) };
    }
    if shared_file_ops.is_some() || private_file_ops.is_some() {
        record_fixed_replacement_owner_committed!();
    } else if fixed {
        // The unowned publication helper already retired overlapping mapped
        // file owners under the VMA transaction.
        record_fixed_replacement_owner_committed!();
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

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat};
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

    struct ReadErrorFile;

    impl FileOps for ReadErrorFile {
        fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Err(FsError::ReadOnly) })
        }

        fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Err(FsError::ReadOnly) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 4096,
                blocks: 8,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    fn smoke_file_demand_io_error_fails_closed() -> TestResult {
        let file: Arc<dyn FileOps> = Arc::new(ReadErrorFile);
        if load_file_demand_page(&file, 0).is_ok() {
            return TestResult::Fail("file demand I/O error became readable backing");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_file_demand_io_error_fails_closed);

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

    /// `mm/mmap.c::do_mmap` admits a file mapping according to the open
    /// file-description's access mode.  The page-fault path must never be a
    /// second, accidentally more-permissive admission path: once a VMA exists
    /// it retains the file reference, but an O_WRONLY descriptor cannot create
    /// one and MAP_SHARED|PROT_WRITE needs O_RDWR.
    fn smoke_mmap_enforces_file_description_access_mode() -> TestResult {
        const PRIVATE_BASE: u64 = 0x0000_3700_0000_0000;
        const SHARED_BASE: u64 = PRIVATE_BASE + 0x1000;
        const RW_BASE: u64 = PRIVATE_BASE + 0x2000;
        const MAP_SHARED: u64 = 0x01;
        const MAP_PRIVATE: u64 = 0x02;
        const MAP_FIXED: u64 = 0x10;

        // SAFETY: the test owns this user root until it removes every VMA
        // below.  A live root makes a success on a regressed implementation
        // observable, rather than turning it into an unrelated ENOMEM.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
        crate::fd::__test_reset();

        let file = Arc::new(TestFile {
            bytes: IrqSafeSpinLock::new(vec![0; 4096]),
            writes: AtomicUsize::new(0),
        });
        let install = |status_flags| {
            crate::fd::install(
                TASK,
                crate::fd::FdEntry {
                    ops: Arc::clone(&file) as Arc<dyn FileOps>,
                    offset: 0,
                    flags: 0,
                    status_flags,
                },
            )
        };
        let (Some(write_only), Some(read_only), Some(read_write)) = (
            install(crate::fd::O_WRONLY),
            install(crate::fd::O_RDONLY),
            install(crate::fd::O_RDWR),
        ) else {
            crate::fd::__test_reset();
            *USER_AS.lock() = None;
            return TestResult::Fail("could not install test file descriptors");
        };

        let invoke = |base, fd, prot, flags| {
            let mut ctx = TestCtx {
                args: SyscallArgs {
                    arg0: base,
                    arg1: 4096,
                    arg2: prot,
                    arg3: flags | MAP_FIXED,
                    arg4: u64::from(fd),
                    ..SyscallArgs::default()
                },
                ret: None,
            };
            sys_mmap(&mut ctx);
            ctx.ret
        };
        let write_only_private = invoke(PRIVATE_BASE, write_only, 1, MAP_PRIVATE);
        let read_only_shared_write = invoke(SHARED_BASE, read_only, 2, MAP_SHARED);
        let read_write_shared = invoke(RW_BASE, read_write, 3, MAP_SHARED);

        // These removals are no-ops on a correct implementation.  They also
        // clean up the VMA owner registration when this test is first run
        // against an older implementation that incorrectly admits a mapping.
        for base in [PRIVATE_BASE, SHARED_BASE, RW_BASE] {
            let _ = aspace.unmap_region(VirtAddr::new(base));
            crate::mapped_file::unmap_current(base);
        }
        crate::fd::__test_reset();
        *USER_AS.lock() = None;

        let is_errno = |ret: Option<SyscallReturn>, errno: i64| {
            ret.is_some_and(|ret| ret.status == SyscallReturn::OK && ret.value as i64 == -errno)
        };
        let rw_succeeded = read_write_shared.is_some_and(|ret| {
            ret.status == SyscallReturn::OK && ret.value == RW_BASE
        });
        if !is_errno(write_only_private, EACCES)
            || !is_errno(read_only_shared_write, EACCES)
            || !rw_succeeded
        {
            return TestResult::Fail("mmap file-description access mode diverged from Linux");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mmap_enforces_file_description_access_mode
    );

    fn smoke_mmap_fixed_noreplace_is_non_destructive() -> TestResult {
        const BASE: u64 = 0x0000_3300_0000_0000;
        const MAP_PRIVATE: u64 = 0x02;
        const MAP_FIXED: u64 = 0x10;
        const MAP_ANONYMOUS: u64 = 0x20;
        const MAP_FIXED_NOREPLACE: u64 = 0x0010_0000;

        let aspace = Arc::new(AddressSpace::empty());
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);

        let mut initial = TestCtx {
            args: SyscallArgs {
                arg0: BASE,
                arg1: 4096,
                arg2: 1, // PROT_READ
                arg3: MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                arg4: u64::MAX,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut initial);
        let initial_ok = initial
            .ret
            .is_some_and(|ret| ret.status == SyscallReturn::OK && ret.value == BASE);

        let occupied_errno = mmap_errno(SyscallArgs {
            arg0: BASE,
            arg1: 4096,
            arg2: 2, // PROT_WRITE: would visibly alter the target if replaced.
            arg3: MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            arg4: u64::MAX,
            ..SyscallArgs::default()
        });
        let original_intact = aspace.lookup(VirtAddr::new(BASE)).is_some_and(|region| {
            region.perms.contains(RegionPerms::READ)
                && !region.perms.contains(RegionPerms::WRITE)
        });

        let mut free = TestCtx {
            args: SyscallArgs {
                arg0: BASE + 4096,
                arg1: 4096,
                arg2: 2,
                arg3: MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                arg4: u64::MAX,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut free);
        let free_ok = free.ret.is_some_and(|ret| {
            ret.status == SyscallReturn::OK && ret.value == BASE + 4096
        });
        let free_registered = aspace
            .lookup(VirtAddr::new(BASE + 4096))
            .is_some_and(|region| region.perms.contains(RegionPerms::WRITE));

        *USER_AS.lock() = None;
        if !initial_ok || occupied_errno != Some(17) || !original_intact {
            return TestResult::Fail("MAP_FIXED_NOREPLACE replaced an occupied mapping");
        }
        if !free_ok || !free_registered {
            return TestResult::Fail("MAP_FIXED_NOREPLACE rejected an exact free address");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mmap_fixed_noreplace_is_non_destructive
    );

    fn smoke_nonfixed_file_mmap_stale_completion_is_success() -> TestResult {
        const BASE: u64 = 0x0000_3f00_0000_0000;
        let aspace = AddressSpace::empty();
        let first = Region {
            base: VirtAddr::new(BASE),
            len: 4096,
            perms: RegionPerms::READ,
            phys: vec![PhysAddr::new(0)].into(),
        };
        let receipt = match aspace.map_region_limited_receipt(first, false, u64::MAX, false) {
            Ok(receipt) => receipt,
            Err(_) => return TestResult::Fail("initial file VMA publication failed"),
        };
        let successor = Region {
            base: VirtAddr::new(BASE),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: vec![PhysAddr::new(0)].into(),
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
                phys: vec![low_frame].into(),
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

    /// Linux MAP_POPULATE prefaults accessible anonymous pages, while
    /// MAP_NONBLOCK deliberately turns that request into a no-op. Pin both
    /// the authoritative Region backing and the installed leaf: checking
    /// only one would miss either an unowned PTE or an eager allocation that
    /// still faults on first access.
    fn smoke_mmap_populate_and_nonblock_backing() -> TestResult {
        const POPULATED_BASE: u64 = 0x0000_3100_0000_0000;
        const NONBLOCK_BASE: u64 = 0x0000_3200_0000_0000;
        const MAP_PRIVATE: u64 = 0x02;
        const MAP_FIXED: u64 = 0x10;
        const MAP_ANONYMOUS: u64 = 0x20;
        const MAP_POPULATE: u64 = 0x8000;
        const MAP_NONBLOCK: u64 = 0x1_0000;

        // SAFETY: paging and the allocator are live in the kernel-test
        // harness; this test owns the inactive user root until teardown.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);

        let mut populated = TestCtx {
            args: SyscallArgs {
                arg0: POPULATED_BASE,
                arg1: 8192,
                arg2: 3, // PROT_READ | PROT_WRITE
                arg3: MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE,
                arg4: u64::MAX,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut populated);
        let populated_ok = populated.ret.is_some_and(|ret| {
            ret.status == SyscallReturn::OK && ret.value == POPULATED_BASE
        });
        let populated_region = aspace.lookup(VirtAddr::new(POPULATED_BASE));
        let populated_backed = populated_region.as_ref().is_some_and(|region| {
            region.phys.len() >= 2
                && region.phys[0].as_u64() != 0
                && region.phys[1].as_u64() != 0
        });
        // SAFETY: this test exclusively owns the live root and queries only
        // the user leaves it just requested through sys_mmap.
        let populated_mapped = unsafe {
            narf_memory::x86_64::paging::translate(
                aspace.root,
                VirtAddr::new(POPULATED_BASE),
            )
            .is_some()
                && narf_memory::x86_64::paging::translate(
                    aspace.root,
                    VirtAddr::new(POPULATED_BASE + 4096),
                )
                .is_some()
        };

        let mut nonblock = TestCtx {
            args: SyscallArgs {
                arg0: NONBLOCK_BASE,
                arg1: 4096,
                arg2: 3,
                arg3: MAP_PRIVATE
                    | MAP_FIXED
                    | MAP_ANONYMOUS
                    | MAP_POPULATE
                    | MAP_NONBLOCK,
                arg4: u64::MAX,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut nonblock);
        let nonblock_ok = nonblock.ret.is_some_and(|ret| {
            ret.status == SyscallReturn::OK && ret.value == NONBLOCK_BASE
        });
        let nonblock_lazy = aspace
            .lookup(VirtAddr::new(NONBLOCK_BASE))
            .is_some_and(|region| {
                let page = ((NONBLOCK_BASE - region.base.as_u64()) >> 12) as usize;
                region
                    .phys
                    .get(page)
                    .is_none_or(|phys| phys.as_u64() == 0)
            });
        // SAFETY: same test-owned live-root contract as above.
        let nonblock_unmapped = unsafe {
            narf_memory::x86_64::paging::translate(aspace.root, VirtAddr::new(NONBLOCK_BASE))
                .is_none()
        };

        *USER_AS.lock() = None;
        if !populated_ok || !populated_backed || !populated_mapped {
            return TestResult::Fail("MAP_POPULATE left accessible anonymous pages lazy");
        }
        if !nonblock_ok || !nonblock_lazy || !nonblock_unmapped {
            return TestResult::Fail("MAP_NONBLOCK performed MAP_POPULATE work");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mmap_populate_and_nonblock_backing
    );

    /// Anonymous shared mmap is an unlinked sparse shmem file: publishing a
    /// three-page VMA allocates no data page, and touching its middle page
    /// materialises exactly that page. The mapping owner is the final file
    /// reference, so removing it after the VMA returns the page to the buddy.
    fn smoke_mmap_shared_anon_faults_sparse_shmem_lazily() -> TestResult {
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

        let mut mmap = TestCtx {
            args: SyscallArgs {
                arg1: 3 * 4096,
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
        let initially_lazy = aspace.lookup(VirtAddr::new(base)).is_some_and(|region| {
            region.perms.contains(RegionPerms::SHARED)
                && region.perms.contains(RegionPerms::FILE_DEMAND)
                && region.phys.is_empty()
        });
        if !initially_lazy || aspace.memory_stats().resident_pages != 0 {
            *USER_AS.lock() = None;
            return TestResult::Fail("anonymous MAP_SHARED eagerly allocated data pages");
        }

        // SAFETY: the test owns this live user root and the address is inside
        // the VMA just published above.
        if unsafe { aspace.demand_alloc_page(VirtAddr::new(base + 4096)) }.is_err() {
            *USER_AS.lock() = None;
            return TestResult::Fail("anonymous MAP_SHARED middle-page fault failed");
        }
        let phys = match aspace.lookup(VirtAddr::new(base)) {
            Some(region)
                if region.perms.contains(RegionPerms::SHARED)
                    && region.phys.len() == 2
                    && region.phys[0].raw() == 0
                    && region.phys[1].raw() != 0 =>
            {
                region.phys[1]
            }
            _ => {
                *USER_AS.lock() = None;
                return TestResult::Fail("anonymous MAP_SHARED fault did not stay sparse");
            }
        };
        if aspace.memory_stats().resident_pages != 1 {
            *USER_AS.lock() = None;
            return TestResult::Fail("one shared-anonymous fault charged more than one page");
        }
        // SAFETY: `phys` is the live allocator frame owned by the mapping's
        // memfile; the kernel direct map covers it for this read-only check.
        if unsafe { core::slice::from_raw_parts(phys.kernel_ptr::<u8>(), 4096) }
            .iter()
            .any(|byte| *byte != 0)
        {
            *USER_AS.lock() = None;
            return TestResult::Fail("fresh shared-anonymous page was not zeroed");
        }

        if aspace.unmap_region(VirtAddr::new(base)).is_err() {
            *USER_AS.lock() = None;
            return TestResult::Fail("anonymous MAP_SHARED unmap failed");
        }
        crate::mapped_file::unmap_current(base);
        *USER_AS.lock() = None;
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mmap_shared_anon_faults_sparse_shmem_lazily
    );

    fn smoke_mmap_private_file_faults_owned_pages_lazily() -> TestResult {
        // SAFETY: kernel tests run after paging/frame initialization and this
        // root remains owned by the test until both VMAs are removed.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
        crate::fd::__test_reset();

        let mut contents = vec![0; 4096];
        contents[..8].copy_from_slice(b"PRIVATE!");
        let file = Arc::new(TestFile {
            bytes: IrqSafeSpinLock::new(contents),
            writes: AtomicUsize::new(0),
        });
        let fd = match crate::fd::install(
            TASK,
            crate::fd::FdEntry {
                ops: Arc::clone(&file) as Arc<dyn FileOps>,
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDONLY,
            },
        ) {
            Some(fd) => fd,
            None => return TestResult::Fail("could not install test file fd"),
        };

        let map_private = |len: u64| {
            let mut call = TestCtx {
                args: SyscallArgs {
                    arg1: len,
                    arg2: 3,    // PROT_READ | PROT_WRITE
                    arg3: 0x02, // MAP_PRIVATE
                    arg4: u64::from(fd),
                    ..SyscallArgs::default()
                },
                ret: None,
            };
            sys_mmap(&mut call);
            call.ret.and_then(|ret| {
                (ret.status == SyscallReturn::OK && (ret.value as i64) > 0).then_some(ret.value)
            })
        };

        let Some(base) = map_private(8192) else {
            return TestResult::Fail("MAP_PRIVATE file mmap failed");
        };
        if !aspace.lookup(VirtAddr::new(base)).is_some_and(|region| {
            region.perms.contains(RegionPerms::FILE_DEMAND)
                && !region.perms.contains(RegionPerms::SHARED)
                && region.phys.is_empty()
        }) {
            return TestResult::Fail("MAP_PRIVATE file mapping was eagerly backed");
        }
        // SAFETY: `base` lies in this test-owned FILE_DEMAND VMA.
        if unsafe { aspace.demand_alloc_page(VirtAddr::new(base)) }.is_err() {
            return TestResult::Fail("private file demand fault failed");
        }
        let first = match aspace.lookup(VirtAddr::new(base)) {
            Some(region) if region.phys.first().is_some_and(|phys| phys.raw() != 0) => {
                region.phys[0]
            }
            _ => return TestResult::Fail("private file fault did not publish backing"),
        };
        // SAFETY: `first` is the mapping's live, kernel-direct-mapped frame.
        if unsafe { core::slice::from_raw_parts(first.kernel_ptr::<u8>(), 8) } != b"PRIVATE!" {
            return TestResult::Fail("private file fault loaded incorrect bytes");
        }
        // SAFETY: this mapping owns the private writable frame.
        unsafe { first.kernel_mut_ptr::<u8>().write_volatile(b'X') };
        if file.bytes.lock()[0] != b'P' {
            return TestResult::Fail("MAP_PRIVATE write modified the backing file");
        }

        let Some(second_base) = map_private(4096) else {
            return TestResult::Fail("second MAP_PRIVATE file mmap failed");
        };
        // SAFETY: `second_base` lies in a second test-owned FILE_DEMAND VMA.
        if unsafe { aspace.demand_alloc_page(VirtAddr::new(second_base)) }.is_err() {
            return TestResult::Fail("second private file demand fault failed");
        }
        let second = match aspace.lookup(VirtAddr::new(second_base)) {
            Some(region) if region.phys.first().is_some_and(|phys| phys.raw() != 0) => {
                region.phys[0]
            }
            _ => return TestResult::Fail("second private file fault has no backing"),
        };
        // Separate MAP_PRIVATE mappings must neither alias writes nor source
        // their initial bytes from another mapping's already-modified frame.
        // SAFETY: `second` is the second mapping's live, kernel-direct-mapped
        // frame and remains owned by `aspace` for this comparison.
        let second_bytes = unsafe { core::slice::from_raw_parts(second.kernel_ptr::<u8>(), 8) };
        if second == first || second_bytes != b"PRIVATE!" {
            return TestResult::Fail("MAP_PRIVATE mappings did not remain isolated");
        }
        // A page wholly beyond EOF follows Linux's SIGBUS path, represented by
        // the memory layer's typed fault refusal.
        // SAFETY: the address is inside the VMA but begins at file EOF.
        if unsafe { aspace.demand_alloc_page(VirtAddr::new(base + 4096)) }.is_ok() {
            return TestResult::Fail("private file fault beyond EOF unexpectedly succeeded");
        }

        let _ = aspace.unmap_region(VirtAddr::new(second_base));
        crate::mapped_file::unmap_current(second_base);
        let _ = aspace.unmap_region(VirtAddr::new(base));
        crate::mapped_file::unmap_current(base);
        crate::fd::__test_reset();
        *USER_AS.lock() = None;
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mmap_private_file_faults_owned_pages_lazily
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
        let fd = crate::fd::install(
            TASK,
            crate::fd::FdEntry {
                ops: Arc::clone(&file) as Arc<dyn FileOps>,
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDWR,
            },
        )
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
        let initially_lazy = aspace
            .lookup(narf_memory::VirtAddr::new(base))
            .is_some_and(|region| {
                region.perms.contains(RegionPerms::FILE_DEMAND)
                    && region.phys.is_empty()
            });
        // SAFETY: the test owns this live user root and the address lies in
        // the FILE_DEMAND mapping just published through sys_mmap.
        let first_fault = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(base)) };
        if !initially_lazy || first_fault.is_err() {
            return TestResult::Fail("generic MAP_SHARED mapping was not demand-backed");
        }
        let region = match aspace.lookup(narf_memory::VirtAddr::new(base)) {
            Some(region) if region.phys.len() == 1 && region.phys[0].raw() != 0 => region,
            _ => return TestResult::Fail("file fault did not publish a physical page"),
        };
        // A real store would fault on the clean page's read-only PTE first.
        crate::mapped_file::shared_page_write_fault(region.phys[0].raw());
        // SAFETY: the syscall allocated this page exclusively for the test
        // mapping and all physical memory is kernel identity-mapped.
        unsafe {
            core::ptr::copy_nonoverlapping(
                c"JOURNAL".as_ptr().cast(),
                region.phys[0].kernel_mut_ptr::<u8>(),
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
        // SAFETY: same test-owned root and FILE_DEMAND contract as above.
        if unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(second_base)) }.is_err() {
            return TestResult::Fail("second MAP_SHARED file fault failed");
        }
        let second_region = match aspace.lookup(narf_memory::VirtAddr::new(second_base)) {
            Some(region) if region.phys.len() == 1 && region.phys[0].raw() != 0 => region,
            _ => return TestResult::Fail("second file fault did not publish a physical page"),
        };
        if second_region.phys[0] != region.phys[0] {
            return TestResult::Fail("same-range MAP_SHARED mappings did not alias one file page");
        }
        // SAFETY: both mappings resolve to the same identity-mapped page.
        if unsafe { core::slice::from_raw_parts(second_region.phys[0].kernel_ptr::<u8>(), 8) }
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

        // A real store would fault on the clean page's read-only PTE first.
        crate::mapped_file::shared_page_write_fault(second_region.phys[0].raw());
        // SAFETY: both mappings still retain the identity-mapped page.
        unsafe {
            *(second_region.phys[0].kernel_mut_ptr::<u8>()).add(8) = b'!';
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

    // #677: a mapping of an overlay file must keep faulting from the layer
    // that was active when the mapping was published. A copy-up through
    // the mapped file's own ops flips `OverlayFile::active()` from the
    // lower to the upper file; before publication pinned the backing file,
    // later faults in the same VMA served upper pages (and the owner's
    // `mmap_backing_identity` flipped with them), so one mapping silently
    // mixed two files. Linux pins the real file in the VMA at `mmap`.
    fn smoke_mmap_overlay_copy_up_keeps_mapping_pinned_to_lower() -> TestResult {
        use narf_filesystem::FsInstance as _;

        // SAFETY: the test owns this user root until it removes every VMA
        // below, the same contract as the other sys_mmap smokes.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
        crate::fd::__test_reset();

        let mut contents = vec![0u8; 8192];
        contents[..8].copy_from_slice(b"LOWER-P0");
        contents[4096..4104].copy_from_slice(b"LOWER-P1");
        let lower = Arc::new(narf_filesystem::MemFs::with_seeds(
            "ov677-lower",
            &[("pagefile", contents.as_slice())],
        ));
        let upper = Arc::new(narf_filesystem::MemFs::new("ov677-upper"));
        let overlay = narf_filesystem::OverlayFs::new(
            "ov677",
            upper.root(),
            vec![lower.root() as Arc<dyn narf_filesystem::DirOps>],
        );
        let root = overlay.root();
        let Some(ops) = root.lookup("pagefile") else {
            return TestResult::Fail("overlay lookup missed the lower file");
        };
        let Some(lower_file) = lower.root().lookup("pagefile") else {
            return TestResult::Fail("lower lookup missed the seeded file");
        };

        let fd = match crate::fd::install(
            TASK,
            crate::fd::FdEntry {
                ops: Arc::clone(&ops),
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDWR,
            },
        ) {
            Some(fd) => fd,
            None => return TestResult::Fail("could not install overlay file fd"),
        };
        let map_shared = |len: u64| {
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
            call.ret.and_then(|ret| {
                (ret.status == SyscallReturn::OK && (ret.value as i64) > 0).then_some(ret.value)
            })
        };

        let Some(base) = map_shared(8192) else {
            return TestResult::Fail("overlay MAP_SHARED mmap failed");
        };
        if !aspace.lookup(VirtAddr::new(base)).is_some_and(|region| {
            region.perms.contains(RegionPerms::FILE_DEMAND)
                && region.phys.first().is_some_and(|phys| phys.raw() == 0)
        }) {
            return TestResult::Fail("overlay mapping was not demand-backed");
        }
        // The owner registered at publication is the pin itself: the lower
        // memfs file, not the overlay wrapper.
        let Some((owner, _)) = crate::mapped_file::shared_file_at(aspace.identity(), base) else {
            return TestResult::Fail("overlay mapping registered no file owner");
        };
        if !Arc::ptr_eq(&owner, &lower_file) {
            return TestResult::Fail("overlay mapping owner is not the pinned lower file");
        }
        let identity_at_mmap = owner.mmap_backing_identity();

        // Fault page 0: served by the lower file.
        // SAFETY: `base` lies in this test-owned FILE_DEMAND VMA.
        if unsafe { aspace.demand_alloc_page(VirtAddr::new(base)) }.is_err() {
            return TestResult::Fail("overlay page-0 fault failed");
        }
        let lower_p0 = match lower_file.mmap_fault(0) {
            Ok(phys) => phys,
            Err(_) => return TestResult::Fail("lower page-0 fault failed"),
        };
        let page0 = match aspace.lookup(VirtAddr::new(base)) {
            Some(region) if region.phys.first().is_some_and(|phys| phys.raw() == lower_p0) => {
                region.phys[0]
            }
            _ => return TestResult::Fail("overlay page 0 did not come from the lower file"),
        };
        // SAFETY: `page0` is the mapping's live, kernel-direct-mapped frame.
        if unsafe { core::slice::from_raw_parts(page0.kernel_ptr::<u8>(), 8) } != b"LOWER-P0" {
            return TestResult::Fail("overlay page 0 has the wrong bytes");
        }

        // Copy up through the mapped fd's own ops (the overlay write path)
        // and make the upper file's page 1 diverge from the lower's.
        if !matches!(poll_io_to_completion(ops.write(4096, b"UPPER-P1")), Some(Ok(8))) {
            return TestResult::Fail("overlay write (copy-up) failed");
        }
        let Some(upper_file) = upper.root().lookup("pagefile") else {
            return TestResult::Fail("copy-up did not create the upper file");
        };
        let mut upper_p1 = [0u8; 8];
        if !matches!(
            poll_io_to_completion(upper_file.read(4096, &mut upper_p1)),
            Some(Ok(8))
        ) || &upper_p1 != b"UPPER-P1"
        {
            return TestResult::Fail("upper page 1 does not hold the copied-up write");
        }

        // The live mapping's owner and backing identity must not have moved.
        let Some((owner_after, _)) = crate::mapped_file::shared_file_at(aspace.identity(), base)
        else {
            return TestResult::Fail("overlay mapping lost its file owner");
        };
        if !Arc::ptr_eq(&owner_after, &lower_file)
            || owner_after.mmap_backing_identity() != identity_at_mmap
        {
            return TestResult::Fail("copy-up retargeted the live mapping's backing identity");
        }

        // Fault page 1 in the SAME VMA: still the lower file's page, even
        // though the overlay now resolves to the upper file.
        // SAFETY: `base + 4096` lies in this test-owned FILE_DEMAND VMA.
        if unsafe { aspace.demand_alloc_page(VirtAddr::new(base + 4096)) }.is_err() {
            return TestResult::Fail("overlay page-1 fault failed");
        }
        let lower_p1 = match lower_file.mmap_fault(4096) {
            Ok(phys) => phys,
            Err(_) => return TestResult::Fail("lower page-1 fault failed"),
        };
        let upper_p1_phys = match upper_file.mmap_fault(4096) {
            Ok(phys) => phys,
            Err(_) => return TestResult::Fail("upper page-1 fault failed"),
        };
        if upper_p1_phys == lower_p1 {
            return TestResult::Fail("upper and lower page 1 unexpectedly alias");
        }
        let page1 = match aspace.lookup(VirtAddr::new(base + 4096)) {
            Some(region) if region.phys.get(1).is_some_and(|phys| phys.raw() == lower_p1) => {
                region.phys[1]
            }
            _ => return TestResult::Fail("post-copy-up fault did not serve the lower page"),
        };
        // SAFETY: `page1` is the mapping's live, kernel-direct-mapped frame.
        if unsafe { core::slice::from_raw_parts(page1.kernel_ptr::<u8>(), 8) } != b"LOWER-P1" {
            return TestResult::Fail("post-copy-up fault served upper bytes in a lower mapping");
        }

        // A NEW mapping published after the copy-up pins the upper file:
        // the pin is per mapping, not a property of the overlay object.
        let Some(second_base) = map_shared(8192) else {
            return TestResult::Fail("post-copy-up overlay mmap failed");
        };
        let Some((second_owner, _)) =
            crate::mapped_file::shared_file_at(aspace.identity(), second_base)
        else {
            return TestResult::Fail("second overlay mapping registered no file owner");
        };
        if !Arc::ptr_eq(&second_owner, &upper_file) {
            return TestResult::Fail("post-copy-up mapping did not pin the upper file");
        }
        // SAFETY: `second_base + 4096` lies in the second test-owned VMA.
        if unsafe { aspace.demand_alloc_page(VirtAddr::new(second_base + 4096)) }.is_err() {
            return TestResult::Fail("second mapping page-1 fault failed");
        }
        match aspace.lookup(VirtAddr::new(second_base + 4096)) {
            Some(region)
                if region
                    .phys
                    .get(1)
                    .is_some_and(|phys| phys.raw() == upper_p1_phys) => {}
            _ => return TestResult::Fail("post-copy-up mapping did not fault from the upper file"),
        }

        let _ = aspace.unmap_region(VirtAddr::new(second_base));
        crate::mapped_file::unmap_current(second_base);
        let _ = aspace.unmap_region(VirtAddr::new(base));
        crate::mapped_file::unmap_current(base);
        crate::fd::__test_reset();
        *USER_AS.lock() = None;
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mmap_overlay_copy_up_keeps_mapping_pinned_to_lower
    );

    // ── #676: generic-fallback coherence and writeback lifecycle ──────
    //
    // The generic fallback cache used to be a write-only island: write(2)
    // bypassed its frames, and its dirty pages were committed only by an
    // fsync/msync from the owning process — never by munmap, exit or
    // sync(2). These tests pin the Linux contract end to end through the
    // real syscall handlers: the file TestFile serves IS what read(2)
    // would return, so a stale file image is the observable bug.

    /// Stand up the fsync test's environment with a caller-chosen file
    /// image: a fresh user AS as current, TASK registered, and one
    /// O_RDWR fd on a fresh TestFile.
    fn fallback_test_setup(
        image: alloc::vec::Vec<u8>,
    ) -> Result<(Arc<AddressSpace>, Arc<TestFile>, u32), TestResult> {
        // SAFETY: the syscall runs with paging active; this allocates an
        // independent user address space without switching the active one.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err(TestResult::Fail("new_for_user failed")),
        };
        *USER_AS.lock() = Some(Arc::clone(&aspace));
        install_address_space_lookup(address_space);
        install_task_id_lookup(task);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
        crate::fd::__test_reset();
        crate::handlers::register_task_to_pid(TASK, PROCESS);
        let file = Arc::new(TestFile {
            bytes: IrqSafeSpinLock::new(image),
            writes: AtomicUsize::new(0),
        });
        let fd = crate::fd::install(
            TASK,
            crate::fd::FdEntry {
                ops: Arc::clone(&file) as Arc<dyn FileOps>,
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDWR,
            },
        )
        .unwrap_or(u32::MAX);
        if fd == u32::MAX {
            return Err(TestResult::Fail("could not install test file fd"));
        }
        Ok((aspace, file, fd))
    }

    fn fallback_test_teardown() {
        crate::fd::__test_reset();
        *USER_AS.lock() = None;
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
    }

    /// mmap `len` bytes of `fd` MAP_SHARED PROT_READ|PROT_WRITE and fault
    /// the first page in, returning (base, frame phys).
    fn mmap_shared_faulted(
        aspace: &Arc<AddressSpace>,
        fd: u32,
        len: u64,
    ) -> Result<(u64, narf_memory::PhysAddr), TestResult> {
        let mut mmap = TestCtx {
            args: SyscallArgs {
                arg1: len,
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
            _ => return Err(TestResult::Fail("MAP_SHARED file mmap failed")),
        };
        // SAFETY: the test owns this live user root and the address lies in
        // the FILE_DEMAND mapping just published through sys_mmap.
        if unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(base)) }.is_err() {
            return Err(TestResult::Fail("file fault did not publish a page"));
        }
        let region = match aspace.lookup(narf_memory::VirtAddr::new(base)) {
            Some(region) if !region.phys.is_empty() && region.phys[0].raw() != 0 => region,
            _ => return Err(TestResult::Fail("file fault left the region unbacked")),
        };
        Ok((base, region.phys[0]))
    }

    fn call_syscall(
        handler: fn(&mut dyn TrapContext),
        args: SyscallArgs,
    ) -> Result<SyscallReturn, TestResult> {
        let mut ctx = TestCtx { args, ret: None };
        handler(&mut ctx);
        match ctx.ret {
            Some(ret) if ret.status == SyscallReturn::OK && (ret.value as i64) >= 0 => Ok(ret),
            _ => Err(TestResult::Fail("syscall did not return success")),
        }
    }

    /// The headline #676 sequence, under Linux's rules: a store through a
    /// generic-fallback MAP_SHARED mapping, then munmap, must be what a
    /// later read(2) returns — with no fsync anywhere. munmap itself writes
    /// nothing (`zap_pte_range` only marks the folio dirty): the page stays
    /// in the file cache, read(2) reads through it, and sync(2) — or the
    /// writeback task — commits it.
    fn smoke_mmap_shared_write_survives_munmap() -> TestResult {
        // The pread64 below reads into a kernel buffer.
        let _kernel_buffers = crate::handlers::kernel_buffers_guard();
        let (aspace, file, fd) = match fallback_test_setup(vec![0; 4096]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let (base, phys) = match mmap_shared_faulted(&aspace, fd, 4096) {
            Ok(pair) => pair,
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        // A real store would fault on the clean page's read-only PTE first.
        crate::mapped_file::shared_page_write_fault(phys.raw());
        // SAFETY: the fault published this cache-owned frame for the test
        // mapping and all physical memory is kernel identity-mapped.
        unsafe {
            core::ptr::copy_nonoverlapping(
                c"PERSIST!".as_ptr().cast(),
                phys.kernel_mut_ptr::<u8>(),
                9,
            );
        }
        let waits = crate::handlers::fallback_waits();
        if call_syscall(
            crate::handlers::sys_munmap,
            SyscallArgs {
                arg0: base,
                arg1: 4096,
                ..SyscallArgs::default()
            },
        )
        .is_err()
        {
            fallback_test_teardown();
            return TestResult::Fail("munmap of the shared file mapping failed");
        }
        if file.writes.load(Ordering::Relaxed) != 0 {
            fallback_test_teardown();
            return TestResult::Fail("munmap wrote the dirty page itself");
        }
        if crate::handlers::fallback_waits() != waits {
            fallback_test_teardown();
            return TestResult::Fail("munmap waited on the filesystem");
        }
        let mut read_back = [0u8; 9];
        let read = call_syscall(
            crate::handlers::sys_pread64,
            SyscallArgs {
                arg0: fd as u64,
                arg1: read_back.as_mut_ptr() as u64,
                arg2: 9,
                arg3: 0,
                ..SyscallArgs::default()
            },
        );
        if read.is_err() || &read_back != b"PERSIST!\0" {
            fallback_test_teardown();
            return TestResult::Fail(
                "read(2) after munmap did not return the mapped store; it served stale bytes",
            );
        }
        if file.writes.load(Ordering::Relaxed) != 0 {
            fallback_test_teardown();
            return TestResult::Fail("read(2) had to write the page to see it");
        }
        if call_syscall(crate::handlers::sys_sync, SyscallArgs::default()).is_err() {
            fallback_test_teardown();
            return TestResult::Fail("sync(2) failed");
        }
        let persisted = &file.bytes.lock()[..9] == b"PERSIST!\0";
        let writes = file.writes.load(Ordering::Relaxed);
        fallback_test_teardown();
        if !persisted || writes != 1 {
            return TestResult::Fail(
                "a page left dirty by munmap was not written exactly once by sync(2)",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_mmap_shared_write_survives_munmap
    );

    /// `munmap` of a large dirty MAP_SHARED mapping — the path the lockup
    /// detector caught: a few thousand dirty pages kept one CPU in this
    /// syscall for over a minute, one filesystem write per page, with every
    /// task queued on that CPU waiting behind it. Now the syscall writes
    /// nothing and waits for nothing however many pages are dirty; every
    /// page stays readable; and when the pages are written, neighbours go
    /// to the filesystem together, a batch to an operation.
    fn smoke_munmap_of_large_dirty_mapping_writes_nothing() -> TestResult {
        const PAGES: usize = 512;
        // The pread64 below reads into a kernel buffer.
        let _kernel_buffers = crate::handlers::kernel_buffers_guard();
        let (aspace, file, fd) = match fallback_test_setup(vec![0; PAGES * 4096]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let (base, _) = match mmap_shared_faulted(&aspace, fd, (PAGES * 4096) as u64) {
            Ok(pair) => pair,
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        // Touch and dirty every page, as a process writing a cache index
        // through its mapping does.
        for page in 0..PAGES {
            let va = narf_memory::VirtAddr::new(base + (page * 4096) as u64);
            let frame = |aspace: &Arc<AddressSpace>| {
                aspace
                    .lookup(narf_memory::VirtAddr::new(base))
                    .filter(|region| region.phys.len() > page && region.phys[page].raw() != 0)
                    .map(|region| region.phys[page])
            };
            if frame(&aspace).is_none() {
                // SAFETY: the test owns this live user root and the address
                // lies in the FILE_DEMAND mapping published by sys_mmap.
                let _ = unsafe { aspace.demand_alloc_page(va) };
            }
            let Some(phys) = frame(&aspace) else {
                fallback_test_teardown();
                return TestResult::Fail("a page of the large mapping did not fault in");
            };
            // A real store would fault on the clean page's read-only PTE first.
            crate::mapped_file::shared_page_write_fault(phys.raw());
            // SAFETY: the cache-owned frame behind the test's own mapping.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (page as u64 + 1).to_le_bytes().as_ptr(),
                    phys.kernel_mut_ptr::<u8>().add(16),
                    8,
                );
            }
        }
        let waits = crate::handlers::fallback_waits();
        if call_syscall(
            crate::handlers::sys_munmap,
            SyscallArgs {
                arg0: base,
                arg1: (PAGES * 4096) as u64,
                ..SyscallArgs::default()
            },
        )
        .is_err()
        {
            fallback_test_teardown();
            return TestResult::Fail("munmap of the large shared file mapping failed");
        }
        if file.writes.load(Ordering::Relaxed) != 0 {
            fallback_test_teardown();
            return TestResult::Fail("munmap wrote dirty pages of the mapping it removed");
        }
        if crate::handlers::fallback_waits() != waits {
            fallback_test_teardown();
            return TestResult::Fail("munmap waited on the filesystem");
        }
        // Any page is still what read(2) returns.
        let probe = PAGES - 3;
        let mut read_back = [0u8; 8];
        let read = call_syscall(
            crate::handlers::sys_pread64,
            SyscallArgs {
                arg0: fd as u64,
                arg1: read_back.as_mut_ptr() as u64,
                arg2: 8,
                arg3: (probe * 4096 + 16) as u64,
                ..SyscallArgs::default()
            },
        );
        if read.is_err() || u64::from_le_bytes(read_back) != probe as u64 + 1 {
            fallback_test_teardown();
            return TestResult::Fail("read(2) after munmap lost a store of the large mapping");
        }
        if call_syscall(crate::handlers::sys_sync, SyscallArgs::default()).is_err() {
            fallback_test_teardown();
            return TestResult::Fail("sync(2) failed");
        }
        let all_written = {
            let bytes = file.bytes.lock();
            (0..PAGES).all(|page| {
                bytes[page * 4096 + 16..page * 4096 + 24] == (page as u64 + 1).to_le_bytes()
            })
        };
        let writes = file.writes.load(Ordering::Relaxed);
        fallback_test_teardown();
        if !all_written {
            return TestResult::Fail("a page left dirty by munmap never reached the file");
        }
        if writes != PAGES / crate::mapped_file::WRITEBACK_BATCH_PAGES {
            return TestResult::Fail(
                "neighbouring dirty pages were not written one batch to a filesystem operation",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_munmap_of_large_dirty_mapping_writes_nothing
    );

    /// Truncating a file nobody maps looks at no address space. The
    /// truncate here runs while this address space's own VMA transaction
    /// is held — a long `munmap` in progress — and returns: before the
    /// reverse map every truncate of any file, an `open(O_TRUNC)` of a
    /// tmpfs file included, took that interrupts-off lock in every address
    /// space and spun until its holder was done.
    fn smoke_truncate_of_unmapped_file_visits_no_address_space() -> TestResult {
        let (aspace, _file, fd) = match fallback_test_setup(vec![0; 8192]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        // The address space does map a file — a different one.
        if let Err(result) = mmap_shared_faulted(&aspace, fd, 8192) {
            fallback_test_teardown();
            return result;
        }
        let unmapped: Arc<dyn FileOps> = Arc::new(TestFile {
            bytes: IrqSafeSpinLock::new(vec![1; 8192]),
            writes: AtomicUsize::new(0),
        });
        let visits = crate::mapped_file::TRUNCATE_SPACE_VISITS.load(Ordering::Relaxed);
        let outcome = aspace
            .with_vma_transaction(|| crate::mapped_file::truncate_file_mappings(unmapped.as_ref(), 0));
        let visited = crate::mapped_file::TRUNCATE_SPACE_VISITS.load(Ordering::Relaxed) != visits;
        fallback_test_teardown();
        if outcome.is_err() {
            return TestResult::Fail("truncate of an unmapped file failed");
        }
        if visited {
            return TestResult::Fail("truncate of an unmapped file took an address space's lock");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_truncate_of_unmapped_file_visits_no_address_space
    );

    /// Truncating a mapped file visits the address space that maps it —
    /// once — and takes the page past the new EOF out of the mapping while
    /// the page below it stays.
    fn smoke_truncate_of_mapped_file_zaps_its_mapper() -> TestResult {
        let (aspace, file, fd) = match fallback_test_setup(vec![7; 8192]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let (base, _) = match mmap_shared_faulted(&aspace, fd, 8192) {
            Ok(pair) => pair,
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        let second = narf_memory::VirtAddr::new(base + 4096);
        let backed = |va| matches!(aspace.page_backing(va), Some((_, phys)) if phys.raw() != 0);
        if !backed(second) {
            // SAFETY: the test owns this live user root and the address
            // lies in the FILE_DEMAND mapping published by sys_mmap.
            let _ = unsafe { aspace.demand_alloc_page(second) };
        }
        if !backed(second) {
            fallback_test_teardown();
            return TestResult::Fail("the second page of the mapping did not fault in");
        }
        // The filesystem's half of a truncate to one page, then the bridge.
        file.bytes.lock().truncate(4096);
        let visits = crate::mapped_file::TRUNCATE_SPACE_VISITS.load(Ordering::Relaxed);
        let mapped: &dyn FileOps = file.as_ref();
        let outcome = crate::mapped_file::truncate_file_mappings(mapped, 4096);
        let visited =
            crate::mapped_file::TRUNCATE_SPACE_VISITS.load(Ordering::Relaxed) - visits;
        let first_kept = backed(narf_memory::VirtAddr::new(base));
        let second_gone = !backed(second);
        fallback_test_teardown();
        if outcome.is_err() {
            return TestResult::Fail("truncate of a mapped file failed");
        }
        if visited != 1 {
            return TestResult::Fail("truncate did not visit exactly the one mapper of the file");
        }
        if !second_gone {
            return TestResult::Fail("a page past the new EOF stayed mapped after truncate");
        }
        if !first_kept {
            return TestResult::Fail("truncate unmapped a page below the new EOF");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_truncate_of_mapped_file_zaps_its_mapper
    );

    /// `mmap(PROT_READ, MAP_SHARED)` of `fd`, then `mprotect` to read and
    /// write: the raw syscall result.
    fn map_then_make_writable(fd: u32) -> Result<(u64, SyscallReturn), TestResult> {
        let mut mmap = TestCtx {
            args: SyscallArgs {
                arg1: 4096,
                arg2: 1,    // PROT_READ
                arg3: 0x01, // MAP_SHARED
                arg4: fd as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut mmap);
        let base = match mmap.ret {
            Some(ret) if ret.status == SyscallReturn::OK && (ret.value as i64) > 0 => ret.value,
            _ => return Err(TestResult::Fail("read-only MAP_SHARED mmap failed")),
        };
        let mut mprotect = TestCtx {
            args: SyscallArgs {
                arg0: base,
                arg1: 4096,
                arg2: 3, // PROT_READ | PROT_WRITE
                ..SyscallArgs::default()
            },
            ret: None,
        };
        crate::handlers::sys_mprotect(&mut mprotect);
        match mprotect.ret {
            Some(ret) => Ok((base, ret)),
            None => Err(TestResult::Fail("mprotect returned nothing")),
        }
    }

    /// A shared mapping of a descriptor not open for writing cannot be made
    /// writable: Linux clears `VM_MAYWRITE` on it and `mprotect` is EACCES.
    /// Through a descriptor open for writing it can, and its stores reach
    /// the file.
    fn smoke_mprotect_write_needs_a_writable_descriptor() -> TestResult {
        let (aspace, file, rw_fd) = match fallback_test_setup(vec![0; 4096]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let ro_fd = crate::fd::install(
            TASK,
            crate::fd::FdEntry {
                ops: Arc::clone(&file) as Arc<dyn FileOps>,
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDONLY,
            },
        )
        .unwrap_or(u32::MAX);
        if ro_fd == u32::MAX {
            fallback_test_teardown();
            return TestResult::Fail("could not install a read-only fd");
        }
        let refused = match map_then_make_writable(ro_fd) {
            Ok((_, ret)) => ret.status == SyscallReturn::OK && ret.value as i64 == -13,
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        let allowed = match map_then_make_writable(rw_fd) {
            Ok((base, ret)) => {
                (ret.status == SyscallReturn::OK && ret.value as i64 >= 0).then_some(base)
            }
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        let persisted = allowed.is_some_and(|base| {
            // SAFETY: the test owns this live user root; the address lies in
            // the FILE_DEMAND mapping just published.
            let _ = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(base)) };
            let Some(region) = aspace.lookup(narf_memory::VirtAddr::new(base)) else {
                return false;
            };
            let Some(phys) = region.phys.first().copied().filter(|phys| phys.raw() != 0) else {
                return false;
            };
            // A real store would fault on the clean page's read-only PTE first.
            crate::mapped_file::shared_page_write_fault(phys.raw());
            // SAFETY: the cache frame behind the test's own writable mapping.
            unsafe { core::ptr::copy_nonoverlapping(b"RW".as_ptr(), phys.kernel_mut_ptr::<u8>(), 2) };
            call_syscall(crate::handlers::sys_sync, SyscallArgs::default()).is_ok()
                && file.bytes.lock()[..2] == *b"RW"
        });
        fallback_test_teardown();
        if !refused {
            return TestResult::Fail(
                "mprotect(PROT_WRITE) of a shared mapping of a read-only fd was not EACCES",
            );
        }
        if allowed.is_none() {
            return TestResult::Fail("mprotect(PROT_WRITE) through a writable fd was refused");
        }
        if !persisted {
            return TestResult::Fail("a store after mprotect(PROT_WRITE) never reached the file");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_mprotect_write_needs_a_writable_descriptor
    );

    /// The frame a page of the test mapping holds now, if any.
    fn mapped_frame(aspace: &Arc<AddressSpace>, va: u64) -> Option<narf_memory::PhysAddr> {
        aspace
            .page_backing(narf_memory::VirtAddr::new(va))
            .map(|(_, phys)| phys)
            .filter(|phys| phys.raw() != 0)
    }

    /// Clean shared file pages are reclaimable while mapped, and their
    /// mappings record stores by faulting. A file is mapped writable and
    /// read in full; a few pages are then stored to, through the kernel
    /// write path that takes the same write-notify fault a user store does.
    /// Reclaim then unmaps every clean page from the mapping and frees it,
    /// and leaves the stored-to pages alone; touching an unmapped page again
    /// refaults it with the file's bytes; and the stores reach the file.
    fn smoke_reclaim_frees_clean_mapped_pages_and_keeps_stores() -> TestResult {
        const PAGES: usize = 16;
        const STORED: usize = 3;
        let mut image = vec![0u8; PAGES * 4096];
        for (page, chunk) in image.chunks_mut(4096).enumerate() {
            chunk.fill(page as u8 + 1);
        }
        let (aspace, file, fd) = match fallback_test_setup(image) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let (base, _) = match mmap_shared_faulted(&aspace, fd, (PAGES * 4096) as u64) {
            Ok(pair) => pair,
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        let va = |page: usize| base + (page * 4096) as u64;
        for page in 0..PAGES {
            if mapped_frame(&aspace, va(page)).is_none() {
                // SAFETY: the test owns this live user root; the address lies
                // in the FILE_DEMAND mapping published by sys_mmap.
                let _ = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(va(page))) };
            }
        }
        let Some(first) = mapped_frame(&aspace, va(0)) else {
            fallback_test_teardown();
            return TestResult::Fail("the mapping did not fault in");
        };
        if crate::mapped_file::shared_page_write_enabled(first.raw()) {
            fallback_test_teardown();
            return TestResult::Fail("a clean page of a writable shared mapping was mapped writable");
        }
        for page in 0..STORED {
            // SAFETY: as above; the kernel write path for a present user page.
            if !unsafe { aspace.user_page_writable_or_resolve(narf_memory::VirtAddr::new(va(page))) } {
                fallback_test_teardown();
                return TestResult::Fail("the write-notify fault did not admit a store");
            }
            let Some(phys) = mapped_frame(&aspace, va(page)) else {
                fallback_test_teardown();
                return TestResult::Fail("a stored-to page was not mapped");
            };
            if !crate::mapped_file::shared_page_write_enabled(phys.raw()) {
                fallback_test_teardown();
                return TestResult::Fail("the write-notify fault did not record the store");
            }
            // SAFETY: the cache frame behind the test's own writable mapping.
            unsafe { *phys.kernel_mut_ptr::<u8>().add(7) = 0xEE };
        }

        // Reclaim until every clean page is gone from the mapping (other
        // tests' cache pages may be scanned first).
        for _ in 0..64 {
            if (STORED..PAGES).all(|page| mapped_frame(&aspace, va(page)).is_none()) {
                break;
            }
            crate::mapped_file::reclaim_mapped_for_test(PAGES);
        }
        let clean_gone = (STORED..PAGES).all(|page| mapped_frame(&aspace, va(page)).is_none());
        let dirty_kept = (0..STORED).all(|page| mapped_frame(&aspace, va(page)).is_some());
        // Touch an unmapped page again: it comes back from the file.
        // SAFETY: as above.
        let _ = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(va(PAGES - 1))) };
        let refaulted = mapped_frame(&aspace, va(PAGES - 1)).is_some_and(|phys| {
            // SAFETY: the frame now backing the test's own mapping.
            unsafe { core::slice::from_raw_parts(phys.kernel_ptr::<u8>(), 4096) }
                .iter()
                .all(|byte| *byte == PAGES as u8)
        });
        let synced = call_syscall(crate::handlers::sys_sync, SyscallArgs::default()).is_ok();
        let stored = {
            let bytes = file.bytes.lock();
            (0..STORED).all(|page| bytes[page * 4096 + 7] == 0xEE)
                && (STORED..PAGES).all(|page| bytes[page * 4096 + 7] == page as u8 + 1)
        };
        fallback_test_teardown();
        if !clean_gone {
            return TestResult::Fail("reclaim left a clean mapped page mapped");
        }
        if !dirty_kept {
            return TestResult::Fail("reclaim unmapped a page holding an unwritten store");
        }
        if !refaulted {
            return TestResult::Fail("a reclaimed page did not come back with the file's bytes");
        }
        if !synced || !stored {
            return TestResult::Fail("stores through the mapping did not reach the file");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_reclaim_frees_clean_mapped_pages_and_keeps_stores
    );

    /// Store `bytes` at user address `va` of `aspace` through the page
    /// tables: the address space is made current and the store goes through
    /// `copy_to_user`. With CR0.WP set the CPU enforces a read-only PTE for
    /// this kernel-mode store too, so a store to a clean shared file page
    /// takes the real #PF, the trap handler's present-read-only path calls
    /// the write-notify hook and re-installs the PTE writable, and the store
    /// is retried — the path a user store takes (only the U bit differs).
    #[cfg(target_arch = "x86_64")]
    fn store_through_ptes(aspace: &Arc<AddressSpace>, va: u64, bytes: &[u8]) -> bool {
        // SAFETY: CPL0; the value is restored below.
        let saved = unsafe { narf_arch::x86_64::cr::read_cr3() };
        if aspace.activate().is_err() {
            return false;
        }
        // SAFETY: `va` lies in the test's live mapping, which the active
        // root now translates; the guarded copy opens SMAP itself.
        let stored = unsafe { crate::handlers::copy_to_user(va, bytes) }.is_ok();
        // SAFETY: `saved` is the root this CPU ran on before `activate`.
        unsafe { narf_arch::x86_64::cr::write_cr3(saved) };
        stored
    }

    #[cfg(target_arch = "x86_64")]
    fn pread_all(fd: u32, offset: u64, len: usize) -> Option<alloc::vec::Vec<u8>> {
        let mut buf = vec![0u8; len];
        let ret = call_syscall(
            crate::handlers::sys_pread64,
            SyscallArgs {
                arg0: fd as u64,
                arg1: buf.as_mut_ptr() as u64,
                arg2: len as u64,
                arg3: offset,
                ..SyscallArgs::default()
            },
        )
        .ok()?;
        (ret.value as usize == len).then_some(buf)
    }

    /// The soak's cases through the real write-notify fault. Case (2):
    /// `pwrite` 0xbd, a store of 0xaf through the mapping over part of it,
    /// munmap, `pread` must return 0xaf. Case (1): two stores through two
    /// mappings, the second over the first; a fresh mapping, faulted and
    /// read through the page tables, must show the second. Both before and
    /// after writeback.
    #[cfg(target_arch = "x86_64")]
    fn smoke_stores_through_real_ptes_take_the_write_notify_fault() -> TestResult {
        const PAGES: usize = 8;
        const LEN: u64 = (PAGES * 4096) as u64;
        let _kernel_buffers = crate::handlers::kernel_buffers_guard();
        let (aspace, file, fd) = match fallback_test_setup(vec![0x11; PAGES * 4096]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let outcome = (|| -> Result<(), &'static str> {
            // Case (2).
            let src = vec![0xbdu8; 3 * 4096 + 700];
            call_syscall(
                crate::handlers::sys_pwrite64,
                SyscallArgs {
                    arg0: fd as u64,
                    arg1: src.as_ptr() as u64,
                    arg2: src.len() as u64,
                    arg3: 4096 + 900,
                    ..SyscallArgs::default()
                },
            )
            .map_err(|_| "pwrite64 failed")?;
            let (base, _) = mmap_shared_faulted(&aspace, fd, LEN).map_err(|_| "mmap failed")?;
            for page in 0..PAGES as u64 {
                // SAFETY: the test's live mapping.
                let _ = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(base + page * 4096)) };
            }
            let page1 = aspace
                .page_backing(narf_memory::VirtAddr::new(base + 4096))
                .map(|(_, phys)| phys)
                .ok_or("page 1 did not fault in")?;
            if crate::mapped_file::shared_page_write_enabled(page1.raw()) {
                return Err("a clean page was mapped writable before any store");
            }
            let (m_from, m_len) = (2 * 4096 + 1500, 4096 + 2100);
            if !store_through_ptes(&aspace, base + m_from, &vec![0xafu8; m_len]) {
                return Err("a store through the page tables faulted for good");
            }
            let page2 = aspace
                .page_backing(narf_memory::VirtAddr::new(base + 2 * 4096))
                .map(|(_, phys)| phys)
                .ok_or("page 2 is not mapped")?;
            if !crate::mapped_file::shared_page_write_enabled(page2.raw()) {
                return Err("the hardware write fault did not record the store as dirty");
            }
            call_syscall(
                crate::handlers::sys_munmap,
                SyscallArgs {
                    arg0: base,
                    arg1: LEN,
                    ..SyscallArgs::default()
                },
            )
            .map_err(|_| "munmap failed")?;
            let read = pread_all(fd, m_from, m_len).ok_or("pread failed")?;
            if read.iter().any(|b| *b != 0xaf) {
                return Err("case (2): pread after munmap returned the pwrite's bytes");
            }
            call_syscall(crate::handlers::sys_sync, SyscallArgs::default())
                .map_err(|_| "sync failed")?;
            let read = pread_all(fd, m_from, m_len).ok_or("pread failed")?;
            if read.iter().any(|b| *b != 0xaf)
                || file.bytes.lock()[m_from as usize..m_from as usize + m_len]
                    .iter()
                    .any(|b| *b != 0xaf)
            {
                return Err("case (2): the store did not reach the file through writeback");
            }

            // Case (1): two generations, then a fresh mapping.
            for (byte, from, len) in [(0xc1u8, 3 * 4096 + 1808, 3 * 4096), (0x93u8, 3 * 4096 + 900, 2 * 4096 + 500)] {
                let (base, _) = mmap_shared_faulted(&aspace, fd, LEN).map_err(|_| "mmap failed")?;
                for page in 0..PAGES as u64 {
                    // SAFETY: the test's live mapping.
                    let _ = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(base + page * 4096)) };
                }
                if !store_through_ptes(&aspace, base + from, &vec![byte; len]) {
                    return Err("a store through the page tables faulted for good");
                }
                call_syscall(
                    crate::handlers::sys_munmap,
                    SyscallArgs {
                        arg0: base,
                        arg1: LEN,
                        ..SyscallArgs::default()
                    },
                )
                .map_err(|_| "munmap failed")?;
            }
            let (base, _) = mmap_shared_faulted(&aspace, fd, LEN).map_err(|_| "mmap failed")?;
            // SAFETY: the test's live mapping.
            let _ = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(base + 4 * 4096)) };
            let fresh = aspace
                .page_backing(narf_memory::VirtAddr::new(base + 4 * 4096))
                .map(|(_, phys)| phys)
                .ok_or("the fresh mapping did not fault in")?;
            // SAFETY: the frame backing the test's own mapping.
            let bytes = unsafe { core::slice::from_raw_parts(fresh.kernel_ptr::<u8>(), 4096) };
            // Page 4 = [16384, 20480): 0x93 covers [13188, 21880).
            if bytes.iter().any(|b| *b != 0x93) {
                return Err("case (1): a fresh mapping showed the older generation");
            }
            Ok(())
        })();
        fallback_test_teardown();
        match outcome {
            Ok(()) => TestResult::Pass,
            Err(why) => TestResult::Fail(why),
        }
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "userspace/writeback",
        smoke_stores_through_real_ptes_take_the_write_notify_fault
    );

    /// write(2) must be visible through a live generic-fallback mapping,
    /// and a later msync must not resurrect the pre-write bytes: the
    /// fallback page's snapshot marks the whole page dirty after one
    /// mapped store, so a whole-page writeback used to clobber every
    /// interleaved write(2) change in that page.
    fn smoke_mmap_write2_coherent_and_msync_no_clobber() -> TestResult {
        // The pwrite64 below passes a kernel buffer as its source; the
        // scope makes validate_rw_user_range accept it on this CPU.
        let _kernel_buffers = crate::handlers::kernel_buffers_guard();
        let (aspace, file, fd) = match fallback_test_setup(vec![b'A'; 4096]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let (base, phys) = match mmap_shared_faulted(&aspace, fd, 4096) {
            Ok(pair) => pair,
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        // pwrite64(fd, "BBBB", 4, 100) through the write(2) path, into a
        // byte range the live mapping covers. (The source is a kernel
        // buffer: this harness never switches the active page tables to
        // the test AS, so syscall buffers are kernel pointers — the same
        // idiom as every other handler test.)
        let src = *b"BBBB";
        if call_syscall(
            crate::handlers::sys_pwrite64,
            SyscallArgs {
                arg0: fd as u64,
                arg1: src.as_ptr() as u64,
                arg2: 4,
                arg3: 100,
                ..SyscallArgs::default()
            },
        )
        .is_err()
        {
            fallback_test_teardown();
            return TestResult::Fail("pwrite64 on the mapped file failed");
        }
        // SAFETY: the frame is the canonical cache page for this mapping.
        let coherent =
            unsafe { core::slice::from_raw_parts(phys.kernel_ptr::<u8>(), 4096) }[100..104]
                == *b"BBBB";
        if !coherent {
            fallback_test_teardown();
            return TestResult::Fail("write(2) did not update the live MAP_SHARED page");
        }
        // A real store would fault on the clean page's read-only PTE first.
        crate::mapped_file::shared_page_write_fault(phys.raw());
        // One mapped store, then msync: writeback must carry the store
        // without clobbering the write(2) bytes at offset 100.
        // SAFETY: as above.
        unsafe {
            *phys.kernel_mut_ptr::<u8>().add(200) = b'C';
        }
        if call_syscall(
            crate::handlers::sys_msync,
            SyscallArgs {
                arg0: base,
                arg1: 4096,
                arg2: 4, // MS_SYNC
                ..SyscallArgs::default()
            },
        )
        .is_err()
        {
            fallback_test_teardown();
            return TestResult::Fail("msync of the shared file mapping failed");
        }
        let bytes = file.bytes.lock();
        let kept_write = bytes[100..104] == *b"BBBB";
        let kept_store = bytes[200] == b'C';
        let kept_rest = bytes[0] == b'A' && bytes[3000] == b'A';
        drop(bytes);
        fallback_test_teardown();
        if !kept_write {
            return TestResult::Fail("msync writeback clobbered interleaved write(2) data");
        }
        if !kept_store || !kept_rest {
            return TestResult::Fail("msync did not persist exactly the mapped store");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_mmap_write2_coherent_and_msync_no_clobber
    );

    /// sync(2) is global: it must commit fallback dirty pages whose owner
    /// is a different address space that never calls fsync. Before the
    /// fix, flush entry points only ever walked the caller's own owner
    /// bucket, so another process's dirty pages were unreachable.
    fn smoke_mmap_shared_dirty_pages_flush_on_sync() -> TestResult {
        let (aspace, file, fd) = match fallback_test_setup(vec![0; 4096]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let (_base, phys) = match mmap_shared_faulted(&aspace, fd, 4096) {
            Ok(pair) => pair,
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        // A real store would fault on the clean page's read-only PTE first.
        crate::mapped_file::shared_page_write_fault(phys.raw());
        // SAFETY: the fault published this cache-owned frame for the test
        // mapping and all physical memory is kernel identity-mapped.
        unsafe {
            core::ptr::copy_nonoverlapping(
                c"SYNCDIRT".as_ptr().cast(),
                phys.kernel_mut_ptr::<u8>(),
                9,
            );
        }
        // sync(2) arrives from an unrelated process context: a different
        // current address space that owns no mappings of the file.
        // SAFETY: as in fallback_test_setup.
        let other = match unsafe { AddressSpace::new_for_user() } {
            Ok(other) => Arc::new(other),
            Err(_) => {
                fallback_test_teardown();
                return TestResult::Fail("second new_for_user failed");
            }
        };
        *USER_AS.lock() = Some(other);
        if call_syscall(
            crate::handlers::sys_sync,
            SyscallArgs::default(),
        )
        .is_err()
        {
            fallback_test_teardown();
            return TestResult::Fail("sync(2) failed");
        }
        let persisted = &file.bytes.lock()[..9] == b"SYNCDIRT\0";
        fallback_test_teardown();
        if !persisted {
            return TestResult::Fail(
                "sync(2) did not commit another address space's dirty MAP_SHARED pages",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_mmap_shared_dirty_pages_flush_on_sync
    );

    /// A process that dirties a fallback page and exits without
    /// munmap/fsync does not lose it — and does not write it on the way
    /// out either. The hook memory's drop path calls runs wherever the last
    /// reference to the address space drops (the executor thread, for an
    /// exit or a SIGKILL), so it does no I/O: the page stays the file
    /// cache's, and sync(2) or the writeback task commits it.
    fn smoke_mmap_shared_dirty_pages_survive_exit() -> TestResult {
        let (aspace, file, fd) = match fallback_test_setup(vec![0; 4096]) {
            Ok(setup) => setup,
            Err(result) => return result,
        };
        let (_base, phys) = match mmap_shared_faulted(&aspace, fd, 4096) {
            Ok(pair) => pair,
            Err(result) => {
                fallback_test_teardown();
                return result;
            }
        };
        // A real store would fault on the clean page's read-only PTE first.
        crate::mapped_file::shared_page_write_fault(phys.raw());
        // SAFETY: the fault published this cache-owned frame for the test
        // mapping and all physical memory is kernel identity-mapped.
        unsafe {
            core::ptr::copy_nonoverlapping(
                c"EXITDIRT".as_ptr().cast(),
                phys.kernel_mut_ptr::<u8>(),
                9,
            );
        }
        let waits = crate::handlers::fallback_waits();
        crate::drop_mapped_file_address_space(aspace.identity());
        if file.writes.load(Ordering::Relaxed) != 0 {
            fallback_test_teardown();
            return TestResult::Fail("address-space teardown wrote a dirty MAP_SHARED page");
        }
        if crate::handlers::fallback_waits() != waits {
            fallback_test_teardown();
            return TestResult::Fail("address-space teardown waited on the filesystem");
        }
        if call_syscall(crate::handlers::sys_sync, SyscallArgs::default()).is_err() {
            fallback_test_teardown();
            return TestResult::Fail("sync(2) failed");
        }
        let persisted = &file.bytes.lock()[..9] == b"EXITDIRT\0";
        fallback_test_teardown();
        if !persisted {
            return TestResult::Fail(
                "a MAP_SHARED page dirtied before exit never reached the file",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/writeback",
        smoke_mmap_shared_dirty_pages_survive_exit
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
        crate::fd::install(
            ARENA_TASK,
            crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDWR,
            },
        )
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
        // Capability discovery is side-effect free: neither the arena nor
        // the Region is backed until an actual fault. This matters for files
        // whose first mapped offset is temporarily beyond EOF.
        if unbacked(0) != Some(true) || unbacked(2) != Some(true) {
            arena_test_teardown();
            return TestResult::Fail("the arena mapping was eagerly backed");
        }
        if arena.len_bytes() != 0 {
            arena_test_teardown();
            return TestResult::Fail("mmap populated the arena before a page fault");
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

        /// Buddy free-count corrected for what the kernel HEAP took during
        /// the same window.
        ///
        /// The heap's slab calls `alloc_frame()` when a size class runs
        /// dry, so any Rust allocation inside the code under measurement
        /// consumes a buddy frame as a side effect — and whether it needs
        /// to depends on how full the magazines already were, i.e. on
        /// whatever test ran before. That is what made this test flaky:
        /// `munmap` returned all 16 arena frames every time, but the raw
        /// delta came up short whenever munmap's own bookkeeping happened
        /// to grow a size class.
        ///
        /// The original comment here claimed 16 frames was "far more than
        /// the noise a single-threaded kernel test sees between two
        /// adjacent samples". The noise is not unrelated frame traffic; it
        /// is caused BY the code being measured, so no margin makes it go
        /// away.
        fn free_frames_net() -> usize {
            narf_memory::frame::stats().free + narf_memory::slab::frames_held()
        }

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
        let before = free_frames_net();
        drop(group);
        let while_mapped = free_frames_net().saturating_sub(before);
        if while_mapped >= PAGES {
            arena_test_teardown();
            return TestResult::Fail(
                "arena frames went back to the buddy while a userspace mapping still had them",
            );
        }

        // Now release the mapping. Its `Arc<dyn FileOps>` was the last
        // reference, so this is the drop that must free them.
        let before = free_frames_net();
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
        let after_munmap = free_frames_net().saturating_sub(before);
        if after_munmap < PAGES {
            arena_test_teardown();
            // If this ever fires again the corrected accounting has missed a
            // source. `frames_held` covers both halves of the heap's
            // footprint — size-class growth and large allocations — so the
            // next candidate is a frame consumer that is not the heap at
            // all (a driver, or a deferred reclaim landing mid-window).
            return TestResult::Fail(
                "munmap did not return the arena's frames to the buddy (net of heap growth)",
            );
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

    // `mbind(2)` installs a range policy in `vma->vm_policy`, which lives in
    // `mm_struct` — NOT in task_struct. `CLONE_VM` shares that mm outright
    // (`kernel/fork.c:1579-1581`: `mmget(oldmm); mm = oldmm;`), so a thread
    // must observe a range binding its thread-group peer installed.
    //
    // Regression: NARF's range table was keyed by the scheduler task id, which
    // `CLONE_THREAD` makes distinct per thread, so each thread got a PRIVATE
    // set of mbind ranges and a sibling saw the default policy. Contrast
    // `set_mempolicy`, which writes `current->mempolicy` (`mm/mempolicy.c:1091`)
    // and IS correctly per-task.
    fn smoke_mbind_range_policy_shared_with_thread_group_peer() -> TestResult {
        // The nodemask in-pointer and the mode out-pointer below are kernel
        // stack addresses standing in for user buffers; this is the scoped
        // opt-in that lets `validate_user_range` accept them.
        let _kbuf = crate::handlers::kernel_buffers_guard();
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
        crate::handlers::register_task_to_pid(TASK, PROCESS);
        crate::handlers::register_task_to_pid(WORKER_TASK, PROCESS);

        // A real mapping, so `get_mempolicy(MPOL_F_ADDR)` clears its
        // `contains_address` check and reaches the policy lookup.
        let mut mmap = TestCtx {
            args: SyscallArgs {
                arg1: 4096,
                arg2: 0x3,  // PROT_READ | PROT_WRITE
                arg3: 0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                arg4: u64::MAX,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        sys_mmap(&mut mmap);
        let base = match mmap.ret {
            Some(ret) if ret.status == SyscallReturn::OK && (ret.value as i64) > 0 => ret.value,
            _ => return TestResult::Fail("anonymous mmap for the mbind range failed"),
        };

        // Thread A binds the range with MPOL_BIND(2) over node 0. `arg3` is a
        // POINTER to the nodemask word, which `get_nodes()` copies in.
        let nodes: u64 = 1;
        let mut bind = TestCtx {
            args: SyscallArgs {
                arg0: base,
                arg1: 4096,
                arg2: 2, // MPOL_BIND
                arg3: &nodes as *const u64 as u64,
                arg4: 64,
                arg5: 0,
            },
            ret: None,
        };
        crate::handlers::sys_mbind(&mut bind);
        if !matches!(bind.ret, Some(ret) if ret.status == SyscallReturn::OK && ret.value == 0) {
            return TestResult::Fail("mbind(MPOL_BIND) over the mapped range failed");
        }

        // Thread B is a CLONE_THREAD peer: same process, same address space,
        // distinct scheduler task id.
        CURRENT_TASK.store(WORKER_TASK, Ordering::Relaxed);
        let mut mode: u32 = u32::MAX;
        let mode_ptr = &mut mode as *mut u32 as u64;
        let mut query = TestCtx {
            args: SyscallArgs {
                arg0: mode_ptr,
                arg1: 0,
                arg2: 0,
                arg3: base,
                arg4: 1 << 1, // MPOL_F_ADDR
                arg5: 0,
            },
            ret: None,
        };
        crate::handlers::sys_get_mempolicy(&mut query);
        CURRENT_TASK.store(TASK, Ordering::Relaxed);
        if !matches!(query.ret, Some(ret) if ret.status == SyscallReturn::OK && ret.value == 0) {
            return TestResult::Fail("get_mempolicy(MPOL_F_ADDR) from the peer failed");
        }
        // Before the fix the peer resolved no range and reported MPOL_DEFAULT(0).
        if mode != 2 {
            return TestResult::Fail(
                "CLONE_VM peer did not observe the mbind range policy (saw MPOL_DEFAULT)",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mbind_range_policy_shared_with_thread_group_peer
    );
}
