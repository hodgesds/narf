#[allow(unused_imports)]
use super::*;

const MREMAP_MAYMOVE: u32 = 1;
const MREMAP_FIXED: u32 = 2;
const MREMAP_DONTUNMAP: u32 = 4;
const EPERM: i64 = 1;
const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;

fn round_len(requested: u64) -> Result<u64, i64> {
    requested
        .checked_add(0xFFF)
        .map(|value| value & !0xFFF)
        .ok_or(EINVAL)
}

fn mremap_memory_errno(error: narf_memory::AddressSpaceError) -> i64 {
    match error {
        narf_memory::AddressSpaceError::LockLimit => EAGAIN,
        narf_memory::AddressSpaceError::AlignmentMismatch => EINVAL,
        narf_memory::AddressSpaceError::Unmapped
        | narf_memory::AddressSpaceError::SharedMapping => EFAULT,
        narf_memory::AddressSpaceError::NotImplemented => EINVAL,
        narf_memory::AddressSpaceError::MappingLimit
        | narf_memory::AddressSpaceError::AllocationFailed
        | narf_memory::AddressSpaceError::OutOfRange
        | narf_memory::AddressSpaceError::Overlap => ENOMEM,
        _ => ENOMEM,
    }
}

#[cfg(feature = "linux-compat")]
fn shm_mremap_prepare_error(
    error: ShmMremapPrepareError,
) -> narf_memory::AddressSpaceError {
    match error {
        ShmMremapPrepareError::InvalidRange => {
            narf_memory::AddressSpaceError::AlignmentMismatch
        }
        ShmMremapPrepareError::PartialSysvSource
        | ShmMremapPrepareError::AmbiguousSysvSource
        | ShmMremapPrepareError::SegmentMissing => narf_memory::AddressSpaceError::Unmapped,
        ShmMremapPrepareError::PreparationConflict
        | ShmMremapPrepareError::AllocationFailed
        | ShmMremapPrepareError::TokenExhausted => {
            narf_memory::AddressSpaceError::AllocationFailed
        }
    }
}

/// Publish one shared alias while the caller holds the address-space VMA,
/// shared-owner, and (under linux-compat) SysV mapping transactions.
///
/// The returned typed failure preserves Linux's destructive fixed-remap
/// boundary: once memory has punched the target, file and SysV owner metadata
/// must retire that target even if later alias admission fails.
#[allow(clippy::too_many_arguments)]
unsafe fn publish_shared_mremap_alias_locked(
    as_ref: &AddressSpace,
    old_addr: u64,
    len: u64,
    new_addr: u64,
    mode: narf_memory::SharedMremapMode,
    fixed: bool,
    limits: narf_memory::MremapLimits,
) -> Result<Option<(u64, u64)>, narf_memory::FixedRelocationError> {
    let early = |error| narf_memory::FixedRelocationError {
        error,
        target_punched: false,
    };
    let source_end = old_addr
        .checked_add(len)
        .ok_or_else(|| early(narf_memory::AddressSpaceError::OutOfRange))?;
    let destination_end = new_addr
        .checked_add(len)
        .ok_or_else(|| early(narf_memory::AddressSpaceError::OutOfRange))?;
    if old_addr < destination_end && new_addr < source_end {
        return Err(early(narf_memory::AddressSpaceError::Overlap));
    }

    #[cfg(feature = "linux-compat")]
    let shm_plan = {
        let task = current_task_id();
        let lpid = task_to_pid_raw(task).unwrap_or(task);
        let as_key = shm_as_key_ref(as_ref);
        // SAFETY: the caller holds shm_mapping_transaction(as_key) through
        // plan consumption and the VMA transaction keeps both ranges stable.
        unsafe {
            shm_prepare_mremap_shared_alias_locked(as_key, old_addr, len, new_addr, lpid)
        }
        .map_err(|error| early(shm_mremap_prepare_error(error)))?
    };

    let result = crate::mapped_file::publish_current_owner_alias(
        old_addr,
        new_addr,
        len,
        fixed,
        || {
            if fixed {
                // SAFETY: caller holds the VMA and shared-owner transactions;
                // file/SysV metadata has been prepared for the same ranges.
                unsafe {
                    as_ref.alias_shared_region_fixed_locked_limited(
                        VirtAddr::new(old_addr),
                        len,
                        VirtAddr::new(new_addr),
                        mode,
                        limits,
                        true,
                    )
                }
            } else {
                // SAFETY: same transaction/live-root contract as the fixed
                // path; this variant cannot destructively punch a target.
                unsafe {
                    as_ref.alias_shared_region_locked_limited(
                        VirtAddr::new(old_addr),
                        len,
                        VirtAddr::new(new_addr),
                        mode,
                        limits,
                    )
                }
                .map_err(early)
            }
        },
    );

    #[cfg(feature = "linux-compat")]
    match &result {
        Ok(_) => shm_plan.commit(fixed),
        Err(failure) => shm_plan.abort(failure.target_punched),
    }
    result
}

/// Core Linux-compatible `mremap` operation.
///
/// Private complete-VMA operations support no-op, real tail shrink, in-place
/// lazy grow, MAYMOVE/FIXED relocation, and DONTUNMAP's destination move plus
/// lazy old range. Base-page shared mappings additionally support DONTUNMAP
/// and the historical zero-old-length duplication form, with file and SysV
/// owner metadata published in the same transaction as the destination VMA.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn mremap_core(
    as_ref: &AddressSpace,
    old_addr: u64,
    old_len_requested: u64,
    new_len_requested: u64,
    flags: u32,
    new_addr: u64,
) -> Result<u64, i64> {
    mremap_core_limited(
        as_ref,
        old_addr,
        old_len_requested,
        new_len_requested,
        flags,
        new_addr,
        narf_memory::MremapLimits::UNLIMITED,
    )
}

#[allow(clippy::too_many_arguments)]
fn mremap_core_limited(
    as_ref: &AddressSpace,
    old_addr: u64,
    old_len_requested: u64,
    new_len_requested: u64,
    flags: u32,
    new_addr: u64,
    limits: narf_memory::MremapLimits,
) -> Result<u64, i64> {
    // Match Linux check_mremap_params() ordering before looking up the VMA.
    // In particular, a request with both a bad target and an unmapped source
    // is EINVAL, not EFAULT. PAGE_ALIGN overflow wraps to zero in Linux and is
    // subsequently rejected as an invalid new length, so checked overflow is
    // also EINVAL here rather than ENOMEM.
    if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 {
        return Err(EINVAL);
    }
    if old_addr & 0xFFF != 0 {
        return Err(EINVAL);
    }
    let old_len = round_len(old_len_requested)?;
    let new_len = round_len(new_len_requested)?;
    if new_len == 0 || new_len > AddressSpace::USER_HALF_END {
        return Err(EINVAL);
    }
    if flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 {
        let new_end = new_addr.checked_add(new_len).ok_or(EINVAL)?;
        if new_addr & 0xFFF != 0
            || new_end > AddressSpace::USER_HALF_END
            || flags & MREMAP_MAYMOVE == 0
            || flags & MREMAP_DONTUNMAP != 0 && old_len != new_len
        {
            return Err(EINVAL);
        }
        let old_end = old_addr.checked_add(old_len).ok_or(EINVAL)?;
        if old_addr < new_end && new_addr < old_end {
            return Err(EINVAL);
        }
    }
    if flags & MREMAP_FIXED != 0 {
        // SysV uses its own per-AS owner table. Only a fixed move can retire a
        // SysV target, so keep its global registry entirely off the common
        // no-op/shrink/grow path.
        #[cfg(feature = "linux-compat")]
        let task = current_task_id();
        #[cfg(feature = "linux-compat")]
        let lpid = task_to_pid_raw(task).unwrap_or(task);
        #[cfg(feature = "linux-compat")]
        let as_key = shm_as_key_ref(as_ref);
        #[cfg(feature = "linux-compat")]
        shm_register_as_owner(as_key, lpid);
        #[cfg(feature = "linux-compat")]
        let shm_transaction = shm_mapping_transaction(as_key);
        #[cfg(feature = "linux-compat")]
        let _shm_guard = shm_transaction.lock();

        // SAFETY: mremap_core holds an Arc-owned live address space; both
        // disjoint ranges were page/bounds validated above. Locked growth
        // admission, target replacement, and relocation share one VMA
        // transaction, so EAGAIN leaves the target untouched.
        let moved = as_ref.with_vma_transaction(|| {
            // Keep source lookup and every mutation under one Linux-style
            // mmap-write transaction. A CLONE_VM peer cannot replace the VMA
            // between validation and the fixed punch.
            let old_end = old_addr.checked_add(old_len).ok_or(EFAULT)?;
            // SAFETY: the enclosing closure holds the VMA transaction. Shared
            // aliases may cover a subrange; private relocation retains the
            // existing exact-VMA restriction. A zero old length identifies
            // the containing shared VMA for Linux's legacy duplication mode.
            let covering_perms = unsafe {
                as_ref.region_perms_covering_locked(VirtAddr::new(old_addr), old_len)
            }
            .ok_or(EFAULT)?;
            let source_perms = if old_len == 0
                || covering_perms.contains(RegionPerms::SHARED)
            {
                covering_perms
            } else {
                // SAFETY: the enclosing closure holds the VMA transaction.
                unsafe {
                    as_ref.exact_region_perms_locked(VirtAddr::new(old_addr), old_len)
                }
                .ok_or(EFAULT)?
            };
            if old_end > AddressSpace::USER_HALF_END {
                return Err(EFAULT);
            }
            let source_shared = source_perms.contains(RegionPerms::SHARED);
            if old_len == 0 && !source_shared {
                return Err(EINVAL);
            }
            if source_perms.contains(RegionPerms::LOCK_EXEMPT) && !source_shared {
                return Err(if flags & MREMAP_DONTUNMAP != 0 {
                    EINVAL
                } else {
                    EFAULT
                });
            }
            if source_perms.contains(RegionPerms::STACK_SEGMENT) {
                return Err(EFAULT);
            }
            if new_addr < AddressSpace::USER_FIXED_FLOOR {
                return Err(EPERM);
            }
            if source_shared {
                let mode = if old_len == 0 {
                    narf_memory::SharedMremapMode::Duplicate
                } else if flags & MREMAP_DONTUNMAP != 0 {
                    narf_memory::SharedMremapMode::DontUnmap
                } else {
                    // Ordinary shared relocation/resize is a move, not an
                    // alias. It is handled by the remaining mremap work rather
                    // than silently retaining the source here.
                    return Err(EFAULT);
                };
                let alias_len = if old_len == 0 { new_len } else { old_len };
                let result = narf_memory::with_shared_mapping_transaction(|| {
                    // SAFETY: SysV -> VMA -> shared-owner lock order is held;
                    // the helper adds file-owner preparation before memory.
                    unsafe {
                        publish_shared_mremap_alias_locked(
                            as_ref,
                            old_addr,
                            alias_len,
                            new_addr,
                            mode,
                            true,
                            limits,
                        )
                    }
                });
                return result.map_err(|failure| mremap_memory_errno(failure.error));
            }
            // SAFETY: the VMA transaction keeps target classification stable
            // through the relocation.
            let shared = unsafe {
                as_ref.fixed_relocation_needs_shared_transaction_locked(
                    VirtAddr::new(new_addr),
                    new_len,
                )
            }
            .map_err(|_| EINVAL)?;
            let relocate = || {
                crate::mapped_file::publish_current_fixed_remap(new_addr, new_len, || {
                    // SAFETY: VMA -> shared-owner -> file-owner transactions
                    // are held; the address space and its root remain live.
                    if flags & MREMAP_DONTUNMAP != 0 {
                        // SAFETY: the same VMA/shared-owner/root contract as
                        // the ordinary fixed relocation is held.
                        unsafe {
                            as_ref.dontunmap_region_fixed_locked_limited(
                                VirtAddr::new(old_addr),
                                old_len,
                                VirtAddr::new(new_addr),
                                limits,
                                shared,
                            )
                        }
                        .map(|()| None)
                    } else {
                        // SAFETY: VMA -> shared-owner -> file-owner
                        // transactions are held; the root remains live.
                        unsafe {
                            as_ref.relocate_region_fixed_locked_limited(
                                VirtAddr::new(old_addr),
                                old_len,
                                VirtAddr::new(new_addr),
                                new_len,
                                limits,
                                shared,
                            )
                        }
                    }
                })
            };
            let result = if shared {
                narf_memory::with_shared_mapping_transaction(relocate)
            } else {
                relocate()
            };
            result
            .map_err(|failure| {
                #[cfg(feature = "linux-compat")]
                if failure.target_punched {
                    shm_record_fixed_punch(as_key, new_addr, new_addr + new_len, lpid);
                }
                mremap_memory_errno(failure.error)
            })
        });
        match moved {
            Ok(eager_range) => {
                #[cfg(feature = "linux-compat")]
                shm_record_fixed_punch(as_key, new_addr, new_addr + new_len, lpid);
                as_ref.finish_relocation_population(eager_range);
            }
            Err(errno) => return Err(errno),
        }
        return Ok(new_addr);
    }

    // Shared aliases must prepare SysV attachment accounting outside the VMA
    // transaction to preserve the global SysV -> VMA -> shared-owner order.
    // Taking this per-AS transaction for the private path is harmless and
    // avoids a classification race before the VMA lock is held.
    #[cfg(feature = "linux-compat")]
    let task = current_task_id();
    #[cfg(feature = "linux-compat")]
    let lpid = task_to_pid_raw(task).unwrap_or(task);
    #[cfg(feature = "linux-compat")]
    let as_key = shm_as_key_ref(as_ref);
    #[cfg(feature = "linux-compat")]
    shm_register_as_owner(as_key, lpid);
    #[cfg(feature = "linux-compat")]
    let shm_transaction = shm_mapping_transaction(as_key);
    #[cfg(feature = "linux-compat")]
    let _shm_guard = shm_transaction.lock();

    let moved = as_ref.with_vma_transaction(|| {
        // NARF's region table is the VMA authority. This exact-region
        // restriction is temporary; keeping it under the transaction at least
        // makes every accepted operation atomic with CLONE_VM peers.
        let old_end = old_addr.checked_add(old_len).ok_or(EFAULT)?;
        // SAFETY: the enclosing closure holds the VMA transaction. Shared
        // aliases may cover a subrange and old_len==0 identifies the VMA at
        // old_addr; private moves remain exact-VMA operations for now.
        let covering_perms = unsafe {
            as_ref.region_perms_covering_locked(VirtAddr::new(old_addr), old_len)
        }
        .ok_or(EFAULT)?;
        if old_end > AddressSpace::USER_HALF_END {
            return Err(EFAULT);
        }
        let source_shared = covering_perms.contains(RegionPerms::SHARED);
        if old_len == 0 && !source_shared {
            return Err(EINVAL);
        }
        let source_perms = if old_len == 0 || source_shared {
            covering_perms
        } else {
            // SAFETY: the enclosing closure holds the VMA transaction.
            unsafe { as_ref.exact_region_perms_locked(VirtAddr::new(old_addr), old_len) }
                .ok_or(EFAULT)?
        };
        if source_perms.contains(RegionPerms::LOCK_EXEMPT) && !source_shared {
            return Err(if flags & MREMAP_DONTUNMAP != 0 {
                EINVAL
            } else {
                EFAULT
            });
        }
        if source_perms.contains(RegionPerms::STACK_SEGMENT) {
            return Err(EFAULT);
        }
        if source_shared {
            if old_len != 0 && flags & MREMAP_DONTUNMAP == 0 {
                if new_len == old_len {
                    return Ok((old_addr, None));
                }
                // Shared grow/shrink/move needs backing-owner relocation, not
                // alias publication. Keep it rejected until that path lands.
                return Err(EFAULT);
            }
            if old_len == 0 && flags & MREMAP_MAYMOVE == 0 {
                return Err(ENOMEM);
            }
            let mode = if old_len == 0 {
                narf_memory::SharedMremapMode::Duplicate
            } else {
                narf_memory::SharedMremapMode::DontUnmap
            };
            let alias_len = if old_len == 0 { new_len } else { old_len };
            let preferred = if mode == narf_memory::SharedMremapMode::DontUnmap
                && new_addr >= AddressSpace::USER_FIXED_FLOOR
            {
                Some(new_addr)
            } else {
                None
            };
            let result = narf_memory::with_shared_mapping_transaction(|| {
                if let Some(destination) = preferred {
                    // SAFETY: SysV/VMA/shared transactions and the live root
                    // are held continuously through prepared metadata commit.
                    let attempted = unsafe {
                        publish_shared_mremap_alias_locked(
                            as_ref,
                            old_addr,
                            alias_len,
                            destination,
                            mode,
                            false,
                            limits,
                        )
                    };
                    match attempted {
                        Ok(eager) => return Ok((destination, eager)),
                        Err(failure)
                            if !failure.target_punched
                                && failure.error
                                    == narf_memory::AddressSpaceError::Overlap => {}
                        Err(failure) => return Err(failure),
                    }
                }
                // SAFETY: the VMA transaction makes this candidate stable and
                // successful alias publication advances the cursor itself.
                let destination = unsafe { as_ref.mmap_cursor_candidate_locked(alias_len) }
                    .map_err(|error| narf_memory::FixedRelocationError {
                        error,
                        target_punched: false,
                    })?
                    .as_u64();
                // SAFETY: same transaction/live-root contract as above.
                let eager = unsafe {
                    publish_shared_mremap_alias_locked(
                        as_ref,
                        old_addr,
                        alias_len,
                        destination,
                        mode,
                        false,
                        limits,
                    )
                }?;
                Ok((destination, eager))
            });
            return result.map_err(|failure| mremap_memory_errno(failure.error));
        }
        if flags & MREMAP_DONTUNMAP != 0 {
            let hint = if new_addr < AddressSpace::USER_FIXED_FLOOR {
                None
            } else {
                Some(VirtAddr::new(new_addr))
            };
            // SAFETY: the VMA transaction and live address space remain held;
            // the memory operation validates source/destination topology and
            // advances the mmap cursor only after successful publication.
            let destination = unsafe {
                as_ref.dontunmap_region_hint_locked_limited(
                    VirtAddr::new(old_addr),
                    old_len,
                    hint,
                    limits,
                )
            }
            .map_err(|error| match error {
                narf_memory::AddressSpaceError::MappingLimit
                | narf_memory::AddressSpaceError::AllocationFailed
                | narf_memory::AddressSpaceError::OutOfRange
                | narf_memory::AddressSpaceError::Overlap => ENOMEM,
                narf_memory::AddressSpaceError::Unmapped => EFAULT,
                _ => EINVAL,
            })?
            .as_u64();
            return Ok((destination, None));
        }
        if new_len == old_len {
            return Ok((old_addr, None));
        }
        if new_len < old_len {
            let tail = old_addr + new_len;
            crate::mapped_file::publish_current_punch(tail, old_len - new_len, || {
                // SAFETY: the enclosing closure holds the VMA transaction.
                unsafe {
                    as_ref.punch_fixed_locked_for_syscall(
                        VirtAddr::new(tail),
                        old_len - new_len,
                    )
                }
            })
            .map_err(|_| EFAULT)?;
            return Ok((old_addr, None));
        }
        // SAFETY: the VMA transaction is held and `old_len` was validated
        // against the exact source mapping above.
        match unsafe {
            as_ref.grow_region_locked_limited(
                VirtAddr::new(old_addr),
                old_len,
                new_len,
                limits,
            )
        } {
            Ok(eager_range) => return Ok((old_addr, eager_range)),
            Err(narf_memory::AddressSpaceError::LockLimit) => return Err(EAGAIN),
            Err(narf_memory::AddressSpaceError::MappingLimit)
            | Err(narf_memory::AddressSpaceError::AllocationFailed) => return Err(ENOMEM),
            Err(narf_memory::AddressSpaceError::Overlap)
            | Err(narf_memory::AddressSpaceError::OutOfRange) => {}
            Err(_) => return Err(ENOMEM),
        }
        if flags & MREMAP_MAYMOVE == 0 {
            return Err(ENOMEM);
        }

        let destination = as_ref.reserve_mmap_va(new_len);
        if destination == 0 {
            return Err(ENOMEM);
        }
        // SAFETY: reserve_mmap_va returned a disjoint page-aligned user range;
        // source validation and relocation share the VMA transaction.
        let eager_range = unsafe {
            as_ref.relocate_region_locked_limited(
                VirtAddr::new(old_addr),
                old_len,
                VirtAddr::new(destination),
                new_len,
                limits,
            )
        }
        .map_err(|error| match error {
            narf_memory::AddressSpaceError::LockLimit => EAGAIN,
            _ => ENOMEM,
        })?;
        Ok((destination, eager_range))
    })?;
    as_ref.finish_relocation_population(moved.1);
    Ok(moved.0)
}

/// `mremap(old_addr, old_len, new_len, flags, new_addr)` — resize or move a
/// complete private mapping while preserving its resident backing.
pub(crate) fn sys_mremap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let task = current_task_id();
    let authority = current_mlock_authority();
    let defaults = default_rlimits();
    let data_limit = read_rlimit(task, RLIMIT_DATA).unwrap_or(defaults[RLIMIT_DATA]);
    let limits = narf_memory::MremapLimits {
        memlock_bytes: authority.limit_bytes,
        address_space_bytes: read_rlimit(task, RLIMIT_AS)
            .unwrap_or(defaults[RLIMIT_AS])
            .cur,
        data_bytes: data_limit.cur,
        data_max_bytes: data_limit.max,
        bypass_memlock: authority.bypass_limit,
    };
    match mremap_core_limited(
        &as_ref,
        args.arg0,
        args.arg1,
        args.arg2,
        args.arg3 as u32,
        args.arg4,
        limits,
    ) {
        Ok(address) => ctx.set_return(SyscallReturn::ok(address)),
        Err(errno) => ctx.set_return(SyscallReturn::ok((-errno) as u64)),
    }
}

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn lazy_region(base: u64, pages: u64) -> Region {
        Region {
            base: VirtAddr::new(base),
            len: pages * 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: (0..pages)
                .map(|index| PhysAddr::new(0x0200_0000 + index * 4096))
                .collect(),
        }
    }

    fn smoke_mremap_shrink_really_unmaps_tail() -> TestResult {
        const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        let aspace = AddressSpace::empty();
        if aspace.map_region(lazy_region(BASE, 4)).is_err() {
            return TestResult::Fail("initial region failed");
        }
        if mremap_core(&aspace, BASE, 4 * 4096, 2 * 4096, 0, 0) != Ok(BASE) {
            return TestResult::Fail("shrink failed");
        }
        let Some(region) = aspace.lookup(VirtAddr::new(BASE)) else {
            return TestResult::Fail("shrunk region disappeared");
        };
        if region.len != 2 * 4096
            || region.phys.len() != 2
            || aspace.lookup(VirtAddr::new(BASE + 2 * 4096)).is_some()
        {
            return TestResult::Fail("shrink reported success without removing its tail");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_mremap_shrink_really_unmaps_tail);

    fn smoke_mremap_maymove_preserves_backing_and_grows_lazily() -> TestResult {
        const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        let aspace = AddressSpace::empty();
        let source = lazy_region(BASE, 2);
        let expected = source.phys.clone();
        if aspace.map_region(source).is_err()
            || aspace.map_region(lazy_region(BASE + 2 * 4096, 2)).is_err()
        {
            return TestResult::Fail("could not create grow collision");
        }
        if mremap_core(&aspace, BASE, 2 * 4096, 4 * 4096, 0, 0) != Err(ENOMEM) {
            return TestResult::Fail("colliding grow without MAYMOVE did not fail");
        }
        let moved = match mremap_core(&aspace, BASE, 2 * 4096, 4 * 4096, MREMAP_MAYMOVE, 0) {
            Ok(address) if address != BASE => address,
            _ => return TestResult::Fail("MAYMOVE did not relocate"),
        };
        let Some(region) = aspace.lookup(VirtAddr::new(moved)) else {
            return TestResult::Fail("moved region missing");
        };
        if aspace.lookup(VirtAddr::new(BASE)).is_some()
            || region.len != 4 * 4096
            || region.phys[..2] != expected
            || region.phys[2..].iter().any(|phys| phys.raw() != 0)
        {
            return TestResult::Fail("MAYMOVE lost backing or did not create a lazy tail");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_maymove_preserves_backing_and_grows_lazily
    );

    fn smoke_mremap_maymove_at_user_ceiling_relocates() -> TestResult {
        let source = AddressSpace::USER_HALF_END - 0x1000;
        let aspace = AddressSpace::empty();
        if aspace.map_region(lazy_region(source, 1)).is_err() {
            return TestResult::Fail("user-ceiling source setup failed");
        }
        let moved = match mremap_core(&aspace, source, 0x1000, 0x2000, MREMAP_MAYMOVE, 0) {
            Ok(address) if address != source => address,
            _ => return TestResult::Fail("MAYMOVE did not escape the user ceiling"),
        };
        if aspace.lookup(VirtAddr::new(source)).is_none()
            && aspace
                .lookup(VirtAddr::new(moved))
                .is_some_and(|region| region.len == 0x2000)
        {
            TestResult::Pass
        } else {
            TestResult::Fail("user-ceiling relocation published the wrong VMA state")
        }
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_maymove_at_user_ceiling_relocates
    );

    fn smoke_mremap_stack_rejection_preserves_guard() -> TestResult {
        const GUARD: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x40_0000;
        const STACK: u64 = GUARD + 0x1000;
        let aspace = AddressSpace::empty();
        if aspace
            .map_region(Region {
                base: VirtAddr::new(GUARD),
                len: 0x1000,
                perms: RegionPerms::STACK_GUARD | RegionPerms::LOCK_EXEMPT,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
            || aspace
                .map_region(Region {
                    base: VirtAddr::new(STACK),
                    len: 0x1000,
                    perms: RegionPerms::READ
                        | RegionPerms::WRITE
                        | RegionPerms::STACK_SEGMENT,
                    phys: alloc::vec![PhysAddr::new(0)],
                })
                .is_err()
        {
            return TestResult::Fail("stack mremap setup failed");
        }
        if mremap_core(&aspace, STACK, 0x1000, 0x2000, MREMAP_MAYMOVE, 0) == Err(EFAULT)
            && aspace.lookup(VirtAddr::new(GUARD)).is_some_and(|region| {
                region.perms.contains(RegionPerms::STACK_GUARD)
            })
            && aspace.lookup(VirtAddr::new(STACK)).is_some_and(|region| {
                region.len == 0x1000 && region.perms.contains(RegionPerms::STACK_SEGMENT)
            })
        {
            TestResult::Pass
        } else {
            TestResult::Fail("unsupported stack remap changed the stack/guard pair")
        }
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_stack_rejection_preserves_guard
    );

    fn smoke_mremap_dontunmap_moves_backing_and_lazies_source() -> TestResult {
        const SOURCE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        const HINT: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x30_0000;
        let aspace = AddressSpace::empty();
        let mut source = lazy_region(SOURCE, 2);
        source.perms = source.perms | RegionPerms::LOCKED;
        let expected = source.phys.clone();
        if aspace.map_region(source).is_err() {
            return TestResult::Fail("DONTUNMAP source setup failed");
        }
        let result = mremap_core(
            &aspace,
            SOURCE,
            0x2000,
            0x2000,
            MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
            HINT,
        );
        let source_ok = aspace.lookup(VirtAddr::new(SOURCE)).is_some_and(|region| {
            region.len == 0x2000
                && !region.perms.contains(RegionPerms::LOCKED)
                && region.phys.iter().all(|phys| phys.raw() == 0)
        });
        let target_ok = aspace.lookup(VirtAddr::new(HINT)).is_some_and(|region| {
            region.len == 0x2000
                && region.perms.contains(RegionPerms::LOCKED)
                && region.phys == expected
        });
        if result == Ok(HINT) && source_ok && target_ok {
            TestResult::Pass
        } else {
            TestResult::Fail("DONTUNMAP aliased backing or lost source/destination state")
        }
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_dontunmap_moves_backing_and_lazies_source
    );

    fn smoke_mremap_shared_dontunmap_preserves_backing_alias() -> TestResult {
        const SOURCE: u64 = AddressSpace::USER_FIXED_FLOOR;
        const HINT: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x50_0000;
        let aspace = AddressSpace::empty();
        let mut source = lazy_region(SOURCE, 2);
        source.perms = source.perms | RegionPerms::SHARED | RegionPerms::LOCKED;
        let expected = source.phys.clone();
        if aspace.map_region(source).is_err() {
            return TestResult::Fail("shared DONTUNMAP source setup failed");
        }
        let result = mremap_core(
            &aspace,
            SOURCE,
            0x2000,
            0x2000,
            MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
            HINT,
        );
        let source_ok = aspace.lookup(VirtAddr::new(SOURCE)).is_some_and(|region| {
            region.phys == expected && !region.perms.contains(RegionPerms::LOCKED)
        });
        let target_ok = aspace.lookup(VirtAddr::new(HINT)).is_some_and(|region| {
            region.phys == expected
                && region.perms.contains(RegionPerms::SHARED)
                && region.perms.contains(RegionPerms::LOCKED)
        });
        if result == Ok(HINT) && source_ok && target_ok {
            TestResult::Pass
        } else {
            TestResult::Fail("shared DONTUNMAP lost backing or lock-state semantics")
        }
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_shared_dontunmap_preserves_backing_alias
    );

    fn smoke_mremap_zero_old_len_duplicates_shared_only() -> TestResult {
        const SOURCE: u64 = AddressSpace::USER_FIXED_FLOOR;
        let aspace = AddressSpace::empty();
        let mut source = lazy_region(SOURCE, 2);
        source.perms = source.perms | RegionPerms::SHARED;
        let expected = source.phys[1];
        if aspace.map_region(source).is_err() {
            return TestResult::Fail("zero-old-len source setup failed");
        }
        if mremap_core(&aspace, SOURCE + 0x1000, 0, 0x1000, 0, 0) != Err(ENOMEM) {
            return TestResult::Fail("zero-old-len duplication omitted MAYMOVE");
        }
        let destination = match mremap_core(
            &aspace,
            SOURCE + 0x1000,
            0,
            0x1000,
            MREMAP_MAYMOVE,
            0,
        ) {
            Ok(destination) => destination,
            Err(_) => return TestResult::Fail("shared zero-old-len duplication failed"),
        };
        if aspace
            .lookup(VirtAddr::new(destination))
            .is_some_and(|region| {
                region.len == 0x1000
                    && region.perms.contains(RegionPerms::SHARED)
                    && region.phys == alloc::vec![expected]
            })
            && aspace
                .lookup(VirtAddr::new(SOURCE + 0x1000))
                .is_some_and(|region| region.phys[1] == expected)
        {
            TestResult::Pass
        } else {
            TestResult::Fail("zero-old-len duplication changed its shared source/backing")
        }
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_zero_old_len_duplicates_shared_only
    );

    fn smoke_mremap_dontunmap_failure_does_not_consume_mmap_cursor() -> TestResult {
        const SOURCE: u64 = AddressSpace::USER_FIXED_FLOOR;
        let aspace = AddressSpace::empty();
        if aspace.map_region(lazy_region(SOURCE, 1)).is_err() {
            return TestResult::Fail("DONTUNMAP cursor setup failed");
        }
        let constrained = narf_memory::MremapLimits {
            memlock_bytes: u64::MAX,
            address_space_bytes: 0x1000,
            data_bytes: u64::MAX,
            data_max_bytes: u64::MAX,
            bypass_memlock: true,
        };
        if mremap_core_limited(
            &aspace,
            SOURCE,
            0x1000,
            0x1000,
            MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
            0,
            constrained,
        ) != Err(ENOMEM)
        {
            return TestResult::Fail("DONTUNMAP ignored its AS limit");
        }
        let retry = mremap_core(
            &aspace,
            SOURCE,
            0x1000,
            0x1000,
            MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
            0,
        );
        if retry == Ok(AddressSpace::MMAP_CURSOR_BASE) {
            TestResult::Pass
        } else {
            TestResult::Fail("failed DONTUNMAP consumed mmap cursor space")
        }
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_dontunmap_failure_does_not_consume_mmap_cursor
    );

    fn smoke_mremap_dontunmap_special_mapping_is_einval() -> TestResult {
        const SOURCE: u64 = AddressSpace::USER_FIXED_FLOOR;
        let aspace = AddressSpace::empty();
        let mut source = lazy_region(SOURCE, 1);
        source.perms = source.perms | RegionPerms::LOCK_EXEMPT;
        if aspace.map_region(source).is_err() {
            return TestResult::Fail("special DONTUNMAP setup failed");
        }
        if mremap_core(
            &aspace,
            SOURCE,
            0x1000,
            0x1000,
            MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
            0,
        ) == Err(EINVAL)
        {
            TestResult::Pass
        } else {
            TestResult::Fail("special DONTUNMAP did not return EINVAL")
        }
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_dontunmap_special_mapping_is_einval
    );

    fn smoke_mremap_fixed_dontunmap_replaces_only_target() -> TestResult {
        const SOURCE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        const TARGET: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x34_0000;
        let aspace = AddressSpace::empty();
        let source = lazy_region(SOURCE, 1);
        let expected = source.phys.clone();
        if aspace.map_region(source).is_err()
            || aspace.map_region(lazy_region(TARGET, 2)).is_err()
        {
            return TestResult::Fail("fixed DONTUNMAP setup failed");
        }
        let result = mremap_core(
            &aspace,
            SOURCE,
            0x1000,
            0x1000,
            MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
            TARGET,
        );
        let source_ok = aspace.lookup(VirtAddr::new(SOURCE)).is_some_and(|region| {
            region.len == 0x1000 && region.phys[0].raw() == 0
        });
        let target_ok = aspace
            .lookup(VirtAddr::new(TARGET))
            .is_some_and(|region| region.len == 0x1000 && region.phys == expected);
        if result == Ok(TARGET)
            && source_ok
            && target_ok
            && aspace
                .lookup(VirtAddr::new(TARGET + 0x1000))
                .is_some_and(|region| region.len == 0x1000)
        {
            TestResult::Pass
        } else {
            TestResult::Fail("fixed DONTUNMAP did not preserve source and replace target")
        }
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_fixed_dontunmap_replaces_only_target
    );

    fn smoke_mremap_fixed_replaces_target() -> TestResult {
        const SOURCE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        const TARGET: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x20_0000;
        let aspace = AddressSpace::empty();
        let source = lazy_region(SOURCE, 2);
        let expected = source.phys.clone();
        if aspace.map_region(source).is_err() || aspace.map_region(lazy_region(TARGET, 3)).is_err()
        {
            return TestResult::Fail("could not register source and target");
        }
        let result = mremap_core(
            &aspace,
            SOURCE,
            2 * 4096,
            3 * 4096,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            TARGET,
        );
        let Some(region) = aspace.lookup(VirtAddr::new(TARGET)) else {
            return TestResult::Fail("fixed target missing");
        };
        if result != Ok(TARGET)
            || aspace.lookup(VirtAddr::new(SOURCE)).is_some()
            || region.len != 3 * 4096
            || region.phys[..2] != expected
            || region.phys[2].raw() != 0
        {
            return TestResult::Fail("MREMAP_FIXED did not replace target correctly");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_mremap_fixed_replaces_target);

    fn smoke_mremap_rejects_unsafe_flag_shapes() -> TestResult {
        const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        let aspace = AddressSpace::empty();
        if aspace.map_region(lazy_region(BASE, 2)).is_err() {
            return TestResult::Fail("initial region failed");
        }
        if mremap_core(&aspace, BASE, 8192, 8192, MREMAP_FIXED, BASE + 0x20_0000) != Err(EINVAL)
            || mremap_core(&aspace, BASE, 0, 8192, MREMAP_MAYMOVE, 0) != Err(EINVAL)
            || mremap_core(
                &aspace,
                BASE,
                8192,
                8192,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                BASE + 4096,
            ) != Err(EINVAL)
        {
            return TestResult::Fail("unsafe mremap flag/address shape was accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_mremap_rejects_unsafe_flag_shapes);
}
