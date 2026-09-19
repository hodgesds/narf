//! Linux syscall ABI conformance — mem group.
use alloc::sync::Arc;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, RegionPerms, VirtAddr};

use crate::abi_test_support::*;

static MEM_TEST_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_mem_test_as() -> Option<Arc<AddressSpace>> {
    MEM_TEST_AS.lock().clone()
}

fn with_mem_test_as(
    body: impl FnOnce(&Arc<AddressSpace>) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    // SAFETY: kernel tests run after paging is enabled, and MEM_TEST_AS owns
    // the page-table root for the complete syscall sequence.
    let as_ref = match unsafe { AddressSpace::new_for_user() } {
        Ok(as_ref) => Arc::new(as_ref),
        Err(_) => return Err("failed to create memory-test address space"),
    };
    *MEM_TEST_AS.lock() = Some(Arc::clone(&as_ref));
    crate::handlers::install_address_space_lookup(lookup_mem_test_as);
    let result = body(&as_ref);
    crate::handlers::restore_address_space_lookup(None);
    *MEM_TEST_AS.lock() = None;
    result
}

// ════════════════════════════════════════════════════════════════════
// Harness note on address-space–backed mem syscalls.
//
// The ABI harness installs a fake task + fd table but NO per-task
// AddressSpace (it never registers an AS lookup). Every handler that
// opens with `current_address_space()` therefore takes its `None` arm,
// which for the VM-region syscalls (mmap/munmap/mremap/mprotect/mlock/
// munlock/mlockall/munlockall/madvise/mincore/mlock2/pkey_mprotect/
// process_madvise) is `SyscallReturn::invalid_op()` — surfaced by the
// harness as `call(..) == None`. The success path of those needs a live
// AS (real user mapping) we can't build here, so those get a reachable
// negative/stub pin plus, where an EARLIER validation arm fires before
// the AS check (bad flags / unaligned addr), a positive-ish error pin
// asserting that exact pre-AS errno. Handlers that don't touch the AS
// (memfd_create, memfd_secret, brk-without-AS, the mempolicy side
// tables, move_pages, migrate_pages, set_mempolicy_home_node, pkey
// alloc/free) have fully reachable success paths and get real positives.
// ════════════════════════════════════════════════════════════════════

// ── Brk (12) ─────────────────────────────────────────────────────────
// The break lives on the AddressSpace (`AddressSpace::brk_top`), seeded to the
// arena base on first use. Every path here returns a NARF-Ok status with a
// non-negative value (current break or 0); we pin the status + sign rather than
// an exact address (the break depends on the test's AS state).

fn smoke_abi_mem_brk_query_pos() -> TestResult {
    with_setup(|| {
        // arg0 == 0 is the "report current break" query.
        let r = call_raw(Syscall::Brk.raw(), a0(0));
        if r.status != SyscallReturn::OK {
            return Err("brk query should report NARF Ok");
        }
        if (r.value as i64) < 0 {
            return Err("brk query should return a non-negative break");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_brk_query_pos);

fn smoke_abi_mem_brk_shrink_neg() -> TestResult {
    with_setup(|| {
        // A shrink to a tiny break never errors in NARF brk(2): it records
        // the value and returns it (or 0 when the table is uninitialised).
        // Either way the status is Ok — brk has no -errno return shape.
        // NOT a divergence in the errno: Linux's brk never fails the value
        // either. What differs is the harness, which has no live heap to
        // clamp against, so the value is the requested break or 0.
        let r = call_raw(Syscall::Brk.raw(), a0(0x1000));
        if r.status != SyscallReturn::OK {
            return Err("brk shrink should report NARF Ok");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_brk_shrink_neg);

// ── MemfdCreate (319) ────────────────────────────────────────────────
// NARF shape: (name_ptr, name_len, flags). Returns a fresh fd (>=0) on
// success, ok(-1) sentinel only if the fd table is exhausted.

fn smoke_abi_mem_memfd_create_pos() -> TestResult {
    with_setup(|| {
        // Linux memfd_create(2): (name_ptr, flags). flags=0.
        let name = b"abi-memfd\0";
        let args = a3(name.as_ptr() as u64, 0, 0, 0);
        match call(Syscall::MemfdCreate.raw(), args) {
            Some(fd) if fd >= 0 => Ok(()),
            Some(_) => Err("memfd_create should return a non-negative fd"),
            None => Err("memfd_create returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_memfd_create_pos);

fn smoke_abi_mem_memfd_create_cloexec_pos() -> TestResult {
    with_setup(|| {
        // MFD_CLOEXEC (bit 0) is honoured; still yields a valid fd.
        // Linux memfd_create(2): (name_ptr, flags). flags=MFD_CLOEXEC=1.
        let name = b"abi-memfd-cx\0";
        let args = a3(name.as_ptr() as u64, 1, 0, 0);
        match call(Syscall::MemfdCreate.raw(), args) {
            Some(fd) if fd >= 0 => Ok(()),
            Some(_) => Err("memfd_create(CLOEXEC) should return a valid fd"),
            None => Err("memfd_create(CLOEXEC) returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_memfd_create_cloexec_pos);

// ── MemfdSecret (447) ────────────────────────────────────────────────
// flags in arg0; FD_CLOEXEC honoured. Returns fd (>=0) on success.

fn smoke_abi_mem_memfd_secret_pos() -> TestResult {
    with_setup(|| match call(Syscall::MemfdSecret.raw(), a0(0)) {
        Some(fd) if fd >= 0 => Ok(()),
        Some(_) => Err("memfd_secret should return a non-negative fd"),
        None => Err("memfd_secret returned non-Ok status"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_memfd_secret_pos);

fn smoke_abi_mem_memfd_secret_cloexec_pos() -> TestResult {
    with_setup(|| {
        // FD_CLOEXEC shares MFD_CLOEXEC's bit value (1).
        match call(Syscall::MemfdSecret.raw(), a0(1)) {
            Some(fd) if fd >= 0 => Ok(()),
            Some(_) => Err("memfd_secret(CLOEXEC) should return a valid fd"),
            None => Err("memfd_secret(CLOEXEC) returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_memfd_secret_cloexec_pos);

// ── Mmap (9) ─────────────────────────────────────────────────────────
// No AS in the harness → the shared `no_address_space()` answer, -ENOMEM. A
// MAP_FIXED with a misaligned hint hits its own pre-check… but that
// pre-check is AFTER the AS lookup, so it too lands here. Both pin the
// no-AS arm.
//
// The arm used to answer `invalid_op()`, whose `value` is 0 — the register
// the Linux ABI returns. For mmap that is not merely a wrong errno but a
// wrong ADDRESS: libc screens for MAP_FAILED, so a caller took 0 as a valid
// mapping and dereferenced it. -ENOMEM is what Linux returns when it cannot
// serve the range, and what the LINUX-GAP markers these cases used to carry
// already named as the right answer.

fn smoke_abi_mem_mmap_no_as_neg() -> TestResult {
    with_setup(|| {
        // 6-arg: hint=0, len=4096, prot=RW(3), flags=MAP_ANON|MAP_PRIVATE(0x22).
        let args = SyscallArgs {
            arg0: 0,
            arg1: 0x1000,
            arg2: 3,
            arg3: 0x22,
            arg4: (-1i64) as u64,
            arg5: 0,
        };
        // `Some(0)` is called out separately because for mmap a 0 is an
        // address, not just a wrong status.
        match call_raw(Syscall::Mmap.raw(), args).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("mmap reported success with no address space"),
            _ => Err("mmap with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mmap_no_as_neg);

fn smoke_abi_mem_map_locked_linux_errno_ordering() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|as_ref| {
            // RLIMIT_MEMLOCK == 0 makes mlock unavailable to an unprivileged
            // caller. Linux resolves a non-anonymous mapping's file descriptor
            // before do_mmap checks MAP_LOCKED authority, so an invalid fd wins.
            let zero_limit = [0u64, 0u64];
            if call(Syscall::Setrlimit.raw(), a1(8, zero_limit.as_ptr() as u64)) != Some(0) {
                return Err("failed to set zero RLIMIT_MEMLOCK");
            }
            let invalid_file = SyscallArgs {
                arg0: 0,
                arg1: 0x1000,
                arg2: 3,
                arg3: 0x02 | 0x2000, // MAP_PRIVATE | MAP_LOCKED
                arg4: 999,
                arg5: 0,
            };
            if call(Syscall::Mmap.raw(), invalid_file) != Some(EBADF) {
                return Err("invalid file-backed MAP_LOCKED must return EBADF before EPERM");
            }

            // With no fd lookup in the way, the same unprivileged caller gets
            // EPERM for an otherwise valid anonymous MAP_LOCKED request.
            let anonymous = SyscallArgs {
                arg3: 0x02 | 0x20 | 0x2000, // MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED
                arg4: (-1i64) as u64,
                ..invalid_file
            };
            if call(Syscall::Mmap.raw(), anonymous) != Some(EPERM) {
                return Err("anonymous MAP_LOCKED without authority must return EPERM");
            }
            if !as_ref.regions_snapshot().is_empty() {
                return Err("rejected MAP_LOCKED requests unexpectedly changed the address space");
            }
            Ok(())
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_map_locked_linux_errno_ordering);

fn smoke_abi_mem_future_locked_map_fixed_limit_preserves_old_mapping() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|as_ref| {
            const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x0200_0000;
            const MAP_PRIVATE: u64 = 0x02;
            const MAP_FIXED: u64 = 0x10;
            const MAP_ANONYMOUS: u64 = 0x20;

            let one_page_limit = [0x1000u64, 0x1000u64];
            if call(
                Syscall::Setrlimit.raw(),
                a1(8, one_page_limit.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("failed to set one-page RLIMIT_MEMLOCK");
            }

            let original = SyscallArgs {
                arg0: BASE,
                arg1: 0x1000,
                arg2: 3,
                arg3: MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                arg4: (-1i64) as u64,
                arg5: 0,
            };
            if call(Syscall::Mmap.raw(), original) != Some(BASE as i64) {
                return Err("failed to establish original MAP_FIXED mapping");
            }

            // MCL_FUTURE | MCL_ONFAULT: future VMAs count against the limit,
            // while the already-present mapping remains unlocked.
            if call(Syscall::Mlockall.raw(), a0(2 | 4)) != Some(0) {
                return Err("failed to install future on-fault lock policy");
            }

            let oversized_replacement = SyscallArgs {
                arg1: 0x2000,
                ..original
            };
            if call(Syscall::Mmap.raw(), oversized_replacement) != Some(EAGAIN) {
                return Err("future-locked MAP_FIXED over the limit must return EAGAIN");
            }

            let regions = as_ref.regions_snapshot();
            if regions.len() != 1 {
                return Err("failed MAP_FIXED changed the region count");
            }
            let old = &regions[0];
            if old.base.as_u64() != BASE || old.len != 0x1000 {
                return Err("failed MAP_FIXED did not preserve the old mapping extent");
            }
            if old.perms.contains(RegionPerms::LOCKED)
                || old.perms.contains(RegionPerms::LOCK_ONFAULT)
            {
                return Err("MCL_FUTURE retroactively changed the old mapping");
            }
            Ok(())
        })
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_future_locked_map_fixed_limit_preserves_old_mapping
);

// ── Munmap (11) ──────────────────────────────────────────────────────

fn smoke_abi_mem_munmap_no_as_neg() -> TestResult {
    with_setup(|| {
        // Linux munmap returns 0/-EINVAL; with no AS there is nothing to
        // unmap, and reporting 0 claimed the range had been torn down.
        match call_raw(Syscall::Munmap.raw(), a1(0x1000, 0x1000)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("munmap reported success with no address space"),
            _ => Err("munmap with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_munmap_no_as_neg);

// ── Mremap (25) ──────────────────────────────────────────────────────
// AS lookup happens FIRST, so no-AS → invalid_op() even for the EINVAL
// (unaligned addr / new_len==0) cases.

fn smoke_abi_mem_mremap_no_as_neg() -> TestResult {
    with_setup(|| {
        // old_addr=0x1000, old_len=0x1000, new_len=0x2000, flags=0.
        // Linux mremap returns the (possibly moved) address or
        // -ENOMEM/-EINVAL. As with mmap, a 0 here reads as an address.
        match call_raw(Syscall::Mremap.raw(), a3(0x1000, 0x1000, 0x2000, 0)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("mremap reported success with no address space"),
            _ => Err("mremap with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mremap_no_as_neg);

// ── MProtect (10) ────────────────────────────────────────────────────

fn smoke_abi_mem_mprotect_no_as_neg() -> TestResult {
    with_setup(|| {
        // base=0x1000, len=0x1000, prot=PROT_READ(1).
        // Linux mprotect returns 0/-EINVAL/-EACCES; -ENOMEM is its
        // documented answer for a range that is not mapped.
        match call_raw(Syscall::MProtect.raw(), a2(0x1000, 0x1000, 1)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("mprotect reported success with no address space"),
            _ => Err("mprotect with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mprotect_no_as_neg);

// ── MLock (149) ──────────────────────────────────────────────────────

fn smoke_abi_mem_mlock_no_as_neg() -> TestResult {
    with_setup(|| {
        // Linux mlock returns 0/-ENOMEM/-EPERM; -ENOMEM is documented as
        // "some of the specified address range does not correspond to
        // mapped pages".
        match call_raw(Syscall::MLock.raw(), a1(0x1000, 0x1000)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("mlock reported success with no address space"),
            _ => Err("mlock with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlock_no_as_neg);

fn smoke_abi_mem_mlock_permission_precedes_range_validation() -> TestResult {
    with_setup(|| {
        let zero_limit = [0u64, 0u64];
        if call(Syscall::Setrlimit.raw(), a1(8, zero_limit.as_ptr() as u64)) != Some(0) {
            return Err("failed to set zero RLIMIT_MEMLOCK");
        }
        // This range overflows the address space and would otherwise be
        // EINVAL. Linux checks mlock privilege first, so zero allowance wins.
        match call(Syscall::MLock.raw(), a1(u64::MAX - 0x7ff, 0x1000)) {
            Some(v) if v == EPERM => Ok(()),
            Some(_) => Err("mlock permission failure must precede invalid-range errno"),
            None => Err("mlock permission failure must be Ok(-EPERM)"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mlock_permission_precedes_range_validation
);

// ── MUnlock (150) ────────────────────────────────────────────────────

fn smoke_abi_mem_munlock_no_as_neg() -> TestResult {
    with_setup(|| {
        // Linux munlock returns 0/-ENOMEM; reporting 0 claimed pages had
        // been unlocked that were never locked.
        match call_raw(Syscall::MUnlock.raw(), a1(0x1000, 0x1000)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("munlock reported success with no address space"),
            _ => Err("munlock with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_munlock_no_as_neg);

// ── Mlock2 (325) ─────────────────────────────────────────────────────
// arg2 = flags. Bad flag bits are rejected with -EINVAL BEFORE the AS
// lookup → positive (reachable) errno pin. Valid flags hit the no-AS arm.

fn smoke_abi_mem_mlock2_bad_flags_pos() -> TestResult {
    with_setup(|| {
        // Only MLOCK_ONFAULT(1) is defined; any other bit → -EINVAL,
        // returned before the AS check, so this errno is reachable.
        match call(Syscall::Mlock2.raw(), a3(0x1000, 0x1000, 0x2, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(v) => {
                let _ = v;
                Err("mlock2 with bad flags should return -EINVAL")
            }
            None => Err("mlock2 bad-flags should be Ok(-EINVAL), not InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlock2_bad_flags_pos);

fn smoke_abi_mem_mlock2_no_as_neg() -> TestResult {
    with_setup(|| {
        // Valid flags (MLOCK_ONFAULT) pass the pre-check, then no AS →
        // -ENOMEM.
        match call_raw(Syscall::Mlock2.raw(), a3(0x1000, 0x1000, 1, 0)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("mlock2 (valid flags) reported success with no address space"),
            _ => Err("mlock2 (valid flags) with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlock2_no_as_neg);

// ── Mlockall (151) ───────────────────────────────────────────────────
// flags==0 or unknown bits → -EINVAL BEFORE the AS lookup (reachable).
// Valid flags hit the no-AS arm.

fn smoke_abi_mem_mlockall_bad_flags_pos() -> TestResult {
    with_setup(|| {
        // flags == 0 is invalid (must request CURRENT/FUTURE/ONFAULT).
        match call(Syscall::Mlockall.raw(), a0(0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("mlockall(0) should return -EINVAL"),
            None => Err("mlockall(0) should be Ok(-EINVAL), not InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlockall_bad_flags_pos);

fn smoke_abi_mem_mlockall_no_as_neg() -> TestResult {
    with_setup(|| {
        // MCL_CURRENT(1) is valid → passes the flag check, then no AS →
        // -ENOMEM.
        match call_raw(Syscall::Mlockall.raw(), a0(1)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("mlockall(MCL_CURRENT) reported success with no address space"),
            _ => Err("mlockall(MCL_CURRENT) with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlockall_no_as_neg);

// ── Munlockall (152) ─────────────────────────────────────────────────
// Pure AS walk; no AS → -ENOMEM. Reporting 0 claimed every lock in the
// process had been dropped.

fn smoke_abi_mem_munlockall_no_as_neg() -> TestResult {
    with_setup(|| {
        // Linux munlockall returns 0 when it does the work. Here it does
        // none, so 0 was a claim about locks that were never cleared.
        match call_raw(Syscall::Munlockall.raw(), a0(0)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("munlockall reported success with no address space"),
            _ => Err("munlockall with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_munlockall_no_as_neg);

// ── Madvise (28) ─────────────────────────────────────────────────────
// AS lookup first → no AS → -ENOMEM for every advice value.

fn smoke_abi_mem_madvise_no_as_neg() -> TestResult {
    with_setup(|| {
        // base=0x1000, len=0x1000, advice=MADV_NORMAL(0).
        // Linux madvise returns 0 for accepted hints and -ENOMEM when the
        // range is not mapped, which is the case here.
        match call_raw(Syscall::Madvise.raw(), a2(0x1000, 0x1000, 0)).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("madvise reported success with no address space"),
            _ => Err("madvise with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_madvise_no_as_neg);

// ── ProcessMadvise (440) ─────────────────────────────────────────────
// arg0=pidfd, arg2=iovcnt, arg3=advice. iovcnt > 1024 → -EINVAL (the very
// first check, reachable). A bogus pidfd → -EBADF (also reachable, no AS
// needed because the pidfd lookup fails first).

fn smoke_abi_mem_process_madvise_bad_iovcnt_pos() -> TestResult {
    with_setup(|| {
        // arg2 (iovcnt) = 2048 > 1024 → -EINVAL before anything else.
        let args = a3(0, 0, 2048, 4);
        match call(Syscall::ProcessMadvise.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("process_madvise with huge iovcnt should be -EINVAL"),
            None => Err("process_madvise(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_process_madvise_bad_iovcnt_pos);

fn smoke_abi_mem_process_madvise_bad_pidfd_neg() -> TestResult {
    with_setup(|| {
        // pidfd 999 isn't an open fd → the pidfd_target_pid lookup fails →
        // -EBADF (reached before the AS check).
        let args = a3(999, 0, 1, 4);
        match call(Syscall::ProcessMadvise.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            Some(_) => Err("process_madvise with a bogus pidfd should be -EBADF"),
            None => Err("process_madvise(EBADF) should be Ok(-EBADF)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_process_madvise_bad_pidfd_neg);

// ── MovePages (279) ──────────────────────────────────────────────────
// count > 1<<20 → -EINVAL. A zero-count query is a successful no-op;
// non-empty queries require both the page array and status array.

fn smoke_abi_mem_move_pages_zero_count_pos() -> TestResult {
    with_setup(|| match call(Syscall::MovePages.raw(), a1(0, 0)) {
        Some(0) => Ok(()),
        Some(_) => Err("move_pages zero-count query should return 0"),
        None => Err("move_pages returned non-Ok status"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_move_pages_zero_count_pos);

fn smoke_abi_mem_move_pages_bad_count_neg() -> TestResult {
    with_setup(|| {
        // count = (1<<20)+1 > the cap → -EINVAL.
        let args = a1(0, (1u64 << 20) + 1);
        match call(Syscall::MovePages.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("move_pages with an oversized count should be -EINVAL"),
            None => Err("move_pages(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_move_pages_bad_count_neg);

// ── MigratePages (256) ───────────────────────────────────────────────
// Null/empty node masks are invalid, matching Linux.

fn smoke_abi_mem_migrate_pages_empty_masks_neg() -> TestResult {
    with_setup(|| {
        // (pid, maxnode, old_nodes, new_nodes) with maxnode=1 but no masks.
        match call(Syscall::MigratePages.raw(), a3(0, 1, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("migrate_pages with null masks should be -EINVAL"),
            None => Err("migrate_pages(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_migrate_pages_empty_masks_neg);

// ── SetMempolicyHomeNode (450) ───────────────────────────────────────
// The syscall updates an existing MPOL_BIND range; a range with no policy
// returns -ENOENT.

fn smoke_abi_mem_set_mempolicy_home_node_pos() -> TestResult {
    with_setup(|| {
        let mask = 1u64;
        if call(
            Syscall::Mbind.raw(),
            a3(0x1000, 0x1000, 2, &mask as *const u64 as u64),
        ) != Some(0)
        {
            return Err("failed to install MPOL_BIND prerequisite");
        }
        match call(
            Syscall::SetMempolicyHomeNode.raw(),
            a3(0x1000, 0x1000, 0, 0),
        ) {
            Some(0) => Ok(()),
            Some(_) => Err("set_mempolicy_home_node(flags=0) should return 0"),
            None => Err("set_mempolicy_home_node returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_set_mempolicy_home_node_pos);

fn smoke_abi_mem_set_mempolicy_home_node_bad_flags_neg() -> TestResult {
    with_setup(|| {
        // arg3 (flags) non-zero → -EINVAL.
        match call(
            Syscall::SetMempolicyHomeNode.raw(),
            a3(0x1000, 0x1000, 0, 1),
        ) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("set_mempolicy_home_node(flags!=0) should be -EINVAL"),
            None => Err("set_mempolicy_home_node(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_set_mempolicy_home_node_bad_flags_neg
);

// ── SetMempolicy (238) ───────────────────────────────────────────────
// arg0=mode, arg1=nodemask ptr. Implemented modes are DEFAULT through
// PREFERRED_MANY (0..=5), with Linux UAPI mode flags masked.
// No AS needed.

fn smoke_abi_mem_set_mempolicy_pos() -> TestResult {
    with_setup(|| {
        // mode = MPOL_DEFAULT(0), nodemask ptr = 0 (none).
        match call(Syscall::SetMempolicy.raw(), a1(0, 0)) {
            Some(0) => Ok(()),
            Some(_) => Err("set_mempolicy(MPOL_DEFAULT) should return 0"),
            None => Err("set_mempolicy returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_set_mempolicy_pos);

fn smoke_abi_mem_set_mempolicy_bad_mode_neg() -> TestResult {
    with_setup(|| {
        // mode 9 is not an implemented Linux policy → -EINVAL.
        match call(Syscall::SetMempolicy.raw(), a1(9, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("set_mempolicy with an invalid mode should be -EINVAL"),
            None => Err("set_mempolicy(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_set_mempolicy_bad_mode_neg);

// ── GetMempolicy (239) ───────────────────────────────────────────────
// arg0=mode ptr, arg1=nodemask ptr, arg3=addr, arg4=flags. With
// MPOL_F_MEMS_ALLOWED(4) it writes the allowed-node mask and returns 0.
// With no flags + null mode ptr it also returns 0 (default policy). No
// genuine error arm reachable without a faulting user pointer, so the
// "negative" here is the null-pointer default-query (still 0) — paired
// with a writeback positive.

fn smoke_abi_mem_get_mempolicy_mems_allowed_pos() -> TestResult {
    with_setup(|| {
        // flags = MPOL_F_MEMS_ALLOWED(4); nodemask ptr = &mask (8 bytes).
        let mut mask = [0u8; 8];
        let args = SyscallArgs {
            arg0: 0,
            arg1: mask.as_mut_ptr() as u64,
            arg2: 64,
            arg3: 0,
            arg4: 4,
            arg5: 0,
        };
        match call(Syscall::GetMempolicy.raw(), args) {
            Some(0) => Ok(()),
            Some(_) => Err("get_mempolicy(MPOL_F_MEMS_ALLOWED) should return 0"),
            None => Err("get_mempolicy returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_get_mempolicy_mems_allowed_pos);

fn smoke_abi_mem_get_mempolicy_default_query_neg() -> TestResult {
    with_setup(|| {
        // No flags, null mode/nodemask ptrs → reports the default policy,
        // returns 0 (no fault, no error arm reachable from the harness).
        // A coverage limit, not a divergence: Linux's -EFAULT/-EINVAL arms
        // need a faulting user pointer this harness cannot synthesise.
        match call(Syscall::GetMempolicy.raw(), a0(0)) {
            Some(0) => Ok(()),
            Some(_) => Err("get_mempolicy default query should return 0"),
            None => Err("get_mempolicy default query returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_get_mempolicy_default_query_neg);

fn smoke_abi_mem_get_mempolicy_bad_flags_neg() -> TestResult {
    with_setup(|| {
        let unknown = call(
            Syscall::GetMempolicy.raw(),
            SyscallArgs { arg4: 8, ..a0(0) },
        );
        let conflicting = call(
            Syscall::GetMempolicy.raw(),
            SyscallArgs {
                arg4: 4 | 2,
                ..a0(0)
            },
        );
        if unknown == Some(-22) && conflicting == Some(-22) {
            Ok(())
        } else {
            Err("get_mempolicy should reject unknown/conflicting flags")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_get_mempolicy_bad_flags_neg);

// ── Mbind (237) ──────────────────────────────────────────────────────
// arg0=addr, arg1=len, arg2=mode, arg3=nodemask ptr. Invalid mode →
// -EINVAL; unaligned addr → -EINVAL. Valid + aligned → stored, returns 0.
// No AS needed.

fn smoke_abi_mem_mbind_pos() -> TestResult {
    with_setup(|| {
        let mask = 1u64;
        match call(
            Syscall::Mbind.raw(),
            a3(0x1000, 0x1000, 2, &mask as *const u64 as u64),
        ) {
            Some(0) => Ok(()),
            Some(_) => Err("mbind with a valid aligned range should return 0"),
            None => Err("mbind returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mbind_pos);

/// A child inherits a COPY of the parent's task mempolicy.
///
/// `copy_process()` does `p->mempolicy = mpol_dup(p->mempolicy)`
/// (`kernel/fork.c:2156`) for every child, with no CLONE_ flag guarding it,
/// so a thread inherits it exactly as a forked process does. NARF kept the
/// policy in a per-task table that no fork path ever copied, so a child
/// silently reverted to MPOL_DEFAULT and its allocations ignored the
/// placement its parent had chosen.
fn smoke_abi_mem_mempolicy_inherited_by_child() -> TestResult {
    with_setup(|| {
        const CHILD_TID: u64 = 0x3FED_0001;
        // MPOL_BIND (2) over node 0 — a policy that is distinguishable from
        // the MPOL_DEFAULT an un-inherited child would show.
        let mask = 1u64;
        if call(
            Syscall::SetMempolicy.raw(),
            a2(2, &mask as *const u64 as u64, 64),
        ) != Some(0)
        {
            return Err("set_mempolicy did not seed the parent policy");
        }
        let parent = crate::handlers::__test_task_mempolicy(FAKE_TASK)
            .ok_or("parent has no stored mempolicy after set_mempolicy")?;
        if parent.0 & 0xF != 2 {
            return Err("parent policy is not MPOL_BIND");
        }

        crate::handlers::__test_release_task_tables(CHILD_TID);
        crate::handlers::mempolicy_fork(FAKE_TASK, CHILD_TID);
        let child = match crate::handlers::__test_task_mempolicy(CHILD_TID) {
            Some(c) => c,
            None => {
                crate::handlers::__test_release_task_tables(CHILD_TID);
                return Err("child did not inherit the parent's mempolicy");
            }
        };
        if child != parent {
            crate::handlers::__test_release_task_tables(CHILD_TID);
            return Err("child's inherited policy differs from the parent's");
        }

        // It is a COPY, not a share: `mpol_dup` duplicates the struct, so a
        // later set_mempolicy in the parent must not move the child.
        if call(Syscall::SetMempolicy.raw(), a2(0, 0, 0)) != Some(0) {
            crate::handlers::__test_release_task_tables(CHILD_TID);
            return Err("set_mempolicy(MPOL_DEFAULT) failed in the parent");
        }
        let child_after = crate::handlers::__test_task_mempolicy(CHILD_TID);
        crate::handlers::__test_release_task_tables(CHILD_TID);
        if child_after != Some(child) {
            return Err("parent's later set_mempolicy moved the child's policy");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mempolicy_inherited_by_child);

/// A child inherits the parent's interleave cursor.
///
/// `il_prev` is a plain `task_struct` field that `copy_process` never
/// resets (`include/linux/sched.h:1355`), so the struct copy carries it to
/// every child; only `set_mempolicy` resets it, and only for an interleave
/// policy (`mm/mempolicy.c:1095`). Starting each child at 0 restarted the
/// round-robin, so a forked child re-walked the nodes its parent had just
/// used instead of continuing past them.
fn smoke_abi_mem_interleave_index_inherited_by_child() -> TestResult {
    with_setup(|| {
        const CHILD_TID: u64 = 0x3FED_0003;
        let mask = 1u64;
        // MPOL_INTERLEAVE (3) — the mode the cursor actually drives.
        if call(
            Syscall::SetMempolicy.raw(),
            a2(3, &mask as *const u64 as u64, 64),
        ) != Some(0)
        {
            return Err("set_mempolicy(MPOL_INTERLEAVE) failed");
        }
        // Advance through the production path, so the parent's cursor is
        // somewhere a fresh child would NOT be.
        crate::handlers::__test_advance_interleave_index(FAKE_TASK);
        crate::handlers::__test_advance_interleave_index(FAKE_TASK);
        let parent = crate::handlers::__test_interleave_index(FAKE_TASK)
            .ok_or("parent has no interleave cursor")?;
        if parent == 0 {
            return Err("parent cursor did not advance; test cannot discriminate");
        }

        crate::handlers::__test_release_task_tables(CHILD_TID);
        crate::handlers::interleave_index_fork(FAKE_TASK, CHILD_TID);
        let child = crate::handlers::__test_interleave_index(CHILD_TID);
        crate::handlers::__test_release_task_tables(CHILD_TID);
        match child {
            Some(c) if c == parent => Ok(()),
            Some(_) => Err("child's interleave cursor is not the parent's"),
            None => Err("child did not inherit the parent's interleave cursor"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_interleave_index_inherited_by_child
);

/// The NUMA-balancing scan cursor belongs to the ADDRESS SPACE; only the
/// pacing belongs to the task.
///
/// `mm->numa_next_scan` names a position in a particular address space, so
/// Linux keeps it in the mm and every CLONE_VM thread shares one walk;
/// `p->numa_scan_period` / `p->node_stamp` are per task, and
/// `init_numa_balancing()` (`kernel/sched/fair.c:3620`) staggers a new
/// thread's start precisely so siblings sharing an mm do not all scan on
/// the same tick. Keying the cursor per task made each thread re-walk the
/// same address space independently, sampling the same pages N times over
/// with no thread's progress advancing any other's.
///
/// With the cursor keyed by scope, the CLONE_VM split is structural: a
/// thread shares its parent's scope and therefore its cursor, while a
/// forked child's new scope has none yet and starts at the floor.
fn smoke_abi_mem_numa_scan_cursor_is_per_address_space() -> TestResult {
    with_setup(|| {
        const FORK_TID: u64 = 0x3FED_0004;
        const UNRELATED_SCOPE: u64 = 0x3FED_0006;
        const FLOOR: u64 = 0x0000_0080_0000_0000;
        let scope = crate::handlers::__test_numa_scan_scope();
        if scope == FAKE_TASK {
            // Cannot tell scope-keyed from task-keyed if they collide.
            return Ok(());
        }

        let mask = 1u64;
        // MPOL_BIND | MPOL_F_NUMA_BALANCING (1 << 13) over a range: this is
        // what seeds a scan cursor away from the floor.
        let mode = 2u64 | (1u64 << 13);
        let scan_start = FLOOR + 0x2000;
        if call(
            Syscall::Mbind.raw(),
            a3(scan_start, 0x1000, mode, &mask as *const u64 as u64),
        ) != Some(0)
        {
            return Err("mbind(MPOL_F_NUMA_BALANCING) failed");
        }

        // The cursor is reachable by ADDRESS SPACE...
        match crate::handlers::__test_numa_scan_cursor(scope) {
            Some(c) if c == scan_start => {}
            Some(_) => return Err("scan cursor for this address space is not where mbind put it"),
            None => return Err("mbind did not seed a scan cursor for this address space"),
        }
        // ...and NOT by task: a task id is not a cursor key any more.
        if crate::handlers::__test_numa_scan_cursor(FAKE_TASK).is_some() {
            return Err("scan cursor is still keyed by task");
        }
        // An unrelated address space has a walk of its own, not this one.
        if crate::handlers::__test_numa_scan_cursor(UNRELATED_SCOPE).is_some() {
            return Err("scan cursor leaked into an unrelated address space");
        }

        // Pacing IS per task, and a child's first scan is delayed.
        crate::handlers::__test_release_task_tables(FORK_TID);
        crate::handlers::numa_balance_fork(FAKE_TASK, FORK_TID);
        let child_ticks = crate::handlers::__test_numa_balance_ticks(FORK_TID);
        // A child never gets a cursor of its own — it reads its address
        // space's, which is what makes a thread continue the shared walk
        // instead of restarting it.
        let child_cursor = crate::handlers::__test_numa_scan_cursor(FORK_TID);
        crate::handlers::__test_release_task_tables(FORK_TID);
        if child_cursor.is_some() {
            return Err("child was given a per-task scan cursor");
        }
        match child_ticks {
            Some(0) => {}
            Some(_) => return Err("child's first scan must be delayed"),
            None => return Err("child inherited no balancing pacing"),
        }
        // The shared walk is untouched by the fork.
        match crate::handlers::__test_numa_scan_cursor(scope) {
            Some(c) if c == scan_start => Ok(()),
            _ => Err("forking disturbed the address space's shared scan position"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_numa_scan_cursor_is_per_address_space
);

/// A forked child's new address space inherits the parent's `mbind` ranges.
///
/// `dup_mmap` calls `vma_dup_policy` (`mm/mempolicy.c:2802`) for every VMA
/// it duplicates, so the child's mm carries copies of the parent's range
/// policies. Now that NARF keys those ranges by address space, a fresh
/// address space starts empty — which is correct for an unrelated process
/// and wrong for a forked child, hence this copy. A CLONE_VM child does not
/// come through here at all: it shares the address space, and therefore the
/// ranges, already.
fn smoke_abi_mem_mbind_ranges_inherited_by_forked_child() -> TestResult {
    with_setup(|| {
        const CHILD_SCOPE: u64 = 0x3FED_0002;
        let mask = 1u64;
        if call(
            Syscall::Mbind.raw(),
            a3(0x1000, 0x1000, 2, &mask as *const u64 as u64),
        ) != Some(0)
        {
            return Err("mbind did not record a range policy");
        }
        let parent_scope = crate::handlers::__test_mbind_scope();
        let parent_ranges = crate::handlers::__test_mbind_range_count(parent_scope);
        if parent_ranges == 0 {
            return Err("mbind recorded no range for the parent scope");
        }

        crate::handlers::drop_address_space_mbind_ranges(CHILD_SCOPE);
        crate::handlers::fork_address_space_mbind_ranges(parent_scope, CHILD_SCOPE);
        let child_ranges = crate::handlers::__test_mbind_range_count(CHILD_SCOPE);
        crate::handlers::drop_address_space_mbind_ranges(CHILD_SCOPE);
        if child_ranges != parent_ranges {
            return Err("forked child's address space did not inherit the mbind ranges");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mbind_ranges_inherited_by_forked_child
);

fn smoke_abi_mem_mbind_bad_mode_neg() -> TestResult {
    with_setup(|| {
        // mode 9 is invalid (checked before the addr alignment).
        match call(Syscall::Mbind.raw(), a3(0x1000, 0x1000, 9, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("mbind with an invalid mode should be -EINVAL"),
            None => Err("mbind(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mbind_bad_mode_neg);

fn smoke_abi_mem_mbind_unaligned_neg() -> TestResult {
    with_setup(|| {
        // Valid mode but misaligned addr (0x1001) → -EINVAL.
        match call(Syscall::Mbind.raw(), a3(0x1001, 0x1000, 2, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("mbind with a misaligned addr should be -EINVAL"),
            None => Err("mbind(unaligned) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mbind_unaligned_neg);

fn smoke_abi_mem_mbind_unknown_flags_neg() -> TestResult {
    with_setup(|| {
        let args = SyscallArgs {
            arg0: 0x1000,
            arg1: 0x1000,
            arg2: 2,
            arg5: 1 << 3,
            ..Default::default()
        };
        match call(Syscall::Mbind.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("mbind with an unknown flag should be -EINVAL"),
            None => Err("mbind(unknown flag) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mbind_unknown_flags_neg);

fn smoke_abi_mem_mbind_move_all_requires_privilege_neg() -> TestResult {
    with_setup(|| {
        let args = SyscallArgs {
            arg0: 0x1000,
            arg1: 0x1000,
            arg2: 2,
            arg5: 1 << 2,
            ..Default::default()
        };
        match call(Syscall::Mbind.raw(), args) {
            Some(v) if v == EPERM => Ok(()),
            Some(_) => Err("mbind(MPOL_MF_MOVE_ALL) should require privilege"),
            None => Err("mbind(MOVE_ALL) should be Ok(-EPERM)"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mbind_move_all_requires_privilege_neg
);

// ── Msync (26) ───────────────────────────────────────────────────────
// addr misaligned → -EINVAL (before the AS lookup). Aligned + no mapping
// (no AS, so `lookup` is treated as unmapped) → -ENOMEM. Both reachable.

fn smoke_abi_mem_msync_no_mapping_pos() -> TestResult {
    with_setup(|| {
        // Aligned addr, but no AS / mapping → -ENOMEM.
        match call(Syscall::Msync.raw(), a2(0x1000, 0x1000, 0)) {
            Some(v) if v == ENOMEM => Ok(()),
            Some(_) => Err("msync on an unmapped range should be -ENOMEM"),
            None => Err("msync(ENOMEM) should be Ok(-ENOMEM)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_msync_no_mapping_pos);

fn smoke_abi_mem_msync_unaligned_neg() -> TestResult {
    with_setup(|| {
        // Misaligned addr (0x1001) → -EINVAL (pre-AS check).
        match call(Syscall::Msync.raw(), a2(0x1001, 0x1000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("msync with a misaligned addr should be -EINVAL"),
            None => Err("msync(unaligned) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_msync_unaligned_neg);

// ── Mincore (27) ─────────────────────────────────────────────────────
// addr misaligned → -EINVAL (before the AS lookup). Aligned + no AS →
// -ENOMEM.

fn smoke_abi_mem_mincore_unaligned_pos() -> TestResult {
    with_setup(|| {
        // Misaligned addr (0x1001) → -EINVAL, reached before the AS check.
        let mut vec = [0u8; 1];
        let args = a3(0x1001, 0x1000, vec.as_mut_ptr() as u64, 0);
        match call(Syscall::Mincore.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("mincore with a misaligned addr should be -EINVAL"),
            None => Err("mincore(unaligned) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mincore_unaligned_pos);

fn smoke_abi_mem_mincore_no_as_neg() -> TestResult {
    with_setup(|| {
        // Aligned addr but no AS → -ENOMEM.
        let mut vec = [0u8; 1];
        let args = a3(0x1000, 0x1000, vec.as_mut_ptr() as u64, 0);
        // Linux mincore returns 0/-ENOMEM/-EFAULT. A 0 here was the worst
        // of the three: it told the caller the residency vector it passed
        // had been filled in, over a buffer nothing wrote.
        match call_raw(Syscall::Mincore.raw(), args).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("mincore reported success with no address space"),
            _ => Err("mincore with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mincore_no_as_neg);

// ── PkeyAlloc (330) ──────────────────────────────────────────────────
// arg0 must be 0 (no flags) else -EINVAL. Otherwise allocates the next
// free key in 1..16. No AS needed; per-task side table.

fn smoke_abi_mem_pkey_alloc_pos() -> TestResult {
    with_setup(|| {
        // flags=0, access_rights=0 → returns a key in 1..16.
        match call(Syscall::PkeyAlloc.raw(), a1(0, 0)) {
            Some(k) if (1..16).contains(&k) => Ok(()),
            Some(_) => Err("pkey_alloc should return a key in 1..16"),
            None => Err("pkey_alloc returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_pkey_alloc_pos);

fn smoke_abi_mem_pkey_alloc_bad_flags_neg() -> TestResult {
    with_setup(|| {
        // Non-zero flags → -EINVAL.
        match call(Syscall::PkeyAlloc.raw(), a1(1, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("pkey_alloc with non-zero flags should be -EINVAL"),
            None => Err("pkey_alloc(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_pkey_alloc_bad_flags_neg);

// ── PkeyFree (331) ───────────────────────────────────────────────────
// key must be in 1..16 AND currently allocated, else -EINVAL. Positive:
// alloc-then-free round trip within one task.

fn smoke_abi_mem_pkey_free_pos() -> TestResult {
    with_setup(|| {
        // Allocate a key, then free it — both run as FAKE_TASK so the
        // side table sees the same per-task bitmap.
        let key = match call(Syscall::PkeyAlloc.raw(), a1(0, 0)) {
            Some(k) if (1..16).contains(&k) => k as u64,
            _ => return Err("pkey_alloc precondition failed"),
        };
        match call(Syscall::PkeyFree.raw(), a0(key)) {
            Some(0) => Ok(()),
            Some(_) => Err("pkey_free of an allocated key should return 0"),
            None => Err("pkey_free returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_pkey_free_pos);

fn smoke_abi_mem_pkey_free_bad_key_neg() -> TestResult {
    with_setup(|| {
        // key 0 is reserved (default) → -EINVAL.
        match call(Syscall::PkeyFree.raw(), a0(0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("pkey_free(0) should be -EINVAL"),
            None => Err("pkey_free(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_pkey_free_bad_key_neg);

// ── PkeyMprotect (329) ───────────────────────────────────────────────
// arg3=pkey. An out-of-range key (not -1/0/1..16) → -EINVAL before the AS
// lookup (reachable). A valid key (0) then hits the no-AS arm → -ENOMEM.

fn smoke_abi_mem_pkey_mprotect_bad_key_pos() -> TestResult {
    with_setup(|| {
        // pkey = 99 (not -1, not 0, not in 0..16) → -EINVAL.
        let args = a3(0x1000, 0x1000, 1, 99);
        match call(Syscall::PkeyMprotect.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("pkey_mprotect with an invalid pkey should be -EINVAL"),
            None => Err("pkey_mprotect(EINVAL) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_pkey_mprotect_bad_key_pos);

fn smoke_abi_mem_pkey_mprotect_no_as_neg() -> TestResult {
    with_setup(|| {
        // pkey = 0 (default, always valid) → passes the key check, then no
        // AS → -ENOMEM.
        let args = a3(0x1000, 0x1000, 1, 0);
        match call_raw(Syscall::PkeyMprotect.raw(), args).value as i64 {
            v if v == ENOMEM => Ok(()),
            0 => Err("pkey_mprotect (valid key) reported success with no address space"),
            _ => Err("pkey_mprotect (valid key) with no address space must be -ENOMEM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_pkey_mprotect_no_as_neg);

// ════════════════════════════════════════════════════════════════════
// Errno-conformance audit — mm family.
//
// Every case below pins one arm whose code was previously wrong (bare
// -1/EPERM, a blanket EINVAL, or an error where Linux succeeds), plus the
// positive path that must keep working so a later tightening cannot turn a
// working call into an error. Kernel references are in the handler doc
// comments; the function named in each comment is the one that decides the
// value.
// ════════════════════════════════════════════════════════════════════

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_SEM: u64 = 0x8;
const PROT_GROWSDOWN: u64 = 0x0100_0000;
const PROT_GROWSUP: u64 = 0x0200_0000;

const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_HUGETLB: u64 = 0x0004_0000;
const MAP_FIXED_NOREPLACE: u64 = 0x0010_0000;

/// A canonical-but-unmappable user pointer: bit 48 set, 49..63 clear, so
/// `validate_user_range` rejects it without ever dereferencing it.
const NON_CANONICAL: u64 = 0x0001_0000_0000_0000;

/// The last page of the 64-bit address space: `addr + PAGE_ALIGN(len)` wraps.
const WRAPPING_BASE: u64 = 0xFFFF_FFFF_FFFF_F000;

fn mmap_args(hint: u64, len: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> SyscallArgs {
    SyscallArgs {
        arg0: hint,
        arg1: len,
        arg2: prot,
        arg3: flags,
        arg4: fd,
        arg5: offset,
    }
}

// ── MProtect (10) — do_mprotect_pkey argument contract ───────────────

/// `do_mprotect_pkey`: `if (!len) return 0;` — a zero-length mprotect is a
/// success and never consults a VMA, so it must not fall through to the
/// "no intersecting region" ENOMEM.
fn smoke_abi_mem_mprotect_zero_length_is_success_pos() -> TestResult {
    with_setup(
        || match call(Syscall::MProtect.raw(), a2(0x1000, 0, PROT_READ)) {
            Some(0) => Ok(()),
            Some(_) => Err("mprotect(len == 0) must return 0, not an errno"),
            None => Err("mprotect(len == 0) must be Ok(0)"),
        },
    )
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mprotect_zero_length_is_success_pos
);

/// `do_mprotect_pkey`: `if (start & ~PAGE_MASK) return -EINVAL;` — a
/// malformed address is the caller's arithmetic bug, not a missing mapping.
fn smoke_abi_mem_mprotect_unaligned_start_einval_pos() -> TestResult {
    with_setup(
        || match call(Syscall::MProtect.raw(), a2(0x1001, 0x1000, PROT_READ)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(v) if v == ENOMEM => Err("mprotect(unaligned) is EINVAL, not ENOMEM"),
            _ => Err("mprotect with a misaligned start must be -EINVAL"),
        },
    )
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mprotect_unaligned_start_einval_pos
);

/// `do_mprotect_pkey`: `arch_validate_prot` rejects any bit outside
/// READ|WRITE|EXEC|SEM, and PROT_GROWSDOWN|PROT_GROWSUP together are the
/// explicit "can't be both" EINVAL. Both used to be accepted and ignored.
fn smoke_abi_mem_mprotect_rejects_undefined_prot_bits_pos() -> TestResult {
    with_setup(|| {
        // An undefined prot bit: honouring only the low three bits would give
        // the caller a protection it did not ask for, silently.
        match call(
            Syscall::MProtect.raw(),
            a2(0x1000, 0x1000, PROT_READ | 0x100),
        ) {
            Some(v) if v == EINVAL => {}
            _ => return Err("mprotect with an undefined prot bit must be -EINVAL"),
        }
        // "can't be both" — checked before the address is even looked at.
        let both = PROT_READ | PROT_GROWSDOWN | PROT_GROWSUP;
        match call(Syscall::MProtect.raw(), a2(0x1000, 0x1000, both)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("mprotect(PROT_GROWSDOWN|PROT_GROWSUP) must be -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mprotect_rejects_undefined_prot_bits_pos
);

/// `do_mprotect_pkey`: `end = start + len; if (end <= start) return -ENOMEM;`
/// — a wrapped range is ENOMEM, distinct from the EINVAL arms above.
fn smoke_abi_mem_mprotect_wrapped_range_enomem_pos() -> TestResult {
    with_setup(|| {
        match call(
            Syscall::MProtect.raw(),
            a2(WRAPPING_BASE, 0x2000, PROT_READ),
        ) {
            Some(v) if v == ENOMEM => Ok(()),
            Some(v) if v == EINVAL => Err("mprotect(wrapped range) is ENOMEM, not EINVAL"),
            _ => Err("mprotect over a wrapped range must be -ENOMEM"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mprotect_wrapped_range_enomem_pos
);

/// Positive path: the new pre-checks must not reject a well-formed request.
/// PROT_SEM is accepted-and-ignored by Linux, so it stays a success here.
fn smoke_abi_mem_mprotect_live_mapping_pos() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|as_ref| {
            const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x0300_0000;
            let map = mmap_args(
                BASE,
                0x2000,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            if call(Syscall::Mmap.raw(), map) != Some(BASE as i64) {
                return Err("setup: fixed anonymous mapping failed");
            }
            if call(
                Syscall::MProtect.raw(),
                a2(BASE, 0x2000, PROT_READ | PROT_SEM),
            ) != Some(0)
            {
                return Err("mprotect(PROT_READ|PROT_SEM) over a live mapping must succeed");
            }
            if !as_ref
                .lookup(VirtAddr::new(BASE))
                .is_some_and(|region| region.perms.contains(RegionPerms::READ))
            {
                return Err("mprotect reported success without applying READ");
            }
            Ok(())
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mprotect_live_mapping_pos);

// ── Madvise (28) — madvise_should_skip ───────────────────────────────

/// `madvise_should_skip`: `if (start + PAGE_ALIGN(len_in) == start) { *err = 0; }`
/// — an empty purge is a success. jemalloc emits these constantly; ENOMEM
/// would read as "the arena was unmapped underneath me".
fn smoke_abi_mem_madvise_zero_length_is_success_pos() -> TestResult {
    with_setup(|| {
        const MADV_DONTNEED: u64 = 4;
        match call(Syscall::Madvise.raw(), a2(0x1000, 0, MADV_DONTNEED)) {
            Some(0) => Ok(()),
            Some(_) => Err("madvise(len == 0) must return 0"),
            None => Err("madvise(len == 0) must be Ok(0), not InvalidOp"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_madvise_zero_length_is_success_pos
);

/// `is_valid_madvise`: `if (!PAGE_ALIGNED(start)) return false;` → EINVAL,
/// decided before any address space is consulted.
fn smoke_abi_mem_madvise_unaligned_start_einval_pos() -> TestResult {
    with_setup(|| {
        const MADV_DONTNEED: u64 = 4;
        match call(Syscall::Madvise.raw(), a2(0x1001, 0x1000, MADV_DONTNEED)) {
            Some(v) if v == EINVAL => Ok(()),
            None => Err("madvise(unaligned) must be a reachable -EINVAL, not InvalidOp"),
            _ => Err("madvise with a misaligned start must be -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_madvise_unaligned_start_einval_pos
);

/// `madvise_behavior_valid`: an unknown `advice` is EINVAL, and it is the
/// FIRST thing checked — before the alignment of `start`.
fn smoke_abi_mem_madvise_unknown_advice_einval_pos() -> TestResult {
    with_setup(|| match call(Syscall::Madvise.raw(), a2(0x1001, 0, 4242)) {
        Some(v) if v == EINVAL => Ok(()),
        Some(0) => Err("an unknown madvise advice must not report success"),
        _ => Err("madvise with an unknown advice must be -EINVAL"),
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_madvise_unknown_advice_einval_pos
);

// ── Msync (26) — the end == start success arm ────────────────────────

/// `SYSCALL_DEFINE3(msync)`: `error = 0; if (end == start) goto out;` — taken
/// before `find_vma`, so an empty flush succeeds even over unmapped memory.
fn smoke_abi_mem_msync_zero_length_is_success_pos() -> TestResult {
    with_setup(|| match call(Syscall::Msync.raw(), a2(0x1000, 0, 0)) {
        Some(0) => Ok(()),
        Some(v) if v == ENOMEM => Err("msync(len == 0) is 0, not ENOMEM"),
        _ => Err("msync with a zero length must return 0"),
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_msync_zero_length_is_success_pos
);

// ── Mincore (27) — access_ok(vec) precedes the walk ──────────────────

/// `SYSCALL_DEFINE3(mincore)`: `if (!access_ok(vec, pages)) return -EFAULT;`
/// runs before `do_mincore`, so a bad output buffer wins over an unmapped
/// range. Callers use mincore's ENOMEM as the authoritative "not mapped".
fn smoke_abi_mem_mincore_bad_vec_efault_precedes_walk_pos() -> TestResult {
    with_setup(|| {
        let args = a3(0x1000, 0x1000, NON_CANONICAL, 0);
        match call(Syscall::Mincore.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            Some(v) if v == ENOMEM => Err("mincore(bad vec) is EFAULT, not ENOMEM"),
            None => Err("mincore(bad vec) must be a reachable -EFAULT"),
            _ => Err("mincore with an unwritable vec must be -EFAULT"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mincore_bad_vec_efault_precedes_walk_pos
);

// ── MLock (149) / MUnlock (150) / Mlock2 (325) ───────────────────────

/// `apply_vma_lock_flags`: `if (end == start) return 0;` for all three.
fn smoke_abi_mem_mlock_family_zero_length_is_success_pos() -> TestResult {
    with_setup(|| {
        if call(Syscall::MLock.raw(), a1(0x1000, 0)) != Some(0) {
            return Err("mlock(len == 0) must return 0");
        }
        if call(Syscall::MUnlock.raw(), a1(0x1000, 0)) != Some(0) {
            return Err("munlock(len == 0) must return 0");
        }
        if call(Syscall::Mlock2.raw(), a3(0x1000, 0, 0, 0)) != Some(0) {
            return Err("mlock2(len == 0) must return 0");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mlock_family_zero_length_is_success_pos
);

/// `apply_vma_lock_flags`: `end = start + len; if (end < start) return -EINVAL;`
/// — the only EINVAL in the family, and it must not be confused with the
/// ENOMEM a real coverage hole produces.
fn smoke_abi_mem_mlock_wrapped_range_einval_pos() -> TestResult {
    with_setup(
        || match call(Syscall::MLock.raw(), a1(WRAPPING_BASE, 0x2000)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(v) if v == EPERM => Err("mlock(wrapped) must not be EPERM with a default limit"),
            _ => Err("mlock over a wrapped range must be -EINVAL"),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlock_wrapped_range_einval_pos);

/// `do_mlock`: `len = PAGE_ALIGN(len + offset_in_page(start)); start &= PAGE_MASK;`
/// — mlock locks the pages *containing* the request. Every secret-memory
/// user (libsodium, gnupg, OpenSSL) passes a `malloc`'d pointer here; an
/// alignment EINVAL makes them give up on locking key material entirely.
fn smoke_abi_mem_mlock_rounds_an_unaligned_address_pos() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|as_ref| {
            const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x0400_0000;
            let map = mmap_args(
                BASE,
                0x2000,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            if call(Syscall::Mmap.raw(), map) != Some(BASE as i64) {
                return Err("setup: fixed anonymous mapping failed");
            }
            // A pointer one byte into the first page, one page long: Linux
            // rounds down to BASE and up to one page.
            if call(Syscall::MLock.raw(), a1(BASE + 1, 0x1000)) != Some(0) {
                return Err("mlock of a misaligned buffer must round, not EINVAL");
            }
            if !as_ref
                .lookup(VirtAddr::new(BASE))
                .is_some_and(|region| region.perms.contains(RegionPerms::LOCKED))
            {
                return Err("mlock reported success without locking the containing page");
            }
            if call(Syscall::MUnlock.raw(), a1(BASE + 1, 0x1000)) != Some(0) {
                return Err("munlock must accept the same misaligned pointer mlock did");
            }
            Ok(())
        })
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mlock_rounds_an_unaligned_address_pos
);

// ── Mlockall (151) — `int flags`, not `unsigned long` ────────────────

/// `SYSCALL_DEFINE1(mlockall, int, flags)`: only the low 32 bits are the
/// request. Reading the whole register turned a valid MCL_FUTURE into
/// "unknown MCL_ flags" (EINVAL) whenever the high half held junk.
fn smoke_abi_mem_mlockall_flags_are_32_bit_pos() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|_| {
            const MCL_FUTURE: u64 = 2;
            let with_junk_high_half = 0xDEAD_BEEF_0000_0000u64 | MCL_FUTURE;
            match call(Syscall::Mlockall.raw(), a0(with_junk_high_half)) {
                Some(0) => {}
                Some(v) if v == EINVAL => {
                    return Err("mlockall must ignore the high 32 bits of `int flags`")
                }
                _ => return Err("mlockall(MCL_FUTURE) must succeed"),
            }
            if call(Syscall::Munlockall.raw(), a0(0)) != Some(0) {
                return Err("munlockall must clear the future policy");
            }
            Ok(())
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlockall_flags_are_32_bit_pos);

// ── Mmap (9) — do_mmap's MAP_TYPE switch and MAP_FIXED_NOREPLACE ─────

/// `do_mmap`: both `switch (flags & MAP_TYPE)` arms end in
/// `default: return -EINVAL`. A request with no type bit at all is the
/// classic `mmap(NULL, n, prot, MAP_ANONYMOUS, -1, 0)` typo, which used to
/// produce a working private mapping here and a hard EINVAL on Linux.
fn smoke_abi_mem_mmap_requires_a_map_type_pos() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|_| {
            let no_type = mmap_args(
                0,
                0x1000,
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            match call(Syscall::Mmap.raw(), no_type) {
                Some(v) if v == EINVAL => {}
                Some(v) if v > 0 => return Err("mmap without a MAP_TYPE must not map anything"),
                _ => return Err("mmap without a MAP_TYPE must be -EINVAL"),
            }
            // The positive counterpart: adding the type bit maps normally.
            let private = mmap_args(
                0,
                0x1000,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            match call(Syscall::Mmap.raw(), private) {
                Some(v) if v > 0 => Ok(()),
                _ => Err("MAP_PRIVATE|MAP_ANONYMOUS must still map"),
            }
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mmap_requires_a_map_type_pos);

/// `do_mmap`: MAP_FIXED_NOREPLACE forces MAP_FIXED, then
/// `if (find_vma_intersection(mm, addr, addr + len)) return -EEXIST;`.
/// Ignoring the flag made a "claim this base without clobbering anyone"
/// request destroy the very mapping it was probing for.
fn smoke_abi_mem_mmap_fixed_noreplace_eexist_pos() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|as_ref| {
            const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x0500_0000;
            const FREE: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x0600_0000;
            let occupy = mmap_args(
                BASE,
                0x1000,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            if call(Syscall::Mmap.raw(), occupy) != Some(BASE as i64) {
                return Err("setup: could not occupy the base");
            }
            let noreplace = mmap_args(
                BASE,
                0x1000,
                PROT_READ,
                MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            match call(Syscall::Mmap.raw(), noreplace) {
                Some(v) if v == EEXIST => {}
                Some(v) if v == BASE as i64 => {
                    return Err("MAP_FIXED_NOREPLACE replaced an existing mapping")
                }
                _ => return Err("MAP_FIXED_NOREPLACE over a live mapping must be -EEXIST"),
            }
            if !as_ref
                .lookup(VirtAddr::new(BASE))
                .is_some_and(|region| region.perms.contains(RegionPerms::WRITE))
            {
                return Err("the refused MAP_FIXED_NOREPLACE still disturbed the old mapping");
            }
            // Positive: at a free base the flag still implies MAP_FIXED, so
            // the requested address is the one returned.
            let free = mmap_args(
                FREE,
                0x1000,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            match call(Syscall::Mmap.raw(), free) {
                Some(v) if v == FREE as i64 => Ok(()),
                _ => Err("MAP_FIXED_NOREPLACE at a free base must map exactly there"),
            }
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mmap_fixed_noreplace_eexist_pos);

/// `__get_unmapped_area`: `if (addr > TASK_SIZE - len) return -ENOMEM;`
/// comes BEFORE `if (offset_in_page(addr)) return -EINVAL;`. A MAP_FIXED
/// probe walking candidate bases upward reads ENOMEM as "past the end, stop"
/// and EINVAL as "my arithmetic is broken, abort".
fn smoke_abi_mem_mmap_fixed_range_enomem_precedes_align_einval_pos() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|_| {
            // Both wrong at once: above the user half AND misaligned.
            let beyond = mmap_args(
                AddressSpace::USER_HALF_END | 1,
                0x1000,
                PROT_READ,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            match call(Syscall::Mmap.raw(), beyond) {
                Some(v) if v == ENOMEM => {}
                Some(v) if v == EINVAL => {
                    return Err("MAP_FIXED out of range is ENOMEM; the range test wins")
                }
                _ => return Err("MAP_FIXED beyond the user half must be -ENOMEM"),
            }
            // In range but misaligned is still EINVAL.
            let misaligned = mmap_args(
                AddressSpace::MMAP_CURSOR_BASE + 0x0700_0001,
                0x1000,
                PROT_READ,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                (-1i64) as u64,
                0,
            );
            match call(Syscall::Mmap.raw(), misaligned) {
                Some(v) if v == EINVAL => Ok(()),
                _ => Err("an in-range misaligned MAP_FIXED must be -EINVAL"),
            }
        })
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mmap_fixed_range_enomem_precedes_align_einval_pos
);

/// `ksys_mmap_pgoff`: for a file that is not hugetlbfs,
/// `else if (unlikely(flags & MAP_HUGETLB)) { retval = -EINVAL; goto out_fput; }`.
/// ENODEV would say "this file cannot be mapped at all" and make a caller
/// abandon the file instead of retrying without MAP_HUGETLB.
fn smoke_abi_mem_mmap_hugetlb_on_a_plain_file_einval_pos() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|_| {
            let name = b"abi-hugetlb\0";
            let fd = match call(
                Syscall::MemfdCreate.raw(),
                a3(name.as_ptr() as u64, 0, 0, 0),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("setup: memfd_create failed"),
            };
            let huge = mmap_args(0, 0x1000, PROT_READ, MAP_PRIVATE | MAP_HUGETLB, fd, 0);
            match call(Syscall::Mmap.raw(), huge) {
                Some(v) if v == EINVAL => {}
                Some(v) if v == ENODEV => {
                    return Err("MAP_HUGETLB on a non-hugetlbfs file is EINVAL, not ENODEV")
                }
                _ => return Err("MAP_HUGETLB on a plain file must be -EINVAL"),
            }
            // Positive: the same fd maps fine without MAP_HUGETLB.
            let plain = mmap_args(0, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
            match call(Syscall::Mmap.raw(), plain) {
                Some(v) if v > 0 => Ok(()),
                _ => Err("a plain MAP_PRIVATE file mapping must still succeed"),
            }
        })
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mmap_hugetlb_on_a_plain_file_einval_pos
);

/// `ksys_mmap_pgoff`: `file = fget(fd); if (!file) return -EBADF;` — and
/// `fget` masks out FMODE_PATH, so an O_PATH descriptor is EBADF for mmap.
fn smoke_abi_mem_mmap_o_path_fd_ebadf_pos() -> TestResult {
    with_memfs("/abimm", "abimm", &[("f", b"hello")], || {
        with_mem_test_as(|_| {
            let path = b"/abimm/f\0";
            let fd = match call_open(path.as_ptr() as u64, crate::fd::O_PATH as u64) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("setup: O_PATH open failed"),
            };
            let args = mmap_args(0, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
            match call(Syscall::Mmap.raw(), args) {
                Some(v) if v == EBADF => {}
                Some(v) if v > 0 => return Err("mmap must not map an O_PATH descriptor"),
                _ => return Err("mmap of an O_PATH fd must be -EBADF"),
            }
            // Positive: a real O_RDONLY handle on the same file maps.
            let readable = match call_open(path.as_ptr() as u64, crate::fd::O_RDONLY as u64) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("setup: O_RDONLY open failed"),
            };
            let args = mmap_args(0, 0x1000, PROT_READ, MAP_PRIVATE, readable, 0);
            match call(Syscall::Mmap.raw(), args) {
                Some(v) if v > 0 => Ok(()),
                _ => Err("mmap of an ordinary readable fd must succeed"),
            }
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mmap_o_path_fd_ebadf_pos);

// ── Munmap (11) — do_vmi_munmap ──────────────────────────────────────

/// `do_vmi_munmap`: `vma = vma_find(vmi, end); if (!vma) return 0;` — a
/// well-formed unmap of a range that holds no VMA is a success. `free()`
/// double-unmapping a trimmed arena depends on it.
fn smoke_abi_mem_munmap_unmapped_range_is_success_pos() -> TestResult {
    with_setup(|| {
        with_mem_test_as(|_| {
            const FREE: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x0800_0000;
            match call(Syscall::Munmap.raw(), a1(FREE, 0x1000)) {
                Some(0) => {}
                Some(v) if v == ENOMEM => {
                    return Err("munmap of an unmapped range is 0, not ENOMEM")
                }
                _ => return Err("munmap of a well-formed unmapped range must return 0"),
            }
            // The malformed arms stay EINVAL, which is what tells a caller its
            // own bookkeeping — not the kernel's memory — is the problem.
            match call(Syscall::Munmap.raw(), a1(FREE + 1, 0x1000)) {
                Some(v) if v == EINVAL => {}
                _ => return Err("munmap with a misaligned start must be -EINVAL"),
            }
            match call(Syscall::Munmap.raw(), a1(FREE, 0)) {
                Some(v) if v == EINVAL => Ok(()),
                _ => Err("munmap with a zero length must be -EINVAL"),
            }
        })
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_munmap_unmapped_range_is_success_pos
);

// ── MovePages (279) / MigratePages (256) — ESRCH vs EPERM ────────────

/// `find_mm_struct`: `task = find_get_task_by_vpid(pid); if (!task) return
/// ERR_PTR(-ESRCH);` — only a task that exists but fails `ptrace_may_access`
/// is EPERM. `numactl`/`migratepages` race process exit constantly and need
/// ESRCH to mean "skip this pid" rather than "you lack CAP_SYS_NICE".
fn smoke_abi_mem_move_pages_unknown_pid_esrch_pos() -> TestResult {
    with_setup(|| {
        const DEAD_PID: u64 = 0x7FFF_F000;
        let args = SyscallArgs {
            arg0: DEAD_PID,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        match call(Syscall::MovePages.raw(), args) {
            Some(v) if v == ESRCH => Ok(()),
            Some(v) if v == EPERM => Err("move_pages on a dead pid is ESRCH, not EPERM"),
            _ => Err("move_pages with an unknown pid must be -ESRCH"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_move_pages_unknown_pid_esrch_pos
);

/// `kernel_migrate_pages` runs both `get_nodes()` calls BEFORE
/// `find_task_by_vpid`, so a malformed node mask beats a stale pid; and an
/// unresolvable pid is ESRCH.
fn smoke_abi_mem_migrate_pages_nodemask_precedes_pid_pos() -> TestResult {
    with_setup(|| {
        const DEAD_PID: u64 = 0x7FFF_F001;
        // maxnode == 0 with null masks: get_nodes fails first, whoever the
        // pid names.
        match call(Syscall::MigratePages.raw(), a3(DEAD_PID, 0, 0, 0)) {
            Some(v) if v == EINVAL => {}
            Some(v) if v == ESRCH || v == EPERM => {
                return Err("migrate_pages validates the node masks before the pid")
            }
            _ => return Err("migrate_pages with maxnode == 0 must be -EINVAL"),
        }
        // Well-formed masks, unresolvable pid → ESRCH.
        let mask = 1u64;
        let args = a3(
            DEAD_PID,
            1,
            &mask as *const u64 as u64,
            &mask as *const u64 as u64,
        );
        match call(Syscall::MigratePages.raw(), args) {
            Some(v) if v == ESRCH => Ok(()),
            Some(v) if v == EPERM => Err("migrate_pages on a dead pid is ESRCH, not EPERM"),
            _ => Err("migrate_pages with an unknown pid must be -ESRCH"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_migrate_pages_nodemask_precedes_pid_pos
);

// ── Mbind (237) — get_nodes runs before do_mbind's flag check ────────

/// `kernel_mbind` calls `get_nodes(&nodes, nmask, maxnode)` before entering
/// `do_mbind`, where `flags & ~MPOL_MF_VALID` is rejected. So an unreadable
/// node mask reports EFAULT even when `flags` is also junk — EINVAL there
/// makes a caller conclude the *policy* is unsupported and disable NUMA
/// binding rather than fix the pointer it passed.
fn smoke_abi_mem_mbind_nodemask_efault_precedes_flag_einval_pos() -> TestResult {
    with_setup(|| {
        let args = SyscallArgs {
            arg0: 0x1000,
            arg1: 0x1000,
            arg2: 2, // MPOL_BIND
            arg3: NON_CANONICAL,
            arg4: 0,
            arg5: 1 << 3, // not in MPOL_MF_VALID
        };
        match call(Syscall::Mbind.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            Some(v) if v == EINVAL => Err("mbind reads the node mask before judging flags"),
            _ => Err("mbind with an unreadable node mask must be -EFAULT"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem_mbind_nodemask_efault_precedes_flag_einval_pos
);

// ── process_mrelease(2) ──────────────────────────────────────────
//
// `mm/oom_kill.c`. Reclaims the anonymous memory of an ALREADY-DYING
// process named by a pidfd, so a userspace low-memory killer
// (systemd-oomd, Android lmkd) gets the memory back promptly instead of
// whenever the victim next runs.

/// Install a pidfd for `pid` in the harness task's table.
fn install_pidfd(pid: u64, alive: bool) -> Result<u32, &'static str> {
    let st = crate::pidfd::mint_for(pid, pid, alive);
    let ops: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(st));
    crate::fd::install(
        FAKE_TASK,
        crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: 0,
        },
    )
    .ok_or("could not install a pidfd")
}

/// Argument and target validation, in `do_process_mrelease`'s order.
///
/// `if (flags) return -EINVAL` comes before the fd is looked at, so an
/// unknown flag is reported rather than silently ignored — and a caller
/// cannot use a bad fd to mask a flag this kernel does not implement.
fn smoke_abi_mem_process_mrelease_validation() -> TestResult {
    const EAGAIN: i64 = -11;
    with_setup(|| {
        // A non-zero flag is rejected even with a bogus fd, which is what
        // pins the ORDER rather than just the errno.
        if call(Syscall::ProcessMrelease.raw(), a1(999, 1)) != Some(EINVAL) {
            return Err("process_mrelease with a non-zero flag must be -EINVAL");
        }
        // Not an open fd at all.
        if call(Syscall::ProcessMrelease.raw(), a1(999, 0)) != Some(EBADF) {
            return Err("process_mrelease with a bogus pidfd must be -EBADF");
        }
        // An open fd that is not a pidfd is also -EBADF: `pidfd_get_task`
        // rejects the file type, it does not fall through to the target.
        let not_a_pidfd = match crate::fd::install(
            FAKE_TASK,
            crate::fd::FdEntry {
                ops: alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(crate::pidfd::mint_for(
                    4242, 4242, true,
                ))) as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        ) {
            Some(f) => f,
            None => return Err("could not install a probe fd"),
        };
        // A pidfd naming a pid with no task behind it is -ESRCH: the
        // descriptor is fine, the process is gone. A pidfd deliberately
        // outlives its process, so this is the ordinary race.
        if call(Syscall::ProcessMrelease.raw(), a1(not_a_pidfd as u64, 0)) != Some(ESRCH) {
            return Err("process_mrelease on a departed process must be -ESRCH");
        }
        let _ = EAGAIN;
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_process_mrelease_validation);

/// A LIVE process is -EINVAL; a dying one is released.
///
/// This is the whole security argument for the syscall. `task_will_free_mem`
/// gates it, and without that gate any caller holding a pidfd could destroy
/// a running process's memory out from under it. The live half is therefore
/// not a nicety — it is the property being asserted, and the dying half is
/// the control that says the refusal is a real check and not the syscall
/// failing for everyone.
fn smoke_abi_mem_process_mrelease_only_dying() -> TestResult {
    with_setup(|| {
        const VICTIM: u64 = 7311;
        // A live, registered task with an address space.
        let _t = crate::task::Task::new_registered(VICTIM, VICTIM);
        crate::handlers::register_task_to_pid(VICTIM, VICTIM);
        crate::handlers::register_pid_task_mapping(VICTIM, VICTIM);
        let fd = install_pidfd(VICTIM, true)?;

        // No address space for the victim yet: nothing to release, -ESRCH.
        // (`find_lock_task_mm` failing.)
        if call(Syscall::ProcessMrelease.raw(), a1(fd as u64, 0)) != Some(ESRCH) {
            return Err("process_mrelease on a task with no address space must be -ESRCH");
        }

        // Give it one, still alive → -EINVAL, because it is not dying.
        // SAFETY: same construction the other memory cases use — a fresh
        // user address space with no mappings.
        let as_arc = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => alloc::sync::Arc::new(a),
            Err(_) => return Err("could not build a victim address space"),
        };
        let prev = crate::handlers::__test_swap_as_for_task_lookup(Some(victim_as_lookup));
        VICTIM_AS.lock().replace(as_arc.clone());
        let live = call(Syscall::ProcessMrelease.raw(), a1(fd as u64, 0));

        // Now mark it dying, exactly as `exit_group(2)` would.
        if let Some(t) = crate::task::task_get(VICTIM) {
            t.group_exiting
                .store(true, core::sync::atomic::Ordering::Release);
        }
        let dying = call(Syscall::ProcessMrelease.raw(), a1(fd as u64, 0));

        *VICTIM_AS.lock() = None;
        crate::handlers::__test_swap_as_for_task_lookup(prev);

        if live != Some(EINVAL) {
            return Err("process_mrelease on a LIVE process must be -EINVAL");
        }
        match dying {
            // Released, or nothing to release — both are success. -EAGAIN
            // would mean the reaper deferred, which is also not a refusal.
            Some(0) | Some(-11) => {}
            _ => return Err("process_mrelease on a dying process should not be refused"),
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_process_mrelease_only_dying);

/// The address space the by-task resolver hands back during the case above.
static VICTIM_AS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::sync::Arc<narf_memory::AddressSpace>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn victim_as_lookup(_task: u64) -> Option<alloc::sync::Arc<narf_memory::AddressSpace>> {
    VICTIM_AS.lock().clone()
}
