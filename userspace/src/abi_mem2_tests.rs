//! Linux syscall ABI conformance — mem group, audit pass 2.
//!
//! Additional branch coverage for the mem-family handlers that
//! `abi_mem_tests.rs` leaves untested: the *second* `set_return` arms
//! (writeback paths, EFAULT on a bad out-pointer), boundary values
//! (iovcnt/count exactly at the cap, the high pkey index), the alternate
//! error branch (a valid-range-but-unallocated pkey, unknown mlockall
//! flag bits), and the resource-exhaustion arm (pkey ENOSPC). No case
//! here duplicates one already pinned in `abi_mem_tests.rs`.
//!
//! Same harness invariant as pass 1: the ABI harness installs no per-task
//! AddressSpace, so any handler that reaches `current_address_space()`
//! takes the `None` arm. Every test below is therefore chosen to land on
//! a branch that fires BEFORE the AS lookup (validation / side-table /
//! out-pointer writeback) so the asserted return is genuinely reachable.
use crate::abi_test_support::*;

// ── Mlockall (151) — unknown flag bits ───────────────────────────────
// abi_mem_tests pins flags==0 → EINVAL and MCL_CURRENT → no-AS InvalidOp.
// The OTHER EINVAL trigger is a non-zero flag word with a bit outside
// {CURRENT,FUTURE,ONFAULT}; that second condition of the same `if` is a
// distinct input class and still fires before the AS lookup.

fn smoke_abi_mem2_mlockall_unknown_bit_neg() -> TestResult {
    with_setup(|| {
        // 0x8 is above MCL_ONFAULT(4) and not CURRENT/FUTURE → -EINVAL.
        match call(Syscall::Mlockall.raw(), a0(0x8)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("mlockall with an unknown flag bit should be -EINVAL"),
            None => Err("mlockall(unknown-bit) should be Ok(-EINVAL), not InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_mlockall_unknown_bit_neg);

// ── Mbind (237) — MPOL_DEFAULT removes the binding ───────────────────
// abi_mem_tests covers MPOL_BIND (stores), a bad mode, and an unaligned
// addr. MPOL_DEFAULT(0) is valid + aligned but takes the `if (mode &
// !FLAGS) != 0` FALSE arm (the range is dropped, not pushed) and still
// returns 0 — a separate code path.

fn smoke_abi_mem2_mbind_default_pos() -> TestResult {
    with_setup(|| {
        // addr=0x2000 (aligned), len=0x1000, mode=MPOL_DEFAULT(0), nodemask=0.
        match call(Syscall::Mbind.raw(), a3(0x2000, 0x1000, 0, 0)) {
            Some(0) => Ok(()),
            Some(_) => Err("mbind(MPOL_DEFAULT) should return 0"),
            None => Err("mbind(MPOL_DEFAULT) returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_mbind_default_pos);

// ── SetMempolicy (238) — non-default mode + nodemask read ────────────
// abi_mem_tests covers MPOL_DEFAULT(0)/null-mask and a bad mode. Here:
// a valid non-default mode (MPOL_BIND) WITH a non-null nodemask pointer,
// which takes the `if a.arg1 != 0` read_user_u64 arm before storing.

fn smoke_abi_mem2_set_mempolicy_bind_nodemask_pos() -> TestResult {
    with_setup(|| {
        // mode=MPOL_BIND(2), nodemask=&mask (node 0 selected).
        let mask: u64 = 0x1;
        let args = a1(2, &mask as *const u64 as u64);
        match call(Syscall::SetMempolicy.raw(), args) {
            Some(0) => Ok(()),
            Some(_) => Err("set_mempolicy(BIND, nodemask) should return 0"),
            None => Err("set_mempolicy(BIND, nodemask) returned non-Ok status"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem2_set_mempolicy_bind_nodemask_pos
);

// ── SetMempolicy (238) — Linux UAPI mode-flag boundary ───────────────
// `mpol_mode_valid` masks MPOL_MODE_FLAGS (bits 15 and 14) before the
// range check, so a mode carrying MPOL_F_STATIC_NODES with a low value still
// validates. mode = MPOL_F_STATIC_NODES | MPOL_INTERLEAVE(3) → valid.

fn smoke_abi_mem2_set_mempolicy_flagged_mode_pos() -> TestResult {
    with_setup(|| {
        // 0x8000 (MPOL_F_STATIC_NODES) | 3 (INTERLEAVE).
        let mask = 1u64;
        match call(
            Syscall::SetMempolicy.raw(),
            a1(0x8003, &mask as *const u64 as u64),
        ) {
            Some(0) => Ok(()),
            Some(_) => Err("set_mempolicy(STATIC_NODES|INTERLEAVE) should return 0"),
            None => Err("set_mempolicy(flagged mode) returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_set_mempolicy_flagged_mode_pos);

fn smoke_abi_mem2_relative_nodes_tracks_cpuset() -> TestResult {
    if narf_memory::node_total(1) == 0 {
        return TestResult::Skip("requires a second online NUMA node");
    }
    with_setup(|| {
        let task = crate::handlers::current_task_id();
        narf_scheduler::set_task_mems_allowed(task, 0b10);
        let mask = 1u64; // relative ordinal 0 => first allowed node => node 1
        let set = call(
            Syscall::SetMempolicy.raw(),
            a1(0x4003, &mask as *const u64 as u64),
        );
        let mut node = -1i32;
        let get = call(
            Syscall::GetMempolicy.raw(),
            SyscallArgs {
                arg0: &mut node as *mut i32 as u64,
                arg4: 1, // MPOL_F_NODE
                ..a0(0)
            },
        );
        narf_scheduler::clear_task_mems_allowed(task);
        if set == Some(0) && get == Some(0) && node == 1 {
            Ok(())
        } else {
            Err("relative node ordinal did not map into cpuset.mems")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_relative_nodes_tracks_cpuset);

// ── GetMempolicy (239) — mode-pointer writeback ──────────────────────
// abi_mem_tests covers MPOL_F_MEMS_ALLOWED and the null-everything
// default query. Here we exercise the `mode_ptr != 0` writeback arm
// (no MEMS_ALLOWED, no F_NODE): it writes the in-force mode (DEFAULT=0)
// as an i32 into *mode_ptr and returns 0. Verifies the second
// set_return path plus the actual written value.

fn smoke_abi_mem2_get_mempolicy_mode_writeback_pos() -> TestResult {
    with_setup(|| {
        // Prime the per-task policy to MPOL_BIND(2) so the writeback is
        // observably non-zero (and distinct from the uninitialised case).
        let mask = 1u64;
        if call(
            Syscall::SetMempolicy.raw(),
            a1(2, &mask as *const u64 as u64),
        ) != Some(0)
        {
            return Err("set_mempolicy precondition failed");
        }
        let mut mode_out = [0xFFu8; 4];
        // mode_ptr=&out, nodemask=0, maxnode=0, addr=0, flags=0.
        let args = SyscallArgs {
            arg0: mode_out.as_mut_ptr() as u64,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        match call(Syscall::GetMempolicy.raw(), args) {
            Some(0) => {
                if i32::from_le_bytes(mode_out) == 2 {
                    Ok(())
                } else {
                    Err("get_mempolicy should write the in-force mode (BIND=2)")
                }
            }
            Some(_) => Err("get_mempolicy(mode writeback) should return 0"),
            None => Err("get_mempolicy(mode writeback) returned non-Ok status"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem2_get_mempolicy_mode_writeback_pos
);

// ── GetMempolicy (239) — F_NODE|F_ADDR resolved-node writeback ───────
// MPOL_F_NODE|MPOL_F_ADDR requires an address belonging to the current
// address space. The ABI harness has no user AS, so Linux-compatible
// behavior is EFAULT rather than predicting a placement node.

fn smoke_abi_mem2_get_mempolicy_node_query_pos() -> TestResult {
    with_setup(|| {
        let mut node_out = [0xFFu8; 4];
        // flags = MPOL_F_NODE(1) | MPOL_F_ADDR(2) = 3; addr=0 (unbound).
        let args = SyscallArgs {
            arg0: node_out.as_mut_ptr() as u64,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 3,
            arg5: 0,
        };
        match call(Syscall::GetMempolicy.raw(), args) {
            Some(-14) => Ok(()),
            Some(_) => Err("get_mempolicy(F_NODE|F_ADDR) should return EFAULT without an AS"),
            None => Err("get_mempolicy(F_NODE|F_ADDR) returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_get_mempolicy_node_query_pos);

// ── MovePages (279) — EFAULT on a non-canonical status pointer ───────
// abi_mem_tests covers the good status writeback and the oversized
// count. The `copy_to_user(...).is_err()` arm (EFAULT) is a distinct
// third path. We trigger it with a NON-CANONICAL status pointer (bit 48
// set, bits 49..63 clear): validate_user_range rejects it with EFAULT
// BEFORE any dereference, so the test never wild-writes. (A tiny address
// like 0x1 is canonical and would actually be dereferenced — must avoid.)

fn smoke_abi_mem2_move_pages_bad_status_neg() -> TestResult {
    with_setup(|| {
        // count=1, status = 0x0001_0000_0000_0000 (non-canonical) → EFAULT
        // from validate_user_range, no dereference.
        let args = SyscallArgs {
            arg0: 0,
            arg1: 1,
            arg2: 0,
            arg3: 0,
            arg4: 0x0001_0000_0000_0000,
            arg5: 0,
        };
        // `move_pages` writes per-page status, so an unwritable status
        // pointer is -EFAULT before any page is examined.
        match call(Syscall::MovePages.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            Some(0) => Err("move_pages with a bad status ptr should not succeed"),
            Some(_) => Err("move_pages(bad status) should be -EFAULT"),
            None => Err("move_pages(EFAULT) should be Ok(-EFAULT)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_move_pages_bad_status_neg);

// ── MovePages (279) — count boundary (exactly 1<<20) ─────────────────
// abi_mem_tests pins (1<<20)+1 → EINVAL. The boundary value 1<<20 is
// NOT over the cap (`count > 1<<20` is strict), so validation advances to
// the required page/status pointers and returns EFAULT, not EINVAL.

fn smoke_abi_mem2_move_pages_count_boundary_efault_neg() -> TestResult {
    with_setup(|| {
        // count == 1<<20 (the cap, inclusive), pointers null → EFAULT.
        let args = a1(0, 1u64 << 20);
        match call(Syscall::MovePages.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            Some(v) if v == EINVAL => Err("move_pages(count==1<<20) is the cap, not over it"),
            Some(_) => Err("move_pages(count==1<<20, null pointers) should be -EFAULT"),
            None => Err("move_pages(boundary) returned non-Ok status"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem2_move_pages_count_boundary_efault_neg
);

// ── ProcessMadvise (440) — iovcnt boundary (exactly 1024) ────────────
// abi_mem_tests pins iovcnt=2048 → EINVAL and a bogus pidfd → EBADF.
// The boundary 1024 is NOT over the cap (`iovcnt > 1024` is strict), so
// it PASSES the iovcnt check and falls through to the pidfd lookup,
// which fails for a bogus fd → EBADF. Pins the off-by-one boundary AND
// that the EBADF arm is reached after a max-but-valid iovcnt.

fn smoke_abi_mem2_process_madvise_iovcnt_boundary_neg() -> TestResult {
    with_setup(|| {
        // pidfd=999 (not open), iovcnt=1024 (== cap, allowed), advice=4.
        let args = a3(999, 0, 1024, 4);
        match call(Syscall::ProcessMadvise.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            Some(v) if v == EINVAL => {
                Err("iovcnt==1024 is the cap, not over it (should reach EBADF)")
            }
            Some(_) => Err("process_madvise(iovcnt==1024, bad pidfd) should be -EBADF"),
            None => Err("process_madvise(boundary) should be Ok(-EBADF)"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem2_process_madvise_iovcnt_boundary_neg
);

// ── PkeyFree (331) — high-index boundary ─────────────────────────────
// abi_mem_tests pins key 0 → EINVAL. The OTHER guard (`key >= 16`) is a
// separate boundary: key 16 is the first out-of-range index → EINVAL,
// reached before the per-task allocation lookup.

fn smoke_abi_mem2_pkey_free_high_index_neg() -> TestResult {
    with_setup(|| {
        // key 16 is the first index past the 1..16 window → -EINVAL.
        match call(Syscall::PkeyFree.raw(), a0(16)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("pkey_free(16) should be -EINVAL (out of range)"),
            None => Err("pkey_free(16) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_pkey_free_high_index_neg);

// ── PkeyFree (331) — in-range but never allocated ────────────────────
// Distinct from key 0 / key 16: a key INSIDE 1..16 that was never
// allocated takes the `allocated == false` arm (the second EINVAL
// set_return), not the range guard.

fn smoke_abi_mem2_pkey_free_unallocated_neg() -> TestResult {
    with_setup(|| {
        // PKEY_TABLE survives setup(); a sibling test may have left key 7
        // allocated for FAKE_TASK. Free it first (idempotent: EINVAL if it
        // was already free) so the index is guaranteed unallocated here.
        let _ = call(Syscall::PkeyFree.raw(), a0(7));
        // key 7 is a valid index but nothing is allocated → -EINVAL via
        // the allocation-bitmap miss, not the range check.
        match call(Syscall::PkeyFree.raw(), a0(7)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("pkey_free of an unallocated in-range key should be -EINVAL"),
            None => Err("pkey_free(unallocated) should be Ok(-EINVAL)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_pkey_free_unallocated_neg);

// ── PkeyAlloc (330) — exhaustion → ENOSPC ────────────────────────────
// abi_mem_tests pins one alloc and a bad-flags EINVAL. Allocating until
// the 1..16 bitmap is full reaches the final `ok(-28)` ENOSPC arm — a
// branch the single-alloc test never hits.
//
// NOTE: PKEY_TABLE is a process-global side table NOT reset by setup()
// (only the syscall table is), so the FAKE_TASK bitmap may already carry
// keys from a sibling pkey test depending on run order. We therefore
// drain to exhaustion rather than assuming exactly 15 free keys: keep
// allocating (at most 16, the bitmap width) until ENOSPC, then assert it
// fired. This is order-independent.

fn smoke_abi_mem2_pkey_alloc_exhaust_neg() -> TestResult {
    with_setup(|| {
        const ENOSPC: i64 = -28;
        // At most 15 keys can ever be live (1..16), so 16 attempts always
        // reach the full-bitmap ENOSPC arm regardless of the start state.
        for _ in 0..16 {
            match call(Syscall::PkeyAlloc.raw(), a1(0, 0)) {
                Some(k) if (1..16).contains(&k) => continue, // still room
                Some(v) if v == ENOSPC => return Ok(()),     // exhausted: target arm
                Some(_) => return Err("pkey_alloc returned an out-of-range value"),
                None => return Err("pkey_alloc returned non-Ok status during fill"),
            }
        }
        Err("pkey_alloc never reached -ENOSPC after draining the bitmap")
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_pkey_alloc_exhaust_neg);

// ── PkeyMprotect (329) — valid-range key, not allocated ──────────────
// abi_mem_tests pins pkey=99 (range guard EINVAL) and pkey=0 (no-AS
// InvalidOp). A key INSIDE 0..16 but never allocated takes the *second*
// EINVAL arm (the `!allocated` check), distinct from the range guard,
// and returns before the AS lookup.

fn smoke_abi_mem2_pkey_mprotect_unallocated_key_neg() -> TestResult {
    with_setup(|| {
        // PKEY_TABLE survives setup(); ensure key 5 is unallocated for
        // FAKE_TASK regardless of sibling-test run order (idempotent free).
        let _ = call(Syscall::PkeyFree.raw(), a0(5));
        // pkey=5: passes the 0..16 range check but is not allocated
        // → -EINVAL from the allocation-bitmap miss (pre-AS).
        let args = a3(0x1000, 0x1000, 1, 5);
        match call(Syscall::PkeyMprotect.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            Some(_) => Err("pkey_mprotect with an unallocated key should be -EINVAL"),
            None => Err("pkey_mprotect(unallocated key) should be Ok(-EINVAL), not InvalidOp"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem2_pkey_mprotect_unallocated_key_neg
);

// ── Mincore (27) — EFAULT path is unreachable (no-AS) note ───────────
// abi_mem_tests already pins mincore's unaligned-EINVAL and no-AS
// InvalidOp arms. Its residency-writeback and EFAULT arms both sit
// AFTER the AS lookup, so they are unreachable from this harness (no
// per-task AddressSpace). Documented here; no test — a no-op pin would
// violate the "never always-pass" rule.

// ── Msync (26) — mapped success path is unreachable (no-AS) note ─────
// abi_mem_tests pins msync's unaligned-EINVAL and no-mapping-ENOMEM
// arms. The `mapped == true → ok(0)` arm needs a live mapping in a
// per-task AddressSpace the harness cannot build, so it is unreachable;
// documented, no test.
//
// The MS_INVALIDATE-over-VM_LOCKED → -EBUSY arm (`mm/msync.c`) is
// unreachable here for the same reason: with no AddressSpace,
// `current_address_space()` is None and the check short-circuits to
// false, leaving the existing no-mapping ENOMEM — which is what
// smoke_abi_mem_msync_no_mapping_pos already pins, so that arm stays
// covered. The state the EBUSY decision actually reads is pinned in the
// memory crate by smoke_memory_perms_intersecting_reports_locked, which
// covers the case this harness cannot: a range spanning an unlocked and
// a locked VMA still reporting LOCKED.

// ── mseal(2) ──────────────────────────────────────────────────────────
//
// Sealing makes a range permanently immune to the operations that could
// replace what is mapped there. It is MONOTONIC — `unseal()` does not exist,
// deliberately — which is why a case only ever has to prove that something
// became refused, never that it became allowed again.

static MSEAL_AS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::sync::Arc<narf_memory::AddressSpace>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn lookup_mseal_as() -> Option<alloc::sync::Arc<narf_memory::AddressSpace>> {
    MSEAL_AS.lock().clone()
}

/// A real address space with one anonymous RW mapping, and the address of
/// that mapping. `mseal` needs a range that is actually mapped — an
/// unmapped one is -ENOMEM before anything is recorded.
fn with_mseal_as(
    body: impl FnOnce(u64, u64) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    const LEN: u64 = 0x4000; // four pages, so a sub-range is distinguishable
                             // SAFETY: kernel tests run after paging is enabled; the new root stays
                             // owned by MSEAL_AS for the whole sequence.
    let as_ref = match unsafe { narf_memory::AddressSpace::new_for_user() } {
        Ok(a) => alloc::sync::Arc::new(a),
        Err(_) => return Err("failed to create an mseal test address space"),
    };
    *MSEAL_AS.lock() = Some(alloc::sync::Arc::clone(&as_ref));
    crate::handlers::install_address_space_lookup(lookup_mseal_as);
    let base = as_ref.reserve_mmap_va(LEN);
    let result = if base == 0 {
        Err("failed to reserve a test mapping")
    } else {
        // MAP_ANONYMOUS | MAP_PRIVATE, RW, at a fixed address.
        let args = SyscallArgs {
            arg0: base,
            arg1: LEN,
            arg2: 3,    // PROT_READ | PROT_WRITE
            arg3: 0x32, // MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED
            arg4: (-1i64) as u64,
            arg5: 0,
        };
        match call(Syscall::Mmap.raw(), args) {
            Some(v) if v as u64 == base => body(base, LEN),
            _ => Err("failed to map the test range"),
        }
    };
    crate::handlers::restore_address_space_lookup(None);
    *MSEAL_AS.lock() = None;
    result
}

/// A sealed range refuses every operation that could replace it.
///
/// The five are the ones `mm/mseal.c` lists: munmap, mremap, mprotect,
/// pkey_mprotect and `mmap(MAP_FIXED)`. Each is checked AFTER sealing and
/// each must be -EPERM — a seal that stops only some of them stops none of
/// them, because any one is enough to put different contents at the address.
fn smoke_abi_mem2_mseal_refuses_replacing_operations() -> TestResult {
    with_setup(|| {
        with_mseal_as(|base, len| {
            // Before sealing, mprotect over the range works — so the refusals
            // below are the seal and not some unrelated failure.
            if call(Syscall::MProtect.raw(), a2(base, len, 1)) != Some(0) {
                return Err("mprotect should work before the range is sealed");
            }
            if call(Syscall::Mseal.raw(), a2(base, len, 0)) != Some(0) {
                return Err("mseal over a mapped range should succeed");
            }
            // "adding a seal on an already sealed memory is a no-action (no
            // error)".
            if call(Syscall::Mseal.raw(), a2(base, len, 0)) != Some(0) {
                return Err("re-sealing an already sealed range must not be an error");
            }
            if call(Syscall::MProtect.raw(), a2(base, len, 1)) != Some(EPERM) {
                return Err("mprotect over a sealed range must be -EPERM");
            }
            if call(Syscall::PkeyMprotect.raw(), a3(base, len, 1, 0)) != Some(EPERM) {
                return Err("pkey_mprotect over a sealed range must be -EPERM");
            }
            if call(Syscall::Mremap.raw(), a3(base, len, len * 2, 0)) != Some(EPERM) {
                return Err("mremap of a sealed range must be -EPERM");
            }
            // A destructive MAP_FIXED over the range.
            let fixed = SyscallArgs {
                arg0: base,
                arg1: len,
                arg2: 3,
                arg3: 0x32, // MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED
                arg4: (-1i64) as u64,
                arg5: 0,
            };
            if call(Syscall::Mmap.raw(), fixed) != Some(EPERM) {
                return Err("mmap(MAP_FIXED) over a sealed range must be -EPERM");
            }
            // munmap last — if it succeeded, everything above would be moot.
            if call(Syscall::Munmap.raw(), a1(base, len)) != Some(EPERM) {
                return Err("munmap of a sealed range must be -EPERM");
            }
            Ok(())
        })
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_mem2_mseal_refuses_replacing_operations
);

/// A sub-range seal protects only what it covers, and any OVERLAP is enough
/// to refuse.
///
/// Overlap and not containment: unmapping a range that is half sealed would
/// still leave a hole where the sealed half was, which is exactly what
/// sealing exists to prevent.
fn smoke_abi_mem2_mseal_partial_range() -> TestResult {
    const PAGE: u64 = 0x1000;
    with_setup(|| {
        with_mseal_as(|base, len| {
            // Seal only the second page of four.
            if call(Syscall::Mseal.raw(), a2(base + PAGE, PAGE, 0)) != Some(0) {
                return Err("sealing a sub-range should succeed");
            }
            // The first page is untouched.
            if call(Syscall::MProtect.raw(), a2(base, PAGE, 1)) != Some(0) {
                return Err("a page outside the seal must still be mprotect-able");
            }
            // The fourth page too.
            if call(Syscall::MProtect.raw(), a2(base + 3 * PAGE, PAGE, 1)) != Some(0) {
                return Err("a later page outside the seal must still be mprotect-able");
            }
            // A range that merely OVERLAPS the sealed page is refused.
            if call(Syscall::MProtect.raw(), a2(base, 2 * PAGE, 1)) != Some(EPERM) {
                return Err("a range overlapping the seal must be -EPERM");
            }
            // And the whole mapping, which contains it.
            if call(Syscall::Munmap.raw(), a1(base, len)) != Some(EPERM) {
                return Err("unmapping a range containing the seal must be -EPERM");
            }
            Ok(())
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_mseal_partial_range);

/// `mseal`'s own argument rules.
///
/// ```text
/// if (flags)                 return -EINVAL;   /* reserved */
/// if (!PAGE_ALIGNED(start))  return -EINVAL;
/// len = PAGE_ALIGN(len_in);
/// if (len_in && !len)        return -EINVAL;   /* rounded up to zero */
/// ```
///
/// and -ENOMEM for an address that is not mapped, or a gap inside the range
/// — sealing half a range would leave the caller believing all of it is
/// protected.
fn smoke_abi_mem2_mseal_argument_rules() -> TestResult {
    const PAGE: u64 = 0x1000;
    with_setup(|| {
        with_mseal_as(|base, len| {
            // `flags` is reserved.
            if call(Syscall::Mseal.raw(), a2(base, len, 1)) != Some(EINVAL) {
                return Err("a nonzero mseal flag must be -EINVAL");
            }
            // Unaligned start.
            if call(Syscall::Mseal.raw(), a2(base + 1, len, 0)) != Some(EINVAL) {
                return Err("an unaligned start must be -EINVAL");
            }
            // A length that rounds up to zero.
            if call(Syscall::Mseal.raw(), a2(base, u64::MAX, 0)) != Some(EINVAL) {
                return Err("a length that rounds up to zero must be -EINVAL");
            }
            // Zero length is a no-op, not an error — and must not seal
            // anything, or the mprotect below would fail.
            if call(Syscall::Mseal.raw(), a2(base, 0, 0)) != Some(0) {
                return Err("a zero length must be accepted as a no-op");
            }
            if call(Syscall::MProtect.raw(), a2(base, PAGE, 1)) != Some(0) {
                return Err("a zero-length mseal sealed something");
            }
            // An unmapped address.
            let unmapped = base + 0x1000_0000;
            if call(Syscall::Mseal.raw(), a2(unmapped, PAGE, 0)) != Some(ENOMEM) {
                return Err("sealing an unmapped address must be -ENOMEM");
            }
            // A range that starts inside the mapping and runs past its end
            // is a gap, and must seal nothing.
            if call(Syscall::Mseal.raw(), a2(base, len + PAGE, 0)) != Some(ENOMEM) {
                return Err("a range spanning a gap must be -ENOMEM");
            }
            if call(Syscall::MProtect.raw(), a2(base, PAGE, 1)) != Some(0) {
                return Err("a failed mseal sealed part of the range anyway");
            }
            Ok(())
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_mseal_argument_rules);
