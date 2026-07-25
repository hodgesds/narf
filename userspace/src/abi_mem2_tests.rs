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
#![cfg(feature = "linux-compat")]
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

// ── SetMempolicy (238) — top flag bits boundary ──────────────────────
// `mpol_mode_valid` masks MPOL_MODE_FLAGS (0xc000_0000) before the range
// check, so a mode carrying MPOL_F_STATIC_NODES with a low value still
// validates. mode = MPOL_F_STATIC_NODES | MPOL_INTERLEAVE(3) → valid.

fn smoke_abi_mem2_set_mempolicy_flagged_mode_pos() -> TestResult {
    with_setup(|| {
        // 0x8000_0000 (MPOL_F_STATIC_NODES) | 3 (INTERLEAVE) → masked to 3 < MAX.
        match call(Syscall::SetMempolicy.raw(), a1(0x8000_0003, 0)) {
            Some(0) => Ok(()),
            Some(_) => Err("set_mempolicy(STATIC_NODES|INTERLEAVE) should return 0"),
            None => Err("set_mempolicy(flagged mode) returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem2_set_mempolicy_flagged_mode_pos);

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
        if call(Syscall::SetMempolicy.raw(), a1(2, 0)) != Some(0) {
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
// The deepest get_mempolicy branch: with MPOL_F_NODE|MPOL_F_ADDR the
// out word is the resolved NUMA node (not the mode). NARF is single-node
// for an unbound addr → node 0. Distinct from every abi_mem_tests case.

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
            Some(0) => {
                // The resolved node must be a real online-node index (the
                // local node for an unbound addr). Pins the F_NODE|F_ADDR
                // writeback path without coupling to a specific topology.
                let node = i32::from_le_bytes(node_out);
                if (0..64).contains(&node) {
                    Ok(())
                } else {
                    Err("get_mempolicy(F_NODE|F_ADDR) should resolve a valid node id")
                }
            }
            Some(_) => Err("get_mempolicy(F_NODE|F_ADDR) should return 0"),
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
        // LINUX-GAP: Linux move_pages writes per-page status / -EFAULT;
        // NARF matches the -EFAULT shape here for an unwritable pointer.
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
