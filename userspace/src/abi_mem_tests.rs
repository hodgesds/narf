//! Linux syscall ABI conformance — mem group.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

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
// No AS + (possibly) uninitialised BRK_TABLE: every path here returns a
// NARF-Ok status with a non-negative value (current break or 0). We pin
// the status + sign rather than an exact address (the break base depends
// on whether BRK_TABLE was initialised by an earlier boot test).

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
        // LINUX-GAP: Linux brk never fails the *value* either, but with a
        // live heap it would clamp/return the resulting break; here with no
        // AS the value is the requested break or 0.
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
// No AS in the harness → invalid_op() (call == None). A MAP_FIXED with a
// misaligned hint hits its own pre-check… but that pre-check is AFTER the
// AS lookup, so it too returns invalid_op() here. Both pin the no-AS arm.

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
        // LINUX-GAP: Linux mmap returns a mapped address (or -ENOMEM);
        // with no harness AS the handler returns NARF InvalidOp.
        match call(Syscall::Mmap.raw(), args) {
            None => Ok(()),
            Some(_) => Err("mmap with no address space should be InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mmap_no_as_neg);

// ── Munmap (11) ──────────────────────────────────────────────────────

fn smoke_abi_mem_munmap_no_as_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux munmap returns 0/-EINVAL; no AS → InvalidOp.
        match call(Syscall::Munmap.raw(), a1(0x1000, 0x1000)) {
            None => Ok(()),
            Some(_) => Err("munmap with no address space should be InvalidOp"),
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
        // LINUX-GAP: Linux mremap returns the (possibly moved) address or
        // -ENOMEM/-EINVAL; no AS → InvalidOp.
        match call(Syscall::Mremap.raw(), a3(0x1000, 0x1000, 0x2000, 0)) {
            None => Ok(()),
            Some(_) => Err("mremap with no address space should be InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mremap_no_as_neg);

// ── MProtect (10) ────────────────────────────────────────────────────

fn smoke_abi_mem_mprotect_no_as_neg() -> TestResult {
    with_setup(|| {
        // base=0x1000, len=0x1000, prot=PROT_READ(1).
        // LINUX-GAP: Linux mprotect returns 0/-EINVAL/-EACCES; no AS →
        // InvalidOp.
        match call(Syscall::MProtect.raw(), a2(0x1000, 0x1000, 1)) {
            None => Ok(()),
            Some(_) => Err("mprotect with no address space should be InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mprotect_no_as_neg);

// ── MLock (149) ──────────────────────────────────────────────────────

fn smoke_abi_mem_mlock_no_as_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux mlock returns 0/-ENOMEM/-EPERM; no AS →
        // InvalidOp.
        match call(Syscall::MLock.raw(), a1(0x1000, 0x1000)) {
            None => Ok(()),
            Some(_) => Err("mlock with no address space should be InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlock_no_as_neg);

// ── MUnlock (150) ────────────────────────────────────────────────────

fn smoke_abi_mem_munlock_no_as_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux munlock returns 0/-ENOMEM; no AS → InvalidOp.
        match call(Syscall::MUnlock.raw(), a1(0x1000, 0x1000)) {
            None => Ok(()),
            Some(_) => Err("munlock with no address space should be InvalidOp"),
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
        // InvalidOp.
        match call(Syscall::Mlock2.raw(), a3(0x1000, 0x1000, 1, 0)) {
            None => Ok(()),
            Some(_) => Err("mlock2 (valid flags, no AS) should be InvalidOp"),
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
        // InvalidOp.
        match call(Syscall::Mlockall.raw(), a0(1)) {
            None => Ok(()),
            Some(_) => Err("mlockall(MCL_CURRENT, no AS) should be InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mlockall_no_as_neg);

// ── Munlockall (152) ─────────────────────────────────────────────────
// Pure AS walk; no AS → InvalidOp.

fn smoke_abi_mem_munlockall_no_as_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux munlockall returns 0; no AS → InvalidOp.
        match call(Syscall::Munlockall.raw(), a0(0)) {
            None => Ok(()),
            Some(_) => Err("munlockall with no AS should be InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_munlockall_no_as_neg);

// ── Madvise (28) ─────────────────────────────────────────────────────
// AS lookup first → no AS → InvalidOp for every advice value.

fn smoke_abi_mem_madvise_no_as_neg() -> TestResult {
    with_setup(|| {
        // base=0x1000, len=0x1000, advice=MADV_NORMAL(0).
        // LINUX-GAP: Linux madvise returns 0 for accepted hints; no AS →
        // InvalidOp.
        match call(Syscall::Madvise.raw(), a2(0x1000, 0x1000, 0)) {
            None => Ok(()),
            Some(_) => Err("madvise with no AS should be InvalidOp"),
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
// No AS needed. count > 1<<20 → -EINVAL. A status query (status_ptr set,
// small count) writes node-0 (i32 zeros) for each page and returns 0.

fn smoke_abi_mem_move_pages_status_pos() -> TestResult {
    with_setup(|| {
        // count=1, pages=0, nodes=0, status=&out, flags=0. Handler writes
        // one i32 (node 0) into `out` and returns 0.
        let mut out = [0xFFu8; 4];
        let args = SyscallArgs {
            arg0: 0,
            arg1: 1,
            arg2: 0,
            arg3: 0,
            arg4: out.as_mut_ptr() as u64,
            arg5: 0,
        };
        match call(Syscall::MovePages.raw(), args) {
            Some(0) => {
                if out == [0u8; 4] {
                    Ok(())
                } else {
                    Err("move_pages should report node 0 (i32 zero) per page")
                }
            }
            Some(_) => Err("move_pages status query should return 0"),
            None => Err("move_pages returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_move_pages_status_pos);

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
// NARF is single-node for placement: always a no-op returning 0. No
// reachable error arm, so only the success/no-op pin.

fn smoke_abi_mem_migrate_pages_pos() -> TestResult {
    with_setup(|| {
        // (pid, maxnode, old_nodes, new_nodes) — all ignored; returns 0.
        match call(Syscall::MigratePages.raw(), a3(0, 1, 0, 0)) {
            Some(0) => Ok(()),
            Some(_) => Err("migrate_pages no-op should return 0"),
            None => Err("migrate_pages returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_migrate_pages_pos);

// ── SetMempolicyHomeNode (450) ───────────────────────────────────────
// flags(arg3) must be 0 → else -EINVAL. Otherwise accepted with 0. No AS
// needed.

fn smoke_abi_mem_set_mempolicy_home_node_pos() -> TestResult {
    with_setup(|| {
        // addr=0x1000, len=0x1000, home_node=0, flags=0.
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
// arg0=mode, arg1=nodemask ptr. Valid modes are 0..MPOL_MAX(5) (with the
// top flag bits masked). Stored in a per-task side table; success → 0.
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
        // mode 9 >= MPOL_MAX(5) (and below the flag bits) → -EINVAL.
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
            arg2: 0,
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
        // LINUX-GAP: Linux can return -EFAULT/-EINVAL for bad ptrs/flags;
        // those need a faulting user pointer we can't synthesise here.
        match call(Syscall::GetMempolicy.raw(), a0(0)) {
            Some(0) => Ok(()),
            Some(_) => Err("get_mempolicy default query should return 0"),
            None => Err("get_mempolicy default query returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_get_mempolicy_default_query_neg);

// ── Mbind (237) ──────────────────────────────────────────────────────
// arg0=addr, arg1=len, arg2=mode, arg3=nodemask ptr. Invalid mode →
// -EINVAL; unaligned addr → -EINVAL. Valid + aligned → stored, returns 0.
// No AS needed.

fn smoke_abi_mem_mbind_pos() -> TestResult {
    with_setup(|| {
        // addr=0x1000 (aligned), len=0x1000, mode=MPOL_BIND(2), nodemask=0.
        match call(Syscall::Mbind.raw(), a3(0x1000, 0x1000, 2, 0)) {
            Some(0) => Ok(()),
            Some(_) => Err("mbind with a valid aligned range should return 0"),
            None => Err("mbind returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_mbind_pos);

fn smoke_abi_mem_mbind_bad_mode_neg() -> TestResult {
    with_setup(|| {
        // mode 9 >= MPOL_MAX(5) → -EINVAL (checked before the addr align).
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
// InvalidOp.

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
        // Aligned addr but no AS → InvalidOp.
        let mut vec = [0u8; 1];
        let args = a3(0x1000, 0x1000, vec.as_mut_ptr() as u64, 0);
        // LINUX-GAP: Linux mincore returns 0/-ENOMEM/-EFAULT; no AS →
        // InvalidOp.
        match call(Syscall::Mincore.raw(), args) {
            None => Ok(()),
            Some(_) => Err("mincore with no AS should be InvalidOp"),
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
// lookup (reachable). A valid key (0) then hits the no-AS arm → InvalidOp.

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
        // AS → InvalidOp.
        let args = a3(0x1000, 0x1000, 1, 0);
        match call(Syscall::PkeyMprotect.raw(), args) {
            None => Ok(()),
            Some(_) => Err("pkey_mprotect (valid key, no AS) should be InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mem_pkey_mprotect_no_as_neg);
