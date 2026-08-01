//! `mem_uaccess` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

fn smoke_userspace_default_delivery_auto_blocks_without_nodefer() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF900);
    static DELIVERED_SIG: AtomicU32 = AtomicU32::new(0);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::sigaction_init();
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut act = SigGapCtx {
        args: SyscallArgs {
            arg0: 11,
            arg1: 0xC0DE,
            arg2: 0,
            arg3: 0, // no SA_NODEFER
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut act);
    let mut k = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xF900,
            arg1: 11,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut k);

    struct UserBoundCtx;
    impl TrapContext for UserBoundCtx {
        fn args(&self) -> &SyscallArgs {
            static DUMMY: SyscallArgs = SyscallArgs {
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            };
            &DUMMY
        }
        fn set_return(&mut self, _: SyscallReturn) {}
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
        fn returning_to_user(&self) -> bool {
            true
        }
        fn deliver_signal(&mut self, p: &crate::SigDeliveryParams) -> bool {
            DELIVERED_SIG.store(p.signum, Ordering::Release);
            true
        }
    }
    let mut ctx = UserBoundCtx;
    DELIVERED_SIG.store(0, Ordering::Release);
    crate::handlers::default_signal_delivery(&mut ctx, crate::handlers::SYSCALL_NUM_NONE);

    let mask_after = crate::handlers::signal_mask_of(0xF900);
    let delivered = DELIVERED_SIG.load(Ordering::Acquire);
    __test_clear_global();
    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    if delivered != 11 {
        return TestResult::Fail("delivery hook did not fire");
    }
    if mask_after & crate::handlers::sig_bit(11) == 0 {
        return TestResult::Fail("default delivery should auto-block the signal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_default_delivery_auto_blocks_without_nodefer
);

// ── SMAP copy-from/to-user smoke tests ────────────────────────────
//
// These tests exercise the `copy_from_user` / `copy_to_user` helpers
// added by the SMAP fix. Because the kernel-test harness runs in
// supervisor mode (CPL=0) with the kernel's own address space active,
// we use *kernel-heap* buffers as the simulated "user pointer". The
// kernel heap is canonical (0xFFFF_FF80_*) so `validate_user_range`
// passes; SMAP does not fire because kernel pages carry PTE.U=0 (the
// supervisor-to-supervisor read is always permitted).
//
// A full user-pointer test requires an actual ring-3 task — the
// init/shell boot path exercises that in the QEMU integration test.
//
// Linux analogue: `lib/test_user_copy.c` (`test_kernel_ptr_fail`,
// `test_valid_kernel_copy`).

/// Smoke 1: `sys_write` copies kernel buffer through FileOps without
/// passing the raw user pointer to the FileOps impl.
#[cfg(target_arch = "x86_64")]
fn smoke_smap_sys_write_kbuf_roundtrip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    static SEEN_CORRECT: AtomicBool = AtomicBool::new(false);
    SEEN_CORRECT.store(false, Ordering::Relaxed);

    // FileOps that records whether the write buffer contained the
    // expected sentinel bytes (proving the copy happened correctly).
    struct SentinelFile;
    impl FileOps for SentinelFile {
        fn read<'a>(&'a self, _o: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            buf.fill(0xBB);
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn write<'a>(&'a self, _o: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            // Verify every byte is the expected sentinel.
            let all_aa = buf.iter().all(|&b| b == 0xAA);
            SEEN_CORRECT.store(all_aa, Ordering::Relaxed);
            let n = buf.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    static FAKE_TASK_W: u64 = 0xF001;
    fn task_w() -> u64 {
        FAKE_TASK_W
    }

    fd::__test_reset();
    install_task_id_lookup(task_w);
    let fd_n = fd::with_table(FAKE_TASK_W, |t| {
        t.open(FdEntry {
            ops: Arc::new(SentinelFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("with_table");

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    // "User" buffer is a kernel-heap allocation filled with 0xAA.
    let user_buf = alloc::vec![0xAAu8; 32];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: user_buf.as_ptr() as u64,
            arg2: user_buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 32) {
        return TestResult::Fail("sys_write returned wrong value");
    }
    if !SEEN_CORRECT.load(Ordering::Relaxed) {
        return TestResult::Fail("FileOps::write received wrong bytes (copy_from_user broken)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_smap_sys_write_kbuf_roundtrip);

/// Smoke 2: `sys_write` with `len > 16 MiB` returns EINVAL (-22).
#[cfg(target_arch = "x86_64")]
fn smoke_smap_sys_write_oversized_einval() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

    static FAKE_TASK_OV: u64 = 0xF002;
    fn task_ov() -> u64 {
        FAKE_TASK_OV
    }

    fd::__test_reset();
    install_task_id_lookup(task_ov);

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    // 17 MiB > 16 MiB cap — should return EINVAL = -22.
    // ptr value doesn't matter (len check fires first); use a stable address.
    let dummy_buf = [0u8; 1];
    let dummy_ptr = dummy_buf.as_ptr() as u64;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1, // fd (doesn't matter)
            arg1: dummy_ptr,
            arg2: (17 * 1024 * 1024) as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    let expected = SyscallReturn::ok((-22i64) as u64);
    if ctx.ret != Some(expected) {
        return TestResult::Fail("sys_write with len>16MiB did not return EINVAL");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_smap_sys_write_oversized_einval);

/// Smoke 3: `sys_write` with null pointer returns EFAULT (-14).
#[cfg(target_arch = "x86_64")]
fn smoke_smap_sys_write_null_efault() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

    static FAKE_TASK_NP: u64 = 0xF003;
    fn task_np() -> u64 {
        FAKE_TASK_NP
    }

    fd::__test_reset();
    install_task_id_lookup(task_np);

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    // ptr = 0 (null) → EFAULT = -14.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: 0, // null pointer
            arg2: 16,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    let expected = SyscallReturn::ok((-14i64) as u64);
    if ctx.ret != Some(expected) {
        return TestResult::Fail("sys_write with null ptr did not return EFAULT");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_smap_sys_write_null_efault);

/// Smoke 4: `sys_read` writes kernel-buf result back to a kernel-side
/// output buffer; verifies copy_to_user carries the correct bytes.
#[cfg(target_arch = "x86_64")]
fn smoke_smap_sys_read_kbuf_roundtrip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use narf_filesystem::{FileOps, FsFuture, Stat};

    static FAKE_TASK_R: u64 = 0xF004;
    fn task_r() -> u64 {
        FAKE_TASK_R
    }

    // FileOps that fills the kernel staging buffer with 0xCC.
    struct CcFile;
    impl FileOps for CcFile {
        fn read<'a>(&'a self, _o: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            buf.fill(0xCC);
            let n = buf.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn write<'a>(&'a self, _o: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            let n = buf.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    fd::__test_reset();
    install_task_id_lookup(task_r);
    let fd_n = fd::with_table(FAKE_TASK_R, |t| {
        t.open(FdEntry {
            ops: Arc::new(CcFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("with_table");

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    // Simulated "user" output buffer: kernel heap, all zeros initially.
    let mut out_buf = alloc::vec![0u8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: out_buf.as_mut_ptr() as u64,
            arg2: out_buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 16) {
        return TestResult::Fail("sys_read returned wrong count");
    }
    // copy_to_user must have written 0xCC into the output buffer.
    if out_buf.iter().any(|&b| b != 0xCC) {
        return TestResult::Fail("sys_read output buffer not filled with expected bytes");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_smap_sys_read_kbuf_roundtrip);

// ── uaccess: canonical-hole validation + fault-guarded user copy ────
//
// stress-ng --vma regression cluster. The old validate_user_range
// masked bit 63 out of the canonicality check and never examined the
// END of the range, so two classes of non-canonical access reached
// the raw kernel copy and #GP'd (non-canonical linear addresses are
// the one data-access fault x86_64 reports as #GP, not #PF):
//   - bases like 0x8000_0000_0000_0000 / 0x7FFF_8000_0000_0000
//   - a canonical user-half base + len crossing 0x0000_8000_0000_0000

fn smoke_uaccess_validate_canonical_holes() -> TestResult {
    use crate::handlers::validate_user_range;
    // Bit-63 escapes of the old bits-48..=62 check: both are
    // non-canonical and must be EFAULT-rejected up front.
    if validate_user_range(0x8000_0000_0000_0000, 8).is_ok() {
        return TestResult::Fail("bit-63-set non-canonical base passed validation");
    }
    if validate_user_range(0x7FFF_8000_0000_0000, 8).is_ok() {
        return TestResult::Fail("mid-bits-set non-canonical base passed validation");
    }
    // Range whose base is canonical but whose last byte crosses into
    // the canonical hole.
    if validate_user_range(0x0000_7FFF_FFFF_F000, 0x2000).is_ok() {
        return TestResult::Fail("range crossing the canonical hole passed validation");
    }
    // Flush-to-the-edge stays legal (last byte 0x0000_7FFF_FFFF_FFFF).
    if validate_user_range(0x0000_7FFF_FFFF_F000, 0x1000).is_err() {
        return TestResult::Fail("range ending exactly at the canonical edge rejected");
    }
    // Canonical KERNEL pointers must be rejected. This assertion used to
    // run the other way — "kernel-test code legitimately passes kernel
    // buffers through this path" — which is what made every syscall with a
    // caller-supplied (address, length, content) triple an arbitrary
    // kernel-write primitive: SMAP does not police a kernel page (PTE.U=0)
    // and the STAC bracket disables it anyway, so the copy landed silently
    // and returned Ok. See `validate_user_range` and
    // `abi_uaccess_tests.rs`. Kernel-test buffers now go through the
    // dynamically-scoped `kernel_buffers_guard()` opt-in instead, which is
    // deliberately NOT held here.
    let k_buf = 0u64;
    let k = &k_buf as *const u64 as u64;
    if k >= 0xFFFF_8000_0000_0000 && validate_user_range(k, 8).is_ok() {
        return TestResult::Fail("canonical kernel pointer accepted as a user range");
    }
    // Both ends of the kernel half, independent of where this build's
    // stack happens to live.
    if validate_user_range(0xFFFF_8000_0000_0000, 8).is_ok() {
        return TestResult::Fail("the first canonical kernel address passed validation");
    }
    if validate_user_range(0xFFFF_FFFF_FFFF_FFF0, 8).is_ok() {
        return TestResult::Fail("the top of the kernel half passed validation");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_uaccess_validate_canonical_holes);

#[cfg(target_arch = "x86_64")]
fn smoke_uaccess_guarded_copy_faults_to_efault() -> TestResult {
    // 512 GiB: canonical, and deliberately unmapped in the kernel
    // PML4 (PML4[1] is present but its PDPT[0] — the user-reserved
    // 512..513 GiB slot — is skipped; same address
    // memory::tests::smoke_probe_catches_page_fault relies on).
    // validate_user_range passes it, so this exercises the
    // copy_user_guarded probe path end-to-end: the #PF has no
    // demand-paging recovery, must redirect to the recovery label,
    // and copy_from_user must surface EFAULT — the old
    // with_user_access + copy_nonoverlapping path panicked the
    // kernel here.
    let mut buf = [0u8; 32];
    // SAFETY: dst is a live kernel buffer; surviving the bad src is
    // the guarded copy's contract.
    let r = unsafe { crate::handlers::copy_from_user(&mut buf, 0x0000_0080_0000_0000) };
    match r {
        Err(14) => TestResult::Pass,
        Err(_) => TestResult::Fail("guarded copy failed with a non-EFAULT errno"),
        Ok(()) => TestResult::Fail("copy from unmapped 512 GiB unexpectedly succeeded"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_uaccess_guarded_copy_faults_to_efault);
