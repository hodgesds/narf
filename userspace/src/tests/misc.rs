//! `misc` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

fn smoke_userspace_syscall_table_roundtrip() -> TestResult {
    use crate::{Syscall, SyscallTable};

    // Linux ABI numbering (per-arch).
    //
    // x86_64: numbers per `arch/x86/entry/syscalls/syscall_64.tbl`.
    // aarch64: numbers per `include/uapi/asm-generic/unistd.h`.
    // NARF extensions: 0x4000+ shared on every arch.
    #[cfg(target_arch = "x86_64")]
    {
        if Syscall::Read.raw() != 0 || Syscall::Write.raw() != 1 {
            return TestResult::Fail("x86_64 read/write numbers drifted");
        }
        if Syscall::from_raw(0) != Some(Syscall::Read) {
            return TestResult::Fail("from_raw(0) != Read");
        }
        if Syscall::from_raw(2) != Some(Syscall::OpenFile) {
            return TestResult::Fail("from_raw(2) != OpenFile");
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if Syscall::Read.raw() != 63 || Syscall::Write.raw() != 64 {
            return TestResult::Fail("aarch64 read/write numbers drifted");
        }
        if Syscall::from_raw(56) != Some(Syscall::Openat) {
            return TestResult::Fail("from_raw(56) != Openat");
        }
    }
    // NARF-only syscalls live in 0x4000+ regardless of arch.
    if Syscall::Submit.raw() & 0xFF00 != 0x4000 {
        return TestResult::Fail("Submit not in NARF range");
    }
    if Syscall::Bootstrap.raw() & 0xFF00 != 0x4000 {
        return TestResult::Fail("Bootstrap not in NARF range");
    }
    if Syscall::from_raw(0xDEADBEEF).is_some() {
        return TestResult::Fail("from_raw(0xDEADBEEF) should be None");
    }

    let mut t = SyscallTable::new();
    t.register(Syscall::Submit, "submit");
    t.register(Syscall::Bootstrap, "bootstrap");
    if t.len() != 2 {
        return TestResult::Fail("register did not grow table");
    }
    if t.name_of(Syscall::Submit) != Some("submit") {
        return TestResult::Fail("name_of mismatch");
    }
    if t.name_of(Syscall::Yield).is_some() {
        return TestResult::Fail("unregistered syscall should return None");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_syscall_table_roundtrip);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_shared_ring_kick_round_trip() -> TestResult {
    // Bootstrap mints a SharedRing pair + maps it into the user
    // AS. Drive it via the kernel-identity-mapped phys (which
    // matches the mapping a user task sees) by pushing a Noop into
    // the shared SQ, calling sys_ring_kick synchronously, and
    // reading the Completion back from the shared CQ.
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, shared_rings_for,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext, BOOTSTRAP_SHARED_RING_DEPTH,
    };
    use alloc::sync::Arc;
    use narf_abi::{
        NarfStatus, OpCode, SharedConsumer, SharedProducer, SharedRing, Submission, Tag,
    };
    use narf_memory::AddressSpace;

    static USER_AS_SR: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_SR.lock().clone()
    }
    static FAKE_TASK: u64 = 0xBABE;
    fn task_lookup() -> u64 {
        FAKE_TASK
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user"),
    };
    *USER_AS_SR.lock() = Some(addr_space);

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
    crate::fd::__test_reset();
    crate::bootstrap_init();
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Bootstrap.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("Bootstrap returned non-Ok");
    }
    let pair = match shared_rings_for(FAKE_TASK) {
        Some(p) => p,
        None => return TestResult::Fail("shared_rings_for None"),
    };

    type SqRing = SharedRing<Submission, BOOTSTRAP_SHARED_RING_DEPTH>;
    type CqRing = narf_abi::Completion;
    type CqRingT = SharedRing<CqRing, BOOTSTRAP_SHARED_RING_DEPTH>;

    // SAFETY: `pair.sq_phys` is the identity-mapped phys base of the SQ ring the
    // Bootstrap syscall just allocated with `BOOTSTRAP_SHARED_RING_DEPTH`, so it is
    // a valid, uniquely-owned `SqRing` for this producer to wrap.
    // SAFETY: Valid memory or trusted environment
    let mut sq_prod = unsafe {
        SharedProducer::<Submission, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.sq_phys.raw() as *mut SqRing
        )
    };
    let mut sub = Submission::noop(Tag::new(0xFEED));
    sub.op = OpCode::Noop;
    if sq_prod.try_send(sub).is_err() {
        return TestResult::Fail("shared SQ try_send");
    }

    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::RingKick.raw(), &mut ctx);
    let processed = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => return TestResult::Fail("RingKick non-Ok"),
    };
    if processed != 1 {
        return TestResult::Fail("RingKick processed != 1");
    }

    // SAFETY: `pair.cq_phys` is the identity-mapped phys base of the CQ ring the
    // Bootstrap syscall just allocated with `BOOTSTRAP_SHARED_RING_DEPTH`, so it is
    // a valid, uniquely-owned `CqRingT` for this consumer to wrap.
    // SAFETY: Valid memory or trusted environment
    let mut cq_cons = unsafe {
        SharedConsumer::<CqRing, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.cq_phys.raw() as *mut CqRingT
        )
    };
    let comp = match cq_cons.try_recv() {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("shared CQ try_recv"),
    };
    if comp.tag != 0xFEED {
        let msg = alloc::format!(
            "comp tag mismatch: got {:#x} want 0xfeed (status {:?}, processed {})",
            comp.tag,
            comp.status,
            processed,
        );
        let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
        return TestResult::Fail(s);
    }
    if comp.status != NarfStatus::Ok {
        return TestResult::Fail("comp status not Ok");
    }

    *USER_AS_SR.lock() = None;
    crate::fd::__test_reset();
    crate::handlers::__test_bootstrap_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", not(feature = "user-mode-e2e")))]
kernel_test_in!("userspace", smoke_userspace_shared_ring_kick_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_bootstrap_rings_round_trip() -> TestResult {
    // Full Bootstrap path: mint config page + ring pair, spawn
    // an `abi::Dispatcher` task on the kernel-side ends, and
    // drive a Noop submission round-trip from the user-side ends
    // (which the test takes via `take_user_ends`).
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{Dispatcher, NarfStatus, Submission, Tag};
    use narf_memory::AddressSpace;

    static USER_AS_RT: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn rt_as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_RT.lock().clone()
    }
    static FAKE_TASK: u64 = 0xBEEF;
    fn rt_task_lookup() -> u64 {
        FAKE_TASK
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    *USER_AS_RT.lock() = Some(addr_space);

    install_address_space_lookup(rt_as_lookup);
    install_task_id_lookup(rt_task_lookup);
    crate::bootstrap_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Fire Bootstrap.
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Bootstrap.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        *USER_AS_RT.lock() = None;
        __test_clear_global();
        crate::handlers::__test_bootstrap_reset();
        return TestResult::Fail("Bootstrap returned non-Ok");
    }

    // Take the kernel-side ring ends and spawn an abi::Dispatcher
    // on them. Take the user-side ends to drive the rings.
    let kernel_ends = match crate::take_kernel_ends(FAKE_TASK) {
        Some(e) => e,
        None => {
            *USER_AS_RT.lock() = None;
            __test_clear_global();
            crate::handlers::__test_bootstrap_reset();
            return TestResult::Fail("kernel ring ends missing post-Bootstrap");
        }
    };
    let user_ends = match crate::take_user_ends(FAKE_TASK) {
        Some(e) => e,
        None => {
            *USER_AS_RT.lock() = None;
            __test_clear_global();
            crate::handlers::__test_bootstrap_reset();
            return TestResult::Fail("user ring ends missing post-Bootstrap");
        }
    };

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(kernel_ends.sq_drain, kernel_ends.cq_prod);
        d.run().await;
    });
    narf_scheduler::spawn(async move {
        let mut sq = user_ends.sq_prod;
        let mut cq = user_ends.cq_drain;
        // Submit a Noop with tag 0xABCD.
        let tag = Tag::new(0xABCD);
        sq.send(Submission::noop(tag)).await.unwrap();
        let comp = cq.recv().await.unwrap();
        if comp.tag() == tag && comp.status == NarfStatus::Ok {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(2, Ordering::Relaxed);
        }
        // Drop our halves so the dispatcher's recv unblocks-into-EOF
        // and run_until_empty can drain.
        core::mem::drop(sq);
        core::mem::drop(cq);
    });

    narf_scheduler::run_until_empty();

    *USER_AS_RT.lock() = None;
    __test_clear_global();
    crate::handlers::__test_bootstrap_reset();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("completion didn't match submission tag/status"),
        _ => TestResult::Fail("user-side task didn't complete"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_bootstrap_rings_round_trip);

fn smoke_userspace_chdir_getcwd_round_trip() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // Verify the per-task cwd state round-trips through Chdir +
    // Getcwd. Drive both through the synthetic TrapContext path so
    // we exercise install_core_syscalls' slot wiring as well as
    // the handler bodies.
    use crate::{
        cwd_of, install_core_syscalls, install_global, install_task_id_lookup,
        kernel_syscall_entry, syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn,
        SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xCDD0);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    crate::handlers::__test_cwd_reset();
    crate::cwd_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // chdir now validates that the target is a real directory, so back
    // `/foo` with a mounted MemFs. Capture the handle so we can unmount
    // on every exit — a leaked MemFs grows the shared kernel-test heap.
    let foo_mount = {
        use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
        let auth = bootstrap_mount_authority();
        registry()
            .mount(&auth, "/foo", MemFs::with_seeds("foo-test", &[]))
            .ok()
    };
    let unmount_foo = || {
        if let Some(h) = &foo_mount {
            let _ = narf_filesystem::registry().unmount(h, "/foo");
        }
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    // Default cwd should be `/` even before any Chdir call.
    if cwd_of(FAKE_TASK.load(Ordering::Relaxed)).as_str() != "/" {
        __test_clear_global();
        crate::handlers::__test_cwd_reset();
        unmount_foo();
        return TestResult::Fail("default cwd was not /");
    }

    // Chdir("/foo") — Linux ABI: a single NUL-terminated path in arg0
    // (no length arg).
    let target: &str = "/foo\0";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Chdir.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_cwd_reset();
        unmount_foo();
        return TestResult::Fail("Chdir(/foo) did not Ok");
    }

    // Getcwd into a 16-byte buffer; expect length 4 and `/foo\0`.
    let mut buf = [0u8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getcwd.raw(), &mut ctx);
    let len_ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 4);
    let bytes_ok = &buf[..5] == b"/foo\0";

    // Buffer-too-small path: a 3-byte buf can't fit `/foo\0`. The
    // handler must surface InvalidOp without writing past the buf.
    let mut tiny = [0u8; 3];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: tiny.as_mut_ptr() as u64,
            arg1: tiny.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getcwd.raw(), &mut ctx);
    // Linux getcwd returns ERANGE when the buffer is too small for the path.
    let small_invalid = matches!(ctx.ret, Some(r) if (r.value as i64) == -34);

    // Nonexistent directory rejected. (Relative paths are now resolved
    // against the cwd; an absolute path with no backing dir fails the
    // existence check.) sys_chdir surfaces failure as `ok((-1i64) as
    // u64)` rather than `invalid_op`: the user-runtime asm wrapper only
    // observes the value register, so the -1 sentinel is the
    // wire-visible "no" the libc shim sees.
    let bad: &str = "/nonexistent\0";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: bad.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Chdir.raw(), &mut ctx);
    let rel_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );

    __test_clear_global();
    crate::handlers::__test_cwd_reset();
    unmount_foo();

    if !len_ok {
        return TestResult::Fail("Getcwd did not return length 4");
    }
    if !bytes_ok {
        return TestResult::Fail("Getcwd buffer did not match `/foo\\0`");
    }
    if !small_invalid {
        return TestResult::Fail("Getcwd with too-small buf did not surface ERANGE");
    }
    if !rel_rejected {
        return TestResult::Fail("Chdir(relative) did not surface -1 sentinel");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_chdir_getcwd_round_trip);

fn smoke_userspace_syscall_dispatch_via_global() -> TestResult {
    // Install a global table with a live plain handler for
    // Syscall::Yield; kernel_syscall_entry_plain(104, …) routes
    // to it. Unregistered numbers return invalid_op.
    use crate::{
        install_global, kernel_syscall_entry_plain, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    __test_clear_global();

    static SEEN_ARG: AtomicU64 = AtomicU64::new(0);
    SEEN_ARG.store(0, Ordering::Relaxed);

    let mut table = SyscallTable::new();
    table.install_fn(Syscall::Yield, "yield", |args: &SyscallArgs| {
        SEEN_ARG.store(args.arg0, Ordering::Relaxed);
        SyscallReturn::ok(args.arg0.wrapping_add(1))
    });
    install_global(table);

    // Happy path.
    let args = SyscallArgs {
        arg0: 0x41,
        ..SyscallArgs::default()
    };
    let r = kernel_syscall_entry_plain(Syscall::Yield.raw(), &args);
    if r != SyscallReturn::ok(0x42) {
        __test_clear_global();
        return TestResult::Fail("registered handler return mismatch");
    }
    if SEEN_ARG.load(Ordering::Relaxed) != 0x41 {
        __test_clear_global();
        return TestResult::Fail("handler did not observe args.arg0");
    }

    // Unknown number → invalid_op.
    let r2 = kernel_syscall_entry_plain(999, &args);
    if r2 != SyscallReturn::invalid_op() {
        __test_clear_global();
        return TestResult::Fail("unknown number did not surface invalid_op");
    }

    // Known number without a handler → invalid_op.
    let r3 = kernel_syscall_entry_plain(Syscall::Write.raw(), &args);
    if r3 != SyscallReturn::invalid_op() {
        __test_clear_global();
        return TestResult::Fail("handler-less number did not surface invalid_op");
    }

    // After __test_clear_global, every entry returns invalid_op —
    // pre-boot / post-shutdown safety.
    __test_clear_global();
    let r4 = kernel_syscall_entry_plain(Syscall::Yield.raw(), &args);
    if r4 != SyscallReturn::invalid_op() {
        return TestResult::Fail("no global should surface invalid_op");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_syscall_dispatch_via_global);

fn smoke_userspace_raw_handler_dispatch() -> TestResult {
    // Install a RawSyscallHandler and confirm it observes the
    // TrapContext, can set the return, and (on x86_64) can ask to
    // redirect to kernel — though we only exercise the non-redirect
    // path synchronously here since actual redirection requires a
    // live trap frame.
    use crate::{
        install_global, syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn,
        SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    __test_clear_global();
    static SEEN: AtomicU64 = AtomicU64::new(0);
    SEEN.store(0, Ordering::Relaxed);

    let mut t = SyscallTable::new();
    t.install_raw_fn(Syscall::Yield, "yield_raw", |ctx: &mut dyn TrapContext| {
        SEEN.store(ctx.args().arg0, Ordering::Relaxed);
        ctx.set_return(SyscallReturn::ok(ctx.args().arg0.wrapping_add(10)));
    });
    install_global(t);

    // Synthetic TrapContext — not a live trap, just exercising the
    // dispatch path.
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
        redirect_attempts: u32,
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
            self.redirect_attempts += 1;
            true
        }
    }

    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 5,
            ..Default::default()
        },
        ret: None,
        redirect_attempts: 0,
    };
    crate::kernel_syscall_entry(Syscall::Yield.raw(), &mut ctx);

    if SEEN.load(Ordering::Relaxed) != 5 {
        __test_clear_global();
        return TestResult::Fail("raw handler did not see args.arg0");
    }
    if ctx.ret != Some(SyscallReturn::ok(15)) {
        __test_clear_global();
        return TestResult::Fail("raw handler return not delivered via set_return");
    }

    // Raw handler wins over a plain handler on the same slot.
    __test_clear_global();
    let mut t2 = SyscallTable::new();
    t2.install_fn(Syscall::Sleep, "sleep_plain", |_| SyscallReturn::ok(111));
    t2.install_raw_fn(Syscall::Sleep, "sleep_raw", |ctx: &mut dyn TrapContext| {
        ctx.set_return(SyscallReturn::ok(222));
    });
    install_global(t2);
    let mut ctx2 = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
        redirect_attempts: 0,
    };
    crate::kernel_syscall_entry(Syscall::Sleep.raw(), &mut ctx2);
    if ctx2.ret != Some(SyscallReturn::ok(222)) {
        __test_clear_global();
        return TestResult::Fail("raw handler did not win over plain handler");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_raw_handler_dispatch);

fn smoke_userspace_process_id_and_aux() -> TestResult {
    use crate::{alloc_pid, AuxEntry, ExecImage, ExecKind, ProcessId, Segment, SegmentFlags};

    if ProcessId::KERNEL.raw() != 0 {
        return TestResult::Fail("KERNEL pid reservation wrong");
    }
    let a = alloc_pid();
    let b = alloc_pid();
    if a == b || a.raw() == 0 || b.raw() == 0 {
        return TestResult::Fail("alloc_pid did not mint distinct non-zero ids");
    }

    // Aux tag values match <elf.h>.
    assert!(AuxEntry::Null.tag() == 0);
    assert!(AuxEntry::Entry(0).tag() == 9);
    assert!(AuxEntry::Pagesz(4096).tag() == 6);

    // Segment flags compose.
    let rx = SegmentFlags::READ | SegmentFlags::EXEC;
    if !rx.contains(SegmentFlags::READ) || !rx.contains(SegmentFlags::EXEC) {
        return TestResult::Fail("SegmentFlags::contains broken");
    }
    if rx.contains(SegmentFlags::WRITE) {
        return TestResult::Fail("RX flags should not contain WRITE");
    }

    let mut img = ExecImage::empty(ExecKind::Elf64Dyn);
    img.entry = 0x4000;
    img.segments.push(Segment {
        vaddr: 0x4000,
        file_off: 0,
        file_size: 0x1000,
        mem_size: 0x1000,
        flags: rx,
    });
    if img.entry != 0x4000 || img.segments.len() != 1 {
        return TestResult::Fail("ExecImage assembly broke");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_process_id_and_aux);

fn smoke_userspace_setuid_setgid_round_trip() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        uidgid_init, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    uidgid_init();

    fn call(s: Syscall, arg0: u64) -> Option<SyscallReturn> {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(s.raw(), &mut ctx);
        ctx.ret
    }

    // Default identity is (0, 0).
    let u0 = call(Syscall::GetUid, 0).map(|r| r.value).unwrap_or(!0);
    let g0 = call(Syscall::GetGid, 0).map(|r| r.value).unwrap_or(!0);
    if u0 != 0 || g0 != 0 {
        return TestResult::Fail("default uid/gid not (0, 0)");
    }

    // setuid(1234) → getuid sees 1234; gid unchanged.
    let _ = call(Syscall::SetUid, 1234);
    let u1 = call(Syscall::GetUid, 0).map(|r| r.value).unwrap_or(!0);
    let g1 = call(Syscall::GetGid, 0).map(|r| r.value).unwrap_or(!0);
    if u1 != 1234 || g1 != 0 {
        return TestResult::Fail("setuid did not stick");
    }

    // setgid(56) → getgid sees 56; uid unchanged.
    let _ = call(Syscall::SetGid, 56);
    let u2 = call(Syscall::GetUid, 0).map(|r| r.value).unwrap_or(!0);
    let g2 = call(Syscall::GetGid, 0).map(|r| r.value).unwrap_or(!0);
    if u2 != 1234 || g2 != 56 {
        return TestResult::Fail("setgid did not stick / overwrote uid");
    }

    crate::handlers::__test_uidgid_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_setuid_setgid_round_trip);

fn smoke_userspace_rlimit_round_trip() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, rlimit_init,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::handlers::__test_rlimit_reset();
    rlimit_init();

    // Default RLIMIT_NOFILE (resource 7) is (1024, 4096).
    let mut out = [0u64; 2];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 7,
            arg1: out.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getrlimit.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getrlimit(NOFILE) did not return OK");
    }
    if out != [1024, 4096] {
        return TestResult::Fail("default RLIMIT_NOFILE not (1024, 4096)");
    }

    // Default RLIMIT_STACK (resource 3) is (8 MiB, INFINITY).
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 3,
            arg1: out.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getrlimit.raw(), &mut ctx);
    if out != [8 * 1024 * 1024, !0u64] {
        return TestResult::Fail("default RLIMIT_STACK not (8 MiB, INFINITY)");
    }

    // setrlimit(NOFILE, (1024, 2048)) sticks across a re-read.
    let new_pair: [u64; 2] = [1024, 2048];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 7,
            arg1: new_pair.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Setrlimit.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("setrlimit did not return OK");
    }

    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 7,
            arg1: out.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getrlimit.raw(), &mut ctx);
    if out != [1024, 2048] {
        return TestResult::Fail("setrlimit did not stick");
    }

    // Linux validates the resource number before touching the output pointer
    // and reports the precise errno, EINVAL.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 99,
            arg1: out.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getrlimit.raw(), &mut ctx);
    let bad_resource_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-22i64) as u64,
    );
    if !bad_resource_rejected {
        return TestResult::Fail("getrlimit(99) was not rejected");
    }

    crate::handlers::__test_rlimit_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_rlimit_round_trip);

fn smoke_userspace_priority_round_trip() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, nice_init,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::handlers::__test_nice_reset();
    nice_init();

    fn call(s: Syscall, arg0: u64, arg1: u64, arg2: u64) -> Option<SyscallReturn> {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0,
                arg1,
                arg2,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(s.raw(), &mut ctx);
        ctx.ret
    }

    // Default nice = 0 → wire value 20 (0 + 20 shift).
    let r = call(Syscall::Getpriority, 0, 0, 0)
        .map(|r| r.value)
        .unwrap_or(!0);
    if r != 20 {
        return TestResult::Fail("default nice wire value not 20");
    }

    // setpriority(PRIO_PROCESS, 0, 5).
    let r = call(Syscall::Setpriority, 0, 0, 5);
    if !matches!(r, Some(rr) if rr.status == SyscallReturn::OK && rr.value == 0) {
        return TestResult::Fail("setpriority(5) did not return OK");
    }

    // Re-read: wire value = 25 (5 + 20).
    let r = call(Syscall::Getpriority, 0, 0, 0)
        .map(|r| r.value)
        .unwrap_or(!0);
    if r != 25 {
        return TestResult::Fail("setpriority did not stick");
    }

    // Out-of-range nice rejected.
    let r = call(Syscall::Setpriority, 0, 0, 100);
    let bad_rejected = matches!(
        r,
        Some(rr) if rr.status == SyscallReturn::OK && rr.value == (-1i64) as u64,
    );
    if !bad_rejected {
        return TestResult::Fail("setpriority(100) was not rejected");
    }

    // Bad which (1 = PRIO_PGRP) rejected.
    let r = call(Syscall::Getpriority, 1, 0, 0);
    let bad_which = matches!(
        r,
        Some(rr) if rr.status == SyscallReturn::OK && rr.value == (-1i64) as u64,
    );
    if !bad_which {
        return TestResult::Fail("getpriority(PRIO_PGRP) was not rejected");
    }

    crate::handlers::__test_nice_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_priority_round_trip);

fn smoke_userspace_umask_round_trip() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        umask_init, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::handlers::__test_umask_reset();
    umask_init();

    fn call(arg0: u64) -> u64 {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Umask.raw(), &mut ctx);
        ctx.ret.map(|r| r.value).unwrap_or(!0)
    }

    // First umask call: returns the default 0o022, sets new = 0o077.
    let first = call(0o077);
    if first != 0o022 {
        return TestResult::Fail("first umask did not return default 0o022");
    }
    // Second call: returns the just-set 0o077, sets new = 0o002.
    let second = call(0o002);
    if second != 0o077 {
        return TestResult::Fail("umask did not stick");
    }
    // High bits dropped: 0o7777 → low 9 bits = 0o777.
    let _ = call(0o7777);
    let after = call(0o022);
    if after != 0o777 {
        return TestResult::Fail("umask did not mask to low 9 bits");
    }

    crate::handlers::__test_umask_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_umask_round_trip);

fn smoke_userspace_sched_affinity_round_trip() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    narf_scheduler::__reset_queues_for_test();
    let spec = narf_scheduler::TaskSpec {
        affinity: narf_scheduler::Affinity::any(),
        ..narf_scheduler::TaskSpec::unthrottled()
    };
    let target = narf_scheduler::spawn_with_spec(core::future::pending::<()>(), spec);

    // Linux copies the kernel mask width (8), not the caller's entire buffer.
    let mut mask = [0xFFu8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target.raw(),
            arg1: mask.len() as u64,
            arg2: mask.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::SchedGetaffinity.raw(), &mut ctx);
    let n = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => return TestResult::Fail("sched_getaffinity did not return OK"),
    };
    if n != 8 {
        return TestResult::Fail("sched_getaffinity byte-count != kernel mask width");
    }
    if u64::from_ne_bytes(mask[..8].try_into().unwrap()) != narf_lib::smp::online_bitmap() {
        return TestResult::Fail("sched_getaffinity did not report online allowed CPUs");
    }
    if mask[8..].iter().any(|&b| b != 0xFF) {
        return TestResult::Fail("sched_getaffinity overwrote beyond kernel mask");
    }

    // sched_setaffinity updates the target task's real hard mask.
    let mut in_mask = [0u8; 16];
    in_mask[0] = 1;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target.raw(),
            arg1: in_mask.len() as u64,
            arg2: in_mask.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::SchedSetaffinity.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("sched_setaffinity did not return 0");
    }
    if narf_scheduler::task_affinity(target)
        != Some(narf_scheduler::CpuSet::single(narf_scheduler::CpuId::BOOT))
    {
        return TestResult::Fail("sched_setaffinity did not update scheduler state");
    }

    // Tiny size rejected.
    let mut tiny = [0u8; 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target.raw(),
            arg1: tiny.len() as u64,
            arg2: tiny.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::SchedGetaffinity.raw(), &mut ctx);
    let tiny_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-22i64) as u64,
    );
    if !tiny_rejected {
        return TestResult::Fail("sched_getaffinity did not reject tiny buf");
    }

    narf_scheduler::__reset_queues_for_test();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_sched_affinity_round_trip);

fn smoke_userspace_prctl_name_round_trip() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, prctl_init,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::handlers::__test_prctl_reset();
    prctl_init();

    fn call(op: u64, a: u64) -> Option<SyscallReturn> {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: op,
                arg1: a,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Prctl.raw(), &mut ctx);
        ctx.ret
    }

    // PR_SET_NAME = 15, PR_GET_NAME = 16.
    let want = b"hello-task\0";
    let r = call(15, want.as_ptr() as u64);
    if !matches!(r, Some(rr) if rr.status == SyscallReturn::OK && rr.value == 0) {
        return TestResult::Fail("PR_SET_NAME did not return 0");
    }

    let mut buf = [0u8; 16];
    let r = call(16, buf.as_mut_ptr() as u64);
    if !matches!(r, Some(rr) if rr.status == SyscallReturn::OK && rr.value == 0) {
        return TestResult::Fail("PR_GET_NAME did not return 0");
    }
    if &buf[..10] != b"hello-task" || buf[10] != 0 {
        return TestResult::Fail("PR_GET_NAME did not retrieve the set name");
    }

    // PR_SET_DUMPABLE / PR_GET_DUMPABLE round-trip.
    let _ = call(4, 0); // set dumpable = false
    let r = call(3, 0).map(|r| r.value).unwrap_or(!0);
    if r != 0 {
        return TestResult::Fail("PR_SET_DUMPABLE(false) did not stick");
    }
    let _ = call(4, 1);
    let r = call(3, 0).map(|r| r.value).unwrap_or(!0);
    if r != 1 {
        return TestResult::Fail("PR_SET_DUMPABLE(true) did not stick");
    }

    // Unknown op rejected with -EINVAL (Linux's answer for an unrecognised
    // prctl option; NOT the -1/EPERM sentinel).
    let r = call(99, 0);
    let unknown_rejected = matches!(
        r,
        Some(rr) if rr.status == SyscallReturn::OK && rr.value == (-22i64) as u64,
    );
    if !unknown_rejected {
        return TestResult::Fail("prctl(99) must return -EINVAL");
    }

    crate::handlers::__test_prctl_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_prctl_name_round_trip);

fn smoke_userspace_futex_wait_and_wake_no_op() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    fn call(op: u64) -> Option<SyscallReturn> {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: 0,
                arg1: op,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Futex.raw(), &mut ctx);
        ctx.ret
    }

    // FUTEX_WAIT (0) → 0.
    if !matches!(call(0), Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("FUTEX_WAIT did not return 0");
    }
    // FUTEX_WAKE (1) → 0.
    if !matches!(call(1), Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("FUTEX_WAKE did not return 0");
    }
    // FUTEX_WAIT | FUTEX_PRIVATE (0x80) → 0 (private bit stripped).
    if !matches!(call(0x80), Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("FUTEX_WAIT_PRIVATE did not return 0");
    }
    // Unsupported op → -1.
    let r = call(99);
    let unknown_rejected = matches!(
        r,
        Some(rr) if rr.status == SyscallReturn::OK && rr.value == (-1i64) as u64,
    );
    if !unknown_rejected {
        return TestResult::Fail("futex(99) was not rejected");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_futex_wait_and_wake_no_op);

/// FUTEX_WAIT is a seqlock read: the per-uaddr wake generation MUST be sampled
/// BEFORE the futex word is read, so that a FUTEX_WAKE racing between the word
/// read and the waiter's park is caught by the park guard (`futex_gen(uaddr)
/// != park_gen`). Regression for the intermittent SMP lost-wakeup: sampling
/// the generation AFTER the word read captured the POST-wake value, the waiter
/// parked, the guard saw "no change", and a contended pthread mutex/condvar
/// deadlocked (`futex_contend_smoke` hung under the 16-vCPU topology; clean at
/// SMP=1, where no waker can run in the read→park window).
///
/// `futex_wait_seqlock_read` takes the word read as a closure; here the
/// closure BUMPS the generation while it runs, modelling a wake landing
/// EXACTLY during the read. A correct (gen-before-value) implementation
/// returns the PRE-bump generation, so the live generation is now strictly
/// ahead of the snapshot → the guard fires. The old (value-before-gen) bug
/// returned the post-bump generation, equal to the live one → guard misses.
fn smoke_userspace_futex_wait_seqlock_gen_before_value() -> TestResult {
    use crate::handlers::{__test_futex_bump_counter, futex_gen, futex_wait_seqlock_read};

    // A uaddr no other test touches. Reason about deltas, not absolutes: the
    // per-uaddr counter is process-global and never reset.
    const U: u64 = 0x5EC0_1000;
    let base = futex_gen(U);

    // Seqlock read whose word-read closure injects a racing FUTEX_WAKE (a
    // generation bump) at the instant it runs.
    let (gen, val) = match futex_wait_seqlock_read(U, || {
        __test_futex_bump_counter(U); // a wake races DURING the value read
        Some(0x1234)
    }) {
        Some(x) => x,
        None => return TestResult::Fail("seqlock read reported a spurious fault"),
    };

    if val != 0x1234 {
        return TestResult::Fail("seqlock read returned the wrong word value");
    }
    // The generation was sampled BEFORE the closure's bump → equals the
    // pre-read baseline, NOT the bumped value. This is the whole fix.
    if gen != base {
        return TestResult::Fail(
            "gen sampled AFTER the word read — a racing FUTEX_WAKE would be lost",
        );
    }
    // Because the sample predates the bump, the live generation is now ahead
    // of the snapshot → the park guard (`live != park_gen`) fires and the
    // waiter re-checks instead of parking (no lost wake, no SMP deadlock).
    if futex_gen(U) == gen {
        return TestResult::Fail("park guard would MISS the racing wake (gen not advanced)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_futex_wait_seqlock_gen_before_value
);

/// Complement to the ordering test: with NO wake racing the read, the
/// generation the waiter would park on equals the live generation, so the
/// guard does NOT false-fire (a spurious re-check on every uncontended wait
/// would defeat the point of blocking). Pins that `futex_wait_seqlock_read`
/// only reports a change when one genuinely happened.
fn smoke_userspace_futex_wait_seqlock_no_false_wake() -> TestResult {
    use crate::handlers::{futex_gen, futex_wait_seqlock_read};

    const U: u64 = 0x5EC0_2000;
    let base = futex_gen(U);
    let (gen, val) = match futex_wait_seqlock_read(U, || Some(9)) {
        Some(x) => x,
        None => return TestResult::Fail("seqlock read reported a spurious fault"),
    };
    if val != 9 {
        return TestResult::Fail("seqlock read returned the wrong word value");
    }
    if gen != base {
        return TestResult::Fail("gen snapshot moved without any wake");
    }
    // No race → the park guard sees `live == park_gen` → the waiter parks.
    if futex_gen(U) != gen {
        return TestResult::Fail("live gen advanced with no FUTEX_WAKE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_futex_wait_seqlock_no_false_wake
);

/// `FUTEX_REQUEUE` core semantics: wake up to `nr_wake` waiters on the
/// source word, MOVE up to `nr_requeue` more onto the destination word's
/// queue WITHOUT firing their wakers, and bump the source generation so a
/// registration racing the requeue re-checks. musl's condvar broadcast
/// handoff (`unlock_requeue`: store the barrier word, then requeue the
/// still-parked next waiter onto the mutex) depends on exactly this; the
/// old `_ => -1` arm silently dropped the move and permanently stranded
/// every broadcast waiter past the first (`condbcast_smoke` hang — the
/// permanent form of the SMP scheduler-resume strand).
fn smoke_userspace_futex_requeue_moves_waiters() -> TestResult {
    use crate::handlers::{
        __test_futex_bucket_index, __test_futex_requeue, __test_futex_waiter_count, futex_gen,
        futex_register_waiter, futex_wake_waiters_for_test,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    // Counting waker: an Arc<AtomicU32> bumped by wake/wake_by_ref.
    fn counting_waker(counter: Arc<AtomicU32>) -> Waker {
        unsafe fn clone_raw(d: *const ()) -> RawWaker {
            // SAFETY: `d` came from Arc::into_raw in counting_waker/clone_raw.
            let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
            let cloned = arc.clone();
            let _ = Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(cloned) as *const (), &VTAB)
        }
        unsafe fn wake_raw(d: *const ()) {
            // SAFETY: consumes the refcount handed to this waker.
            let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
            arc.fetch_add(1, Ordering::AcqRel);
        }
        unsafe fn wake_ref_raw(d: *const ()) {
            // SAFETY: caller still owns the waker (and its refcount).
            unsafe { (*(d as *const AtomicU32)).fetch_add(1, Ordering::AcqRel) };
        }
        unsafe fn drop_raw(d: *const ()) {
            // SAFETY: consumes the refcount owned by this waker.
            unsafe { drop(Arc::<AtomicU32>::from_raw(d as *const AtomicU32)) };
        }
        static VTAB: RawWakerVTable =
            RawWakerVTable::new(clone_raw, wake_raw, wake_ref_raw, drop_raw);
        // SAFETY: vtable matches the Arc<AtomicU32> representation.
        unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(counter) as *const (), &VTAB)) }
    }

    // Words no other test touches.
    const U1: u64 = 0x5EC0_3000;
    const U2: u64 = 0x5EC0_3004;

    if __test_futex_bucket_index(0, U1) == __test_futex_bucket_index(0, U2) {
        return TestResult::Fail("requeue smoke no longer exercises two futex buckets");
    }

    let c1 = Arc::new(AtomicU32::new(0));
    let c2 = Arc::new(AtomicU32::new(0));
    futex_register_waiter(U1, 9001, counting_waker(c1.clone()));
    futex_register_waiter(U1, 9002, counting_waker(c2.clone()));

    let gen1_before = futex_gen(U1);
    // Wake 1, requeue 1 → BTreeMap order pops the lowest tid (9001) for the
    // wake and moves 9002.
    let (woken, moved) = __test_futex_requeue(U1, U2, 1, 1);
    if (woken, moved) != (1, 1) {
        return TestResult::Fail("requeue did not report (1 woken, 1 moved)");
    }
    if futex_gen(U1) != gen1_before + 1 {
        return TestResult::Fail("requeue did not bump the source wake generation");
    }
    if c1.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("the woken waiter's waker did not fire");
    }
    if c2.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("the REQUEUED waiter was woken — requeue must move, not wake");
    }
    if __test_futex_waiter_count(U1) != 0 || __test_futex_waiter_count(U2) != 1 {
        return TestResult::Fail("waiter queues after requeue are wrong");
    }
    // A later wake on the DESTINATION word reaches the moved waiter.
    if futex_wake_waiters_for_test(U2, u32::MAX) != 1 || c2.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("wake on the destination word did not reach the moved waiter");
    }

    // Also cover the single-lock path when two distinct keys hash to one
    // bucket; requeue must not try to lock that bucket recursively.
    const U3: u64 = 0x5EC0_4000;
    const U4: u64 = 0x5EC0_4044;
    if __test_futex_bucket_index(0, U3) != __test_futex_bucket_index(0, U4) {
        return TestResult::Fail("same-bucket requeue constants no longer share a bucket");
    }
    let c3 = Arc::new(AtomicU32::new(0));
    futex_register_waiter(U3, 9003, counting_waker(c3.clone()));
    if __test_futex_requeue(U3, U4, 0, 1) != (0, 1) {
        return TestResult::Fail("same-bucket requeue did not move one waiter");
    }
    if __test_futex_waiter_count(U3) != 0 || __test_futex_waiter_count(U4) != 1 {
        return TestResult::Fail("same-bucket waiter queues after requeue are wrong");
    }
    if futex_wake_waiters_for_test(U4, 1) != 1 || c3.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("same-bucket destination wake missed moved waiter");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_futex_requeue_moves_waiters);

/// The park loop's stay-parked decision (`futex_park_should_stay`) must
/// re-validate the futex WORD, not just the wake generation. A word
/// rewritten WITHOUT a wake on it (musl `unlock_requeue`'s barrier store,
/// robust-owner death) previously re-parked the waiter forever: the ~10 ms
/// wheel backstop woke the task, the gen guard saw "no wake", and the park
/// loop swallowed the re-check inside the kernel without ever re-reading
/// the word — converting a one-tick latency blip into a permanent strand.
fn smoke_userspace_futex_park_word_revalidation() -> TestResult {
    use crate::handlers::futex_park_should_stay;

    // Unchanged gen + unchanged word → keep blocking.
    if !futex_park_should_stay(7, 7, Some(2), 2) {
        return TestResult::Fail("unchanged gen+word must stay parked");
    }
    // A wake generation advanced → proceed (classic gen guard).
    if futex_park_should_stay(8, 7, Some(2), 2) {
        return TestResult::Fail("advanced gen must unpark");
    }
    // The WORD changed with no wake (requeue handoff) → proceed. This is
    // the case that used to strand forever.
    if futex_park_should_stay(7, 7, Some(0), 2) {
        return TestResult::Fail("silently-rewritten word must unpark");
    }
    // Word unreadable (AS torn down / unmapped) → never re-park on memory
    // we cannot re-check.
    if futex_park_should_stay(7, 7, None, 2) {
        return TestResult::Fail("unreadable word must unpark");
    }
    TestResult::Pass
}

fn smoke_userspace_private_futex_namespaces_isolate_same_uaddr() -> TestResult {
    use crate::handlers::{__test_futex_register_waiter_scoped, __test_futex_wake_scoped};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    fn scoped_counting_waker(counter: Arc<AtomicU32>) -> Waker {
        unsafe fn clone_raw(d: *const ()) -> RawWaker {
            // SAFETY: `d` was produced by `Arc::into_raw` below; this
            // temporary reconstruction is balanced by converting it back.
            let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
            let cloned = arc.clone();
            let _ = Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(cloned) as *const (), &VTAB)
        }
        unsafe fn wake_raw(d: *const ()) {
            // SAFETY: `d` owns one strong reference transferred by the
            // RawWaker contract, which this consuming wake releases.
            let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
            arc.fetch_add(1, Ordering::AcqRel);
        }
        unsafe fn wake_ref_raw(d: *const ()) {
            // SAFETY: the RawWaker retains a live strong reference for the
            // duration of this non-consuming wake.
            unsafe { (*(d as *const AtomicU32)).fetch_add(1, Ordering::AcqRel) };
        }
        unsafe fn drop_raw(d: *const ()) {
            // SAFETY: `d` owns the strong reference transferred into the
            // RawWaker and drop is called exactly once for that reference.
            unsafe { drop(Arc::<AtomicU32>::from_raw(d as *const AtomicU32)) };
        }
        static VTAB: RawWakerVTable =
            RawWakerVTable::new(clone_raw, wake_raw, wake_ref_raw, drop_raw);
        // SAFETY: the vtable consistently treats `d` as an Arc<AtomicU32>
        // raw pointer and follows RawWaker ownership rules.
        unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(counter) as *const (), &VTAB)) }
    }

    const UADDR: u64 = 0x7fff_ffff_f450;
    let a = Arc::new(AtomicU32::new(0));
    let b = Arc::new(AtomicU32::new(0));
    __test_futex_register_waiter_scoped(0xA, UADDR, 41, scoped_counting_waker(a.clone()));
    __test_futex_register_waiter_scoped(0xB, UADDR, 42, scoped_counting_waker(b.clone()));

    if __test_futex_wake_scoped(0xA, UADDR, 1) != 1 {
        return TestResult::Fail("private futex wake did not find same-AS waiter");
    }
    if a.load(Ordering::Acquire) != 1 || b.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("private futex wake crossed address-space namespace");
    }
    let _ = __test_futex_wake_scoped(0xB, UADDR, 1);
    TestResult::Pass
}

kernel_test_in!(
    "userspace/futex",
    smoke_userspace_private_futex_namespaces_isolate_same_uaddr
);

/// A `FUTEX_WAIT` that ends WITHOUT a `FUTEX_WAKE` (timeout expiry, pending
/// signal, wheel-full bailout) must remove its waker from the per-uaddr wait
/// queue, exactly like Linux: `__futex_wait` calls `futex_unqueue(&q)` on
/// every non-woken exit path (kernel/futex/waitwake.c — "If we were woken
/// (and unqueued), we succeeded"; otherwise unqueue → -ETIMEDOUT/-ERESTARTSYS),
/// so a later `futex_wake(nr=1)` can only ever wake a CURRENT waiter.
///
/// NARF's park-loop unpark paths (`park_should_block`'s deadline-reached
/// cleanup and `UserTaskFuture::poll`'s twin) clear `futex_uaddr` but never
/// call `futex_drop_waiter_key`, leaving a GHOST entry. A later
/// `FUTEX_WAKE(word, 1)` — e.g. glibc `pthread_cond_signal` — pops the ghost,
/// reports 1 woken, force-clears the ghost task's CURRENT park deadline
/// (`wake_one`), and does NOT wake the real waiter, which then rides the
/// ~10 ms wheel backstop instead of the wake. Drives the REAL
/// `park_should_block` (via `__test_park_should_block`) through a park and a
/// timeout-expiry unpark, then pins the Linux invariant: nothing may remain
/// on the queue.
#[cfg(target_arch = "x86_64")]
fn smoke_userspace_futex_timeout_unpark_unqueues_waiter() -> TestResult {
    use crate::handlers::{
        dbg_futex_waiter_registered, futex_gen, futex_wake_waiters_for_test, with_kernel_buffers,
    };
    use crate::user_task::{UserTaskCtx, __test_park_should_block};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    fn counting_waker(counter: Arc<AtomicU32>) -> Waker {
        unsafe fn clone_raw(d: *const ()) -> RawWaker {
            // SAFETY: `d` came from Arc::into_raw below; the temporary
            // reconstruction is balanced by converting it back.
            let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
            let cloned = arc.clone();
            let _ = Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(cloned) as *const (), &VTAB)
        }
        unsafe fn wake_raw(d: *const ()) {
            // SAFETY: consumes the strong reference owned by this waker.
            let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
            arc.fetch_add(1, Ordering::AcqRel);
        }
        unsafe fn wake_ref_raw(d: *const ()) {
            // SAFETY: the waker retains its strong reference across this call.
            unsafe { (*(d as *const AtomicU32)).fetch_add(1, Ordering::AcqRel) };
        }
        unsafe fn drop_raw(d: *const ()) {
            // SAFETY: releases the strong reference owned by this waker.
            unsafe { drop(Arc::<AtomicU32>::from_raw(d as *const AtomicU32)) };
        }
        static VTAB: RawWakerVTable =
            RawWakerVTable::new(clone_raw, wake_raw, wake_ref_raw, drop_raw);
        // SAFETY: vtable matches the Arc<AtomicU32> representation.
        unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(counter) as *const (), &VTAB)) }
    }

    // The futex word lives on the kernel stack; `with_kernel_buffers` lets
    // `futex_read_user_word`'s copy_from_user accept it (same opt-in the ABI
    // smokes use for their fixtures).
    let word: u32 = 7;
    let uaddr = &word as *const u32 as u64;
    let woken = Arc::new(AtomicU32::new(0));
    let waker = counting_waker(woken);
    let uc = UserTaskCtx::new();
    let now = narf_scheduler::narf_time::monotonic_ns();

    // Publish the exact park state sys_futex's FUTEX_WAIT arm publishes
    // (sys_futex.rs): expected value, gen snapshot, uaddr, finite deadline.
    uc.futex_uaddr.store(uaddr, Ordering::Release);
    uc.futex_namespace.store(0, Ordering::Release);
    uc.futex_val.store(7, Ordering::Release);
    uc.futex_park_gen.store(futex_gen(uaddr), Ordering::Release);
    uc.sleep_deadline_ns
        .store(now.saturating_add(60_000_000_000), Ordering::Release);

    let mut sleep_handle = None;
    let tid = crate::handlers::current_task_id();
    let blocked = with_kernel_buffers(|| __test_park_should_block(&uc, &waker, &mut sleep_handle));
    if blocked {
        // Parked: the loop registered our waker on the word's wait queue.
        if !dbg_futex_waiter_registered(0, uaddr, tid) {
            let _ = futex_wake_waiters_for_test(uaddr, u32::MAX);
            return TestResult::Fail("setup: park loop parked without registering the waiter");
        }
        // The timed wait expires (the wheel backstop re-poll re-runs the
        // park decision with the deadline in the past).
        uc.sleep_deadline_ns.store(1, Ordering::Release);
        if with_kernel_buffers(|| __test_park_should_block(&uc, &waker, &mut sleep_handle)) {
            let _ = futex_wake_waiters_for_test(uaddr, u32::MAX);
            return TestResult::Fail("setup: park loop did not break at an expired deadline");
        }
    } else if !dbg_futex_waiter_registered(0, uaddr, tid) {
        // Neither parked nor registered (e.g. a pending signal for the
        // kernel-test tid broke the park before the futex arm ran) — the
        // scenario under test was never reached.
        return TestResult::Fail("setup: park loop never reached the futex arm");
    }

    // The wait ended with NO FUTEX_WAKE on the word. Linux parity
    // (futex_unqueue): the queue is empty; a later FUTEX_WAKE finds nobody.
    let leaked = dbg_futex_waiter_registered(0, uaddr, tid);
    // (Also cleans up the ghost so later tests see a clean global table.)
    let ghost_woken = futex_wake_waiters_for_test(uaddr, u32::MAX);
    if let Some(h) = sleep_handle.take() {
        narf_scheduler::narf_time::timer_wheel::cancel(h);
    }
    if leaked || ghost_woken != 0 {
        return TestResult::Fail(
            "timed-out FUTEX_WAIT left its waker enqueued — a later FUTEX_WAKE(1) \
             wakes a ghost instead of a real waiter (Linux futex_unqueue removes it)",
        );
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace/futex",
    smoke_userspace_futex_timeout_unpark_unqueues_waiter
);

/// The CLONE_CHILD_CLEARTID exit wake must reach a SHARED-namespace waiter.
/// Linux fires it WITHOUT `FUTEX_PRIVATE_FLAG` — kernel/fork.c `mm_release`:
/// `put_user(0, tsk->clear_child_tid); do_futex(tsk->clear_child_tid,
/// FUTEX_WAKE, 1, ...)` — and glibc matches: `pthread_join` waits on the
/// ctid word with `LLL_SHARED` ("The kernel [...] futex wake-up [...] is not
/// private", nptl/pthread_join_common.c). musl's `__tl_lock` waiters on the
/// ctid word (`&__thread_list_lock`) also wait with priv=0. A wake published
/// ONLY in the private (AddressSpace-Arc) namespace therefore never finds
/// these waiters, and every glibc pthread_join degrades to the ~10 ms wheel
/// backstop (`fire_clear_child_tid_on_exit` currently wakes only
/// `futex_key(entry.futex_namespace, uaddr)`).
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
fn smoke_userspace_cleartid_exit_wake_reaches_shared_waiter() -> TestResult {
    use crate::handlers::{
        __test_futex_wake_counter, __test_set_clear_child_tid_scoped, futex_drop_waiter,
        futex_register_waiter,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    fn counting_waker(counter: Arc<AtomicU32>) -> Waker {
        unsafe fn clone_raw(d: *const ()) -> RawWaker {
            // SAFETY: `d` came from Arc::into_raw below; balanced reconstruction.
            let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
            let cloned = arc.clone();
            let _ = Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(cloned) as *const (), &VTAB)
        }
        unsafe fn wake_raw(d: *const ()) {
            // SAFETY: consumes the strong reference owned by this waker.
            let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
            arc.fetch_add(1, Ordering::AcqRel);
        }
        unsafe fn wake_ref_raw(d: *const ()) {
            // SAFETY: the waker retains its strong reference across this call.
            unsafe { (*(d as *const AtomicU32)).fetch_add(1, Ordering::AcqRel) };
        }
        unsafe fn drop_raw(d: *const ()) {
            // SAFETY: releases the strong reference owned by this waker.
            unsafe { drop(Arc::<AtomicU32>::from_raw(d as *const AtomicU32)) };
        }
        static VTAB: RawWakerVTable =
            RawWakerVTable::new(clone_raw, wake_raw, wake_ref_raw, drop_raw);
        // SAFETY: vtable matches the Arc<AtomicU32> representation.
        unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(counter) as *const (), &VTAB)) }
    }

    const TID: u64 = 71_101;
    const PID: u64 = 71_100;
    const JOINER_TID: u64 = 71_142;
    // A word no other test touches (as_root=0 in the scoped entry skips the
    // word write; the wake still fires — the subject of this test).
    const UADDR: u64 = 0x5EC0_5000;
    // Models the exiting thread's private namespace (an AddressSpace Arc
    // pointer — always nonzero for a real task).
    const PRIVATE_NS: u64 = 0xA51D_0001;

    // Real exit-observer wiring, exactly like smoke_exit_sweeps_task_tables.
    crate::user_task::__test_clear_exit_observers();
    crate::handlers::wait_init();
    crate::handlers::clear_child_tid_init();
    crate::handlers::install_clear_child_tid_observer();

    let task = crate::task::Task::new_registered(TID, PID);
    __test_set_clear_child_tid_scoped(TID, UADDR, PRIVATE_NS);

    // The glibc joiner: FUTEX_WAIT on the ctid word WITHOUT FUTEX_PRIVATE
    // (LLL_SHARED) → registered in namespace 0.
    let woken = Arc::new(AtomicU32::new(0));
    futex_register_waiter(UADDR, JOINER_TID, counting_waker(woken.clone()));
    let shared_gen_before = __test_futex_wake_counter(UADDR);

    // Thread exit → fire_clear_child_tid_on_exit.
    crate::task::mark_zombie(TID);
    crate::user_task::notify_task_exited(PID, TID);

    let fired = woken.load(Ordering::Acquire) == 1;
    let shared_gen_bumped = __test_futex_wake_counter(UADDR) != shared_gen_before;

    // Cleanup regardless of outcome: drop an un-woken joiner entry and the
    // test observer wiring so later tests see clean global state.
    futex_drop_waiter(UADDR, JOINER_TID);
    crate::task::release_task(TID);
    let _ = task;
    crate::user_task::__test_clear_exit_observers();

    if !shared_gen_bumped {
        return TestResult::Fail(
            "CLEARTID exit wake skipped the shared (namespace-0) gen — Linux's \
             mm_release wake carries no FUTEX_PRIVATE_FLAG (kernel/fork.c)",
        );
    }
    if !fired {
        return TestResult::Fail(
            "CLEARTID exit wake never fired the shared-namespace joiner — \
             glibc pthread_join waits with LLL_SHARED and misses a private-only wake",
        );
    }
    TestResult::Pass
}
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
kernel_test_in!(
    "userspace/futex",
    smoke_userspace_cleartid_exit_wake_reaches_shared_waiter
);

fn smoke_userspace_exited_pthread_does_not_remain_zombie() -> TestResult {
    const PID: u64 = 70_001;
    const LEADER: u64 = 70_101;
    const THREAD: u64 = 70_102;

    crate::handlers::pid_task_map_reset();
    crate::handlers::__test_thread_group_live_reset();
    crate::task::__test_reset_tasks();
    let _leader = crate::task::Task::new_registered(LEADER, PID);
    let _thread = crate::task::Task::new_registered(THREAD, PID);
    crate::handlers::register_pid_task_mapping(PID, LEADER);
    crate::handlers::register_task_to_pid(THREAD, PID);
    crate::handlers::thread_group_live_inc(PID);

    // Drive the real exit fan-out. The tracked group is still live, so this
    // must release only the non-leader task and must not run process teardown.
    crate::user_task::notify_task_exited(PID, THREAD);
    if crate::task::task_get(THREAD).is_some() {
        return TestResult::Fail("exited pthread retained a zombie task entry");
    }
    if crate::task::task_get(LEADER).is_none() {
        return TestResult::Fail("pthread exit released the live process leader");
    }

    crate::task::release_task(LEADER);
    crate::handlers::__test_thread_group_live_reset();
    crate::handlers::pid_task_map_reset();
    TestResult::Pass
}
kernel_test_in!(
    "userspace/process",
    smoke_userspace_exited_pthread_does_not_remain_zombie
);

kernel_test_in!("userspace", smoke_userspace_futex_park_word_revalidation);

/// Task #32 DELETED the ~10 ms lost-wake backstop: every readiness source now
/// fires a durable targeted wake, so `park_fire_deadline_ns` is the IDENTITY —
/// a finite park fires at its REAL deadline (no clamp), and an infinite park
/// (`u64::MAX`) gets an inert never-firing timer, relying purely on its
/// registered wakers. (Previously infinite + finite io-wait parks were clamped
/// to a ~10 ms backstop — e.g. a QtDBus worker poll()ing the 25 s D-Bus method
/// timeout; that clamp is gone now that the io-waiter wake is durable.)
#[cfg(target_arch = "x86_64")]
fn smoke_userspace_park_fire_deadline_is_identity() -> TestResult {
    use crate::user_task::park_fire_deadline_ns;
    let now = 1_000_000_000; // arbitrary "now"

    // Infinite park → u64::MAX (inert timer), NOT a 10 ms backstop, regardless
    // of io-wait.
    if park_fire_deadline_ns(u64::MAX, now, false) != u64::MAX {
        return TestResult::Fail("infinite park must return u64::MAX (backstop deleted)");
    }
    if park_fire_deadline_ns(u64::MAX, now, true) != u64::MAX {
        return TestResult::Fail("infinite io-wait park must return u64::MAX (backstop deleted)");
    }

    // Finite io-wait park with a FAR deadline (25 s) → its REAL deadline, NOT
    // clamped (the durable io-waiter wake revives it earlier in practice).
    let far = now + 25_000_000_000;
    if park_fire_deadline_ns(far, now, true) != far {
        return TestResult::Fail("finite io-wait park must fire at its real deadline (no clamp)");
    }

    // Finite NON-io park (plain sleep) → its real deadline.
    if park_fire_deadline_ns(far, now, false) != far {
        return TestResult::Fail("finite sleep park must fire at its real deadline");
    }

    // A near deadline is returned unchanged too.
    let near = now + 2_000_000; // 2 ms
    if park_fire_deadline_ns(near, now, true) != near {
        return TestResult::Fail("near deadline must be returned unchanged");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_park_fire_deadline_is_identity);

/// A global readiness notification that races an epoll/poll waiter's
/// registration is not evidence that *this* interest set is ready.  The
/// waiter must remain parked (with its generation refreshed) so unrelated
/// AF_UNIX or network activity cannot turn an infinite wait into a tight
/// return-to-userspace loop.  A true missed source-specific wake is bounded by
/// the established 10 ms backstop above.
fn smoke_userspace_io_generation_race_keeps_wait_parked() -> TestResult {
    use crate::user_task::{refresh_io_wait_generation_after_registration, UserTaskCtx};
    use core::sync::atomic::Ordering;

    let ctx = UserTaskCtx::new();
    ctx.net_io_wait.store(true, Ordering::Release);
    ctx.sleep_deadline_ns.store(u64::MAX, Ordering::Release);
    ctx.epoll_park_gen.store(41, Ordering::Release);

    // Simulate an unrelated readiness notification in the scan→register
    // window.  The handler has already registered the waker; it must not
    // clear the park state and synchronously return 0 from epoll_wait.
    refresh_io_wait_generation_after_registration(&ctx, 42);

    if !ctx.net_io_wait.load(Ordering::Acquire)
        || ctx.sleep_deadline_ns.load(Ordering::Acquire) != u64::MAX
    {
        return TestResult::Fail("global readiness race cancelled an I/O park");
    }
    if ctx.epoll_park_gen.load(Ordering::Acquire) != 42 {
        return TestResult::Fail("I/O park did not refresh its readiness generation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_io_generation_race_keeps_wait_parked
);

/// An own-stack task parks by `kernel_switch`, not the legacy longjmp hook.
/// Requiring that hook before considering the own-stack path turns an
/// infinite `epoll_wait` into a tight stream of successful empty returns.
fn smoke_userspace_own_stack_park_does_not_require_legacy_hook() -> TestResult {
    use crate::epoll::can_park_with_task_context;

    if !can_park_with_task_context(true, false) {
        return TestResult::Fail("own-stack park incorrectly requires legacy yield hook");
    }
    if !can_park_with_task_context(false, true) {
        return TestResult::Fail("legacy park with a yield hook was rejected");
    }
    if can_park_with_task_context(false, false) {
        return TestResult::Fail("park without own-stack or legacy hook was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_own_stack_park_does_not_require_legacy_hook
);

/// Multi-threaded `exit_group` must run PROCESS-scoped exit observers
/// EXACTLY ONCE — on the group's last thread (`group_dead`) — while
/// THREAD-scoped observers run for EVERY thread. This is Linux's
/// `group_dead = atomic_dec_and_test(&signal->live)` gate. Regression:
/// the OCI container-teardown #UD, where a concurrent multi-thread
/// exit_group ran the per-pid reap once per thread, double-freeing the
/// PID pool and scribbling the observer list into a wild `fn(u64,u64)`
/// slot → ring-0 call to a low garbage address. Drives the fan-out
/// directly through `notify_task_exited` with a 3-thread group.
fn smoke_userspace_exit_observer_group_dead_once() -> TestResult {
    use crate::handlers::{__test_thread_group_live_reset, thread_group_live_inc};
    use crate::user_task::{
        __test_clear_exit_observers, notify_task_exited, register_process_exit_observer,
        register_thread_exit_observer,
    };
    use core::sync::atomic::{AtomicU32, Ordering};

    static THREAD_HITS: AtomicU32 = AtomicU32::new(0);
    static PROCESS_HITS: AtomicU32 = AtomicU32::new(0);

    fn thread_obs(_pid: u64, _tid: u64) {
        THREAD_HITS.fetch_add(1, Ordering::Relaxed);
    }
    fn process_obs(_pid: u64, _tid: u64) {
        PROCESS_HITS.fetch_add(1, Ordering::Relaxed);
    }

    __test_clear_exit_observers();
    __test_thread_group_live_reset();
    THREAD_HITS.store(0, Ordering::Relaxed);
    PROCESS_HITS.store(0, Ordering::Relaxed);
    register_thread_exit_observer(thread_obs);
    register_process_exit_observer(process_obs);

    // Thread group pid=5000 with THREE threads: the implicit main plus
    // two CLONE_THREAD siblings (two `inc`s → tracked live count 3).
    const PID: u64 = 5000;
    thread_group_live_inc(PID); // 2nd thread joins (count 1→2)
    thread_group_live_inc(PID); // 3rd thread joins (count 2→3)

    // First two of the three threads exit (distinct tids, shared pid).
    notify_task_exited(PID, 5000);
    notify_task_exited(PID, 5001);
    // NOT group-dead yet — process teardown must not have fired, or the
    // still-live third thread's process state would be freed under it.
    if PROCESS_HITS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail(
            "process observer fired before the last thread (double-free window)",
        );
    }
    if THREAD_HITS.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("thread observer must fire once per exiting thread");
    }
    // Last thread exits → group_dead → process teardown fires ONCE.
    notify_task_exited(PID, 5002);
    if THREAD_HITS.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("thread observer count wrong after the last thread");
    }
    if PROCESS_HITS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("process observer must fire exactly once on group_dead");
    }

    // An untracked single-threaded process is implicitly its own last
    // thread → process teardown fires immediately on its sole exit.
    notify_task_exited(6000, 6000);
    if PROCESS_HITS.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("untracked single-threaded exit must be group_dead");
    }
    if THREAD_HITS.load(Ordering::Relaxed) != 4 {
        return TestResult::Fail("thread observer must fire for the single-threaded exit too");
    }

    // Leave the registry cleared so later tests re-wire their own.
    __test_clear_exit_observers();
    __test_thread_group_live_reset();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_exit_observer_group_dead_once);

/// FUTEX_WAKE_OP (op 5) must atomically read-modify-write `*uaddr2` per the
/// encoded op AND wake (up to `val`) waiters on `uaddr` — Linux
/// `futex_wake_op`. Regression: op 5 fell through to the `_ => fail` arm
/// (returned -1, woke nobody), so glibc/Qt pthread_cond_signal dropped its
/// wake and a Qt6 app (kcalc) deadlocked at startup — its worker thread
/// signalled the main thread via FUTEX_WAKE_OP and the main thread never woke.
fn smoke_userspace_futex_wake_op_rmw() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Encoded op: FUTEX_OP_ADD oparg=5 (newval = *uaddr2 + 5),
    // FUTEX_OP_CMP_GT cmparg=0 (wake uaddr2 waiters iff oldval > 0).
    // Layout: [31:28]=op [27:24]=cmp [23:12]=oparg [11:0]=cmparg.
    let encoded: u64 = (1 << 28) | (4 << 24) | (5 << 12);
    let mut word: u32 = 10;
    let uaddr2 = &mut word as *mut u32 as u64;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0xF00D,  // uaddr — used only as a wait-queue key (no memory access)
            arg1: 5,       // FUTEX_WAKE_OP
            arg2: 1,       // nr_wake
            arg3: 1,       // nr_wake2
            arg4: uaddr2,  // uaddr2 (the RMW target)
            arg5: encoded, // encoded op
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Futex.raw(), &mut ctx);

    // Must succeed with a non-negative woken count (0 here — no waiters),
    // NOT the old -1 "unimplemented op" result.
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && (r.value as i64) >= 0 => {}
        _ => {
            __test_clear_global();
            return TestResult::Fail("FUTEX_WAKE_OP returned an error (op unimplemented?)");
        }
    }
    // The atomic RMW must have applied: 10 + 5 = 15.
    if word != 15 {
        __test_clear_global();
        return TestResult::Fail("FUTEX_WAKE_OP did not RMW *uaddr2 (expected 10+5=15)");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_futex_wake_op_rmw);

fn smoke_userspace_sched_priority_bounds_and_param() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        init_per_task_state, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::handlers::__test_sched_param_reset();
    init_per_task_state();

    fn call(s: Syscall, arg0: u64, arg1: u64) -> Option<SyscallReturn> {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0,
                arg1,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(s.raw(), &mut ctx);
        ctx.ret
    }

    // Bounds: SCHED_OTHER → (0, 0); SCHED_FIFO/RR → (1, 99); bad → -1.
    let max_other = call(Syscall::SchedGetPriorityMax, 0, 0)
        .map(|r| r.value as i64)
        .unwrap_or(99);
    let min_other = call(Syscall::SchedGetPriorityMin, 0, 0)
        .map(|r| r.value as i64)
        .unwrap_or(99);
    if max_other != 0 || min_other != 0 {
        return TestResult::Fail("SCHED_OTHER bounds not (0,0)");
    }
    let max_rr = call(Syscall::SchedGetPriorityMax, 2, 0)
        .map(|r| r.value as i64)
        .unwrap_or(99);
    let min_rr = call(Syscall::SchedGetPriorityMin, 2, 0)
        .map(|r| r.value as i64)
        .unwrap_or(99);
    if max_rr != 99 || min_rr != 1 {
        return TestResult::Fail("SCHED_RR bounds not (1, 99)");
    }
    let bad = call(Syscall::SchedGetPriorityMax, 99, 0)
        .map(|r| r.value)
        .unwrap_or(0);
    if bad != (-1i64) as u64 {
        return TestResult::Fail("bad policy not rejected");
    }

    // Param round-trip: default 0, set to 50, read back 50.
    let mut prio: i32 = 0xAB;
    let _ = call(Syscall::SchedGetparam, 0, &mut prio as *mut i32 as u64);
    if prio != 0 {
        return TestResult::Fail("default sched_priority not 0");
    }
    let want: i32 = 50;
    let _ = call(Syscall::SchedSetparam, 0, &want as *const i32 as u64);
    let mut got: i32 = 0xCD;
    let _ = call(Syscall::SchedGetparam, 0, &mut got as *mut i32 as u64);
    if got != 50 {
        return TestResult::Fail("setparam did not stick");
    }

    crate::handlers::__test_sched_param_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_sched_priority_bounds_and_param);

fn smoke_userspace_pgid_round_trip() -> TestResult {
    use crate::{
        init_per_task_state, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::handlers::__test_pgid_reset();
    init_per_task_state();

    fn call(s: Syscall, arg0: u64, arg1: u64) -> Option<SyscallReturn> {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0,
                arg1,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(s.raw(), &mut ctx);
        ctx.ret
    }

    // Default pgid == pid (which is 0 for the test harness's
    // current_task_id).
    let pid = call(Syscall::GetPid, 0, 0).map(|r| r.value).unwrap_or(!0);
    let p0 = call(Syscall::Getpgid, 0, 0).map(|r| r.value).unwrap_or(!0);
    if p0 != pid {
        return TestResult::Fail("default pgid != pid");
    }

    // setpgid(0, 7) — explicitly stick pgid to 7.
    let _ = call(Syscall::Setpgid, 0, 7);
    let p1 = call(Syscall::Getpgid, 0, 0).map(|r| r.value).unwrap_or(!0);
    if p1 != 7 {
        return TestResult::Fail("setpgid(7) did not stick");
    }

    // setpgid(0, 0) — pgid resolves to the target's pid (creates
    // a fresh group leader).
    let _ = call(Syscall::Setpgid, 0, 0);
    let p2 = call(Syscall::Getpgid, 0, 0).map(|r| r.value).unwrap_or(!0);
    if p2 != pid {
        return TestResult::Fail("setpgid(0,0) did not resolve to pid");
    }

    crate::handlers::__test_pgid_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_pgid_round_trip);

fn smoke_userspace_setsid_makes_session_leader() -> TestResult {
    use crate::{
        init_per_task_state, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    init_per_task_state();

    fn call(s: Syscall, arg0: u64) -> Option<SyscallReturn> {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(s.raw(), &mut ctx);
        ctx.ret
    }

    let pid = call(Syscall::GetPid, 0).map(|r| r.value).unwrap_or(!0);

    // Default sid == pid.
    let s0 = call(Syscall::Getsid, 0).map(|r| r.value).unwrap_or(!0);
    if s0 != pid {
        return TestResult::Fail("default sid != pid");
    }

    // Stomp sid (no setter, so use pgid as a witness): setpgid
    // table is wired to setsid below.

    // Pre-stomp pgid to a distinct value, then setsid resets both.
    let _ = {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: 0,
                arg1: 12345,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Setpgid.raw(), &mut ctx);
        ctx.ret
    };

    let new_sid = call(Syscall::Setsid, 0).map(|r| r.value).unwrap_or(!0);
    if new_sid != pid {
        return TestResult::Fail("setsid did not return the caller's pid");
    }

    // Both sid and pgid are now == pid (setsid resets both).
    let s1 = call(Syscall::Getsid, 0).map(|r| r.value).unwrap_or(!0);
    let p1 = call(Syscall::Getpgid, 0).map(|r| r.value).unwrap_or(!0);
    if s1 != pid || p1 != pid {
        return TestResult::Fail("setsid did not reset both sid and pgid to pid");
    }

    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_setsid_makes_session_leader);

// ── ELF helper used by unresolved-symbol tests (relocated from verification) ──

// ── relocated from verification ──

#[cfg(target_arch = "x86_64")]
fn smoke_abi_dispatcher_serves_file_ops() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // Bootstrap mints rings, kernel installs the
    // abi-file-op-bridge, dispatcher runs on the kernel-side
    // ends, user-side task issues an `OpCode::Open` followed by
    // `OpCode::Read` against a stub-FS file mounted under
    // `/test_abi`. The completion's result[0] carries the bytes-
    // read count; the user-mapped buffer holds the file's bytes.
    use crate::{
        abi_file_op_bridge, install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, syscall::__test_clear_global, SyscallTable,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{Dispatcher, NarfStatus, OpCode, Submission, Tag};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };
    use narf_memory::AddressSpace;

    static FILE_BYTES: &[u8] = b"VFS-via-ABI";
    struct StubFile;
    impl FileOps for StubFile {
        fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move {
                let off = offset as usize;
                if off >= FILE_BYTES.len() {
                    return Ok(0);
                }
                let n = core::cmp::min(buf.len(), FILE_BYTES.len() - off);
                buf[..n].copy_from_slice(&FILE_BYTES[off..off + n]);
                Ok(n)
            })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: FILE_BYTES.len() as u64,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StubDir;
    impl DirOps for StubDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "f" {
                Some(Arc::new(StubFile))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct StubFs;
    impl FsInstance for StubFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(StubDir)
        }
        fn name(&self) -> &str {
            "stub_abi"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/test_abi", StubFs);

    static USER_AS_ABI: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_ABI.lock().clone()
    }
    static FAKE_TASK: u64 = 0xABBA;
    fn task_lookup() -> u64 {
        FAKE_TASK
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    *USER_AS_ABI.lock() = Some(addr_space);

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
    crate::fd::__test_reset();
    crate::bootstrap_init();
    narf_abi::install_file_op_bridge(abi_file_op_bridge);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Direct Bootstrap call (test runs in kernel context).
    use crate::{kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, TrapContext};
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Bootstrap.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("Bootstrap returned non-Ok");
    }

    let kernel_ends = crate::take_kernel_ends(FAKE_TASK).expect("ke");
    let user_ends = crate::take_user_ends(FAKE_TASK).expect("ue");

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    // Stable-static buffers for the path/mount/data so the user
    // task can hand pointers across awaits without lifetime
    // complications.
    static PATH: &[u8] = b"/test_abi/f\0";
    static mut READ_BUF: [u8; 16] = [0u8; 16];

    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(kernel_ends.sq_drain, kernel_ends.cq_prod);
        d.run().await;
    });
    narf_scheduler::spawn(async move {
        let mut sq = user_ends.sq_prod;
        let mut cq = user_ends.cq_drain;

        // Open("/test_abi/f"). Linux open(2) ABI: inline[0] = NUL-
        // terminated absolute path, inline[1] = flags.
        let mut sub = Submission::noop(Tag::new(0x10));
        sub.op = OpCode::OpenFile;
        sub.inline[0] = PATH.as_ptr() as u64;
        sub.inline[1] = 0;
        sq.send(sub).await.unwrap();
        let comp = cq.recv().await.unwrap();
        if comp.status != NarfStatus::Ok || comp.result[0] != 3 {
            OUTCOME.store(2, Ordering::Relaxed);
            core::mem::drop(sq);
            core::mem::drop(cq);
            return;
        }
        let fd = comp.result[0];

        // Read(fd, READ_BUF, 16).
        let mut sub = Submission::noop(Tag::new(0x11));
        sub.op = OpCode::Read;
        sub.inline[0] = fd;
        sub.inline[1] = core::ptr::addr_of_mut!(READ_BUF) as u64;
        sub.inline[2] = 16;
        sq.send(sub).await.unwrap();
        let comp = cq.recv().await.unwrap();
        if comp.status != NarfStatus::Ok {
            OUTCOME.store(3, Ordering::Relaxed);
            core::mem::drop(sq);
            core::mem::drop(cq);
            return;
        }
        let n = comp.result[0] as usize;
        // SAFETY: single-threaded test; only this body reads
        // READ_BUF after the syscall populates it. `&raw const`
        // (Rust 2024) avoids the rust_2024_compatibility
        // static_mut_refs lint by going through a raw pointer
        // instead of a `&` reference.
        // SAFETY: Valid memory or trusted environment
        let buf = unsafe { &*core::ptr::addr_of!(READ_BUF) };
        if &buf[..n] == FILE_BYTES {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(4, Ordering::Relaxed);
        }
        core::mem::drop(sq);
        core::mem::drop(cq);
    });

    narf_scheduler::run_until_empty();

    *USER_AS_ABI.lock() = None;
    crate::fd::__test_reset();
    crate::handlers::__test_bootstrap_reset();
    __test_clear_global();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("Open completion was not Ok / fd != 3"),
        3 => TestResult::Fail("Read completion was not Ok"),
        4 => TestResult::Fail("Read bytes mismatched expected payload"),
        _ => TestResult::Fail("user-side task did not complete"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_abi_dispatcher_serves_file_ops);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_dispatcher_serves_mmap() -> TestResult {
    // Same shape as smoke_abi_dispatcher_serves_file_ops, but
    // exercises the Mmap/Munmap ring path. Submit `OpCode::Mmap`
    // for one page → expect `Ok` with a non-zero user vaddr in
    // `result[0]`. Then `OpCode::Munmap` that base → expect `Ok`.
    use crate::{
        abi_file_op_bridge, install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, syscall::__test_clear_global, SyscallTable,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{Dispatcher, NarfStatus, OpCode, Submission, Tag};
    use narf_memory::AddressSpace;

    static USER_AS_MMAP: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_MMAP.lock().clone()
    }
    static FAKE_TASK: u64 = 0xACAC;
    fn task_lookup() -> u64 {
        FAKE_TASK
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    *USER_AS_MMAP.lock() = Some(addr_space);

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
    crate::fd::__test_reset();
    crate::bootstrap_init();
    narf_abi::install_file_op_bridge(abi_file_op_bridge);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    use crate::{kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, TrapContext};
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Bootstrap.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("Bootstrap returned non-Ok");
    }

    let kernel_ends = crate::take_kernel_ends(FAKE_TASK).expect("ke");
    let user_ends = crate::take_user_ends(FAKE_TASK).expect("ue");

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(kernel_ends.sq_drain, kernel_ends.cq_prod);
        d.run().await;
    });
    narf_scheduler::spawn(async move {
        let mut sq = user_ends.sq_prod;
        let mut cq = user_ends.cq_drain;

        // Mmap(hint=0, len=0x1000, flags=0).
        let mut sub = Submission::noop(Tag::new(0x20));
        sub.op = OpCode::Mmap;
        sub.inline[0] = 0;
        sub.inline[1] = 0x1000;
        sub.inline[2] = 0;
        sq.send(sub).await.unwrap();
        let comp = cq.recv().await.unwrap();
        if comp.status != NarfStatus::Ok || comp.result[0] == 0 {
            OUTCOME.store(2, Ordering::Relaxed);
            core::mem::drop(sq);
            core::mem::drop(cq);
            return;
        }
        let base = comp.result[0];

        // Munmap(base). The v1 native ring op retains its whole-VMA contract;
        // Linux syscall 11 separately takes and validates an explicit length.
        let mut sub = Submission::noop(Tag::new(0x21));
        sub.op = OpCode::Munmap;
        sub.inline[0] = base;
        sq.send(sub).await.unwrap();
        let comp = cq.recv().await.unwrap();
        if comp.status != NarfStatus::Ok {
            OUTCOME.store(3, Ordering::Relaxed);
            core::mem::drop(sq);
            core::mem::drop(cq);
            return;
        }
        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq);
        core::mem::drop(cq);
    });

    narf_scheduler::run_until_empty();

    *USER_AS_MMAP.lock() = None;
    crate::fd::__test_reset();
    crate::handlers::__test_bootstrap_reset();
    __test_clear_global();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("Mmap completion was not Ok / vaddr was 0"),
        3 => TestResult::Fail("Munmap completion was not Ok"),
        _ => TestResult::Fail("user-side task did not complete"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_abi_dispatcher_serves_mmap);

fn smoke_syscall_versioning_dispatch() -> TestResult {
    // Build a private SyscallTable with a v0 + v1 handler for the
    // same syscall number, exercise dispatch_ctx_versioned for both
    // versions, and assert each handler set its own canary value.
    use crate::{
        syscall_number, syscall_pack, syscall_version, RawFnHandler, Syscall, SyscallArgs,
        SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU32, Ordering};

    static V0_SEEN: AtomicU32 = AtomicU32::new(0);
    static V1_SEEN: AtomicU32 = AtomicU32::new(0);
    V0_SEEN.store(0, Ordering::Relaxed);
    V1_SEEN.store(0, Ordering::Relaxed);

    let mut table = SyscallTable::new();
    table.install_raw(
        Syscall::Yield,
        "yield-v0",
        RawFnHandler(|ctx: &mut dyn TrapContext| {
            V0_SEEN.fetch_add(1, Ordering::Relaxed);
            ctx.set_return(SyscallReturn::ok(0xC0DE_0000));
        }),
    );
    table.install_raw_versioned(
        Syscall::Yield,
        1,
        RawFnHandler(|ctx: &mut dyn TrapContext| {
            V1_SEEN.fetch_add(1, Ordering::Relaxed);
            ctx.set_return(SyscallReturn::ok(0xC0DE_0001));
        }),
    );

    // Bit-packing helpers round-trip cleanly.
    let raw = syscall_pack(1, Syscall::Yield);
    if syscall_version(raw) != 1 {
        return TestResult::Fail("version_of did not extract 1");
    }
    if syscall_number(raw) != Syscall::Yield.raw() {
        return TestResult::Fail("number_of did not extract Yield");
    }

    // Manual ctx for dispatch.
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
    let mut ctx0 = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    table.dispatch_ctx_versioned(Syscall::Yield, 0, &mut ctx0);
    if ctx0.ret.map(|r| r.value) != Some(0xC0DE_0000) {
        return TestResult::Fail("v0 dispatch did not return v0 sentinel");
    }
    if V0_SEEN.load(Ordering::Relaxed) != 1 || V1_SEEN.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("v0 path did not invoke v0 handler exclusively");
    }

    let mut ctx1 = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    table.dispatch_ctx_versioned(Syscall::Yield, 1, &mut ctx1);
    if ctx1.ret.map(|r| r.value) != Some(0xC0DE_0001) {
        return TestResult::Fail("v1 dispatch did not return v1 sentinel");
    }
    if V1_SEEN.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("v1 path did not invoke v1 handler");
    }

    // Unknown version (v2) falls through to v0 — the documented
    // "if no override, use canonical" rule.
    let mut ctx2 = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    table.dispatch_ctx_versioned(Syscall::Yield, 2, &mut ctx2);
    if ctx2.ret.map(|r| r.value) != Some(0xC0DE_0000) {
        return TestResult::Fail("v2 unknown did not fall through to v0");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_syscall_versioning_dispatch);

fn smoke_userspace_sa_nodefer_skips_auto_block() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF800);
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

    // Variant A — handler with SA_NODEFER set. Deliver: mask
    // afterwards must NOT have the signal blocked.
    let mut act = SigGapCtx {
        args: SyscallArgs {
            arg0: 10,
            arg1: 0xC0DE,
            arg2: 0,
            arg3: crate::handlers::SA_NODEFER as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut act);
    // Kill self with SIGUSR1.
    let mut k = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xF800,
            arg1: 10,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut k);

    // FakeCtx that pretends to return to user — drives delivery.
    struct UserBoundCtx {
        #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
        signum: u32,
    }
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
    let mut ctx = UserBoundCtx { signum: 0 };
    DELIVERED_SIG.store(0, Ordering::Release);
    crate::handlers::default_signal_delivery(&mut ctx, crate::handlers::SYSCALL_NUM_NONE);
    let _ = ctx;

    let mask_after = crate::handlers::signal_mask_of(0xF800);
    let delivered = DELIVERED_SIG.load(Ordering::Acquire);
    __test_clear_global();
    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    if delivered != 10 {
        return TestResult::Fail("delivery hook did not fire");
    }
    if mask_after & crate::handlers::sig_bit(10) != 0 {
        return TestResult::Fail("SA_NODEFER should NOT auto-block the signal");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_sa_nodefer_skips_auto_block);

/// A per-pid `/proc` hook is handed the outer ProcessId, but per-task state
/// (the fd table, comm, argv, cwd, …) is keyed by TaskId — the hook MUST
/// resolve ProcessId→TaskId via `proc_pid_to_tid`. Regression this pins:
/// `proc_fd_list` keyed straight on the ProcessId returned an empty fd set, so
/// `/proc/self/fd/N` was unresolvable and systemd's
/// `execve("/proc/self/fd/N")` executor spawn EBADF'd, stalling the whole boot
/// (project_pidns_flow_model). Not namespace-gated: the ProcessId≠TaskId split
/// exists in every build.
fn smoke_proc_fd_hook_resolves_processid_to_taskid() -> TestResult {
    let tid = 0x0FD5_C001u64;
    let pid = 0x0FD5_C0DEu64; // a DISTINCT ProcessId

    crate::handlers::register_pid_task_mapping(pid, tid);

    // proc_pid_to_tid maps the ProcessId to its TaskId; an unmapped pid is
    // identity (a bare tid / thread id resolves to itself).
    if crate::handlers::proc_pid_to_tid(pid) != tid {
        return TestResult::Fail("proc_pid_to_tid did not map ProcessId→TaskId");
    }
    if crate::handlers::proc_pid_to_tid(0x0FD5_BEEF) != 0x0FD5_BEEF {
        return TestResult::Fail("proc_pid_to_tid must be identity for an unmapped pid");
    }

    // Open an fd in the TASK's fd table (fresh tables seed stdio at 0,1,2, so
    // the first open lands at fd 3).
    let fd = match crate::fd::install(
        tid,
        crate::fd::FdEntry {
            ops: narf_filesystem::memfs::new_anon_file(),
            offset: 0,
            flags: 0,
            status_flags: 0,
        },
    ) {
        Some(f) => f,
        None => return TestResult::Fail("with_table open failed"),
    };

    // The hook is handed the ProcessId and must enumerate the TASK's fds.
    // Keyed on the raw ProcessId this returns empty — the executor-spawn bug.
    if !crate::handlers::proc_fd_list(pid).contains(&fd) {
        return TestResult::Fail("proc_fd_list(ProcessId) did not resolve to the task's fd table");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_proc_fd_hook_resolves_processid_to_taskid);
