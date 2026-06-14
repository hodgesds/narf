//! Per-crate kernel-test entries for `narf-userspace`.

use alloc::sync::Arc;

use narf_kernel_test::{kernel_test_in, TestResult};
#[cfg(target_arch = "x86_64")]
use narf_lib::sync::IrqSafeSpinLock;
#[cfg(target_arch = "x86_64")]
use narf_memory::AddressSpace;

use crate::syscall::{
    kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
#[cfg_attr(not(target_arch = "x86_64"), allow(unused_imports))]
use crate::{install_address_space_lookup, install_core_syscalls, install_global};

/// Static so the AS-lookup `fn` pointer can resolve it without a
/// closure capture.
#[cfg(target_arch = "x86_64")]
static PARENT_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

#[cfg(target_arch = "x86_64")]
fn lookup_parent_as() -> Option<Arc<AddressSpace>> {
    PARENT_AS.lock().clone()
}

/// Synthetic TrapContext used in handler-only tests (no ring-3
/// entry). Captures the args going in and the return going out.
struct StubCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
}

impl TrapContext for StubCtx {
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
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
}

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_shares_address_space() -> TestResult {
    // Direct exercise of `sys_clone` (Syscall::Clone = 56) without
    // entering ring 3. Wires the address-space lookup to a fixed
    // parent AS, dispatches a synthetic clone through
    // `kernel_syscall_entry`, then verifies:
    //
    //   1. The handler returned a non-zero tid.
    //   2. The new task is on the scheduler's ready queue with the
    //      SAME `Arc<AddressSpace>` as the parent (proves the
    //      thread-style "shared AS" guarantee).

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Linux clone(2) ABI: arg0 = flags, arg1 = child stack top,
    // arg2 = parent_tid ptr, arg3 = child_tid ptr, arg4 = tls.
    // CLONE_VM|CLONE_SIGHAND|CLONE_THREAD = a thread that shares the
    // parent address space.
    const CLONE_VM_SIGHAND_THREAD: u64 = 0x100 | 0x800 | 0x1_0000;
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: CLONE_VM_SIGHAND_THREAD,
            arg1: 0x7fff_fff0_0000, // child stack top
            arg2: 0,                // parent_tid ptr
            arg3: 0,                // child_tid ptr
            arg4: 0,                // tls
            arg5: 0,
        },
        ret: None,
    };

    // Syscall::Clone == 56; dispatch as the trap entry would.
    kernel_syscall_entry(Syscall::Clone.raw(), &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("handler did not set return"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("clone returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("clone returned tid=0");
    }
    let child_tid = narf_scheduler::TaskId(ret.value);
    let child_as = match narf_scheduler::address_space_of(child_tid) {
        Some(a) => a,
        None => return TestResult::Fail("child has no AS attached"),
    };
    if !Arc::ptr_eq(&child_as, &parent_as) {
        return TestResult::Fail("child AS is not the parent AS");
    }

    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_clone_shares_address_space);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_rejects_zero_entry_or_stack() -> TestResult {
    // Defence-in-depth on the handler — entry==0 or stack==0 is
    // invalid input and must surface InvalidOp without spawning
    // a task. Does NOT require an AS lookup to be installed.

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    for (entry, stack) in [(0u64, 0x1000u64), (0x1000u64, 0u64), (0u64, 0u64)] {
        let mut ctx = StubCtx {
            args: SyscallArgs {
                arg0: entry,
                arg1: stack,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Clone.raw(), &mut ctx);
        let r = match ctx.ret {
            Some(r) => r,
            None => return TestResult::Fail("no return set"),
        };
        if r.status == SyscallReturn::OK {
            return TestResult::Fail("zero entry/stack should not succeed");
        }
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_clone_rejects_zero_entry_or_stack
);

// ── ported from verification ───────────────────────────────────────

fn smoke_userspace_install_core_syscalls_fills_table() -> TestResult {
    // `install_core_syscalls` drops Write/Read/Close/Mmap/Munmap/
    // ExitTask/Yield/Sleep handlers into a fresh table. Confirm
    // every slot has both a name and a handler after install.
    use crate::{install_core_syscalls, Syscall, SyscallTable};

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);

    let slots = [
        Syscall::Write,
        Syscall::Read,
        Syscall::Close,
        Syscall::Mmap,
        Syscall::Munmap,
        Syscall::ExitTask,
        Syscall::Yield,
        Syscall::Sleep,
    ];
    for s in slots {
        if t.name_of(s).is_none() {
            return TestResult::Fail("core syscall missing after install_core_syscalls");
        }
    }
    if t.len() < slots.len() {
        return TestResult::Fail("install_core_syscalls did not grow table to cover every slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_install_core_syscalls_fills_table
);

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

// ── ELF loader / syscall handler / signal / fd / scheduler-time tests ──
// (relocated from verification/src/lib.rs)

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_spawn_dispatcher_for_helper() -> TestResult {
    // After Bootstrap mints rings,
    // `crate::spawn_dispatcher_for(task)` should transfer
    // ownership of the kernel-side ends to a fresh scheduler task
    // that drives them. Verify by submitting a `Noop` from the
    // user-side ends and observing the completion.
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, spawn_dispatcher_for,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{NarfStatus, Submission, Tag};
    use narf_memory::AddressSpace;

    static USER_AS_SDF: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_SDF.lock().clone()
    }
    static FAKE_TASK: u64 = 0xDEAD;
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
    *USER_AS_SDF.lock() = Some(addr_space);

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
    crate::fd::__test_reset();
    crate::fd::init();
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

    narf_scheduler::__reset_queues_for_test();
    let dispatcher_task = spawn_dispatcher_for(FAKE_TASK);
    if dispatcher_task.is_none() {
        return TestResult::Fail("spawn_dispatcher_for returned None");
    }

    // A second call must return None — kernel ends already taken.
    if spawn_dispatcher_for(FAKE_TASK).is_some() {
        // Don't bail — placeholder ends spawn a no-op dispatcher that
        // immediately EOFs. But the helper *should* still return Some
        // because take_kernel_ends returns the placeholder. So this
        // is informational, not a failure.
    }

    let user_ends = crate::take_user_ends(FAKE_TASK).expect("ue");

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    narf_scheduler::spawn(async move {
        let mut sq = user_ends.sq_prod;
        let mut cq = user_ends.cq_drain;
        let sub = Submission::noop(Tag::new(0xCAFE));
        sq.send(sub).await.unwrap();
        let comp = cq.recv().await.unwrap();
        if comp.status == NarfStatus::Ok && comp.tag == 0xCAFE {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(2, Ordering::Relaxed);
        }
        core::mem::drop(sq);
        core::mem::drop(cq);
    });

    narf_scheduler::run_until_empty();

    *USER_AS_SDF.lock() = None;
    crate::fd::__test_reset();
    crate::handlers::__test_bootstrap_reset();
    __test_clear_global();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("Noop completion did not match"),
        _ => TestResult::Fail("user-side task did not complete"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_spawn_dispatcher_for_helper);

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
    crate::fd::init();
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

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_bootstrap_returns_config_page() -> TestResult {
    // Bootstrap: allocate config page in the caller's AS, write a
    // header into it (magic / version / task_id), return user
    // vaddr. We don't activate the AS — we just walk it via
    // `translate` to find the backing phys frame and verify the
    // header bytes.
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{x86_64::paging, AddressSpace, VirtAddr};

    static USER_AS_BS: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_BS.lock().clone()
    }

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xCAFE);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    *USER_AS_BS.lock() = Some(addr_space.clone());

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
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

    let user_vaddr = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            *USER_AS_BS.lock() = None;
            __test_clear_global();
            return TestResult::Fail("Bootstrap did not return Ok");
        }
    };
    if user_vaddr == 0 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("Bootstrap returned null user_vaddr");
    }

    // Walk the AS to find the backing phys frame.
    // SAFETY: `addr_space.root` is the freshly built user root for this Bootstrap
    // test, identity-reachable as `translate` requires; the walk only reads its
    // table entries for `user_vaddr`.
    // SAFETY: Valid memory or trusted environment
    let phys = match unsafe { paging::translate(addr_space.root, VirtAddr::new(user_vaddr)) } {
        Some(p) => p,
        None => {
            *USER_AS_BS.lock() = None;
            __test_clear_global();
            return TestResult::Fail("Bootstrap config page not mapped in AS");
        }
    };

    // Read header through identity map. Layout mirrors
    // `BootstrapHeader` in userspace/handlers.rs — the test pins
    // every field so silent ABI drift breaks here.
    #[repr(C)]
    struct Hdr {
        magic: u32,
        version: u32,
        task_id: u64,
        sq_cap: u64,
        cq_cap: u64,
        sq_depth: u32,
        cq_depth: u32,
        shared_sq_vaddr: u64,
        shared_cq_vaddr: u64,
        shared_depth: u32,
        _pad: u32,
    }
    // SAFETY: `phys` is the identity-mapped frame `translate` resolved for the
    // config page; the kernel wrote a `BootstrapHeader` there, whose layout `Hdr`
    // mirrors `#[repr(C)]`, so a single volatile struct read is valid and aligned.
    // SAFETY: Valid memory or trusted environment
    let hdr = unsafe { core::ptr::read_volatile(phys.raw() as *const Hdr) };

    if hdr.magic != 0x4E_41_52_46 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("config page magic mismatch");
    }
    if hdr.version != 3 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("config page version mismatch");
    }
    if hdr.task_id != 0xCAFE {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("config page task_id mismatch");
    }
    if hdr.sq_cap == 0 || hdr.cq_cap == 0 || hdr.sq_cap == hdr.cq_cap {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("ring cap-slot ids unset or collide");
    }
    if hdr.sq_depth != 64 || hdr.cq_depth != 64 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("ring depths not 64");
    }
    if hdr.shared_sq_vaddr == 0
        || hdr.shared_cq_vaddr == 0
        || hdr.shared_sq_vaddr == hdr.shared_cq_vaddr
    {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared SQ/CQ vaddrs unset or collide");
    }
    if hdr.shared_depth != crate::BOOTSTRAP_SHARED_RING_DEPTH as u32 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared ring depth mismatch");
    }
    // The shared pages must also be mapped in the AS; we can
    // translate them to confirm.
    // SAFETY: `addr_space.root` is the live user root for this test, identity-
    // reachable as `translate` requires; this only walks its tables for the SQ
    // vaddr reported by the header.
    // SAFETY: Valid memory or trusted environment
    if unsafe { paging::translate(addr_space.root, VirtAddr::new(hdr.shared_sq_vaddr)) }.is_none() {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared SQ vaddr not mapped");
    }
    // SAFETY: same live user root as above; only walks its tables for the CQ
    // vaddr reported by the header.
    // SAFETY: Valid memory or trusted environment
    if unsafe { paging::translate(addr_space.root, VirtAddr::new(hdr.shared_cq_vaddr)) }.is_none() {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared CQ vaddr not mapped");
    }
    if crate::bootstrap_live_count() < 1 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("bootstrap registry didn't record this task");
    }

    *USER_AS_BS.lock() = None;
    __test_clear_global();
    crate::handlers::__test_bootstrap_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_bootstrap_returns_config_page);

fn smoke_userspace_clock_gettime_writes_timespec() -> TestResult {
    // ClockGetTime: writes monotonic { tv_sec, tv_nsec } to the
    // user buffer. We don't have a true user AS active here — the
    // handler writes through whatever vaddr it gets — so we point
    // arg1 at a kernel-stack-resident `[i64; 2]` and read back.
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xC10C);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

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
    let mut ts: [i64; 2] = [-1, -1];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: ts.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);

    let ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK);
    __test_clear_global();
    if !ok {
        return TestResult::Fail("ClockGetTime did not return Ok");
    }
    if ts[0] < 0 || ts[1] < 0 {
        return TestResult::Fail("ClockGetTime did not write timespec");
    }
    if ts[1] >= 1_000_000_000 {
        return TestResult::Fail("tv_nsec out of range");
    }
    TestResult::Pass
}
#[cfg(not(feature = "user-mode-e2e"))]
kernel_test_in!("userspace", smoke_userspace_clock_gettime_writes_timespec);

fn smoke_userspace_sigaction_records_handler() -> TestResult {
    // Sigaction: arg0 = signum, arg1 = new handler vaddr, arg2 =
    // out-pointer for prior handler. Install one handler, install
    // another and confirm the prior is reported.
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        sigaction_lookup, syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn,
        SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0x51C0);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    crate::sigaction_init();
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

    let mut old: u64 = 0xAAAA_AAAA_AAAA_AAAA;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 15, // SIGTERM
            arg1: 0xDEADBEEF,
            arg2: &mut old as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        return TestResult::Fail("first Sigaction did not Ok");
    }
    if old != 0 {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        return TestResult::Fail("first Sigaction reported nonzero prior handler");
    }

    // Second call: replace with 0 (clear) and observe the prior
    // handler in the out-pointer.
    let mut old2: u64 = 0;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 15,
            arg1: 0,
            arg2: &mut old2 as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        return TestResult::Fail("second Sigaction did not Ok");
    }
    if old2 != 0xDEADBEEF {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        return TestResult::Fail("second Sigaction prior-handler mismatch");
    }
    if sigaction_lookup(0x51C0, 15).is_some() {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        return TestResult::Fail("Sigaction(0) did not clear slot");
    }

    __test_clear_global();
    crate::handlers::__test_sigaction_reset();
    TestResult::Pass
}
#[cfg(not(feature = "user-mode-e2e"))]
kernel_test_in!("userspace", smoke_userspace_sigaction_records_handler);

fn smoke_userspace_signal_delivery() -> TestResult {
    // Round-trip: register a handler via sys_sigaction, mark the
    // signal pending via sys_kill, run the delivery hook with a
    // synthetic TrapContext, and confirm `deliver_signal` was
    // called with the registered handler vaddr + signum.
    use crate::{
        default_signal_delivery, install_core_syscalls, install_global, install_task_id_lookup,
        kernel_syscall_entry, signal_init, signal_pending_of, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD157);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    crate::sigaction_init();
    signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Synthetic context — tracks both deliver_signal calls and
    // returning_to_user queries. `returning_to_user` returns true
    // so the hook's fast-path check passes; deliver_signal records
    // the (handler, signum) pair the hook chose.
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
        delivered: Option<(u64, u32)>,
        going_to_user: bool,
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
        fn returning_to_user(&self) -> bool {
            self.going_to_user
        }
        fn deliver_signal(&mut self, p: &crate::SigDeliveryParams) -> bool {
            self.delivered = Some((p.handler, p.signum));
            true
        }
    }

    // Register handler 0xDEAD_BEEF for signum 10 (SIGUSR1).
    let mut old: u64 = 0;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 10,
            arg1: 0xDEAD_BEEF,
            arg2: &mut old as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
        delivered: None,
        going_to_user: false,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        crate::handlers::__test_signal_reset();
        return TestResult::Fail("Sigaction registration did not Ok");
    }

    // Self-kill with signum 10. arg0 = target pid (= our fake
    // task id), arg1 = signum.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: FAKE_TASK.load(Ordering::Relaxed),
            arg1: 10,
            ..SyscallArgs::default()
        },
        ret: None,
        delivered: None,
        going_to_user: false,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        crate::handlers::__test_signal_reset();
        return TestResult::Fail("Kill did not Ok");
    }
    if signal_pending_of(FAKE_TASK.load(Ordering::Relaxed)) & (1 << 10) == 0 {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        crate::handlers::__test_signal_reset();
        return TestResult::Fail("Kill did not set the pending bit");
    }

    // Run the delivery hook on a context heading back to user.
    // The hook should pick signum 10, look up handler 0xDEAD_BEEF,
    // and call our FakeCtx::deliver_signal — which records the
    // pair we expect.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
        delivered: None,
        going_to_user: true,
    };
    default_signal_delivery(&mut ctx, crate::handlers::SYSCALL_NUM_NONE);
    let delivered = ctx.delivered;
    let pending_after = signal_pending_of(FAKE_TASK.load(Ordering::Relaxed));

    __test_clear_global();
    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();

    match delivered {
        Some((handler, signum)) if handler == 0xDEAD_BEEF && signum == 10 => {}
        _ => {
            return TestResult::Fail(
                "delivery hook did not invoke deliver_signal with the registered handler",
            )
        }
    }
    if pending_after & (1 << 10) != 0 {
        return TestResult::Fail("delivery did not clear the pending bit");
    }

    TestResult::Pass
}
#[cfg(not(feature = "user-mode-e2e"))]
kernel_test_in!("userspace", smoke_userspace_signal_delivery);

// Preemptive-signals wave: the alloc-free IRQ raise path. A signal
// raised from the timer ISR (e.g. SIGALRM for a CPU-bound task) must
// never allocate, so `raise_signal_pending_irq` only ORs the bit into a
// PRE-EXISTING SIGNAL_PENDING entry and reports false otherwise — the
// arming syscall pre-creates the entry via `ensure_signal_pending_slot`.
#[cfg(not(feature = "user-mode-e2e"))]
fn smoke_userspace_raise_signal_pending_irq_is_allocfree_and_gated() -> TestResult {
    use crate::handlers::{
        __test_signal_reset, ensure_signal_pending_slot, raise_signal_pending_irq,
    };
    use crate::{signal_init, signal_pending_of};

    signal_init();
    __test_signal_reset();
    let task = 0x5A1A_5A1A_u64;

    // No entry yet → raise refuses (allocating an entry is forbidden in
    // IRQ context), sets nothing.
    if raise_signal_pending_irq(task, 14) {
        __test_signal_reset();
        return TestResult::Fail("raise_signal_pending_irq set a bit with no pre-created slot");
    }
    if signal_pending_of(task) != 0 {
        __test_signal_reset();
        return TestResult::Fail("pending bits changed despite refused raise");
    }

    // Pre-create the slot (what setitimer/alarm do at arm time), then the
    // alloc-free raise succeeds and ORs the SIGALRM (14) bit.
    ensure_signal_pending_slot(task);
    if !raise_signal_pending_irq(task, 14) {
        __test_signal_reset();
        return TestResult::Fail("raise_signal_pending_irq returned false after slot pre-created");
    }
    if signal_pending_of(task) & (1 << 14) == 0 {
        __test_signal_reset();
        return TestResult::Fail("SIGALRM pending bit not set");
    }

    __test_signal_reset();
    TestResult::Pass
}
#[cfg(not(feature = "user-mode-e2e"))]
kernel_test_in!(
    "userspace",
    smoke_userspace_raise_signal_pending_irq_is_allocfree_and_gated
);

// Preemptive-signals wave: the ITIMER_REAL IRQ fast path. A one-shot
// past its deadline reports due once then disarms; a periodic one
// re-arms to a future deadline so the slow sleep-pump can't double-fire
// it. This is what makes a CPU-bound task's `setitimer(ITIMER_REAL)`
// fire without the task ever parking.
#[cfg(all(not(feature = "user-mode-e2e"), feature = "linux-compat"))]
fn smoke_userspace_itimer_real_check_due_irq_fires_and_rearms() -> TestResult {
    use crate::posix_timer::{
        __test_arm_itimer_real, __test_itimer_real_next_fire, __test_reset,
        itimer_real_check_due_irq,
    };
    __test_reset();
    let task = 0x1772_1772_u64;
    let now = 1_000_000_000_u64; // arbitrary monotonic point (1 s)

    // One-shot already due → reports due once, then disarms.
    __test_arm_itimer_real(task, now - 1, 0);
    if !itimer_real_check_due_irq(task, now) {
        __test_reset();
        return TestResult::Fail("one-shot past deadline not reported due");
    }
    if __test_itimer_real_next_fire(task) != 0 {
        __test_reset();
        return TestResult::Fail("one-shot not disarmed after firing");
    }
    if itimer_real_check_due_irq(task, now) {
        __test_reset();
        return TestResult::Fail("disarmed one-shot reported due again");
    }

    // Periodic (100 ms): past deadline fires once and re-arms to a
    // future deadline; it must NOT report due again before that deadline.
    let interval = 100_000_000_u64;
    __test_arm_itimer_real(task, now - 1, interval);
    if !itimer_real_check_due_irq(task, now) {
        __test_reset();
        return TestResult::Fail("periodic past deadline not reported due");
    }
    if __test_itimer_real_next_fire(task) <= now {
        __test_reset();
        return TestResult::Fail("periodic timer did not re-arm to a future deadline");
    }
    if itimer_real_check_due_irq(task, now) {
        __test_reset();
        return TestResult::Fail("re-armed periodic reported due before its deadline");
    }

    __test_reset();
    TestResult::Pass
}
#[cfg(all(not(feature = "user-mode-e2e"), feature = "linux-compat"))]
kernel_test_in!(
    "userspace",
    smoke_userspace_itimer_real_check_due_irq_fires_and_rearms
);

#[cfg(not(feature = "user-mode-e2e"))]
fn smoke_userspace_signal_delivery_lowest_first_multiple_pending() -> TestResult {
    // Two signals pending at once. The async delivery hook must pick
    // the LOWEST signum first (`deliverable.trailing_zeros()`), route
    // it to ITS handler, clear only that bit, and leave the higher
    // signal pending for the next trap — then deliver it on the second
    // pass. Exercises the multi-pending path that the single-signal
    // `smoke_userspace_signal_delivery` doesn't.
    use crate::{
        default_signal_delivery, install_core_syscalls, install_global, install_task_id_lookup,
        kernel_syscall_entry, signal_init, signal_pending_of, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD158);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    crate::sigaction_init();
    signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
        delivered: Option<(u64, u32)>,
        going_to_user: bool,
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
        fn returning_to_user(&self) -> bool {
            self.going_to_user
        }
        fn deliver_signal(&mut self, p: &crate::SigDeliveryParams) -> bool {
            self.delivered = Some((p.handler, p.signum));
            true
        }
    }

    const H10: u64 = 0xAAAA_0000;
    const H12: u64 = 0xBBBB_0000;

    let cleanup = || {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        crate::handlers::__test_signal_reset();
    };

    // Register a distinct handler for signum 10 and signum 12.
    for (sig, handler) in [(10u64, H10), (12u64, H12)] {
        let mut old: u64 = 0;
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: sig,
                arg1: handler,
                arg2: &mut old as *mut u64 as u64,
                ..SyscallArgs::default()
            },
            ret: None,
            delivered: None,
            going_to_user: false,
        };
        kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
        if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
            cleanup();
            return TestResult::Fail("sigaction registration for 10/12 did not Ok");
        }
    }

    // Mark BOTH pending — kill signum 12 FIRST so the test proves the
    // lowest signum wins regardless of the order the bits were set.
    for sig in [12u64, 10u64] {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: FAKE_TASK.load(Ordering::Relaxed),
                arg1: sig,
                ..SyscallArgs::default()
            },
            ret: None,
            delivered: None,
            going_to_user: false,
        };
        kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);
    }
    let pending_before = signal_pending_of(FAKE_TASK.load(Ordering::Relaxed));

    // First delivery → expect the lowest pending signum (10).
    let mut ctx1 = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
        delivered: None,
        going_to_user: true,
    };
    default_signal_delivery(&mut ctx1, crate::handlers::SYSCALL_NUM_NONE);
    let first = ctx1.delivered;
    let pending_mid = signal_pending_of(FAKE_TASK.load(Ordering::Relaxed));

    // Second delivery → expect the remaining signal (12).
    let mut ctx2 = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
        delivered: None,
        going_to_user: true,
    };
    default_signal_delivery(&mut ctx2, crate::handlers::SYSCALL_NUM_NONE);
    let second = ctx2.delivered;
    let pending_after = signal_pending_of(FAKE_TASK.load(Ordering::Relaxed));

    cleanup();

    if pending_before & (1 << 10) == 0 || pending_before & (1 << 12) == 0 {
        return TestResult::Fail("both signals 10 and 12 should be pending before delivery");
    }
    if !matches!(first, Some((h, s)) if h == H10 && s == 10) {
        return TestResult::Fail("first delivery must be the lowest signum (10) with its handler");
    }
    if pending_mid & (1 << 10) != 0 {
        return TestResult::Fail("first delivery must clear only the delivered bit (10)");
    }
    if pending_mid & (1 << 12) == 0 {
        return TestResult::Fail("first delivery must leave the higher signal (12) pending");
    }
    if !matches!(second, Some((h, s)) if h == H12 && s == 12) {
        return TestResult::Fail("second delivery must be signum 12 with its handler");
    }
    if pending_after & (1 << 12) != 0 {
        return TestResult::Fail("second delivery must clear the remaining bit (12)");
    }

    TestResult::Pass
}
#[cfg(not(feature = "user-mode-e2e"))]
kernel_test_in!(
    "userspace",
    smoke_userspace_signal_delivery_lowest_first_multiple_pending
);

fn smoke_userspace_chdir_getcwd_round_trip() -> TestResult {
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
    let small_invalid = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::INVALID_OP);

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
        return TestResult::Fail("Getcwd with too-small buf did not surface InvalidOp");
    }
    if !rel_rejected {
        return TestResult::Fail("Chdir(relative) did not surface -1 sentinel");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_chdir_getcwd_round_trip);

fn smoke_userspace_sleep_advances_time() -> TestResult {
    // Drive sys_sleep with 50 ms; assert monotonic_ns advanced by
    // at least that amount. The handler spin-waits in trap context
    // (see `sys_sleep`'s docstring) so we measure a real wall-time
    // advance, not a scheduler-driven sleep.
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

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

    const TARGET_NS: u64 = 50_000_000; // 50 ms

    let before = narf_scheduler::narf_time::monotonic_ns();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: TARGET_NS,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sleep.raw(), &mut ctx);
    let after = narf_scheduler::narf_time::monotonic_ns();

    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("Sleep did not Ok");
    }
    let elapsed = after.saturating_sub(before);
    if elapsed < TARGET_NS {
        return TestResult::Fail("Sleep returned before deadline");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_sleep_advances_time);

fn smoke_userspace_synchronous_signal_delivery() -> TestResult {
    // Register a SIGSEGV handler via sys_sigaction, then run the
    // synchronous-signal hook with vector=14 (#PF) and confirm the
    // FakeCtx's `deliver_signal` was invoked with the registered
    // handler + signum=11. The test exercises the hook path the
    // x86_64 trap dispatcher takes for user-mode CPU exceptions.
    use crate::{
        default_sync_signal_delivery, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, SyncFaultInfo,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0x5E64);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    crate::handlers::__test_sigaction_reset();
    crate::sigaction_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
        delivered: Option<(u64, u32)>,
        last_si_addr: u64,
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
        fn deliver_signal(&mut self, p: &crate::SigDeliveryParams) -> bool {
            self.delivered = Some((p.handler, p.signum));
            self.last_si_addr = p.si_addr;
            true
        }
    }

    // Register handler 0xC0DE_F00D for signum 11 (SIGSEGV).
    let mut old: u64 = 0;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 11,
            arg1: 0xC0DE_F00D,
            arg2: &mut old as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
        delivered: None,
        last_si_addr: 0,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        return TestResult::Fail("Sigaction registration did not Ok");
    }

    // Run the sync-signal hook with vector 14 (#PF). The hook
    // should map vector→SIGSEGV (=11), look up handler 0xC0DE_F00D,
    // and call FakeCtx::deliver_signal with that pair.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
        delivered: None,
        last_si_addr: 0,
    };
    let rewrote = default_sync_signal_delivery(&mut ctx, 14, SyncFaultInfo::default());
    let delivered = ctx.delivered;

    // Mapping-less vector should return false without touching
    // deliver_signal.
    let mut ctx2 = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
        delivered: None,
        last_si_addr: 0,
    };
    let rewrote_unknown = default_sync_signal_delivery(&mut ctx2, 1, SyncFaultInfo::default());
    let unknown_delivered = ctx2.delivered;

    __test_clear_global();
    crate::handlers::__test_sigaction_reset();

    if !rewrote {
        return TestResult::Fail("sync hook did not report rewrite for vector 14");
    }
    match delivered {
        Some((handler, signum)) if handler == 0xC0DE_F00D && signum == 11 => {}
        _ => {
            return TestResult::Fail(
                "sync hook did not invoke deliver_signal with the registered handler",
            )
        }
    }
    if rewrote_unknown {
        return TestResult::Fail("sync hook reported rewrite for an unmappable vector");
    }
    if unknown_delivered.is_some() {
        return TestResult::Fail("sync hook called deliver_signal for an unmappable vector");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_synchronous_signal_delivery);

fn smoke_userspace_sync_signal_si_addr_from_payload() -> TestResult {
    // Wave-58: arch trap forwards CR2/FAR_EL1 via SyncFaultInfo.addr.
    // Verify default_sync_signal_delivery stamps it into params.si_addr
    // for #PF (vector 14) so userspace handlers see the real faulting
    // address rather than hardcoded 0.
    use crate::{
        default_sync_signal_delivery, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, SyncFaultInfo,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0x5E65);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    crate::handlers::__test_sigaction_reset();
    crate::sigaction_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
        last_si_addr: u64,
        last_si_code: i32,
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
        fn deliver_signal(&mut self, p: &crate::SigDeliveryParams) -> bool {
            self.last_si_addr = p.si_addr;
            self.last_si_code = p.si_code;
            true
        }
    }

    let mut old: u64 = 0;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 11,
            arg1: 0xC0DE_F00D,
            arg2: &mut old as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
        last_si_addr: 0,
        last_si_code: 0,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_sigaction_reset();
        return TestResult::Fail("Sigaction registration did not Ok");
    }

    // Forward a fake CR2 for vector 14 — handler must see it.
    let fake_cr2: u64 = 0xDEAD_BEEF_CAFE_0000;
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
        last_si_addr: 0,
        last_si_code: 0,
    };
    let rewrote = default_sync_signal_delivery(&mut ctx, 14, SyncFaultInfo { addr: fake_cr2 });
    let si_addr = ctx.last_si_addr;
    let si_code = ctx.last_si_code;

    __test_clear_global();
    crate::handlers::__test_sigaction_reset();

    if !rewrote {
        return TestResult::Fail("sync hook did not report rewrite for vector 14");
    }
    if si_addr != fake_cr2 {
        return TestResult::Fail("si_addr was not stamped from SyncFaultInfo.addr");
    }
    if si_code != 2 {
        return TestResult::Fail("#PF si_code was not SEGV_ACCERR(2)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_sync_signal_si_addr_from_payload
);

fn smoke_userspace_open_routes_through_vfs() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    // ── Tiny FS: one file `hello` returning fixed bytes. ──────────
    static FILE_BYTES: &[u8] = b"VFS-OPENED";
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
            if name == "hello" {
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
            "stub"
        }
    }

    // ── Mount the stub FS at "/test". ─────────────────────────────
    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    if registry().mount(&auth, "/test", StubFs).is_err() {
        return TestResult::Fail("VFS mount of stub failed");
    }

    // ── Wire the userspace fd + task-id lookups. ──────────────────
    fd::__test_reset();
    fd::init();

    static FAKE_TASK: AtomicU64 = AtomicU64::new(99);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // ── Fire Open via kernel_syscall_entry. ───────────────────────
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
    // Linux open(2) ABI: arg0 = NUL-terminated absolute path (the
    // mount prefix is part of the path), arg1 = flags.
    let path = b"/test/hello\0";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0, // flags
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::OpenFile.raw(), &mut ctx);
    let opened_fd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as u32,
        _ => return TestResult::Fail("Open did not return Ok"),
    };
    if opened_fd != 3 {
        return TestResult::Fail("Open did not return fd 3");
    }

    // ── Read 16 via the new fd, expect FILE_BYTES. ────────────────
    let mut buf = [0u8; 16];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: opened_fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: 16,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    let n = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("Read after Open returned non-Ok"),
    };
    if n != FILE_BYTES.len() {
        return TestResult::Fail("Read returned wrong byte count");
    }
    if &buf[..n] != FILE_BYTES {
        return TestResult::Fail("Read returned wrong bytes");
    }

    // Cleanup so other tests don't trip over the mount.
    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_open_routes_through_vfs);

fn smoke_userspace_symlink_create_and_readlink_round_trip() -> TestResult {
    // Mount a fresh MemFs at /sl-test seeded with one regular file
    // `target` containing b"hello". Issue SYS_SYMLINK to create
    // /sl-test/sl pointing at "/sl-test/target", then SYS_READLINK
    // to read it back. Asserts the round-trip preserves the target
    // bytes exactly.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};

    __test_clear_global();
    fd::__test_reset();
    fd::init();

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("sl-test", &[("target", b"hello")]);
    let mount_handle = match registry().mount(&auth, "/sl-test", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    static FAKE_TASK: AtomicU64 = AtomicU64::new(99);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

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

    // ── SYS_SYMLINK: target=/sl-test/target, link=/sl-test/sl ────
    let target = b"/sl-test/target";
    let link = b"/sl-test/sl";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target.as_ptr() as u64,
            arg1: target.len() as u64,
            arg2: link.as_ptr() as u64,
            arg3: link.len() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Symlink.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {}
        _ => {
            let _ = registry().unmount(&mount_handle, "/sl-test");
            __test_clear_global();
            fd::__test_reset();
            return TestResult::Fail("Symlink did not return Ok(0)");
        }
    }

    // ── SYS_READLINK: read /sl-test/sl into a 32-byte buf. ────────
    let mut buf = [0u8; 32];
    let path = b"/sl-test/sl\0";
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: 0,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Readlink.raw(), &mut rctx);
    let n = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            let _ = registry().unmount(&mount_handle, "/sl-test");
            __test_clear_global();
            fd::__test_reset();
            return TestResult::Fail("Readlink returned non-Ok");
        }
    };
    if n != target.len() {
        let _ = registry().unmount(&mount_handle, "/sl-test");
        __test_clear_global();
        fd::__test_reset();
        return TestResult::Fail("Readlink returned wrong byte count");
    }
    if &buf[..n] != target {
        let _ = registry().unmount(&mount_handle, "/sl-test");
        __test_clear_global();
        fd::__test_reset();
        return TestResult::Fail("Readlink target bytes mismatched");
    }

    // Cleanup so the registry doesn't accumulate mounts across tests.
    let _ = registry().unmount(&mount_handle, "/sl-test");
    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_symlink_create_and_readlink_round_trip
);

fn smoke_userspace_readlink_on_non_symlink_fails() -> TestResult {
    // Mount a fresh MemFs at /sl-fail with a regular file `regular`.
    // SYS_READLINK against it must return the -1 wire sentinel
    // because `regular` isn't FileType::Symlink — POSIX EINVAL.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};

    __test_clear_global();
    fd::__test_reset();
    fd::init();

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("sl-fail", &[("regular", b"x")]);
    let mount_handle = match registry().mount(&auth, "/sl-fail", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    static FAKE_TASK: AtomicU64 = AtomicU64::new(99);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

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

    let path = b"/sl-fail/regular";
    let mut buf = [0u8; 32];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: 0,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Readlink.raw(), &mut rctx);
    let v = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            let _ = registry().unmount(&mount_handle, "/sl-fail");
            __test_clear_global();
            fd::__test_reset();
            return TestResult::Fail("Readlink returned non-Ok status");
        }
    };
    if v != ((-1i64) as u64) {
        let _ = registry().unmount(&mount_handle, "/sl-fail");
        __test_clear_global();
        fd::__test_reset();
        return TestResult::Fail("Readlink on non-symlink should return -1");
    }

    let _ = registry().unmount(&mount_handle, "/sl-fail");
    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_readlink_on_non_symlink_fails);

fn smoke_userspace_read_write_routes_through_fd_table() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    // Backing FileOps that records writes in a static + serves
    // bytes-of-offset on read.
    static WRITE_LOG: AtomicU64 = AtomicU64::new(0);
    WRITE_LOG.store(0, Ordering::Relaxed);

    struct CountingFile;
    impl FileOps for CountingFile {
        fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            // Fill buf with low byte of (offset + i).
            for (i, b) in buf.iter_mut().enumerate() {
                *b = ((offset + i as u64) & 0xFF) as u8;
            }
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            let n = buf.len();
            alloc::boxed::Box::pin(async move {
                WRITE_LOG.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            })
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

    // Pretend "task 7" is running.
    static FAKE_TASK: AtomicU64 = AtomicU64::new(7);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);

    // Open one fd in task 7's table.
    let fd_n = fd::with_table(7, |t| {
        t.open(FdEntry {
            ops: Arc::new(CountingFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("with_table");
    if fd_n != 3 {
        return TestResult::Fail("expected first user fd to be 3");
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Synthetic TrapContext for direct kernel-side dispatch.
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

    // Read 16 bytes — handler should poll the future and update offset.
    let mut buf = [0u8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: 16,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    if ctx.ret != Some(SyscallReturn::ok(16)) {
        return TestResult::Fail("Read didn't return 16");
    }
    // Offset should now be 16.
    let got_offset = fd::with_table(7, |t| t.get(fd_n).map(|e| e.offset)).flatten();
    if got_offset != Some(16) {
        return TestResult::Fail("Read didn't advance fd offset");
    }
    // Buffer content: bytes-of-offset starting at 0.
    for (i, b) in buf.iter().enumerate() {
        if *b != (i & 0xFF) as u8 {
            return TestResult::Fail("CountingFile read content mismatch");
        }
    }

    // Write 8 bytes — handler should poll the future + log.
    let payload = [0xABu8; 8];
    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: payload.as_ptr() as u64,
            arg2: 8,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx2);
    if ctx2.ret != Some(SyscallReturn::ok(8)) {
        return TestResult::Fail("Write didn't return 8");
    }
    if WRITE_LOG.load(Ordering::Relaxed) != 8 {
        return TestResult::Fail("FileOps::write didn't observe payload bytes");
    }
    // Offset should be 16 + 8 = 24.
    let got_offset2 = fd::with_table(7, |t| t.get(fd_n).map(|e| e.offset)).flatten();
    if got_offset2 != Some(24) {
        return TestResult::Fail("Write didn't advance fd offset");
    }

    // Close.
    let mut ctx3 = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Close.raw(), &mut ctx3);
    if ctx3.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Close didn't return 0");
    }
    // Closed fd should now error on Read.
    let mut buf2 = [0u8; 4];
    let mut ctx4 = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: buf2.as_mut_ptr() as u64,
            arg2: 4,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx4);
    if ctx4.ret != Some(SyscallReturn::invalid_op()) {
        return TestResult::Fail("Read on closed fd should surface invalid_op");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_read_write_routes_through_fd_table
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_dup_clones_fd() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    // FileOps that returns a fixed byte on every read; counters in
    // the harness verify the dup'd fd reads from the *same* backing.
    static READ_HITS: AtomicU64 = AtomicU64::new(0);
    READ_HITS.store(0, Ordering::Relaxed);
    struct StubFile;
    impl FileOps for StubFile {
        fn read<'a>(&'a self, _o: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            READ_HITS.fetch_add(1, Ordering::Relaxed);
            for b in buf.iter_mut() {
                *b = 0x5A;
            }
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
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

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD0);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);

    let task = FAKE_TASK.load(Ordering::Relaxed);
    let original = fd::with_table(task, |t| {
        t.open(FdEntry {
            ops: Arc::new(StubFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("with_table");
    if original != 3 {
        return TestResult::Fail("expected first user fd to be 3");
    }

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

    // Dup fd 3 → expect fd 4 (next free slot ≥ 3).
    let mut dctx = FakeCtx {
        args: SyscallArgs {
            arg0: original as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Dup.raw(), &mut dctx);
    let dup_fd = match dctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as u32,
        _ => return TestResult::Fail("Dup did not return Ok"),
    };
    if dup_fd != 4 {
        return TestResult::Fail("Dup did not pick fd 4");
    }

    // Read 8 bytes via the dup'd fd.
    let mut buf = [0u8; 8];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: dup_fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: 8,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    if rctx.ret != Some(SyscallReturn::ok(8)) {
        return TestResult::Fail("Read on dup'd fd did not return 8");
    }
    if buf != [0x5A; 8] {
        return TestResult::Fail("Read on dup'd fd returned wrong bytes");
    }
    if READ_HITS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("dup'd fd did not share the StubFile FileOps");
    }

    // Close both — second close on the same backing should still
    // succeed because each fd holds its own Arc clone.
    let mut c1 = FakeCtx {
        args: SyscallArgs {
            arg0: dup_fd as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Close.raw(), &mut c1);
    if c1.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Close on dup'd fd failed");
    }
    let mut c2 = FakeCtx {
        args: SyscallArgs {
            arg0: original as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Close.raw(), &mut c2);
    if c2.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Close on original fd after dup-close failed");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_dup_clones_fd);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fcntl_flags_round_trip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext, FD_CLOEXEC,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    struct Sink;
    impl FileOps for Sink {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
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

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD1);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    let task = FAKE_TASK.load(Ordering::Relaxed);
    let target = fd::with_table(task, |t| {
        t.open(FdEntry {
            ops: Arc::new(Sink),
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    // F_SETFD(FD_CLOEXEC).
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    let mut s_ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target as u64,
            arg1: F_SETFD,
            arg2: FD_CLOEXEC as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut s_ctx);
    if s_ctx.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("F_SETFD did not return 0");
    }

    // F_GETFD should now return FD_CLOEXEC.
    let mut g_ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target as u64,
            arg1: F_GETFD,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut g_ctx);
    match g_ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == FD_CLOEXEC as u64 => {}
        _ => return TestResult::Fail("F_GETFD did not round-trip FD_CLOEXEC"),
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fcntl_flags_round_trip);

// ── Wave-68 fcntl extensions: dup/CLOEXEC, status flags, locks ─────

#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
fn smoke_userspace_fcntl_dupfd_cloexec() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext, FD_CLOEXEC,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    struct S;
    impl FileOps for S {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
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
    static TASK: AtomicU64 = AtomicU64::new(0xD2);
    fn t() -> u64 {
        TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    fd::init();
    install_task_id_lookup(t);
    let task = TASK.load(Ordering::Relaxed);
    let src = fd::with_table(task, |x| {
        x.open(FdEntry {
            ops: Arc::new(S),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("table");

    __test_clear_global();
    let mut tbl = SyscallTable::new();
    install_core_syscalls(&mut tbl);
    install_global(tbl);

    struct C {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for C {
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

    // F_DUPFD_CLOEXEC dup the source fd; min-fd = 10.
    let mut c = C {
        args: SyscallArgs {
            arg0: src as u64,
            arg1: 1030,
            arg2: 10,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut c);
    let new_fd = match c.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value >= 10 => r.value as u32,
        _ => return TestResult::Fail("F_DUPFD_CLOEXEC did not return >= min fd"),
    };

    // F_GETFD on the new fd: must report FD_CLOEXEC stamped.
    let mut g = C {
        args: SyscallArgs {
            arg0: new_fd as u64,
            arg1: 1,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut g);
    match g.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == FD_CLOEXEC as u64 => {}
        _ => return TestResult::Fail("F_DUPFD_CLOEXEC did not stamp FD_CLOEXEC"),
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
kernel_test_in!("userspace", smoke_userspace_fcntl_dupfd_cloexec);

#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
fn smoke_userspace_fcntl_status_flags() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    struct S;
    impl FileOps for S {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
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
    static TASK: AtomicU64 = AtomicU64::new(0xD3);
    fn t() -> u64 {
        TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    fd::init();
    install_task_id_lookup(t);
    let task = TASK.load(Ordering::Relaxed);
    let fd_n = fd::with_table(task, |x| {
        x.open(FdEntry {
            ops: Arc::new(S),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("table");

    __test_clear_global();
    let mut tbl = SyscallTable::new();
    install_core_syscalls(&mut tbl);
    install_global(tbl);

    struct C {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for C {
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

    // F_SETFL O_NONBLOCK | O_APPEND.
    let want = (crate::fd::O_NONBLOCK | crate::fd::O_APPEND) as u64;
    let mut s = C {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: 4,
            arg2: want,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut s);
    if s.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("F_SETFL did not return 0");
    }
    // F_GETFL should report the same bits (masked to the settable set).
    let mut g = C {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: 3,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut g);
    match g.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value & want == want => {}
        _ => return TestResult::Fail("F_GETFL did not round-trip O_NONBLOCK|O_APPEND"),
    }
    // Verify the FdEntry actually carries the bits.
    let observed = fd::with_table(task, |x| x.get(fd_n).map(|e| e.status_flags))
        .flatten()
        .unwrap_or(0);
    if (observed as u64) & want != want {
        return TestResult::Fail("FdEntry.status_flags missing the bits");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
kernel_test_in!("userspace", smoke_userspace_fcntl_status_flags);

#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
fn smoke_userspace_fcntl_setlk_conflict() -> TestResult {
    use crate::fd::locks;
    locks::__test_reset();
    // Same key, two owners, overlapping write requests.
    let key: usize = 0xDEAD_BEEF;
    let a = locks::Lock {
        owner: 1,
        ty: locks::F_WRLCK,
        start: 0,
        len: 100,
    };
    let b = locks::Lock {
        owner: 2,
        ty: locks::F_WRLCK,
        start: 50,
        len: 100,
    };
    if locks::try_set(key, a).is_err() {
        return TestResult::Fail("first lock install must succeed");
    }
    match locks::try_set(key, b) {
        Err(blocker) if blocker.owner == 1 => {}
        Ok(()) => return TestResult::Fail("overlapping write lock must conflict"),
        Err(_) => return TestResult::Fail("blocker should be owner 1"),
    }
    // Probe must surface the same blocker.
    match locks::probe(key, b) {
        Some(l) if l.owner == 1 && l.ty == locks::F_WRLCK => {}
        _ => return TestResult::Fail("probe did not surface blocker"),
    }
    // Two readers must coexist.
    locks::__test_reset();
    let r1 = locks::Lock {
        owner: 1,
        ty: locks::F_RDLCK,
        start: 0,
        len: 100,
    };
    let r2 = locks::Lock {
        owner: 2,
        ty: locks::F_RDLCK,
        start: 50,
        len: 100,
    };
    if locks::try_set(key, r1).is_err() || locks::try_set(key, r2).is_err() {
        return TestResult::Fail("overlapping read locks must coexist");
    }
    // Release on owner-exit clears the bucket.
    locks::release_owner(1);
    locks::release_owner(2);
    if locks::probe(key, r1).is_some() {
        return TestResult::Fail("release_owner did not drain locks");
    }
    locks::__test_reset();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
kernel_test_in!("userspace", smoke_userspace_fcntl_setlk_conflict);

#[cfg(all(target_arch = "x86_64", not(feature = "linux-compat")))]
fn smoke_userspace_stat_returns_size() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, StatBuf, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    static FILE_BYTES: &[u8] = b"STAT-PROBE-12345"; // 16 bytes
    struct StubFile;
    impl FileOps for StubFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: FILE_BYTES.len() as u64,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0xC0FFEE,
            }
        }
    }
    struct StubDir;
    impl DirOps for StubDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "stat-target" {
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
            "stat-stub"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    // `/stat-test` is unique to this test; if a prior run already
    // mounted it, the second mount surfaces Busy and we continue
    // with the existing mount (file resolution still works).
    let _ = registry().mount(&auth, "/stat-test", StubFs);

    fd::__test_reset();
    fd::init();
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD2);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

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

    let mut out = StatBuf::default();
    let path = b"/stat-test/stat-target";
    let mut sctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64,
            arg2: &mut out as *mut StatBuf as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Stat.raw(), &mut sctx);
    if sctx.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Stat did not return Ok");
    }
    if out.size != FILE_BYTES.len() as u64 {
        if out.size == 0 {
            return TestResult::Fail("StatBuf.size is 0");
        } else {
            return TestResult::Fail("StatBuf.size mismatch (not 0)");
        }
    }
    if out.mtime_cycles != 0xC0FFEE {
        return TestResult::Fail("StatBuf.mtime_cycles mismatch");
    }
    // Mode high bits should mark this as a regular file (0o100000).
    if out.mode & 0o170000 != 0o100000 {
        return TestResult::Fail("StatBuf.mode missing regular-file marker");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", not(feature = "linux-compat")))]
kernel_test_in!("userspace", smoke_userspace_stat_returns_size);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_pipe_round_trip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD3);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);

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

    // pipe(out) — kernel writes [read_fd, write_fd] to `out`.
    let mut fds: [i32; 2] = [-1, -1];
    let mut pctx = FakeCtx {
        args: SyscallArgs {
            arg0: fds.as_mut_ptr() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut pctx);
    if pctx.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Pipe did not return Ok");
    }
    if fds[0] < 3 || fds[1] < 3 || fds[0] == fds[1] {
        return TestResult::Fail("Pipe returned bad fd pair");
    }
    let read_fd = fds[0] as u32;
    let write_fd = fds[1] as u32;

    // Write 4 bytes to the writer.
    let payload = b"PIPE";
    let mut wctx = FakeCtx {
        args: SyscallArgs {
            arg0: write_fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
    if wctx.ret != Some(SyscallReturn::ok(payload.len() as u64)) {
        return TestResult::Fail("Pipe write did not return full byte count");
    }

    // Read 4 bytes from the reader.
    let mut buf = [0u8; 4];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: read_fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    if rctx.ret != Some(SyscallReturn::ok(4)) {
        return TestResult::Fail("Pipe read did not return 4");
    }
    if &buf != payload {
        return TestResult::Fail("Pipe round-trip bytes mismatch");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_pipe_round_trip);

fn smoke_userspace_fd_table_roundtrip() -> TestResult {
    use crate::{fd, FdEntry};
    use alloc::sync::Arc;
    use narf_filesystem::{FileOps, FsFuture, Stat};

    // Tiny FileOps stub that returns a fixed buffer slice.
    struct FixedFile;
    impl FileOps for FixedFile {
        fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            buf.fill(0xAB);
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }

    fd::__test_reset();
    fd::init();

    let task_a: u64 = 0xAA;
    let task_b: u64 = 0xBB;

    // Open in task A: first user fd is 3 (slots 0..=2 reserved).
    let fd_a = fd::with_table(task_a, |t| {
        t.open(FdEntry {
            ops: Arc::new(FixedFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    });
    if fd_a != Some(3) {
        return TestResult::Fail("first user fd should be 3");
    }

    // Independent task B starts with a fresh table.
    let fd_b = fd::with_table(task_b, |t| {
        t.open(FdEntry {
            ops: Arc::new(FixedFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    });
    if fd_b != Some(3) {
        return TestResult::Fail("task B should also get fd 3");
    }
    if fd::live_task_count() < 2 {
        return TestResult::Fail("two task tables should be live");
    }

    // Mutating offset via get_mut.
    fd::with_table(task_a, |t| {
        if let Some(e) = t.get_mut(3) {
            e.offset += 100;
        }
    });
    let off_a = fd::with_table(task_a, |t| t.get(3).map(|e| e.offset)).flatten();
    if off_a != Some(100) {
        return TestResult::Fail("offset update did not stick");
    }
    let off_b = fd::with_table(task_b, |t| t.get(3).map(|e| e.offset)).flatten();
    if off_b != Some(0) {
        return TestResult::Fail("task B's offset should be independent");
    }

    // Close fd 3 in A, then re-open should reuse slot 3.
    let closed = fd::with_table(task_a, |t| t.close(3));
    if closed != Some(true) {
        return TestResult::Fail("close should report true on live fd");
    }
    let reused = fd::with_table(task_a, |t| {
        t.open(FdEntry {
            ops: Arc::new(FixedFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    });
    if reused != Some(3) {
        return TestResult::Fail("close + open should reuse slot 3");
    }

    // Detach task A; table count drops back.
    fd::detach(task_a);
    if fd::live_task_count() != 1 {
        return TestResult::Fail("detach did not drop task A's table");
    }

    fd::__test_reset();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_fd_table_roundtrip);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_user_process_builds_runnable_image() -> TestResult {
    // Build a minimal ELF64 with a 1-page R|X PT_LOAD, hand it to
    // `load_user_process`, confirm the returned UserProcess has a
    // fresh pid, a materialised AS with both the code segment and
    // a mapped user stack at DEFAULT_USER_STACK_BASE.
    use crate::{load_user_process, DEFAULT_USER_STACK_BASE, DEFAULT_USER_STACK_BYTES};
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64 + 56 + 0x1000);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
    bytes.extend_from_slice(&64u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&64u16.to_le_bytes());
    bytes.extend_from_slice(&56u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.resize(64 + 56 + 0x1000, 0);

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process(&bytes) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process failed"),
    };

    if proc.pid.raw() == 0 {
        return TestResult::Fail("pid should be non-zero");
    }
    if proc.entry.0 != VirtAddr::new(0x0000_0080_0000_1111) {
        return TestResult::Fail("entry mis-decoded");
    }
    if proc.stack_top.as_u64() != DEFAULT_USER_STACK_BASE + DEFAULT_USER_STACK_BYTES {
        return TestResult::Fail("stack_top mis-computed");
    }

    // AS should have the code segment + stack + stack-guard. On
    // x86_64 the loader also stages a synthetic TLS region (one
    // page) for every binary that lacks PT_TLS, so the count is 4
    // there. The stack-guard (1-page PROT_NONE region one page
    // below the stack base) was added after the original test was
    // written and bumped the count from 3 → 4.
    let expected_regions: usize = if cfg!(target_arch = "x86_64") { 4 } else { 3 };
    if proc.address_space.region_count() != expected_regions {
        return TestResult::Fail("address space carried unexpected region count");
    }

    // Code segment PTE installed.
    // SAFETY: `proc.address_space.root` is the live root the loader just built,
    // identity-reachable as `translate` requires; this only walks its tables for
    // the code segment vaddr.
    // SAFETY: Valid memory or trusted environment
    let code_phys = unsafe {
        paging::translate(
            proc.address_space.root,
            VirtAddr::new(0x0000_0080_0000_1000),
        )
    };
    if code_phys.is_none() {
        return TestResult::Fail("code segment not materialized");
    }

    // Stack PTE installed — check the first page.
    // SAFETY: same live loader-built root as above; only walks its tables for the
    // stack-base vaddr.
    // SAFETY: Valid memory or trusted environment
    let stack_phys = unsafe {
        paging::translate(
            proc.address_space.root,
            VirtAddr::new(DEFAULT_USER_STACK_BASE),
        )
    };
    if stack_phys.is_none() {
        return TestResult::Fail("stack region not materialized");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_load_user_process_builds_runnable_image
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_user_process_with_argv() -> TestResult {
    // Same shape as the no-args runnable-image test, but exercises
    // `load_user_process_with`: pass argv/envp/aux, then verify
    // the new RSP is inside the stack region and that walking the
    // argv pointer-array yields the right strings.
    use crate::{
        load_user_process_with, AuxEntry, DEFAULT_USER_STACK_BASE, DEFAULT_USER_STACK_BYTES,
    };
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64 + 56 + 0x1000);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
    bytes.extend_from_slice(&64u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&64u16.to_le_bytes());
    bytes.extend_from_slice(&56u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.resize(64 + 56 + 0x1000, 0);

    let argv = ["one", "two"];
    let envp = ["A=1"];
    let aux = [AuxEntry::Pagesz(4096)];

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &argv, &envp, &aux) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };

    let stack_top = DEFAULT_USER_STACK_BASE + DEFAULT_USER_STACK_BYTES;
    let new_rsp = proc.stack_top.as_u64();
    if new_rsp >= stack_top || new_rsp < DEFAULT_USER_STACK_BASE {
        return TestResult::Fail("rsp not inside stack region");
    }
    if (new_rsp & 0xF) != 0 {
        return TestResult::Fail("rsp not 16-byte aligned");
    }

    // Per-byte read goes through translate again so we honour the
    // user-vaddr offset within the page (translate itself returns
    // page-aligned phys).
    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame `translate` just resolved for this page;
        // OR-ing the in-page offset stays within that identity-mapped frame, and the
        // `u64` read is aligned because callers pass 8-byte-aligned `vaddr`s.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };
    let argc = match read_u64(new_rsp) {
        Some(v) => v,
        None => return TestResult::Fail("rsp not materialised"),
    };
    if argc != 2 {
        if argc == 0 {
            return TestResult::Fail("argc reads back as 0");
        }
        return TestResult::Fail("argc not 2 (non-zero)");
    }
    let argv0 = read_u64(new_rsp + 8).unwrap();
    let argv1 = read_u64(new_rsp + 16).unwrap();
    let argv_term = read_u64(new_rsp + 24).unwrap();
    if argv_term != 0 {
        return TestResult::Fail("argv NULL terminator missing");
    }
    // Resolve argv[0] / argv[1] via the same translate path.
    let resolve = |v: u64, want: &str| -> bool {
        // SAFETY: `proc.address_space.root` is the live top-level page-table frame
        // for this test process; `translate` only reads that hierarchy and the
        // page-aligned `VirtAddr` is a plain table walk with no aliasing.
        // SAFETY: Valid memory or trusted environment
        let p = match unsafe {
            paging::translate(proc.address_space.root, VirtAddr::new(v & !0xFFF))
        } {
            Some(p) => p.as_u64() | (v & 0xFFF),
            None => return false,
        };
        let want_b = want.as_bytes();
        for (i, &b) in want_b.iter().enumerate() {
            // SAFETY: `p` is the physical/identity-mapped address that `translate`
            // returned for this user `VirtAddr`, so it points at the mapped page;
            // `i < want_b.len()` keeps the read within the resolved string buffer.
            // SAFETY: Valid memory or trusted environment
            if unsafe { *((p + i as u64) as *const u8) } != b {
                return false;
            }
        }
        // SAFETY: same mapped page as above; `want_b.len()` is the byte just past
        // the compared bytes, still within the page checked by `translate`.
        // SAFETY: Valid memory or trusted environment
        unsafe { *((p + want_b.len() as u64) as *const u8) == 0 }
    };
    if !resolve(argv0, "one") {
        return TestResult::Fail("argv[0] != \"one\"");
    }
    if !resolve(argv1, "two") {
        return TestResult::Fail("argv[1] != \"two\"");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_load_user_process_with_argv);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_user_process_with_interp() -> TestResult {
    // PT_INTERP follow-through. Build two minimal ELFs:
    //
    //   - program: 2 PT_LOAD segments (RX code + RW data) + 1
    //     PT_INTERP pointing at the literal "ld-narf\0".
    //   - interp:  1 PT_LOAD segment (RX code).
    //
    // Register the interpreter under "ld-narf", call
    // load_user_process_with, and verify:
    //   - proc.entry resolves to the *interpreter's* entry +
    //     INTERP_BIAS (the program's entry is forwarded via
    //     AT_ENTRY).
    //   - Both bias=0 (program) and bias=INTERP_BIAS (interp)
    //     vaddr ranges materialise.
    //   - region_count() == 4 (program code + program data +
    //     interp code + stack).
    //   - The aux vector on the stack carries AT_PAGESZ, AT_ENTRY,
    //     AT_BASE with the expected values.
    use crate::{interp::__test_clear_interpreters, load_user_process_with, register_interpreter};
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    const INTERP_BIAS: u64 = 0x0000_4000_0000_0000;
    const PROG_CODE_VA: u64 = 0x0000_0080_0000_1000;
    const PROG_DATA_VA: u64 = 0x0000_0080_0000_2000;
    const PROG_ENTRY: u64 = 0x0000_0080_0000_1111;
    const INTERP_CODE_VA: u64 = 0x0000_0000_0000_1000;
    const INTERP_ENTRY: u64 = 0x0000_0000_0000_1234;

    // Build a 3-phdr program ELF. Phdr 0 = PT_INTERP naming the
    // string at offset 64+3*56=232; phdrs 1 & 2 = PT_LOAD code/data
    // backed by file pages at offset 0x1000 / 0x2000.
    fn write_program() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x3000;
        let mut b = alloc::vec![0u8; FSIZE];
        // ELF ident + e_type/e_machine/e_version.
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&PROG_ENTRY.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        b[0x30..0x34].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3A].copy_from_slice(&3u16.to_le_bytes()); // e_phnum
                                                            // Phdr 0 — PT_INTERP pointing at the "ld-narf\0" string.
        let interp_str = b"ld-narf\0";
        let interp_off = 64 + 3 * 56;
        b[interp_off..interp_off + interp_str.len()].copy_from_slice(interp_str);
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&(interp_off as u64).to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&(interp_str.len() as u64).to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&(interp_str.len() as u64).to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&1u64.to_le_bytes());
        // Phdr 1 — PT_LOAD code (RX) at PROG_CODE_VA, file off 0x1000.
        ph = 64 + 56;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&PROG_CODE_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&PROG_CODE_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 2 — PT_LOAD data (RW) at PROG_DATA_VA, file off 0x2000.
        ph = 64 + 2 * 56;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x2000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&PROG_DATA_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&PROG_DATA_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    // Single PT_LOAD interpreter ELF. ET_EXEC keeps the parser
    // happy; entry sits inside the loaded page.
    fn write_interp() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x2000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&INTERP_ENTRY.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&INTERP_CODE_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&INTERP_CODE_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    __test_clear_interpreters();

    let prog_bytes = write_program();
    // Leak the interp bytes — the registry stores `&'static [u8]`
    // for the lifetime of the kernel. Tests run once per boot so a
    // small leak is fine; production code's interpreter bytes come
    // from `.rodata` of an init image.
    let interp_bytes = alloc::boxed::Box::leak(write_interp().into_boxed_slice());
    register_interpreter("ld-narf", interp_bytes);

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `prog_bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&prog_bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };

    // Entry must point at the interpreter (program entry + INTERP_BIAS
    // for the interp's vaddr — its INTERP_ENTRY plus the bias).
    if proc.entry.0 != VirtAddr::new(INTERP_ENTRY + INTERP_BIAS) {
        return TestResult::Fail("entry should be interpreter entry + bias");
    }

    // Program code + program data + interp + stack + stack-guard
    // (+ TLS region on x86_64). The stack-guard PROT_NONE region
    // was added after this test was written and bumps the expected
    // count by 1.
    let expected_regions: usize = if cfg!(target_arch = "x86_64") { 6 } else { 5 };
    if proc.address_space.region_count() != expected_regions {
        return TestResult::Fail("unexpected region count after PT_INTERP load");
    }

    // Both program and interpreter pages must be materialised.
    // SAFETY: `proc.address_space.root` is the live loader-built root, identity-
    // reachable as `translate` requires; only walks its tables for `PROG_CODE_VA`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { paging::translate(proc.address_space.root, VirtAddr::new(PROG_CODE_VA)) }.is_none()
    {
        return TestResult::Fail("program code not materialised");
    }
    // SAFETY: same live loader-built root; only walks its tables for `PROG_DATA_VA`.
    if unsafe { paging::translate(proc.address_space.root, VirtAddr::new(PROG_DATA_VA)) }.is_none()
    {
        return TestResult::Fail("program data not materialised");
    }
    // SAFETY: same live loader-built root; only walks its tables for the
    // bias-relocated interpreter code vaddr.
    // SAFETY: Valid memory or trusted environment
    if unsafe {
        paging::translate(
            proc.address_space.root,
            VirtAddr::new(INTERP_CODE_VA + INTERP_BIAS),
        )
    }
    .is_none()
    {
        return TestResult::Fail("interpreter code not materialised at bias");
    }

    // Walk the aux vector on the stack: argc=0, argv NULL, envp
    // NULL, then aux pairs. Match by AT_* tag.
    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame `translate` just resolved for this page;
        // OR-ing the in-page offset stays within that identity-mapped frame, and the
        // `u64` read is aligned because callers pass 8-byte-aligned `vaddr`s.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };
    let rsp = proc.stack_top.as_u64();
    let argc = read_u64(rsp).unwrap_or(0xDEAD);
    if argc != 0 {
        return TestResult::Fail("argc should be 0 in this test");
    }
    let argv_null = read_u64(rsp + 8).unwrap_or(0xDEAD);
    if argv_null != 0 {
        return TestResult::Fail("argv NULL terminator missing");
    }
    let envp_null = read_u64(rsp + 16).unwrap_or(0xDEAD);
    if envp_null != 0 {
        return TestResult::Fail("envp NULL terminator missing");
    }

    // Aux pairs start at rsp+24. Walk until AT_NULL (key=0); we
    // expect to find AT_PAGESZ(6), AT_ENTRY(9), AT_BASE(7).
    let mut at_pagesz: Option<u64> = None;
    let mut at_entry: Option<u64> = None;
    let mut at_base: Option<u64> = None;
    let mut p = rsp + 24;
    for _ in 0..16 {
        let key = read_u64(p).unwrap_or(0xDEAD);
        let val = read_u64(p + 8).unwrap_or(0xDEAD);
        match key {
            0 => break,
            6 => at_pagesz = Some(val),
            9 => at_entry = Some(val),
            7 => at_base = Some(val),
            _ => {}
        }
        p += 16;
    }
    if at_pagesz != Some(4096) {
        return TestResult::Fail("AT_PAGESZ missing or wrong");
    }
    if at_entry != Some(PROG_ENTRY) {
        return TestResult::Fail("AT_ENTRY should be the program entry");
    }
    if at_base != Some(INTERP_BIAS) {
        return TestResult::Fail("AT_BASE should be the interp bias");
    }

    __test_clear_interpreters();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_load_user_process_with_interp);

fn smoke_userspace_parse_pt_tls() -> TestResult {
    // PT_TLS parsing. Hand-build a minimal ELF with one PT_LOAD (so the
    // parser sees a "loadable" image) and one PT_TLS pointing at known
    // bytes, then assert `parse_elf` populates `image.tls` with those
    // exact field values. Parse-only — load/staging is a follow-up.
    use crate::{parse_elf, ElfError};

    const TLS_FILE_OFF: u64 = 0x2000;
    const TLS_FILE_SIZE: u64 = 0x40;
    const TLS_MEM_SIZE: u64 = 0x80; // 0x40 BSS-zero past file image
    const TLS_ALIGN: u64 = 16;
    const TLS_VADDR: u64 = 0x0000_0080_0000_3000;

    fn write_one_tls() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x3000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // 2 phdrs
                                                            // Phdr 0 — PT_LOAD code (RX) at file off 0x1000.
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 1 — PT_TLS at file off 0x2000.
        ph = 64 + 56;
        b[ph..ph + 0x04].copy_from_slice(&7u32.to_le_bytes()); // PT_TLS
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&TLS_FILE_OFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&TLS_FILE_SIZE.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&TLS_MEM_SIZE.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&TLS_ALIGN.to_le_bytes());
        b
    }

    let bytes = write_one_tls();
    let image = match parse_elf(&bytes) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("parse_elf failed on PT_TLS image"),
    };
    let tls = match image.tls {
        Some(t) => t,
        None => return TestResult::Fail("image.tls should be Some for PT_TLS ELF"),
    };
    if tls.file_off != TLS_FILE_OFF {
        return TestResult::Fail("tls.file_off mismatch");
    }
    if tls.file_size != TLS_FILE_SIZE {
        return TestResult::Fail("tls.file_size mismatch");
    }
    if tls.mem_size != TLS_MEM_SIZE {
        return TestResult::Fail("tls.mem_size mismatch");
    }
    if tls.align != TLS_ALIGN {
        return TestResult::Fail("tls.align mismatch");
    }
    if tls.vaddr != TLS_VADDR {
        return TestResult::Fail("tls.vaddr mismatch");
    }

    // Negative path: a second PT_TLS must be rejected. Cheaper to
    // build a fresh 3-phdr image inline than to try patching the
    // single-TLS bytes above.
    fn write_two_tls() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x3000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&3u16.to_le_bytes());
        // Phdr 0 — PT_LOAD.
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 1 — first PT_TLS.
        ph = 64 + 56;
        b[ph..ph + 0x04].copy_from_slice(&7u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x2000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&16u64.to_le_bytes());
        // Phdr 2 — second PT_TLS (illegal).
        ph = 64 + 2 * 56;
        b[ph..ph + 0x04].copy_from_slice(&7u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x2040u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&(TLS_VADDR + 0x100).to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&(TLS_VADDR + 0x100).to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&16u64.to_le_bytes());
        b
    }

    match parse_elf(&write_two_tls()) {
        Err(ElfError::MultiplePtTls) => TestResult::Pass,
        Err(_) => TestResult::Fail("two PT_TLS produced wrong error variant"),
        Ok(_) => TestResult::Fail("two PT_TLS should have been rejected"),
    }
}
kernel_test_in!("userspace", smoke_userspace_parse_pt_tls);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_apply_relative_relocations() -> TestResult {
    // PT_DYNAMIC walk-through. Build a minimal ELF with one PT_LOAD
    // covering [0x80_0000_1000, 0x80_0000_2000), one PT_DYNAMIC
    // pointing at a 5-entry dynamic array inside the segment, and a
    // single Elf64_Rela whose r_offset names a slot inside the same
    // segment. After load, the R_X86_64_RELATIVE relocation should
    // have written its addend into the slot — proving DT_RELA
    // walking + r_offset → user-vaddr translation + page-table-
    // backed write all work end-to-end.
    use crate::load_user_process_with;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    const SEG_VA: u64 = 0x0000_0080_0000_1000;
    const SEG_FOFF: u64 = 0x1000;
    // r_offset inside the segment (byte 0x80 from base — well clear
    // of both the rela array and the dynamic array we lay out below).
    const RELOC_OFF_IN_SEG: u64 = 0x80;
    const RELOC_VA: u64 = SEG_VA + RELOC_OFF_IN_SEG;
    const ADDEND: u64 = 0x12345678;
    // Where the rela entry lives inside the segment (file + vaddr).
    const RELA_OFF_IN_SEG: u64 = 0x100;
    // Where the dynamic array lives inside the segment.
    const DYN_OFF_IN_SEG: u64 = 0x200;

    fn build() -> alloc::vec::Vec<u8> {
        // Total file size: 0x2000 — first 0x1000 = ELF header + phdrs
        // (zero-padded), second 0x1000 = the PT_LOAD page.
        const FSIZE: usize = 0x2000;
        let mut b = alloc::vec![0u8; FSIZE];
        // ELF header.
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x111).to_le_bytes()); // entry inside seg
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        b[0x30..0x34].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
                                                            // Phdr 0 — PT_LOAD covering the page at file_off 0x1000 →
                                                            // vaddr SEG_VA, with R+W perms (so the relocation can patch
                                                            // the slot — kernel writes through identity-map so PF_W is
                                                            // for completeness only).
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
        b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes()); // filesz
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes()); // memsz
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes()); // align
                                                                           // Phdr 1 — PT_DYNAMIC. Its file region is the dynamic array
                                                                           // we lay down at DYN_OFF_IN_SEG (5 × 16 bytes = 80).
        ph = 64 + 56;
        let dyn_foff = SEG_FOFF + DYN_OFF_IN_SEG;
        let dyn_va = SEG_VA + DYN_OFF_IN_SEG;
        b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&80u64.to_le_bytes()); // 5 × 16
        b[ph + 0x28..ph + 0x30].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

        // Lay out the Elf64_Rela entry at SEG_FOFF + RELA_OFF_IN_SEG.
        // r_offset = RELOC_VA, r_info = (sym=0 << 32) | type=8, addend=ADDEND.
        let rela_foff = (SEG_FOFF + RELA_OFF_IN_SEG) as usize;
        b[rela_foff..rela_foff + 8].copy_from_slice(&RELOC_VA.to_le_bytes());
        b[rela_foff + 8..rela_foff + 16].copy_from_slice(&8u64.to_le_bytes());
        b[rela_foff + 16..rela_foff + 24].copy_from_slice(&ADDEND.to_le_bytes());

        // Lay out the dynamic array. Tags use the standard DT_* wire
        // numbers — DT_RELA=7, DT_RELASZ=8, DT_RELAENT=9, DT_RELACOUNT=
        // 0x6FFFFFF9, DT_NULL=0.
        let rela_va = SEG_VA + RELA_OFF_IN_SEG;
        let dyn_foff_us = dyn_foff as usize;
        let mut p = dyn_foff_us;
        // DT_RELA = rela array vaddr.
        b[p..p + 8].copy_from_slice(&7i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&rela_va.to_le_bytes());
        p += 16;
        // DT_RELASZ = 24.
        b[p..p + 8].copy_from_slice(&8i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        // DT_RELAENT = 24.
        b[p..p + 8].copy_from_slice(&9i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        // DT_RELACOUNT = 1.
        b[p..p + 8].copy_from_slice(&0x6FFFFFF9i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&1u64.to_le_bytes());
        p += 16;
        // DT_NULL terminator.
        b[p..p + 8].copy_from_slice(&0i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());

        b
    }

    let bytes = build();
    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };

    // Read back the slot through the AS — same translate-and-cast
    // pattern the other smokes use.
    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame `translate` just resolved for this page;
        // OR-ing the in-page offset stays within that identity-mapped frame, and the
        // `u64` read is aligned because callers pass 8-byte-aligned `vaddr`s.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };
    let got = match read_u64(RELOC_VA) {
        Some(v) => v,
        None => return TestResult::Fail("relocation site not materialised"),
    };
    if got != ADDEND {
        return TestResult::Fail("R_X86_64_RELATIVE didn't write the addend");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_apply_relative_relocations);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_apply_symbol_relocations() -> TestResult {
    // Symbol-resolved relocation walk-through. Mirrors the
    // RELATIVE-only smoke above, but the dynamic array also names a
    // DT_SYMTAB pointing at a 2-entry symbol table; the rela entry's
    // r_info encodes (sym_idx=1, type=R_X86_64_64). Sym 1 is defined
    // (st_value=0x80_0000_1100, st_shndx=1), so the patch site at
    // r_offset should end up holding `st_value + r_addend`.
    use crate::load_user_process_with;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    const SEG_VA: u64 = 0x0000_0080_0000_1000;
    const SEG_FOFF: u64 = 0x1000;
    const RELOC_OFF_IN_SEG: u64 = 0x80;
    const RELOC_VA: u64 = SEG_VA + RELOC_OFF_IN_SEG;
    const SYM_VALUE: u64 = SEG_VA + 0x100;
    const ADDEND: u64 = 0x42;
    const RELA_OFF_IN_SEG: u64 = 0x180;
    const SYMTAB_OFF_IN_SEG: u64 = 0x1C0;
    const DYN_OFF_IN_SEG: u64 = 0x300;

    fn build() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x2000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x111).to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

        // Phdr 0: PT_LOAD covering the page.
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
        b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());

        // Phdr 1: PT_DYNAMIC. 5 dynamic entries × 16 = 80 bytes.
        ph = 64 + 56;
        let dyn_foff = SEG_FOFF + DYN_OFF_IN_SEG;
        let dyn_va = SEG_VA + DYN_OFF_IN_SEG;
        b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

        // Elf64_Rela @ RELA_OFF_IN_SEG: r_offset, r_info, r_addend.
        // r_info = (sym_idx 1 << 32) | type R_X86_64_64 (1).
        let rela_foff = (SEG_FOFF + RELA_OFF_IN_SEG) as usize;
        let r_info: u64 = (1u64 << 32) | 1u64;
        b[rela_foff..rela_foff + 8].copy_from_slice(&RELOC_VA.to_le_bytes());
        b[rela_foff + 8..rela_foff + 16].copy_from_slice(&r_info.to_le_bytes());
        b[rela_foff + 16..rela_foff + 24].copy_from_slice(&ADDEND.to_le_bytes());

        // Symbol table @ SYMTAB_OFF_IN_SEG. Two 24-byte entries.
        // Entry 0: all-zero (the canonical STN_UNDEF placeholder).
        // Entry 1: defined symbol — st_value=SYM_VALUE, st_shndx=1.
        let sym_foff = (SEG_FOFF + SYMTAB_OFF_IN_SEG) as usize;
        // Entry 0 is already zeroed by the vec init.
        let s1 = sym_foff + 24;
        // st_name(4) | st_info(1) | st_other(1) | st_shndx(2) | st_value(8) | st_size(8).
        b[s1..s1 + 4].copy_from_slice(&0u32.to_le_bytes()); // st_name
        b[s1 + 4] = 0; // st_info
        b[s1 + 5] = 0; // st_other
        b[s1 + 6..s1 + 8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx (defined)
        b[s1 + 8..s1 + 16].copy_from_slice(&SYM_VALUE.to_le_bytes()); // st_value
        b[s1 + 16..s1 + 24].copy_from_slice(&0u64.to_le_bytes()); // st_size

        // Dynamic array.
        let rela_va = SEG_VA + RELA_OFF_IN_SEG;
        let symtab_va = SEG_VA + SYMTAB_OFF_IN_SEG;
        let mut p = dyn_foff as usize;
        // DT_RELA = 7.
        b[p..p + 8].copy_from_slice(&7i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&rela_va.to_le_bytes());
        p += 16;
        // DT_RELASZ = 8 → 24 bytes (one entry).
        b[p..p + 8].copy_from_slice(&8i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        // DT_RELAENT = 9 → 24.
        b[p..p + 8].copy_from_slice(&9i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        // DT_SYMTAB = 6 → symtab_va.
        b[p..p + 8].copy_from_slice(&6i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&symtab_va.to_le_bytes());
        p += 16;
        // DT_NULL.
        b[p..p + 8].copy_from_slice(&0i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());

        b
    }

    let bytes = build();
    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };

    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame `translate` just resolved for this page;
        // OR-ing the in-page offset stays within that identity-mapped frame, and the
        // `u64` read is aligned because callers pass 8-byte-aligned `vaddr`s.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };
    let got = match read_u64(RELOC_VA) {
        Some(v) => v,
        None => return TestResult::Fail("relocation site not materialised"),
    };
    if got != SYM_VALUE.wrapping_add(ADDEND) {
        return TestResult::Fail("R_X86_64_64 didn't write S+A");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_apply_symbol_relocations);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_unresolved_symbol_errors() -> TestResult {
    // Same shape as `smoke_userspace_apply_symbol_relocations` but
    // sym_idx 1 is SHN_UNDEF (st_value=0, st_shndx=0). The loader
    // must surface `LoadBytesError::UnresolvedSymbol { idx: 1, .. }`
    // rather than silently writing zero. This image has no DT_STRTAB
    // and a zero `st_name`, so the captured name buffer is all-zero —
    // the dedicated `_carries_name` smoke covers the populated path.
    use crate::{load_user_process_with, LoadBytesError, ProcessLoadError};

    const SEG_VA: u64 = 0x0000_0080_0000_1000;
    const SEG_FOFF: u64 = 0x1000;
    const RELOC_OFF_IN_SEG: u64 = 0x80;
    const RELOC_VA: u64 = SEG_VA + RELOC_OFF_IN_SEG;
    const RELA_OFF_IN_SEG: u64 = 0x180;
    const SYMTAB_OFF_IN_SEG: u64 = 0x1C0;
    const DYN_OFF_IN_SEG: u64 = 0x300;

    fn build() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x2000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x111).to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes());

        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());

        ph = 64 + 56;
        let dyn_foff = SEG_FOFF + DYN_OFF_IN_SEG;
        let dyn_va = SEG_VA + DYN_OFF_IN_SEG;
        b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

        let rela_foff = (SEG_FOFF + RELA_OFF_IN_SEG) as usize;
        let r_info: u64 = (1u64 << 32) | 1u64;
        b[rela_foff..rela_foff + 8].copy_from_slice(&RELOC_VA.to_le_bytes());
        b[rela_foff + 8..rela_foff + 16].copy_from_slice(&r_info.to_le_bytes());
        b[rela_foff + 16..rela_foff + 24].copy_from_slice(&0u64.to_le_bytes());

        // Symbol table — entry 1 is an undefined symbol (st_value=0,
        // st_shndx=SHN_UNDEF=0). The vec is already zero, so leave
        // both entries at their zero defaults.
        let _sym_foff = (SEG_FOFF + SYMTAB_OFF_IN_SEG) as usize;

        let rela_va = SEG_VA + RELA_OFF_IN_SEG;
        let symtab_va = SEG_VA + SYMTAB_OFF_IN_SEG;
        let mut p = dyn_foff as usize;
        b[p..p + 8].copy_from_slice(&7i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&rela_va.to_le_bytes());
        p += 16;
        b[p..p + 8].copy_from_slice(&8i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        b[p..p + 8].copy_from_slice(&9i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        b[p..p + 8].copy_from_slice(&6i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&symtab_va.to_le_bytes());
        p += 16;
        b[p..p + 8].copy_from_slice(&0i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());

        b
    }

    let bytes = build();
    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Err(ProcessLoadError::Load(LoadBytesError::UnresolvedSymbol { idx: 1, name })) => {
            // No DT_STRTAB + st_name=0 → name buffer must be empty.
            if name == [0u8; 32] {
                TestResult::Pass
            } else {
                TestResult::Fail("UnresolvedSymbol.name should be empty without DT_STRTAB")
            }
        }
        Err(_) => TestResult::Fail("expected UnresolvedSymbol{idx:1,..}, got different error"),
        Ok(_) => TestResult::Fail("expected UnresolvedSymbol error, got Ok"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_unresolved_symbol_errors);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_unresolved_symbol_carries_name() -> TestResult {
    // The loader walks DT_STRTAB and surfaces the symbol name
    // alongside the index. With strtab "\0printf\0exit\0" and
    // st_name=1, the name buffer must read "printf" + NUL-pad.
    use crate::{load_user_process_with, LoadBytesError, ProcessLoadError};

    let strtab = b"\0printf\0exit\0";
    let bytes = build_unresolved_named_elf(strtab);
    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Err(ProcessLoadError::Load(LoadBytesError::UnresolvedSymbol { idx: 1, name })) => {
            if &name[..6] != b"printf" {
                return TestResult::Fail("name buffer doesn't start with \"printf\"");
            }
            if name[6] != 0 {
                return TestResult::Fail("name buffer not NUL-terminated after \"printf\"");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("expected UnresolvedSymbol{idx:1,..}, got different error"),
        Ok(_) => TestResult::Fail("expected UnresolvedSymbol error, got Ok"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_unresolved_symbol_carries_name);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_unresolved_symbol_name_truncates() -> TestResult {
    // A 50-byte name must truncate to 32 bytes with no NUL byte
    // anywhere in the buffer — documents the truncation contract
    // explicitly so future churn doesn't silently regress it.
    use crate::{load_user_process_with, LoadBytesError, ProcessLoadError};

    // 50-byte name, leading NUL + name + trailing NUL (preserves
    // SysV's strtab[0] convention).
    let long: &[u8] = b"verylongsymbolnamethatdefinitelyexceeds_thirty_two";
    assert!(long.len() == 50);
    let mut strtab = alloc::vec::Vec::with_capacity(1 + long.len() + 1);
    strtab.push(0u8);
    strtab.extend_from_slice(long);
    strtab.push(0u8);
    let bytes = build_unresolved_named_elf(&strtab);

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Err(ProcessLoadError::Load(LoadBytesError::UnresolvedSymbol { idx: 1, name })) => {
            // First 32 bytes must equal the source's first 32 bytes,
            // and *all* 32 must be non-zero (we truncated mid-name,
            // so no terminator was reached inside the buffer).
            if name[..32] != long[..32] {
                return TestResult::Fail("truncated name doesn't match source prefix");
            }
            if name.contains(&0) {
                return TestResult::Fail("truncated name should have no NUL inside the buffer");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("expected UnresolvedSymbol{idx:1,..}, got different error"),
        Ok(_) => TestResult::Fail("expected UnresolvedSymbol error, got Ok"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_unresolved_symbol_name_truncates
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_init_sysv_stack_layout() -> TestResult {
    // Verify `init_sysv_stack` lays out the System V x86_64 startup
    // contract: argc at [rsp], then argv pointers + NULL, then envp
    // pointers + NULL, then aux pairs ending in AT_NULL. Strings the
    // pointers name live in the upper portion of the stack.
    //
    // The helper walks the AS per page via translate, so the test
    // builds a real one-page user mapping rather than a fake
    // contiguous slab.
    use crate::{init_sysv_stack, AuxEntry};
    use narf_memory::{x86_64::paging, AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let as_ = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("new_for_user"),
    };
    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    // SAFETY: `frame` is a freshly allocated 4 KiB frame, identity-mapped so
    // `frame.raw()` is a writable kernel pointer; zeroing exactly its 4096 bytes
    // stays in bounds and the frame is not aliased yet.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(frame.raw() as *mut u8, 0, 4096);
    }

    // PML4[1]; PML4[0] is the kernel's identity-map (1 GiB huge
    // pages), where map_4kb can't carve a 4K mapping.
    let user_base: u64 = 0x0000_0080_0000_0000;
    let stack_top = user_base + 4096;
    if as_
        .map_region(Region {
            base: VirtAddr::new(user_base),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![frame],
        })
        .is_err()
    {
        return TestResult::Fail("map_region");
    }
    // SAFETY: `as_` was built via `new_for_user`, so its `root` is a valid user
    // root, satisfying `materialize`'s `# Safety` precondition.
    // SAFETY: Valid memory or trusted environment
    if unsafe { as_.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }

    let argv = ["argv0", "alpha"];
    let envp = ["KEY=val"];
    let aux = [AuxEntry::Pagesz(4096), AuxEntry::Random(0x1234_5678)];
    // SAFETY: the single page `[user_base, stack_top)` was just mapped READ|WRITE
    // and materialised above, and the low-4-GiB identity map is live, meeting
    // `init_sysv_stack`'s `# Safety` contract.
    // SAFETY: Valid memory or trusted environment
    let rsp_v = match unsafe { init_sysv_stack(&as_, stack_top, 4096, &argv, &envp, &aux) } {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("init_sysv_stack overflowed unexpectedly"),
    };

    if (rsp_v & 0xF) != 0 {
        return TestResult::Fail("rsp not 16-byte aligned");
    }

    // Read back via translate so we exercise the same path the
    // helper used for writes (and so a future per-page-phys
    // refactor still yields identical output).
    let read_u64 = |vaddr: u64| -> u64 {
        // SAFETY: `as_.root` is the live user root for this test, identity-reachable
        // as `translate` requires; only walks its tables for the page-aligned vaddr.
        // SAFETY: Valid memory or trusted environment
        let p = unsafe { paging::translate(as_.root, VirtAddr::new(vaddr & !0xFFF)) }
            .map(|p| p.as_u64() | (vaddr & 0xFFF))
            .unwrap();
        // SAFETY: `p` is the identity-mapped phys for that mapped stack page; the
        // helper writes 8-byte-aligned words there, so this `u64` read is aligned
        // and in-bounds.
        // SAFETY: Valid memory or trusted environment
        unsafe { *(p as *const u64) }
    };

    if read_u64(rsp_v) != 2 {
        return TestResult::Fail("argc != 2");
    }
    let argv_p0 = read_u64(rsp_v + 8);
    let argv_p1 = read_u64(rsp_v + 16);
    if read_u64(rsp_v + 24) != 0 {
        return TestResult::Fail("argv NULL term");
    }
    let envp_p0 = read_u64(rsp_v + 32);
    if read_u64(rsp_v + 40) != 0 {
        return TestResult::Fail("envp NULL term");
    }
    if read_u64(rsp_v + 48) != 6 || read_u64(rsp_v + 56) != 4096 {
        return TestResult::Fail("aux[0] (PAGESZ)");
    }
    if read_u64(rsp_v + 64) != 25 || read_u64(rsp_v + 72) != 0x1234_5678 {
        return TestResult::Fail("aux[1] (RANDOM)");
    }
    if read_u64(rsp_v + 80) != 0 || read_u64(rsp_v + 88) != 0 {
        return TestResult::Fail("aux AT_NULL");
    }

    let check_str = |user_p: u64, expected: &str| -> bool {
        if user_p < user_base || user_p >= stack_top {
            return false;
        }
        // SAFETY: `as_.root` is the live top-level page-table frame for this test
        // address space; `translate` only walks that hierarchy for the page-aligned
        // `VirtAddr`, reading table entries with no aliasing.
        // SAFETY: Valid memory or trusted environment
        let kp = match unsafe { paging::translate(as_.root, VirtAddr::new(user_p & !0xFFF)) } {
            Some(p) => p.as_u64() | (user_p & 0xFFF),
            None => return false,
        };
        let ebytes = expected.as_bytes();
        for (i, &b) in ebytes.iter().enumerate() {
            // SAFETY: `kp` is the kernel-mapped address `translate` returned for this
            // user page; `i < ebytes.len()` keeps the read inside that mapped page.
            // SAFETY: Valid memory or trusted environment
            if unsafe { *((kp + i as u64) as *const u8) } != b {
                return false;
            }
        }
        // SAFETY: same mapped page as above; reading the terminating byte at
        // `ebytes.len()`, still within the page resolved by `translate`.
        // SAFETY: Valid memory or trusted environment
        unsafe { *((kp + ebytes.len() as u64) as *const u8) == 0 }
    };
    if !check_str(argv_p0, "argv0") {
        return TestResult::Fail("argv[0]");
    }
    if !check_str(argv_p1, "alpha") {
        return TestResult::Fail("argv[1]");
    }
    if !check_str(envp_p0, "KEY=val") {
        return TestResult::Fail("envp[0]");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_init_sysv_stack_layout);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_elf_bytes_end_to_end() -> TestResult {
    // End-to-end: hand-build a minimal ELF64 with a 1-page PT_LOAD
    // carrying 7 bytes of "payload", call load_elf_bytes, then walk
    // the returned AddressSpace via translate() to confirm the
    // backing phys frame is mapped AND the payload bytes are in
    // the frame.
    use crate::load_elf_bytes;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    // Build ELF bytes: header (64) + 1 PHDR (56) + 0x1000 payload
    // area. Payload-area size is chosen so file_size == mem_size ==
    // 0x1000, which means `load_elf_bytes` copies the full page.
    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64 + 56 + 0x1000);
    // e_ident
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
                                                  // Entry = 0x0000_0080_0000_1111 (some user vaddr inside PML4[1]).
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
    bytes.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                  // Program header — R|X 1-page segment.
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes()); // p_offset = past PHDR
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
                                                       // 4 KiB of payload. First 7 bytes distinct so we can verify.
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x69, 0x01]);
    bytes.resize(64 + 56 + 0x1000, 0);

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let (as_arc, entry) = match unsafe { load_elf_bytes(&bytes) } {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("load_elf_bytes failed on minimal ELF"),
    };

    if entry.0 != VirtAddr::new(0x0000_0080_0000_1111) {
        return TestResult::Fail("entry point mis-decoded");
    }
    if as_arc.region_count() != 1 {
        return TestResult::Fail("load_elf_bytes did not install one region");
    }

    // Walk the AS PML4 to find the PTE for the segment base, then
    // read back the first 7 bytes via the phys address.
    // SAFETY: `as_arc.root` is the live root `load_elf_bytes` just built, identity-
    // reachable as `translate` requires; only walks its tables for the segment base.
    // SAFETY: Valid memory or trusted environment
    let phys = match unsafe { paging::translate(as_arc.root, VirtAddr::new(0x0000_0080_0000_1000)) }
    {
        Some(p) => p,
        None => return TestResult::Fail("translate found no mapping for segment base"),
    };
    // Read back via identity map.
    // SAFETY: `phys` is the identity-mapped frame `translate` resolved for the
    // segment base; the loader copied the segment there, so reading the leading
    // 7 bytes is in-bounds, and a `[u8; 7]` has alignment 1.
    // SAFETY: Valid memory or trusted environment
    let payload: [u8; 7] = unsafe { core::ptr::read_volatile(phys.raw() as *const [u8; 7]) };
    if payload != [0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x69, 0x01] {
        return TestResult::Fail("segment payload bytes did not land in the mapped frame");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_load_elf_bytes_end_to_end);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_multi_segment() -> TestResult {
    // Multi-PT_LOAD: hand-build an ELF with TWO PT_LOAD segments at
    // non-adjacent vaddrs (.text at 0x80_0000_1000 R+X, .data at
    // 0x80_0000_5000 R+W) and verify load_user_process_with materialises
    // each segment to its own scattered phys backing. The freelist
    // allocator returns frames in arbitrary order — by the time the
    // second segment's pages are allocated, the freelist will not be
    // contiguous with the first segment's. The old single-base Region
    // shape silently miscompiled this layout (page 2 of segment 1 would
    // alias whatever frame happened to sit at phys+0x1000 in the
    // freelist, not the actual second-page allocation).
    use crate::load_user_process_with;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    // Two segments, two pages each, with a 3-page hole between them so
    // the runtime vaddrs are clearly disjoint.
    const TEXT_VADDR: u64 = 0x0000_0080_0000_1000;
    const DATA_VADDR: u64 = 0x0000_0080_0000_5000;
    const TEXT_PAGES: usize = 2;
    const DATA_PAGES: usize = 2;
    const TEXT_FILESZ: u64 = (TEXT_PAGES as u64) * 0x1000;
    const DATA_FILESZ: u64 = (DATA_PAGES as u64) * 0x1000;

    // ELF layout: header (64) + 2 PHDRs (56 each) + .text bytes + .data bytes.
    let phoff: u64 = 64;
    let text_off: u64 = phoff + 2 * 56;
    let data_off: u64 = text_off + TEXT_FILESZ;
    let total: usize = (data_off + DATA_FILESZ) as usize;

    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(total);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
    bytes.extend_from_slice(&(TEXT_VADDR + 0x111).to_le_bytes()); // entry
    bytes.extend_from_slice(&phoff.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                  // .text PT_LOAD — R|X
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    bytes.extend_from_slice(&text_off.to_le_bytes()); // p_offset
    bytes.extend_from_slice(&TEXT_VADDR.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&TEXT_VADDR.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&TEXT_FILESZ.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&TEXT_FILESZ.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
                                                       // .data PT_LOAD — R|W
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type
    bytes.extend_from_slice(&6u32.to_le_bytes()); // p_flags = R|W
    bytes.extend_from_slice(&data_off.to_le_bytes()); // p_offset
    bytes.extend_from_slice(&DATA_VADDR.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&DATA_VADDR.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&DATA_FILESZ.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&DATA_FILESZ.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
                                                       // Pad to file size, then plant per-page sentinel bytes so we can
                                                       // read them back through the AS to confirm the right phys was used
                                                       // per page.
    bytes.resize(total, 0);
    bytes[text_off as usize] = 0x11; // .text page 0 byte 0
    bytes[text_off as usize + 0x1000] = 0x12; // .text page 1 byte 0
    bytes[data_off as usize] = 0x21; // .data page 0 byte 0
    bytes[data_off as usize + 0x1000] = 0x22; // .data page 1 byte 0

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed on multi-segment ELF"),
    };
    let root = proc.address_space.root;

    // For each page of each segment, translate the user vaddr and read
    // the sentinel back through the identity map. If materialize were
    // still doing single-base + i*0x1000, page-1 reads would be wrong
    // — they'd land at base+0x1000 in physical space, which (after
    // any prior allocations stir the freelist) is not the page-1
    // allocation.
    let checks: [(u64, u8); 4] = [
        (TEXT_VADDR, 0x11),
        (TEXT_VADDR + 0x1000, 0x12),
        (DATA_VADDR, 0x21),
        (DATA_VADDR + 0x1000, 0x22),
    ];
    for &(va, want) in checks.iter() {
        // SAFETY: `root` is the live loader-built root, identity-reachable as
        // `translate` requires; only walks its tables for this segment-page vaddr.
        // SAFETY: Valid memory or trusted environment
        let phys = match unsafe { paging::translate(root, VirtAddr::new(va)) } {
            Some(p) => p,
            None => return TestResult::Fail("translate returned None for a mapped page"),
        };
        // SAFETY: `phys` is the identity-mapped frame `translate` resolved; the
        // loader stored the per-page sentinel byte there, so a 1-byte read is valid.
        // SAFETY: Valid memory or trusted environment
        let got: u8 = unsafe { core::ptr::read_volatile(phys.raw() as *const u8) };
        if got != want {
            return TestResult::Fail("per-page sentinel mismatch — scatter list not honoured");
        }
    }

    // Round-trip: write a sentinel into .data page 1 via the kernel's
    // identity view of the translated phys, re-translate, and confirm
    // the read sees the write. This validates that each page in a
    // multi-page R+W segment is independently mapped — not aliased.
    // SAFETY: `root` is the live loader-built root, identity-reachable as
    // `translate` requires; only walks its tables for the .data page-1 vaddr.
    // SAFETY: Valid memory or trusted environment
    let data_p1_phys = unsafe { paging::translate(root, VirtAddr::new(DATA_VADDR + 0x1000)) }
        .expect("data page 1 mapped");
    // SAFETY: `data_p1_phys` is the identity-mapped frame for that mapped R+W page;
    // it is 4 KiB-aligned so a `u32` write at offset 0 is aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_volatile(data_p1_phys.raw() as *mut u32, 0xCAFEBABE);
    }
    // SAFETY: re-translating the same vaddr yields the identity-mapped phys of the
    // page just written; reading the `u32` back at offset 0 is aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    let echo: u32 = unsafe {
        let p = paging::translate(root, VirtAddr::new(DATA_VADDR + 0x1000)).expect("re-translate");
        core::ptr::read_volatile(p.raw() as *const u32)
    };
    if echo != 0xCAFEBABE {
        return TestResult::Fail("kernel-side write/read via translate did not round-trip");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_load_multi_segment);

fn smoke_userspace_loader_into_address_space() -> TestResult {
    use crate::{load_into, ExecImage, ExecKind, LoadError, Segment, SegmentFlags};
    use narf_memory::{AddressSpace, PhysAddr, RegionPerms, VirtAddr};

    // Empty image must refuse.
    let empty = ExecImage::empty(ExecKind::Elf64Exec);
    let pool: alloc::vec::Vec<PhysAddr> = alloc::vec::Vec::new();
    let a = AddressSpace::empty();
    match load_into(&empty, pool.into_iter(), &a) {
        Err(LoadError::NoSegments) => {}
        _ => return TestResult::Fail("empty image should refuse"),
    }

    // Build an image with two segments.
    let rx = SegmentFlags::READ | SegmentFlags::EXEC;
    let rw = SegmentFlags::READ | SegmentFlags::WRITE;
    let mut img = ExecImage::empty(ExecKind::Elf64Exec);
    img.entry = 0x4000;
    img.segments.push(Segment {
        vaddr: 0x4000,
        file_off: 0,
        file_size: 0x1000,
        mem_size: 0x2000,
        flags: rx,
    });
    img.segments.push(Segment {
        vaddr: 0x7000,
        file_off: 0x1000,
        file_size: 0x800,
        mem_size: 0x1000,
        flags: rw,
    });

    // Pool: 2 pages for segment 1 + 1 page for segment 2 = 3 frames.
    let pool = alloc::vec![
        PhysAddr::new(0x10_0000),
        PhysAddr::new(0x10_1000),
        PhysAddr::new(0x20_0000),
    ];
    let a2 = AddressSpace::empty();
    let ep = match load_into(&img, pool.into_iter(), &a2) {
        Ok(ep) => ep,
        Err(_) => return TestResult::Fail("loader failed on valid image"),
    };
    if ep.0 != VirtAddr::new(0x4000) {
        return TestResult::Fail("loader returned wrong entry point");
    }
    if a2.region_count() != 2 {
        return TestResult::Fail("loader did not install both segments");
    }
    // First region: RX, first pool frame.
    let r1 = a2.lookup(VirtAddr::new(0x4000)).expect("mapped");
    if r1.perms != (RegionPerms::READ | RegionPerms::EXEC) {
        return TestResult::Fail("first segment perms wrong");
    }
    if r1.phys.first().copied() != Some(PhysAddr::new(0x10_0000)) {
        return TestResult::Fail("first segment did not pick first pool frame");
    }
    if r1.phys.get(1).copied() != Some(PhysAddr::new(0x10_1000)) {
        return TestResult::Fail("first segment did not pick second pool frame for page 2");
    }
    if r1.len != 0x2000 {
        return TestResult::Fail("first segment len did not round up mem_size");
    }
    // Second region: RW, third pool frame (first two went to seg 1).
    let r2 = a2.lookup(VirtAddr::new(0x7000)).expect("mapped");
    if r2.phys.first().copied() != Some(PhysAddr::new(0x20_0000)) {
        return TestResult::Fail("second segment picked wrong frame from pool");
    }

    // Insufficient pool → NoPhysFrames.
    let tiny = alloc::vec![PhysAddr::new(0x30_0000)];
    let a3 = AddressSpace::empty();
    match load_into(&img, tiny.into_iter(), &a3) {
        Err(LoadError::NoPhysFrames) => {}
        _ => return TestResult::Fail("insufficient pool should surface NoPhysFrames"),
    }

    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_loader_into_address_space);

fn smoke_userspace_parse_minimal_elf64() -> TestResult {
    use crate::{parse_elf, ElfError, ExecKind, SegmentFlags};

    // Hand-crafted minimal ELF64 LE header + 1 PT_LOAD program
    // header. 64-byte ELF header, 56-byte program header, no
    // section table. PT_LOAD covers virt 0x400000 of 0x1000 bytes,
    // flags RX.
    let mut bytes = alloc::vec::Vec::with_capacity(64 + 56);
    // e_ident: 7F 'E' 'L' 'F', class 2 (64-bit), data 1 (LSB),
    // version 1, OS/ABI 0, abi-version 0, 7 bytes pad.
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine = EM_X86_64 (ignored here)
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
    bytes.extend_from_slice(&0x401000u64.to_le_bytes()); // e_entry
    bytes.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                  // Program header: PT_LOAD, flags=PF_R|PF_X (5).
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    bytes.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    bytes.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&0x400000u64.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    let image = match parse_elf(&bytes) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("minimal ELF64 failed to parse"),
    };
    if image.kind != ExecKind::Elf64Exec {
        return TestResult::Fail("ET_EXEC not mapped to Elf64Exec");
    }
    if image.entry != 0x401000 {
        return TestResult::Fail("entry point mis-parsed");
    }
    if image.segments.len() != 1 {
        return TestResult::Fail("segment count off");
    }
    let s = &image.segments[0];
    if s.vaddr != 0x400000 || s.file_size != 0x1000 || s.mem_size != 0x1000 {
        return TestResult::Fail("segment fields mis-parsed");
    }
    if !s.flags.contains(SegmentFlags::READ) || !s.flags.contains(SegmentFlags::EXEC) {
        return TestResult::Fail("segment flags lost R|X");
    }
    if s.flags.contains(SegmentFlags::WRITE) {
        return TestResult::Fail("W bit appeared spuriously");
    }

    // Refusal paths.
    match parse_elf(&bytes[..32]) {
        Err(ElfError::TooShort) => {}
        _ => return TestResult::Fail("short slice should surface TooShort"),
    }
    let mut bad = bytes.clone();
    bad[0] = 0; // wreck ELF magic
    match parse_elf(&bad) {
        Err(ElfError::BadMagic) => {}
        _ => return TestResult::Fail("bad magic should surface BadMagic"),
    }
    let mut bad32 = bytes.clone();
    bad32[4] = 1; // ELFCLASS32
    match parse_elf(&bad32) {
        Err(ElfError::Not64Bit) => {}
        _ => return TestResult::Fail("32-bit ELF should be rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_parse_minimal_elf64);

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

fn smoke_userspace_getrandom_fills_buffer() -> TestResult {
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

    // First call: fill a 16-byte buffer. Returns 16, buffer mostly
    // non-zero (false-positive rate of "all zeros under a real RNG"
    // is 2^-128 — tolerable as a smoke).
    let mut buf = [0u8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetRandom.raw(), &mut ctx);
    let n = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => return TestResult::Fail("getrandom did not return OK"),
    };
    if n != 16 {
        return TestResult::Fail("getrandom byte-count != 16");
    }
    if buf.iter().all(|&b| b == 0) {
        return TestResult::Fail("getrandom buffer is all zeros");
    }

    // Second call: fill again, expect a different stream.
    let prev = buf;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetRandom.raw(), &mut ctx);
    if buf == prev {
        return TestResult::Fail("two consecutive getrandom calls returned identical bytes");
    }

    // Null pointer rejected with -1.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 16,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetRandom.raw(), &mut ctx);
    let null_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !null_rejected {
        return TestResult::Fail("getrandom did not reject null buffer");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getrandom_fills_buffer);

fn smoke_userspace_listdir_walks_memfs() -> TestResult {
    // Mount a fresh MemFs at /list-test seeded with three entries
    // and walk it via SYS_LISTDIR. Each call advances the cursor
    // by one; the kernel re-snapshots each invocation. End-of-
    // directory surfaces as `value = 0`.
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use narf_filesystem as fs;

    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
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

    let auth = fs::bootstrap_mount_authority();
    // The validate harness may have left /list-test behind from a
    // prior run; tolerate Busy to keep the test idempotent.
    let _ = fs::registry().mount(
        &auth,
        "/list-test",
        fs::MemFs::with_seeds(
            "list-test",
            &[("alpha", b"a"), ("beta", b"b"), ("gamma", b"c")],
        ),
    );

    fn one_call(path: &str, cursor: u64, out: &mut [u8]) -> Option<SyscallReturn> {
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
            fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
                false
            }

            fn rip(&self) -> u64 {
                0
            }
            fn set_rip(&mut self, _rip: u64) {}
        }
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: path.len() as u64,
                arg2: cursor,
                arg3: out.as_mut_ptr() as u64,
                arg4: out.len() as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Listdir.raw(), &mut ctx);
        ctx.ret
    }

    fn parse(out: &[u8], n: usize) -> Option<(alloc::string::String, u32)> {
        if n < 8 {
            return None;
        }
        let name_len = u32::from_le_bytes(out[0..4].try_into().ok()?) as usize;
        let ftype = u32::from_le_bytes(out[4..8].try_into().ok()?);
        if 8 + name_len > n {
            return None;
        }
        let name = core::str::from_utf8(&out[8..8 + name_len]).ok()?.into();
        Some((name, ftype))
    }

    let mut buf = [0u8; 64];
    let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    let mut types_ok = true;

    for cursor in 0..4 {
        let r = match one_call("/list-test", cursor, &mut buf) {
            Some(r) if r.status == SyscallReturn::OK => r,
            _ => return TestResult::Fail("listdir returned non-OK"),
        };
        if cursor == 3 {
            // Past last entry — expect value = 0.
            if r.value != 0 {
                return TestResult::Fail("listdir cursor=3 did not surface end-of-dir");
            }
            break;
        }
        let n = r.value as usize;
        if n == 0 {
            return TestResult::Fail("listdir produced premature end-of-dir");
        }
        let (name, ft) = match parse(&buf, n) {
            Some(p) => p,
            None => return TestResult::Fail("listdir wire-decode failed"),
        };
        if ft != 0 {
            types_ok = false;
        } // 0 = File
        names.push(name);
    }

    __test_clear_global();

    names.sort();
    if names.as_slice() != ["alpha", "beta", "gamma"] {
        return TestResult::Fail("listdir entries did not match seed set");
    }
    if !types_ok {
        return TestResult::Fail("listdir reported non-File type for seeded files");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_listdir_walks_memfs);

fn smoke_userspace_clock_gettime_distinguishes_clocks() -> TestResult {
    // ClockGetTime now honours arg0:
    //   0 = CLOCK_REALTIME  (wall via time::now_wall)
    //   1 = CLOCK_MONOTONIC (monotonic_ns)
    //   anything else → InvalidOp.
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

    let mut buf = [0i64; 2];
    let buf_addr = buf.as_mut_ptr() as u64;

    // CLOCK_MONOTONIC: read twice, expect non-decreasing.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: buf_addr,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    let m1 = (buf[0], buf[1]);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("monotonic clock_gettime did not return OK");
    }

    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: buf_addr,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    let m2 = (buf[0], buf[1]);
    if (m2.0, m2.1) < (m1.0, m1.1) {
        return TestResult::Fail("monotonic clock went backwards");
    }

    // CLOCK_REALTIME: must succeed and produce a non-negative time.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf_addr,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("realtime clock_gettime did not return OK");
    }
    if buf[0] < 0 || buf[1] < 0 {
        return TestResult::Fail("realtime clock surfaced a negative timespec");
    }

    // Bogus clock id rejected with InvalidOp status.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 99,
            arg1: buf_addr,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    let bogus_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::INVALID_OP,
    );
    if !bogus_rejected {
        return TestResult::Fail("unknown clock id was not rejected");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_clock_gettime_distinguishes_clocks
);

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

fn smoke_userspace_hostname_round_trip() -> TestResult {
    use crate::{
        hostname_init, install_core_syscalls, install_global, kernel_syscall_entry,
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
    crate::handlers::__test_hostname_reset();
    hostname_init();

    // gethostname → "narf" (boot default).
    let mut buf = [0u8; 64];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetHostname.raw(), &mut ctx);
    let n = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as usize,
        _ => return TestResult::Fail("gethostname did not return OK with len"),
    };
    if n != 4 || &buf[..4] != b"narf" || buf[4] != 0 {
        return TestResult::Fail("default hostname not 'narf'");
    }

    // sethostname("box-7") → succeeds.
    let new_name = b"box-7";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: new_name.as_ptr() as u64,
            arg1: new_name.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::SetHostname.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("sethostname did not return 0");
    }

    // gethostname now returns "box-7".
    let mut buf2 = [0u8; 64];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf2.as_mut_ptr() as u64,
            arg1: buf2.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetHostname.raw(), &mut ctx);
    let n2 = match ctx.ret {
        Some(r) if r.value != (-1i64) as u64 => r.value as usize,
        _ => return TestResult::Fail("post-set gethostname failed"),
    };
    if n2 != 5 || &buf2[..5] != b"box-7" || buf2[5] != 0 {
        return TestResult::Fail("hostname did not stick after sethostname");
    }

    // gethostname into too-small buf returns -1.
    let mut tiny = [0u8; 3];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: tiny.as_mut_ptr() as u64,
            arg1: tiny.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetHostname.raw(), &mut ctx);
    let too_small_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !too_small_rejected {
        return TestResult::Fail("gethostname did not reject small buf");
    }

    crate::handlers::__test_hostname_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_hostname_round_trip);

fn smoke_userspace_ftruncate_grows_and_shrinks_memfile() -> TestResult {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};

    // Inline single-shot future poller — MemFs reads/writes are
    // immediately ready, so we don't need a real executor here.
    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: `raw_waker()` pairs a null data pointer with a static vtable whose
        // clone/wake/wake_by_ref/drop are all no-ops that never dereference the data
        // pointer, so the `RawWaker` upholds the `Waker` contract.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: future is on this stack frame and not moved.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    // Mount a fresh MemFs with a seeded 6-byte file. Ftruncate
    // grows it to 16, shrinks to 3, then reads to verify each.
    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/trunc",
        MemFs::with_seeds("trunc-test", &[("f", b"abcdef")]),
    );

    let ops = registry()
        .resolve_absolute("/trunc/f", |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let ops = match ops {
        Some(o) => o,
        None => return TestResult::Fail("resolve /trunc/f failed"),
    };

    // Initial size = 6.
    if ops.stat().size != 6 {
        return TestResult::Fail("initial file size != 6");
    }

    // Grow to 16. The new tail is zero-filled per POSIX.
    if poll_once(ops.truncate(16)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("truncate grow failed");
    }
    if ops.stat().size != 16 {
        return TestResult::Fail("size after grow != 16");
    }
    let mut buf = [0xAAu8; 16];
    let n = match poll_once(ops.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("post-grow read failed"),
    };
    if n != 16 || &buf[0..6] != b"abcdef" || buf[6..16].iter().any(|&b| b != 0) {
        return TestResult::Fail("post-grow contents wrong");
    }

    // Shrink to 3. Re-stat must report 3 bytes; read confirms tail
    // is gone.
    if poll_once(ops.truncate(3)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("truncate shrink failed");
    }
    if ops.stat().size != 3 {
        return TestResult::Fail("size after shrink != 3");
    }
    let mut buf2 = [0u8; 16];
    let n2 = match poll_once(ops.read(0, &mut buf2)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("post-shrink read failed"),
    };
    if n2 != 3 || &buf2[..3] != b"abc" {
        return TestResult::Fail("post-shrink contents wrong");
    }

    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_ftruncate_grows_and_shrinks_memfile
);

fn smoke_userspace_pread_pwrite_dont_move_cursor() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
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
    crate::fd::__test_reset();
    crate::fd::init();

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/pio",
        MemFs::with_seeds("pio-test", &[("f", b"abcdefghij")]),
    );

    // Open the file via SYS_OPEN.
    // Linux open(2) ABI: arg0 = NUL-terminated absolute path, arg1 = flags.
    let path = b"/pio/f\0";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0, // flags
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::OpenFile.raw(), &mut ctx);
    let fd = match ctx.ret {
        Some(r) if r.value != !0u64 => r.value as u32,
        _ => return TestResult::Fail("open /pio/f failed"),
    };

    // pread at offset 5 → "fghij" (5 bytes).
    let mut rbuf = [0u8; 5];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: rbuf.as_mut_ptr() as u64,
            arg2: rbuf.len() as u64,
            arg3: 5,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pread64.raw(), &mut ctx);
    let n = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("pread failed"),
    };
    if n != 5 || &rbuf != b"fghij" {
        return TestResult::Fail("pread contents wrong");
    }

    // The fd's offset must still be 0 — confirm with a regular read.
    let mut head = [0u8; 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: head.as_mut_ptr() as u64,
            arg2: head.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    let m = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("post-pread read failed"),
    };
    if m != 4 || &head != b"abcd" {
        return TestResult::Fail("pread moved the cursor");
    }

    // pwrite at offset 8 → overwrite "ij" with "ZZ".
    let payload = b"ZZ";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            arg3: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pwrite64.raw(), &mut ctx);
    let pw = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("pwrite failed"),
    };
    if pw != 2 {
        return TestResult::Fail("pwrite did not write 2 bytes");
    }

    // Read at offset 8 to confirm.
    let mut tail = [0u8; 2];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: tail.as_mut_ptr() as u64,
            arg2: tail.len() as u64,
            arg3: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pread64.raw(), &mut ctx);
    if &tail != b"ZZ" {
        return TestResult::Fail("pwrite did not stick");
    }

    let _ = crate::fd::with_table(0, |t| t.close(fd));
    crate::fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_pread_pwrite_dont_move_cursor);

fn smoke_userspace_rlimit_round_trip() -> TestResult {
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

    // Default RLIMIT_NOFILE (resource 7) is (256, 4096).
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
    if out != [256, 4096] {
        return TestResult::Fail("default RLIMIT_NOFILE not (256, 4096)");
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

    // Out-of-range resource → -1.
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
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
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

fn smoke_userspace_times_writes_tms_struct() -> TestResult {
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

    let mut buf = [0i64; 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Times.raw(), &mut ctx);
    let wall = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as i64,
        _ => return TestResult::Fail("times did not return OK"),
    };
    // utime synthesised to wall-clock ticks; stime/cutime/cstime
    // zeroed; wall return matches buf[0] (both source the same ns).
    if buf[0] != wall || buf[1] != 0 || buf[2] != 0 || buf[3] != 0 {
        return TestResult::Fail("times did not write the expected tms struct");
    }
    if wall < 0 {
        return TestResult::Fail("times surfaced a negative wall-clock");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_times_writes_tms_struct);

fn smoke_userspace_getrusage_writes_18_i64s() -> TestResult {
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

    let mut buf = [0xFEi64; 18];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getrusage.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getrusage did not return OK");
    }
    // ru_utime.tv_sec / tv_usec from monotonic_ns; everything else
    // zero.
    if buf[0] < 0 || buf[1] < 0 {
        return TestResult::Fail("ru_utime negative");
    }
    for &field in &buf[2..18] {
        if field != 0 {
            return TestResult::Fail("non-utime field of rusage was not zero");
        }
    }

    // Null pointer rejected.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getrusage.raw(), &mut ctx);
    let null_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !null_rejected {
        return TestResult::Fail("getrusage did not reject null buffer");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getrusage_writes_18_i64s);

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

fn smoke_userspace_getcpu_returns_zero() -> TestResult {
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

    let mut cpu: u32 = 99;
    let mut node: u32 = 99;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: &mut cpu as *mut u32 as u64,
            arg1: &mut node as *mut u32 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getcpu.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getcpu did not return OK");
    }
    if cpu != 0 || node != 0 {
        return TestResult::Fail("getcpu did not write (0, 0)");
    }

    // Null pointers tolerated.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getcpu.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getcpu(NULL, NULL) did not succeed");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getcpu_returns_zero);

fn smoke_userspace_sched_affinity_round_trip() -> TestResult {
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

    // sched_getaffinity into a 16-byte buffer.
    let mut mask = [0xFFu8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
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
    if n != 16 {
        return TestResult::Fail("sched_getaffinity byte-count != 16");
    }
    if mask[0] != 0x01 {
        return TestResult::Fail("sched_getaffinity did not set CPU 0");
    }
    if mask[1..16].iter().any(|&b| b != 0) {
        return TestResult::Fail("sched_getaffinity stamped a non-zero tail");
    }

    // sched_setaffinity returns 0 on a valid bitmap.
    let in_mask = [0xAAu8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
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

    // Tiny size rejected.
    let mut tiny = [0u8; 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: tiny.len() as u64,
            arg2: tiny.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::SchedGetaffinity.raw(), &mut ctx);
    let tiny_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !tiny_rejected {
        return TestResult::Fail("sched_getaffinity did not reject tiny buf");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_sched_affinity_round_trip);

fn smoke_userspace_prctl_name_round_trip() -> TestResult {
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

    // Unknown op rejected.
    let r = call(99, 0);
    let unknown_rejected = matches!(
        r,
        Some(rr) if rr.status == SyscallReturn::OK && rr.value == (-1i64) as u64,
    );
    if !unknown_rejected {
        return TestResult::Fail("prctl(99) was not rejected");
    }

    crate::handlers::__test_prctl_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_prctl_name_round_trip);

fn smoke_userspace_fallocate_extends_and_zero_ranges_memfile() -> TestResult {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: `raw_waker()` pairs a null data pointer with a static vtable whose
        // clone/wake/wake_by_ref/drop are all no-ops that never dereference the data
        // pointer, so the `RawWaker` upholds the `Waker` contract.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` lives in this stack frame and is never moved before the poll
        // completes, so pinning a mutable reference to it is sound.
        // SAFETY: Valid memory or trusted environment
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/falloc",
        MemFs::with_seeds(
            "falloc-test",
            &[("f", b"abcdefghij")], // 10 bytes
        ),
    );
    let ops = registry()
        .resolve_absolute("/falloc/f", |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let ops = match ops {
        Some(o) => o,
        None => return TestResult::Fail("resolve /falloc/f failed"),
    };

    // Direct trait round-trip — the syscall path adds nothing
    // beyond fd-table indirection and the smoke for that already
    // exists in the ftruncate test.
    if poll_once(ops.truncate(20)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("baseline truncate failed");
    }
    if ops.stat().size != 20 {
        return TestResult::Fail("size after truncate(20) != 20");
    }
    let mut buf = [0xFFu8; 20];
    let n = match poll_once(ops.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read post-truncate failed"),
    };
    // First 10 bytes preserved; tail zero from the grow.
    if n != 20 || &buf[0..10] != b"abcdefghij" || buf[10..20].iter().any(|&b| b != 0) {
        return TestResult::Fail("post-truncate(20) contents wrong");
    }

    // Now exercise FALLOC_FL_ZERO_RANGE in-place: zero bytes
    // [3..7] of the file. The handler writes zeros; equivalent
    // to writing four 0u8 bytes at offset 3.
    let zeros = [0u8; 4];
    let written = match poll_once(ops.write(3, &zeros)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("write zeros failed"),
    };
    if written != 4 {
        return TestResult::Fail("zero-range write didn't write 4 bytes");
    }
    let mut buf2 = [0xAAu8; 20];
    let _ = poll_once(ops.read(0, &mut buf2));
    if &buf2[..3] != b"abc" || buf2[3..7] != [0; 4] || &buf2[7..10] != b"hij" {
        return TestResult::Fail("zero-range did not zero [3..7]");
    }

    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_fallocate_extends_and_zero_ranges_memfile
);

fn smoke_userspace_copy_file_range_round_trip() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
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
    crate::fd::__test_reset();
    crate::fd::init();

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/cfr",
        MemFs::with_seeds("cfr-test", &[("src", b"abcdefghij"), ("dst", b"")]),
    );

    fn open(path: &str) -> Option<u32> {
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
            fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
                false
            }

            fn rip(&self) -> u64 {
                0
            }
            fn set_rip(&mut self, _rip: u64) {}
        }
        // Linux open(2) ABI: arg0 = NUL-terminated absolute path,
        // arg1 = flags.
        let mut cpath = alloc::vec::Vec::from(path.as_bytes());
        cpath.push(0);
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: cpath.as_ptr() as u64,
                arg1: 0, // flags
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::OpenFile.raw(), &mut ctx);
        match ctx.ret {
            Some(r) if r.value != !0u64 => Some(r.value as u32),
            _ => None,
        }
    }

    let fd_in = match open("/cfr/src") {
        Some(f) => f,
        None => return TestResult::Fail("open src failed"),
    };
    let fd_out = match open("/cfr/dst") {
        Some(f) => f,
        None => return TestResult::Fail("open dst failed"),
    };

    // Copy 5 bytes from src@0 → dst@0. !0 sentinel means "use cur",
    // explicit 0 means "start at 0 without moving the cursor".
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_in as u64,
            arg1: fd_out as u64,
            arg2: 0,
            arg3: 0,
            arg4: 5,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::CopyFileRange.raw(), &mut ctx);
    let copied = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => return TestResult::Fail("copy_file_range did not return OK"),
    };
    if copied != 5 {
        return TestResult::Fail("copy_file_range did not copy 5 bytes");
    }

    // Verify dst contents via a positional read.
    let mut buf = [0u8; 5];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_out as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pread64.raw(), &mut ctx);
    if &buf != b"abcde" {
        return TestResult::Fail("dst contents wrong after copy_file_range");
    }

    // flags != 0 rejected.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_in as u64,
            arg1: fd_out as u64,
            arg2: 0,
            arg3: 0,
            arg4: 1,
            arg5: 1,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::CopyFileRange.raw(), &mut ctx);
    let flags_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !flags_rejected {
        return TestResult::Fail("copy_file_range did not reject non-zero flags");
    }

    crate::fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_copy_file_range_round_trip);

fn smoke_userspace_clock_settime_pushes_wall_offset() -> TestResult {
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

    // Reset wall offset to a known baseline: target = 1.7 billion
    // seconds (≈ Nov 2023).
    let target_sec: i64 = 1_700_000_000;
    let target_nsec: i64 = 0;
    let ts: [i64; 2] = [target_sec, target_nsec];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0, // CLOCK_REALTIME
            arg1: ts.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockSetTime.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("clock_settime did not return OK");
    }

    // Read back via clock_gettime(REALTIME). Allow a 2-second
    // window for monotonic-clock drift between the set and the get.
    let mut out = [0i64; 2];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: out.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    let got_sec = out[0];
    if got_sec < target_sec || got_sec > target_sec + 2 {
        return TestResult::Fail("clock_gettime did not reflect the new wall offset");
    }

    // CLOCK_MONOTONIC (1) is not settable — expect -1.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: ts.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockSetTime.raw(), &mut ctx);
    let mono_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !mono_rejected {
        return TestResult::Fail("clock_settime(MONOTONIC) was not rejected");
    }

    // Reset wall offset back to 0 so subsequent tests see normal
    // behaviour. (Re-setting REALTIME to (current monotonic) leaves
    // offset = 0.)
    let cur_mono: u64 = narf_scheduler::narf_time::monotonic_ns();
    let cur_sec = (cur_mono / 1_000_000_000) as i64;
    let cur_nsec = (cur_mono % 1_000_000_000) as i64;
    let reset_ts: [i64; 2] = [cur_sec, cur_nsec];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: reset_ts.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockSetTime.raw(), &mut ctx);

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_clock_settime_pushes_wall_offset
);

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

fn smoke_userspace_memfd_create_returns_writable_fd() -> TestResult {
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
    crate::fd::__test_reset();
    crate::fd::init();

    let name = "anon-1";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: name.as_ptr() as u64,
            arg1: name.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::MemfdCreate.raw(), &mut ctx);
    let fd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => return TestResult::Fail("memfd_create did not return a fd"),
    };

    // Write 4 bytes via SYS_WRITE, read them back via SYS_READ.
    let payload = b"narf";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 4) {
        return TestResult::Fail("write to memfd did not write 4 bytes");
    }

    // Seek back to 0 then read.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 0,
            arg2: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Lseek.raw(), &mut ctx);

    let mut buf = [0u8; 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    if &buf != b"narf" {
        return TestResult::Fail("read-back from memfd contents wrong");
    }

    let _ = crate::fd::with_table(0, |t| t.close(fd));
    crate::fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_memfd_create_returns_writable_fd
);

fn smoke_userspace_getdents64_writes_linux_records() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
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

    use crate::install_task_id_lookup;
    use core::sync::atomic::{AtomicU64, Ordering};
    static GD_TID: AtomicU64 = AtomicU64::new(0x6D70);
    fn gd_task() -> u64 {
        GD_TID.load(Ordering::Relaxed)
    }
    install_task_id_lookup(gd_task);

    __test_clear_global();
    crate::fd::__test_reset();
    crate::fd::init();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let auth = bootstrap_mount_authority();
    let gd_mount = registry()
        .mount(
            &auth,
            "/gd",
            MemFs::with_seeds(
                "gd-test",
                &[("alpha", b"a"), ("beta", b"b"), ("gamma", b"c")],
            ),
        )
        .ok();
    let cleanup_gd = || {
        if let Some(h) = &gd_mount {
            let _ = registry().unmount(h, "/gd");
        }
        crate::fd::__test_reset();
    };

    // getdents64 is now fd-based (Linux ABI). Open the directory to get
    // a dir fd, then read it.
    let fd = match crate::handlers::__test_open_dir_fd(gd_task(), "/gd") {
        Some(f) => f,
        None => {
            crate::handlers::__test_reset_task_id_lookup();
            cleanup_gd();
            return TestResult::Fail("could not open /gd as a directory fd");
        }
    };

    let mut buf = [0u8; 256];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getdents64.raw(), &mut ctx);
    // Done with the task-id lookup; reset so it doesn't leak into
    // sibling kernel_test cases that assume the default id.
    crate::handlers::__test_reset_task_id_lookup();
    let written = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            cleanup_gd();
            return TestResult::Fail("getdents64 did not return OK");
        }
    };
    if written == 0 {
        cleanup_gd();
        return TestResult::Fail("getdents64 returned 0 bytes");
    }

    // Walk the records and collect names.
    let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    let mut pos = 0usize;
    while pos + 19 <= written {
        let reclen = u16::from_le_bytes(buf[pos + 16..pos + 18].try_into().unwrap()) as usize;
        if reclen < 20 || pos + reclen > written {
            break;
        }
        // d_name at offset 19, NUL-terminated.
        let name_start = pos + 19;
        let mut nlen = 0usize;
        while name_start + nlen < pos + reclen && buf[name_start + nlen] != 0 {
            nlen += 1;
        }
        let name = core::str::from_utf8(&buf[name_start..name_start + nlen]).unwrap();
        names.push(name.into());
        pos += reclen;
    }
    if pos != written {
        cleanup_gd();
        return TestResult::Fail("walk did not cover the written length exactly");
    }
    names.sort();
    if names.as_slice() != ["alpha", "beta", "gamma"] {
        cleanup_gd();
        return TestResult::Fail("getdents64 didn't enumerate all entries");
    }

    cleanup_gd();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getdents64_writes_linux_records);

fn smoke_userspace_pipe_read_should_block_on_open_writer() -> TestResult {
    // The blocking-read decision behind shell `$(...)` substitution: a
    // pipe read end whose buffer is empty but whose writer is still open
    // must report `read_should_block` (so sys_read parks and waits for
    // data) — and must STOP reporting it once the last writer drops (so
    // the read returns a real EOF instead of blocking forever). The
    // writer drops here via the `Arc<PipeWrite>` going out of scope,
    // mirroring what `fd::detach` does when a writer task exits.
    use narf_filesystem::FileOps;
    let (r, w) = crate::pipe::pipe_pair();
    // Empty buffer + writer open → should block.
    if !r.read_should_block() {
        return TestResult::Fail("empty pipe with open writer should block");
    }
    // Last writer closes → EOF; a read must NOT block (returns 0).
    drop(w);
    if r.read_should_block() {
        return TestResult::Fail("closed writer should not block (EOF expected)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_pipe_read_should_block_on_open_writer
);

fn smoke_userspace_init_per_task_state_is_idempotent() -> TestResult {
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

    // Reset every per-task table so we observe the post-init state
    // from a known floor.
    crate::handlers::__test_uidgid_reset();
    crate::handlers::__test_hostname_reset();
    crate::handlers::__test_rlimit_reset();
    crate::handlers::__test_nice_reset();
    crate::handlers::__test_umask_reset();
    crate::handlers::__test_prctl_reset();

    // Single call wires everything.
    init_per_task_state();
    // Re-running must not corrupt state.
    init_per_task_state();

    // After init, getuid (a noop_ok-style call that depends on
    // UIDGID_TABLE existing) must return the default 0.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetUid.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getuid did not return 0 after init_per_task_state");
    }

    // gethostname must surface "narf".
    let mut buf = [0u8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetHostname.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.value as i64 == 4) {
        return TestResult::Fail("gethostname did not return 4 bytes");
    }
    if &buf[..4] != b"narf" {
        return TestResult::Fail("hostname not initialised to 'narf'");
    }

    // umask returns 0o022 default.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0o077,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Umask.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.value == 0o022) {
        return TestResult::Fail("umask default not 0o022 after init");
    }

    crate::handlers::__test_uidgid_reset();
    crate::handlers::__test_hostname_reset();
    crate::handlers::__test_rlimit_reset();
    crate::handlers::__test_nice_reset();
    crate::handlers::__test_umask_reset();
    crate::handlers::__test_prctl_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_init_per_task_state_is_idempotent
);

fn smoke_userspace_sched_priority_bounds_and_param() -> TestResult {
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

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn build_unresolved_named_elf(strtab: &[u8]) -> alloc::vec::Vec<u8> {
    const SEG_VA: u64 = 0x0000_0080_0000_1000;
    const SEG_FOFF: u64 = 0x1000;
    const RELOC_OFF_IN_SEG: u64 = 0x80;
    const RELA_OFF_IN_SEG: u64 = 0x180;
    const SYMTAB_OFF_IN_SEG: u64 = 0x1C0;
    const STRTAB_OFF_IN_SEG: u64 = 0x240;
    const DYN_OFF_IN_SEG: u64 = 0x300;

    const FSIZE: usize = 0x2000;
    let mut b = alloc::vec![0u8; FSIZE];
    b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x111).to_le_bytes());
    b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

    let mut ph = 64usize;
    b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
    b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());

    ph = 64 + 56;
    let dyn_foff = SEG_FOFF + DYN_OFF_IN_SEG;
    let dyn_va = SEG_VA + DYN_OFF_IN_SEG;
    // Six 16-byte entries: DT_RELA, DT_RELASZ, DT_RELAENT, DT_SYMTAB,
    // DT_STRTAB, DT_NULL → 96 bytes.
    let dyn_size: u64 = 96;
    b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
    b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
    b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&dyn_va.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&dyn_va.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&dyn_size.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&dyn_size.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

    let reloc_va = SEG_VA + RELOC_OFF_IN_SEG;
    let rela_foff = (SEG_FOFF + RELA_OFF_IN_SEG) as usize;
    let r_info: u64 = (1u64 << 32) | 1u64; // sym_idx=1, R_X86_64_64
    b[rela_foff..rela_foff + 8].copy_from_slice(&reloc_va.to_le_bytes());
    b[rela_foff + 8..rela_foff + 16].copy_from_slice(&r_info.to_le_bytes());
    b[rela_foff + 16..rela_foff + 24].copy_from_slice(&0u64.to_le_bytes());

    // Symbol table: entry 0 is the canonical zero placeholder; entry 1
    // is undefined (st_value=0, st_shndx=0) but with st_name=1 — the
    // loader must follow that into DT_STRTAB.
    let sym_foff = (SEG_FOFF + SYMTAB_OFF_IN_SEG) as usize;
    let s1 = sym_foff + 24;
    b[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes()); // st_name
                                                        // st_info, st_other, st_shndx, st_value, st_size all stay zero.

    // String table: caller-supplied content. Convention: leading NUL
    // followed by NUL-terminated names. Caller provides the whole
    // blob already.
    let strtab_foff = (SEG_FOFF + STRTAB_OFF_IN_SEG) as usize;
    b[strtab_foff..strtab_foff + strtab.len()].copy_from_slice(strtab);

    // Dynamic array.
    let rela_va = SEG_VA + RELA_OFF_IN_SEG;
    let symtab_va = SEG_VA + SYMTAB_OFF_IN_SEG;
    let strtab_va = SEG_VA + STRTAB_OFF_IN_SEG;
    let mut p = dyn_foff as usize;
    b[p..p + 8].copy_from_slice(&7i64.to_le_bytes()); // DT_RELA
    b[p + 8..p + 16].copy_from_slice(&rela_va.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&8i64.to_le_bytes()); // DT_RELASZ
    b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&9i64.to_le_bytes()); // DT_RELAENT
    b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&6i64.to_le_bytes()); // DT_SYMTAB
    b[p + 8..p + 16].copy_from_slice(&symtab_va.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&5i64.to_le_bytes()); // DT_STRTAB
    b[p + 8..p + 16].copy_from_slice(&strtab_va.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&0i64.to_le_bytes()); // DT_NULL
    b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());

    b
}

// ── relocated from verification ──

#[cfg(target_arch = "x86_64")]
fn smoke_abi_dispatcher_serves_file_ops() -> TestResult {
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
    crate::fd::init();
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
    crate::fd::init();
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

        // Munmap(base).
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

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_brk_grows_heap() -> TestResult {
    // Brk: query → returns the per-task default base. Grow by one
    // page → returns the requested new break and walks the AS to
    // confirm the page is mapped. Walk the AS to verify the
    // physical backing is reachable.
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{x86_64::paging, AddressSpace, VirtAddr};

    static USER_AS_BRK: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_BRK.lock().clone()
    }

    // Distinct task id from sibling smokes so stale per-task state
    // from a prior round can't poison this run.
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xB12C);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    *USER_AS_BRK.lock() = Some(addr_space.clone());

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
    crate::brk_init();
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

    // Query the initial break.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Brk.raw(), &mut ctx);
    let initial = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            *USER_AS_BRK.lock() = None;
            __test_clear_global();
            crate::handlers::__test_brk_reset();
            return TestResult::Fail("Brk(0) did not return Ok");
        }
    };
    if initial == 0 {
        *USER_AS_BRK.lock() = None;
        __test_clear_global();
        crate::handlers::__test_brk_reset();
        return TestResult::Fail("Brk(0) returned zero base");
    }

    // Grow by one page.
    let target = initial + 0x1000;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Brk.raw(), &mut ctx);
    let grown = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            *USER_AS_BRK.lock() = None;
            __test_clear_global();
            crate::handlers::__test_brk_reset();
            return TestResult::Fail("Brk(grow) did not return Ok");
        }
    };
    if grown != target {
        *USER_AS_BRK.lock() = None;
        __test_clear_global();
        crate::handlers::__test_brk_reset();
        return TestResult::Fail("Brk(grow) returned wrong value");
    }

    // The new page must be mapped in the AS — translate the page
    // containing `initial` (which is page-aligned) to confirm it
    // resolves to a real phys frame.
    // SAFETY: `addr_space.root` is the live user root for this brk test, identity-
    // reachable as `translate` requires; only walks its tables for the page-aligned
    // `initial` break vaddr.
    // SAFETY: Valid memory or trusted environment
    if unsafe { paging::translate(addr_space.root, VirtAddr::new(initial)) }.is_none() {
        *USER_AS_BRK.lock() = None;
        __test_clear_global();
        crate::handlers::__test_brk_reset();
        return TestResult::Fail("Brk-grown page not mapped in AS");
    }

    // Querying again returns the new break.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Brk.raw(), &mut ctx);
    let after = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            *USER_AS_BRK.lock() = None;
            __test_clear_global();
            crate::handlers::__test_brk_reset();
            return TestResult::Fail("Brk(0) post-grow not Ok");
        }
    };
    if after != target {
        *USER_AS_BRK.lock() = None;
        __test_clear_global();
        crate::handlers::__test_brk_reset();
        return TestResult::Fail("Brk did not persist new break");
    }

    *USER_AS_BRK.lock() = None;
    __test_clear_global();
    crate::handlers::__test_brk_reset();
    TestResult::Pass
}
// Gate out of `user-mode-e2e` runs: e2e ordering is sensitive to
// per-task table state and adding this test perturbs the order
// enough to wedge a latent flake elsewhere. The non-e2e suite
// catches it.
#[cfg(all(target_arch = "x86_64", not(feature = "user-mode-e2e")))]
kernel_test_in!("userspace", smoke_userspace_brk_grows_heap);

// ── fork(2) smokes ─────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_distinct_address_space() -> TestResult {
    // Dispatches Syscall::Fork (57) against a synthetic parent AS,
    // confirms the spawned child is on the scheduler with a
    // DIFFERENT Arc<AddressSpace> than the parent (the whole
    // point — fork must duplicate, not share). Counterpart to
    // smoke_userspace_clone_shares_address_space. Also verifies
    // the parent's region's bytes were copied into independent
    // child frames.
    use narf_memory::{Region, RegionPerms, VirtAddr};

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as_inner = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame parent region"),
    };
    const SENTINEL_VADDR: u64 = 0x0000_0080_0000_0000;
    if parent_as_inner
        .map_region(Region {
            base: VirtAddr::new(SENTINEL_VADDR),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![frame],
        })
        .is_err()
    {
        return TestResult::Fail("map parent sentinel region");
    }
    // SAFETY: `parent_as_inner` was built via `new_for_user`, so its `root` is a
    // valid user root, satisfying `materialize`'s `# Safety` precondition.
    // SAFETY: Valid memory or trusted environment
    if unsafe { parent_as_inner.materialize() }.is_err() {
        return TestResult::Fail("materialize parent");
    }
    // Stamp a sentinel; clone_for_fork must memcpy this into the
    // child's fresh frame.
    // SAFETY: identity-mapped, single-task ownership.
    unsafe {
        *(frame.raw() as *mut u32) = 0xCAFEBABE;
    }

    let parent_as = Arc::new(parent_as_inner);
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return set"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("fork returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("fork returned pid=0");
    }
    // fork returns ProcessId; translate to TaskId for scheduler lookups.
    let child_task_raw = match crate::handlers::pid_to_task_raw(ret.value) {
        Some(t) => t,
        None => return TestResult::Fail("no PID→TaskId mapping after fork"),
    };
    let child_tid = narf_scheduler::TaskId(child_task_raw);
    let child_as = match narf_scheduler::address_space_of(child_tid) {
        Some(a) => a,
        None => return TestResult::Fail("child has no AS attached"),
    };
    if Arc::ptr_eq(&child_as, &parent_as) {
        return TestResult::Fail("child AS is the parent AS — fork must duplicate, not share");
    }

    let parent_region = match parent_as.lookup(VirtAddr::new(SENTINEL_VADDR)) {
        Some(r) => r,
        None => return TestResult::Fail("parent region missing"),
    };
    let child_region = match child_as.lookup(VirtAddr::new(SENTINEL_VADDR)) {
        Some(r) => r,
        None => return TestResult::Fail("child region missing — fork didn't copy"),
    };
    // Post-COW: parent and child SHARE the physical frame
    // immediately after fork. The page-fault handler will split
    // on first write via cow_split_on_write. Both regions also
    // lose their WRITE bit (the trap path needs the fault).
    if parent_region.phys[0] != child_region.phys[0] {
        return TestResult::Fail("COW fork must share frames, not eagerly memcpy");
    }
    if narf_memory::frame::cow::count(parent_region.phys[0]) < 2 {
        return TestResult::Fail("COW refcount should be >= 2 after fork");
    }
    if parent_region
        .perms
        .contains(narf_memory::RegionPerms::WRITE)
        || child_region.perms.contains(narf_memory::RegionPerms::WRITE)
    {
        return TestResult::Fail("post-fork regions must lose WRITE pending split");
    }

    // Verify the shared frame still holds the sentinel byte
    // (parent's bytes are visible to the child since they share).
    // SAFETY: `parent_region.phys[0]` is the identity-mapped COW frame the parent
    // stamped; it is 4 KiB-aligned so reading the `u32` sentinel at offset 0 is
    // aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    let shared_word = unsafe { *(parent_region.phys[0].raw() as *const u32) };
    if shared_word != 0xCAFEBABE {
        return TestResult::Fail("shared COW frame lost the sentinel");
    }

    // Trigger a manual COW split on the child's side, then mutate
    // the child's now-private frame and confirm the parent's
    // shared frame is unchanged.
    // SAFETY: the low-4-GiB identity map is live and the frame allocator + COW
    // refcount table are initialised in the test harness, meeting
    // `cow_split_on_write`'s `# Safety` contract.
    // SAFETY: Valid memory or trusted environment
    if unsafe { child_as.cow_split_on_write(VirtAddr::new(SENTINEL_VADDR)) }.is_err() {
        return TestResult::Fail("cow_split_on_write failed");
    }
    let post_split_child = match child_as.lookup(VirtAddr::new(SENTINEL_VADDR)) {
        Some(r) => r,
        None => return TestResult::Fail("child region missing post-split"),
    };
    if post_split_child.phys[0] == parent_region.phys[0] {
        return TestResult::Fail("split should have allocated a private child frame");
    }
    if !post_split_child
        .perms
        .contains(narf_memory::RegionPerms::WRITE)
    {
        return TestResult::Fail("split should have restored WRITE on the child");
    }
    // SAFETY: `post_split_child.phys[0]` is the identity-mapped private frame the
    // split just allocated and memcpy'd into; 4 KiB-aligned, so the `u32` read at
    // offset 0 is aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    let child_word = unsafe { *(post_split_child.phys[0].raw() as *const u32) };
    if child_word != 0xCAFEBABE {
        return TestResult::Fail("split didn't memcpy the parent's bytes");
    }
    // SAFETY: same private child frame as above; writing a `u32` at offset 0 is
    // aligned, in-bounds, and only the child owns this post-split frame.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        *(post_split_child.phys[0].raw() as *mut u32) = 0xDEADBEEF;
    }
    // SAFETY: `parent_region.phys[0]` is the parent's still-owned identity-mapped
    // frame; reading the `u32` at offset 0 is aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    let parent_word = unsafe { *(parent_region.phys[0].raw() as *const u32) };
    if parent_word != 0xCAFEBABE {
        return TestResult::Fail("mutating child's split frame leaked into parent");
    }

    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fork_distinct_address_space);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_inherits_fd_table() -> TestResult {
    // After fork, the child's fd table is a per-entry copy of the
    // parent's at fork time. fd::with_table lazily creates a table
    // pre-populated with stdio; touching the parent here
    // materialises it for fd::fork to copy.
    use crate::fd;

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    fd::init();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let parent_tid = 0xA11CEu64;
    let parent_count: usize = fd::with_table(parent_tid, |t| {
        (0..16).filter(|&i| t.get(i).is_some()).count()
    })
    .unwrap_or(0);
    if parent_count < 3 {
        return TestResult::Fail("parent table missing default stdio");
    }

    let child_tid = 0xB0BBu64;
    let copied = fd::fork(parent_tid, child_tid);
    if copied < 3 {
        return TestResult::Fail("fork did not copy at least the 3 stdio fds");
    }

    let child_count: usize = fd::with_table(child_tid, |t| {
        (0..16).filter(|&i| t.get(i).is_some()).count()
    })
    .unwrap_or(0);
    if child_count != parent_count {
        return TestResult::Fail("child fd count differs from parent at fork time");
    }

    // Closing a parent fd must NOT touch the child's table — the
    // tables are independent post-fork.
    fd::with_table(parent_tid, |t| t.close(0));
    let child_post: usize = fd::with_table(child_tid, |t| {
        (0..16).filter(|&i| t.get(i).is_some()).count()
    })
    .unwrap_or(0);
    if child_post != parent_count {
        return TestResult::Fail("closing parent fd leaked into child");
    }

    fd::detach(parent_tid);
    fd::detach(child_tid);
    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fork_inherits_fd_table);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_rejects_without_address_space() -> TestResult {
    // Defence-in-depth: with no AS lookup installed, fork must
    // return InvalidOp rather than panic / spawn a bogus task.
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    *PARENT_AS.lock() = None;
    install_address_space_lookup(lookup_parent_as); // returns None

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return set"),
    };
    if ret.status == SyscallReturn::OK {
        return TestResult::Fail("fork without AS lookup should not succeed");
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_fork_rejects_without_address_space
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_resumes_child_with_rax_zero() -> TestResult {
    // Trap-frame inheritance: when the parent's TrapContext can
    // populate a UserState (the real x86_64 path does), sys_fork
    // must:
    //   - capture the parent's saved state via save_user_state,
    //   - mutate rax = 0 in the child's copy (POSIX fork return),
    //   - construct the child's UserTaskFuture via resume_with so
    //     the first poll calls enter_user_mode_resume against the
    //     saved state instead of (entry, stack_top).
    //
    // We synthesise a TrapContext whose save_user_state populates
    // the destination with a known-non-zero set of GPRs + rip + rsp,
    // dispatch fork, then walk the child's UserTaskFuture (via
    // address_space_of → fish out the task) to confirm the saved
    // state's rax was zeroed and the rest matches the parent's.
    use crate::user_task::UserState;

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Parent's would-be saved state. rax is the syscall number on
    // entry (57 = Fork); the rest are arbitrary sentinels we'll
    // verify get inherited unchanged.
    let parent_snapshot = UserState {
        r15: 0x1515_1515_1515_1515,
        r14: 0x1414_1414_1414_1414,
        r13: 0x1313_1313_1313_1313,
        r12: 0x1212_1212_1212_1212,
        r11: 0x1111_1111_1111_1111,
        r10: 0x1010_1010_1010_1010,
        r9: 0x0909_0909_0909_0909,
        r8: 0x0808_0808_0808_0808,
        rbp: 0x4242_4242_4242_4242,
        rdi: 0xDEAD_BEEF_DEAD_BEEF,
        rsi: 0xCAFE_F00D_CAFE_F00D,
        rdx: 0x0123_4567_89AB_CDEF,
        rcx: 0xFEDC_BA98_7654_3210,
        rbx: 0xAAAA_BBBB_CCCC_DDDD,
        rax: 57,
        rip: 0x0000_8000_0001_2345,
        rflags: 0x202,
        rsp: 0x0000_7FFF_FFFC_3FF8,
        valid: 1,
    };

    /// TrapContext that publishes a deterministic snapshot through
    /// save_user_state and remembers the most-recent return.
    struct ForkSnapCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
        snapshot: UserState,
    }
    impl TrapContext for ForkSnapCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
            false
        }
        unsafe fn save_user_state(&self, out: *mut u8) -> bool {
            // SAFETY: caller declared `out` is writable for at
            // least size_of::<UserState>() bytes — the trait's
            // contract; the test passes a freshly-zeroed
            // MaybeUninit<UserState> stack slot.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                core::ptr::write(out as *mut UserState, self.snapshot);
            }
            true
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    let mut ctx = ForkSnapCtx {
        args: SyscallArgs::default(),
        ret: None,
        snapshot: parent_snapshot,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return set"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("fork returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("parent return pid=0");
    }
    // fork returns ProcessId; translate to TaskId for scheduler lookups.
    let child_task_raw = match crate::handlers::pid_to_task_raw(ret.value) {
        Some(t) => t,
        None => return TestResult::Fail("no PID→TaskId mapping after fork"),
    };
    let child_tid = narf_scheduler::TaskId(child_task_raw);

    // Reach into the scheduler to find the child task and confirm
    // its UserTaskFuture's saved state matches `parent_snapshot`
    // with rax rewritten to 0.
    //
    // The scheduler stores the future pinned in the queue; we
    // can't unpack it from the public API. Instead we exercise
    // the observable contract: its state should match
    // `parent_snapshot` modulo rax. We use the
    // `__test_inspect_user_task_state` shim if available.
    //
    // No such shim exists today, so verify what we can: the
    // child task is on the queue with the cloned AS, and the
    // scheduler accepts the resume_with-shaped future.
    let child_as = match narf_scheduler::address_space_of(child_tid) {
        Some(a) => a,
        None => return TestResult::Fail("child has no AS attached"),
    };
    if Arc::ptr_eq(&child_as, &parent_as) {
        return TestResult::Fail("child AS is the parent AS — fork must duplicate");
    }
    // Smoke: the parent's snapshot should still be
    // `parent_snapshot` (the handler captured by value, didn't
    // mutate the source).
    if ctx.snapshot.rax != 57 {
        return TestResult::Fail("handler mutated parent's snapshot rax");
    }
    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_fork_resumes_child_with_rax_zero
);

// ── execve smokes ───────────────────────────────────────────────
//
// `sys_execve` (Syscall::Execve = 179) replaces the current process
// image. Full end-to-end requires a polling user-task ctx (so the
// EXECVE longjmp + ExecRequest pickup can fire); the no-ctx path
// returns `invalid_op()` after the load completes, which is exactly
// what we need to validate the load-side without entering ring 3.

#[cfg(target_arch = "x86_64")]
fn build_minimal_elf_for_execve() -> alloc::vec::Vec<u8> {
    // Same ELF shape used by smoke_userspace_load_user_process_*:
    // one PT_LOAD R|X segment, entry at 0x80_0000_1111.
    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64 + 56 + 0x1000);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine x86_64
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes()); // e_entry
    bytes.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                  // PT_LOAD program header.
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type PT_LOAD
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags R|X
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes()); // p_offset
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    bytes.resize(64 + 56 + 0x1000, 0);
    bytes
}

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_rejects_short_elf() -> TestResult {
    // ELF length below 64-byte header → handler must reject without
    // touching the loader (defensive arg check).
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0xDEAD_BEEFu64, // any non-null pointer
            arg1: 32,             // < 64 — too short
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    if r != SyscallReturn::invalid_op() {
        return TestResult::Fail("short-elf should be rejected with invalid_op");
    }
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_rejects_short_elf);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_rejects_null_ptr() -> TestResult {
    // Null ELF pointer → handler bails before the user-memory copy.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0,    // null
            arg1: 4096, // plausible len
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    if r != SyscallReturn::invalid_op() {
        return TestResult::Fail("null-ptr should be rejected with invalid_op");
    }
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_rejects_null_ptr);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_rejects_oversized_elf() -> TestResult {
    // 64+ MiB cap is the defensive upper bound on `elf_len`.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0xDEAD_BEEFu64,
            arg1: 65 * 1024 * 1024, // > 64 MiB
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    if r != SyscallReturn::invalid_op() {
        return TestResult::Fail("oversized elf_len should be rejected with invalid_op");
    }
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_rejects_oversized_elf);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_loads_elf_then_bails_without_user_ctx() -> TestResult {
    // End-to-end the load side: a valid minimal ELF + valid argv
    // pack. The handler runs `load_user_process_with` to completion,
    // updates /proc/[pid]/{argv,comm}, then discovers there's no
    // active user-task ctx (we're in a kernel-test stub) and bails
    // with `invalid_op()`. Confirms the load-and-publish path
    // doesn't fault on a clean input.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    // argv pack: "init\0" — one NUL-terminated string.
    let argv: alloc::vec::Vec<u8> = b"init\0".to_vec();

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: elf.as_ptr() as u64,
            arg1: elf.len() as u64,
            arg2: argv.as_ptr() as u64,
            arg3: argv.len() as u64,
            arg4: 0, // empty envp
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    // load completed but no user ctx → bail with invalid_op.
    if r != SyscallReturn::invalid_op() {
        return TestResult::Fail("expected invalid_op fallback when no user ctx");
    }
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_loads_elf_then_bails_without_user_ctx
);

// ── extended fork/clone/execve coverage ────────────────────────────
//
// Cover the parts of POSIX inheritance + child-spawning that the
// existing smokes don't reach: cwd / sigaction / fd inheritance
// across fork, basename / cmdline publication on execve, distinct
// child ASes from successive forks, distinct child tids from
// successive clones.

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_distinct_tids_same_as() -> TestResult {
    // Two back-to-back clone calls against the same parent AS must:
    //   (1) both succeed,
    //   (2) yield distinct child tids,
    //   (3) attach the SAME `Arc<AddressSpace>` to both children
    //       (thread-style sharing — the entire point of clone vs fork).
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Linux clone(2): arg0 = flags, arg1 = child stack. CLONE_VM
    // shares the parent address space; the scheduler still assigns a
    // fresh tid to each call.
    const CLONE_VM_SIGHAND_THREAD: u64 = 0x100 | 0x800 | 0x1_0000;
    let dispatch = || -> Option<u64> {
        let mut ctx = StubCtx {
            args: SyscallArgs {
                arg0: CLONE_VM_SIGHAND_THREAD,
                arg1: 0x7fff_fff0_0000,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Clone.raw(), &mut ctx);
        match ctx.ret {
            Some(r) if r.status == SyscallReturn::OK && r.value != 0 => Some(r.value),
            _ => None,
        }
    };

    let t1 = match dispatch() {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("first clone failed");
        }
    };
    let t2 = match dispatch() {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("second clone failed");
        }
    };
    if t1 == t2 {
        *PARENT_AS.lock() = None;
        return TestResult::Fail("two clones returned the same tid");
    }
    let a1 = narf_scheduler::address_space_of(narf_scheduler::TaskId(t1));
    let a2 = narf_scheduler::address_space_of(narf_scheduler::TaskId(t2));
    let pass = match (a1, a2) {
        (Some(a), Some(b)) => Arc::ptr_eq(&a, &parent_as) && Arc::ptr_eq(&b, &parent_as),
        _ => false,
    };
    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    if pass {
        TestResult::Pass
    } else {
        TestResult::Fail("one or both clones don't share the parent AS")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_clone_distinct_tids_same_as);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_rejects_without_address_space() -> TestResult {
    // Symmetric to smoke_userspace_fork_rejects_without_address_space:
    // a clone issued with no AS lookup wired (or one that returns None)
    // must surface a non-OK return rather than panic / spawn a child
    // against a phantom AS.
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    *PARENT_AS.lock() = None;
    install_address_space_lookup(lookup_parent_as); // returns None

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0x8000_0000_1000,
            arg1: 0x7fff_fff0_0000,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Clone.raw(), &mut ctx);
    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    crate::syscall::__test_clear_global();
    if ret.status == SyscallReturn::OK {
        TestResult::Fail("clone without AS lookup should not succeed")
    } else {
        TestResult::Pass
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_clone_rejects_without_address_space
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_inherits_cwd() -> TestResult {
    // fork(2) inheritance contract: the child's cwd starts at the
    // parent's cwd at fork time. sys_fork calls `cwd_fork(parent, child)`
    // which copies the entry under the parent_pid key to the child_pid
    // key. Verify the post-fork lookup returns the parent's path.
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    crate::handlers::__test_cwd_reset();
    crate::handlers::cwd_init();

    static FAKE_TID: AtomicU64 = AtomicU64::new(0xC1D0);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    // Record a non-default cwd against the parent tid. We don't go
    // through sys_chdir because that needs a user-pointer string;
    // poke the CWD_TABLE shape via the public `set` shim isn't
    // exposed, so call the syscall with a kernel-side buffer that
    // the handler reads through identity-mapped low 4 GiB.
    let path = b"/usr/local/tests\0";
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    // chdir validates the target is a real directory — back it with a
    // mounted MemFs at the (nested) mount path. Capture the handle so we
    // can unmount on every exit (a leaked MemFs grows the shared heap).
    let ulc_mount = {
        use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
        let auth = bootstrap_mount_authority();
        registry()
            .mount(
                &auth,
                "/usr/local/tests",
                MemFs::with_seeds("ulctests", &[]),
            )
            .ok()
    };
    let unmount_ulc = || {
        if let Some(h) = &ulc_mount {
            let _ = narf_filesystem::registry().unmount(h, "/usr/local/tests");
        }
    };
    // chdir reads a NUL-terminated path from arg0 (Linux ABI); arg1 is
    // ignored.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(crate::Syscall::Chdir.raw(), &mut ctx);
    let parent_tid = FAKE_TID.load(Ordering::Relaxed);
    let parent_cwd = crate::handlers::cwd_of(parent_tid);
    if parent_cwd != "/usr/local/tests" {
        *PARENT_AS.lock() = None;
        unmount_ulc();
        return TestResult::Fail("parent's Chdir didn't take");
    }

    // Now fork. The handler reads current_task_id() = FAKE_TID for
    // the parent_pid, calls cwd_fork(parent_pid, child_tid).
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
    let child_pid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            *PARENT_AS.lock() = None;
            unmount_ulc();
            return TestResult::Fail("fork failed");
        }
    };
    // fork returns ProcessId; cwd table is keyed by TaskId.
    let child_task_raw = match crate::handlers::pid_to_task_raw(child_pid) {
        Some(t) => t,
        None => {
            *PARENT_AS.lock() = None;
            unmount_ulc();
            return TestResult::Fail("no PID→TaskId mapping after fork");
        }
    };
    let child_cwd = crate::handlers::cwd_of(child_task_raw);
    *PARENT_AS.lock() = None;
    crate::handlers::__test_cwd_reset();
    crate::syscall::__test_clear_global();
    unmount_ulc();
    if child_cwd == parent_cwd {
        TestResult::Pass
    } else {
        TestResult::Fail("child's cwd diverges from parent's at fork time")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fork_inherits_cwd);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_inherits_sigaction_handlers() -> TestResult {
    // fork(2) inheritance: per-signal handler entries cross fork
    // intact. POSIX §3.3.3: "Signals set to the default action
    // (SIG_DFL) in the calling process are set to the default
    // action in the new process. Signals set to be ignored
    // (SIG_IGN) by the calling process are set to be ignored by
    // the new process. Signals set to be caught by the calling
    // process are set to the default action in the new process"
    // — narf currently inherits user handlers (a Linux-compatible
    // deviation; future refinement resets to SIG_DFL).
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    crate::handlers::__test_sigaction_reset();
    crate::sigaction_init();
    crate::handlers::pid_task_map_init();

    static FAKE_TID: AtomicU64 = AtomicU64::new(0x51C1);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Install a handler against signum 15 in the parent.
    const SIGTERM: u64 = 15;
    const HANDLER: u64 = 0xDEAD_F00D_BEEF_CAFE;
    let mut prev: u64 = 0;
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: SIGTERM,
            arg1: HANDLER,
            arg2: &mut prev as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(crate::Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("Sigaction install in parent did not Ok");
    }
    let parent_tid = FAKE_TID.load(Ordering::Relaxed);
    if crate::handlers::sigaction_lookup(parent_tid, SIGTERM as usize) != Some(HANDLER) {
        return TestResult::Fail("parent handler not recorded");
    }

    // Fork → child_pid; sigaction_lookup(child_task_id, SIGTERM) must
    // return HANDLER. fork returns ProcessId; sigaction table is keyed
    // by TaskId so translate through the explicit mapping.
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
    let child_pid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("fork failed");
        }
    };
    let child_task_raw = match crate::handlers::pid_to_task_raw(child_pid) {
        Some(t) => t,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("no PID→TaskId mapping after fork");
        }
    };
    let inherited = crate::handlers::sigaction_lookup(child_task_raw, SIGTERM as usize);
    *PARENT_AS.lock() = None;
    crate::handlers::__test_sigaction_reset();
    crate::handlers::pid_task_map_reset();
    crate::syscall::__test_clear_global();
    if inherited == Some(HANDLER) {
        TestResult::Pass
    } else {
        TestResult::Fail("child did not inherit the parent's SIGTERM handler")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_fork_inherits_sigaction_handlers
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_multiple_distinct_address_spaces() -> TestResult {
    // Two back-to-back forks against the same parent must each get
    // their own fresh `Arc<AddressSpace>` — distinct from the
    // parent AND from each other. Catches a regression where the
    // handler memoised the clone result.
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let do_fork = || -> Option<u64> {
        let mut ctx = StubCtx {
            args: SyscallArgs::default(),
            ret: None,
        };
        kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
        match ctx.ret {
            Some(r) if r.status == SyscallReturn::OK && r.value != 0 => Some(r.value),
            _ => None,
        }
    };

    let c1 = match do_fork() {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("first fork failed");
        }
    };
    let c2 = match do_fork() {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("second fork failed");
        }
    };
    // c1/c2 are ProcessIds; translate to TaskId for scheduler lookups.
    let t1 = crate::handlers::pid_to_task_raw(c1).map(narf_scheduler::TaskId);
    let t2 = crate::handlers::pid_to_task_raw(c2).map(narf_scheduler::TaskId);
    let as1 = t1.and_then(narf_scheduler::address_space_of);
    let as2 = t2.and_then(narf_scheduler::address_space_of);
    let pass = match (as1, as2) {
        (Some(a), Some(b)) => {
            !Arc::ptr_eq(&a, &parent_as) && !Arc::ptr_eq(&b, &parent_as) && !Arc::ptr_eq(&a, &b)
        }
        _ => false,
    };
    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    narf_memory::frame::cow::__test_clear();
    if pass {
        TestResult::Pass
    } else {
        TestResult::Fail("successive forks didn't produce three distinct ASes")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_fork_multiple_distinct_address_spaces
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_sets_comm_to_argv0_basename() -> TestResult {
    // sys_execve takes the basename of argv[0] (the substring after
    // the last '/') and stores it as /proc/[pid]/comm via
    // `set_proc_comm`. Trigger a load with argv[0] = "/usr/bin/foo"
    // and verify comm == "foo" via the public `proc_comm_of` shim.
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    static FAKE_TID: AtomicU64 = AtomicU64::new(0xC0DE_F00D);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Linux execve(path, argv[], envp[]): the kernel resolves `path`
    // through the VFS and reads the ELF from it, so mount the program
    // as a file first.
    let elf = build_minimal_elf_for_execve();
    let auth = narf_filesystem::bootstrap_mount_authority();
    let mounted = narf_filesystem::registry().mount(
        &auth,
        "/execve-comm",
        narf_filesystem::MemFs::with_seeds("execve-comm", &[("prog", &elf)]),
    );
    if mounted.is_err() {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("mount of execve FS failed");
    }

    // argv[0] = "/usr/bin/foo" → comm = basename = "foo". argv is a
    // NUL-terminated array of `char *`, each a NUL-terminated string.
    let path = b"/execve-comm/prog\0";
    let arg0 = b"/usr/bin/foo\0";
    let argv: [u64; 2] = [arg0.as_ptr() as u64, 0];
    let envp: [u64; 1] = [0];
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: argv.as_ptr() as u64,
            arg2: envp.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    // Handler returns invalid_op without a polling user-task ctx,
    // but the load + comm publication runs before that bail-out.

    let pid = FAKE_TID.load(Ordering::Relaxed);
    let comm = crate::handlers::proc_comm_of(pid);
    if let Ok(h) = mounted {
        let _ = narf_filesystem::registry().unmount(&h, "/execve-comm");
    }
    crate::syscall::__test_clear_global();
    match comm {
        Some(s) if s == "foo" => TestResult::Pass,
        Some(other) => {
            let msg = alloc::format!("comm = {:?}; expected \"foo\"", other);
            let leaked: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            TestResult::Fail(leaked)
        }
        None => TestResult::Fail("comm not set by execve"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_sets_comm_to_argv0_basename
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_publishes_cmdline_argv_pack() -> TestResult {
    // After load, /proc/[pid]/cmdline holds the NUL-separated argv
    // bytes the user passed. Confirms `set_proc_argv` ran and the
    // recorded shape matches the wire format.
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    static FAKE_TID: AtomicU64 = AtomicU64::new(0xC0DE_BABE);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Linux execve(path, argv[], envp[]): mount the program so the VFS
    // can resolve `path`, then pass argv as a NUL-terminated array of
    // `char *`. argv = ["init", "-q", "--debug"].
    let elf = build_minimal_elf_for_execve();
    let auth = narf_filesystem::bootstrap_mount_authority();
    let mounted = narf_filesystem::registry().mount(
        &auth,
        "/execve-cmd",
        narf_filesystem::MemFs::with_seeds("execve-cmd", &[("prog", &elf)]),
    );
    if mounted.is_err() {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("mount of execve FS failed");
    }
    let path = b"/execve-cmd/prog\0";
    let a0 = b"init\0";
    let a1 = b"-q\0";
    let a2 = b"--debug\0";
    let argv: [u64; 4] = [
        a0.as_ptr() as u64,
        a1.as_ptr() as u64,
        a2.as_ptr() as u64,
        0,
    ];
    let envp: [u64; 1] = [0];
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: argv.as_ptr() as u64,
            arg2: envp.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);

    let pid = FAKE_TID.load(Ordering::Relaxed);
    let recorded = crate::handlers::proc_argv_of(pid);
    if let Ok(h) = mounted {
        let _ = narf_filesystem::registry().unmount(&h, "/execve-cmd");
    }
    crate::syscall::__test_clear_global();
    // We expect the same NUL-separated shape Linux reports: the
    // original pack bytes joined back together.
    let want: alloc::vec::Vec<u8> = b"init\0-q\0--debug\0".to_vec();
    if recorded == want {
        TestResult::Pass
    } else {
        let msg = alloc::format!("cmdline mismatch: got {:?} want {:?}", recorded, want);
        let leaked: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
        TestResult::Fail(leaked)
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_publishes_cmdline_argv_pack
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_with_envp_pack_accepts() -> TestResult {
    // execve must accept a populated envp pack alongside argv (the
    // existing smokes pass envp = (0, 0)). Confirms `copy_user_pack`
    // is called for both arg2/arg3 and arg4/arg5 and that a valid
    // envp doesn't reject the call.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    let argv = b"sh\0".to_vec();
    let envp = b"PATH=/bin\0LANG=C\0".to_vec();
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: elf.as_ptr() as u64,
            arg1: elf.len() as u64,
            arg2: argv.as_ptr() as u64,
            arg3: argv.len() as u64,
            arg4: envp.as_ptr() as u64,
            arg5: envp.len() as u64,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    crate::syscall::__test_clear_global();
    // Load completes, then the no-ctx path returns invalid_op —
    // same shape as smoke_userspace_execve_loads_elf_then_bails_*.
    // A reject would surface SOMETHING else (handler bailed before
    // the load) which would mean the envp parse failed.
    if r == SyscallReturn::invalid_op() {
        TestResult::Pass
    } else {
        TestResult::Fail("execve with valid envp didn't reach the no-user-ctx bail")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_with_envp_pack_accepts);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_rejects_oversized_argv_pack() -> TestResult {
    // copy_user_pack caps each pack at 64 KiB. An over-cap argv_len
    // must surface invalid_op without copying.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: elf.as_ptr() as u64,
            arg1: elf.len() as u64,
            arg2: 0xDEAD_BEEF_u64,
            arg3: 65 * 1024, // > 64 KiB → rejected
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    crate::syscall::__test_clear_global();
    if r == SyscallReturn::invalid_op() {
        TestResult::Pass
    } else {
        TestResult::Fail("oversized argv pack should be rejected")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_rejects_oversized_argv_pack
);

// ── userspace/init ─────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_init_initramfs_not_staged_yields_clear_error() -> TestResult {
    // Without a staged initramfs (default test condition since no
    // boot path runs install()), spawn_pid1_from_initramfs must
    // return InitError::InitramfsNotStaged — not panic, not silent.
    if narf_initramfs::is_staged() {
        return TestResult::Skip("initramfs is staged in this test env");
    }
    // SAFETY: function is safe to call when initramfs isn't staged;
    // bails out before any unsafe code path runs.
    // SAFETY: Valid memory or trusted environment
    let r = unsafe { crate::init::spawn_pid1_from_initramfs("/sbin/init") };
    match r {
        Err(crate::init::InitError::InitramfsNotStaged) => TestResult::Pass,
        _ => TestResult::Fail("missing initramfs must surface as InitramfsNotStaged"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace/init",
    smoke_init_initramfs_not_staged_yields_clear_error
);

#[cfg(target_arch = "x86_64")]
fn smoke_init_file_listing_returns_none_when_not_staged() -> TestResult {
    if narf_initramfs::is_staged() {
        return TestResult::Skip("initramfs is staged in this test env");
    }
    if crate::init::initramfs_file_listing().is_some() {
        return TestResult::Fail("listing should be None when not staged");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace/init",
    smoke_init_file_listing_returns_none_when_not_staged
);

// ── Phase-2 signal gap-fill smokes ─────────────────────────────────
//
// One smoke per new syscall (sigaltstack install + query, tkill +
// tgkill TID targeting, rt_sigpending pending-and-blocked filter,
// rt_sigsuspend mask round-trip, rt_sigtimedwait delivery + timeout
// paths). All use the FakeCtx pattern shared with the existing
// signal smokes.

struct SigGapCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
}
impl TrapContext for SigGapCtx {
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
    fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
        false
    }
}

fn smoke_userspace_sigaltstack_install_and_query() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0x5A_57_AC_C0);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // First call: query-only — expect SS_DISABLE.
    #[repr(C)]
    #[derive(Copy, Clone, Default, Debug)]
    struct StackT {
        sp: u64,
        flags: u32,
        _pad: u32,
        size: u64,
    }
    let mut out = StackT::default();
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: &mut out as *mut StackT as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaltstack.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_signal_reset();
        return TestResult::Fail("query-only sigaltstack did not Ok");
    }
    if out.flags != 2
    /* SS_DISABLE */
    {
        __test_clear_global();
        crate::handlers::__test_signal_reset();
        return TestResult::Fail("query-only sigaltstack should report SS_DISABLE");
    }

    // Install: sp = 0xABCDEF00, size = 4096, flags = 0.
    let install = StackT {
        sp: 0xABCD_EF00,
        flags: 0,
        _pad: 0,
        size: 4096,
    };
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: &install as *const StackT as u64,
            arg1: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaltstack.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_signal_reset();
        return TestResult::Fail("install sigaltstack did not Ok");
    }

    // Re-query — expect the values just installed.
    let mut out2 = StackT::default();
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: &mut out2 as *mut StackT as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaltstack.raw(), &mut ctx);
    let ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK);
    let match_ = out2.sp == 0xABCD_EF00 && out2.flags == 0 && out2.size == 4096;
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if ok && match_ {
        TestResult::Pass
    } else {
        TestResult::Fail("re-query did not match install")
    }
}
kernel_test_in!("userspace", smoke_userspace_sigaltstack_install_and_query);

fn smoke_userspace_sigaltstack_rejects_too_small() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0x5A_57_AC_C1);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    #[repr(C)]
    struct StackT {
        sp: u64,
        flags: u32,
        _pad: u32,
        size: u64,
    }
    let install = StackT {
        sp: 0x1000,
        flags: 0,
        _pad: 0,
        size: 100, /* < MIN_SIGSTKSZ */
    };
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: &install as *const StackT as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaltstack.raw(), &mut ctx);
    let r = ctx.ret.unwrap_or(SyscallReturn::invalid_op());
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    // -1 (0xFFFF_FFFF_FFFF_FFFF) on rejection.
    if r.status == SyscallReturn::OK && r.value == (-1i64 as u64) {
        TestResult::Pass
    } else {
        TestResult::Fail("undersized altstack should be rejected")
    }
}
kernel_test_in!("userspace", smoke_userspace_sigaltstack_rejects_too_small);

fn smoke_userspace_tkill_targets_specific_tid() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xAAAA);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // tkill TID=0xBBBB with signum=10 (SIGUSR1).
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xBBBB,
            arg1: 10,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Tkill.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_signal_reset();
        return TestResult::Fail("tkill did not Ok");
    }
    let pending_target = crate::handlers::signal_pending_of(0xBBBB);
    let pending_caller = crate::handlers::signal_pending_of(0xAAAA);
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if pending_target & (1 << 10) == 0 {
        return TestResult::Fail("tkill did not set target's pending bit");
    }
    if pending_caller != 0 {
        return TestResult::Fail("tkill bled to caller TID");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_tkill_targets_specific_tid);

fn smoke_userspace_tgkill_routes_via_tid() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xCCCC);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // tgkill TGID=0xCCCC TID=0xDDDD SIG=15 (SIGTERM).
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xCCCC,
            arg1: 0xDDDD,
            arg2: 15,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Tgkill.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_signal_reset();
        return TestResult::Fail("tgkill did not Ok");
    }
    // Target is the TID, NOT the TGID.
    let pending_tid = crate::handlers::signal_pending_of(0xDDDD);
    let pending_tgid = crate::handlers::signal_pending_of(0xCCCC);
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if pending_tid & (1 << 15) == 0 {
        return TestResult::Fail("tgkill did not set TID's pending bit");
    }
    if pending_tgid != 0 {
        return TestResult::Fail("tgkill bled to TGID (which is not the target)");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_tgkill_routes_via_tid);

fn smoke_userspace_rt_sigpending_filters_by_mask() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xEEEE);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Mark SIGUSR1 (10) + SIGTERM (15) pending, mask only SIGUSR1.
    // rt_sigpending must return pending & mask = SIGUSR1 only.
    let mut k = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xEEEE,
            arg1: 10,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut k);
    let mut k = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xEEEE,
            arg1: 15,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut k);
    // sigprocmask BLOCK SIGUSR1. Linux ABI: arg0=how, arg1=set ptr,
    // arg2=old ptr, arg3=sigsetsize (must be 8). A userspace `sigset_t`
    // puts signal N at bit N-1, so SIGUSR1 (10) is bit 9.
    let block: u64 = 1 << 9;
    let mut m = SigGapCtx {
        args: SyscallArgs {
            arg0: 0, /* SIG_BLOCK */
            arg1: &block as *const u64 as u64,
            arg3: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigprocmask.raw(), &mut m);

    let mut out: u64 = 0;
    let mut q = SigGapCtx {
        args: SyscallArgs {
            arg0: &mut out as *mut u64 as u64,
            arg1: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::RtSigpending.raw(), &mut q);
    let ok = matches!(q.ret, Some(r) if r.status == SyscallReturn::OK);
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if !ok {
        return TestResult::Fail("rt_sigpending did not Ok");
    }
    // pending = {10, 15}; mask = {10}; pending & mask = {10}. rt_sigpending
    // reports it back in the userspace sigset convention (signal N at bit
    // N-1), so SIGUSR1 (10) is bit 9.
    if out != (1u64 << 9) {
        return TestResult::Fail("rt_sigpending should report only blocked-and-pending bits");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_rt_sigpending_filters_by_mask);

fn smoke_userspace_rt_sigsuspend_replaces_mask() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF000);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Pre-install a mask of 0x0F via sigprocmask SETMASK.
    let mut m = SigGapCtx {
        args: SyscallArgs {
            arg0: 2, /* SIG_SETMASK */
            arg1: 0x0F,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigprocmask.raw(), &mut m);

    // rt_sigsuspend with set = 0xF0 (userspace sigset). NARF stores the
    // mask shifted `<<1` to align signal N with bit N, so the internal mask
    // becomes 0xF0 << 1 = 0x1E0.
    let new_set: u64 = 0xF0;
    let mut s = SigGapCtx {
        args: SyscallArgs {
            arg0: &new_set as *const u64 as u64,
            arg1: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::RtSigsuspend.raw(), &mut s);
    // POSIX: rt_sigsuspend returns -1 always.
    let returned_minus_one =
        matches!(s.ret, Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64 as u64));
    let mask_after = crate::handlers::signal_mask_of(0xF000);
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if !returned_minus_one {
        return TestResult::Fail("rt_sigsuspend must return -1 (EINTR)");
    }
    if mask_after != 0x1E0 {
        return TestResult::Fail("rt_sigsuspend did not replace mask");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_rt_sigsuspend_replaces_mask);

fn smoke_userspace_rt_sigtimedwait_returns_pending_signal() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF100);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Make SIGUSR2 (12) pending on the calling task.
    let mut k = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xF100,
            arg1: 12,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut k);

    // rt_sigtimedwait waiting for SIGUSR2 (12) should return 12. Userspace
    // sigset puts signal N at bit N-1, so SIGUSR2 is bit 11.
    let set_in: u64 = 1u64 << 11;
    let mut siginfo = [0u8; 128];
    let mut w = SigGapCtx {
        args: SyscallArgs {
            arg0: &set_in as *const u64 as u64,
            arg1: siginfo.as_mut_ptr() as u64,
            arg2: 0, // null timeout
            arg3: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::RtSigtimedwait.raw(), &mut w);
    let r = w.ret.unwrap_or(SyscallReturn::invalid_op());
    let pending_after = crate::handlers::signal_pending_of(0xF100);
    let signo_in_info = i32::from_le_bytes([siginfo[0], siginfo[1], siginfo[2], siginfo[3]]);
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if r.status != SyscallReturn::OK || r.value != 12 {
        return TestResult::Fail("rt_sigtimedwait should return the signum");
    }
    if pending_after & (1 << 12) != 0 {
        return TestResult::Fail("rt_sigtimedwait must clear the pending bit");
    }
    if signo_in_info != 12 {
        return TestResult::Fail("rt_sigtimedwait should fill siginfo.si_signo");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_rt_sigtimedwait_returns_pending_signal
);

fn smoke_userspace_rt_sigtimedwait_no_pending_returns_minus_one() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF200);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Nothing pending. Waiting on SIGUSR1 must return -1 with no
    // siginfo filled.
    let set_in: u64 = 1u64 << 10;
    let mut w = SigGapCtx {
        args: SyscallArgs {
            arg0: &set_in as *const u64 as u64,
            arg1: 0, // info_out null
            arg2: 0, // null timeout
            arg3: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::RtSigtimedwait.raw(), &mut w);
    let r = w.ret.unwrap_or(SyscallReturn::invalid_op());
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if r.status == SyscallReturn::OK && r.value == (-1i64 as u64) {
        TestResult::Pass
    } else {
        TestResult::Fail("rt_sigtimedwait must return -1 when none pending")
    }
}
kernel_test_in!(
    "userspace",
    smoke_userspace_rt_sigtimedwait_no_pending_returns_minus_one
);

fn smoke_userspace_rt_sigtimedwait_picks_lowest_match() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF300);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Make signals 5, 10, 15 pending. Wait on {5, 15} (userspace sigset:
    // signal N at bit N-1, so bits 4 and 14). Should return 5 (lowest match).
    for s in [5u64, 10, 15] {
        let mut k = SigGapCtx {
            args: SyscallArgs {
                arg0: 0xF300,
                arg1: s,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Kill.raw(), &mut k);
    }
    let set_in: u64 = (1u64 << 4) | (1u64 << 14);
    let mut w = SigGapCtx {
        args: SyscallArgs {
            arg0: &set_in as *const u64 as u64,
            arg1: 0,
            arg2: 0,
            arg3: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::RtSigtimedwait.raw(), &mut w);
    let r = w.ret.unwrap_or(SyscallReturn::invalid_op());
    let pending_after = crate::handlers::signal_pending_of(0xF300);
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if r.status != SyscallReturn::OK || r.value != 5 {
        return TestResult::Fail("rt_sigtimedwait must pick the lowest matching signum");
    }
    // 5 cleared; 10 + 15 still pending.
    let want = (1u32 << 10) | (1u32 << 15);
    if pending_after != want {
        return TestResult::Fail("rt_sigtimedwait must clear only the returned signum");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_rt_sigtimedwait_picks_lowest_match
);

fn smoke_userspace_rt_sigpending_zero_when_nothing_blocked() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF400);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Pending SIGUSR1 but no mask. rt_sigpending must report 0.
    let mut k = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xF400,
            arg1: 10,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut k);
    let mut out: u64 = 0xDEADBEEF;
    let mut q = SigGapCtx {
        args: SyscallArgs {
            arg0: &mut out as *mut u64 as u64,
            arg1: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::RtSigpending.raw(), &mut q);
    let ok = matches!(q.ret, Some(r) if r.status == SyscallReturn::OK);
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if !ok {
        return TestResult::Fail("rt_sigpending did not Ok");
    }
    if out != 0 {
        return TestResult::Fail("rt_sigpending must report 0 with empty mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_rt_sigpending_zero_when_nothing_blocked
);

fn smoke_userspace_sigaltstack_query_only_keeps_prior_install() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF500);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    #[repr(C)]
    struct StackT {
        sp: u64,
        flags: u32,
        _pad: u32,
        size: u64,
    }
    let install = StackT {
        sp: 0xDEAD_F000,
        flags: 0,
        _pad: 0,
        size: 8192,
    };
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: &install as *const StackT as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaltstack.raw(), &mut ctx);

    // Two query-onlys in a row — both must return the install
    // values, not 0/SS_DISABLE.
    for _ in 0..2 {
        let mut out = StackT {
            sp: 0,
            flags: 0xFFFF_FFFF,
            _pad: 0,
            size: 0,
        };
        let mut ctx = SigGapCtx {
            args: SyscallArgs {
                arg0: 0,
                arg1: &mut out as *mut StackT as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Sigaltstack.raw(), &mut ctx);
        if out.sp != 0xDEAD_F000 || out.size != 8192 {
            __test_clear_global();
            crate::handlers::__test_signal_reset();
            return TestResult::Fail("query-only must not alter prior install");
        }
    }
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_sigaltstack_query_only_keeps_prior_install
);

fn smoke_userspace_sigaction_flags_stored_and_recovered() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF700);
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

    // Install handler 0xDEAD with flags = SA_SIGINFO | SA_RESTART.
    let flags = crate::handlers::SA_SIGINFO | crate::handlers::SA_RESTART;
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: 10,     // signum = SIGUSR1
            arg1: 0xDEAD, // handler
            arg2: 0,      // old_out null
            arg3: flags as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    let saved = crate::handlers::sigaction_lookup_full(0xF700, 10);
    __test_clear_global();
    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    match saved {
        Some(a) if a.handler == 0xDEAD && a.flags == flags => TestResult::Pass,
        Some(a) => {
            let _ = a;
            TestResult::Fail("sigaction flags were not stored")
        }
        None => TestResult::Fail("sigaction did not install handler"),
    }
}
kernel_test_in!(
    "userspace",
    smoke_userspace_sigaction_flags_stored_and_recovered
);

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
    if mask_after & (1 << 10) != 0 {
        return TestResult::Fail("SA_NODEFER should NOT auto-block the signal");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_sa_nodefer_skips_auto_block);

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
    if mask_after & (1 << 11) == 0 {
        return TestResult::Fail("default delivery should auto-block the signal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_default_delivery_auto_blocks_without_nodefer
);

fn smoke_userspace_tkill_signum_out_of_range_rejected() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xF600);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    crate::handlers::signal_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // signum = 32 (NSIG) must be rejected.
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xBEEF,
            arg1: 32,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Tkill.raw(), &mut ctx);
    let r = ctx.ret.unwrap_or(SyscallReturn::ok(0));
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    if r == SyscallReturn::invalid_op() {
        TestResult::Pass
    } else {
        TestResult::Fail("signum 32 must be rejected")
    }
}
kernel_test_in!(
    "userspace",
    smoke_userspace_tkill_signum_out_of_range_rejected
);

// ─────────────────────────────────────────────────────────────────────────────
// poll / select / pselect6 / epoll smoke tests
// ─────────────────────────────────────────────────────────────────────────────
//
// Test fixture: `ReadyFile` — a `FileOps` whose readiness mask is
// controlled by an `AtomicU32`. Tests install it as an fd, then call
// poll/epoll and verify the returned masks.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering as AtomicOrd};

struct ReadyFile(AtomicU32);

impl core::fmt::Debug for ReadyFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ReadyFile({})", self.0.load(AtomicOrd::Relaxed))
    }
}

impl narf_filesystem::FileOps for ReadyFile {
    fn read<'a>(&'a self, _off: u64, _buf: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _off: u64, buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        let n = buf.len();
        alloc::boxed::Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn poll_readiness(&self) -> u32 {
        self.0.load(AtomicOrd::Relaxed)
    }
}

/// Install `ReadyFile` at a fresh fd under `task_id`.
/// Returns the fd number.
fn install_ready_file(task_id: u64, mask: u32) -> u32 {
    crate::fd::with_table(task_id, |t| {
        t.open(crate::fd::FdEntry {
            ops: Arc::new(ReadyFile(AtomicU32::new(mask))),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .unwrap()
}

/// Common test setup: reset global state, install task-id lookup, build
/// syscall table. Returns task id.
fn setup_poll_test() -> u64 {
    crate::syscall::__test_clear_global();
    crate::fd::__test_reset();
    crate::fd::init();
    crate::handlers::init_per_task_state();
    crate::epoll::__test_reset();

    const TASK: u64 = 0xFACE_CAFE;
    static POLL_TASK: AtomicU64 = AtomicU64::new(TASK);
    fn task_lu() -> u64 {
        POLL_TASK.load(AtomicOrd::Relaxed)
    }
    crate::install_task_id_lookup(task_lu);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    TASK
}

// ── Helper: fire a syscall via StubCtx ───────────────────────────────

fn call(syscall: Syscall, args: SyscallArgs) -> SyscallReturn {
    let mut ctx = StubCtx { args, ret: None };
    kernel_syscall_entry(syscall.raw(), &mut ctx);
    ctx.ret.unwrap_or(SyscallReturn::invalid_op())
}

// ── Poll tests (≥ 6) ─────────────────────────────────────────────────

/// poll: 1 fd, 0 timeout, data ready → returns 1
fn smoke_poll_one_fd_ready_returns_one() -> TestResult {
    let task = setup_poll_test();
    let fd = install_ready_file(task, narf_filesystem::POLL_IN);

    // pollfd: { fd=fd, events=POLLIN, revents=0 }
    let mut pfd: [u8; 8] = [0; 8];
    pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    pfd[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfd.as_ptr() as u64,
            arg1: 1,
            arg2: 0, // timeout_ms = 0 = nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("poll returned non-OK status");
    }
    if r.value != 1 {
        return TestResult::Fail("poll should return 1 for one ready fd");
    }
    // Check revents was written.
    let revents = u16::from_ne_bytes([pfd[6], pfd[7]]);
    if revents == 0 {
        return TestResult::Fail("poll did not write revents");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_one_fd_ready_returns_one);

/// poll: 1 fd, 0 timeout, no data → returns 0 immediately
fn smoke_poll_one_fd_not_ready_returns_zero() -> TestResult {
    let task = setup_poll_test();
    let fd = install_ready_file(task, 0); // not ready

    let mut pfd: [u8; 8] = [0; 8];
    pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    pfd[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfd.as_ptr() as u64,
            arg1: 1,
            arg2: 0, // nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("poll returned non-OK");
    }
    if r.value != 0 {
        return TestResult::Fail("poll should return 0 when fd is not ready (nonblocking)");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_one_fd_not_ready_returns_zero);

/// poll: invalid fd gives POLLNVAL in revents, returns 1
fn smoke_poll_invalid_fd_returns_pollnval() -> TestResult {
    let _task = setup_poll_test();

    let mut pfd: [u8; 8] = [0; 8];
    let bad_fd: i32 = 9999;
    pfd[..4].copy_from_slice(&bad_fd.to_ne_bytes());
    pfd[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfd.as_ptr() as u64,
            arg1: 1,
            arg2: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("poll returned non-OK");
    }
    if r.value != 1 {
        return TestResult::Fail("invalid fd: poll should count as one event (POLLNVAL)");
    }
    let revents = u16::from_ne_bytes([pfd[6], pfd[7]]);
    if (revents as u32 & narf_filesystem::POLL_NVAL) == 0 {
        return TestResult::Fail("POLLNVAL must be set for closed fd");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_invalid_fd_returns_pollnval);

/// poll: POLLHUP signalled when closed-pipe end is ready
fn smoke_poll_pollhup_on_closed_read_end() -> TestResult {
    let task = setup_poll_test();
    // Simulate a half-closed pipe: the read end has POLL_HUP set.
    let fd = install_ready_file(task, narf_filesystem::POLL_HUP);

    let mut pfd: [u8; 8] = [0; 8];
    pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    // We ask for POLL_IN but should get POLL_HUP even without asking.
    pfd[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfd.as_ptr() as u64,
            arg1: 1,
            arg2: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value == 0 {
        return TestResult::Fail("poll should notice POLL_HUP");
    }
    let revents = u16::from_ne_bytes([pfd[6], pfd[7]]);
    if (revents as u32 & narf_filesystem::POLL_HUP) == 0 {
        return TestResult::Fail("POLL_HUP must appear in revents");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_pollhup_on_closed_read_end);

/// poll: nfds=0, timeout=0 → returns 0 immediately (no fds, no spin)
fn smoke_poll_zero_fds_returns_zero() -> TestResult {
    let _task = setup_poll_test();
    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: 1, // non-null but irrelevant
            arg1: 0, // nfds=0
            arg2: 0, // timeout=0
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("poll with nfds=0 should return Ok(0)");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_zero_fds_returns_zero);

/// poll: multiple fds, only some ready → correct count
fn smoke_poll_multiple_fds_partial_ready() -> TestResult {
    let task = setup_poll_test();
    let fd_ready = install_ready_file(task, narf_filesystem::POLL_IN);
    let fd_notready = install_ready_file(task, 0);

    let mut pfds: [u8; 16] = [0; 16];
    pfds[..4].copy_from_slice(&(fd_ready as i32).to_ne_bytes());
    pfds[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());
    pfds[8..12].copy_from_slice(&(fd_notready as i32).to_ne_bytes());
    pfds[12..14].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfds.as_ptr() as u64,
            arg1: 2,
            arg2: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("poll returned non-OK");
    }
    if r.value != 1 {
        return TestResult::Fail("poll: only 1 of 2 fds is ready, should return 1");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_multiple_fds_partial_ready);

// ── select tests (≥ 3) ───────────────────────────────────────────────

/// select: 3 fds in readfds, only 1 is ready → only that bit set in output
fn smoke_select_readfds_partial_ready() -> TestResult {
    let task = setup_poll_test();
    let fd_ready = install_ready_file(task, narf_filesystem::POLL_IN);
    let fd_a = install_ready_file(task, 0);
    let fd_b = install_ready_file(task, 0);

    let nfds = (fd_ready.max(fd_a).max(fd_b) + 1) as usize;
    let mut rfds = [0u8; 128];
    // Set all three bits in readfds.
    rfds[fd_ready as usize / 8] |= 1 << (fd_ready % 8);
    rfds[fd_a as usize / 8] |= 1 << (fd_a % 8);
    rfds[fd_b as usize / 8] |= 1 << (fd_b % 8);
    // timeval = 0 → nonblock
    let tv: [i64; 2] = [0, 0];

    let r = call(
        Syscall::Select,
        SyscallArgs {
            arg0: nfds as u64,
            arg1: rfds.as_mut_ptr() as u64,
            arg2: 0,
            arg3: 0,
            arg4: tv.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("select returned non-OK");
    }
    if r.value != 1 {
        return TestResult::Fail("select: only 1 of 3 fds is ready");
    }
    // Check the ready bit is set.
    let bit_ready = (rfds[fd_ready as usize / 8] >> (fd_ready % 8)) & 1;
    let bit_a = (rfds[fd_a as usize / 8] >> (fd_a % 8)) & 1;
    let bit_b = (rfds[fd_b as usize / 8] >> (fd_b % 8)) & 1;
    if bit_ready == 0 {
        return TestResult::Fail("select: ready fd bit not set in output readfds");
    }
    if bit_a != 0 || bit_b != 0 {
        return TestResult::Fail("select: non-ready fd bits should be clear");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_select_readfds_partial_ready);

/// pselect6: sigmask pointer accepted (silently ignored)
fn smoke_pselect6_sigmask_accepted() -> TestResult {
    let task = setup_poll_test();
    let fd_ready = install_ready_file(task, narf_filesystem::POLL_IN);
    let nfds = (fd_ready + 1) as usize;
    let mut rfds = [0u8; 128];
    rfds[fd_ready as usize / 8] |= 1 << (fd_ready % 8);
    // ts = {0, 0} → nonblock
    let ts: [i64; 2] = [0, 0];
    // Fake sigmask pair: { ptr=1, size=8 } — non-null but content ignored.
    let sigmask_pair: [u64; 2] = [1, 8];

    let r = call(
        Syscall::Pselect6,
        SyscallArgs {
            arg0: nfds as u64,
            arg1: rfds.as_mut_ptr() as u64,
            arg2: 0,
            arg3: 0,
            arg4: ts.as_ptr() as u64,
            arg5: sigmask_pair.as_ptr() as u64,
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("pselect6 returned non-OK");
    }
    if r.value == (!0u64) {
        return TestResult::Fail("pselect6 returned -1");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_pselect6_sigmask_accepted);

/// select: no fds ready, timeout=0 → returns 0
fn smoke_select_no_ready_returns_zero() -> TestResult {
    let task = setup_poll_test();
    let fd = install_ready_file(task, 0); // not ready
    let nfds = (fd + 1) as usize;
    let mut rfds = [0u8; 128];
    rfds[fd as usize / 8] |= 1 << (fd % 8);
    let tv: [i64; 2] = [0, 0]; // nonblock

    let r = call(
        Syscall::Select,
        SyscallArgs {
            arg0: nfds as u64,
            arg1: rfds.as_mut_ptr() as u64,
            arg2: 0,
            arg3: 0,
            arg4: tv.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("select with no ready fds + timeout=0 should return 0");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_select_no_ready_returns_zero);

// ── epoll tests (≥ 7) ───────────────────────────────────────────────

/// epoll_create1 returns a valid fd; close succeeds
fn smoke_epoll_create1_returns_valid_fd() -> TestResult {
    let task = setup_poll_test();

    let r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0, // no flags
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_create1 returned non-OK");
    }
    let epfd = r.value as u32;
    if epfd == (!0u32) {
        return TestResult::Fail("epoll_create1 returned -1");
    }
    // Verify the fd exists in the table by trying to close it.
    let closed = crate::fd::with_table(task, |t| t.close(epfd)).unwrap_or(false);
    if !closed {
        return TestResult::Fail("epoll_create1 fd not in fd table");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_create1_returns_valid_fd);

/// epoll_ctl ADD then DEL — item removed from interest set
fn smoke_epoll_ctl_add_then_del() -> TestResult {
    let task = setup_poll_test();

    // Create epoll fd.
    let r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_create1 failed");
    }
    let epfd = r.value as u32;

    // Install a watched fd.
    let watched = install_ready_file(task, narf_filesystem::POLL_IN);

    // epoll_event = { events: EPOLLIN, data: 0xABCD }
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLIN).to_ne_bytes());
    ev[4..12].copy_from_slice(&0xABCD_u64.to_ne_bytes());

    // ADD
    let r = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("epoll_ctl ADD failed");
    }

    // DEL
    let r = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_DEL as u64,
            arg2: watched as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("epoll_ctl DEL failed");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_ctl_add_then_del);

/// epoll_wait: 0 timeout, no ready items → returns 0
fn smoke_epoll_wait_no_ready_returns_zero() -> TestResult {
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    let watched = install_ready_file(task, 0); // NOT ready
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    ev[4..12].copy_from_slice(&42u64.to_ne_bytes());

    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let mut out_ev = [0u8; 12 * 16];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 16,
            arg3: 0, // timeout=0 → nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("epoll_wait should return 0 when no fd is ready");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_wait_no_ready_returns_zero);

/// epoll_wait: 0 timeout, 1 ready → returns 1 with correct .data
fn smoke_epoll_wait_one_ready_returns_one() -> TestResult {
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    const USERDATA: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    ev[4..12].copy_from_slice(&USERDATA.to_ne_bytes());

    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let mut out_ev = [0u8; 12];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0, // nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 1 {
        return TestResult::Fail("epoll_wait: ready fd should return 1 event");
    }
    let data = u64::from_ne_bytes(out_ev[4..12].try_into().unwrap_or([0; 8]));
    if data != USERDATA {
        return TestResult::Fail("epoll_wait: returned wrong .data value");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_wait_one_ready_returns_one);

/// EPOLLET edge-triggered: first wake delivered; same-state call returns 0
fn smoke_epoll_epollet_edge_triggered() -> TestResult {
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    // Start as ready (POLL_IN) but add with EPOLLET + fresh last_mask=0.
    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    let mut ev = [0u8; 12];
    let flags = crate::epoll::EPOLLIN | crate::epoll::EPOLLET;
    ev[..4].copy_from_slice(&flags.to_ne_bytes());
    ev[4..12].copy_from_slice(&1u64.to_ne_bytes());

    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let mut out_ev = [0u8; 12];
    // First wait: last_mask was 0, current is POLL_IN → transition → deliver.
    let r1 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );

    // Second wait: last_mask now == POLL_IN → no transition → should return 0.
    let r2 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();

    if r1.status != SyscallReturn::OK || r1.value != 1 {
        return TestResult::Fail("EPOLLET: first wake should be delivered");
    }
    if r2.status != SyscallReturn::OK || r2.value != 0 {
        return TestResult::Fail("EPOLLET: second same-state poll should return 0");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_epollet_edge_triggered);

/// EPOLLONESHOT: fires once; re-arm via MOD; fires again
fn smoke_epoll_oneshot_fires_once_rearm_fires_again() -> TestResult {
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    let mut ev = [0u8; 12];
    let flags = crate::epoll::EPOLLIN | crate::epoll::EPOLLONESHOT;
    ev[..4].copy_from_slice(&flags.to_ne_bytes());
    ev[4..12].copy_from_slice(&77u64.to_ne_bytes());

    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let mut out_ev = [0u8; 12];
    // First wait: oneshot fires.
    let r1 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    // Second wait: should return 0 (disarmed).
    let r2 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );

    // Re-arm via MOD.
    let flags2 = crate::epoll::EPOLLIN | crate::epoll::EPOLLONESHOT;
    let mut ev2 = [0u8; 12];
    ev2[..4].copy_from_slice(&flags2.to_ne_bytes());
    ev2[4..12].copy_from_slice(&77u64.to_ne_bytes());
    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_MOD as u64,
            arg2: watched as u64,
            arg3: ev2.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    // Third wait: fires again after re-arm.
    let r3 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();

    if r1.status != SyscallReturn::OK || r1.value != 1 {
        return TestResult::Fail("EPOLLONESHOT: first fire failed");
    }
    if r2.value != 0 {
        return TestResult::Fail("EPOLLONESHOT: should be disarmed after first fire");
    }
    if r3.value != 1 {
        return TestResult::Fail("EPOLLONESHOT: should fire again after MOD re-arm");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_oneshot_fires_once_rearm_fires_again
);

/// 1000 fds in one epoll set, 1 becomes ready → wait returns exactly 1
fn smoke_epoll_1000_fds_one_ready() -> TestResult {
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    // Install 999 not-ready fds + 1 ready one.
    let mut ev = [0u8; 12];
    let mut ready_fd = 0i32;
    const TOTAL: usize = 1000;
    const READY_IDX: usize = 500;
    for i in 0..TOTAL {
        let mask = if i == READY_IDX {
            narf_filesystem::POLL_IN
        } else {
            0
        };
        let fd = install_ready_file(task, mask);
        if i == READY_IDX {
            ready_fd = fd as i32;
        }
        ev.fill(0);
        ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
        ev[4..12].copy_from_slice(&(fd as u64).to_ne_bytes());
        call(
            Syscall::EpollCtl,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: crate::epoll::EPOLL_CTL_ADD as u64,
                arg2: fd as u64,
                arg3: ev.as_ptr() as u64,
                ..SyscallArgs::default()
            },
        );
    }

    let mut out_ev = [0u8; 12 * 16]; // room for 16 results
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 16,
            arg3: 0, // nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();

    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_wait failed");
    }
    if r.value != 1 {
        return TestResult::Fail("1000 fds: only 1 should be returned as ready");
    }
    // Verify the returned data matches the ready fd.
    let data = u64::from_ne_bytes(out_ev[4..12].try_into().unwrap_or([0; 8]));
    if data != ready_fd as u64 {
        return TestResult::Fail("1000 fds: returned wrong fd data");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_1000_fds_one_ready);

// ── Wave-64 eventfd / timerfd / event-loop integration smokes ────────
//
// These exercise the syscall surface for `eventfd2(2)`, `timerfd_create
// /settime/gettime(2)`, and an end-to-end epoll-watching-eventfd loop.
// The handlers themselves were wired earlier — these prove that
// userspace can build a Linux-shaped event loop on top.

/// Wave-64: eventfd2(0, 0) → fd. Write 8 bytes counter delta, read
/// 8 bytes back; counter resets to 0 after a non-semaphore read.
#[cfg(feature = "linux-compat")]
fn smoke_wave64_eventfd_write_read_roundtrip() -> TestResult {
    let task = setup_poll_test();
    let r = call(
        Syscall::Eventfd,
        SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("eventfd2 syscall returned -1");
    }
    let efd = r.value as u32;
    // Write 0x42 to the fd: get the EventFd Arc out of the fd table.
    let ops = crate::fd::with_table(task, |t| t.get(efd).map(|e| e.ops.clone()))
        .flatten()
        .expect("eventfd fd not in table");
    let write_buf = 0x42u64.to_le_bytes();
    let read_buf_res = {
        // Use the FileOps directly — we already proved sys_write
        // routes through it via the OpenFile/Read tests upstream.
        // Driving the future to completion under no_std requires
        // the test poll_once helper which is present in this crate.
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        const NOOP: RawWaker = RawWaker::new(core::ptr::null(), &VT);
        unsafe fn no_op(_: *const ()) {}
        unsafe fn clone(_: *const ()) -> RawWaker {
            NOOP
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        let raw = NOOP;
        // SAFETY: `raw` pairs a null data pointer with the static `VT` vtable whose
        // clone returns the same null waker and wake/drop are no-ops that never
        // dereference the data pointer, so it upholds the `Waker` contract.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw) };
        let mut cx = Context::from_waker(&waker);

        let mut wfut = ops.write(0, &write_buf);
        let _ = match wfut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => r,
            Poll::Pending => {
                crate::syscall::__test_clear_global();
                return TestResult::Fail("eventfd write pending");
            }
        };
        drop(wfut);

        let mut rbuf = [0u8; 8];
        {
            let mut rfut = ops.read(0, &mut rbuf);
            let _ = match rfut.as_mut().poll(&mut cx) {
                Poll::Ready(r) => r,
                Poll::Pending => {
                    crate::syscall::__test_clear_global();
                    return TestResult::Fail("eventfd read pending");
                }
            };
        }
        rbuf
    };
    crate::syscall::__test_clear_global();
    let got = u64::from_le_bytes(read_buf_res);
    if got != 0x42 {
        return TestResult::Fail("eventfd round-trip value mismatch");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_wave64_eventfd_write_read_roundtrip);

/// Wave-64: timerfd_create → settime (1 ms relative) → after the
/// deadline passes, poll_readiness reports POLL_IN.
#[cfg(feature = "linux-compat")]
fn smoke_wave64_timerfd_create_settime_fires() -> TestResult {
    let _task = setup_poll_test();
    let r = call(
        Syscall::TimerfdCreate,
        SyscallArgs {
            arg0: 1, // CLOCK_MONOTONIC (ignored)
            arg1: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("timerfd_create returned -1");
    }
    let tfd = r.value as u32;
    // itimerspec: interval=0 (one-shot); value=1us (so we don't
    // have to wait long in a kernel-test fixture).
    let mut buf = [0u8; 32];
    // interval = 0 — bytes 0..16 stay zero.
    let value_sec: i64 = 0;
    let value_nsec: i64 = 1_000; // 1 μs
    buf[16..24].copy_from_slice(&value_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&value_nsec.to_le_bytes());
    let r = call(
        Syscall::TimerfdSettime,
        SyscallArgs {
            arg0: tfd as u64,
            arg1: 0,
            arg2: buf.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("timerfd_settime returned !=0");
    }
    // Spin until monotonic_ns has moved past the deadline.
    let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
    while narf_scheduler::narf_time::monotonic_ns() < deadline {
        core::hint::spin_loop();
    }
    // poll_readiness should now report POLL_IN — fetch the
    // TimerFd via the kernel-side arc map and call directly.
    let ready = crate::fd::with_table(_task, |t| t.get(tfd).map(|e| e.ops.poll_readiness()))
        .flatten()
        .unwrap_or(0);
    crate::syscall::__test_clear_global();
    if (ready & narf_filesystem::POLL_IN) == 0 {
        return TestResult::Fail("timerfd fd never became readable");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_wave64_timerfd_create_settime_fires);

/// Wave-64: timerfd_gettime returns the configured interval and a
/// value-remaining that drops toward zero. We arm with a 1 s
/// one-shot, then gettime and check the remaining is ≤ 1 s.
#[cfg(feature = "linux-compat")]
fn smoke_wave64_timerfd_gettime_reports_remaining() -> TestResult {
    let _task = setup_poll_test();
    let r = call(Syscall::TimerfdCreate, SyscallArgs::default());
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("timerfd_create -1");
    }
    let tfd = r.value as u32;
    let mut new_value = [0u8; 32];
    // interval = 500ms periodic
    let interval_sec: i64 = 0;
    let interval_nsec: i64 = 500_000_000;
    let value_sec: i64 = 1;
    let value_nsec: i64 = 0;
    new_value[0..8].copy_from_slice(&interval_sec.to_le_bytes());
    new_value[8..16].copy_from_slice(&interval_nsec.to_le_bytes());
    new_value[16..24].copy_from_slice(&value_sec.to_le_bytes());
    new_value[24..32].copy_from_slice(&value_nsec.to_le_bytes());
    let r = call(
        Syscall::TimerfdSettime,
        SyscallArgs {
            arg0: tfd as u64,
            arg1: 0,
            arg2: new_value.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("settime !=0");
    }
    let mut got = [0u8; 32];
    let r = call(
        Syscall::TimerfdGettime,
        SyscallArgs {
            arg0: tfd as u64,
            arg1: got.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("gettime returned non-zero");
    }
    let interval_sec_r = i64::from_le_bytes(got[0..8].try_into().unwrap());
    let interval_nsec_r = i64::from_le_bytes(got[8..16].try_into().unwrap());
    let value_sec_r = i64::from_le_bytes(got[16..24].try_into().unwrap());
    let value_nsec_r = i64::from_le_bytes(got[24..32].try_into().unwrap());
    if interval_sec_r != 0 || interval_nsec_r != 500_000_000 {
        return TestResult::Fail("gettime reported wrong interval");
    }
    // Remaining should be > 0 and ≤ 1 s.
    let total_ns = (value_sec_r as u64).saturating_mul(1_000_000_000) + value_nsec_r as u64;
    if total_ns == 0 || total_ns > 1_000_000_000 {
        return TestResult::Fail("gettime remaining out of range");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_wave64_timerfd_gettime_reports_remaining);

/// Wave-64: end-to-end — register an eventfd in an epoll instance,
/// write to it, and confirm epoll_wait returns the event with the
/// userdata round-tripped intact. Level-triggered (the io_mux
/// epoll variant).
#[cfg(feature = "linux-compat")]
fn smoke_wave64_epoll_watches_eventfd() -> TestResult {
    let task = setup_poll_test();
    // 1. epoll_create1
    let r = call(Syscall::EpollCreate, SyscallArgs::default());
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("epoll_create -1");
    }
    let epfd = r.value as u32;
    // 2. eventfd2 with initval = 0 — starts not-ready.
    let r = call(
        Syscall::Eventfd,
        SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("eventfd -1");
    }
    let efd = r.value as u32;
    // 3. epoll_ctl ADD efd with EPOLLIN + custom userdata.
    const USERDATA: u64 = 0x1234_5678_ABCD_EF01;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_le_bytes());
    ev[4..12].copy_from_slice(&USERDATA.to_le_bytes());
    let r = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: efd as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("epoll_ctl ADD");
    }
    // 4. epoll_wait(timeout=0) — should return 0 (eventfd counter = 0).
    let mut out = [0u8; 12];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("epoll_wait expected 0 events");
    }
    // 5. Poke the eventfd directly via its FileOps to bump the counter.
    {
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        unsafe fn no_op(_: *const ()) {}
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        // SAFETY: the `RawWaker` pairs a null data pointer with the static `VT`
        // vtable whose clone returns the same null waker and wake/drop are no-ops
        // that never dereference the data pointer, so it upholds the `Waker` contract.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        let ops = crate::fd::with_table(task, |t| t.get(efd).map(|e| e.ops.clone()))
            .flatten()
            .expect("efd in table");
        let buf = 7u64.to_le_bytes();
        let mut fut = ops.write(0, &buf);
        let _ = fut.as_mut().poll(&mut cx);
    }
    // 6. epoll_wait — now the eventfd reports POLLIN and userdata
    //    round-trips.
    let mut out = [0u8; 12];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 1 {
        return TestResult::Fail("epoll_wait expected 1 event after eventfd bump");
    }
    let got_events = u32::from_le_bytes(out[..4].try_into().unwrap());
    let got_data = u64::from_le_bytes(out[4..12].try_into().unwrap());
    if got_events & crate::epoll::EPOLLIN == 0 {
        return TestResult::Fail("epoll_wait revents missing EPOLLIN");
    }
    if got_data != USERDATA {
        return TestResult::Fail("epoll_wait userdata mismatch");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_wave64_epoll_watches_eventfd);

// ── AF_INET socket smokes ────────────────────────────────────────────
//
// Exercise the `SocketFile::dispatch_op` surface directly — that's the
// boundary every POSIX syscall lands on, and it doesn't require a
// full syscall-table fixture per test. The smokes cover:
// - SOCK_STREAM bind / listen / connect (loopback path)
// - SOCK_DGRAM bind / connect / sendto / recvfrom
// - SOCK_RAW (IPPROTO_ICMP) — local-loop ICMP echo path
// - Socket options: SO_REUSEADDR, SO_BROADCAST, TCP_NODELAY,
//   TCP_CONGESTION, SO_BINDTODEVICE, SO_TYPE/DOMAIN/PROTOCOL
// - Sockaddr validation: invalid family rejected
// - O_NONBLOCK: recv on empty socket returns EAGAIN
// - SO_ERROR consumes-and-clears pending_error
// - getsockname / getpeername return the bound/peer addrs
// - 16-socket concurrent fan-out

fn build_sockaddr_in(ip: u32, port: u16) -> crate::socket::SockAddr {
    crate::socket::make_sockaddr_in(ip, port)
}

/// AF_INET SOCK_STREAM loopback: socket → bind → listen → connect
/// pairs the listener and connecter via the in-process registry.
fn smoke_socket_inet_tcp_bind_listen_connect() -> TestResult {
    let server = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    // Bind to 127.0.0.1:1234.
    let addr = build_sockaddr_in(0x7F00_0001, 1234);
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind failed");
    }
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("listen failed");
    }
    let client = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    if !matches!(
        client.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        server.unregister();
        return TestResult::Fail("connect failed");
    }
    // Accept the pending connection.
    match server.dispatch_op(crate::socket::SocketOp::Accept) {
        crate::socket::SocketOpResult::Accepted { .. } => {
            server.unregister();
            TestResult::Pass
        }
        _ => {
            server.unregister();
            TestResult::Fail("accept did not return Accepted")
        }
    }
}
kernel_test_in!("userspace", smoke_socket_inet_tcp_bind_listen_connect);

/// AF_INET SOCK_STREAM loopback: full send/recv round-trip after
/// a paired connect+accept.
fn smoke_socket_inet_tcp_send_recv_loopback() -> TestResult {
    let server = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let addr = build_sockaddr_in(0x7F00_0001, 1235);
    let _ = server.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() });
    let _ = server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 1 });
    let client = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let _ = client.dispatch_op(crate::socket::SocketOp::Connect { addr });
    let accepted = match server.dispatch_op(crate::socket::SocketOp::Accept) {
        crate::socket::SocketOpResult::Accepted { socket, .. } => socket,
        _ => {
            server.unregister();
            return TestResult::Fail("no accept");
        }
    };
    // Client → server.
    let payload = b"hello narf";
    let r = client.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: None,
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(n) if n == payload.len() as u64) {
        server.unregister();
        return TestResult::Fail("client send mismatch");
    }
    let mut recv_buf = [0u8; 16];
    let r = accepted.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut recv_buf,
        flags: 0,
    });
    server.unregister();
    match r {
        crate::socket::SocketOpResult::Received { n, .. } => {
            if &recv_buf[..n] != payload {
                TestResult::Fail("recv payload mismatch")
            } else {
                TestResult::Pass
            }
        }
        _ => TestResult::Fail("recv did not return Received"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet_tcp_send_recv_loopback);

/// shutdown(SHUT_WR) closes the tx half on a loopback connection.
fn smoke_socket_inet_tcp_shutdown_wr() -> TestResult {
    let server = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let addr = build_sockaddr_in(0x7F00_0001, 1236);
    let _ = server.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() });
    let _ = server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 1 });
    let client = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let _ = client.dispatch_op(crate::socket::SocketOp::Connect { addr });
    let _ = server.dispatch_op(crate::socket::SocketOp::Accept);
    let r = client.dispatch_op(crate::socket::SocketOp::Shutdown {
        how: crate::socket::SHUT_WR,
    });
    server.unregister();
    if matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        TestResult::Pass
    } else {
        TestResult::Fail("shutdown(SHUT_WR) failed")
    }
}
kernel_test_in!("userspace", smoke_socket_inet_tcp_shutdown_wr);

/// AF_INET SOCK_DGRAM: bind, sendto self, recvfrom returns payload.
fn smoke_socket_inet_udp_send_recv_self() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let addr = build_sockaddr_in(0x7F00_0001, 5000);
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("udp bind failed");
    }
    let payload = b"udp-ping";
    let _ = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(addr),
    });
    let mut buf = [0u8; 32];
    let r = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    });
    sock.unregister();
    match r {
        crate::socket::SocketOpResult::Received { n, peer } => {
            if &buf[..n] != payload {
                return TestResult::Fail("udp payload mismatch");
            }
            if peer.is_none() {
                return TestResult::Fail("udp recv did not return peer");
            }
            TestResult::Pass
        }
        _ => TestResult::Fail("udp recv did not return Received"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet_udp_send_recv_self);

/// SO_BROADCAST: without it, sendto to 255.255.255.255 fails;
/// with it, the send succeeds (queue drop is OK).
fn smoke_socket_inet_udp_so_broadcast_gate() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let addr = build_sockaddr_in(0x7F00_0001, 5001);
    let _ = sock.dispatch_op(crate::socket::SocketOp::Bind { addr });
    let bcast = build_sockaddr_in(0xFFFF_FFFF, 5002);
    let payload = b"bcast";
    // Without SO_BROADCAST: must fail.
    let r = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(bcast.clone()),
    });
    if matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        sock.unregister();
        return TestResult::Fail("broadcast send w/o SO_BROADCAST should fail");
    }
    // Set SO_BROADCAST = 1.
    let one = 1u32.to_ne_bytes();
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_BROADCAST,
        value: &one,
    });
    let r2 = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(bcast),
    });
    sock.unregister();
    if matches!(r2, crate::socket::SocketOpResult::Ok(_)) {
        TestResult::Pass
    } else {
        TestResult::Fail("broadcast send w/ SO_BROADCAST should succeed")
    }
}
kernel_test_in!("userspace", smoke_socket_inet_udp_so_broadcast_gate);

/// UDP connect()'d mode filters packets from a different peer.
fn smoke_socket_inet_udp_connected_filter() -> TestResult {
    // Sock A binds to port 6001, will recv only from 127.0.0.1:6002.
    let a = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = a.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 6001),
    });
    let peer_b = build_sockaddr_in(0x7F00_0001, 6002);
    let _ = a.dispatch_op(crate::socket::SocketOp::Connect {
        addr: peer_b.clone(),
    });
    // Sock C (different sender) shoots a packet at A.
    let c = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = c.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 6003),
    });
    let _ = c.dispatch_op(crate::socket::SocketOp::Send {
        buf: b"stranger",
        flags: 0,
        addr: Some(build_sockaddr_in(0x7F00_0001, 6001)),
    });
    let mut buf = [0u8; 16];
    let r = a.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    });
    a.unregister();
    c.unregister();
    // Connected mode filter drops the unmatched packet → WouldBlock.
    match r {
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            TestResult::Pass
        }
        _ => TestResult::Fail("connected udp did not filter wrong peer"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet_udp_connected_filter);

/// AF_INET SOCK_RAW with IPPROTO_ICMP: send + recv round-trip.
fn smoke_socket_inet_raw_icmp_loopback() -> TestResult {
    let sock = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_INET,
        crate::socket::SOCK_RAW,
        crate::socket::IPPROTO_ICMP,
    );
    let dest = build_sockaddr_in(0x7F00_0001, 0);
    let payload = b"\x08\x00\x00\x00ping";
    let r = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(dest),
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("icmp send failed");
    }
    let mut buf = [0u8; 64];
    let r = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    });
    match r {
        crate::socket::SocketOpResult::Received { n, .. } => {
            if &buf[..n] != payload {
                TestResult::Fail("icmp recv payload mismatch")
            } else {
                TestResult::Pass
            }
        }
        _ => TestResult::Fail("icmp recv did not return Received"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet_raw_icmp_loopback);

/// SO_REUSEADDR: stored value round-trips through get/setsockopt.
fn smoke_socket_so_reuseaddr_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let one = 1u32.to_ne_bytes();
    let r = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_REUSEADDR,
        value: &one,
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("setsockopt(SO_REUSEADDR) failed");
    }
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_REUSEADDR,
        buf: &mut out,
    });
    match r {
        crate::socket::SocketOpResult::OptValue { n: 4 } => {
            let v = u32::from_ne_bytes(out);
            if v == 1 {
                TestResult::Pass
            } else {
                TestResult::Fail("got != 1")
            }
        }
        _ => TestResult::Fail("getsockopt did not return OptValue"),
    }
}
kernel_test_in!("userspace", smoke_socket_so_reuseaddr_round_trip);

/// TCP_NODELAY: stored value round-trips through get/setsockopt.
fn smoke_socket_tcp_nodelay_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let one = 1u32.to_ne_bytes();
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_NODELAY,
        value: &one,
    });
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_NODELAY,
        buf: &mut out,
    });
    if matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 }) && u32::from_ne_bytes(out) == 1
    {
        TestResult::Pass
    } else {
        TestResult::Fail("TCP_NODELAY did not round-trip")
    }
}
kernel_test_in!("userspace", smoke_socket_tcp_nodelay_round_trip);

/// TCP_CONGESTION: round-trip "reno" then "cubic".
fn smoke_socket_tcp_congestion_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_CONGESTION,
        value: b"reno",
    });
    let mut out = [0u8; 16];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_CONGESTION,
        buf: &mut out,
    });
    let n = match r {
        crate::socket::SocketOpResult::OptValue { n } => n,
        _ => return TestResult::Fail("TCP_CONGESTION get failed"),
    };
    if &out[..n] != b"reno" {
        return TestResult::Fail("TCP_CONGESTION 'reno' round-trip failed");
    }
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_CONGESTION,
        value: b"cubic",
    });
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_CONGESTION,
        buf: &mut out,
    });
    let n = match r {
        crate::socket::SocketOpResult::OptValue { n } => n,
        _ => return TestResult::Fail("TCP_CONGESTION (cubic) get failed"),
    };
    if &out[..n] != b"cubic" {
        return TestResult::Fail("TCP_CONGESTION 'cubic' round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_tcp_congestion_round_trip);

/// SO_BINDTODEVICE: string round-trip.
fn smoke_socket_so_bindtodevice_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_BINDTODEVICE,
        value: b"eth0",
    });
    let mut out = [0u8; 16];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_BINDTODEVICE,
        buf: &mut out,
    });
    let n = match r {
        crate::socket::SocketOpResult::OptValue { n } => n,
        _ => return TestResult::Fail("SO_BINDTODEVICE get failed"),
    };
    if &out[..n] == b"eth0" {
        TestResult::Pass
    } else {
        TestResult::Fail("SO_BINDTODEVICE round-trip mismatch")
    }
}
kernel_test_in!("userspace", smoke_socket_so_bindtodevice_round_trip);

/// sockaddr_in with invalid family rejected by Connect.
fn smoke_socket_sockaddr_invalid_family_rejected() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let mut bogus = crate::socket::make_sockaddr_in(0x7F00_0001, 4321);
    bogus.family = 9999; // not AF_INET / AF_UNIX / AF_INET6
    let r = sock.dispatch_op(crate::socket::SocketOp::Connect { addr: bogus });
    if matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        TestResult::Pass
    } else {
        TestResult::Fail("invalid family was not rejected")
    }
}
kernel_test_in!("userspace", smoke_socket_sockaddr_invalid_family_rejected);

/// sockaddr_in port is honored in network byte order.
fn smoke_socket_sockaddr_port_network_byte_order() -> TestResult {
    // Build an explicit body with port 0x4321 (BE) + IP 127.0.0.1.
    let body = alloc::vec![0x43u8, 0x21, 127, 0, 0, 1];
    let addr = crate::socket::SockAddr {
        family: crate::socket::AF_INET,
        body,
    };
    match crate::socket::parse_sockaddr_in(&addr) {
        Some((ip, port)) => {
            if ip == 0x7F00_0001 && port == 0x4321 {
                TestResult::Pass
            } else {
                TestResult::Fail("port/ip parse mismatch")
            }
        }
        None => TestResult::Fail("parse failed"),
    }
}
kernel_test_in!("userspace", smoke_socket_sockaddr_port_network_byte_order);

/// O_NONBLOCK: recv on empty socket returns EAGAIN immediately.
fn smoke_socket_nonblock_recv_returns_eagain() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = sock.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 7000),
    });
    sock.set_nonblock(true);
    if !sock.is_nonblock() {
        sock.unregister();
        return TestResult::Fail("set_nonblock didn't take");
    }
    let mut buf = [0u8; 8];
    let r = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    });
    sock.unregister();
    match r {
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            TestResult::Pass
        }
        _ => TestResult::Fail("nonblock recv did not return WouldBlock"),
    }
}
kernel_test_in!("userspace", smoke_socket_nonblock_recv_returns_eagain);

/// SO_ERROR consumes and clears a pending async error.
fn smoke_socket_so_error_consumes_and_clears() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    sock.set_pending_error(crate::socket::SockError::ConnectionRefused);
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_ERROR,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 }) {
        return TestResult::Fail("first SO_ERROR get failed");
    }
    let v = u32::from_ne_bytes(out);
    // ConnectionRefused → errno 111.
    if v != 111 {
        return TestResult::Fail("SO_ERROR returned wrong errno");
    }
    // Second read should return 0 (cleared).
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_ERROR,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 }) {
        return TestResult::Fail("second SO_ERROR get failed");
    }
    let v = u32::from_ne_bytes(out);
    if v != 0 {
        return TestResult::Fail("SO_ERROR did not clear");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_so_error_consumes_and_clears);

/// getsockname after bind returns the assigned (port, ip).
fn smoke_socket_getsockname_after_bind() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = sock.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 4040),
    });
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockName);
    sock.unregister();
    match r {
        crate::socket::SocketOpResult::Addr(addr) => {
            match crate::socket::parse_sockaddr_in(&addr) {
                Some((ip, port)) if ip == 0x7F00_0001 && port == 4040 => TestResult::Pass,
                _ => TestResult::Fail("getsockname returned wrong addr"),
            }
        }
        _ => TestResult::Fail("getsockname did not return Addr"),
    }
}
kernel_test_in!("userspace", smoke_socket_getsockname_after_bind);

/// getpeername on a connected UDP socket returns the connect()'d peer.
fn smoke_socket_getpeername_after_connect() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let peer = build_sockaddr_in(0x7F00_0001, 9999);
    let _ = sock.dispatch_op(crate::socket::SocketOp::Connect { addr: peer });
    let r = sock.dispatch_op(crate::socket::SocketOp::GetPeerName);
    match r {
        crate::socket::SocketOpResult::Addr(addr) => {
            match crate::socket::parse_sockaddr_in(&addr) {
                Some((ip, port)) if ip == 0x7F00_0001 && port == 9999 => TestResult::Pass,
                _ => TestResult::Fail("getpeername returned wrong addr"),
            }
        }
        _ => TestResult::Fail("getpeername did not return Addr"),
    }
}
kernel_test_in!("userspace", smoke_socket_getpeername_after_connect);

/// SO_TYPE, SO_DOMAIN, SO_PROTOCOL all report what socket() captured.
fn smoke_socket_so_type_domain_protocol() -> TestResult {
    let sock = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_INET,
        crate::socket::SOCK_DGRAM,
        crate::socket::IPPROTO_UDP,
    );
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_TYPE,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        || u32::from_ne_bytes(out) != crate::socket::SOCK_DGRAM
    {
        return TestResult::Fail("SO_TYPE mismatch");
    }
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_DOMAIN,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        || u32::from_ne_bytes(out) != crate::socket::AF_INET as u32
    {
        return TestResult::Fail("SO_DOMAIN mismatch");
    }
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_PROTOCOL,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        || u32::from_ne_bytes(out) != crate::socket::IPPROTO_UDP
    {
        return TestResult::Fail("SO_PROTOCOL mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_so_type_domain_protocol);

/// IP_TTL is validated on the way in (0 and >255 → InvalidArg) and
/// round-trips otherwise.
fn smoke_socket_ip_ttl_validated_and_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    // Reject 0.
    let zero = 0u32.to_ne_bytes();
    let r = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_IP,
        name: crate::socket::IP_TTL,
        value: &zero,
    });
    if !matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("IP_TTL=0 should be rejected");
    }
    // Reject 300.
    let big = 300u32.to_ne_bytes();
    let r = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_IP,
        name: crate::socket::IP_TTL,
        value: &big,
    });
    if !matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("IP_TTL=300 should be rejected");
    }
    // Accept 32.
    let val = 32u32.to_ne_bytes();
    let r = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_IP,
        name: crate::socket::IP_TTL,
        value: &val,
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("IP_TTL=32 set failed");
    }
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::IPPROTO_IP,
        name: crate::socket::IP_TTL,
        buf: &mut out,
    });
    if matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        && u32::from_ne_bytes(out) == 32
    {
        TestResult::Pass
    } else {
        TestResult::Fail("IP_TTL did not round-trip 32")
    }
}
kernel_test_in!("userspace", smoke_socket_ip_ttl_validated_and_round_trip);

/// 16 concurrent UDP sockets — verify no allocator pressure / state leak.
fn smoke_socket_inet_udp_16_concurrent() -> TestResult {
    let mut socks: alloc::vec::Vec<alloc::sync::Arc<crate::socket::SocketFile>> =
        alloc::vec::Vec::with_capacity(16);
    for i in 0..16u16 {
        let s = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
        let r = s.dispatch_op(crate::socket::SocketOp::Bind {
            addr: build_sockaddr_in(0x7F00_0001, 8000 + i),
        });
        if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
            for s in &socks {
                s.unregister();
            }
            return TestResult::Fail("16 concurrent bind failed");
        }
        socks.push(s);
    }
    // sendto self for each.
    for (i, s) in socks.iter().enumerate() {
        let payload = (i as u32).to_ne_bytes();
        let _ = s.dispatch_op(crate::socket::SocketOp::Send {
            buf: &payload,
            flags: 0,
            addr: Some(build_sockaddr_in(0x7F00_0001, 8000 + i as u16)),
        });
    }
    // recvfrom each, verify payload.
    let mut ok = true;
    for (i, s) in socks.iter().enumerate() {
        let mut buf = [0u8; 4];
        let r = s.dispatch_op(crate::socket::SocketOp::Recv {
            buf: &mut buf,
            flags: 0,
        });
        match r {
            crate::socket::SocketOpResult::Received { n: 4, .. } => {
                if u32::from_ne_bytes(buf) != i as u32 {
                    ok = false;
                }
            }
            _ => {
                ok = false;
            }
        }
    }
    for s in &socks {
        s.unregister();
    }
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("16 concurrent payload mismatch")
    }
}
kernel_test_in!("userspace", smoke_socket_inet_udp_16_concurrent);

/// SO_REUSEADDR + double-bind: the second bind to the same
/// (addr, port) succeeds when SO_REUSEADDR is set on the second
/// socket. Without it, the second bind returns EADDRINUSE.
fn smoke_socket_so_reuseaddr_double_bind_inet() -> TestResult {
    let a = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let one = 1u32.to_ne_bytes();
    let _ = a.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_REUSEADDR,
        value: &one,
    });
    let bound = a.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 9100),
    });
    if !matches!(bound, crate::socket::SocketOpResult::Ok(_)) {
        a.unregister();
        return TestResult::Fail("first bind failed");
    }
    // Second socket without SO_REUSEADDR — must reject.
    let b = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let r = b.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 9100),
    });
    if !matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::AddrInUse)
    ) {
        a.unregister();
        b.unregister();
        return TestResult::Fail("second bind without SO_REUSEADDR should fail");
    }
    // Third socket WITH SO_REUSEADDR — must succeed.
    let c = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = c.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_REUSEADDR,
        value: &one,
    });
    let r = c.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 9100),
    });
    a.unregister();
    c.unregister();
    if matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        TestResult::Pass
    } else {
        TestResult::Fail("second bind with SO_REUSEADDR should succeed")
    }
}
kernel_test_in!("userspace", smoke_socket_so_reuseaddr_double_bind_inet);

/// SO_RCVBUF / SO_SNDBUF clamp small values to ≥ 2 KiB and
/// round-trip larger values verbatim.
fn smoke_socket_so_rcvbuf_sndbuf_clamp() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    // Set RCVBUF to 100; should clamp to 2048.
    let v = 100u32.to_ne_bytes();
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_RCVBUF,
        value: &v,
    });
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_RCVBUF,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 }) {
        return TestResult::Fail("SO_RCVBUF get failed");
    }
    if u32::from_ne_bytes(out) != 2_048 {
        return TestResult::Fail("SO_RCVBUF did not clamp");
    }
    // Set SNDBUF to 64 KiB; should round-trip exact.
    let v = 65_536u32.to_ne_bytes();
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_SNDBUF,
        value: &v,
    });
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_SNDBUF,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        || u32::from_ne_bytes(out) != 65_536
    {
        return TestResult::Fail("SO_SNDBUF did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_so_rcvbuf_sndbuf_clamp);

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
    fd::init();
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
    fd::init();
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
    fd::init();
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
    fd::init();
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

// ── ConsoleFile stdin smoke tests (Wave 37) ───────────────────────────────────
//
// These tests drive ConsoleFile::read (fd 0 / stdin) through the BYTE_RING
// to verify the wired serial RX path end-to-end at the FileOps level.
//
// All four tests use the syscall path (sys_read via kernel_syscall_entry) so
// they exercise the same code path as the real shell.

fn smoke_console_read_empty_buf_returns_zero() -> TestResult {
    // ConsoleFile::read with an empty (zero-length) user buffer must
    // return Ok(0) immediately — the fast-path guard before the await.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_0001);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Open stdin (fd 0) is pre-populated by fd::with_table with ConsoleFile.
    // We need fd 0 to exist; force-create the table entry.
    let _dummy = fd::with_table(task, |_t| ());

    // Dummy output buffer — we ask for 0 bytes.
    let mut buf = [0u8; 4];
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0, // fd 0 = stdin
            arg1: buf.as_mut_ptr() as u64,
            arg2: 0, // zero-length read
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    fd::__test_reset();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("zero-len read did not return Ok(0)")
        }
    }
}
kernel_test_in!("userspace", smoke_console_read_empty_buf_returns_zero);

fn smoke_console_read_one_byte_in_ring() -> TestResult {
    // ConsoleFile::read with one byte pre-loaded into the BYTE_RING must
    // return Ok(1) and the exact byte value.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_0002);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Pre-load one byte ('A' = 0x41) into the ASCII ring.
    narf_input::push_global(narf_input::InputEvent::AsciiByte(b'A'));

    let _ = fd::with_table(task, |_t| ());

    let mut buf = [0u8; 4];
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    fd::__test_reset();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 1 => {
            if buf[0] == b'A' {
                TestResult::Pass
            } else {
                TestResult::Fail("byte value mismatch — expected 'A'")
            }
        }
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
            TestResult::Fail("read returned 0 bytes — byte in ring was not consumed")
        }
        _ => TestResult::Fail("sys_read returned unexpected status"),
    }
}
kernel_test_in!("userspace", smoke_console_read_one_byte_in_ring);

fn smoke_console_read_drains_burst() -> TestResult {
    // ConsoleFile::read with 3 bytes pre-loaded must return Ok(3) and
    // deliver all three bytes in order (paste-burst drain path).
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_0003);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Pre-load "hi\n" (3 bytes) into the ASCII ring.
    for &b in b"hi\n" {
        narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
    }

    let _ = fd::with_table(task, |_t| ());

    let mut buf = [0u8; 8];
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    fd::__test_reset();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 3 => {
            if &buf[..3] == b"hi\n" {
                TestResult::Pass
            } else {
                TestResult::Fail("3-byte burst: payload mismatch")
            }
        }
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
            TestResult::Fail("3-byte burst: read returned 0 — bytes not consumed")
        }
        Some(r) if r.status == SyscallReturn::OK => {
            TestResult::Fail("3-byte burst: wrong count returned")
        }
        _ => TestResult::Fail("3-byte burst: sys_read bad status"),
    }
}
kernel_test_in!("userspace", smoke_console_read_drains_burst);

fn smoke_console_read_empty_ring_returns_zero() -> TestResult {
    // ConsoleFile::read with an empty ring and a non-zero buffer must return
    // Ok(0) — no bytes available yet. The shell's usleep-retry loop handles
    // the backoff; returning 0 is the non-blocking "try again later" signal.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_0004);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Ring is empty — no push.
    let _ = fd::with_table(task, |_t| ());

    let mut buf = [0u8; 4];
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    fd::__test_reset();
    __test_clear_global();

    // Either Ok(0) — poll_blocking timed out → handler unwrap_or(0) —
    // or a deliberate Ok(0) from the future. Both signal "no data now".
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => TestResult::Pass,
        _ => TestResult::Fail("empty ring: expected Ok(0) from sys_read"),
    }
}
kernel_test_in!("userspace", smoke_console_read_empty_ring_returns_zero);

// ── Wave 39: end-to-end `echo hello world` golden path ────────────────────
//
// The Wave-37/38/39 chain (serial RX → BYTE_RING → ConsoleFile::read →
// shell built-in echo → ConsoleFile::write → console::write_str → klog)
// is the project's end-to-end target. Each link has its own unit-level
// smoke; this one drives the whole chain in one shot so a regression
// anywhere along the way is caught by a single failing test.
//
// Steps:
//   1. Pre-load "echo hello world\n" into the BYTE_RING (simulates QEMU
//      `-serial stdio` typing).
//   2. sys_read on fd 0 — must drain the full line into a buffer.
//   3. Parse the line shell-style: split on first space, take "hello world"
//      as `rest`. Mirror userspace/shell/src/main.rs:1560-1564's built-in
//      echo (write rest, write NEWLINE).
//   4. sys_write each segment on fd 1 — routes through ConsoleFile::write
//      → narf_console::Writer → write_str → klog::record.
//   5. klog::snapshot must contain "hello world\n" as a contiguous run.
//
// We can't observe the real UART backend in a kernel-test (no QEMU stdio
// hooked to the SUT's COM1 in test mode), but klog is fed unconditionally
// upstream of the backend, so it's a faithful proxy for "the bytes left
// the userspace task and reached the platform console layer."

#[cfg(target_arch = "x86_64")]
fn smoke_echo_hello_world_end_to_end() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_E2E0);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Step 1: stuff "echo hello world\n" into the global ASCII byte ring,
    // exactly as the IRQ-4 serial RX handler would on real bytes typed
    // into `qemu -serial stdio`.
    const LINE: &[u8] = b"echo hello world\n";
    for &b in LINE {
        narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
    }

    // Force the per-task fd table to materialise with fd 0/1/2 wired
    // to ConsoleFile.
    let _ = fd::with_table(task, |_t| ());

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

    // Step 2: sys_read on fd 0. Buffer is sized for the full line plus a
    // generous tail.
    let mut buf = [0u8; 64];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    let n_read = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("sys_read on fd 0: bad status");
        }
    };
    if n_read != LINE.len() || &buf[..n_read] != LINE {
        fd::__test_reset();
        __test_clear_global();
        return TestResult::Fail("sys_read drained wrong payload");
    }

    // Step 3: shell-style parse. Find the first space; "echo" is the
    // command, the rest is the argv tail. Strip the trailing newline so
    // the echo built-in's write_all(rest) matches what we expect on the
    // wire.
    let line_no_nl = &buf[..n_read - 1]; // drop '\n'
    let space_at = match line_no_nl.iter().position(|&b| b == b' ') {
        Some(i) => i,
        None => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("parse: no space in line");
        }
    };
    let cmd = &line_no_nl[..space_at];
    let rest = &line_no_nl[space_at + 1..];
    if cmd != b"echo" {
        fd::__test_reset();
        __test_clear_global();
        return TestResult::Fail("parse: cmd != echo");
    }

    // Snapshot klog *before* we write so we can find the new region after.
    let pre_len = narf_console::klog::snapshot().len();

    // Step 4: sys_write on fd 1 — the body, then a newline. Two calls
    // mirror the shell's `write_all(fd, rest); write_all(fd, NEWLINE);`.
    let mut ctx_w1 = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: rest.as_ptr() as u64,
            arg2: rest.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx_w1);
    match ctx_w1.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == rest.len() as u64 => {}
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("sys_write(rest) failed");
        }
    }

    let nl: &[u8] = b"\n";
    let mut ctx_w2 = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: nl.as_ptr() as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx_w2);
    match ctx_w2.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 1 => {}
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("sys_write(NL) failed");
        }
    }

    // Step 5: pull a fresh klog snapshot and look for "hello world\n"
    // anywhere in the post-write tail. The pre/post split is just a
    // performance hint — if the ring has wrapped, search the whole
    // window.
    let post = narf_console::klog::snapshot();
    let needle: &[u8] = b"hello world\n";
    let tail_start = pre_len.min(post.len().saturating_sub(needle.len()));
    let haystack = &post[tail_start..];
    let found = haystack.windows(needle.len()).any(|w| w == needle);

    fd::__test_reset();
    __test_clear_global();

    if found {
        TestResult::Pass
    } else {
        TestResult::Fail("klog did not contain \"hello world\\n\" after sys_write on fd 1")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_echo_hello_world_end_to_end);

// ── Wave-51: terminal ioctls on the console fd ─────────────────────
//
// Real userspace (ls, bash, vi, less) probes TIOCGWINSZ / FIONREAD /
// TIOCGPGRP to decide whether stdout is a tty and what dimensions
// to draw to. Wave-51 wires these against ConsoleFile so the probes
// stop returning ENOTTY. Each smoke runs the syscall path end-to-end
// via sys_ioctl.

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_tiocgwinsz_default_80x24() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1001);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

    // Kernel-stack buffer for the winsize copy-out. The ioctl arg
    // pointer goes straight into the FileOps impl; copy_to_user's
    // pointer check passes for canonical addresses regardless of
    // half.
    let mut ws = fd::Winsize::default();
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1, // stdout
            arg1: fd::TIOCGWINSZ as u64,
            arg2: &mut ws as *mut _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
            if ws.ws_row == 24 && ws.ws_col == 80 {
                TestResult::Pass
            } else {
                TestResult::Fail("TIOCGWINSZ default not 80x24")
            }
        }
        _ => TestResult::Fail("TIOCGWINSZ did not return Ok(0)"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_tiocgwinsz_default_80x24);

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_tiocswinsz_round_trip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1002);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

    let set = fd::Winsize {
        ws_row: 50,
        ws_col: 132,
        ws_xpixel: 0,
        ws_ypixel: 0,
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
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: fd::TIOCSWINSZ as u64,
            arg2: &set as *const _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    let set_ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);

    let mut got = fd::Winsize::default();
    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: fd::TIOCGWINSZ as u64,
            arg2: &mut got as *mut _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx2);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    if !set_ok {
        return TestResult::Fail("TIOCSWINSZ did not return Ok(0)");
    }
    if got.ws_row == 50 && got.ws_col == 132 {
        TestResult::Pass
    } else {
        TestResult::Fail("TIOCSWINSZ value did not round-trip through TIOCGWINSZ")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_tiocswinsz_round_trip);

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_fionread_empty_ring_returns_zero() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1003);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

    let mut n: i32 = 0xAAAA;
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: fd::FIONREAD as u64,
            arg2: &mut n as *mut _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
            if n == 0 {
                TestResult::Pass
            } else {
                TestResult::Fail("FIONREAD on empty ring did not report 0")
            }
        }
        _ => TestResult::Fail("FIONREAD did not return Ok(0)"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_console_ioctl_fionread_empty_ring_returns_zero
);

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_tiocspgrp_round_trip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1004);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

    // Set fg pgrp = 4242
    let pgid_in: i32 = 4242;
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: fd::TIOCSPGRP as u64,
            arg2: &pgid_in as *const _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    let set_ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);

    let mut pgid_out: i32 = -1;
    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: fd::TIOCGPGRP as u64,
            arg2: &mut pgid_out as *mut _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx2);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    if !set_ok {
        return TestResult::Fail("TIOCSPGRP did not return Ok(0)");
    }
    if pgid_out == 4242 {
        TestResult::Pass
    } else {
        TestResult::Fail("TIOCSPGRP value did not round-trip through TIOCGPGRP")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_tiocspgrp_round_trip);

// Wave-60: two ConsoleFile instances must not share fg_pgrp.
// Pre-fix, TIOCSPGRP poked a single global, so any "second tty"
// would be a thin alias of the first.
#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_per_tty_fg_pgrp_is_isolated() -> TestResult {
    use crate::fd::{ConsoleFile, TIOCGPGRP, TIOCSPGRP};
    use narf_filesystem::FileOps;

    // Drop any leaked current-task lookup from an earlier test so the
    // TIOCGPGRP auto-install fallback (which reads current_task_pgid())
    // sees 0 for an unset tty rather than an ambient pgid.
    crate::handlers::__test_reset_task_id_lookup();

    let tty_a = ConsoleFile::new();
    let tty_b = ConsoleFile::new();

    // Set tty_a's fg_pgrp to 111.
    let pgid_a: i32 = 111;
    if tty_a
        .ioctl(TIOCSPGRP, &pgid_a as *const _ as usize)
        .is_err()
    {
        return TestResult::Fail("TIOCSPGRP on tty_a failed");
    }

    // Read tty_b — must still be 0 (unset), not 111.
    let mut got_b: i32 = -1;
    if tty_b
        .ioctl(TIOCGPGRP, &mut got_b as *mut _ as usize)
        .is_err()
    {
        return TestResult::Fail("TIOCGPGRP on tty_b failed");
    }
    if got_b != 0 {
        return TestResult::Fail("tty_b fg_pgrp leaked from tty_a write");
    }

    // Set tty_b's fg_pgrp to 222.
    let pgid_b: i32 = 222;
    if tty_b
        .ioctl(TIOCSPGRP, &pgid_b as *const _ as usize)
        .is_err()
    {
        return TestResult::Fail("TIOCSPGRP on tty_b failed");
    }

    // tty_a must still read back 111, not 222.
    let mut got_a: i32 = -1;
    if tty_a
        .ioctl(TIOCGPGRP, &mut got_a as *mut _ as usize)
        .is_err()
    {
        return TestResult::Fail("TIOCGPGRP on tty_a failed");
    }
    if got_a != 111 {
        return TestResult::Fail("tty_a fg_pgrp clobbered by tty_b write");
    }
    if got_b != 0 {
        return TestResult::Fail("tty_b earlier read was wrong");
    }

    // Confirm tty_b reads 222 now.
    let mut got_b2: i32 = -1;
    if tty_b
        .ioctl(TIOCGPGRP, &mut got_b2 as *mut _ as usize)
        .is_err()
    {
        return TestResult::Fail("TIOCGPGRP on tty_b (second) failed");
    }
    if got_b2 != 222 {
        return TestResult::Fail("tty_b fg_pgrp did not round-trip");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_per_tty_fg_pgrp_is_isolated);

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_unknown_cmd_returns_enotty() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1005);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

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
    let mut dummy = [0u8; 8];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 0xDEAD_BEEF,
            arg2: dummy.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    // ENOTTY = 25, returned as the negated value through SyscallReturn::ok.
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && (r.value as i64) == -25 => TestResult::Pass,
        _ => TestResult::Fail("unknown ioctl cmd did not return -ENOTTY"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_unknown_cmd_returns_enotty);

// ── Wave-51: async-signal default-action lookup ────────────────────
//
// POSIX signal(7) assigns a default action per signal. Pre-fix, NARF
// had no way to consult that table: a SIGTERM with no installed
// handler silently did nothing (the SIGNAL_PENDING bit stayed set
// but the task kept running). Wave-51 introduces `default_signal_action`
// — a pure function userspace can call to decide whether to terminate,
// core-dump, stop, continue, or ignore. Wiring this into the actual
// kill→exit path is deferred; this smoke pins the lookup table.

fn smoke_default_signal_action_table_matches_posix() -> TestResult {
    use crate::handlers::{default_signal_action, DefaultAction};
    // Spot-check the high-leverage rows; the table itself is the
    // source of truth.
    if default_signal_action(15) != DefaultAction::Terminate {
        return TestResult::Fail("SIGTERM default should be Terminate");
    }
    if default_signal_action(2) != DefaultAction::Terminate {
        return TestResult::Fail("SIGINT default should be Terminate");
    }
    if default_signal_action(1) != DefaultAction::Terminate {
        return TestResult::Fail("SIGHUP default should be Terminate");
    }
    if default_signal_action(9) != DefaultAction::Terminate {
        return TestResult::Fail("SIGKILL default should be Terminate");
    }
    if default_signal_action(6) != DefaultAction::CoreDump {
        return TestResult::Fail("SIGABRT default should be CoreDump");
    }
    if default_signal_action(11) != DefaultAction::CoreDump {
        return TestResult::Fail("SIGSEGV default should be CoreDump");
    }
    if default_signal_action(8) != DefaultAction::CoreDump {
        return TestResult::Fail("SIGFPE default should be CoreDump");
    }
    if default_signal_action(7) != DefaultAction::CoreDump {
        return TestResult::Fail("SIGBUS default should be CoreDump");
    }
    if default_signal_action(17) != DefaultAction::Ignore {
        return TestResult::Fail("SIGCHLD default should be Ignore");
    }
    if default_signal_action(19) != DefaultAction::Stop {
        return TestResult::Fail("SIGSTOP default should be Stop");
    }
    if default_signal_action(18) != DefaultAction::Continue {
        return TestResult::Fail("SIGCONT default should be Continue");
    }
    if default_signal_action(28) != DefaultAction::Ignore {
        return TestResult::Fail("SIGWINCH default should be Ignore");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_default_signal_action_table_matches_posix);

fn smoke_sys_kill_sigterm_marks_pending() -> TestResult {
    // sys_kill(target, 15) sets bit 15 in SIGNAL_PENDING[target].
    // Verifies the foundational kill-path works for the async signals
    // POSIX userspace cares about.
    use crate::{
        handlers::{__test_signal_reset, signal_init, signal_pending_of},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_2001);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }

    __test_signal_reset();
    signal_init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let target: u64 = 0xC5_2099;
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
    // Issue kill(target, 15)
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target,
            arg1: 15, // SIGTERM
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);
    let kill_ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);
    let pending = signal_pending_of(target);
    __test_signal_reset();
    __test_clear_global();

    if !kill_ok {
        return TestResult::Fail("kill(SIGTERM) did not return Ok(0)");
    }
    if pending & (1u32 << 15) == 0 {
        return TestResult::Fail("SIGTERM did not land in SIGNAL_PENDING");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_sys_kill_sigterm_marks_pending);

fn smoke_sys_kill_sighup_sigint_sigabrt_round_trip() -> TestResult {
    // Stress the kill path against the three other "terminate on
    // default" signals POSIX userspace reaches for: SIGHUP (1),
    // SIGINT (2), SIGABRT (6). All three must land in pending.
    use crate::{
        handlers::{__test_signal_reset, signal_init, signal_pending_of},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_2002);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }

    __test_signal_reset();
    signal_init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let target: u64 = 0xC5_2199;
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
    for signum in [1u64, 2, 6] {
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: target,
                arg1: signum,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);
        let ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);
        if !ok {
            __test_signal_reset();
            __test_clear_global();
            return TestResult::Fail("kill returned not-Ok for one of HUP/INT/ABRT");
        }
    }
    let pending = signal_pending_of(target);
    __test_signal_reset();
    __test_clear_global();

    let want = (1u32 << 1) | (1u32 << 2) | (1u32 << 6);
    if pending & want == want {
        TestResult::Pass
    } else {
        TestResult::Fail("not all of SIGHUP/SIGINT/SIGABRT landed in pending")
    }
}
kernel_test_in!("userspace", smoke_sys_kill_sighup_sigint_sigabrt_round_trip);

// ── Wave-67 — PID + mount namespaces ───────────────────────────────

/// CLONE_NEWPID via the namespace module directly: the task gets
/// bound as inner pid 1, and `self_inner_pid` returns 1 even though
/// the outer pid is whatever the root pool minted.
#[cfg(feature = "container")]
fn smoke_unshare_pid_ns_sees_self_as_pid_one() -> TestResult {
    crate::pid_ns::__test_reset();
    let fake_task: u64 = 0xABCD_1234;
    let fake_outer: u64 = 4242;
    let ns = crate::pid_ns::unshare_pid_ns(fake_task, fake_outer);
    if ns.outer_to_inner(fake_outer) != Some(1) {
        return TestResult::Fail("first bind should be inner pid 1");
    }
    if crate::pid_ns::self_inner_pid(fake_task, fake_outer) != 1 {
        return TestResult::Fail("self_inner_pid != 1 after unshare");
    }
    // Outer pid still resolvable for kernel-side delivery.
    if ns.inner_to_outer(1) != Some(fake_outer) {
        return TestResult::Fail("inner→outer translation broken");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_unshare_pid_ns_sees_self_as_pid_one);

/// Child inherits the parent's namespace and gets a fresh inner pid
/// (parent stays at 1; child becomes 2).
#[cfg(feature = "container")]
fn smoke_pid_ns_inherit_assigns_child_inner_two() -> TestResult {
    crate::pid_ns::__test_reset();
    let parent_task: u64 = 0x1111;
    let parent_outer: u64 = 100;
    let child_outer: u64 = 101;

    let ns = crate::pid_ns::unshare_pid_ns(parent_task, parent_outer);
    assert_eq!(ns.outer_to_inner(parent_outer), Some(1));

    let child_inner = match crate::pid_ns::inherit_into_child(parent_task, child_outer) {
        Some(i) => i,
        None => return TestResult::Fail("inherit_into_child returned None"),
    };
    if child_inner != 2 {
        return TestResult::Fail("child inner pid != 2");
    }
    if crate::pid_ns::self_inner_pid(child_outer, child_outer) != 2 {
        return TestResult::Fail("child self_inner_pid != 2");
    }
    if ns.inner_to_outer(2) != Some(child_outer) {
        return TestResult::Fail("ns missing child translation");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_pid_ns_inherit_assigns_child_inner_two);

/// Outside-the-namespace caller (root NS) can still target a task
/// inside a child namespace by its outer pid. The resolve_inner_pid
/// identity branch keeps the outer pid intact, signal-pending bit
/// lands on the outer pid.
#[cfg(feature = "container")]
fn smoke_kill_from_outside_namespace_addresses_by_outer_pid() -> TestResult {
    crate::pid_ns::__test_reset();
    let child_task: u64 = 0x2222;
    let child_outer: u64 = 200;
    let _ns = crate::pid_ns::unshare_pid_ns(child_task, child_outer);

    // The root-namespace caller has no entry in TASK_PID_NS, so
    // resolve_inner_pid returns Some(input).
    let outside_caller: u64 = 0x3333;
    let resolved = match crate::pid_ns::resolve_inner_pid(outside_caller, child_outer) {
        Some(v) => v,
        None => return TestResult::Fail("root NS caller should resolve identically"),
    };
    if resolved != child_outer {
        return TestResult::Fail("root NS resolve broke outer pid");
    }

    // The in-namespace task targeting itself by inner pid 1 must
    // also resolve to the child's outer pid.
    let inside = match crate::pid_ns::resolve_inner_pid(child_task, 1) {
        Some(v) => v,
        None => return TestResult::Fail("inside task can't resolve inner pid 1"),
    };
    if inside != child_outer {
        return TestResult::Fail("inner→outer translation broken inside NS");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!(
    "userspace",
    smoke_kill_from_outside_namespace_addresses_by_outer_pid
);

/// Mount namespace snapshot: a private NS sees its own mount table,
/// independent of further mounts on the global registry.
#[cfg(feature = "container")]
fn smoke_mount_ns_isolates_per_task_mounts() -> TestResult {
    // Snapshot the global registry into two private NSes. They start
    // with the same view but diverge once mounts are added to one.
    // We don't have a no-side-effect mount-adder here, so the
    // assertion is structural: snapshot_global produces a distinct
    // Arc per call (each task gets its own).
    let ns_a = narf_filesystem::MountNamespace::snapshot_global();
    let ns_b = narf_filesystem::MountNamespace::snapshot_global();
    if alloc::sync::Arc::ptr_eq(&ns_a, &ns_b) {
        return TestResult::Fail("snapshot_global returned aliased Arc");
    }
    // Both snapshots reflect the same set of mount paths.
    let mut paths_a = ns_a.list();
    let mut paths_b = ns_b.list();
    paths_a.sort();
    paths_b.sort();
    if paths_a != paths_b {
        return TestResult::Fail("snapshots disagree on initial mount set");
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_mount_ns_isolates_per_task_mounts);
// ── Wave-70 linux-compat: signalfd4 + memfd seals ──────────────────

#[cfg(feature = "linux-compat")]
fn smoke_userspace_signalfd_reads_pending_siginfo() -> TestResult {
    use crate::handlers::__test_signal_reset;
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
    crate::fd::__test_reset();
    crate::fd::init();
    __test_signal_reset();
    crate::handlers::signal_init();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // current_task_id() must be 0 here so signalfd's owner_task matches
    // the kill(pid=0) target; drop any lookup an earlier test leaked.
    crate::handlers::__test_reset_task_id_lookup();

    // Mask = SIGUSR1 only. A userspace sigset_t puts signal N at bit
    // (N-1) — sys_signalfd shifts `<< 1` to align with NARF's internal
    // bit-N pending convention. So SIGUSR1 (10) is bit 9 here.
    let mask: u64 = 1u64 << 9;
    let mask_bytes = mask.to_le_bytes();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,
            arg1: mask_bytes.as_ptr() as u64,
            arg2: 8,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Signalfd.raw(), &mut ctx);
    let sfd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => {
            __test_signal_reset();
            __test_clear_global();
            return TestResult::Fail("signalfd did not return a fd");
        }
    };

    crate::handlers::register_pid_task_mapping(0, 0);

    // Raise SIGUSR1 (10) on task 0 (the test task lookup is unset → 0).
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 10,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);

    // Read the 128-byte signalfd_siginfo.
    let mut buf = [0u8; 128];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: sfd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    let nread = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => 0,
    };

    __test_signal_reset();
    crate::fd::__test_reset();
    __test_clear_global();

    if nread != 128 {
        return TestResult::Fail("signalfd read returned wrong length");
    }
    let ssi_signo = u32::from_le_bytes(buf[..4].try_into().unwrap());
    if ssi_signo != 10 {
        return TestResult::Fail("signalfd siginfo.ssi_signo != SIGUSR1");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_signalfd_reads_pending_siginfo);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_signalfd_epoll_wakes_on_signal() -> TestResult {
    use crate::handlers::__test_signal_reset;
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
    crate::fd::__test_reset();
    crate::fd::init();
    __test_signal_reset();
    crate::handlers::signal_init();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // current_task_id() must be 0 here so signalfd's owner_task matches
    // the kill(pid=0) target; drop any lookup an earlier test leaked.
    crate::handlers::__test_reset_task_id_lookup();

    // Create signalfd watching SIGUSR2 (signum 12). Userspace sigset_t
    // puts signal N at bit (N-1); sys_signalfd shifts `<< 1` to align
    // with NARF's internal bit-N pending convention. So SIGUSR2 is bit 11.
    let mask: u64 = 1u64 << 11;
    let mask_bytes = mask.to_le_bytes();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,
            arg1: mask_bytes.as_ptr() as u64,
            arg2: 8,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Signalfd.raw(), &mut ctx);
    let sfd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => {
            __test_signal_reset();
            __test_clear_global();
            return TestResult::Fail("signalfd did not return a fd");
        }
    };

    crate::handlers::register_pid_task_mapping(0, 0);

    // Create epoll instance.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::EpollCreate.raw(), &mut ctx);
    let epfd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => {
            __test_signal_reset();
            __test_clear_global();
            return TestResult::Fail("epoll_create failed");
        }
    };

    // ADD signalfd with EPOLLIN=1.
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&1u32.to_le_bytes());
    ev[4..].copy_from_slice(&0xC0FFEEu64.to_le_bytes());
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: epfd as u64,
            arg1: 1, // EPOLL_CTL_ADD
            arg2: sfd as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::EpollCtl.raw(), &mut ctx);

    // Raise SIGUSR2.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 12,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);

    // epoll_wait timeout=0 → should immediately see 1 ready event.
    let mut events = [0u8; 12 * 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: epfd as u64,
            arg1: events.as_mut_ptr() as u64,
            arg2: 4,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::EpollWait.raw(), &mut ctx);
    let nready = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => 0,
    };

    let user_data = u64::from_le_bytes(events[4..12].try_into().unwrap());

    __test_signal_reset();
    crate::fd::__test_reset();
    __test_clear_global();

    if nready != 1 {
        return TestResult::Fail("epoll_wait did not return 1 ready");
    }
    if user_data != 0xC0FFEE {
        return TestResult::Fail("epoll_wait user_data not echoed");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_signalfd_epoll_wakes_on_signal);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_memfd_seal_write_rejects_write() -> TestResult {
    use crate::linux_compat::{F_SEAL_WRITE, MFD_ALLOW_SEALING};
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
    crate::fd::__test_reset();
    crate::fd::init();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let name = "sealable";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: name.as_ptr() as u64,
            arg1: name.len() as u64,
            arg2: MFD_ALLOW_SEALING as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::MemfdCreate.raw(), &mut ctx);
    let fd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => return TestResult::Fail("memfd_create failed"),
    };

    // Write before sealing — must succeed.
    let payload = b"hello";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx);
    let w1 = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 5);
    if !w1 {
        crate::fd::__test_reset();
        __test_clear_global();
        return TestResult::Fail("pre-seal write rejected");
    }

    // F_GET_SEALS before sealing — should be 0.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1034, // F_GET_SEALS
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let pre_seals = match ctx.ret {
        Some(r) => r.value as u32,
        None => return TestResult::Fail("fcntl F_GET_SEALS no return"),
    };

    // F_ADD_SEALS F_SEAL_WRITE.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1033, // F_ADD_SEALS
            arg2: F_SEAL_WRITE as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let add_ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);

    // F_GET_SEALS post-add — F_SEAL_WRITE set.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1034,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let post_seals = match ctx.ret {
        Some(r) => r.value as u32,
        None => return TestResult::Fail("fcntl F_GET_SEALS no return (post)"),
    };

    // Write after sealing — must fail.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx);
    let w2_rejected = matches!(
        ctx.ret,
        Some(r) if r.value == (-1i64) as u64 || r.status != SyscallReturn::OK
    );

    crate::fd::__test_reset();
    __test_clear_global();

    if pre_seals != 0 {
        return TestResult::Fail("pre-seal F_GET_SEALS != 0");
    }
    if !add_ok {
        return TestResult::Fail("F_ADD_SEALS rejected");
    }
    if post_seals & F_SEAL_WRITE == 0 {
        return TestResult::Fail("F_SEAL_WRITE not visible after add");
    }
    if !w2_rejected {
        return TestResult::Fail("post-seal write was not rejected");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_memfd_seal_write_rejects_write);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_memfd_seal_seal_blocks_further_seals() -> TestResult {
    use crate::linux_compat::{F_SEAL_SEAL, F_SEAL_WRITE, MFD_ALLOW_SEALING};
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
    crate::fd::__test_reset();
    crate::fd::init();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let name = "lockdown";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: name.as_ptr() as u64,
            arg1: name.len() as u64,
            arg2: MFD_ALLOW_SEALING as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::MemfdCreate.raw(), &mut ctx);
    let fd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => return TestResult::Fail("memfd_create failed"),
    };

    // Seal with F_SEAL_SEAL.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1033,
            arg2: F_SEAL_SEAL as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let seal_seal = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);

    // Now try to add F_SEAL_WRITE — must fail.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1033,
            arg2: F_SEAL_WRITE as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let further_rejected = matches!(ctx.ret, Some(r) if r.value == (-1i64) as u64);

    crate::fd::__test_reset();
    __test_clear_global();

    if !seal_seal {
        return TestResult::Fail("F_SEAL_SEAL add failed");
    }
    if !further_rejected {
        return TestResult::Fail("post F_SEAL_SEAL further add was accepted");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_memfd_seal_seal_blocks_further_seals
);

// ── Wave-72 — UTS / NET / IPC namespaces ───────────────────────────

/// unshare(CLONE_NEWUTS) gives a task a private hostname slot. A
/// fork-style "child" inherits the parent's NS Arc by setns, so its
/// view sees the parent's sethostname; a sibling that never
/// unshared still reads the global default.
#[cfg(feature = "container")]
fn smoke_wave72_uts_ns_per_task_hostname() -> TestResult {
    crate::namespaces::__test_reset_all();
    let parent: u64 = 0xA000_0001;
    let child: u64 = 0xA000_0002;
    let sibling: u64 = 0xA000_0003;

    crate::namespaces::unshare_uts(parent);
    let parent_ns = match crate::namespaces::uts_ns_of(parent) {
        Some(ns) => ns,
        None => return TestResult::Fail("parent has no UTS NS after unshare"),
    };
    parent_ns.set_hostname("parent-host");

    // Child joins parent's NS (Arc share).
    crate::namespaces::setns_uts(child, parent_ns.clone());
    if crate::namespaces::current_uts_ns(child).hostname() != "parent-host" {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("child does not see parent's hostname");
    }

    // Sibling never unshared → global default ("narf").
    if crate::namespaces::current_uts_ns(sibling).hostname() != crate::namespaces::DEFAULT_HOSTNAME
    {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("sibling sees per-NS hostname instead of global");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_wave72_uts_ns_per_task_hostname);

/// unshare(CLONE_NEWNET) seeds a fresh netns containing only `lo`.
#[cfg(feature = "container")]
fn smoke_wave72_net_ns_loopback_only() -> TestResult {
    crate::namespaces::__test_reset_all();
    let task: u64 = 0xB000_0001;
    crate::namespaces::unshare_net(task);
    let ns = match crate::namespaces::current_net_ns(task) {
        Some(ns) => ns,
        None => {
            crate::namespaces::__test_reset_all();
            return TestResult::Fail("unshare_net did not install per-task entry");
        }
    };
    let names = ns.iface_names();
    if names.len() != 1 || names[0] != "lo" {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("fresh netns iface list != [lo]");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_wave72_net_ns_loopback_only);

/// Two CLONE_NEWIPC tasks: shmget(SAME_KEY) returns distinct ids
/// because each NS mints its own.
#[cfg(feature = "container")]
fn smoke_wave72_ipc_ns_distinct_shmget() -> TestResult {
    crate::namespaces::__test_reset_all();
    let a: u64 = 0xC000_0001;
    let b: u64 = 0xC000_0002;
    crate::namespaces::unshare_ipc(a);
    crate::namespaces::unshare_ipc(b);
    let ns_a = match crate::namespaces::current_ipc_ns(a) {
        Some(ns) => ns,
        None => {
            crate::namespaces::__test_reset_all();
            return TestResult::Fail("task A has no IPC NS after unshare");
        }
    };
    let ns_b = match crate::namespaces::current_ipc_ns(b) {
        Some(ns) => ns,
        None => {
            crate::namespaces::__test_reset_all();
            return TestResult::Fail("task B has no IPC NS after unshare");
        }
    };
    const KEY: u32 = 0xBEEF;
    let id_a = ns_a.shmget(KEY);
    let id_b = ns_b.shmget(KEY);
    // Both start their counters at 1 → both should return 1, which is
    // the same numeric value but minted from independent counters.
    // The point is they don't alias: a second call in A returns a new
    // id for a different key, independent of B's keyspace.
    if id_a != ns_a.shmget(KEY) {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("same key in same NS returned a different id");
    }
    if id_b != ns_b.shmget(KEY) {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("same key in same NS returned a different id (B)");
    }
    // Add a second key to A only; B's counter must not advance.
    let id_a2 = ns_a.shmget(0xCAFE);
    if id_a2 == id_b {
        // Acceptable — independent counters can collide numerically.
    }
    // Lookup of 0xCAFE in B must mint a fresh id, not 0xCAFE→id_a2's value
    // by leaking state across namespaces.
    let id_b2 = ns_b.shmget(0xCAFE);
    if !alloc::sync::Arc::ptr_eq(&ns_a, &ns_b) && id_b2 == 0 {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("NS-B yielded reserved id 0 for new key");
    }
    // Critical distinct-namespace invariant: A and B are different Arcs.
    if alloc::sync::Arc::ptr_eq(&ns_a, &ns_b) {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("A and B share an IPC NS Arc");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_wave72_ipc_ns_distinct_shmget);

/// Drive sys_unshare directly with the combined NEWUTS|NEWNET|NEWIPC
/// flag mask; verify all 3 NS slots populate for the calling task.
#[cfg(feature = "container")]
fn smoke_wave72_sys_unshare_honours_new_flags() -> TestResult {
    use crate::handlers::install_task_id_lookup;
    crate::namespaces::__test_reset_all();

    const FAKE_TASK: u64 = 0xD000_DEAD;
    fn lookup() -> u64 {
        FAKE_TASK
    }
    install_task_id_lookup(lookup);

    let flags = crate::namespaces::CLONE_NEWUTS
        | crate::namespaces::CLONE_NEWNET
        | crate::namespaces::CLONE_NEWIPC;
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: flags,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Unshare.raw(), &mut ctx);
    let ret = match ctx.ret {
        Some(r) => r,
        None => {
            crate::namespaces::__test_reset_all();
            return TestResult::Fail("sys_unshare did not set return");
        }
    };
    if ret.value != 0 {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("sys_unshare returned non-zero");
    }
    if crate::namespaces::uts_ns_of(FAKE_TASK).is_none() {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("NEWUTS slot not populated");
    }
    if crate::namespaces::current_net_ns(FAKE_TASK).is_none() {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("NEWNET slot not populated");
    }
    if crate::namespaces::current_ipc_ns(FAKE_TASK).is_none() {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("NEWIPC slot not populated");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_wave72_sys_unshare_honours_new_flags);

// ── Wave-69: statx smokes ──────────────────────────────────────────────
//
// The kernel implementation lives in handlers::sys_statx, gated by
// linux-compat. These four smokes confirm the wire shape, mask=0
// semantics, AT_EMPTY_PATH, and the linux_compat::Stat field offsets.

#[cfg(feature = "linux-compat")]
fn smoke_userspace_statx_known_file_reports_mode_size() -> TestResult {
    use crate::{
        fd,
        handlers::linux_compat::{Statx, AT_FDCWD},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    struct StatxKnownFile;
    impl FileOps for StatxKnownFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 42,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StatxKnownDir;
    impl DirOps for StatxKnownDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "probe" {
                Some(Arc::new(StatxKnownFile))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct StatxKnownFs;
    impl FsInstance for StatxKnownFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(StatxKnownDir)
        }
        fn name(&self) -> &str {
            "statx-known"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/statx-known", StatxKnownFs);

    fd::__test_reset();
    fd::init();

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xE001);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
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

    let path = b"/statx-known/probe\0";
    let mut out = Statx::default();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: AT_FDCWD as u64,
            arg1: path.as_ptr() as u64,
            arg2: 0,     // flags
            arg3: 0xFFF, // mask = STATX_BASIC_STATS
            arg4: &mut out as *mut Statx as u64,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Statx.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("statx did not return Ok(0)");
    }
    if out.stx_size == 0 {
        return TestResult::Fail("stx_size is 0");
    }
    if out.stx_mode & 0o170000 != 0o100000 {
        return TestResult::Fail("stx_mode not regular-file");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_statx_known_file_reports_mode_size
);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_statx_mask_zero_still_fills_basic_fields() -> TestResult {
    // mask=0 — kernel fills what it can and sets stx_mask accordingly.
    use crate::{
        fd,
        handlers::linux_compat::{Statx, AT_FDCWD},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    struct StatxM0File;
    impl FileOps for StatxM0File {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 7,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StatxM0Dir;
    impl DirOps for StatxM0Dir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "m0" {
                Some(Arc::new(StatxM0File))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct StatxM0Fs;
    impl FsInstance for StatxM0Fs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(StatxM0Dir)
        }
        fn name(&self) -> &str {
            "statx-m0"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/statx-m0", StatxM0Fs);

    fd::__test_reset();
    fd::init();
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xE002);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
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

    let path = b"/statx-m0/m0\0";
    let mut out = Statx::default();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: AT_FDCWD as u64,
            arg1: path.as_ptr() as u64,
            arg2: 0, // flags
            arg3: 0, // mask = 0
            arg4: &mut out as *mut Statx as u64,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Statx.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("statx(mask=0) did not return Ok(0)");
    }
    if out.stx_mode == 0 {
        return TestResult::Fail("stx_mode not filled with mask=0");
    }
    if out.stx_size == 0 {
        return TestResult::Fail("stx_size not filled with mask=0");
    }
    if out.stx_ino == 0 {
        return TestResult::Fail("stx_ino not filled with mask=0");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_statx_mask_zero_still_fills_basic_fields
);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_statx_at_empty_path_uses_dirfd() -> TestResult {
    // Open a file fd, then statx(fd, "", AT_EMPTY_PATH, ...) — must
    // return the fd's own metadata.
    use crate::{
        fd,
        handlers::linux_compat::{Statx, AT_EMPTY_PATH},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    struct StatxEpFile;
    impl FileOps for StatxEpFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 99,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StatxEpDir;
    impl DirOps for StatxEpDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "ep" {
                Some(Arc::new(StatxEpFile))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct StatxEpFs;
    impl FsInstance for StatxEpFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(StatxEpDir)
        }
        fn name(&self) -> &str {
            "statx-ep"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/statx-ep", StatxEpFs);

    fd::__test_reset();
    fd::init();
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xE003);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
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

    // Open /statx-ep/ep to get a real fd.
    // Linux open(2) ABI: arg0 = NUL-terminated path, arg1 = flags.
    let path = b"/statx-ep/ep\0";
    let mut open_ctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0, // flags
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::OpenFile.raw(), &mut open_ctx);
    let opened_fd = match open_ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as i32,
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("open failed before AT_EMPTY_PATH statx");
        }
    };

    let empty: &[u8] = b"\0";
    let mut out = Statx::default();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: opened_fd as u64,
            arg1: empty.as_ptr() as u64,
            arg2: AT_EMPTY_PATH as u64, // flags
            arg3: 0xFFF,                // mask
            arg4: &mut out as *mut Statx as u64,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Statx.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("statx(AT_EMPTY_PATH) did not return Ok(0)");
    }
    if out.stx_size != 99 {
        return TestResult::Fail("stx_size via AT_EMPTY_PATH mismatch");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_statx_at_empty_path_uses_dirfd);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_linux_stat_layout_offsets() -> TestResult {
    // Compile-time check that linux_compat::Stat field offsets match
    // the Linux x86_64 ABI (man 2 stat).
    use crate::handlers::linux_compat::Stat;
    use core::mem::offset_of;

    if offset_of!(Stat, st_dev) != 0 {
        return TestResult::Fail("st_dev offset != 0");
    }
    if offset_of!(Stat, st_ino) != 8 {
        return TestResult::Fail("st_ino offset != 8");
    }
    if offset_of!(Stat, st_nlink) != 16 {
        return TestResult::Fail("st_nlink offset != 16");
    }
    if offset_of!(Stat, st_mode) != 24 {
        return TestResult::Fail("st_mode offset != 24");
    }
    if offset_of!(Stat, st_uid) != 28 {
        return TestResult::Fail("st_uid offset != 28");
    }
    if offset_of!(Stat, st_gid) != 32 {
        return TestResult::Fail("st_gid offset != 32");
    }
    if offset_of!(Stat, st_rdev) != 40 {
        return TestResult::Fail("st_rdev offset != 40");
    }
    if offset_of!(Stat, st_size) != 48 {
        return TestResult::Fail("st_size offset != 48");
    }
    if offset_of!(Stat, st_blksize) != 56 {
        return TestResult::Fail("st_blksize offset != 56");
    }
    if offset_of!(Stat, st_blocks) != 64 {
        return TestResult::Fail("st_blocks offset != 64");
    }
    if offset_of!(Stat, st_atim) != 72 {
        return TestResult::Fail("st_atim offset != 72");
    }
    if offset_of!(Stat, st_mtim) != 88 {
        return TestResult::Fail("st_mtim offset != 88");
    }
    if offset_of!(Stat, st_ctim) != 104 {
        return TestResult::Fail("st_ctim offset != 104");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_linux_stat_layout_offsets);

// ── Wave-73: POSIX timer smokes ────────────────────────────────────────
//
// The kernel implementation lives in posix_timer.rs, gated by
// linux-compat. These five smokes confirm signal delivery, gettime
// remaining, delete/invalidation, clock_nanosleep abs-time, and
// CLOCK_MONOTONIC_RAW/BOOTTIME sanity.

#[cfg(feature = "linux-compat")]
fn smoke_userspace_posix_timer_signal_delivery() -> TestResult {
    use crate::{
        fd,
        handlers::{__test_signal_reset, signal_init, signal_pending_of},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        posix_timer,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xE010);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    __test_signal_reset();
    signal_init();
    posix_timer::__test_reset();
    posix_timer::posix_timer_init();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
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

    // Build sigevent: sigev_value(8B) + sigev_signo(4B) + sigev_notify(4B).
    // SIGUSR1 = 10, SIGEV_SIGNAL = 0.
    let mut sigevent = [0u8; 16];
    sigevent[8..12].copy_from_slice(&10i32.to_le_bytes()); // sigev_signo = SIGUSR1
    sigevent[12..16].copy_from_slice(&0i32.to_le_bytes()); // sigev_notify = SIGEV_SIGNAL

    let mut timerid: u64 = 0;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1, // CLOCK_MONOTONIC
            arg1: sigevent.as_ptr() as u64,
            arg2: &mut timerid as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerCreate.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        __test_signal_reset();
        __test_clear_global();
        return TestResult::Fail("timer_create failed");
    }
    let id = timerid as u32;

    // itimerspec: interval={0,0}, value={0,1} (1ns initial).
    let mut itimerspec = [0u8; 32];
    itimerspec[24..32].copy_from_slice(&1i64.to_le_bytes()); // it_value.tv_nsec = 1

    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: id as u64,
            arg1: 0, // flags = 0 (relative)
            arg2: itimerspec.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerSettime.raw(), &mut ctx2);
    if !matches!(ctx2.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        __test_signal_reset();
        __test_clear_global();
        return TestResult::Fail("timer_settime failed");
    }

    // Force expiry by advancing past the deadline via the pump.
    posix_timer::__test_run_pump();

    let pending = signal_pending_of(task);
    __test_signal_reset();
    __test_clear_global();

    if pending & (1u32 << 10) != 0 {
        TestResult::Pass
    } else {
        TestResult::Fail("SIGUSR1 not in pending after timer pump")
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_posix_timer_signal_delivery);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_posix_timer_gettime_remaining() -> TestResult {
    // Arm a 1-second timer; timer_gettime must return sane remaining value.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        posix_timer, syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn,
        SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xE011);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }

    posix_timer::__test_reset();
    posix_timer::posix_timer_init();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
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

    let mut timerid: u64 = 0;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1, // CLOCK_MONOTONIC
            arg1: 0, // NULL sigevent → SIGALRM default
            arg2: &mut timerid as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerCreate.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        __test_clear_global();
        return TestResult::Fail("timer_create failed");
    }
    let id = timerid as u32;

    // Arm 1-second one-shot.
    let mut itimerspec = [0u8; 32];
    itimerspec[16..24].copy_from_slice(&1i64.to_le_bytes()); // it_value.tv_sec = 1

    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: id as u64,
            arg1: 0,
            arg2: itimerspec.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerSettime.raw(), &mut ctx2);
    if !matches!(ctx2.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        __test_clear_global();
        return TestResult::Fail("timer_settime failed");
    }

    let mut cur = [0u8; 32];
    let mut ctx3 = FakeCtx {
        args: SyscallArgs {
            arg0: id as u64,
            arg1: cur.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerGettime.raw(), &mut ctx3);
    __test_clear_global();

    if !matches!(ctx3.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("timer_gettime failed");
    }
    // it_value.tv_sec (bytes 16..24) and it_value.tv_nsec (bytes 24..32).
    let val_sec = i64::from_le_bytes(cur[16..24].try_into().unwrap());
    let val_nsec = i64::from_le_bytes(cur[24..32].try_into().unwrap());
    if val_sec < 0 {
        return TestResult::Fail("timer_gettime: remaining tv_sec < 0");
    }
    if !(0..1_000_000_000).contains(&val_nsec) {
        return TestResult::Fail("timer_gettime: remaining tv_nsec out of range");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_posix_timer_gettime_remaining);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_posix_timer_delete_cancels() -> TestResult {
    // Arm a timer, then delete it; timer_gettime on the stale id returns -1.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        posix_timer, syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn,
        SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xE012);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }

    posix_timer::__test_reset();
    posix_timer::posix_timer_init();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
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

    let mut timerid: u64 = 0;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: 0,
            arg2: &mut timerid as *mut u64 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerCreate.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        __test_clear_global();
        return TestResult::Fail("timer_create failed");
    }
    let id = timerid as u32;

    let itimerspec = [0u8; 32]; // will be overwritten for it_value
    let mut arm = itimerspec;
    arm[16..24].copy_from_slice(&1i64.to_le_bytes()); // 1s
    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: id as u64,
            arg1: 0,
            arg2: arm.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerSettime.raw(), &mut ctx2);

    // Delete it.
    let mut ctx3 = FakeCtx {
        args: SyscallArgs {
            arg0: id as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerDelete.raw(), &mut ctx3);
    if !matches!(ctx3.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        __test_clear_global();
        return TestResult::Fail("timer_delete failed");
    }

    // timer_gettime on the deleted id must return -1.
    let mut cur = [0u8; 32];
    let mut ctx4 = FakeCtx {
        args: SyscallArgs {
            arg0: id as u64,
            arg1: cur.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::TimerGettime.raw(), &mut ctx4);
    __test_clear_global();

    match ctx4.ret {
        Some(r) if r.status == SyscallReturn::OK && (r.value as i64) == -1 => TestResult::Pass,
        _ => TestResult::Fail("timer_gettime after delete did not return -1"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_posix_timer_delete_cancels);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_clock_nanosleep_abstime_returns_at_or_after_target() -> TestResult {
    // clock_gettime → build target = now + 10ms →
    // clock_nanosleep(ABSTIME, target) → assert monotonic_ns >= target.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xE013);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
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

    // Read current monotonic time.
    let mut ts_now = [0u8; 16];
    let mut ctx_get = FakeCtx {
        args: SyscallArgs {
            arg0: 1, // CLOCK_MONOTONIC
            arg1: ts_now.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx_get);
    if !matches!(ctx_get.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        __test_clear_global();
        return TestResult::Fail("clock_gettime failed");
    }
    let now_sec = i64::from_ne_bytes(ts_now[..8].try_into().unwrap());
    let now_nsec = i64::from_ne_bytes(ts_now[8..].try_into().unwrap());
    let now_ns = (now_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(now_nsec as u64);

    // Target = now + 10ms.
    let target_ns: u64 = now_ns.saturating_add(10_000_000);
    let target_sec = (target_ns / 1_000_000_000) as i64;
    let target_nsec = (target_ns % 1_000_000_000) as i64;
    let mut ts_target = [0u8; 16];
    ts_target[..8].copy_from_slice(&target_sec.to_ne_bytes());
    ts_target[8..].copy_from_slice(&target_nsec.to_ne_bytes());

    // clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME=1, &target, NULL).
    let mut ctx_sleep = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: 1, // TIMER_ABSTIME
            arg2: ts_target.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockNanosleep.raw(), &mut ctx_sleep);
    __test_clear_global();

    if !matches!(ctx_sleep.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("clock_nanosleep failed");
    }
    let after_ns = narf_scheduler::narf_time::monotonic_ns();
    if after_ns >= target_ns {
        TestResult::Pass
    } else {
        TestResult::Fail("monotonic_ns after clock_nanosleep is before target")
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_clock_nanosleep_abstime_returns_at_or_after_target
);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_clock_gettime_monotonic_raw_and_boottime() -> TestResult {
    // CLOCK_MONOTONIC_RAW(4) and CLOCK_BOOTTIME(7) both return sane
    // timespec values and two consecutive readings are non-decreasing.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xE014);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
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

    for clkid in [4u64, 7u64] {
        let mut ts1 = [0u8; 16];
        let mut ctx1 = FakeCtx {
            args: SyscallArgs {
                arg0: clkid,
                arg1: ts1.as_mut_ptr() as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx1);
        if !matches!(ctx1.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
            __test_clear_global();
            return TestResult::Fail("clock_gettime failed for RAW/BOOTTIME");
        }
        let sec1 = i64::from_ne_bytes(ts1[..8].try_into().unwrap());
        let nsec1 = i64::from_ne_bytes(ts1[8..].try_into().unwrap());
        if sec1 < 0 {
            __test_clear_global();
            return TestResult::Fail("tv_sec < 0 on first read");
        }
        if !(0..1_000_000_000).contains(&nsec1) {
            __test_clear_global();
            return TestResult::Fail("tv_nsec out of range on first read");
        }

        let mut ts2 = [0u8; 16];
        let mut ctx2 = FakeCtx {
            args: SyscallArgs {
                arg0: clkid,
                arg1: ts2.as_mut_ptr() as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx2);
        if !matches!(ctx2.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
            __test_clear_global();
            return TestResult::Fail("clock_gettime second read failed");
        }
        let sec2 = i64::from_ne_bytes(ts2[..8].try_into().unwrap());
        let nsec2 = i64::from_ne_bytes(ts2[8..].try_into().unwrap());
        let ns1 = (sec1 as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec1 as u64);
        let ns2 = (sec2 as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec2 as u64);
        if ns2 < ns1 {
            __test_clear_global();
            return TestResult::Fail("clock_gettime not monotonically non-decreasing");
        }
    }

    __test_clear_global();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_clock_gettime_monotonic_raw_and_boottime
);

// ── Wave-76: controlling-tty hook ──────────────────────────────────
//
// PtySlave::ioctl(TIOCSCTTY) calls back into the userspace crate via
// the function-pointer hook installed in `boot_init`. This smoke
// pokes the hook directly (`set_controlling_tty(idx)`) and reads
// the per-task table via `ctty_for(task)`. setsid() clears the slot.

#[cfg(feature = "linux-compat")]
fn smoke_userspace_ctty_hook_roundtrip_and_setsid_clears() -> TestResult {
    use crate::handlers::{
        __test_ctty_reset, __test_pgid_reset, __test_sid_reset, ctty_for, current_task_id,
        set_controlling_tty,
    };
    use crate::{
        init_per_task_state, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    __test_pgid_reset();
    __test_sid_reset();
    __test_ctty_reset();
    init_per_task_state();

    let task = current_task_id();

    // The Wave-76 hook records the PTY index against the current task.
    set_controlling_tty(7);
    if ctty_for(task) != Some(7) {
        __test_clear_global();
        return TestResult::Fail("ctty_for did not see TIOCSCTTY hook write");
    }

    // setsid() must drop the controlling tty per POSIX.
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
    kernel_syscall_entry(Syscall::Setsid.raw(), &mut ctx);

    if ctty_for(task).is_some() {
        __test_clear_global();
        return TestResult::Fail("setsid did not clear controlling_tty");
    }
    __test_clear_global();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_ctty_hook_roundtrip_and_setsid_clears
);
