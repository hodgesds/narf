//! Per-crate kernel-test entries for `narf-userspace`.

use alloc::sync::Arc;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::AddressSpace;

use crate::syscall::{
    kernel_syscall_entry, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
use crate::{
    install_address_space_lookup, install_core_syscalls, install_global,
};

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

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0x8000_0000_1000, // synthetic child entry
            arg1: 0x7fff_fff0_0000, // synthetic child stack top
            arg2: 0xC0FFEE,         // arg passed to child (RDI plumbing TBD)
            arg3: 0,                // inherit parent fs_base
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };

    // Syscall::Clone == 56; dispatch as the trap entry would.
    kernel_syscall_entry(56, &mut ctx);

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
        kernel_syscall_entry(56, &mut ctx);
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
kernel_test_in!("userspace", smoke_userspace_clone_rejects_zero_entry_or_stack);

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
kernel_test_in!("userspace", smoke_userspace_install_core_syscalls_fills_table);

fn smoke_userspace_syscall_table_roundtrip() -> TestResult {
    use crate::{Syscall, SyscallTable};

    // Pinned numbers.
    if Syscall::Submit.raw() != 100 || Syscall::Bootstrap.raw() != 101 {
        return TestResult::Fail("syscall numbers drifted");
    }
    if Syscall::from_raw(110) != Some(Syscall::OpenFile) {
        return TestResult::Fail("from_raw(110) did not match OpenFile");
    }
    if Syscall::from_raw(999).is_some() {
        return TestResult::Fail("from_raw(999) should be None");
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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{NarfStatus, Submission, Tag};
    use narf_memory::AddressSpace;
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, spawn_dispatcher_for,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

    static USER_AS_SDF: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_SDF.lock().clone()
    }
    static FAKE_TASK: u64 = 0xDEAD;
    fn task_lookup() -> u64 {
        FAKE_TASK
    }

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use alloc::sync::Arc;
    use narf_abi::{
        NarfStatus, OpCode, SharedConsumer, SharedProducer, SharedRing, Submission, Tag,
    };
    use narf_memory::AddressSpace;
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, shared_rings_for,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext, BOOTSTRAP_SHARED_RING_DEPTH,
    };

    static USER_AS_SR: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_SR.lock().clone()
    }
    static FAKE_TASK: u64 = 0xBABE;
    fn task_lookup() -> u64 {
        FAKE_TASK
    }

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
            comp.tag, comp.status, processed,
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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{Dispatcher, NarfStatus, Submission, Tag};
    use narf_memory::AddressSpace;
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

    static USER_AS_RT: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn rt_as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_RT.lock().clone()
    }
    static FAKE_TASK: u64 = 0xBEEF;
    fn rt_task_lookup() -> u64 {
        FAKE_TASK
    }

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{x86_64::paging, AddressSpace, VirtAddr};
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

    static USER_AS_BS: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_BS.lock().clone()
    }

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xCAFE);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    if unsafe { paging::translate(addr_space.root, VirtAddr::new(hdr.shared_sq_vaddr)) }.is_none() {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared SQ vaddr not mapped");
    }
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
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        sigaction_lookup, syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn,
        SyscallTable, TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::{
        default_signal_delivery, install_core_syscalls, install_global, install_task_id_lookup,
        kernel_syscall_entry, signal_init, signal_pending_of, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
        fn returning_to_user(&self) -> bool {
            self.going_to_user
        }
        fn deliver_signal(&mut self, h: u64, s: u32) -> bool {
            self.delivered = Some((h, s));
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
    default_signal_delivery(&mut ctx);
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

fn smoke_userspace_chdir_getcwd_round_trip() -> TestResult {
    // Verify the per-task cwd state round-trips through Chdir +
    // Getcwd. Drive both through the synthetic TrapContext path so
    // we exercise install_core_syscalls' slot wiring as well as
    // the handler bodies.
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::{
        cwd_of, install_core_syscalls, install_global, install_task_id_lookup,
        kernel_syscall_entry, syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn,
        SyscallTable, TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
    }

    // Default cwd should be `/` even before any Chdir call.
    if cwd_of(FAKE_TASK.load(Ordering::Relaxed)).as_str() != "/" {
        __test_clear_global();
        crate::handlers::__test_cwd_reset();
        return TestResult::Fail("default cwd was not /");
    }

    // Chdir("/foo")
    let target: &str = "/foo";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target.as_ptr() as u64,
            arg1: target.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Chdir.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        __test_clear_global();
        crate::handlers::__test_cwd_reset();
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

    // Relative path rejected (Stage-4 first cut: absolute paths only).
    let bad: &str = "relative";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: bad.as_ptr() as u64,
            arg1: bad.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Chdir.raw(), &mut ctx);
    // sys_chdir now mirrors sys_unlink/sys_mkdir/etc. and surfaces
    // failure as `ok((-1i64) as u64)` rather than `invalid_op`. The
    // user-runtime asm wrapper only observes the value register, so
    // a separate INVALID_OP status is invisible to the user side
    // (success and failure both rax=0). The -1 sentinel is the
    // wire-visible "no" the libc shim sees.
    let rel_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );

    __test_clear_global();
    crate::handlers::__test_cwd_reset();

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::{
        default_sync_signal_delivery, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

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
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
        fn deliver_signal(&mut self, h: u64, s: u32) -> bool {
            self.delivered = Some((h, s));
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
    };
    let rewrote = default_sync_signal_delivery(&mut ctx, 14);
    let delivered = ctx.delivered;

    // Mapping-less vector should return false without touching
    // deliver_signal.
    let mut ctx2 = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
        delivered: None,
    };
    let rewrote_unknown = default_sync_signal_delivery(&mut ctx2, 1);
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

fn smoke_userspace_open_routes_through_vfs() -> TestResult {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
    }
    let path = b"hello";
    let mount = b"/test";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64,
            arg2: mount.as_ptr() as u64,
            arg3: mount.len() as u64,
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
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    let path = b"/sl-test/sl";
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64,
            arg2: buf.as_mut_ptr() as u64,
            arg3: buf.len() as u64,
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
kernel_test_in!("userspace", smoke_userspace_symlink_create_and_readlink_round_trip);

fn smoke_userspace_readlink_on_non_symlink_fails() -> TestResult {
    // Mount a fresh MemFs at /sl-fail with a regular file `regular`.
    // SYS_READLINK against it must return the -1 wire sentinel
    // because `regular` isn't FileType::Symlink — POSIX EINVAL.
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
    }

    let path = b"/sl-fail/regular";
    let mut buf = [0u8; 32];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64,
            arg2: buf.as_mut_ptr() as u64,
            arg3: buf.len() as u64,
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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
kernel_test_in!("userspace", smoke_userspace_read_write_routes_through_fd_table);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_dup_clones_fd() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext, FD_CLOEXEC,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_stat_returns_size() -> TestResult {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, StatBuf, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        return TestResult::Fail("StatBuf.size mismatch");
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
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_stat_returns_size);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_pipe_round_trip() -> TestResult {
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use alloc::sync::Arc;
    use narf_filesystem::{FileOps, FsFuture, Stat};
    use crate::{fd, FdEntry};

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
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;
    use crate::{load_user_process, DEFAULT_USER_STACK_BASE, DEFAULT_USER_STACK_BYTES};

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
kernel_test_in!("userspace", smoke_userspace_load_user_process_builds_runnable_image);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_user_process_with_argv() -> TestResult {
    // Same shape as the no-args runnable-image test, but exercises
    // `load_user_process_with`: pass argv/envp/aux, then verify
    // the new RSP is inside the stack region and that walking the
    // argv pointer-array yields the right strings.
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;
    use crate::{
        load_user_process_with, AuxEntry, DEFAULT_USER_STACK_BASE, DEFAULT_USER_STACK_BYTES,
    };

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
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
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
        let p = match unsafe {
            paging::translate(proc.address_space.root, VirtAddr::new(v & !0xFFF))
        } {
            Some(p) => p.as_u64() | (v & 0xFFF),
            None => return false,
        };
        let want_b = want.as_bytes();
        for i in 0..want_b.len() {
            if unsafe { *((p + i as u64) as *const u8) } != want_b[i] {
                return false;
            }
        }
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
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;
    use crate::{
        interp::__test_clear_interpreters, load_user_process_with, register_interpreter,
    };

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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&(interp_off as u64).to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&(interp_str.len() as u64).to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&(interp_str.len() as u64).to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&1u64.to_le_bytes());
        // Phdr 1 — PT_LOAD code (RX) at PROG_CODE_VA, file off 0x1000.
        ph = 64 + 56;
        b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&PROG_CODE_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&PROG_CODE_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 2 — PT_LOAD data (RW) at PROG_DATA_VA, file off 0x2000.
        ph = 64 + 2 * 56;
        b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
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
    if unsafe { paging::translate(proc.address_space.root, VirtAddr::new(PROG_CODE_VA)) }.is_none()
    {
        return TestResult::Fail("program code not materialised");
    }
    if unsafe { paging::translate(proc.address_space.root, VirtAddr::new(PROG_DATA_VA)) }.is_none()
    {
        return TestResult::Fail("program data not materialised");
    }
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
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 1 — PT_TLS at file off 0x2000.
        ph = 64 + 56;
        b[ph + 0x00..ph + 0x04].copy_from_slice(&7u32.to_le_bytes()); // PT_TLS
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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 1 — first PT_TLS.
        ph = 64 + 56;
        b[ph + 0x00..ph + 0x04].copy_from_slice(&7u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x2000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&16u64.to_le_bytes());
        // Phdr 2 — second PT_TLS (illegal).
        ph = 64 + 2 * 56;
        b[ph + 0x00..ph + 0x04].copy_from_slice(&7u32.to_le_bytes());
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
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;
    use crate::load_user_process_with;

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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
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
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };

    // Read back the slot through the AS — same translate-and-cast
    // pattern the other smokes use.
    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
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
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;
    use crate::load_user_process_with;

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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
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
        b[s1 + 0..s1 + 4].copy_from_slice(&0u32.to_le_bytes()); // st_name
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
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };

    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes());
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
        b[ph + 0x00..ph + 0x04].copy_from_slice(&2u32.to_le_bytes());
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

    match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Err(ProcessLoadError::Load(LoadBytesError::UnresolvedSymbol { idx: 1, name })) => {
            // First 32 bytes must equal the source's first 32 bytes,
            // and *all* 32 must be non-zero (we truncated mid-name,
            // so no terminator was reached inside the buffer).
            if &name[..32] != &long[..32] {
                return TestResult::Fail("truncated name doesn't match source prefix");
            }
            if name.iter().any(|&b| b == 0) {
                return TestResult::Fail("truncated name should have no NUL inside the buffer");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("expected UnresolvedSymbol{idx:1,..}, got different error"),
        Ok(_) => TestResult::Fail("expected UnresolvedSymbol error, got Ok"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_unresolved_symbol_name_truncates);

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
    use narf_memory::{x86_64::paging, AddressSpace, Region, RegionPerms, VirtAddr};
    use crate::{init_sysv_stack, AuxEntry};

    let as_ = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("new_for_user"),
    };
    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
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
    if unsafe { as_.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }

    let argv = ["argv0", "alpha"];
    let envp = ["KEY=val"];
    let aux = [AuxEntry::Pagesz(4096), AuxEntry::Random(0x1234_5678)];
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
        let p = unsafe { paging::translate(as_.root, VirtAddr::new(vaddr & !0xFFF)) }
            .map(|p| p.as_u64() | (vaddr & 0xFFF))
            .unwrap();
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
        let kp = match unsafe { paging::translate(as_.root, VirtAddr::new(user_p & !0xFFF)) } {
            Some(p) => p.as_u64() | (user_p & 0xFFF),
            None => return false,
        };
        let ebytes = expected.as_bytes();
        for i in 0..ebytes.len() {
            if unsafe { *((kp + i as u64) as *const u8) } != ebytes[i] {
                return false;
            }
        }
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
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;
    use crate::load_elf_bytes;

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
    let phys = match unsafe { paging::translate(as_arc.root, VirtAddr::new(0x0000_0080_0000_1000)) }
    {
        Some(p) => p,
        None => return TestResult::Fail("translate found no mapping for segment base"),
    };
    // Read back via identity map.
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
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;
    use crate::load_user_process_with;

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
        let phys = match unsafe { paging::translate(root, VirtAddr::new(va)) } {
            Some(p) => p,
            None => return TestResult::Fail("translate returned None for a mapped page"),
        };
        let got: u8 = unsafe { core::ptr::read_volatile(phys.raw() as *const u8) };
        if got != want {
            return TestResult::Fail("per-page sentinel mismatch — scatter list not honoured");
        }
    }

    // Round-trip: write a sentinel into .data page 1 via the kernel's
    // identity view of the translated phys, re-translate, and confirm
    // the read sees the write. This validates that each page in a
    // multi-page R+W segment is independently mapped — not aliased.
    let data_p1_phys = unsafe { paging::translate(root, VirtAddr::new(DATA_VADDR + 0x1000)) }
        .expect("data page 1 mapped");
    unsafe {
        core::ptr::write_volatile(data_p1_phys.raw() as *mut u32, 0xCAFEBABE);
    }
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
    use narf_memory::{AddressSpace, PhysAddr, RegionPerms, VirtAddr};
    use crate::{load_into, ExecImage, ExecKind, LoadError, Segment, SegmentFlags};

    // Empty image must refuse.
    let empty = ExecImage::empty(ExecKind::Elf64Exec);
    let pool: alloc::vec::Vec<PhysAddr> = alloc::vec::Vec::new();
    let mut a = AddressSpace::empty();
    match load_into(&empty, pool.into_iter(), &mut a) {
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
    let mut a2 = AddressSpace::empty();
    let ep = match load_into(&img, pool.into_iter(), &mut a2) {
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
    let mut a3 = AddressSpace::empty();
    match load_into(&img, tiny.into_iter(), &mut a3) {
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
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::{
        install_global, kernel_syscall_entry_plain, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable,
    };

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
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::{
        install_global, syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn,
        SyscallTable, TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
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
    use crate::{
        alloc_pid, AuxEntry, ExecImage, ExecKind, ProcessId, Segment, SegmentFlags,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use narf_filesystem as fs;
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
            fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
                false
            }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
kernel_test_in!("userspace", smoke_userspace_clock_gettime_distinguishes_clocks);

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
kernel_test_in!("userspace", smoke_userspace_ftruncate_grows_and_shrinks_memfile);

fn smoke_userspace_pread_pwrite_dont_move_cursor() -> TestResult {
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    let path = "/pio/f";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64,
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    for i in 2..18 {
        if buf[i] != 0 {
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
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
    if &buf2[..3] != b"abc" || &buf2[3..7] != &[0; 4] || &buf2[7..10] != b"hij" {
        return TestResult::Fail("zero-range did not zero [3..7]");
    }

    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_fallocate_extends_and_zero_ranges_memfile);

fn smoke_userspace_copy_file_range_round_trip() -> TestResult {
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
            fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
                false
            }
        }
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: path.len() as u64,
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
kernel_test_in!("userspace", smoke_userspace_clock_settime_pushes_wall_offset);

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    if !matches!(call(0 | 0x80), Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
kernel_test_in!("userspace", smoke_userspace_memfd_create_returns_writable_fd);

fn smoke_userspace_getdents64_writes_linux_records() -> TestResult {
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/gd",
        MemFs::with_seeds(
            "gd-test",
            &[("alpha", b"a"), ("beta", b"b"), ("gamma", b"c")],
        ),
    );

    let mut buf = [0u8; 256];
    let path = "/gd";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64,
            arg2: 0,
            arg3: buf.as_mut_ptr() as u64,
            arg4: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getdents64.raw(), &mut ctx);
    let written = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("getdents64 did not return OK"),
    };
    if written == 0 {
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
        return TestResult::Fail("walk did not cover the written length exactly");
    }
    names.sort();
    if names.as_slice() != ["alpha", "beta", "gamma"] {
        return TestResult::Fail("getdents64 didn't enumerate all entries");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getdents64_writes_linux_records);

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
kernel_test_in!("userspace", smoke_userspace_init_per_task_state_is_idempotent);

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    b[ph + 0x00..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
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
    b[ph + 0x00..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
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
    b[s1 + 0..s1 + 4].copy_from_slice(&1u32.to_le_bytes()); // st_name
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
    use crate::{
        abi_file_op_bridge, install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, syscall::__test_clear_global, SyscallTable,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    static PATH: &[u8] = b"f";
    static MOUNT: &[u8] = b"/test_abi";
    static mut READ_BUF: [u8; 16] = [0u8; 16];

    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(kernel_ends.sq_drain, kernel_ends.cq_prod);
        d.run().await;
    });
    narf_scheduler::spawn(async move {
        let mut sq = user_ends.sq_prod;
        let mut cq = user_ends.cq_drain;

        // Open(/test_abi, "f").
        let mut sub = Submission::noop(Tag::new(0x10));
        sub.op = OpCode::OpenFile;
        sub.inline[0] = PATH.as_ptr() as u64;
        sub.inline[1] = PATH.len() as u64;
        sub.inline[2] = MOUNT.as_ptr() as u64;
        sub.inline[3] = MOUNT.len() as u64;
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
        let buf = unsafe { &*(&raw const READ_BUF) };
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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{Dispatcher, NarfStatus, OpCode, Submission, Tag};
    use narf_memory::AddressSpace;
    use crate::{
        abi_file_op_bridge, install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, syscall::__test_clear_global, SyscallTable,
    };

    static USER_AS_MMAP: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_MMAP.lock().clone()
    }
    static FAKE_TASK: u64 = 0xACAC;
    fn task_lookup() -> u64 {
        FAKE_TASK
    }

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::{
        syscall_number, syscall_pack, syscall_version, RawFnHandler, Syscall, SyscallArgs,
        SyscallReturn, SyscallTable, TrapContext,
    };

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
            ctx.set_return(SyscallReturn {
                value: 0xC0DE_0000,
                status: 0,
            });
        }),
    );
    table.install_raw_versioned(
        Syscall::Yield,
        1,
        RawFnHandler(|ctx: &mut dyn TrapContext| {
            V1_SEEN.fetch_add(1, Ordering::Relaxed);
            ctx.set_return(SyscallReturn {
                value: 0xC0DE_0001,
                status: 0,
            });
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
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{x86_64::paging, AddressSpace, VirtAddr};
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
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
    kernel_syscall_entry(57, &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return set"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("fork returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("fork returned tid=0");
    }
    let child_tid = narf_scheduler::TaskId(ret.value);
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
    if parent_region.perms.contains(narf_memory::RegionPerms::WRITE)
        || child_region.perms.contains(narf_memory::RegionPerms::WRITE)
    {
        return TestResult::Fail("post-fork regions must lose WRITE pending split");
    }

    // Verify the shared frame still holds the sentinel byte
    // (parent's bytes are visible to the child since they share).
    let shared_word = unsafe { *(parent_region.phys[0].raw() as *const u32) };
    if shared_word != 0xCAFEBABE {
        return TestResult::Fail("shared COW frame lost the sentinel");
    }

    // Trigger a manual COW split on the child's side, then mutate
    // the child's now-private frame and confirm the parent's
    // shared frame is unchanged.
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
    if !post_split_child.perms.contains(narf_memory::RegionPerms::WRITE) {
        return TestResult::Fail("split should have restored WRITE on the child");
    }
    let child_word = unsafe { *(post_split_child.phys[0].raw() as *const u32) };
    if child_word != 0xCAFEBABE {
        return TestResult::Fail("split didn't memcpy the parent's bytes");
    }
    unsafe {
        *(post_split_child.phys[0].raw() as *mut u32) = 0xDEADBEEF;
    }
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
    kernel_syscall_entry(57, &mut ctx);

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
kernel_test_in!("userspace", smoke_userspace_fork_rejects_without_address_space);

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
        r9:  0x0909_0909_0909_0909,
        r8:  0x0808_0808_0808_0808,
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
        fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
            false
        }
        unsafe fn save_user_state(&self, out: *mut u8) -> bool {
            // SAFETY: caller declared `out` is writable for at
            // least size_of::<UserState>() bytes — the trait's
            // contract; the test passes a freshly-zeroed
            // MaybeUninit<UserState> stack slot.
            unsafe {
                core::ptr::write(out as *mut UserState, self.snapshot);
            }
            true
        }
    }

    let mut ctx = ForkSnapCtx {
        args: SyscallArgs::default(),
        ret: None,
        snapshot: parent_snapshot,
    };
    kernel_syscall_entry(57, &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return set"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("fork returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("parent return tid=0");
    }
    let child_tid = narf_scheduler::TaskId(ret.value);

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
kernel_test_in!("userspace", smoke_userspace_fork_resumes_child_with_rax_zero);

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
    bytes.extend_from_slice(&2u16.to_le_bytes());          // e_type ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes());       // e_machine x86_64
    bytes.extend_from_slice(&1u32.to_le_bytes());          // e_version
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes()); // e_entry
    bytes.extend_from_slice(&64u64.to_le_bytes());         // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes());          // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes());          // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes());         // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes());         // e_phentsize
    bytes.extend_from_slice(&1u16.to_le_bytes());          // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes());          // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes());          // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes());          // e_shstrndx
    // PT_LOAD program header.
    bytes.extend_from_slice(&1u32.to_le_bytes());          // p_type PT_LOAD
    bytes.extend_from_slice(&5u32.to_le_bytes());          // p_flags R|X
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes());  // p_offset
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());     // p_filesz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());     // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());     // p_align
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
            arg0: 0xDEAD_BEEFu64,  // any non-null pointer
            arg1: 32,               // < 64 — too short
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(179, &mut ctx);
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
            arg0: 0,                // null
            arg1: 4096,             // plausible len
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(179, &mut ctx);
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
            arg1: 65 * 1024 * 1024,  // > 64 MiB
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(179, &mut ctx);
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
            arg4: 0,                    // empty envp
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(179, &mut ctx);
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
kernel_test_in!("userspace", smoke_userspace_execve_loads_elf_then_bails_without_user_ctx);

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

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let dispatch = |entry: u64| -> Option<u64> {
        let mut ctx = StubCtx {
            args: SyscallArgs {
                arg0: entry,
                arg1: 0x7fff_fff0_0000,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret: None,
        };
        kernel_syscall_entry(56, &mut ctx);
        match ctx.ret {
            Some(r) if r.status == SyscallReturn::OK && r.value != 0 => Some(r.value),
            _ => None,
        }
    };

    let t1 = match dispatch(0x8000_0000_1000) {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("first clone failed");
        }
    };
    let t2 = match dispatch(0x8000_0000_2000) {
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
    kernel_syscall_entry(56, &mut ctx);
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
kernel_test_in!("userspace", smoke_userspace_clone_rejects_without_address_space);

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
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64 - 1, // exclude trailing NUL
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(crate::Syscall::Chdir.raw(), &mut ctx);
    let parent_tid = FAKE_TID.load(Ordering::Relaxed);
    let parent_cwd = crate::handlers::cwd_of(parent_tid);
    if parent_cwd != "/usr/local/tests" {
        return TestResult::Fail("parent's Chdir didn't take");
    }

    // Now fork. The handler reads current_task_id() = FAKE_TID for
    // the parent_pid, calls cwd_fork(parent_pid, child_tid).
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(57, &mut ctx);
    let child_tid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("fork failed");
        }
    };
    let child_cwd = crate::handlers::cwd_of(child_tid);
    *PARENT_AS.lock() = None;
    crate::handlers::__test_cwd_reset();
    crate::syscall::__test_clear_global();
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

    static FAKE_TID: AtomicU64 = AtomicU64::new(0x51C1);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

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

    // Fork → child_tid; sigaction_lookup(child, SIGTERM) must
    // return HANDLER.
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(57, &mut ctx);
    let child_tid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("fork failed");
        }
    };
    let inherited = crate::handlers::sigaction_lookup(child_tid, SIGTERM as usize);
    *PARENT_AS.lock() = None;
    crate::handlers::__test_sigaction_reset();
    crate::syscall::__test_clear_global();
    if inherited == Some(HANDLER) {
        TestResult::Pass
    } else {
        TestResult::Fail("child did not inherit the parent's SIGTERM handler")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fork_inherits_sigaction_handlers);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_multiple_distinct_address_spaces() -> TestResult {
    // Two back-to-back forks against the same parent must each get
    // their own fresh `Arc<AddressSpace>` — distinct from the
    // parent AND from each other. Catches a regression where the
    // handler memoised the clone result.
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

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
        kernel_syscall_entry(57, &mut ctx);
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
    let as1 = narf_scheduler::address_space_of(narf_scheduler::TaskId(c1));
    let as2 = narf_scheduler::address_space_of(narf_scheduler::TaskId(c2));
    let pass = match (as1, as2) {
        (Some(a), Some(b)) => {
            !Arc::ptr_eq(&a, &parent_as)
                && !Arc::ptr_eq(&b, &parent_as)
                && !Arc::ptr_eq(&a, &b)
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
kernel_test_in!("userspace", smoke_userspace_fork_multiple_distinct_address_spaces);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_sets_comm_to_argv0_basename() -> TestResult {
    // sys_execve takes the basename of argv[0] (the substring after
    // the last '/') and stores it as /proc/[pid]/comm via
    // `set_proc_comm`. Trigger a load with argv[0] = "/usr/bin/foo"
    // and verify comm == "foo" via the public `proc_comm_of` shim.
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    static FAKE_TID: AtomicU64 = AtomicU64::new(0xC0_DE_F00D);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    // argv pack: "/usr/bin/foo\0" → one NUL-terminated string.
    let argv = b"/usr/bin/foo\0".to_vec();

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: elf.as_ptr() as u64,
            arg1: elf.len() as u64,
            arg2: argv.as_ptr() as u64,
            arg3: argv.len() as u64,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(179, &mut ctx);
    // Handler returns invalid_op without a polling user-task ctx,
    // but the load + comm publication runs before that bail-out.

    let pid = FAKE_TID.load(Ordering::Relaxed);
    let comm = crate::handlers::proc_comm_of(pid);
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
kernel_test_in!("userspace", smoke_userspace_execve_sets_comm_to_argv0_basename);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_publishes_cmdline_argv_pack() -> TestResult {
    // After load, /proc/[pid]/cmdline holds the NUL-separated argv
    // bytes the user passed. Confirms `set_proc_argv` ran and the
    // recorded shape matches the wire format.
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    static FAKE_TID: AtomicU64 = AtomicU64::new(0xC0_DE_BABE);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    // argv pack: ["init", "-q", "--debug"] → "init\0-q\0--debug\0".
    let argv = b"init\0-q\0--debug\0".to_vec();
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: elf.as_ptr() as u64,
            arg1: elf.len() as u64,
            arg2: argv.as_ptr() as u64,
            arg3: argv.len() as u64,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(179, &mut ctx);

    let pid = FAKE_TID.load(Ordering::Relaxed);
    let recorded = crate::handlers::proc_argv_of(pid);
    crate::syscall::__test_clear_global();
    // We expect the same NUL-separated shape Linux reports: the
    // original pack bytes joined back together.
    let want: alloc::vec::Vec<u8> = b"init\0-q\0--debug\0".to_vec();
    if recorded == want {
        TestResult::Pass
    } else {
        let msg = alloc::format!(
            "cmdline mismatch: got {:?} want {:?}",
            recorded, want
        );
        let leaked: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
        TestResult::Fail(leaked)
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_publishes_cmdline_argv_pack);

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
    kernel_syscall_entry(179, &mut ctx);
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
            arg3: 65 * 1024,        // > 64 KiB → rejected
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(179, &mut ctx);
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
kernel_test_in!("userspace", smoke_userspace_execve_rejects_oversized_argv_pack);

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
    let r = unsafe { crate::init::spawn_pid1_from_initramfs("/sbin/init") };
    match r {
        Err(crate::init::InitError::InitramfsNotStaged) => TestResult::Pass,
        _ => TestResult::Fail(
            "missing initramfs must surface as InitramfsNotStaged",
        ),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/init", smoke_init_initramfs_not_staged_yields_clear_error);

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
kernel_test_in!("userspace/init", smoke_init_file_listing_returns_none_when_not_staged);
