//! `signals` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

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
    if signal_pending_of(FAKE_TASK.load(Ordering::Relaxed)) & crate::handlers::sig_bit(10) == 0 {
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
    if pending_after & crate::handlers::sig_bit(10) != 0 {
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
    if signal_pending_of(task) & crate::handlers::sig_bit(14) == 0 {
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

    if pending_before & crate::handlers::sig_bit(10) == 0
        || pending_before & crate::handlers::sig_bit(12) == 0
    {
        return TestResult::Fail("both signals 10 and 12 should be pending before delivery");
    }
    if !matches!(first, Some((h, s)) if h == H10 && s == 10) {
        return TestResult::Fail("first delivery must be the lowest signum (10) with its handler");
    }
    if pending_mid & crate::handlers::sig_bit(10) != 0 {
        return TestResult::Fail("first delivery must clear only the delivered bit (10)");
    }
    if pending_mid & crate::handlers::sig_bit(12) == 0 {
        return TestResult::Fail("first delivery must leave the higher signal (12) pending");
    }
    if !matches!(second, Some((h, s)) if h == H12 && s == 12) {
        return TestResult::Fail("second delivery must be signum 12 with its handler");
    }
    if pending_after & crate::handlers::sig_bit(12) != 0 {
        return TestResult::Fail("second delivery must clear the remaining bit (12)");
    }

    TestResult::Pass
}
#[cfg(not(feature = "user-mode-e2e"))]
kernel_test_in!(
    "userspace",
    smoke_userspace_signal_delivery_lowest_first_multiple_pending
);

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
    let rewrote_unknown = default_sync_signal_delivery(&mut ctx2, 9, SyncFaultInfo::default());
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

// ── Phase-2 signal gap-fill smokes ─────────────────────────────────
//
// One smoke per new syscall (sigaltstack install + query, tkill +
// tgkill TID targeting, rt_sigpending pending-and-blocked filter,
// rt_sigsuspend mask round-trip, rt_sigtimedwait delivery + timeout
// paths). All use the FakeCtx pattern shared with the existing
// signal smokes.

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

    // Register the target tid so it exists for the signal target check
    // (tkill now returns ESRCH for an unknown tid — Linux parity).
    crate::handlers::register_task_to_pid(0xBBBB, 0xBBBB);
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
    if pending_target & crate::handlers::sig_bit(10) == 0 {
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

    // Register tid 0xDDDD as a member of thread-group 0xCCCC, so the
    // target exists AND the (tgid,tid) consistency check passes — both
    // required now that tgkill enforces Linux ESRCH semantics.
    crate::handlers::register_task_to_pid(0xDDDD, 0xCCCC);
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
    if pending_tid & crate::handlers::sig_bit(15) == 0 {
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
    // mask in the SAME bit-N-1 layout as the user sigset now, so the
    // internal mask equals 0xF0 verbatim (no `<<1` shim).
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
    if mask_after != 0xF0 {
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
    if pending_after & crate::handlers::sig_bit(12) != 0 {
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
    let want = crate::handlers::sig_bit(10) | crate::handlers::sig_bit(15);
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

    // signum = 65 must be rejected: the bit-N-1 bitmaps represent the
    // full valid range 1..=64 (SIGRTMAX = 64 is now valid), so 65 is
    // the first out-of-range value.
    let mut ctx = SigGapCtx {
        args: SyscallArgs {
            arg0: 0xBEEF,
            arg1: 65,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Tkill.raw(), &mut ctx);
    let r = ctx.ret.unwrap_or(SyscallReturn::ok(0));
    __test_clear_global();
    crate::handlers::__test_signal_reset();
    // Linux parity: an out-of-range signum returns -EINVAL (was an
    // InvalidOp NARF status before the signal-parity pass). The signum
    // check fires before the target existence check, so 0xBEEF's
    // (non)existence is irrelevant here.
    if r == SyscallReturn::ok((-22i64) as u64) {
        TestResult::Pass
    } else {
        TestResult::Fail("signum 65 must be rejected with -EINVAL")
    }
}
kernel_test_in!(
    "userspace",
    smoke_userspace_tkill_signum_out_of_range_rejected
);

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
    // kill() now returns ESRCH for an unknown target and routes real
    // pids through kill_process (which resolves via the task registry),
    // so register the target as a live task, not just in the pid map.
    crate::task::release_task(target);
    let _ = crate::task::Task::new_registered(target, target);
    crate::handlers::register_pid_task_mapping(target, target);
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
    if pending & crate::handlers::sig_bit(15) == 0 {
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
    // Register the target as a live task so kill_process resolves it
    // via the registry (ESRCH parity).
    crate::task::release_task(target);
    let _ = crate::task::Task::new_registered(target, target);
    crate::handlers::register_pid_task_mapping(target, target);
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

    let want =
        crate::handlers::sig_bit(1) | crate::handlers::sig_bit(2) | crate::handlers::sig_bit(6);
    if pending & want == want {
        TestResult::Pass
    } else {
        TestResult::Fail("not all of SIGHUP/SIGINT/SIGABRT landed in pending")
    }
}
kernel_test_in!("userspace", smoke_sys_kill_sighup_sigint_sigabrt_round_trip);

#[cfg(feature = "container")]
fn smoke_unshare_pid_ns_for_children_assigns_child_as_pid_one() -> TestResult {
    crate::pid_ns::__test_reset();
    let parent_task: u64 = 0x2221;
    let child_task: u64 = 0x2222;
    let child_outer: u64 = 5555;

    let _ns = crate::pid_ns::unshare_pid_ns_for_children(parent_task);
    if crate::pid_ns::self_inner_pid(parent_task, 999) == 1 {
        return TestResult::Fail("parent should remain in parent namespace");
    }

    let child_inner = match crate::pid_ns::inherit_into_child(parent_task, child_task, child_outer)
    {
        Some(i) => i,
        None => return TestResult::Fail("inherit_into_child returned None"),
    };

    if child_inner != 1 {
        return TestResult::Fail("first child of unshare_pid_ns_for_children must be inner pid 1");
    }
    if crate::pid_ns::self_inner_pid(child_task, child_outer) != 1 {
        return TestResult::Fail("child self_inner_pid != 1");
    }

    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!(
    "userspace",
    smoke_unshare_pid_ns_for_children_assigns_child_as_pid_one
);

/// Child inherits the parent's namespace and gets a fresh inner pid
/// (parent stays at 1; child becomes 2).
#[cfg(feature = "container")]
fn smoke_pid_ns_inherit_assigns_child_inner_two() -> TestResult {
    crate::pid_ns::__test_reset();
    let parent_task: u64 = 0x1111;
    let parent_outer: u64 = 100;
    // TaskId and ProcessId are distinct spaces — the child's namespace is
    // keyed by its TaskId (what every self-lookup uses), while its inner pid
    // is minted from its outer ProcessId. Using distinct values here pins the
    // keying: a regression that stores the ns under the ProcessId again would
    // make `self_inner_pid(child_task, …)` miss.
    let child_task: u64 = 0x1112;
    let child_outer: u64 = 101;

    let ns = crate::pid_ns::unshare_pid_ns(parent_task, parent_outer);
    assert_eq!(ns.outer_to_inner(parent_outer), Some(1));

    let child_inner = match crate::pid_ns::inherit_into_child(parent_task, child_task, child_outer)
    {
        Some(i) => i,
        None => return TestResult::Fail("inherit_into_child returned None"),
    };
    if child_inner != 2 {
        return TestResult::Fail("child inner pid != 2");
    }
    // getpid path: look the child's ns up by its TaskId, then translate its
    // OUTER ProcessId through the ns → inner 2.
    if crate::pid_ns::self_inner_pid(child_task, child_outer) != 2 {
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
    __test_signal_reset();
    crate::handlers::signal_init();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // current_task_id() must be 0 here so signalfd's owner_task matches
    // the kill(pid=0) target; drop any lookup an earlier test leaked.
    crate::handlers::__test_reset_task_id_lookup();

    // Mask = SIGUSR1 only. NARF's internal pending layout now matches
    // the userspace sigset_t (signal N at bit N-1), so SIGUSR1 (10) is
    // bit 9 both in the user mask and internally.
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

    // Raise SIGUSR1 (10) on the signalfd owner (task 0). Direct raise
    // rather than kill(0) — see the signalfd_epoll test for why
    // (kill(0) is now the caller's process group, Linux parity).
    crate::handlers::raise_signal_pending(0, 10);

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

    if pending & crate::handlers::sig_bit(10) != 0 {
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
