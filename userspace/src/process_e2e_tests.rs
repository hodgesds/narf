//! Wave-30 + Wave-35 + Wave-37 process-model end-to-end smokes.
//!
//! Covers: fork → wait4 → signal delivery, all the way through the
//! kernel-side handler layer.  Each test drives the syscall handlers
//! directly through synthetic `TrapContext` implementations (the same
//! pattern `tests.rs` uses for clone/fork smokes) so no real ELF
//! binary or ring-3 trip is required.
//!
//! Wave-35 additions (smokes 13-18): verify that the syscall numbers
//!
//! Wave-37 additions (smokes 19-22): verify the sys_wait4 cooperative-
//! yield rewrite — waker registration, on_child_exit wake-up, fallback
//! busy-spin path (test context), and concurrent 3-child reap.
//! used by the newly-wired narf-libc fork/pipe/dup2/getpid/getppid
//! wrappers reach the right kernel handlers and return correct values.
//! These complement the Wave-30 kernel-level smokes (1-12) and the
//! narf_user_runtime ABI which already had execve/wait4 wired.
//!
//! Linux references:
//!   - `kernel/fork.c::copy_process`        (fork inheritance rules)
//!   - `kernel/signal.c::do_signal`         (signal delivery hook)
//!   - `kernel/signal.c::complete_signal`   (SIGKILL default action)
//!   - `kernel/exit.c::do_exit`             (exit observer, SIGCHLD)
//!   - `fs/pipe.c::do_pipe2`                (pipe allocation)
//!   - `fs/fcntl.c::do_dup2`               (dup2 semantics)

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::AddressSpace;

use crate::syscall::{
    kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
use crate::{
    default_signal_delivery, install_address_space_lookup, install_core_syscalls, install_global,
    install_task_id_lookup, signal_mask_of, signal_pending_of, SigDeliveryParams,
};

// ── Shared helpers ────────────────────────────────────────────────────

/// Shared parent AS for tests that need a live address space.  Kept in
/// a lock the same way `tests.rs` does it.
#[cfg(target_arch = "x86_64")]
static PROC_PARENT_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
    IrqSafeSpinLock::new(None);

#[cfg(target_arch = "x86_64")]
fn lookup_proc_parent_as() -> Option<Arc<AddressSpace>> {
    PROC_PARENT_AS.lock().clone()
}

/// Minimal synthetic `TrapContext`.  Used where the test doesn't need
/// `deliver_signal` or `returning_to_user`.
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

/// `TrapContext` that also participates in signal delivery.
struct SignalCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
    going_to_user: bool,
    delivered: Option<SigDeliveryParams>,
}

impl TrapContext for SignalCtx {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, r: SyscallReturn) {
        self.ret = Some(r);
    }
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
    fn returning_to_user(&self) -> bool {
        self.going_to_user
    }
    fn deliver_signal(&mut self, p: &SigDeliveryParams) -> bool {
        self.delivered = Some(*p);
        true
    }
}

/// Standard boilerplate for a test that needs full per-task state.
fn setup_process_state(task_id: u64) {
    // Store the task id into the file-scope atomic that the fn-pointer
    // shim reads.  All tests run sequentially so there is no race.
    LOOKUP_TASK.store(task_id, Ordering::Relaxed);
    install_task_id_lookup(lookup_task_shim);
    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    crate::handlers::__test_wait_reset();
    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    crate::user_task::__test_clear_exit_observers();
    crate::sigaction_init();
    crate::signal_init();
    crate::handlers::pgid_init();
    crate::handlers::sid_init();
    crate::handlers::wait_init();
}

static LOOKUP_TASK: AtomicU64 = AtomicU64::new(0);
fn lookup_task_shim() -> u64 {
    LOOKUP_TASK.load(Ordering::Relaxed)
}

fn teardown_process_state() {
    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    crate::handlers::__test_wait_reset();
    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    crate::user_task::__test_clear_exit_observers();
    crate::syscall::__test_clear_global();
}

// ── Smoke 1: fork basic — parent spawns child, wait4 reaps it ────────
//
// Linux ref: kernel/fork.c::copy_process, kernel/exit.c::do_exit
//
// Note: on_child_exit always records status=0 in the current
// implementation (the exit-code threading from sys_exit_task → the
// observer is a noted TODO in handlers.rs:3632).  The smoke verifies
// everything *except* the non-zero wstatus value and documents the
// gap explicitly.

#[cfg(target_arch = "x86_64")]
fn smoke_process_fork_basic_wait4_reap() -> TestResult {
    use narf_memory::AddressSpace;

    const PARENT: u64 = 0xF0_01;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => {
            teardown_process_state();
            return TestResult::Fail("AddressSpace::new_for_user");
        }
    };
    *PROC_PARENT_AS.lock() = Some(parent_as);
    install_address_space_lookup(lookup_proc_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // (1) fork
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
    let child_pid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("fork did not return child pid");
        }
    };

    // (2) verify child task was registered in the scheduler. Wave-38
    //     split ProcessId from TaskId, so translate before query.
    let child_task_raw = match crate::handlers::pid_to_task_raw(child_pid) {
        Some(t) => t,
        None => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("no PID→TaskId mapping registered by fork");
        }
    };
    let child_tid_obj = narf_scheduler::TaskId(child_task_raw);
    if narf_scheduler::address_space_of(child_tid_obj).is_none() {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("child has no AS in scheduler after fork");
    }

    // (3) fire the exit observer manually (simulates child calling
    //     sys_exit_task) and verify wait4 reaps it. notify_task_exited
    //     takes a ProcessId per Wave-38.
    crate::user_task::notify_task_exited(child_pid);

    // (4) wait4(-1, &status, 0) from the parent should return child_tid
    let mut status: i32 = -1;
    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,               // any child
            arg1: &mut status as *mut i32 as u64,
            arg2: 1,                             // WNOHANG — child already exited
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);

    let reaped = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("wait4 did not return OK");
        }
    };
    if reaped != child_pid {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("wait4 returned wrong child pid");
    }
    // wstatus low byte = 0 (normal exit, no signal), because
    // on_child_exit currently records status=0 unconditionally.
    // See handlers.rs:3632 TODO.
    if status != 0 {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("wstatus should be 0 (exit-code threading not yet wired)");
    }

    teardown_process_state();
    *PROC_PARENT_AS.lock() = None;
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_process_fork_basic_wait4_reap);

// ── Smoke 2: fork return values — parent sees child PID, not zero ─────
//
// POSIX: fork() returns the child's PID in the parent and 0 in the
// child.  The child's "0 return" is baked into the saved UserState
// (rax=0) by sys_fork before resume_with; here we only verify the
// parent's side since we're not running a real child future.

#[cfg(target_arch = "x86_64")]
fn smoke_process_fork_return_values() -> TestResult {
    const PARENT: u64 = 0xF0_02;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => {
            teardown_process_state();
            return TestResult::Fail("AddressSpace::new_for_user");
        }
    };
    *PROC_PARENT_AS.lock() = Some(parent_as);
    install_address_space_lookup(lookup_proc_parent_as);

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
        None => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("fork: no return value set");
        }
    };
    if ret.status != SyscallReturn::OK {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("fork returned non-OK status");
    }
    // Parent gets the child's non-zero tid.
    if ret.value == 0 {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("parent should see non-zero child pid from fork");
    }
    // Child return value of 0 is embedded in the child's UserState.rax.
    // We verified this separately in smoke_userspace_fork_resumes_child_with_rax_zero
    // (tests.rs); this smoke just pins the parent's side.

    teardown_process_state();
    *PROC_PARENT_AS.lock() = None;
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_process_fork_return_values);

// ── Smoke 3: wait4 WNOHANG before and after child exits ──────────────
//
// Linux ref: kernel/exit.c::do_wait (WNOHANG returns 0 with no exited
// child, returns child pid once the child is in the zombie queue).

#[cfg(target_arch = "x86_64")]
fn smoke_process_wait4_wnohang() -> TestResult {
    const PARENT: u64 = 0xF0_03;
    const CHILD: u64 = 0xC0_03;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Pre-register a fake parent→child relationship directly, so
    // the exit observer can route it without needing a real fork.
    crate::handlers::__test_inject_parent_of(CHILD, PARENT);

    // (A) WNOHANG before child exits — must return 0
    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64, // any child
            arg1: 0,
            arg2: 1,              // WNOHANG
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("WNOHANG before exit should return 0");
        }
    }

    // (B) Simulate child exit
    crate::user_task::notify_task_exited(CHILD);

    // (C) WNOHANG after exit — must return child pid
    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,
            arg1: 0,
            arg2: 1, // WNOHANG
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == CHILD => {}
        other => {
            teardown_process_state();
            let _ = other;
            return TestResult::Fail("WNOHANG after exit should return child pid");
        }
    }

    teardown_process_state();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_process_wait4_wnohang);

// ── Smoke 4: wait4 specific-child routing ────────────────────────────
//
// Parent has two children; wait4(child_a) must reap only child_a,
// leaving child_b still in the pending queue.

#[cfg(target_arch = "x86_64")]
fn smoke_process_wait4_specific_child() -> TestResult {
    const PARENT: u64 = 0xF0_04;
    const CHILD_A: u64 = 0xCA_04;
    const CHILD_B: u64 = 0xCB_04;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    crate::handlers::__test_inject_parent_of(CHILD_A, PARENT);
    crate::handlers::__test_inject_parent_of(CHILD_B, PARENT);

    // Both children exit.
    crate::user_task::notify_task_exited(CHILD_A);
    crate::user_task::notify_task_exited(CHILD_B);

    // wait4(CHILD_A) — should reap only CHILD_A
    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: CHILD_A,
            arg1: 0,
            arg2: 1, // WNOHANG
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == CHILD_A => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("wait4(CHILD_A) should reap CHILD_A");
        }
    }

    // CHILD_B must still be in the pending queue — reap it too.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64, // any
            arg1: 0,
            arg2: 1,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == CHILD_B => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("CHILD_B should still be reapable after CHILD_A was taken");
        }
    }

    teardown_process_state();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_process_wait4_specific_child);

// ── Smoke 5: SIGCHLD on child exit ───────────────────────────────────
//
// Parent installs a SIGCHLD (signal 17) handler, then the child
// exits.  The test verifies that the pending-signal bitmap for the
// parent has bit 17 set after `on_child_exit` fires.
//
// POSIX 2017 §2.4.3: "SIGCHLD shall be generated for the parent
// process whenever a child process changes state."  Fixed in
// handlers.rs::on_child_exit as part of this Wave-30 smoke series.
//
// Linux ref: kernel/signal.c::do_notify_parent (sends SIGCHLD).

#[cfg(target_arch = "x86_64")]
fn smoke_process_sigchld_on_child_exit() -> TestResult {
    const PARENT: u64 = 0xF0_05;
    const CHILD: u64 = 0xC0_05;
    const SIGCHLD: u32 = 17;

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Install a SIGCHLD handler for the parent.
    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: SIGCHLD as u64,
            arg1: 0xDEAD_5C4D, // synthetic handler vaddr
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        teardown_process_state();
        return TestResult::Fail("sigaction(SIGCHLD) failed");
    }

    // Wire the parent-of relationship and fire the exit.
    crate::handlers::__test_inject_parent_of(CHILD, PARENT);
    crate::user_task::notify_task_exited(CHILD);

    // SIGCHLD bit (17) should be pending on the parent.
    let pending = signal_pending_of(PARENT);
    if pending & (1 << SIGCHLD) == 0 {
        teardown_process_state();
        return TestResult::Fail("SIGCHLD not set in parent's pending bitmap after child exit");
    }

    teardown_process_state();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_process_sigchld_on_child_exit);

// ── Smoke 6: kill + signal handler ────────────────────────────────────
//
// Parent installs SIGUSR1 (10) handler, kills itself, delivery hook
// runs, handler vaddr is delivered.  Tests the full async-signal
// path: sigaction → kill → default_signal_delivery.
//
// Linux ref: kernel/signal.c::do_signal → handle_signal

fn smoke_process_kill_sigusr1_delivery() -> TestResult {
    const TASK: u64 = 0xF0_06;
    const SIGUSR1: u32 = 10;
    const HANDLER: u64 = 0xDEAD_0010;

    crate::syscall::__test_clear_global();
    setup_process_state(TASK);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // (1) Register handler
    LOOKUP_TASK.store(TASK, Ordering::Relaxed);
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: SIGUSR1 as u64,
            arg1: HANDLER,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        teardown_process_state();
        return TestResult::Fail("sigaction registration failed");
    }

    // (2) Kill self
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: TASK,
            arg1: SIGUSR1 as u64,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        teardown_process_state();
        return TestResult::Fail("kill(self, SIGUSR1) failed");
    }
    if signal_pending_of(TASK) & (1 << SIGUSR1) == 0 {
        teardown_process_state();
        return TestResult::Fail("kill did not set SIGUSR1 pending bit");
    }

    // (3) Run delivery hook, heading back to user
    let mut sctx = SignalCtx {
        args: SyscallArgs::default(),
        ret: None,
        going_to_user: true,
        delivered: None,
    };
    default_signal_delivery(&mut sctx, crate::handlers::SYSCALL_NUM_NONE);

    // (4) Verify handler vaddr + signum were dispatched
    let pending_after = signal_pending_of(TASK);
    teardown_process_state();

    match sctx.delivered {
        Some(p) if p.handler == HANDLER && p.signum == SIGUSR1 => {}
        _ => return TestResult::Fail("delivery hook did not call deliver_signal with expected params"),
    }
    if pending_after & (1 << SIGUSR1) != 0 {
        return TestResult::Fail("delivery did not clear the pending bit");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_process_kill_sigusr1_delivery);

// ── Smoke 7: SIGKILL kills child ──────────────────────────────────────
//
// kill(child, SIGKILL) sets the pending bit for SIGKILL (9) on the
// target task.  In user-mode the default action is task termination;
// at this kernel-side level we verify the pending bit is set correctly
// so the exit path can consume it.  wstatus would have the low byte
// equal to SIGKILL but that threading is not yet wired (same TODO as
// smoke 1).
//
// Linux ref: kernel/signal.c::complete_signal — SIGKILL always
// bypasses masking.

fn smoke_process_sigkill_sets_pending() -> TestResult {
    const PARENT: u64 = 0xF0_07;
    const CHILD: u64 = 0xC0_07;
    const SIGKILL: u32 = 9;

    crate::syscall::__test_clear_global();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Kill the child from the parent's context (kill is not restricted
    // by who is current_task here — it targets by tid).
    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: CHILD,
            arg1: SIGKILL as u64,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        teardown_process_state();
        return TestResult::Fail("kill(child, SIGKILL) returned non-OK");
    }

    let pending = signal_pending_of(CHILD);
    if pending & (1 << SIGKILL) == 0 {
        teardown_process_state();
        return TestResult::Fail("SIGKILL not set in child's pending bitmap");
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_process_sigkill_sets_pending);

// ── Smoke 8: sa_mask blocks reentry ───────────────────────────────────
//
// Install SIGUSR1 with sa_mask = SIGUSR1 (SA_NODEFER not set).
// After delivery, the handler's signal is auto-added to the mask so a
// second SIGUSR1 during the handler is blocked.  On notional return
// from the handler (mask restored), the blocked signal becomes
// deliverable.
//
// This smoke exercises `default_signal_delivery`'s post-delivery mask
// update (`*slot |= 1 << signum` when SA_NODEFER is absent).
//
// Linux ref: kernel/signal.c::handle_signal → sigorsets for sa_mask.

fn smoke_process_sa_mask_blocks_reentry() -> TestResult {
    const TASK: u64 = 0xF0_08;
    const SIGUSR1: u32 = 10;
    const HANDLER: u64 = 0xDEAD_0008;

    crate::syscall::__test_clear_global();
    setup_process_state(TASK);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    LOOKUP_TASK.store(TASK, Ordering::Relaxed);

    // Install handler *without* SA_NODEFER — auto-block on delivery.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: SIGUSR1 as u64,
            arg1: HANDLER,
            arg2: 0,
            arg3: 0, // flags = 0 (no SA_NODEFER)
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        teardown_process_state();
        return TestResult::Fail("sigaction failed");
    }

    // Deliver first SIGUSR1.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: TASK,
            arg1: SIGUSR1 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);

    let mut sctx = SignalCtx {
        args: SyscallArgs::default(),
        ret: None,
        going_to_user: true,
        delivered: None,
    };
    default_signal_delivery(&mut sctx, crate::handlers::SYSCALL_NUM_NONE);

    if sctx.delivered.is_none() {
        teardown_process_state();
        return TestResult::Fail("first SIGUSR1 was not delivered");
    }

    // After delivery, SIGUSR1 should be in the mask (auto-blocked).
    let mask_after = signal_mask_of(TASK);
    if mask_after & (1 << SIGUSR1) == 0 {
        teardown_process_state();
        return TestResult::Fail(
            "SIGUSR1 should be auto-blocked in mask after delivery (SA_NODEFER absent)",
        );
    }

    // A second SIGUSR1 kill should set it pending but delivery hook
    // should not deliver it (masked).
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: TASK,
            arg1: SIGUSR1 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);

    let mut sctx2 = SignalCtx {
        args: SyscallArgs::default(),
        ret: None,
        going_to_user: true,
        delivered: None,
    };
    default_signal_delivery(&mut sctx2, crate::handlers::SYSCALL_NUM_NONE);

    if sctx2.delivered.is_some() {
        teardown_process_state();
        return TestResult::Fail("masked SIGUSR1 should not be delivered during handler");
    }

    // Unblock: clear the mask entry.
    LOOKUP_TASK.store(TASK, Ordering::Relaxed);
    let unblock_mask: u32 = 1 << SIGUSR1;
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 1u64,                    // SIG_UNBLOCK
            arg1: unblock_mask as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigprocmask.raw(), &mut ctx);

    // Now the pending second SIGUSR1 should be deliverable.
    let mut sctx3 = SignalCtx {
        args: SyscallArgs::default(),
        ret: None,
        going_to_user: true,
        delivered: None,
    };
    default_signal_delivery(&mut sctx3, crate::handlers::SYSCALL_NUM_NONE);

    teardown_process_state();

    if sctx3.delivered.is_none() {
        return TestResult::Fail("unblocked SIGUSR1 should be delivered after mask cleared");
    }

    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_process_sa_mask_blocks_reentry);

// ── Smoke 9: sigprocmask block + pending then unblock ─────────────────
//
// Block SIGUSR2 (12), kill self with SIGUSR2 → not delivered; unblock
// → delivered on next delivery hook invocation.
//
// Linux ref: kernel/signal.c::__set_task_blocked / do_sigprocmask.

fn smoke_process_sigprocmask_block_unblock() -> TestResult {
    const TASK: u64 = 0xF0_09;
    const SIGUSR2: u32 = 12;
    const HANDLER: u64 = 0xDEAD_0012;

    crate::syscall::__test_clear_global();
    setup_process_state(TASK);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    LOOKUP_TASK.store(TASK, Ordering::Relaxed);

    // Install handler for SIGUSR2.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: SIGUSR2 as u64,
            arg1: HANDLER,
            arg2: 0,
            arg3: crate::SA_NODEFER as u64, // SA_NODEFER — don't auto-block
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigaction.raw(), &mut ctx);

    // Block SIGUSR2.
    let block_set: u32 = 1 << SIGUSR2;
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0,                     // SIG_BLOCK
            arg1: block_set as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigprocmask.raw(), &mut ctx);

    // Kill self → pending bit set but masked.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: TASK,
            arg1: SIGUSR2 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Kill.raw(), &mut ctx);

    // Delivery hook — should not deliver (blocked).
    let mut sctx = SignalCtx {
        args: SyscallArgs::default(),
        ret: None,
        going_to_user: true,
        delivered: None,
    };
    default_signal_delivery(&mut sctx, crate::handlers::SYSCALL_NUM_NONE);

    if sctx.delivered.is_some() {
        teardown_process_state();
        return TestResult::Fail("blocked SIGUSR2 must not be delivered");
    }

    // Pending bit still set.
    if signal_pending_of(TASK) & (1 << SIGUSR2) == 0 {
        teardown_process_state();
        return TestResult::Fail("pending bit must remain after blocked delivery attempt");
    }

    // Unblock.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 1,                     // SIG_UNBLOCK
            arg1: block_set as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sigprocmask.raw(), &mut ctx);

    // Now deliver.
    let mut sctx2 = SignalCtx {
        args: SyscallArgs::default(),
        ret: None,
        going_to_user: true,
        delivered: None,
    };
    default_signal_delivery(&mut sctx2, crate::handlers::SYSCALL_NUM_NONE);

    teardown_process_state();

    match sctx2.delivered {
        Some(p) if p.handler == HANDLER && p.signum == SIGUSR2 => {}
        _ => return TestResult::Fail("SIGUSR2 should be delivered after unblock"),
    }
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_process_sigprocmask_block_unblock);

// ── Smoke 10: getpid + getppid ────────────────────────────────────────
//
// getpid() returns current_task_id().  getppid() currently returns 0
// (the Stage-4 stub documented in handlers.rs:3287).
//
// This smoke pins the current behaviour so a real implementation of
// getppid (parent-task lookup) is caught by a regression if it breaks
// getpid.

fn smoke_process_getpid_getppid() -> TestResult {
    const TASK: u64 = 0xF0_0A;
    crate::syscall::__test_clear_global();
    setup_process_state(TASK);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    LOOKUP_TASK.store(TASK, Ordering::Relaxed);

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetPid.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == TASK => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("getpid should return current task id");
        }
    }

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetPpid.raw(), &mut ctx);
    // Stage-4 stub: getppid returns 0 until parent-tracking lands.
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("getppid should return OK status");
        }
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_process_getpid_getppid);

// ── Smoke 11: setpgid + getpgid + setsid round-trip ──────────────────
//
// setpgid(0, 0) makes the caller the leader of a new process group
// with pgid == pid.  getpgid(0) should round-trip the value.
// setsid() sets both pgid and sid to pid.
//
// Linux ref: kernel/sys.c::sys_setpgid, sys_setsid.

fn smoke_process_pgid_setsid_roundtrip() -> TestResult {
    const TASK: u64 = 0xF0_0B;
    crate::syscall::__test_clear_global();
    setup_process_state(TASK);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    LOOKUP_TASK.store(TASK, Ordering::Relaxed);

    // setpgid(0, 0) — "make me my own group leader"
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Setpgid.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        teardown_process_state();
        return TestResult::Fail("setpgid(0,0) failed");
    }

    // getpgid(0) should return TASK (pid == pgid after setpgid(0,0))
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getpgid.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == TASK => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("getpgid(0) should equal task id after setpgid(0,0)");
        }
    }

    // setsid() — sets both pgid and sid to TASK
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Setsid.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == TASK => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("setsid() should return the task's own id");
        }
    }

    // getpgid should still equal TASK after setsid
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getpgid.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == TASK => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("getpgid should equal task id after setsid");
        }
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_process_pgid_setsid_roundtrip);

// ── Smoke 12: execve validates inputs ────────────────────────────────
//
// Full exec of a kernel-test entry without a real ELF binary is out
// of scope (requires a polling user-task ctx). Instead this smoke
// verifies the input-validation guards: null ptr → invalid_op, too-
// short ELF → invalid_op.  The full exec smoke (replacing the task's
// image) is deferred to the user-mode-e2e gate.
//
// Linux ref: fs/exec.c::do_execve → bprm_fill_uid.

#[cfg(target_arch = "x86_64")]
fn smoke_process_execve_input_validation() -> TestResult {
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // (A) null ELF pointer
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 4096,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r == SyscallReturn::invalid_op() => {}
        _ => {
            crate::syscall::__test_clear_global();
            return TestResult::Fail("execve with null ptr should return invalid_op");
        }
    }

    // (B) too-short ELF (< 64 bytes)
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0xDEAD_BEEF,
            arg1: 32,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r == SyscallReturn::invalid_op() => {}
        _ => {
            crate::syscall::__test_clear_global();
            return TestResult::Fail("execve with too-short ELF should return invalid_op");
        }
    }

    // (C) oversized ELF (> 64 MiB)
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0xDEAD_BEEF,
            arg1: 65 * 1024 * 1024,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r == SyscallReturn::invalid_op() => {}
        _ => {
            crate::syscall::__test_clear_global();
            return TestResult::Fail("execve with oversized ELF should return invalid_op");
        }
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_process_execve_input_validation);

// ── Smoke 13 (Wave-35): fork via Syscall::Fork returns non-zero child
//    pid — the narf-libc fork() wrapper wires to SYS_FORK (wire=57).
//    This verifies that the syscall number reaches sys_fork, which is
//    the root cause of the Wave-34 ENOSYS regression.
//
// Linux ref: arch/x86/entry/syscalls/syscall_64.tbl (fork = 57).

#[cfg(target_arch = "x86_64")]
fn smoke_wave35_fork_returns_nonzero_child_pid() -> TestResult {
    const PARENT: u64 = 0xF0_13;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => {
            teardown_process_state();
            return TestResult::Fail("AddressSpace::new_for_user failed");
        }
    };
    *PROC_PARENT_AS.lock() = Some(parent_as);
    install_address_space_lookup(lookup_proc_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Issue Syscall::Fork — this is the number narf-libc's fork() now
    // invokes.  The kernel handler must return a non-zero child tid in
    // the parent (proving no ENOSYS / stub return of -1).
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
    let ret = match ctx.ret {
        Some(r) => r,
        None => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("fork: no return value (ENOSYS stub hit?)");
        }
    };
    if ret.status != SyscallReturn::OK {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("fork returned non-OK status (ENOSYS stub?)");
    }
    if ret.value == 0 {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("fork returned 0 in parent (expected child pid)");
    }

    teardown_process_state();
    *PROC_PARENT_AS.lock() = None;
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_wave35_fork_returns_nonzero_child_pid);

// ── Smoke 14 (Wave-35): pipe allocates two distinct fds > 2 ──────────
//
// Verifies that Syscall::Pipe (the wire number narf-libc's pipe()
// wrapper uses) allocates a read+write fd pair with fds[0] != fds[1]
// and both > stderr (fd 2).
//
// Linux ref: fs/pipe.c::do_pipe2; musl src/unistd/pipe.c.

fn smoke_wave35_pipe_allocates_distinct_fds() -> TestResult {
    const TASK: u64 = 0xF0_14;
    crate::syscall::__test_clear_global();
    setup_process_state(TASK);

    crate::fd::__test_reset();
    crate::fd::init();

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    LOOKUP_TASK.store(TASK, Ordering::Relaxed);

    // Provide a two-element output buffer in a local array.  The pipe
    // syscall writes [read_fd: i32, write_fd: i32] to arg0 (a pointer).
    let mut fds: [i32; 2] = [-1, -1];
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: fds.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("pipe: non-OK return");
        }
    }
    if fds[0] < 0 || fds[1] < 0 {
        teardown_process_state();
        return TestResult::Fail("pipe: fds not written (still -1)");
    }
    if fds[0] == fds[1] {
        teardown_process_state();
        return TestResult::Fail("pipe: read_fd == write_fd");
    }
    if fds[0] <= 2 || fds[1] <= 2 {
        teardown_process_state();
        return TestResult::Fail("pipe: fds should be > stderr (2)");
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave35_pipe_allocates_distinct_fds);

// ── Smoke 15 (Wave-35): dup2 rewires a descriptor ────────────────────
//
// Verifies that Syscall::Dup2 successfully re-points fd 0 (stdin) to
// an existing fd — the narf-libc dup2() wrapper wires to SYS_DUP2
// (wire=33 on x86_64).  The smoke checks the kernel returns newfd in
// the success value, matching POSIX "dup2 returns the new fd".
//
// Linux ref: fs/fcntl.c::do_dup2; musl src/unistd/dup2.c.

fn smoke_wave35_dup2_rewires_descriptor() -> TestResult {
    const TASK: u64 = 0xF0_15;
    crate::syscall::__test_clear_global();
    setup_process_state(TASK);

    crate::fd::__test_reset();
    crate::fd::init();

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    LOOKUP_TASK.store(TASK, Ordering::Relaxed);

    // Allocate a pipe so we have a real fd > 2 to dup onto 0.
    let mut fds: [i32; 2] = [-1, -1];
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: fds.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut ctx);
    if fds[0] < 0 {
        teardown_process_state();
        return TestResult::Fail("dup2 smoke: pipe setup failed");
    }
    let rfd = fds[0];

    // dup2(rfd, 0) — rewire stdin to the read-end of the pipe.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: rfd as u64,
            arg1: 0,          // target = stdin
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Dup2.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("dup2(rfd, 0): expected OK with value=0");
        }
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave35_dup2_rewires_descriptor);

// ── Smoke 16 (Wave-35): getpid returns non-zero ───────────────────────
//
// Verifies that Syscall::GetPid returns the calling task's id (non-
// zero). The narf-libc getpid() wrapper routes to SYS_GETPID = 39.
//
// Linux ref: kernel/sys.c::sys_getpid; musl src/process/getpid.c.

fn smoke_wave35_getpid_nonzero() -> TestResult {
    const TASK: u64 = 0xF0_16;
    crate::syscall::__test_clear_global();
    setup_process_state(TASK);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    LOOKUP_TASK.store(TASK, Ordering::Relaxed);

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetPid.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("getpid should return non-zero task id");
        }
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave35_getpid_nonzero);

// ── Smoke 17 (Wave-35): getppid differs from getpid after fork ────────
//
// Verifies that after a fork, Syscall::GetPpid from the child returns
// the parent's task id (non-zero, != child pid).  The narf-libc
// getppid() wrapper routes to SYS_GETPPID = 110.
//
// Linux ref: kernel/sys.c::sys_getppid; musl src/process/getppid.c.

#[cfg(target_arch = "x86_64")]
fn smoke_wave35_getppid_differs_from_getpid() -> TestResult {
    const PARENT: u64 = 0xF0_17;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => {
            teardown_process_state();
            return TestResult::Fail("AddressSpace::new_for_user failed");
        }
    };
    *PROC_PARENT_AS.lock() = Some(parent_as);
    install_address_space_lookup(lookup_proc_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Fork to get a child task id.
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
    let child_tid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("fork failed in getppid smoke");
        }
    };

    // Switch task context to the child and query getpid + getppid.
    LOOKUP_TASK.store(child_tid, Ordering::Relaxed);

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetPid.raw(), &mut ctx);
    let child_pid_seen = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("getpid in child returned non-OK");
        }
    };

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetPpid.raw(), &mut ctx);
    let child_ppid_seen = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("getppid in child returned non-OK");
        }
    };

    if child_pid_seen == child_ppid_seen {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("child: getpid == getppid (ppid should be parent)");
    }
    if child_ppid_seen != PARENT {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("child ppid should equal parent task id");
    }

    teardown_process_state();
    *PROC_PARENT_AS.lock() = None;
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_wave35_getppid_differs_from_getpid);

// ── Smoke 18 (Wave-35): waitpid WNOHANG before/after child exit ───────
//
// Mirrors the Wave-30 Smoke 3 pattern but exercises the libc-shaped
// waitpid wrapper's syscall number explicitly via Syscall::Wait4
// (both waitpid and wait4 route to the same kernel handler on NARF —
// the narf-libc waitpid() calls narf_user_runtime::wait4()).
//
// Verifies:
//   (A) Wait4 WNOHANG before child exits → returns 0 (no child ready).
//   (B) Wait4 WNOHANG after child exits  → returns child pid.
//
// Linux ref: kernel/exit.c::do_wait; musl src/process/waitpid.c.

fn smoke_wave35_waitpid_wnohang_before_after() -> TestResult {
    const PARENT: u64 = 0xF0_18;
    const CHILD: u64 = 0xC0_18;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    crate::handlers::__test_inject_parent_of(CHILD, PARENT);

    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);

    // (A) WNOHANG before child exits — must return 0.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64, // any child
            arg1: 0,
            arg2: 1,              // WNOHANG
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("waitpid WNOHANG before exit: expected 0");
        }
    }

    // (B) Fire child exit, then WNOHANG — must return child pid.
    crate::user_task::notify_task_exited(CHILD);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,
            arg1: 0,
            arg2: 1, // WNOHANG
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == CHILD => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("waitpid WNOHANG after exit: expected child pid");
        }
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave35_waitpid_wnohang_before_after);

// ── Smoke 19 (Wave-37): blocking wait4 fallback — exit before wait ────
//
// Tests the "test/no-future fallback" path in sys_wait4: when there is
// no UserTaskFuture/yield hook installed (StubCtx), the handler falls
// back to a synchronous busy-poll.  Pre-registering the child exit
// ensures the loop exits immediately and returns the child pid.
//
// This also validates the WNOHANG-false path, which was previously the
// deadlock path in QEMU (the spin prevented the child from running).
//
// Linux ref: kernel/exit.c::do_wait.

fn smoke_wave37_blocking_wait4_fallback_exit_before_wait() -> TestResult {
    const PARENT: u64 = 0xF0_19;
    const CHILD: u64 = 0xC0_19;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    crate::handlers::__test_inject_parent_of(CHILD, PARENT);

    // Fire child exit BEFORE the blocking wait4 call.
    crate::user_task::notify_task_exited(CHILD);

    // Blocking wait4(-1, &status, 0) — no WNOHANG.
    // In test context (no yield hook), the fallback busy-spin exits
    // immediately because PENDING_EXITS already has an entry.
    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    let mut status: i32 = -1;
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,
            arg1: &mut status as *mut i32 as u64,
            arg2: 0, // blocking (no WNOHANG)
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);

    let reaped = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            teardown_process_state();
            return TestResult::Fail("blocking wait4 (fallback): non-OK return");
        }
    };
    if reaped != CHILD {
        teardown_process_state();
        return TestResult::Fail("blocking wait4 (fallback): wrong child pid");
    }
    if status != 0 {
        teardown_process_state();
        return TestResult::Fail("wstatus should be 0");
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave37_blocking_wait4_fallback_exit_before_wait);

// ── Smoke 20 (Wave-37): wait_child_check_fn callback contract ─────────
//
// Directly invokes the `wait_child_check_fn` callback registered by
// `wait_init` to verify it:
//   (A) returns 0 when the queue is empty,
//   (B) returns the child pid when the queue has a matching entry and
//       drains it (so a second call returns 0 again).
//
// Linux ref: kernel/exit.c::wait_consider_task.

fn smoke_wave37_wait_child_check_fn_contract() -> TestResult {
    const PARENT: u64 = 0xF0_20;
    const CHILD: u64 = 0xC0_20;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    crate::handlers::__test_inject_parent_of(CHILD, PARENT);

    // (A) Queue empty → check returns 0.
    let r0 = crate::user_task::call_wait_child_check(PARENT, -1, 0);
    if r0 != 0 {
        teardown_process_state();
        return TestResult::Fail("check_fn on empty queue should return 0");
    }

    // Populate the queue.
    crate::user_task::notify_task_exited(CHILD);

    // (B) Queue has entry → returns child pid.
    let r1 = crate::user_task::call_wait_child_check(PARENT, -1, 0);
    if r1 != CHILD as i64 {
        teardown_process_state();
        return TestResult::Fail("check_fn should return child pid after exit");
    }

    // (C) Queue was drained → second call returns 0.
    let r2 = crate::user_task::call_wait_child_check(PARENT, -1, 0);
    if r2 != 0 {
        teardown_process_state();
        return TestResult::Fail("check_fn should return 0 after queue was drained");
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave37_wait_child_check_fn_contract);

// ── Smoke 21 (Wave-37): on_child_exit fires wake_wait_child ───────────
//
// Verifies that when a child exits, `on_child_exit` (called via
// `notify_task_exited`) also calls `wake_wait_child` for the parent.
// We confirm this by pre-registering a waker, firing the exit, and
// checking whether the waker was consumed (the waker table entry
// should be gone after the wake).
//
// Because we can't easily introspect a `Waker`'s fired state in
// no_std, we verify the table entry is removed by calling
// `call_wait_child_check` which is idempotent — the real verification
// is that `wake_wait_child` was called (draining the slot) rather
// than the pending-exits queue (which we drain via check_fn).
//
// Linux ref: kernel/signal.c::do_notify_parent → complete_signal.

fn smoke_wave37_on_child_exit_fires_wake() -> TestResult {
    use core::sync::atomic::{AtomicBool, Ordering as Ord};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    const PARENT: u64 = 0xF0_21;
    const CHILD: u64 = 0xC0_21;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    crate::handlers::__test_inject_parent_of(CHILD, PARENT);

    // Build a tiny waker backed by an AtomicBool flag.
    static WOKE: AtomicBool = AtomicBool::new(false);
    WOKE.store(false, Ord::Relaxed);

    unsafe fn clone_raw(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    unsafe fn wake_raw(_: *const ()) {
        WOKE.store(true, Ord::Release);
    }
    unsafe fn wake_by_ref_raw(_: *const ()) {
        WOKE.store(true, Ord::Release);
    }
    unsafe fn drop_raw(_: *const ()) {}
    static VTAB: RawWakerVTable =
        RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw);

    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTAB)) };
    crate::user_task::register_wait_child_waker(PARENT, waker);

    // Fire child exit — this should call wake_wait_child(PARENT)
    // which consumes the waker we stored and calls w.wake().
    crate::user_task::notify_task_exited(CHILD);

    if !WOKE.load(Ord::Acquire) {
        teardown_process_state();
        return TestResult::Fail("on_child_exit did not call wake_wait_child");
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave37_on_child_exit_fires_wake);

// ── Smoke 22 (Wave-37): concurrent 3 children, sequential WNOHANG reap
//
// Three children exit before the parent calls wait4.  Each successive
// WNOHANG call should reap exactly one child.  After three calls the
// queue is empty and the fourth returns 0.
//
// Regresses the "leftover children block subsequent wait4" class of
// bugs that can arise from the try_reap remove-by-index logic.
//
// Linux ref: kernel/exit.c::do_wait → wait_consider_task.

fn smoke_wave37_three_children_sequential_reap() -> TestResult {
    const PARENT: u64 = 0xF0_22;
    const C1: u64 = 0xCA_22;
    const C2: u64 = 0xCB_22;
    const C3: u64 = 0xCC_22;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    crate::handlers::__test_inject_parent_of(C1, PARENT);
    crate::handlers::__test_inject_parent_of(C2, PARENT);
    crate::handlers::__test_inject_parent_of(C3, PARENT);

    crate::user_task::notify_task_exited(C1);
    crate::user_task::notify_task_exited(C2);
    crate::user_task::notify_task_exited(C3);

    let mut reaped_set = [0u64; 3];

    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    for slot in reaped_set.iter_mut() {
        let mut ctx = StubCtx {
            args: SyscallArgs {
                arg0: (-1i64) as u64,
                arg1: 0,
                arg2: 1, // WNOHANG
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
        let v = match ctx.ret {
            Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
            _ => {
                teardown_process_state();
                return TestResult::Fail("sequential reap: WNOHANG returned 0 too early");
            }
        };
        *slot = v;
    }

    // All three must have been reaped — check each expected child
    // appears exactly once in the result set.
    for &c in &[C1, C2, C3] {
        if !reaped_set.contains(&c) {
            teardown_process_state();
            return TestResult::Fail("sequential reap: not all children reaped");
        }
    }

    // Fourth call: queue empty → 0.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,
            arg1: 0,
            arg2: 1, // WNOHANG
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {}
        _ => {
            teardown_process_state();
            return TestResult::Fail("sequential reap: 4th WNOHANG should return 0");
        }
    }

    teardown_process_state();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave37_three_children_sequential_reap);

// ── Wave-38 smokes: ProcessId ↔ TaskId aliasing hardening ────────────
//
// These smokes verify that the explicit PID↔TaskId mapping introduced
// in Wave-38 works correctly even when the two counters are out of
// alignment (e.g. after the scheduler has already advanced its counter
// independently).  They directly exercise the side-table without going
// through a full fork() round-trip.
//
// Smoke 23: mapping table stores and retrieves correctly (both dirs)
// Smoke 24: fork produces a mapping entry; translation is consistent
// Smoke 25: wait4 returns child ProcessId, not child TaskId
// Smoke 26: on_child_exit fires via ProcessId key; waker uses TaskId

/// Smoke 23: Direct mapping table insert + bidirectional lookup.
fn smoke_wave38_pid_task_mapping_roundtrip() -> TestResult {
    use crate::handlers::{__test_wait_reset, pid_to_task_raw, register_pid_task_mapping, task_to_pid_raw, wait_init};

    crate::syscall::__test_clear_global();
    crate::handlers::__test_wait_reset();
    wait_init();

    // Synthesise a task with ProcessId(5) and TaskId(99) — these are
    // deliberately mismatched to prove the table tracks them as distinct
    // values rather than treating them as the same integer.
    let pid_raw: u64 = 5;
    let task_raw: u64 = 99;
    register_pid_task_mapping(pid_raw, task_raw);

    // Forward lookup: ProcessId → TaskId
    match pid_to_task_raw(pid_raw) {
        Some(t) if t == task_raw => {}
        other => {
            crate::handlers::__test_wait_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail(if other.is_none() {
                "pid_to_task_raw returned None for registered pid"
            } else {
                "pid_to_task_raw returned wrong TaskId"
            });
        }
    }

    // Reverse lookup: TaskId → ProcessId
    match task_to_pid_raw(task_raw) {
        Some(p) if p == pid_raw => {}
        other => {
            crate::handlers::__test_wait_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail(if other.is_none() {
                "task_to_pid_raw returned None for registered task"
            } else {
                "task_to_pid_raw returned wrong ProcessId"
            });
        }
    }

    // A different PID must not resolve to the same TaskId.
    if pid_to_task_raw(pid_raw + 1).is_some() {
        crate::handlers::__test_wait_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("unregistered pid_raw+1 should not be found");
    }

    crate::handlers::__test_wait_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave38_pid_task_mapping_roundtrip);

/// Smoke 24: fork() registers a PID↔TaskId mapping; the translation is
/// consistent (ProcessId from fork return → TaskId in scheduler).
#[cfg(target_arch = "x86_64")]
fn smoke_wave38_fork_registers_mapping() -> TestResult {
    use narf_memory::AddressSpace;

    const PARENT: u64 = 0xF0_24;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => {
            teardown_process_state();
            return TestResult::Fail("AddressSpace::new_for_user");
        }
    };
    *PROC_PARENT_AS.lock() = Some(parent_as);
    install_address_space_lookup(lookup_proc_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
    let child_pid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("fork failed");
        }
    };

    // The PID→TaskId mapping must exist after fork.
    let child_task_raw = match crate::handlers::pid_to_task_raw(child_pid) {
        Some(t) => t,
        None => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("no PID→TaskId mapping registered by fork");
        }
    };

    // Reverse direction must also work.
    match crate::handlers::task_to_pid_raw(child_task_raw) {
        Some(p) if p == child_pid => {}
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("task_to_pid_raw reverse lookup incorrect");
        }
    }

    // The TaskId must correspond to an actual scheduler slot.
    let child_tid_obj = narf_scheduler::TaskId(child_task_raw);
    if narf_scheduler::address_space_of(child_tid_obj).is_none() {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("child has no AS in scheduler after fork");
    }

    // The ProcessId and TaskId must be distinct values (the whole
    // point of this fix — they could be equal by coincidence, but
    // the system must not *require* them to be equal).
    // We just verify the mapping records them as independent fields.
    // (On a freshly reset queue they may happen to be equal; that's
    // fine — what we're testing is the code path, not the values.)
    let _ = (child_pid, child_task_raw); // both valid, independently tracked

    teardown_process_state();
    *PROC_PARENT_AS.lock() = None;
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_wave38_fork_registers_mapping);

/// Smoke 25: wait4 returns child ProcessId (user-visible) not TaskId.
/// The child's ProcessId is what the parent's fork() returned; the
/// wait4 reap must echo that same value back.
#[cfg(target_arch = "x86_64")]
fn smoke_wave38_wait4_returns_child_process_id() -> TestResult {
    use narf_memory::AddressSpace;

    const PARENT: u64 = 0xF0_25;
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    setup_process_state(PARENT);

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => {
            teardown_process_state();
            return TestResult::Fail("AddressSpace::new_for_user");
        }
    };
    *PROC_PARENT_AS.lock() = Some(parent_as);
    install_address_space_lookup(lookup_proc_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Fork → child_pid (ProcessId).
    let mut ctx = StubCtx { args: SyscallArgs::default(), ret: None };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
    let child_pid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("fork failed");
        }
    };
    let child_task_raw = match crate::handlers::pid_to_task_raw(child_pid) {
        Some(t) => t,
        None => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("no PID→TaskId mapping");
        }
    };

    // Verify ProcessId != TaskId here; if they happen to be equal on
    // this run we skip the "distinctness" sub-check but keep going.
    let ids_differ = child_pid != child_task_raw;

    // Simulate child exit via notify_task_exited(ProcessId).
    crate::user_task::notify_task_exited(child_pid);

    // wait4 by the parent should return the child's ProcessId.
    let mut status: i32 = -1;
    LOOKUP_TASK.store(PARENT, Ordering::Relaxed);
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64, // any child
            arg1: &mut status as *mut i32 as u64,
            arg2: 1, // WNOHANG
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    let reaped = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            teardown_process_state();
            *PROC_PARENT_AS.lock() = None;
            return TestResult::Fail("wait4 did not return OK");
        }
    };

    // Reaped value must equal the child's ProcessId.
    if reaped != child_pid {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("wait4 returned TaskId instead of ProcessId");
    }

    // If ProcessId and TaskId differ, verify wait4 did NOT return TaskId.
    if ids_differ && reaped == child_task_raw {
        teardown_process_state();
        *PROC_PARENT_AS.lock() = None;
        return TestResult::Fail("wait4 returned TaskId when ProcessId != TaskId");
    }

    teardown_process_state();
    *PROC_PARENT_AS.lock() = None;
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/process", smoke_wave38_wait4_returns_child_process_id);

/// Smoke 26: on_child_exit fires correctly even when the child's
/// ProcessId and TaskId are explicitly mismatched (injected directly
/// into the mapping table, bypassing fork's counter alignment).
fn smoke_wave38_on_child_exit_with_mismatched_ids() -> TestResult {
    use crate::handlers::{
        __test_inject_parent_of, __test_wait_reset, pid_to_task_raw,
        register_pid_task_mapping, signal_pending_of, wait_init,
    };

    const PARENT_TASK: u64 = 0xAA01; // parent's "TaskId" (current_task_id() value)
    const CHILD_PID: u64 = 0xBB05;   // child's ProcessId (alloc_pid() value)
    const CHILD_TASK: u64 = 0xCC99;  // child's TaskId (spawn_user() value) — different!

    crate::syscall::__test_clear_global();
    crate::handlers::__test_wait_reset();
    crate::handlers::__test_sigaction_reset();
    crate::sigaction_init();
    crate::signal_init();
    wait_init();

    // Directly register the mismatched mapping.
    register_pid_task_mapping(CHILD_PID, CHILD_TASK);

    // Register CHILD_PID → PARENT_TASK in the parent-of table (as
    // sys_fork would do using child_pid.raw() as key).
    __test_inject_parent_of(CHILD_PID, PARENT_TASK);

    // Verify lookup works in both directions.
    match pid_to_task_raw(CHILD_PID) {
        Some(t) if t == CHILD_TASK => {}
        _ => {
            crate::handlers::__test_wait_reset();
            crate::handlers::__test_sigaction_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("pid_to_task_raw lookup failed for injected mapping");
        }
    }

    // Fire the exit observer with the child's ProcessId.
    crate::user_task::notify_task_exited(CHILD_PID);

    // on_child_exit must have pushed (CHILD_PID, status) into
    // PENDING_EXITS[PARENT_TASK] and set SIGCHLD pending on PARENT_TASK.
    let sigchld_pending = signal_pending_of(PARENT_TASK);
    const SIGCHLD: u32 = 17;
    if sigchld_pending & (1 << SIGCHLD) == 0 {
        crate::handlers::__test_wait_reset();
        crate::handlers::__test_sigaction_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("SIGCHLD not pending on parent after child exit");
    }

    // wait4 from PARENT_TASK should reap CHILD_PID.
    LOOKUP_TASK.store(PARENT_TASK, Ordering::Relaxed);
    install_task_id_lookup(lookup_task_shim);

    let mut status: i32 = -1;
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,
            arg1: &mut status as *mut i32 as u64,
            arg2: 1, // WNOHANG
            arg3: 0, arg4: 0, arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut ctx);
    let reaped = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            crate::handlers::__test_wait_reset();
            crate::handlers::__test_sigaction_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("wait4 did not return OK");
        }
    };
    if reaped != CHILD_PID {
        crate::handlers::__test_wait_reset();
        crate::handlers::__test_sigaction_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("wait4 returned wrong value — expected CHILD_PID");
    }
    // Must not return CHILD_TASK (the internal scheduler ID).
    if reaped == CHILD_TASK {
        crate::handlers::__test_wait_reset();
        crate::handlers::__test_sigaction_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("wait4 returned TaskId instead of ProcessId");
    }

    crate::handlers::__test_wait_reset();
    crate::handlers::__test_sigaction_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/process", smoke_wave38_on_child_exit_with_mismatched_ids);
