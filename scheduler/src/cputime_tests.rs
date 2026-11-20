//! Kernel tests for the per-CPU / per-task CPU-time accounting
//! (`scheduler/cputime`).
//!
//! These drive the accounting's real transition points — the dispatch
//! bracket `poll_with_domain` uses, the trap-boundary user entry/exit the
//! frame hooks call, the idle bracket, the hard-IRQ guard and the softirq
//! scope — on the CPU the test runs on, and check both the CPU's columns and
//! the charged task. Ring-3 coverage (a real user busy loop and a real
//! syscall loop through the SYSCALL/IRET hooks) lives in
//! `verification/cputime`.

use core::fmt::Write as _;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::cputime::{self, CpuTimes, TaskCputime};

const MS: u64 = 1_000_000;

fn spin_ns(ns: u64) {
    let end = narf_time::monotonic_ns() + ns;
    while narf_time::monotonic_ns() < end {
        core::hint::spin_loop();
    }
}

/// Run `body` with interrupts masked on one CPU, returning that CPU's
/// columns before and after, and the wall time the body took.
fn on_this_cpu(body: impl FnOnce()) -> (CpuTimes, CpuTimes, u64) {
    narf_lib::sync::without_interrupts(|| {
        let cpu = narf_lib::percpu::current_cpu();
        let before = cputime::cpu_times(cpu);
        let t0 = narf_time::monotonic_ns();
        body();
        let wall = narf_time::monotonic_ns() - t0;
        (before, cputime::cpu_times(cpu), wall)
    })
}

/// `body` runs as task `task`'s dispatch, as the executor brackets a poll.
fn dispatched(task: &TaskCputime, softirq: bool, body: impl FnOnce()) {
    let dispatcher = cputime::dispatch_enter(task, softirq);
    body();
    cputime::dispatch_exit(dispatcher);
}

/// `value` is `expected` within `slack_ns` either way.
fn near(value: u64, expected: u64, slack_ns: u64) -> bool {
    value + slack_ns >= expected && value <= expected + slack_ns
}

fn smoke_cputime_kernel_work_is_system_time() -> TestResult {
    let task = TaskCputime::new();
    let (before, after, wall) = on_this_cpu(|| dispatched(&task, false, || spin_ns(5 * MS)));
    let t = task.sample();
    if t.utime_ns != 0 {
        return TestResult::Fail("kernel work was charged as user time");
    }
    if !near(t.stime_ns, wall, MS) {
        return TestResult::Fail("a task's kernel work was not charged to its stime");
    }
    if after.system.saturating_sub(before.system) + MS < t.stime_ns {
        return TestResult::Fail("a task's stime is missing from the CPU's system column");
    }
    if after.user != before.user {
        return TestResult::Fail("kernel work moved the CPU's user column");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/cputime",
    smoke_cputime_kernel_work_is_system_time
);

fn smoke_cputime_user_spans_and_nice() -> TestResult {
    let task = TaskCputime::new();
    let user_span = |task: &TaskCputime| {
        dispatched(task, false, || {
            // What the trap hooks do around a user-mode run.
            // SAFETY: `on_this_cpu` masks interrupts.
            unsafe { cputime::user_enter_irqs_off() };
            spin_ns(5 * MS);
            // SAFETY: as above.
            unsafe { cputime::user_exit_irqs_off() };
        })
    };
    let (before, after, wall) = on_this_cpu(|| user_span(&task));
    let t = task.sample();
    if !near(t.utime_ns, wall, MS) || t.stime_ns > MS {
        return TestResult::Fail("a user-mode span was not charged to utime");
    }
    if after.user.saturating_sub(before.user) + MS < t.utime_ns || after.nice != before.nice {
        return TestResult::Fail("user time is missing from the CPU's user column");
    }
    if after.system.saturating_sub(before.system) > MS {
        return TestResult::Fail("a user-mode span leaked into system time");
    }
    // `account_user_time`: a task with positive nice is the nice column.
    task.set_nice(5);
    let (before, after, _) = on_this_cpu(|| user_span(&task));
    if after.nice.saturating_sub(before.nice) + MS < 5 * MS
        || after.user.saturating_sub(before.user) > MS
    {
        return TestResult::Fail("a positive-nice task's user time is not in the nice column");
    }
    if task.sample().utime_ns < t.utime_ns + 4 * MS {
        return TestResult::Fail("a niced task lost its own utime");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/cputime", smoke_cputime_user_spans_and_nice);

fn smoke_cputime_idle_charges_no_task() -> TestResult {
    let task = TaskCputime::new();
    let idle_span = || {
        dispatched(&task, false, || {
            let idle = cputime::idle_enter();
            spin_ns(5 * MS);
            cputime::idle_exit(idle);
        })
    };
    let (before, after, _) = on_this_cpu(idle_span);
    if task.sample().total_ns() > MS {
        return TestResult::Fail("idle time was charged to the task that waited");
    }
    if after.idle.saturating_sub(before.idle) + MS < 5 * MS
        || after.system.saturating_sub(before.system) > MS
    {
        return TestResult::Fail("a halted span is missing from the idle column");
    }
    // `get_cpu_iowait_time_us`: idle while a task waits for I/O is iowait.
    let mut wait = narf_lib::kstat::IoWait::new();
    wait.block();
    let (before, after, _) = on_this_cpu(idle_span);
    wait.wake();
    if after.iowait.saturating_sub(before.iowait) + MS < 5 * MS
        || after.idle.saturating_sub(before.idle) > MS
    {
        return TestResult::Fail("idle with a blocked I/O waiter is not iowait");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/cputime", smoke_cputime_idle_charges_no_task);

fn smoke_cputime_hard_irq_time_is_irq_not_task() -> TestResult {
    let task = TaskCputime::new();
    let mut during = (0u64, 0u64);
    let (before, after, wall) = on_this_cpu(|| {
        dispatched(&task, false, || {
            let irq = crate::interrupt_account_enter(crate::InterruptKind::HardIrq);
            spin_ns(5 * MS);
            // A remote reader inside the handler already sees interrupt time.
            during = (
                task.sample().stime_ns,
                cputime::cpu_times(narf_lib::percpu::current_cpu()).irq,
            );
            drop(irq);
        })
    });
    let stime = task.sample().stime_ns;
    if stime > MS || during.0 > MS {
        return TestResult::Fail("hard-IRQ time was charged to the interrupted task");
    }
    if after.irq.saturating_sub(before.irq) + MS < wall
        || during.1.saturating_sub(before.irq) + MS < 5 * MS
    {
        return TestResult::Fail("hard-IRQ time is missing from the irq column");
    }
    if after.system.saturating_sub(before.system) > MS {
        return TestResult::Fail("hard-IRQ time leaked into system time");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/cputime",
    smoke_cputime_hard_irq_time_is_irq_not_task
);

fn smoke_cputime_softirq_scope_and_softirq_tasks() -> TestResult {
    use narf_lib::kstat::{softirq_count, softirq_enter, vector};
    let cpu = narf_lib::percpu::current_cpu();
    let task = TaskCputime::new();
    let timers = softirq_count(cpu, vector::TIMER);
    let (before, after, _) = on_this_cpu(|| {
        dispatched(&task, false, || {
            let softirq = softirq_enter(vector::TIMER);
            spin_ns(3 * MS);
            drop(softirq);
        })
    });
    if softirq_count(cpu, vector::TIMER) != timers + 1 {
        return TestResult::Fail("a softirq handler run was not counted");
    }
    if task.sample().total_ns() > MS {
        return TestResult::Fail("softirq work was charged to the task it interrupted");
    }
    if after.softirq.saturating_sub(before.softirq) + MS < 3 * MS
        || after.system.saturating_sub(before.system) > MS
    {
        return TestResult::Fail("softirq handler time is missing from the softirq column");
    }
    // A NAPI-style poller (`WorkKind::SoftIrq`) is NET_RX, charged to itself
    // as ksoftirqd is.
    let poller = TaskCputime::new();
    let net_rx = softirq_count(cpu, vector::NET_RX);
    let (before, after, _) = on_this_cpu(|| dispatched(&poller, true, || spin_ns(3 * MS)));
    if softirq_count(cpu, vector::NET_RX) != net_rx + 1
        || poller.sample().stime_ns + MS < 3 * MS
        || after.softirq.saturating_sub(before.softirq) + MS < 3 * MS
    {
        return TestResult::Fail("a softirq-kind task is not NET_RX softirq time");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/cputime",
    smoke_cputime_softirq_scope_and_softirq_tasks
);

/// A stackful continuation preempted inside an idle bracket takes the idle
/// context with it: the executor that runs meanwhile is system time.
fn smoke_cputime_switched_out_continuation_keeps_its_context() -> TestResult {
    let task = TaskCputime::new();
    let mut idle_left = 0u64;
    let mut system_left = 0u64;
    let (before, after, _) = on_this_cpu(|| {
        dispatched(&task, false, || {
            // poll_to_yield: switch into the continuation.
            let executor = cputime::context_swap(cputime::FRESH_CONTEXT, &task);
            let idle = cputime::idle_enter();
            spin_ns(2 * MS);
            // Preempted inside the bracket: switch back to the executor.
            let saved = cputime::context_restore(executor);
            let mid = cputime::cpu_times(narf_lib::percpu::current_cpu());
            spin_ns(3 * MS);
            let resumed = cputime::cpu_times(narf_lib::percpu::current_cpu());
            idle_left = resumed.idle.saturating_sub(mid.idle);
            system_left = resumed.system.saturating_sub(mid.system);
            // Resumed later: the bracket is still open.
            let executor = cputime::context_swap(saved, &task);
            spin_ns(2 * MS);
            cputime::idle_exit(idle);
            cputime::context_restore(executor);
        })
    });
    if idle_left > MS || system_left + MS < 3 * MS {
        return TestResult::Fail("a switched-out idle bracket kept the CPU idle");
    }
    if after.idle.saturating_sub(before.idle) + MS < 4 * MS {
        return TestResult::Fail("the continuation's idle bracket lost its own time");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/cputime",
    smoke_cputime_switched_out_continuation_keeps_its_context
);

/// Every span lands in exactly one column, so a CPU's total tracks wall
/// time across a mix of contexts.
fn smoke_cputime_columns_track_elapsed() -> TestResult {
    let task = TaskCputime::new();
    let (before, after, wall) = on_this_cpu(|| {
        dispatched(&task, false, || {
            spin_ns(2 * MS);
            // SAFETY: masked by `on_this_cpu`.
            unsafe { cputime::user_enter_irqs_off() };
            spin_ns(2 * MS);
            // SAFETY: as above.
            unsafe { cputime::user_exit_irqs_off() };
            let idle = cputime::idle_enter();
            spin_ns(2 * MS);
            cputime::idle_exit(idle);
            let irq = crate::interrupt_account_enter(crate::InterruptKind::HardIrq);
            spin_ns(2 * MS);
            drop(irq);
        })
    });
    let accounted = after.total().saturating_sub(before.total());
    if !near(accounted, wall, wall / 20 + MS / 2) {
        return TestResult::Fail("a CPU's columns do not sum to the elapsed time");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/cputime", smoke_cputime_columns_track_elapsed);

fn smoke_cputime_context_switches_count_task_changes() -> TestResult {
    let a = TaskCputime::new();
    let b = TaskCputime::new();
    let mut switches = (0, 0);
    on_this_cpu(|| {
        let cpu = narf_lib::percpu::current_cpu();
        dispatched(&b, false, || {
            let start = cputime::cpu_context_switches(cpu);
            // b → a → b: two switches (`__schedule` counts `prev != next`).
            let back = cputime::context_swap(cputime::FRESH_CONTEXT, &a);
            cputime::context_restore(back);
            // Resuming the task that is already running is not a switch.
            let same = cputime::context_swap(cputime::FRESH_CONTEXT, &b);
            cputime::context_restore(same);
            switches.0 = cputime::cpu_context_switches(cpu) - start;
            // b → idle → b: two more.
            let idle = cputime::idle_enter();
            cputime::idle_exit(idle);
            switches.1 = cputime::cpu_context_switches(cpu) - start;
        });
    });
    if switches != (2, 4) {
        return TestResult::Fail("ctxt does not count each change of running task");
    }
    if cputime::nr_context_switches() < switches.1 {
        return TestResult::Fail("the system ctxt total misses a CPU's switches");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/cputime",
    smoke_cputime_context_switches_count_task_changes
);

/// The cost of one user↔kernel transition: the TSC read plus this CPU's
/// stores, interrupts masked. Reported, not gated: under QEMU the number is
/// the emulator's, not the hardware's. 31 batches of 4096 pairs; the median
/// batch is printed alongside the fastest and the 95th percentile.
fn smoke_cputime_transition_cost() -> TestResult {
    const BATCHES: usize = 31;
    const PAIRS: u64 = 4096;
    let task = TaskCputime::new();
    let mut per_transition = [0u64; BATCHES];
    on_this_cpu(|| {
        dispatched(&task, false, || {
            for slot in per_transition.iter_mut() {
                let t0 = narf_time::now_cycles();
                for _ in 0..PAIRS {
                    // SAFETY: masked by `on_this_cpu`.
                    unsafe {
                        cputime::user_enter_irqs_off();
                        cputime::user_exit_irqs_off();
                    }
                }
                *slot = (narf_time::now_cycles() - t0) / (2 * PAIRS);
            }
        })
    });
    per_transition.sort_unstable();
    let _ = writeln!(
        narf_console::Writer,
        "cputime: transition cost cycles min={} median={} p95={} ({} batches x {} pairs)",
        per_transition[0],
        per_transition[BATCHES / 2],
        per_transition[BATCHES * 95 / 100],
        BATCHES,
        PAIRS,
    );
    if task.sample().utime_ns == 0 {
        return TestResult::Fail("timed transitions charged nothing");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/cputime", smoke_cputime_transition_cost);
