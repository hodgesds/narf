//! Smokes for the polling-idle wake protocol and wake-time placement.
//!
//! The protocol checks drive one CPU index that no core ever ran on, so no
//! live executor owns its idle word, halted flag or notification, and every
//! assertion is deterministic. The reschedule-IPI hook is interposed only for
//! that index; IPIs to real CPUs still go out while a check runs.
//!
//! Registered under `scheduler/idle_poll`.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::percpu::MAX_CPUS;

use crate::{
    idle_word_arm, idle_word_disarm, kick_word_if_polling, notify_wake_cpu, resched_remote,
    resched_remote_force, CPU_HALTED, IDLE_EXEC, IDLE_KICKED, IDLE_POLLING, IDLE_WORD,
    NEED_RESCHED, RESCHED_IPI_HOOK, WAKE_PENDING,
};

/// Linux `set_nr_if_polling` on one word: only a polling idle is kicked by a
/// store, a kick is idempotent, and leaving idle consumes it.
fn smoke_idle_poll_kick_word_protocol() -> TestResult {
    let word = AtomicU32::new(0);
    if kick_word_if_polling(&word) || word.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("a running CPU was treated as polling");
    }
    word.store(IDLE_EXEC, Ordering::SeqCst);
    if kick_word_if_polling(&word) || word.load(Ordering::SeqCst) != IDLE_EXEC {
        return TestResult::Fail("a HALT idle was kicked by a store instead of an IPI");
    }
    let armed = IDLE_EXEC | IDLE_POLLING;
    word.store(armed, Ordering::SeqCst);
    if !kick_word_if_polling(&word) || word.load(Ordering::SeqCst) != armed | IDLE_KICKED {
        return TestResult::Fail("a polling idle was not ended by the kick store");
    }
    if !kick_word_if_polling(&word) || word.load(Ordering::SeqCst) != armed | IDLE_KICKED {
        return TestResult::Fail("a repeated kick changed the word or asked for an IPI");
    }
    if word.swap(0, Ordering::SeqCst) != armed | IDLE_KICKED || kick_word_if_polling(&word) {
        return TestResult::Fail("leaving idle did not consume the kick and the polling flag");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/idle_poll", smoke_idle_poll_kick_word_protocol);

/// A CPU index outside every boot's CPU set: never online, never ran an
/// executor, so its per-CPU scheduler cells belong to the test.
fn ghost_cpu() -> Option<usize> {
    let ever = narf_lib::smp::ever_online_bitmap() | narf_lib::smp::online_bitmap();
    (1..MAX_CPUS).rev().find(|cpu| ever & (1u64 << cpu) == 0)
}

static GHOST: AtomicUsize = AtomicUsize::new(usize::MAX);
static GHOST_IPIS: AtomicU64 = AtomicU64::new(0);
static FORWARD_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Count IPIs aimed at the ghost CPU; forward every other one unchanged.
fn counting_hook(cpu: u32) {
    if cpu as usize == GHOST.load(Ordering::Acquire) {
        GHOST_IPIS.fetch_add(1, Ordering::AcqRel);
        return;
    }
    let forward = FORWARD_HOOK.load(Ordering::Acquire);
    if forward != 0 {
        // SAFETY: saved from RESCHED_IPI_HOOK, which only holds `fn(u32)`.
        let f: fn(u32) = unsafe { core::mem::transmute::<usize, fn(u32)>(forward) };
        f(cpu);
    }
}

struct GhostCpu {
    cpu: usize,
}

impl GhostCpu {
    fn install() -> Option<Self> {
        let cpu = ghost_cpu()?;
        GHOST.store(cpu, Ordering::Release);
        GHOST_IPIS.store(0, Ordering::Release);
        let previous = RESCHED_IPI_HOOK.load(Ordering::Acquire);
        FORWARD_HOOK.store(previous, Ordering::Release);
        RESCHED_IPI_HOOK.store(counting_hook as usize, Ordering::Release);
        let ghost = Self { cpu };
        ghost.state(false, 0);
        Some(ghost)
    }

    /// Set the ghost's halted flag and idle word; clear its notifications.
    fn state(&self, halted: bool, word: u32) {
        CPU_HALTED[self.cpu].store(halted, Ordering::SeqCst);
        IDLE_WORD[self.cpu].0.store(word, Ordering::SeqCst);
        WAKE_PENDING[self.cpu].store(false, Ordering::SeqCst);
        NEED_RESCHED[self.cpu].store(false, Ordering::SeqCst);
        GHOST_IPIS.store(0, Ordering::SeqCst);
    }

    fn ipis(&self) -> u64 {
        GHOST_IPIS.load(Ordering::SeqCst)
    }

    fn word(&self) -> u32 {
        IDLE_WORD[self.cpu].0.load(Ordering::SeqCst)
    }
}

impl Drop for GhostCpu {
    fn drop(&mut self) {
        RESCHED_IPI_HOOK.store(FORWARD_HOOK.load(Ordering::Acquire), Ordering::Release);
        GHOST.store(usize::MAX, Ordering::Release);
        self.state(false, 0);
    }
}

/// Linux `ttwu_queue_wakelist` + `send_call_function_single_ipi`: a batch of
/// wakes to an idle CPU costs at most one IPI, none if it polls; a busy CPU
/// gets one for the batch's first entry. A CPU halted outside its executor
/// (the `block_on` bridge) does not consume the notification and keeps
/// getting a kick per wake.
fn smoke_idle_poll_wake_batch_ipi_counts() -> TestResult {
    let Some(ghost) = GhostCpu::install() else {
        return TestResult::Skip("every CPU index is in use");
    };
    let cpu = ghost.cpu as u32;
    let wake3 = || {
        for _ in 0..3 {
            notify_wake_cpu(cpu);
        }
    };

    // Polling in executor idle: no IPI at all, the word is kicked.
    ghost.state(true, IDLE_EXEC | IDLE_POLLING);
    wake3();
    if ghost.ipis() != 0 {
        return TestResult::Fail("a wake IPI'd a CPU polling in idle");
    }
    if ghost.word() & IDLE_KICKED == 0 || !WAKE_PENDING[ghost.cpu].load(Ordering::SeqCst) {
        return TestResult::Fail("a polling CPU was neither kicked nor notified");
    }

    // HALT in executor idle: one IPI for the batch.
    ghost.state(true, IDLE_EXEC);
    wake3();
    if ghost.ipis() != 1 {
        return TestResult::Fail("a batch of wakes to a halted CPU did not cost exactly one IPI");
    }

    // Halted in a `block_on` bridge: every wake must still kick it.
    ghost.state(true, 0);
    notify_wake_cpu(cpu);
    notify_wake_cpu(cpu);
    if ghost.ipis() != 2 {
        return TestResult::Fail("a bridge-halted CPU was not kicked for every wake");
    }

    // Busy: one IPI for the batch's first entry.
    ghost.state(false, 0);
    wake3();
    if ghost.ipis() != 1 {
        return TestResult::Fail("a batch of wakes to a busy CPU did not cost exactly one IPI");
    }

    // Reschedule requests (Linux `resched_curr` → `set_nr_and_not_polling`).
    ghost.state(true, IDLE_EXEC | IDLE_POLLING);
    resched_remote(cpu);
    resched_remote_force(cpu);
    if ghost.ipis() != 0 || ghost.word() & IDLE_KICKED == 0 {
        return TestResult::Fail("a reschedule request IPI'd a polling CPU");
    }
    if !NEED_RESCHED[ghost.cpu].load(Ordering::SeqCst) {
        return TestResult::Fail("a polling CPU lost the reschedule request");
    }
    ghost.state(true, IDLE_EXEC);
    resched_remote(cpu);
    resched_remote(cpu);
    if ghost.ipis() != 1 {
        return TestResult::Fail(
            "reschedule requests to a halted CPU did not cost exactly one IPI",
        );
    }
    ghost.state(false, 0);
    resched_remote_force(cpu);
    if ghost.ipis() != 1 {
        return TestResult::Fail("a forced reschedule did not interrupt a busy CPU");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/idle_poll", smoke_idle_poll_wake_batch_ipi_counts);

/// No lost wakeup when a wake races the idle commit. The executor's commit is
/// replayed step by step on the ghost CPU (arm the idle word, publish halted,
/// fence, consume `WAKE_PENDING`, enter, leave), with one wake injected at
/// every step, for a polling and a HALT idle. Each interleaving must end with
/// the CPU woken: it saw the notification at its commit check, or its
/// post-MONITOR recheck saw the kick, or an IPI was sent, or the wake landed
/// after it left idle and is still pending for its next executor round.
fn smoke_idle_poll_commit_race_never_loses_a_wake() -> TestResult {
    let Some(ghost) = GhostCpu::install() else {
        return TestResult::Skip("every CPU index is in use");
    };
    let cpu = ghost.cpu;
    for polls in [true, false] {
        for wake_at in 0..5 {
            ghost.state(false, 0);
            let mut woken = false;
            let inject = |step: usize| {
                if step == wake_at {
                    notify_wake_cpu(cpu as u32);
                }
            };
            inject(0);
            let armed = idle_word_arm(cpu, polls);
            CPU_HALTED[cpu].store(true, Ordering::SeqCst);
            core::sync::atomic::fence(Ordering::SeqCst);
            inject(1);
            if WAKE_PENDING[cpu].swap(false, Ordering::SeqCst) {
                woken = true;
            } else {
                inject(2);
                // `enter_idle`: a polling state waits only while the word still
                // holds `armed` after MONITOR; HALT waits for an interrupt.
                let would_sleep = if polls {
                    IDLE_WORD[cpu].0.load(Ordering::SeqCst) == armed
                } else {
                    ghost.ipis() == 0
                };
                woken |= !would_sleep;
                inject(3);
            }
            CPU_HALTED[cpu].store(false, Ordering::SeqCst);
            idle_word_disarm(cpu);
            inject(4);
            // A wake that found the CPU awake leaves WAKE_PENDING for the round.
            woken |= ghost.ipis() != 0 || WAKE_PENDING[cpu].load(Ordering::SeqCst);
            if !woken {
                return TestResult::Fail("a wake racing the idle commit was lost");
            }
            if (1..=2).contains(&wake_at) && polls && ghost.ipis() != 0 {
                return TestResult::Fail("a wake before a polling idle's MONITOR sent an IPI");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/idle_poll",
    smoke_idle_poll_commit_race_never_loses_a_wake
);

/// Linux `wake_affine_idle`: an idle waker that shares a cache with the
/// wakee's busy previous CPU takes the wake itself (a local enqueue, no IPI);
/// a busy waker, or one in another LLC, does not.
fn smoke_idle_poll_wake_affine_idle_waker() -> TestResult {
    use crate::affinity::CpuId;
    let online = narf_lib::smp::online_bitmap();
    let cpus: alloc::vec::Vec<u32> = (0..MAX_CPUS as u32)
        .filter(|c| online & (1u64 << c) != 0)
        .collect();
    // Linux `cpus_share_cache`: same known LLC, or (LLC unknown) same node.
    let share = |a: u32, b: u32| match (
        crate::steal::llc_id(CpuId(a)),
        crate::steal::llc_id(CpuId(b)),
    ) {
        (Some(x), Some(y)) => x == y,
        _ => narf_acpi::cpu_node(a) == narf_acpi::cpu_node(b),
    };
    let same = cpus.iter().find_map(|&a| {
        cpus.iter()
            .find(|&&b| b != a && share(a, b))
            .map(|&b| (a, b))
    });
    let Some((prev, waker)) = same else {
        return TestResult::Skip("needs two online CPUs sharing a cache");
    };
    let is_online = |c: CpuId| online & (1u64 << c.0) != 0;
    let allowed = |_: CpuId| true;
    // Only the waker is idle; prev and everyone else are busy.
    let only_waker = |c: CpuId| c.0 == waker;
    if crate::policy::select_idle_sibling(
        CpuId(prev),
        CpuId(waker),
        &is_online,
        &only_waker,
        &allowed,
    ) != Some(CpuId(waker))
    {
        return TestResult::Fail("an idle same-LLC waker did not take the wake");
    }
    let nobody = |_: CpuId| false;
    if crate::policy::select_idle_sibling(CpuId(prev), CpuId(waker), &is_online, &nobody, &allowed)
        .is_some()
    {
        return TestResult::Fail("a busy waker took the wake with no idle CPU");
    }
    let far = cpus.iter().copied().find(|&c| !share(c, prev));
    if let Some(far) = far {
        let only_far = |c: CpuId| c.0 == far;
        let picked = crate::policy::select_idle_sibling(
            CpuId(prev),
            CpuId(far),
            &is_online,
            &only_far,
            &allowed,
        );
        // The far waker may still be chosen by the outer (any idle CPU) scan,
        // but never through the wake-affine shortcut ahead of a same-LLC idle
        // CPU: give prev's LLC an idle sibling and it must win.
        let sibling_or_far = |c: CpuId| c.0 == far || c.0 == waker;
        let picked_with_sibling = crate::policy::select_idle_sibling(
            CpuId(prev),
            CpuId(far),
            &is_online,
            &sibling_or_far,
            &allowed,
        );
        if picked_with_sibling != Some(CpuId(waker)) || picked.is_none() {
            return TestResult::Fail("a waker in another LLC pre-empted an idle same-LLC CPU");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/idle_poll",
    smoke_idle_poll_wake_affine_idle_waker
);
