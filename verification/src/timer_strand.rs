//! Timer expiry with one CPU stuck, on real CPUs under tickless idle.
//!
//! These run with the production clock setup the kernel-test boot leaves
//! out: the HPET/LAPIC timer pump installs the clockevent programmer
//! (without it every sleep self-wakes and polls), and user-task SMP is on so
//! idle CPUs halt with interrupts enabled instead of spin-polling.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::Poll;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::percpu::MAX_CPUS;
use narf_scheduler::{Affinity, CpuId, TaskSpec};

/// How long a timer may fire after its expiry before it counts as delayed
/// by the stuck CPU: far above an interrupt round trip under an emulator,
/// far below the stuck time.
const TIMER_LATE_BOUND_NS: u64 = 100_000_000;
/// Upper bound on how long the stuck CPU stays stuck if nobody releases it.
const HOLD_LIMIT_NS: u64 = 3_000_000_000;

/// Spin until `done` holds or `ns` elapse.
fn wait_for(ns: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(ns));
    loop {
        if done() {
            return true;
        }
        if narf_time::now_cycles() >= deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Every AP that really came up, as a mask.
fn live_aps() -> u64 {
    let me = narf_lib::percpu::current_cpu();
    narf_lib::smp::ever_online_bitmap() & narf_lib::smp::online_bitmap() & !(1u64 << me)
}

fn pinned(cpu: usize) -> TaskSpec {
    TaskSpec {
        affinity: Affinity::pinned(CpuId(cpu as u32)),
        ..TaskSpec::kernel_any()
    }
}

/// Production timer setup for the duration of a test; [`Self::restore`]
/// undoes the user-task SMP and tickless switches.
struct ProdTimers {
    aps: u64,
    user_smp: bool,
}

impl ProdTimers {
    /// `None` when the boot has no programmable clockevent or no AP stops
    /// its tick.
    fn enter(aps: u64) -> Option<Self> {
        if !narf_interrupts::x86_64::timer_pump::is_initialised()
            && narf_interrupts::x86_64::timer_pump::init().is_err()
        {
            return None;
        }
        let this = Self {
            aps,
            user_smp: narf_scheduler::__test_set_user_task_smp(true),
        };
        narf_time::set_nohz_idle_enabled(true);
        // An idle AP stops its tick at its next idle entry; let every AP
        // pass through one.
        this.kick_aps();
        let tickless = wait_for(1_000_000_000, || {
            (0..MAX_CPUS).any(|cpu| aps & (1u64 << cpu) != 0 && !narf_time::periodic_tick_wanted(cpu))
        });
        if !tickless {
            this.restore();
            return None;
        }
        Some(this)
    }

    /// Every AP dispatches once.
    fn kick_aps(&self) {
        static WOKE: AtomicUsize = AtomicUsize::new(0);
        WOKE.store(0, Ordering::Release);
        let mut count = 0;
        for cpu in (0..MAX_CPUS).filter(|cpu| self.aps & (1u64 << cpu) != 0) {
            narf_scheduler::spawn_with_spec(
                async {
                    WOKE.fetch_add(1, Ordering::AcqRel);
                },
                pinned(cpu),
            );
            count += 1;
        }
        let _ = wait_for(1_000_000_000, || WOKE.load(Ordering::Acquire) == count);
    }

    fn restore(self) {
        narf_time::set_nohz_idle_enabled(false);
        narf_scheduler::__test_set_user_task_smp(self.user_smp);
        // Every AP dispatches once, so its periodic tick runs again.
        self.kick_aps();
    }
}

/// A sleeper on AP `sleeper` fires on time while AP `held` — which queued
/// an earlier timer first, so it was the CPU whose clockevent carried every
/// timer — is stuck. `masked`: the stuck CPU has interrupts off (takes no
/// interrupt at all); otherwise it spins with interrupts on but never
/// returns to its executor. Every other AP idles with its tick stopped and
/// this CPU only spins.
fn timer_fires_behind_stuck_cpu(masked: bool) -> TestResult {
    static STARTED: AtomicBool = AtomicBool::new(false);
    static RELEASE: AtomicBool = AtomicBool::new(false);
    static DONE: AtomicBool = AtomicBool::new(false);
    static MASKED: AtomicBool = AtomicBool::new(false);
    static WOKE_NS: AtomicU64 = AtomicU64::new(0);
    static WOKE_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
    // The held CPU's timer is far enough out that the sleeper's CPU stops
    // its tick when it idles; the sleeper's is later still.
    const EARLY_NS: u64 = 200_000_000;
    const SLEEP_NS: u64 = 300_000_000;
    let live = live_aps();
    let mut aps = (0..MAX_CPUS).filter(|cpu| live & (1u64 << cpu) != 0);
    let (Some(held), Some(sleeper)) = (aps.next(), aps.next()) else {
        return TestResult::Skip("needs two APs that really came up");
    };
    let Some(prod) = ProdTimers::enter(live) else {
        return TestResult::Skip("no programmable tickless clockevent");
    };
    STARTED.store(false, Ordering::Release);
    RELEASE.store(false, Ordering::Release);
    DONE.store(false, Ordering::Release);
    MASKED.store(masked, Ordering::Release);
    WOKE_NS.store(0, Ordering::Release);
    WOKE_CPU.store(usize::MAX, Ordering::Release);
    narf_scheduler::spawn_with_spec(
        async {
            let mut early = narf_time::sleep_ns(EARLY_NS);
            core::future::poll_fn(|cx| {
                let _ = Pin::new(&mut early).poll(cx);
                Poll::Ready(())
            })
            .await;
            let hold = || {
                STARTED.store(true, Ordering::Release);
                wait_for(HOLD_LIMIT_NS, || RELEASE.load(Ordering::Acquire));
            };
            if MASKED.load(Ordering::Acquire) {
                narf_lib::sync::without_interrupts(hold);
            } else {
                hold();
            }
            drop(early);
            DONE.store(true, Ordering::Release);
        },
        pinned(held),
    );
    if !wait_for(1_000_000_000, || STARTED.load(Ordering::Acquire)) {
        RELEASE.store(true, Ordering::Release);
        prod.restore();
        return TestResult::Fail("the AP did not start its stuck section");
    }
    let start = narf_time::monotonic_ns();
    narf_scheduler::spawn_with_spec(
        async {
            narf_time::sleep_ns(SLEEP_NS).await;
            WOKE_NS.store(narf_time::monotonic_ns(), Ordering::Release);
            WOKE_CPU.store(narf_lib::percpu::current_cpu(), Ordering::Release);
        },
        pinned(sleeper),
    );
    // Halfway through the sleep the sleeper's CPU must be tickless-idle, or
    // the test does not test what it is named for.
    let _ = wait_for(SLEEP_NS / 2, || false);
    let idle = narf_scheduler::__test_cpu_halted(sleeper)
        && !narf_time::periodic_tick_wanted(sleeper);
    let woke = wait_for(SLEEP_NS + 4 * TIMER_LATE_BOUND_NS, || {
        WOKE_NS.load(Ordering::Acquire) != 0
    });
    let still_stuck = !DONE.load(Ordering::Acquire);
    RELEASE.store(true, Ordering::Release);
    let released = wait_for(1_000_000_000, || DONE.load(Ordering::Acquire));
    let woke_at = WOKE_NS.load(Ordering::Acquire);
    let woke_on = WOKE_CPU.load(Ordering::Acquire);
    // Let a late sleeper finish before restoring the boot's timer setup.
    let _ = wait_for(1_000_000_000, || WOKE_NS.load(Ordering::Acquire) != 0);
    prod.restore();
    if !released {
        return TestResult::Fail("the stuck section never finished");
    }
    if !idle {
        return TestResult::Skip("the sleeper's CPU did not go tickless-idle");
    }
    if !woke {
        return TestResult::Fail("a sleeper's timer waited for a stuck CPU");
    }
    if !still_stuck {
        return TestResult::Fail("the AP left its stuck section before the timer fired");
    }
    if woke_on != sleeper {
        return TestResult::Fail("the sleeper ran on a CPU it was not pinned to");
    }
    if woke_at.saturating_sub(start) > SLEEP_NS + TIMER_LATE_BOUND_NS {
        return TestResult::Fail("a sleeper's timer fired late behind a stuck CPU");
    }
    TestResult::Pass
}

/// The stuck CPU has interrupts masked: no timer interrupt reaches it.
fn smoke_timer_fires_while_other_cpu_masked() -> TestResult {
    timer_fires_behind_stuck_cpu(true)
}
kernel_test_in!(
    "scheduler/strand/timer",
    smoke_timer_fires_while_other_cpu_masked
);

/// The stuck CPU takes interrupts but never runs its executor, so nothing
/// it queues for its executor is woken.
fn smoke_timer_fires_while_other_cpu_busy() -> TestResult {
    timer_fires_behind_stuck_cpu(false)
}
kernel_test_in!(
    "scheduler/strand/timer",
    smoke_timer_fires_while_other_cpu_busy
);
