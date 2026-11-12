//! Timer expiry with one CPU stuck, on real CPUs under tickless idle.
//!
//! These run with the production clock setup the kernel-test boot leaves
//! out: each CPU's LAPIC TSC-deadline clockevent is the hrtimer programmer
//! (without one every sleep self-wakes and polls), and user-task SMP is on so
//! idle CPUs halt with interrupts enabled instead of spin-polling. Both are
//! undone afterwards.

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
    installed_programmer: bool,
}

impl ProdTimers {
    /// `None` when the boot has no programmable clockevent or no AP stops
    /// its tick.
    fn enter(aps: u64) -> Option<Self> {
        let installed_programmer =
            narf_interrupts::x86_64::apic::__test_install_hrtimer_programmer();
        if !narf_time::hrtimer::arm_callback_installed() {
            return None;
        }
        let this = Self {
            aps,
            user_smp: narf_scheduler::__test_set_user_task_smp(true),
            installed_programmer,
        };
        narf_time::set_nohz_idle_enabled(true);
        // An idle AP stops its tick at its next idle entry; let every AP
        // pass through one.
        this.kick_aps();
        let tickless = wait_for(1_000_000_000, || {
            (0..MAX_CPUS)
                .any(|cpu| aps & (1u64 << cpu) != 0 && !narf_time::periodic_tick_wanted(cpu))
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
        if self.installed_programmer {
            narf_time::hrtimer::clear_arm_callback();
        }
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
    let idle =
        narf_scheduler::__test_cpu_halted(sleeper) && !narf_time::periodic_tick_wanted(sleeper);
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

static REMOTE_FIRED_NS: AtomicU64 = AtomicU64::new(0);
static REMOTE_FIRED_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);

fn remote_timer_fn(_: &narf_time::hrtimer::HrTimer) -> narf_time::hrtimer::HrtimerRestart {
    REMOTE_FIRED_NS.store(narf_time::monotonic_ns(), Ordering::Release);
    REMOTE_FIRED_CPU.store(narf_lib::percpu::current_cpu(), Ordering::Release);
    narf_time::hrtimer::HrtimerRestart::NoRestart
}

static REMOTE_TIMER: narf_time::hrtimer::HrTimer = narf_time::hrtimer::HrTimer::new(
    remote_timer_fn,
    narf_time::hrtimer::ClockId::Monotonic,
    narf_time::hrtimer::HrtimerMode::ABS_HARD,
);

/// A timer queued from here onto a tickless-idle AP's base, earlier than
/// anything that AP has programmed, sends exactly one re-program IPI and
/// fires on that AP on time (Linux `trigger_dyntick_cpu`): the AP's re-arm
/// is not lost across its idle entry. Then a cancel from here while the
/// timer is queued on the AP, and an unpinned restart from here, which
/// moves it to this CPU's base.
fn smoke_hrtimer_remote_earlier_event_rearms_by_ipi() -> TestResult {
    use narf_time::hrtimer::{self, HrtimerMode};
    const DELAY_NS: u64 = 10_000_000;
    let me = narf_lib::percpu::current_cpu();
    let live = live_aps();
    let Some(ap) = (0..MAX_CPUS).find(|cpu| live & (1u64 << cpu) != 0) else {
        return TestResult::Skip("needs a second CPU that really came up");
    };
    hrtimer::hrtimers_prepare_cpu(ap);
    let Some(prod) = ProdTimers::enter(live) else {
        return TestResult::Skip("no programmable tickless clockevent");
    };
    let quiet = wait_for(1_000_000_000, || {
        narf_scheduler::__test_cpu_halted(ap)
            && !narf_time::periodic_tick_wanted(ap)
            && hrtimer::next_event_ns_of(ap)
                .is_none_or(|n| n > narf_time::monotonic_ns() + 10 * DELAY_NS)
    });
    if !quiet {
        prod.restore();
        return TestResult::Skip("the AP never went tickless-idle without a near timer");
    }
    REMOTE_FIRED_NS.store(0, Ordering::Release);
    REMOTE_FIRED_CPU.store(usize::MAX, Ordering::Release);
    let kicks = hrtimer::remote_kicks();
    let start = narf_time::monotonic_ns();
    // SAFETY: the timer is a static.
    unsafe { hrtimer::hrtimer_start_on(&REMOTE_TIMER, ap, start + DELAY_NS, 0, HrtimerMode::ABS) };
    let sent = hrtimer::remote_kicks() - kicks;
    let fired = wait_for(DELAY_NS + 4 * TIMER_LATE_BOUND_NS, || {
        REMOTE_FIRED_NS.load(Ordering::Acquire) != 0
    });
    let fired_at = REMOTE_FIRED_NS.load(Ordering::Acquire);
    let fired_on = REMOTE_FIRED_CPU.load(Ordering::Acquire);

    let far = start + 1_000_000_000_000;
    // SAFETY: as above.
    unsafe { hrtimer::hrtimer_start_on(&REMOTE_TIMER, ap, far, 0, HrtimerMode::ABS) };
    let queued_remote = REMOTE_TIMER.is_queued() && REMOTE_TIMER.cpu() == Some(ap as u32);
    let cancelled = hrtimer::hrtimer_cancel(&REMOTE_TIMER) && !REMOTE_TIMER.is_queued();
    // SAFETY: as above.
    unsafe { hrtimer::hrtimer_start_range_ns(&REMOTE_TIMER, far, 0, HrtimerMode::ABS) };
    let moved_here = REMOTE_TIMER.cpu() == Some(me as u32);
    hrtimer::hrtimer_cancel(&REMOTE_TIMER);
    prod.restore();
    if sent != 1 {
        return TestResult::Fail("an earlier remote timer did not send exactly one IPI");
    }
    if !fired || fired_on != ap {
        return TestResult::Fail("a timer queued on an idle AP's base did not fire there");
    }
    if fired_at.saturating_sub(start) > DELAY_NS + TIMER_LATE_BOUND_NS {
        return TestResult::Fail("a timer queued on an idle AP's base fired late");
    }
    if !queued_remote || !cancelled {
        return TestResult::Fail("cancel from another CPU did not unlink the timer");
    }
    if !moved_here {
        return TestResult::Fail("an unpinned restart did not move the timer to this CPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand/timer",
    smoke_hrtimer_remote_earlier_event_rearms_by_ipi
);
