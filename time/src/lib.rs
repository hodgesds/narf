//! narf-time — monotonic clock + simple busy-sleep Future.
//!
//! Spec: `time/specification/spec.md`. Stage 1 subset: `Instant` built
//! from TSC (x86_64) / `CNTPCT_EL0` (aarch64), `now_monotonic` /
//! `now_monotonic_raw`, and a `sleep_cycles` Future. Wall-clock time,
//! timer wheel, NTP/PTP discipline — later stages.
//!
//! Units: Stage 1 speaks raw CPU cycles. Calibration to nanoseconds is
//! a Wave 3 task that requires consulting ACPI / FDT for the timer
//! frequency. A naive cycles-to-ns conversion under the 1 GHz assumption
//! is fine for demo purposes until calibration lands.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod clockevent;
pub mod hpet;
pub mod hrtimer;
pub mod ntp;
pub mod phc;
pub mod rtc;
pub mod timer;
pub mod timer_migration;
pub mod timerqueue;
pub mod wall;

mod hrtimer_tests;
mod sleep_tests;
mod tests;
mod timer_migration_tests;
mod timer_tests;
pub use wall::{
    adjust_wall_offset_ns, begin_leap_smear, cyc_to_ns_mult_shift, cycles_per_ns, cycles_to_ns,
    monotonic_ns, now_wall, ns_to_cycles, set_clock_hz, set_cycles_per_ns, set_wall_offset,
    set_wall_offset_uncapped, wall_offset_ns, WallClock, WallError, WallInstant,
};

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

/// Whether the periodic clock-event tick is delivered reliably.
///
/// `true` (the default) means the primary clock-event uses a self-rearming
/// one-shot source — TSC-deadline on x86_64 — whose IRQ is dependable, so a
/// CPU may halt indefinitely between deadlines and trust the next tick to
/// wake it.
///
/// `false` means no per-CPU tick was armed (no clockevent passed its probe,
/// or the selected one is a shared device that ticks only one CPU), so a
/// halted CPU might never be woken; the executor then spin-polls instead of
/// halting. A periodic per-CPU tick — the LAPIC InitialCount mode of CPUs
/// without TSC-deadline included — IS reliable: it wakes a halted CPU every
/// period, exactly as Linux's periodic-tick idle relies on. Whether the tick
/// can also be stopped for NOHZ idle is a separate, per-device question
/// (`clockevent::ClockEvent::can_stop_idle_tick`). See `scheduler`'s idle
/// path.
static TICK_RELIABLE: AtomicBool = AtomicBool::new(true);

/// Publish whether the selected primary clock-event tick is reliable.
/// Called by the clock-event backend once it has armed the primary tick.
pub fn set_tick_reliable(reliable: bool) {
    TICK_RELIABLE.store(reliable, Ordering::Release);
}

/// Read whether the primary clock-event tick is reliable. See
/// [`set_tick_reliable`].
#[inline]
pub fn tick_reliable() -> bool {
    TICK_RELIABLE.load(Ordering::Acquire)
}

/// Monotonic instant in raw CPU cycles. Operations are saturating to
/// prevent wrap-around panics on very-long uptimes.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub struct Instant(u64);

impl Instant {
    #[inline]
    pub fn now() -> Self {
        Self(now_cycles())
    }

    #[inline]
    pub fn as_cycles(self) -> u64 {
        self.0
    }

    /// Saturating add: if `other` would overflow past u64::MAX we cap.
    #[inline]
    pub fn plus_cycles(self, other: u64) -> Self {
        Self(self.0.saturating_add(other))
    }

    /// Number of cycles elapsed from `earlier` to `self`. Returns 0 if
    /// `earlier` is in the future (clock went backwards — should not
    /// happen but TSC hot-plug on AMD can produce glitches).
    #[inline]
    pub fn cycles_since(self, earlier: Instant) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// NO_HZ_IDLE per-CPU "wants the periodic scheduler tick" flag. Shared here
/// because the scheduler writes it (idle vs dispatch) and the arch timer ISR
/// reads it every tick. The scheduler clears it when a CPU goes idle so the ISR
/// stops re-anchoring the TSC-deadline to the periodic tick — the CPU then HLTs
/// until a real event (device IRQ, reschedule IPI, or an armed wheel deadline),
/// matching Linux tickless idle. Defaults `true`, so an unmanaged CPU ticks.
const TICK_MAX_CPUS: usize = narf_lib::percpu::MAX_CPUS;
static PERIODIC_TICK_WANTED: [core::sync::atomic::AtomicBool; TICK_MAX_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(true) }; TICK_MAX_CPUS];

/// Scheduler hook: `false` before halting an idle CPU, `true` on task dispatch.
#[inline]
pub fn set_periodic_tick_wanted(cpu: usize, wanted: bool) {
    if cpu < TICK_MAX_CPUS {
        PERIODIC_TICK_WANTED[cpu].store(wanted, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Arch-timer-ISR read: does `cpu` still want the periodic tick re-armed?
#[inline]
pub fn periodic_tick_wanted(cpu: usize) -> bool {
    cpu >= TICK_MAX_CPUS || PERIODIC_TICK_WANTED[cpu].load(core::sync::atomic::Ordering::Relaxed)
}

/// `local_softirq_pending()` for the timer softirqs: this CPU has raised
/// `TIMER_SOFTIRQ` (a due wheel base, or an idle CPU's global timers to
/// expire as timer migrator) or `HRTIMER_SOFTIRQ`, and the executor round
/// that runs them ([`hrtimer::hrtimer_run_softirq`]) has not run yet.
///
/// Linux runs pending softirqs at `irq_exit`, whatever task the interrupt
/// came in on, and `tick_nohz_stop_tick` / the idle loop never stop the tick
/// or halt over one. NARF runs them in the executor round, so the scheduler
/// asks this both before letting a running task keep the CPU and before
/// committing a CPU to halt. The due event itself is no longer reported once
/// raised (it would re-arm the clockevent into the past), so this is the
/// only place a pending one shows. Lock-free.
pub fn softirq_pending_local() -> bool {
    softirq_pending_on(narf_lib::percpu::current_cpu())
}

/// [`softirq_pending_local`] for `cpu`, read from any CPU (diagnostics: the
/// stall watchdog's "halted over runnable work" test).
pub fn softirq_pending_on(cpu: usize) -> bool {
    timer::softirq_pending_on(cpu)
        || hrtimer::softirq_pending_on(cpu)
        || timer_migration::requires_handle_remote_on(cpu)
}

/// Boot policy for tickless idle. The local clockevent must also support it.
static NOHZ_IDLE_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Enable tickless idle on supported local clockevents.
#[inline]
pub fn set_nohz_idle_enabled(on: bool) {
    NOHZ_IDLE_ENABLED.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Is tickless idle enabled? Gates the scheduler's periodic-tick suppression.
#[inline]
pub fn nohz_idle_enabled() -> bool {
    NOHZ_IDLE_ENABLED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Counter cycles the system spent suspended. CLOCK_MONOTONIC does not
/// advance across suspend (Linux suspends the timekeeper's clocksource), so
/// monotonic counter time is the raw counter minus this. Grows only in
/// [`timekeeping_resume`].
static SUSPENDED_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// `tk->offs_boot`: CLOCK_BOOTTIME = CLOCK_MONOTONIC + this (ns slept).
static OFFS_BOOT_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Timekeeping suspended: monotonic time reads as [`FROZEN_MONO_CYCLES`].
static TK_FROZEN: AtomicBool = AtomicBool::new(false);
static FROZEN_MONO_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static SUSPEND_START_RAW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Monotonic counter time (CLOCK_MONOTONIC in counter cycles): the raw
/// counter minus the time spent suspended. Every `Instant`, deadline and
/// duration uses this; only clockevent hardware programming uses
/// [`raw_cycles`] (convert with [`mono_to_raw_cycles`]).
#[inline]
pub fn now_cycles() -> u64 {
    if TK_FROZEN.load(Ordering::Acquire) {
        return FROZEN_MONO_CYCLES.load(Ordering::Relaxed);
    }
    raw_cycles().wrapping_sub(SUSPENDED_CYCLES.load(Ordering::Acquire))
}

/// The monotonic-cycles value `c` in raw counter cycles, for programming a
/// clockevent (TSC-deadline) that compares against the raw counter.
#[inline]
pub fn mono_to_raw_cycles(c: u64) -> u64 {
    if c == u64::MAX {
        return u64::MAX;
    }
    c.saturating_add(SUSPENDED_CYCLES.load(Ordering::Acquire))
}

/// Counter cycles spent suspended so far (published to the vDSO).
#[inline]
pub fn suspended_cycles() -> u64 {
    SUSPENDED_CYCLES.load(Ordering::Acquire)
}

/// `offs_boot` in ns: time spent suspended (CLOCK_BOOTTIME − CLOCK_MONOTONIC).
#[inline]
pub fn boot_offset_ns() -> u64 {
    OFFS_BOOT_NS.load(Ordering::Acquire)
}

/// CLOCK_BOOTTIME in ns: monotonic time plus time spent suspended.
#[inline]
pub fn boottime_ns() -> u64 {
    monotonic_ns().saturating_add(boot_offset_ns())
}

/// `timekeeping_suspend`: stop CLOCK_MONOTONIC at its current value. Called
/// with the system quiesced, right before the platform sleep.
pub fn timekeeping_suspend() {
    if TK_FROZEN.load(Ordering::Acquire) {
        return;
    }
    let raw = raw_cycles();
    FROZEN_MONO_CYCLES.store(
        raw.wrapping_sub(SUSPENDED_CYCLES.load(Ordering::Acquire)),
        Ordering::Relaxed,
    );
    SUSPEND_START_RAW.store(raw, Ordering::Relaxed);
    TK_FROZEN.store(true, Ordering::Release);
}

/// `timekeeping_resume` + `__timekeeping_inject_sleeptime`: the counter
/// cycles since [`timekeeping_suspend`] were spent asleep. CLOCK_MONOTONIC
/// resumes from where it stopped; CLOCK_BOOTTIME and CLOCK_REALTIME gain the
/// sleep time; every CPU re-evaluates its hrtimers (`clock_was_set`).
/// Returns the injected ns.
pub fn timekeeping_resume() -> u64 {
    if !TK_FROZEN.load(Ordering::Acquire) {
        return 0;
    }
    let slept = raw_cycles().wrapping_sub(SUSPEND_START_RAW.load(Ordering::Relaxed));
    // Publish the new offset before thawing: a reader that sees the thaw
    // sees the offset, so monotonic time continues from the frozen value.
    SUSPENDED_CYCLES.fetch_add(slept, Ordering::AcqRel);
    TK_FROZEN.store(false, Ordering::Release);
    let ns = cycles_to_ns(slept);
    OFFS_BOOT_NS.fetch_add(ns, Ordering::AcqRel);
    // Wall time kept running while asleep.
    adjust_wall_offset_ns(ns as i64);
    hrtimer::clock_was_set();
    ns
}

/// Read the raw hardware counter (TSC / `CNTPCT_EL0`). Counts through
/// suspend; see [`now_cycles`] for monotonic time.
#[inline]
pub fn raw_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // LFENCE;RDTSC — the fence stops the out-of-order engine from
        // hoisting/sinking the RDTSC past surrounding loads, so two
        // reads on the same core never observe time going backwards.
        // This matches Linux `rdtsc_ordered()` and `arch::tsc::rdtsc`;
        // bare RDTSC (the old code here) is not ordered and can retire
        // out of program order, breaking the monotonic guarantee that
        // the wheel/Instant deadline math relies on.
        let low: u32;
        let high: u32;
        // SAFETY: LFENCE and RDTSC are legal at CPL=0 with no memory operand.
        unsafe {
            core::arch::asm!(
                "lfence",
                "rdtsc",
                out("eax") low, out("edx") high,
                options(nomem, nostack, preserves_flags),
            );
        }
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        // CNTPCT_EL0 — the physical generic-timer counter, EL0-readable.
        let v: u64;
        // SAFETY: MRS of CNTPCT_EL0 is always legal.
        unsafe {
            core::arch::asm!(
                "mrs {v}, cntpct_el0",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

/// Named alias for consumers who want the "raw" semantics explicitly —
/// identical to `now_cycles` in Stage 1 (no virtualisation offset yet).
#[inline]
pub fn now_monotonic_raw() -> Instant {
    Instant::now()
}

/// Stage-1 "now_monotonic" is an alias for the raw form. A hypervisor
/// offset subtraction lands with the Wave 2 time spec.
#[inline]
pub fn now_monotonic() -> Instant {
    Instant::now()
}

/// Busy-wait for at least `cycles` TSC ticks by spin-polling the
/// counter. Intended for short calibration-type waits; anything
/// else should use `sleep_cycles` through the scheduler.
pub fn busy_wait_cycles(cycles: u64) {
    let deadline = now_cycles().saturating_add(cycles);
    while now_cycles() < deadline {
        core::hint::spin_loop();
    }
}

// ── kernel sleeps (Linux kernel/time/sleep_timeout.c, include/linux/delay.h)
//
// Which timer a sleep arms and how much slack it gets follow Linux:
//
// | NARF                                         | Linux                                    | timer, slack                       |
// |----------------------------------------------|------------------------------------------|------------------------------------|
// | `sleep_ns` / `sleep_us` / `sleep` / `sleep_cycles` / `fsleep` | `fsleep`                 | < 4 ms: hrtimer, 25 %; else wheel  |
// | `usleep_range`                               | `usleep_range`                           | hrtimer, `max - min`               |
// | `sleep_ms` / `msleep`                        | `msleep`                                 | wheel (at most 12.5 % past 8 ms)   |
// | `sleep_jiffies` / `sleep_until_jiffies`      | `schedule_timeout`, `delayed_work` timer | wheel                              |
// | `sleep_until` / `SleepUntil::new`            | `schedule_hrtimeout_range(abs, current->timer_slack_ns)` | hrtimer, 50 µs     |
// | `SleepUntil::range` / `schedule_hrtimeout_range` | `schedule_hrtimeout_range`           | hrtimer, explicit                  |
// | `SleepUntil::exact`                          | `schedule_hrtimeout`                     | hrtimer, 0                         |
// | `timeout`                                    | `wait_event_timeout` / `schedule_timeout` | wheel                             |
//
// Slack only ever makes a sleep longer, never shorter: an hrtimer with range
// `[t, t + slack]` expires at the first interrupt at or after `t` that runs
// before `t + slack`, which is what lets nearby timers share one interrupt.

/// `init_task.timer_slack_ns`: the slack every Linux task, kernel threads
/// included, starts with (50 µs), and what `PR_SET_TIMERSLACK(0)` restores.
/// Absolute kernel sleeps ([`SleepUntil::new`]) use it as `hrtimer_nanosleep`
/// and the `poll` / `futex` timeouts use `current->timer_slack_ns`.
pub const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;

/// `TICK_NSEC` at `HZ` = 1000.
pub const TICK_NSEC: u64 = 1_000_000_000 / timer::HZ;

/// `max_slack_shift` (`include/linux/delay.h`): `fsleep` allows 25 % slack.
const MAX_SLACK_SHIFT: u32 = 2;

/// `USLEEP_RANGE_UPPER_BOUND` in ns: below `TICK_NSEC << max_slack_shift`
/// (4 ms at HZ = 1000) a jiffy-granular `msleep` could overshoot by more than
/// 25 %, so `fsleep` uses an hrtimer range; from there on, the wheel.
pub const USLEEP_RANGE_UPPER_BOUND_NS: u64 = TICK_NSEC << MAX_SLACK_SHIFT;

/// How a [`SleepUntil`] waits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SleepKind {
    /// An hrtimer sleeper with range `[deadline, deadline + slack_ns]`.
    Hrtimer { slack_ns: u64 },
    /// A timer-wheel timeout (`schedule_timeout`) with `TIMER_*` flags.
    Wheel { flags: u32 },
}

/// Future that yields Pending until `deadline` has passed, driven by an
/// hrtimer sleeper on the polling CPU's base (Linux
/// `schedule_hrtimeout_range`) or by a timer-wheel timeout (Linux
/// `schedule_timeout`), as its constructor chose (see the table above).
///
/// The first pending poll arms the timer; its expiry wakes the task by
/// reference. Later polls only refresh the waker. Without a clockevent
/// programmer (early boot, bare tests) the future self-wakes and polls.
/// Dropping it while pending cancels the timer. The constructor's caller is
/// recorded as the timer's arm site for `/proc/timer_list`.
#[derive(Debug)]
pub struct SleepUntil {
    deadline: Instant,
    kind: SleepKind,
    site: &'static core::panic::Location<'static>,
    handle: Option<hrtimer::SleepHandle>,
    coarse: Option<timer::TimeoutHandle>,
}

impl SleepUntil {
    /// Sleep until `deadline` on an hrtimer with the default task slack
    /// ([`DEFAULT_TIMER_SLACK_NS`]): Linux `schedule_hrtimeout_range(abs,
    /// current->timer_slack_ns)`, the absolute-deadline sleep every Linux
    /// task path (`clock_nanosleep(TIMER_ABSTIME)`, futex and poll timeouts)
    /// takes. Use [`Self::exact`] where the deadline must not slip at all.
    #[track_caller]
    pub fn new(deadline: Instant) -> Self {
        Self::range(deadline, DEFAULT_TIMER_SLACK_NS)
    }

    /// `schedule_hrtimeout`: an hrtimer with no slack. For waits whose
    /// deadline is itself the point (timing measurements, tests).
    #[track_caller]
    pub fn exact(deadline: Instant) -> Self {
        Self::range(deadline, 0)
    }

    /// `schedule_hrtimeout_range(deadline, delta_ns)`: wake at the first
    /// timer interrupt in `[deadline, deadline + delta_ns]`.
    #[track_caller]
    pub fn range(deadline: Instant, delta_ns: u64) -> Self {
        Self {
            deadline,
            kind: SleepKind::Hrtimer { slack_ns: delta_ns },
            site: core::panic::Location::caller(),
            handle: None,
            coarse: None,
        }
    }

    /// Linux `msleep` / `schedule_timeout`: sleep on the timer wheel, which
    /// may fire up to one wheel-level granularity late (one jiffy below
    /// 63 ms, then at most 12.5 %) but costs no hrtimer reprogramming and
    /// shares its bucket's interrupt with every other timer in it.
    #[track_caller]
    pub fn coarse(deadline: Instant) -> Self {
        Self::wheel(deadline, 0)
    }

    /// [`Self::coarse`] with `TIMER_*` flags (`TIMER_DEFERRABLE`: never wake
    /// an idle CPU for it, like `INIT_DEFERRABLE_WORK` housekeeping).
    #[track_caller]
    pub fn wheel(deadline: Instant, flags: u32) -> Self {
        Self {
            deadline,
            kind: SleepKind::Wheel { flags },
            site: core::panic::Location::caller(),
            handle: None,
            coarse: None,
        }
    }

    /// The deadline this sleep ends at, at the earliest.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// The hrtimer slack this sleep allows (`None` for a wheel sleep).
    pub fn slack_ns(&self) -> Option<u64> {
        match self.kind {
            SleepKind::Hrtimer { slack_ns } => Some(slack_ns),
            SleepKind::Wheel { .. } => None,
        }
    }

    /// The `TIMER_*` flags of a wheel sleep (`None` for an hrtimer sleep).
    pub fn wheel_flags(&self) -> Option<u32> {
        match self.kind {
            SleepKind::Wheel { flags } => Some(flags),
            SleepKind::Hrtimer { .. } => None,
        }
    }

    /// Where the sleep was constructed (its timer's arm site).
    pub fn site(&self) -> &'static core::panic::Location<'static> {
        self.site
    }
}

/// Monotonic ns by which `deadline_cycles` has certainly passed:
/// `cycles_to_ns` truncates, so a timer at the truncated value could fire a
/// fraction of a nanosecond before the cycle deadline.
#[inline]
pub fn deadline_cycles_to_ns(deadline_cycles: u64) -> u64 {
    if deadline_cycles == u64::MAX {
        return u64::MAX;
    }
    cycles_to_ns(deadline_cycles).saturating_add(1)
}

impl Future for SleepUntil {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if Instant::now() >= this.deadline {
            this.handle = None;
            this.coarse = None;
            return Poll::Ready(());
        }
        let slack_ns = match this.kind {
            SleepKind::Wheel { flags } => {
                // The first jiffy whose start is at or after the deadline.
                let expires =
                    timer::ns_to_jiffies(deadline_cycles_to_ns(this.deadline.as_cycles()));
                this.coarse
                    .get_or_insert_with(|| timer::TimeoutHandle::new(flags))
                    .arm_from(expires, cx.waker(), this.site);
                if !hrtimer::arm_callback_installed() {
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
            SleepKind::Hrtimer { slack_ns } => slack_ns,
        };
        let refreshed = this
            .handle
            .as_ref()
            .is_some_and(|h| h.refresh_waker(cx.waker()));
        if !refreshed {
            // First poll, or woken before the deadline after the timer had
            // already fired: (re)arm.
            let expires = deadline_cycles_to_ns(this.deadline.as_cycles());
            let h = this
                .handle
                .get_or_insert_with(|| hrtimer::SleepHandle::new(hrtimer::ClockId::Monotonic));
            h.start_from(
                expires,
                slack_ns,
                hrtimer::HrtimerMode::ABS,
                cx.waker(),
                this.site,
            );
        }
        if !hrtimer::arm_callback_installed() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

/// `fsleep` for a delay in ns: under [`USLEEP_RANGE_UPPER_BOUND_NS`] an
/// hrtimer with 25 % slack (`usleep_range(us, us + us / 4)`), otherwise
/// `msleep` of the delay rounded up to whole milliseconds.
///
/// Linux busy-waits (`udelay`) for 10 µs and less; an async task yields to
/// the executor instead, so short delays take the hrtimer range too.
#[track_caller]
pub fn fsleep_ns(ns: u64) -> SleepUntil {
    if ns < USLEEP_RANGE_UPPER_BOUND_NS {
        SleepUntil::range(Deadline::after_ns(ns).as_instant(), ns >> MAX_SLACK_SHIFT)
    } else {
        SleepUntil::coarse(Deadline::after_ms(ns.div_ceil(1_000_000)).as_instant())
    }
}

/// Linux `fsleep(usecs)`: the flexible sleep that picks the mechanism with
/// at most 25 % slack (see [`fsleep_ns`]).
#[track_caller]
pub fn fsleep(us: u64) -> SleepUntil {
    fsleep_ns(us.saturating_mul(1_000))
}

/// Linux `usleep_range(min, max)`: at least `min_us`, ending at the first
/// timer interrupt before `max_us` (an hrtimer with range `max - min`).
/// `max_us < min_us` gets no slack (Linux warns and does the same).
#[track_caller]
pub fn usleep_range(min_us: u64, max_us: u64) -> SleepUntil {
    let delta_ns = max_us.saturating_sub(min_us).saturating_mul(1_000);
    SleepUntil::range(Deadline::after_us(min_us).as_instant(), delta_ns)
}

/// Linux `schedule_hrtimeout_range(&deadline, delta_ns, HRTIMER_MODE_ABS)`.
#[track_caller]
pub fn schedule_hrtimeout_range(deadline: Deadline, delta_ns: u64) -> SleepUntil {
    SleepUntil::range(deadline.0, delta_ns)
}

/// Linux `schedule_timeout(j)`: sleep `j` jiffies on the timer wheel.
#[track_caller]
pub fn sleep_jiffies(j: u64) -> SleepUntil {
    sleep_until_jiffies(timer::jiffies().saturating_add(j), 0)
}

/// Sleep on the wheel until absolute jiffy `expires` with `TIMER_*` flags:
/// the timer a Linux `delayed_work` re-queued for `expires` (with
/// `round_jiffies`, or `INIT_DEFERRABLE_WORK` for `TIMER_DEFERRABLE`) arms.
#[track_caller]
pub fn sleep_until_jiffies(expires: u64, flags: u32) -> SleepUntil {
    // The deadline is the start of jiffy `expires`; the wheel fires the
    // bucket at or after it.
    let deadline = Instant(ns_to_cycles(timer::jiffies_to_ns(expires)));
    SleepUntil::wheel(deadline, flags)
}

/// Sleep for `cycles` counter cycles from now: [`fsleep_ns`] of the
/// equivalent duration.
#[track_caller]
pub fn sleep_cycles(cycles: u64) -> SleepUntil {
    fsleep_ns(cycles_to_ns(cycles))
}

/// Sleep until `deadline` (spec §3.2): [`SleepUntil::new`], an hrtimer with
/// the default task slack.
#[track_caller]
pub fn sleep_until(deadline: Deadline) -> SleepUntil {
    SleepUntil::new(deadline.0)
}

/// Sleep for a wall-clock duration (spec §3.2): [`fsleep_ns`]. Like every
/// ns-based constructor, this uses the calibrated scale; before calibration
/// it is 1 cycle per ns and expires early on a >1 GHz TSC (see [`Deadline`]).
#[track_caller]
pub fn sleep(duration: core::time::Duration) -> SleepUntil {
    fsleep_ns(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
}

/// Sleep for `ns` nanoseconds of wall-clock time: [`fsleep_ns`]. Prefer this
/// (or [`sleep_us`] / [`sleep_ms`]) over [`sleep_cycles`] with a
/// hand-converted count: a literal cycle count is a different duration on
/// every CPU.
#[track_caller]
pub fn sleep_ns(ns: u64) -> SleepUntil {
    fsleep_ns(ns)
}

/// Sleep for `us` microseconds of wall-clock time: Linux [`fsleep`].
#[track_caller]
pub fn sleep_us(us: u64) -> SleepUntil {
    fsleep(us)
}

/// Sleep for `ms` milliseconds of wall-clock time: Linux `msleep`, a coarse
/// sleep on the timer wheel ([`msleep`]) — it ends no earlier than `ms` and
/// at most one wheel-level granularity later (within a jiffy or two below
/// 63 ms). Use [`usleep_range`] where the millisecond matters.
#[track_caller]
pub fn sleep_ms(ms: u64) -> SleepUntil {
    msleep(ms)
}

/// Linux `msleep`: a coarse sleep on the timer wheel, which may end up to
/// one wheel-level granularity late.
#[track_caller]
pub fn msleep(ms: u64) -> SleepUntil {
    SleepUntil::coarse(Deadline::after_ms(ms).0)
}

/// Wall-clock deadline anchored to a future TSC reading. Cheap to
/// copy + check; use this instead of ad-hoc `for _ in 0..N` iter
/// counts when the wait should be bounded by real wall time
/// rather than an arbitrary spin budget that varies with CPU
/// clock.
///
/// Duration constructors use the calibrated fixed-point ns -> cycles scale.
/// Before calibration they fall back to "1 cycle per ns". This is not wall
/// time: on a >1 GHz TSC, both minimum delays and timeouts fire too early.
/// Callers requiring hardware-specified delays must establish calibration
/// before constructing them. `expired()` uses the raw monotonic counter.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline(Instant);

impl Deadline {
    /// Construct a deadline at the given absolute `Instant`.
    #[inline]
    pub const fn at(instant: Instant) -> Self {
        Self(instant)
    }

    /// Construct a deadline `cycles` TSC ticks from now.
    #[inline]
    pub fn after_cycles(cycles: u64) -> Self {
        Self(Instant::now().plus_cycles(cycles))
    }

    /// Construct a deadline `ns` nanoseconds from now. Uses the
    /// calibrated fixed-point scale; falls back to 1 ns ≈ 1 cycle
    /// when calibration hasn't completed.
    #[inline]
    pub fn after_ns(ns: u64) -> Self {
        Self::after_cycles(wall::ns_to_cycles(ns))
    }

    /// Construct a deadline `us` microseconds from now.
    #[inline]
    pub fn after_us(us: u64) -> Self {
        Self::after_ns(us.saturating_mul(1_000))
    }

    /// Construct a deadline `ms` milliseconds from now.
    #[inline]
    pub fn after_ms(ms: u64) -> Self {
        Self::after_ns(ms.saturating_mul(1_000_000))
    }

    /// True iff the current TSC reading has reached or passed the
    /// deadline.
    #[inline]
    pub fn expired(&self) -> bool {
        Instant::now() >= self.0
    }

    /// TSC cycles remaining until the deadline; 0 once past.
    #[inline]
    pub fn remaining_cycles(&self) -> u64 {
        self.0.cycles_since(Instant::now())
    }

    /// Underlying Instant — handy when constructing a `SleepUntil`.
    #[inline]
    pub const fn as_instant(&self) -> Instant {
        self.0
    }
}

/// Returned by `timeout` / `poll_bit_async` when the deadline
/// passes before the inner work completes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Elapsed;

/// Wrap a future with a wall-clock deadline. Resolves to
/// `Ok(output)` if the inner future completes first, or
/// `Err(Elapsed)` if the deadline passes first. Cancels the
/// inner future via Drop on timeout.
///
/// The deadline is a timer-wheel timeout, as Linux's
/// `wait_event_timeout` / `wait_for_completion_timeout` are
/// (`schedule_timeout`): it ends no earlier than `deadline` and at most
/// one wheel-level granularity later. Cheap-when-not-firing: when the
/// inner future completes promptly the timer-wheel slot is cancelled in
/// `drop` without the wheel ever having to fire. The combinator polls the
/// inner future first on each round so a ready inner short-circuits the
/// deadline check.
#[inline]
#[track_caller]
pub fn timeout<F: Future>(deadline: Deadline, fut: F) -> Timeout<F> {
    Timeout {
        fut,
        sleep: SleepUntil::coarse(deadline.as_instant()),
    }
}

/// Future returned by [`timeout`].
#[derive(Debug)]
pub struct Timeout<F> {
    fut: F,
    sleep: SleepUntil,
}

impl<F: Future> Future for Timeout<F> {
    type Output = Result<F::Output, Elapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: `self` is pinned; we project to `fut` and
        // `sleep` by raw pointer to avoid pulling in
        // `pin_project_lite`. Neither field is moved out — only
        // re-pinned for the inner poll call.
        // SAFETY: Valid memory or trusted environment
        let this = unsafe { self.get_unchecked_mut() };
        // SAFETY: `this.fut` is a field of the pinned `Timeout`, so it is
        // structurally pinned: it lives as long as `self` and is never moved
        // out (we only re-pin it here and poll through it). Re-establishing
        // the pin invariant for the projected field is therefore sound.
        // SAFETY: Valid memory or trusted environment
        let fut = unsafe { Pin::new_unchecked(&mut this.fut) };
        match fut.poll(cx) {
            Poll::Ready(v) => return Poll::Ready(Ok(v)),
            Poll::Pending => {}
        }
        // SAFETY: `this.sleep` is a field of the pinned `Timeout`, so it is
        // structurally pinned exactly like `this.fut` above: it is never moved
        // out, only re-pinned here for the inner poll. Re-establishing the pin
        // invariant for the projected field is sound.
        // SAFETY: Valid memory or trusted environment
        let sleep = unsafe { Pin::new_unchecked(&mut this.sleep) };
        match sleep.poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Async equivalent of `narf_scheduler::responsive_spin` for
/// callers already running inside an async task: poll a
/// hardware bit (or any cheap predicate) at `sample_interval`
/// resolution, sleeping between samples via the timer wheel
/// instead of busy-waiting. Returns `Ok` once `probe` returns
/// true, `Err(Elapsed)` if `deadline` passes first.
///
/// Use when the wait is expected to be milliseconds-scale (long
/// enough that yielding to the executor + sleeping in the wheel
/// pays back the wake-up overhead). For sub-microsecond waits,
/// `narf_scheduler::responsive_spin` is cheaper.
pub async fn poll_bit_async<F: FnMut() -> bool>(
    mut probe: F,
    sample_interval_cycles: u64,
    deadline: Deadline,
) -> Result<(), Elapsed> {
    loop {
        if probe() {
            return Ok(());
        }
        if deadline.expired() {
            return Err(Elapsed);
        }
        sleep_cycles(sample_interval_cycles).await;
    }
}

/// Which calibration source produced the most-recent TSC Hz. Set
/// by [`calibrate_clocks`] / [`calibrate_clocks_with_source`] so
/// the early-boot console line can show *how* the platform's clock
/// got its number, not just that it did. Real-HW bring-up wants
/// this — a Zen4 laptop should land on `AmdPstate0`, not
/// `HpetXcheck` (the HPET reading is unreliable on Phoenix
/// HawkPoint1 under SMM activity).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CalibrationSource {
    /// Cached value from a prior call.
    Cached,
    /// Intel CPUID 0x15 (TSC / crystal clock ratio) — most
    /// accurate on Skylake+ with a non-zero crystal.
    CpuId15h,
    /// Intel CPUID 0x16 (processor base frequency, MHz). Coarser
    /// than 0x15 (rounded to MHz) but available without the
    /// crystal entry.
    CpuId16h,
    /// Intel `MSR_PLATFORM_INFO` (0xCE) decode. Used on Sandy
    /// Bridge+ Intel parts where CPUID 0x15 has no crystal and
    /// CPUID 0x16 isn't populated (some virtualised hosts).
    /// Encodes the max non-turbo ratio; TSC = ratio * 100 MHz BCLK.
    IntelPlatformInfo,
    /// AMD `MSR_AMD_PSTATE_DEF_0` (`Core::X86::Msr::PStateDef`)
    /// decode. Used on Zen2 / Zen3 / Zen4 / Zen5 where Intel
    /// CPUID leaves are not populated.
    AmdPstate0,
    /// HPET cross-check (`Δtsc / Δhpet * hpet_hz`). Works on any
    /// chipset with a functioning HPET; unreliable on some
    /// laptops (Phoenix HawkPoint1).
    HpetXcheck,
    /// Every source failed — kernel is running in raw-cycle units.
    None,
}

impl CalibrationSource {
    /// Short human-readable name for boot-log lines.
    pub const fn name(self) -> &'static str {
        match self {
            CalibrationSource::Cached => "cached",
            CalibrationSource::CpuId15h => "cpuid-15h",
            CalibrationSource::CpuId16h => "cpuid-16h",
            CalibrationSource::IntelPlatformInfo => "intel-platform-info",
            CalibrationSource::AmdPstate0 => "amd-pstate0",
            CalibrationSource::HpetXcheck => "hpet-xcheck",
            CalibrationSource::None => "none",
        }
    }
}

/// One-shot boot-time clock calibration. Picks the best TSC-Hz
/// estimate available — Intel CPUID 0x15 / 0x16 / MSR_PLATFORM_INFO,
/// then AMD `MSR_AMD_PSTATE_DEF_0` for Family 0x17+, then a HPET
/// cross-check — and pushes the resulting cycles-per-ns into the
/// wall module so `monotonic_ns()` reports real nanoseconds
/// instead of raw TSC ticks. Returns the chosen TSC Hz, or 0 if
/// every source failed (in which case `cycles_per_ns` stays at 1
/// and timing remains in raw-tick units — better than panicking).
///
/// HPET must already be `init`'d when this is called for the
/// HPET fallback to fire. Idempotent: subsequent calls return the
/// cached frequency without re-measuring.
///
/// Callers that want to know *which* source produced the Hz value
/// (e.g. for a boot-log line) should call
/// [`calibrate_clocks_with_source`] instead.
#[cfg(target_arch = "x86_64")]
pub fn calibrate_clocks() -> u64 {
    calibrate_clocks_with_source().0
}

/// Variant of [`calibrate_clocks`] that also reports which path
/// produced the Hz value. On a Zen4 laptop the expected outcome
/// is `(non-zero, CalibrationSource::AmdPstate0)`; on a Skylake
/// desktop `(non-zero, CalibrationSource::CpuId15h)`; on a
/// virtualised host that masks AMD MSRs, `(non-zero,
/// CalibrationSource::HpetXcheck)`. `(0, CalibrationSource::None)`
/// indicates total failure — `cycles_per_ns` stays at the default
/// `1` and duration deadlines have no wall-time guarantee.
#[cfg(target_arch = "x86_64")]
pub fn calibrate_clocks_with_source() -> (u64, CalibrationSource) {
    let cached = narf_arch::x86_64::tsc::frequency_hz();
    if cached != 0 {
        // The arch cache can be populated before the wall-clock conversion
        // pairs (for example by an early driver). A cached frequency alone
        // does not make Deadline's ns -> cycles conversion calibrated.
        apply_cycles_per_ns(cached);
        return (cached, CalibrationSource::Cached);
    }
    // 1. Intel CPUID 0x15. When the leaf populates a non-zero
    //    crystal-Hz this is the most accurate source we have.
    let hz_15h = narf_arch::x86_64::tsc::__from_cpuid_15h();
    if let Some(hz) = hz_15h {
        narf_arch::x86_64::tsc::set_hz_via_hpet(hz);
        apply_cycles_per_ns(hz);
        return (hz, CalibrationSource::CpuId15h);
    }
    // 2. Intel CPUID 0x16 (processor base frequency MHz). Coarser
    //    but available when 0x15's crystal is zero.
    let hz_16h = narf_arch::x86_64::tsc::__from_cpuid_16h();
    if let Some(hz) = hz_16h {
        narf_arch::x86_64::tsc::set_hz_via_hpet(hz);
        apply_cycles_per_ns(hz);
        return (hz, CalibrationSource::CpuId16h);
    }
    // 3. Intel MSR_PLATFORM_INFO (0xCE). Sandy Bridge+ parts that
    //    don't populate CPUID 0x15 (no crystal) or report 0 from
    //    CPUID 0x16 (some virtualised hosts) still expose the max
    //    non-turbo ratio here. Vendor-gated to Intel — AMD has no
    //    MSR at that index, and the inner check short-circuits
    //    before issuing the rdmsr.
    let hz_msr_pi = narf_arch::x86_64::tsc::__from_msr_platform_info();
    if let Some(hz) = hz_msr_pi {
        narf_arch::x86_64::tsc::set_hz_via_hpet(hz);
        apply_cycles_per_ns(hz);
        return (hz, CalibrationSource::IntelPlatformInfo);
    }
    // 4. AMD MSR_PSTATE0. Family 0x17+ doesn't populate the
    //    Intel CPUID leaves; the P-state-0 MSR has the boost
    //    clock, which the invariant TSC matches.
    let hz_amd = narf_arch::x86_64::tsc::calibrate_via_amd_pstate0();
    if hz_amd != 0 {
        narf_arch::x86_64::tsc::set_hz_via_hpet(hz_amd);
        apply_cycles_per_ns(hz_amd);
        return (hz_amd, CalibrationSource::AmdPstate0);
    }
    // 5. HPET cross-check. A 100 ms window at the ~14.318 MHz
    //    HPET found on every x86_64 chipset since ICH = ~1.43M
    //    ticks; bumps to whatever the actual HPET reports if
    //    higher (some Coffee Lake parts run HPET at 24 MHz).
    let hpet_hz = hpet::frequency_hz();
    if hpet_hz != 0 {
        let window = (hpet_hz / 10).max(1); // ~100 ms
        if let Some(measured) = hpet::calibrate_tsc_via_hpet(window) {
            // Sanity-bound: same range as amd-pstate0. HPET on
            // Phoenix HawkPoint1 has known SMM-induced drift that
            // can produce wildly wrong measurements; we'd rather
            // run with cpns=1 (waits expressed in raw cycles) than
            // install a bogus value that breaks every Deadline.
            if (1_000_000_000..=6_500_000_000).contains(&measured) {
                narf_arch::x86_64::tsc::set_hz_via_hpet(measured);
                apply_cycles_per_ns(measured);
                return (measured, CalibrationSource::HpetXcheck);
            }
        }
    }
    (0, CalibrationSource::None)
}

/// Push the measured TSC frequency `hz` into the wall module. Feeds
/// the full-precision Hz into `set_clock_hz`, which derives Linux-style
/// mult/shift fixed-point scales for both conversion directions — so a
/// fractional ratio like 2.397 GHz is preserved to <1 ppm instead of
/// being truncated to the integer 2 (the old ~20%-fast bug).
#[cfg(target_arch = "x86_64")]
fn apply_cycles_per_ns(hz: u64) {
    wall::set_clock_hz(hz.max(1));
}

/// aarch64 calibrate_clocks stub. The Generic Timer's
/// `CNTFRQ_EL0` reports the counter's Hz directly — wiring that
/// into `set_cycles_per_ns` is a follow-up; for now the kernel
/// runs in raw-tick units on aarch64.
#[cfg(target_arch = "aarch64")]
pub fn calibrate_clocks() -> u64 {
    0
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn calibrate_clocks() -> u64 {
    0
}
