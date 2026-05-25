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
pub mod rtc;
pub mod timer_wheel;
pub mod wall;

mod tests;
pub use wall::{
    begin_leap_smear, cycles_per_ns, monotonic_ns, now_wall, set_cycles_per_ns,
    set_wall_offset, set_wall_offset_uncapped, WallClock, WallError, WallInstant,
};

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

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

/// Read the raw monotonic counter.
#[inline]
pub fn now_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // RDTSC — not serialising; good enough for a Stage-1 monotonic tick.
        // RDTSCP / CPUID-then-RDTSC for the serialising variant land in
        // the Stage-2 time spec when ordering actually matters.
        let low: u32;
        let high: u32;
        // SAFETY: RDTSC is legal at CPL=0 and has no memory operand.
        unsafe {
            core::arch::asm!(
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

/// Future that yields Pending until `deadline` has passed,
/// driven by an IRQ-armed timer wheel rather than busy-poll.
///
/// On first poll, the future registers `(deadline, waker)`
/// with `timer_wheel::register`. When the wheel's HPET arm
/// fires the deadline, the waker runs and the next poll
/// returns `Ready`. If the wheel is full (more than
/// `MAX_SLEEPERS` concurrent sleepers), the future falls
/// back to self-wake busy-poll so the system keeps making
/// progress at the cost of CPU. Drop while pending cancels
/// the wheel slot.
#[derive(Debug)]
pub struct SleepUntil {
    deadline: Instant,
    handle: Option<timer_wheel::SleepHandle>,
}

impl SleepUntil {
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            handle: None,
        }
    }
}

impl Future for SleepUntil {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if Instant::now() >= this.deadline {
            if let Some(h) = this.handle.take() {
                timer_wheel::cancel(h);
            }
            return Poll::Ready(());
        }
        match this.handle {
            Some(h) => {
                if !timer_wheel::refresh_waker(h, cx.waker().clone()) {
                    // Slot recycled (fired + reused) but our
                    // deadline hasn't passed — must've been a
                    // spurious wake. Re-register.
                    this.handle = None;
                    return Pin::new(this).poll(cx);
                }
            }
            None => {
                match timer_wheel::register(this.deadline.as_cycles(), cx.waker().clone()) {
                    Ok(h) => {
                        this.handle = Some(h);
                    }
                    Err(timer_wheel::WheelError::Full) => {
                        // Fall back: self-wake busy-poll.
                        cx.waker().wake_by_ref();
                    }
                }
            }
        }
        // No installed arm callback (typical in early-boot or
        // bare-test contexts): the wheel won't fire on its own,
        // so degrade to self-wake busy-poll. This keeps the
        // executor making progress at the cost of CPU.
        if !timer_wheel::arm_callback_installed() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Drop for SleepUntil {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            timer_wheel::cancel(h);
        }
    }
}

/// Convenience: sleep for `cycles` from now.
pub fn sleep_cycles(cycles: u64) -> SleepUntil {
    SleepUntil::new(Instant::now().plus_cycles(cycles))
}

/// Wall-clock deadline anchored to a future TSC reading. Cheap to
/// copy + check; use this instead of ad-hoc `for _ in 0..N` iter
/// counts when the wait should be bounded by real wall time
/// rather than an arbitrary spin budget that varies with CPU
/// clock.
///
/// Constructors round to `cycles_per_ns` granularity (set by
/// `calibrate_clocks`); on a system where calibration failed
/// (cycles_per_ns falls through to 1) the *_ms / *_us / *_ns
/// helpers degrade to "1 cycle per ns" which means timeouts fire
/// later in wall time than nominal — caller should either tune
/// the cycle count directly or accept the longer-than-asked
/// wait. `expired()` is monotonic w.r.t. wall time once the TSC
/// is calibrated.
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
    /// calibrated `cycles_per_ns`; falls back to 1 ns ≈ 1 cycle
    /// when calibration hasn't completed.
    #[inline]
    pub fn after_ns(ns: u64) -> Self {
        let cpns = wall::cycles_per_ns().max(1) as u64;
        Self::after_cycles(ns.saturating_mul(cpns))
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
/// Cheap-when-not-firing: when the inner future completes
/// promptly the timer-wheel slot is cancelled in `drop` without
/// the wheel ever having to fire. The combinator polls the inner
/// future first on each round so a ready inner short-circuits
/// the deadline check.
#[inline]
pub fn timeout<F: Future>(deadline: Deadline, fut: F) -> Timeout<F> {
    Timeout {
        fut,
        sleep: SleepUntil::new(deadline.as_instant()),
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
        let this = unsafe { self.get_unchecked_mut() };
        let fut = unsafe { Pin::new_unchecked(&mut this.fut) };
        match fut.poll(cx) {
            Poll::Ready(v) => return Poll::Ready(Ok(v)),
            Poll::Pending => {}
        }
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
/// `1` and `Deadline::after_ms` will fire late rather than early.
#[cfg(target_arch = "x86_64")]
pub fn calibrate_clocks_with_source() -> (u64, CalibrationSource) {
    let cached = narf_arch::x86_64::tsc::frequency_hz();
    if cached != 0 {
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

/// Push `hz` into the wall module as `cycles_per_ns` (clamped to
/// ≥ 1). Rounds *down*: a fractional Hz/ns ratio (e.g. 3.5 GHz →
/// 3 cycles/ns) makes `monotonic_ns` report time slightly faster
/// than reality, which is preferable to slower — timeouts fire
/// early rather than late on a system where calibration was a
/// hair off.
#[cfg(target_arch = "x86_64")]
fn apply_cycles_per_ns(hz: u64) {
    // Clamp to [1, 6] cycles/ns. Real CPUs land in [1, 6] —
    // higher means calibration miscalibrated and `Deadline::after_ms`
    // would produce cycle counts that put deadlines far in the
    // future (waits appear stuck). Lower (zero) is already
    // guarded by the .max(1).
    let raw = (hz / 1_000_000_000).max(1) as u32;
    let cpns = raw.min(6);
    wall::set_cycles_per_ns(cpns);
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
