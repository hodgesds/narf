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

pub mod wall;
pub use wall::{
    begin_leap_smear, monotonic_ns, now_wall, set_cycles_per_ns,
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
    pub fn now() -> Self { Self(now_cycles()) }

    #[inline]
    pub fn as_cycles(self) -> u64 { self.0 }

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
    { 0 }
}

/// Named alias for consumers who want the "raw" semantics explicitly —
/// identical to `now_cycles` in Stage 1 (no virtualisation offset yet).
#[inline]
pub fn now_monotonic_raw() -> Instant { Instant::now() }

/// Stage-1 "now_monotonic" is an alias for the raw form. A hypervisor
/// offset subtraction lands with the Wave 2 time spec.
#[inline]
pub fn now_monotonic() -> Instant { Instant::now() }

/// Busy-wait for at least `cycles` TSC ticks by spin-polling the
/// counter. Intended for short calibration-type waits; anything
/// else should use `sleep_cycles` through the scheduler.
pub fn busy_wait_cycles(cycles: u64) {
    let deadline = now_cycles().saturating_add(cycles);
    while now_cycles() < deadline {
        core::hint::spin_loop();
    }
}

/// Future that yields Pending until `deadline` has passed. The executor's
/// polling loop advances its own idea of time by repolling; we use a
/// no-op waker so the Future never actively schedules itself — the
/// cooperative executor just drains Pending tasks in a loop.
///
/// This is the Stage-1 sleep primitive; Wave 2's timer-wheel + IRQ-driven
/// waker will replace it with event-driven wakeups.
#[derive(Debug)]
pub struct SleepUntil {
    deadline: Instant,
}

impl SleepUntil {
    pub fn new(deadline: Instant) -> Self { Self { deadline } }
}

impl Future for SleepUntil {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.deadline {
            Poll::Ready(())
        } else {
            // Schedule an immediate re-poll. With the Stage-1 cooperative
            // executor this is what advances through Pending tasks.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Convenience: sleep for `cycles` from now.
pub fn sleep_cycles(cycles: u64) -> SleepUntil {
    SleepUntil::new(Instant::now().plus_cycles(cycles))
}
