//! Shared NAPI poll loop and adaptive interrupt moderation.
//!
//! NAPI is the "poll under load, interrupt when idle" receive discipline every
//! high-rate driver needs: once frames are flowing, disable the RX interrupt
//! and poll the ring in a bounded budget; when the ring drains, re-arm the
//! interrupt and — crucially — recheck before parking so a frame that landed
//! during the arm is not lost to a missed wakeup. virtio-net already does this
//! by hand (`EVENT_IDX` re-arm); this factors the pattern so ixgbe / i40e /
//! mlx5 share one correct implementation instead of each re-deriving the
//! arm/recheck race.
//!
//! Interrupt moderation (adaptive ITR) caps the IRQ rate independent of pps:
//! at high packet rates one interrupt per frame would melt a core, so the
//! coalescing interval grows with load (bulk) and shrinks when idle (latency).
//!
//! Reference: Linux `napi_poll` / `napi_complete_done`; Intel dynamic ITR
//! (`ixgbe`/`igb` `update_itr`).

/// Default per-poll frame budget. Linux uses 64; one poll round processes at
/// most this many frames before yielding so one busy queue cannot starve the
/// others sharing a core.
pub const DEFAULT_BUDGET: u32 = 64;

/// A device's RX queue, abstracted for the shared poll loop. One unit of work
/// is one frame; the driver dispatches it into the stack inside `poll_one`.
pub trait NapiDevice {
    /// Process one frame from the ring. Return `true` if a frame was handled,
    /// `false` when the ring is empty.
    fn poll_one(&mut self) -> bool;

    /// Re-enable the RX interrupt and report whether work is already pending.
    /// Called once the ring has drained: if it returns `true` a frame arrived
    /// between drain and arm, so the caller must poll again rather than park
    /// (the arm's wakeup would otherwise be lost). Default: assume no pending
    /// work (a device with no arm/recheck support simply polls on a timer).
    fn arm(&mut self) -> bool {
        false
    }

    /// Suppress the RX interrupt for the duration of a poll burst (NAPI
    /// disables per-frame IRQs while actively polling). Default: no-op.
    fn disable_irq(&mut self) {}
}

/// Outcome of one NAPI poll round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    /// The ring drained within budget after `processed` frames. The caller
    /// should arm the interrupt (via [`complete`]) and, if that reports no
    /// pending work, park.
    Drained { processed: u32 },
    /// The budget was exhausted with work still queued. The caller should
    /// reschedule the poll immediately (do not park, do not re-enable the
    /// per-frame interrupt).
    Budget { processed: u32 },
}

impl Poll {
    /// Frames processed this round.
    pub fn processed(self) -> u32 {
        match self {
            Poll::Drained { processed } | Poll::Budget { processed } => processed,
        }
    }
}

/// Run one NAPI poll round over `dev`, processing up to `budget` frames. On
/// entry the per-frame interrupt is suppressed for the burst. Returns whether
/// the ring drained (arm + park) or the budget capped it (keep polling).
pub fn poll(dev: &mut impl NapiDevice, budget: u32) -> Poll {
    dev.disable_irq();
    let mut processed = 0;
    while processed < budget {
        if !dev.poll_one() {
            return Poll::Drained { processed };
        }
        processed += 1;
    }
    Poll::Budget { processed }
}

/// The race-free NAPI completion step: after a [`Poll::Drained`] round, arm
/// the RX interrupt and recheck. Returns `true` if the caller should poll
/// again (a frame arrived during the arm) and `false` if it is safe to park.
pub fn complete(dev: &mut impl NapiDevice) -> bool {
    dev.arm()
}

// ── Adaptive interrupt moderation (ITR) ─────────────────────────────

/// Coalescing interval for an idle / lightly loaded queue — minimal latency,
/// one IRQ per frame is fine when pps is low.
pub const ITR_LOWEST_US: u32 = 20;
/// Coalescing interval under moderate load — ~20k IRQ/s.
pub const ITR_LOW_US: u32 = 50;
/// Coalescing interval under heavy / bulk load — ~8k IRQ/s, so a 10G+ flood
/// cannot drive the IRQ rate past tens of kHz.
pub const ITR_BULK_US: u32 = 125;

/// pps at/above which the queue is treated as moderately loaded.
pub const PPS_MODERATE: u32 = 10_000;
/// pps at/above which the queue is treated as bulk (cap IRQ rate hardest).
pub const PPS_BULK: u32 = 70_000;
/// Mean frame size (bytes) at/above which a queue is throughput-bound and
/// biased toward the bulk interval regardless of pps — latency matters less
/// when each frame is large.
pub const BULK_FRAME_BYTES: u32 = 1024;

/// Adaptive interrupt-rate limiter, Intel dynamic-ITR in spirit: classify the
/// last interval's packet rate and mean frame size into a latency/bulk tier
/// and pick a coalescing interval, EWMA-smoothed so it does not flap between
/// tiers on a single bursty interval.
#[derive(Clone, Copy, Debug)]
pub struct AdaptiveItr {
    interval_us: u32,
}

impl Default for AdaptiveItr {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveItr {
    pub const fn new() -> Self {
        Self {
            interval_us: ITR_LOWEST_US,
        }
    }

    /// The tier interval for an observed `pps` / `mean_frame_bytes`, before
    /// smoothing. Large frames bias toward bulk even at moderate pps.
    fn target(pps: u32, mean_frame_bytes: u32) -> u32 {
        if pps >= PPS_BULK || (pps >= PPS_MODERATE && mean_frame_bytes >= BULK_FRAME_BYTES) {
            ITR_BULK_US
        } else if pps >= PPS_MODERATE {
            ITR_LOW_US
        } else {
            ITR_LOWEST_US
        }
    }

    /// Fold the last interval's observed rate into the coalescing interval and
    /// return the new value. EWMA (3/4 old, 1/4 new) damps per-interval noise.
    pub fn update(&mut self, pps: u32, mean_frame_bytes: u32) -> u32 {
        let target = Self::target(pps, mean_frame_bytes);
        self.interval_us = (self.interval_us * 3 + target) / 4;
        self.interval_us
    }

    /// Current coalescing interval in microseconds.
    pub fn interval_us(&self) -> u32 {
        self.interval_us
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod napi_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A fake queue with `avail` frames and a flag for work that "arrives"
    /// during the arm recheck.
    struct FakeQ {
        avail: u32,
        polled: u32,
        armed: u32,
        irq_suppressed: u32,
        pending_after_arm: bool,
    }

    impl NapiDevice for FakeQ {
        fn poll_one(&mut self) -> bool {
            if self.avail == 0 {
                return false;
            }
            self.avail -= 1;
            self.polled += 1;
            true
        }
        fn arm(&mut self) -> bool {
            self.armed += 1;
            self.pending_after_arm
        }
        fn disable_irq(&mut self) {
            self.irq_suppressed += 1;
        }
    }

    fn smoke_napi_poll_drain_and_budget() -> TestResult {
        // Ring shallower than budget: one round drains it, IRQ suppressed once.
        let mut q = FakeQ {
            avail: 3,
            polled: 0,
            armed: 0,
            irq_suppressed: 0,
            pending_after_arm: false,
        };
        match poll(&mut q, DEFAULT_BUDGET) {
            Poll::Drained { processed: 3 } => {}
            _ => return TestResult::Fail("shallow ring should drain within budget"),
        }
        if q.irq_suppressed != 1 {
            return TestResult::Fail("poll must suppress the per-frame IRQ for the burst");
        }
        // complete() with nothing pending ⇒ safe to park.
        if complete(&mut q) || q.armed != 1 {
            return TestResult::Fail("complete should arm once and report no pending work");
        }

        // Ring deeper than budget: capped at budget, work remains.
        let mut q = FakeQ {
            avail: DEFAULT_BUDGET + 10,
            polled: 0,
            armed: 0,
            irq_suppressed: 0,
            pending_after_arm: false,
        };
        match poll(&mut q, DEFAULT_BUDGET) {
            Poll::Budget { processed } if processed == DEFAULT_BUDGET => {}
            _ => return TestResult::Fail("deep ring should cap at budget"),
        }

        // A frame arriving during the arm forces a re-poll (no lost wakeup).
        let mut q = FakeQ {
            avail: 0,
            polled: 0,
            armed: 0,
            irq_suppressed: 0,
            pending_after_arm: true,
        };
        if !complete(&mut q) {
            return TestResult::Fail("pending work during arm must force a re-poll");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/napi", smoke_napi_poll_drain_and_budget);

    fn smoke_napi_adaptive_itr() -> TestResult {
        // Idle stays at the lowest-latency interval.
        let mut itr = AdaptiveItr::new();
        for _ in 0..8 {
            itr.update(100, 64);
        }
        if itr.interval_us() != ITR_LOWEST_US {
            return TestResult::Fail("idle should settle at the lowest-latency interval");
        }
        // A sustained flood converges toward the bulk interval (IRQ rate
        // bounded) and never overshoots it.
        for _ in 0..32 {
            itr.update(200_000, 1500);
        }
        if itr.interval_us() > ITR_BULK_US || itr.interval_us() < ITR_LOW_US {
            return TestResult::Fail("flood should converge toward the bulk interval");
        }
        // Moderate pps with small frames picks the low (not bulk) tier.
        if AdaptiveItr::target(20_000, 64) != ITR_LOW_US {
            return TestResult::Fail("moderate small-frame load should be the low tier");
        }
        // Large frames at moderate pps bias to bulk (throughput-bound).
        if AdaptiveItr::target(20_000, 1500) != ITR_BULK_US {
            return TestResult::Fail("large frames should bias to the bulk tier");
        }
        // EWMA damps a single bursty interval (no instant jump to bulk).
        let mut itr = AdaptiveItr::new();
        let after_one = itr.update(200_000, 1500);
        if after_one >= ITR_BULK_US {
            return TestResult::Fail("one bursty interval must not jump straight to bulk");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/napi", smoke_napi_adaptive_itr);
}
