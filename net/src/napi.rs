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

use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    task::Waker,
};
use narf_lib::sync::IrqSafeSpinLock;

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

// ── NAPI in softirq context: the bounded pump and its deferral ─────────────

/// `MAX_SOFTIRQ_RESTART` (`kernel/softirq.c`): `__do_softirq` runs the
/// pending handlers at most this many times per IRQ exit.
pub const MAX_SOFTIRQ_RESTART: u32 = 10;
/// `MAX_SOFTIRQ_TIME` (2 ms): `__do_softirq` stops restarting after this.
pub const MAX_SOFTIRQ_TIME_NS: u64 = 2_000_000;
/// `netdev_budget`: packets one `net_rx_action` round processes.
pub const NETDEV_BUDGET: u32 = 300;
/// `netdev_budget_usecs` (2000 µs): one `net_rx_action` round's time limit.
pub const NETDEV_BUDGET_NS: u64 = 2_000_000;

/// What a receive pump does after a NAPI poll that left work queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftirqNext {
    /// Poll again in this context.
    Repoll,
    /// The softirq bound is spent: hand the queue to its deferral task
    /// (`wakeup_softirqd`).
    Defer,
}

/// The work one softirq-context run (one IRQ wake) may do.
#[derive(Clone, Copy, Debug)]
pub struct SoftirqBudget {
    start_ns: u64,
    round_start_ns: u64,
    round_packets: u32,
    rounds: u32,
}

impl SoftirqBudget {
    /// A run starting at `now_ns`.
    pub fn start(now_ns: u64) -> Self {
        Self {
            start_ns: now_ns,
            round_start_ns: now_ns,
            round_packets: 0,
            rounds: 0,
        }
    }

    /// Account a NAPI poll that processed `processed` frames and left work
    /// queued, at `now_ns`.
    ///
    /// `net_rx_action` ends a round once it has processed `netdev_budget`
    /// packets or run `netdev_budget_usecs`; `__do_softirq` restarts it while
    /// it has run fewer than `MAX_SOFTIRQ_RESTART` rounds and for less than
    /// `MAX_SOFTIRQ_TIME`, then wakes ksoftirqd.
    pub fn account(&mut self, processed: u32, now_ns: u64) -> SoftirqNext {
        self.round_packets = self.round_packets.saturating_add(processed);
        if self.round_packets >= NETDEV_BUDGET
            || now_ns.saturating_sub(self.round_start_ns) >= NETDEV_BUDGET_NS
        {
            self.rounds += 1;
            self.round_packets = 0;
            self.round_start_ns = now_ns;
        }
        if self.rounds >= MAX_SOFTIRQ_RESTART
            || now_ns.saturating_sub(self.start_ns) >= MAX_SOFTIRQ_TIME_NS
        {
            SoftirqNext::Defer
        } else {
            SoftirqNext::Repoll
        }
    }
}

fn pinned_softirq_spec(cpu: u32) -> narf_scheduler::TaskSpec {
    let mut spec =
        narf_scheduler::TaskSpec::unthrottled().with_work_kind(narf_scheduler::WorkKind::SoftIrq);
    spec.affinity =
        narf_scheduler::affinity::Affinity::pinned(narf_scheduler::affinity::CpuId(cpu));
    spec
}

/// The task spec of a NIC queue's receive pump on `cpu`.
///
/// Linux polls a queue in softirq context on IRQ exit, before any task on
/// that CPU runs again. The pump is Interactive class so NARF's strict-class
/// dispatcher runs it ahead of the CPU's Default-class tasks; its
/// [`SoftirqBudget`] bounds how long it does so.
pub fn rx_pump_spec(cpu: u32) -> narf_scheduler::TaskSpec {
    let mut spec = pinned_softirq_spec(cpu);
    spec.class = narf_scheduler::SchedClass::Interactive;
    spec
}

/// The task spec of a queue's deferral task on `cpu`: ksoftirqd, a
/// normal-priority thread on the queue's CPU that takes the queue over when
/// a softirq run ends with work left, and shares the CPU with the tasks
/// there.
pub fn rx_deferral_spec(cpu: u32) -> Option<narf_scheduler::TaskSpec> {
    let mut spec = pinned_softirq_spec(cpu);
    spec.class = narf_scheduler::SchedClass::Default;
    Some(spec)
}

/// One queue's ownership between its receive pump and its deferral task:
/// `NAPI_STATE_SCHED` held across `wakeup_softirqd`. Exactly one of the two
/// polls the queue; the queue's interrupt stays masked while the deferral
/// task holds it, and the pump re-enables it once the queue comes back.
#[derive(Debug)]
pub struct SoftirqHandoff {
    deferred: AtomicBool,
    deferral: IrqSafeSpinLock<Option<Waker>>,
    pump: IrqSafeSpinLock<Option<Waker>>,
}

impl Default for SoftirqHandoff {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftirqHandoff {
    /// A queue its pump holds.
    pub const fn new() -> Self {
        Self {
            deferred: AtomicBool::new(false),
            deferral: IrqSafeSpinLock::new(None),
            pump: IrqSafeSpinLock::new(None),
        }
    }

    /// Whether the deferral task holds the queue.
    pub fn is_deferred(&self) -> bool {
        self.deferred.load(Ordering::Acquire)
    }

    /// Pump: the softirq bound is spent with work left; hand the queue to
    /// the deferral task and stop polling until [`returned`] resolves.
    ///
    /// [`returned`]: SoftirqHandoff::returned
    pub fn defer(&self) {
        // Release: the deferral task's first poll sees the ring state this
        // pump's last poll left.
        self.deferred.store(true, Ordering::Release);
        wake(&self.deferral);
    }

    /// Deferral task: resolves once the pump has handed the queue over.
    pub fn taken(&self) -> impl Future<Output = ()> + '_ {
        core::future::poll_fn(move |cx| park(&self.deferral, cx, || self.is_deferred()))
    }

    /// Deferral task: the queue is drained; give it back to the pump, which
    /// completes it (`napi_complete_done`) and re-enables its interrupt.
    pub fn hand_back(&self) {
        self.deferred.store(false, Ordering::Release);
        wake(&self.pump);
    }

    /// Pump: resolves once the deferral task has handed the queue back.
    pub fn returned(&self) -> impl Future<Output = ()> + '_ {
        core::future::poll_fn(move |cx| park(&self.pump, cx, || !self.is_deferred()))
    }
}

fn wake(slot: &IrqSafeSpinLock<Option<Waker>>) {
    // Taken under the lock, woken after it is released.
    let waker = slot.lock().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// Register `cx`'s waker in `slot`, then check `ready`: a hand-over that
/// lands between the check and the registration is seen by the re-check.
fn park(
    slot: &IrqSafeSpinLock<Option<Waker>>,
    cx: &mut core::task::Context<'_>,
    ready: impl Fn() -> bool,
) -> core::task::Poll<()> {
    if ready() {
        return core::task::Poll::Ready(());
    }
    {
        let mut slot = slot.lock();
        if !slot.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            *slot = Some(cx.waker().clone());
        }
    }
    if ready() {
        core::task::Poll::Ready(())
    } else {
        core::task::Poll::Pending
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod softirq_tests {
    //! The receive pump's policy on one CPU, simulated against NARF's
    //! strict-class dispatcher: a higher class always runs first; tasks of
    //! one class share the CPU in slices. A Default-class hog is always
    //! runnable on the queue's CPU, as in the desktop reproduction (a busy
    //! loop pinned to each queue CPU dropped RQDPC on igc queue 2).
    use super::*;
    use alloc::{sync::Arc, vec::Vec};
    use core::{pin::Pin, sync::atomic::AtomicU32};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_scheduler::SchedClass;

    /// Cost of one received frame in a NAPI poll.
    const POLL_NS_PER_FRAME: u64 = 50;
    /// Time slice two Default-class tasks share the CPU by.
    const SLICE_NS: u64 = 1_000_000;
    /// The hog runs in quanta this long; an IRQ-woken higher-class task
    /// preempts at a quantum boundary.
    const HOG_QUANTUM_NS: u64 = 1_000;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Who {
        Pump,
        Deferral,
        Hog,
    }

    #[derive(Default, Debug)]
    struct Outcome {
        /// Frames that found the ring full (igc RQDPC).
        overruns: u64,
        hog_ran_ns: u64,
        /// The longest stretch the softirq-context pump kept a runnable hog
        /// off the CPU.
        max_softirq_stretch_ns: u64,
        deferral_polls: u64,
        first_deferral_ns: Option<u64>,
        /// Frames the softirq-context pump processed before its first
        /// deferral.
        softirq_frames_before_defer: u64,
    }

    fn rank(class: SchedClass) -> u8 {
        match class {
            SchedClass::Idle => 0,
            SchedClass::Batch => 1,
            SchedClass::Default => 2,
            SchedClass::Interactive => 3,
            SchedClass::Realtime => 4,
        }
    }

    /// `arrivals_per_us` frames reach a `ring_cap`-slot ring every µs for
    /// `duration_us`.
    fn simulate(arrivals_per_us: u64, ring_cap: u64, duration_us: u64) -> Outcome {
        let pump_class = rx_pump_spec(0).class;
        let deferral_class = rx_deferral_spec(0).map(|spec| spec.class);
        let mut out = Outcome::default();
        let (mut now, end) = (0u64, duration_us * 1000);
        let (mut ring, mut arrival_acc) = (0u64, 0u64);
        let (mut armed, mut irq, mut softirq, mut deferred) = (true, false, false, false);
        let mut budget = SoftirqBudget::start(0);
        let mut stretch_start: Option<u64> = None;
        let (mut holder, mut holder_since) = (Who::Hog, 0u64);
        while now < end {
            let pump_ready = !deferred && (irq || softirq);
            let deferral_ready = deferred && deferral_class.is_some();
            let mut ready: Vec<(Who, SchedClass)> = Vec::new();
            if pump_ready {
                ready.push((Who::Pump, pump_class));
            }
            if deferral_ready {
                ready.push((Who::Deferral, deferral_class.unwrap_or(SchedClass::Default)));
            }
            ready.push((Who::Hog, SchedClass::Default));
            let top = ready.iter().map(|(_, c)| rank(*c)).max().unwrap_or(0);
            let peers: Vec<Who> = ready
                .iter()
                .filter(|(_, c)| rank(*c) == top)
                .map(|(w, _)| *w)
                .collect();
            let who = if peers.len() == 1 {
                peers[0]
            } else if peers.contains(&holder) && now - holder_since < SLICE_NS {
                holder
            } else {
                let next = peers
                    .iter()
                    .copied()
                    .find(|w| *w != holder)
                    .unwrap_or(peers[0]);
                holder = next;
                holder_since = now;
                next
            };
            if who == Who::Pump && stretch_start.is_none() {
                stretch_start = Some(now);
            }
            let (cost, polled) = match who {
                Who::Hog => {
                    if let Some(start) = stretch_start.take() {
                        out.max_softirq_stretch_ns = out.max_softirq_stretch_ns.max(now - start);
                    }
                    out.hog_ran_ns += HOG_QUANTUM_NS;
                    (HOG_QUANTUM_NS, 0)
                }
                Who::Pump | Who::Deferral => {
                    if who == Who::Pump && irq {
                        irq = false;
                        softirq = true;
                        budget = SoftirqBudget::start(now);
                    }
                    let n = ring.min(u64::from(DEFAULT_BUDGET));
                    ring -= n;
                    ((n * POLL_NS_PER_FRAME).max(100), n as u32)
                }
            };
            // Frames keep arriving while the CPU works.
            arrival_acc += arrivals_per_us * cost;
            let arrived = arrival_acc / 1000;
            arrival_acc %= 1000;
            ring += arrived;
            if ring > ring_cap {
                out.overruns += ring - ring_cap;
                ring = ring_cap;
            }
            now += cost;
            match who {
                Who::Pump => {
                    if out.first_deferral_ns.is_none() {
                        out.softirq_frames_before_defer += u64::from(polled);
                    }
                    if ring == 0 {
                        softirq = false;
                        armed = true;
                    } else if budget.account(polled, now) == SoftirqNext::Defer
                        && deferral_class.is_some()
                    {
                        softirq = false;
                        deferred = true;
                        out.first_deferral_ns.get_or_insert(now);
                    }
                }
                Who::Deferral => {
                    out.deferral_polls += 1;
                    if ring == 0 {
                        deferred = false;
                        armed = true;
                    }
                }
                Who::Hog => {}
            }
            if armed && ring > 0 {
                armed = false;
                irq = true;
            }
        }
        if let Some(start) = stretch_start {
            out.max_softirq_stretch_ns = out.max_softirq_stretch_ns.max(now - start);
        }
        out
    }

    /// `__do_softirq` + `net_rx_action`: a softirq run ends after
    /// MAX_SOFTIRQ_RESTART rounds of NETDEV_BUDGET packets, or after
    /// MAX_SOFTIRQ_TIME, whichever comes first, and never before.
    fn smoke_softirq_budget_bounds_one_irq_wake() -> TestResult {
        // Fast polls: the round count ends the run.
        let mut budget = SoftirqBudget::start(0);
        let mut polls = 0u32;
        let mut now = 0u64;
        loop {
            polls += 1;
            now += 3_200;
            if budget.account(DEFAULT_BUDGET, now) == SoftirqNext::Defer {
                break;
            }
            if polls > 1_000 {
                return TestResult::Fail("fast polls never ended the softirq run");
            }
        }
        // 300 packets end a round after five 64-frame polls; ten rounds.
        if polls != 50 {
            return TestResult::Fail("the run did not end after ten 300-packet rounds");
        }
        // Slow polls: MAX_SOFTIRQ_TIME ends the run.
        let mut budget = SoftirqBudget::start(0);
        let mut deferred_at = None;
        for i in 1..=8u64 {
            if budget.account(8, i * 600_000) == SoftirqNext::Defer {
                deferred_at = Some(i * 600_000);
                break;
            }
        }
        if deferred_at != Some(2_400_000) {
            return TestResult::Fail("the run did not end at the first poll past 2 ms");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/napi-softirq", smoke_softirq_budget_bounds_one_irq_wake);

    /// A Default-class hog pinned to the queue's CPU: a softirq-priority
    /// pump drains the ring as frames arrive, so nothing overruns. A pump
    /// sharing the CPU with the hog waits out the hog's slice while the
    /// ring fills (the RQDPC drops seen on the desktop).
    fn smoke_softirq_pump_drains_under_a_cpu_hog() -> TestResult {
        let out = simulate(1, 256, 20_000);
        if out.overruns != 0 {
            return TestResult::Fail("the ring overran while a hog shared the queue CPU");
        }
        if out.hog_ran_ns < 10_000_000 {
            return TestResult::Fail("the hog was starved at a load the pump keeps up with");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "net/napi-softirq",
        smoke_softirq_pump_drains_under_a_cpu_hog
    );

    /// A flood the queue cannot keep up with: the softirq-context pump
    /// stops at the softirq bound and its Default-class deferral task (the
    /// ksoftirqd role) takes the queue over, so the hog keeps running and is
    /// never kept off the CPU by softirq work for longer than the bound.
    fn smoke_softirq_flood_defers_and_never_starves() -> TestResult {
        let out = simulate(40, 256, 20_000);
        let Some(first) = out.first_deferral_ns else {
            return TestResult::Fail("no deferral task took the flooded queue over");
        };
        if out.deferral_polls == 0 {
            return TestResult::Fail("the deferral task never polled the queue");
        }
        // Not before the bound: ten full rounds, or 2 ms.
        if out.softirq_frames_before_defer
            < u64::from(MAX_SOFTIRQ_RESTART) * u64::from(NETDEV_BUDGET)
            && first < MAX_SOFTIRQ_TIME_NS
        {
            return TestResult::Fail("the queue was deferred before the softirq bound");
        }
        if out.max_softirq_stretch_ns > MAX_SOFTIRQ_TIME_NS + 64 * POLL_NS_PER_FRAME {
            return TestResult::Fail("softirq work kept the hog off the CPU past 2 ms");
        }
        if out.hog_ran_ns < 8_000_000 {
            return TestResult::Fail("the hog did not get its share under a flood");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "net/napi-softirq",
        smoke_softirq_flood_defers_and_never_starves
    );

    struct Wakes(AtomicU32);
    impl alloc::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn poll_once<F: Future<Output = ()>>(f: Pin<&mut F>, w: &Waker) -> bool {
        let mut cx = core::task::Context::from_waker(w);
        f.poll(&mut cx).is_ready()
    }

    /// The pump defers: the deferral task is woken and owns the queue; the
    /// pump waits until it is handed back, is woken then, and owns it again.
    fn smoke_softirq_handoff_passes_the_queue_both_ways() -> TestResult {
        let handoff = SoftirqHandoff::new();
        let deferral_wakes = Arc::new(Wakes(AtomicU32::new(0)));
        let pump_wakes = Arc::new(Wakes(AtomicU32::new(0)));
        let deferral_waker = Waker::from(deferral_wakes.clone());
        let pump_waker = Waker::from(pump_wakes.clone());
        for _ in 0..2 {
            // The deferral task parks until it is handed the queue.
            let mut taken = core::pin::pin!(handoff.taken());
            if poll_once(taken.as_mut(), &deferral_waker) {
                return TestResult::Fail("the deferral task took a queue its pump holds");
            }
            let before = deferral_wakes.0.load(Ordering::Acquire);
            handoff.defer();
            if !handoff.is_deferred() {
                return TestResult::Fail("defer did not hand the queue to the deferral task");
            }
            if deferral_wakes.0.load(Ordering::Acquire) != before + 1 {
                return TestResult::Fail("defer did not wake the deferral task");
            }
            if !poll_once(taken.as_mut(), &deferral_waker) {
                return TestResult::Fail("the woken deferral task did not get the queue");
            }
            // The pump waits for the queue to come back.
            let mut returned = core::pin::pin!(handoff.returned());
            if poll_once(returned.as_mut(), &pump_waker) {
                return TestResult::Fail("the pump resumed while the deferral task held the queue");
            }
            let before = pump_wakes.0.load(Ordering::Acquire);
            handoff.hand_back();
            if handoff.is_deferred() {
                return TestResult::Fail("hand_back left the queue with the deferral task");
            }
            if pump_wakes.0.load(Ordering::Acquire) != before + 1 {
                return TestResult::Fail("hand_back did not wake the pump");
            }
            if !poll_once(returned.as_mut(), &pump_waker) {
                return TestResult::Fail("the woken pump did not get the queue back");
            }
        }
        // Handed over before the deferral task parks: it takes the queue at
        // once, without a wake.
        handoff.defer();
        let mut taken = core::pin::pin!(handoff.taken());
        if !poll_once(taken.as_mut(), &deferral_waker) {
            return TestResult::Fail("a deferral task arriving late missed the hand-over");
        }
        handoff.hand_back();
        TestResult::Pass
    }
    kernel_test_in!("net/napi-softirq", smoke_softirq_handoff_passes_the_queue_both_ways);
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
