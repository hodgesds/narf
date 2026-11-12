//! High-resolution timers — Linux `kernel/time/hrtimer.c`.
//!
//! Every CPU owns an [`HrTimerCpuBase`] (`struct hrtimer_cpu_base`) with
//! eight clock bases (`HRTIMER_MAX_CLOCK_BASES`): MONOTONIC, REALTIME,
//! BOOTTIME and TAI, each in a hard-IRQ and a `_SOFT` variant. Each clock
//! base is a [`TimerQueueHead`] — a red-black tree ordered by expiry with the
//! earliest node cached — of intrusive [`HrTimer`] nodes. Nothing on these
//! paths allocates, frees, or has a capacity limit: a timer is linked through
//! the node embedded in it.
//!
//! * **Enqueue** (`hrtimer_start_range_ns`) queues on the *calling* CPU's base
//!   (Linux `switch_hrtimer_base`: an unpinned restart from another CPU moves
//!   the timer, except while its callback runs). If it becomes that base's
//!   earliest event, the local clockevent is reprogrammed at once
//!   (`hrtimer_reprogram` → `tick_program_event`) through the arm callback
//!   the arch timer installs.
//! * **Expiry** runs on each CPU from its own timer interrupt
//!   ([`hrtimer_interrupt`]): hard bases expire in the interrupt; soft bases
//!   are flagged and expire from the executor ([`hrtimer_run_softirq`]),
//!   NARF's `HRTIMER_SOFTIRQ`. Afterwards the interrupt returns the next
//!   event and the arch code programs the local clockevent to it.
//! * **Remote earlier event**: an enqueue that lands on another CPU's base
//!   (a callback-running timer restarted elsewhere, or a timer handed over at
//!   CPU offline) and is earlier than that CPU's programmed event publishes
//!   the new `expires_next` under the remote base lock, then sends the CPU a
//!   reschedule IPI whose handler re-programs from the base
//!   ([`retrigger_next_event`]; Linux `retrigger_next_event` /
//!   `trigger_dyntick_cpu`). The IPI is unconditional, so a CPU halting
//!   concurrently can never sleep through the new event.
//! * **Sleepers** ([`SleepHandle`], Linux `struct hrtimer_sleeper`): the
//!   expiry callback (`hrtimer_wakeup`) wakes the task by reference. A
//!   scheduler-owned waker takes the IRQ-safe path in hard-IRQ context, so the
//!   wake is placed immediately; the `Waker` itself stays in the sleeper and is
//!   only dropped by its owner, in task context. Other wakers are queued on the
//!   `_SOFT` base and woken from the executor.
//!
//! Time unit: nanoseconds of the timer's clock (`ktime_t`). MONOTONIC is
//! [`crate::monotonic_ns`]; REALTIME and TAI are MONOTONIC plus the wall
//! offset (TAI adds the NTP TAI offset); BOOTTIME is MONOTONIC plus the time
//! spent suspended (`offs_boot`). The clockevent hook takes monotonic counter
//! cycles; a clockevent that compares against the raw counter converts.
//!
//! Lock order: a CPU base lock is never held while another CPU base lock is
//! taken (`switch_hrtimer_base` releases the old base before it locks the new
//! one, with the timer marked migrating in between), and no callback runs
//! with a base lock held. A sleeper's waker lock nests inside nothing.

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{
    fence, AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering,
};
use core::task::Waker;

use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::{IrqSafeSpinLock, IrqSafeSpinLockGuard};

use crate::timerqueue::{TimerQueueHead, TimerQueueNode};

/// `ktime_t`: nanoseconds.
pub type Ktime = u64;

/// `KTIME_MAX`: no event.
pub const KTIME_MAX: Ktime = u64::MAX;

/// Clock a timer is measured against (Linux `clockid_t` subset with bases).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockId {
    Monotonic = 0,
    Realtime = 1,
    Boottime = 2,
    Tai = 3,
}

/// `HRTIMER_MAX_CLOCK_BASES`: four clocks, hard and soft.
pub const HRTIMER_MAX_CLOCK_BASES: usize = 8;
const HRTIMER_BASE_SOFT: usize = 4;
const HRTIMER_ACTIVE_HARD: u8 = 0x0f;
const HRTIMER_ACTIVE_SOFT: u8 = 0xf0;

/// `enum hrtimer_mode`, as bit flags.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HrtimerMode(u8);

impl HrtimerMode {
    /// Absolute expiry.
    pub const ABS: Self = Self(0x00);
    /// Expiry relative to now.
    pub const REL: Self = Self(0x01);
    /// Keep the timer on the CPU it is started on.
    pub const PINNED: Self = Self(0x02);
    /// Expire from the softirq-equivalent rather than hard IRQ.
    pub const SOFT: Self = Self(0x04);
    /// Expire in hard IRQ even where soft would be the default.
    pub const HARD: Self = Self(0x08);
    pub const ABS_PINNED: Self = Self(0x02);
    pub const REL_PINNED: Self = Self(0x03);
    pub const ABS_SOFT: Self = Self(0x04);
    pub const REL_SOFT: Self = Self(0x05);
    pub const ABS_HARD: Self = Self(0x08);
    pub const REL_HARD: Self = Self(0x09);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Return value of a timer callback (`enum hrtimer_restart`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HrtimerRestart {
    NoRestart,
    Restart,
}

/// Timer callback. Runs without any base lock held, in hard-IRQ context for
/// hard bases and executor context for soft bases. It must not allocate,
/// free, block, or cancel its own timer.
pub type HrTimerFn = fn(&HrTimer) -> HrtimerRestart;

const STATE_INACTIVE: u8 = 0;
const STATE_ENQUEUED: u8 = 1;

/// `timer->base` not yet set: the timer was never started.
const CPU_UNBOUND: u32 = u32::MAX;
/// `migration_base`: the timer is between two CPU bases.
const CPU_MIGRATING: u32 = u32::MAX - 1;

/// A high-resolution timer (`struct hrtimer`).
///
/// The caller owns the storage. Once started, a timer must stay at the same
/// address and must not be freed until it is inactive and its callback is not
/// running, which [`hrtimer_cancel`] guarantees on return.
#[repr(C)]
pub struct HrTimer {
    node: UnsafeCell<TimerQueueNode>,
    softexpires: UnsafeCell<Ktime>,
    function: HrTimerFn,
    /// Clock base index (`clock + 4` for soft). Written only while the
    /// caller holds the timer's base or its migration claim.
    base_index: AtomicU8,
    /// CPU whose base holds the timer, or `CPU_UNBOUND` / `CPU_MIGRATING`.
    cpu: AtomicU32,
    /// `STATE_*`, written under the base lock.
    state: AtomicU8,
    /// Callback in progress (`cpu_base->running == timer`).
    running: AtomicBool,
}

// SAFETY: the `UnsafeCell` fields are touched only under the lock of the CPU
// base named by `cpu`, or by the single holder of the `CPU_MIGRATING` claim,
// or by the running callback while the timer is unlinked (Linux rules).
unsafe impl Sync for HrTimer {}
// SAFETY: as above; no thread affinity.
unsafe impl Send for HrTimer {}

impl core::fmt::Debug for HrTimer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HrTimer")
            .field("cpu", &self.cpu.load(Ordering::Relaxed))
            .field("state", &self.state.load(Ordering::Relaxed))
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl HrTimer {
    /// `hrtimer_setup(timer, function, clock_id, mode)`. `mode` selects the
    /// soft or hard base; the absolute/relative bit is given at start.
    pub const fn new(function: HrTimerFn, clock: ClockId, mode: HrtimerMode) -> Self {
        let soft = mode.contains(HrtimerMode::SOFT) && !mode.contains(HrtimerMode::HARD);
        Self {
            node: UnsafeCell::new(TimerQueueNode::new()),
            softexpires: UnsafeCell::new(0),
            function,
            base_index: AtomicU8::new(clock as u8 + if soft { HRTIMER_BASE_SOFT as u8 } else { 0 }),
            cpu: AtomicU32::new(CPU_UNBOUND),
            state: AtomicU8::new(STATE_INACTIVE),
            running: AtomicBool::new(false),
        }
    }

    #[inline]
    fn node_ptr(&self) -> *mut TimerQueueNode {
        self.node.get()
    }

    /// `container_of(node, struct hrtimer, node)`.
    #[inline]
    fn from_node(node: *mut TimerQueueNode) -> *const HrTimer {
        // `node` is the first field of a `repr(C)` struct.
        node as *const HrTimer
    }

    /// Clock this timer runs against.
    pub fn clock(&self) -> ClockId {
        match self.base_index.load(Ordering::Relaxed) as usize % HRTIMER_BASE_SOFT {
            0 => ClockId::Monotonic,
            1 => ClockId::Realtime,
            2 => ClockId::Boottime,
            _ => ClockId::Tai,
        }
    }

    /// Hard expiry (`hrtimer_get_expires`). Racy unless the caller owns the
    /// timer's state.
    pub fn expires(&self) -> Ktime {
        // SAFETY: a torn read is impossible for an aligned u64; staleness is
        // the documented race.
        unsafe { ptr::read_volatile(ptr::addr_of!((*self.node.get()).expires)) }
    }

    /// Soft expiry (`hrtimer_get_softexpires`).
    pub fn softexpires(&self) -> Ktime {
        // SAFETY: as for `expires`.
        unsafe { ptr::read_volatile(self.softexpires.get()) }
    }

    /// CPU whose base holds the timer, if it was ever started and is not
    /// mid-migration.
    pub fn cpu(&self) -> Option<u32> {
        let c = self.cpu.load(Ordering::Acquire);
        (c < CPU_MIGRATING).then_some(c)
    }

    /// `hrtimer_is_queued`.
    pub fn is_queued(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_ENQUEUED
    }

    /// `hrtimer_callback_running`.
    pub fn callback_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// `hrtimer_active`: queued or its callback is running.
    pub fn is_active(&self) -> bool {
        self.is_queued() || self.callback_running()
    }

    /// `hrtimer_set_expires_range_ns`. Only while not queued (from the
    /// callback before returning `Restart`, or before starting).
    fn set_expires_range(&self, soft: Ktime, delta: u64) {
        // SAFETY: callers own the unlinked timer (see the `Sync` impl).
        unsafe {
            *self.softexpires.get() = soft;
            (*self.node.get()).expires = soft.saturating_add(delta);
        }
    }

    /// `hrtimer_forward(timer, now, interval)`: push the expiry forward by
    /// whole intervals until it is after `now`; returns the overrun count.
    /// Call only from the callback or while the timer is inactive.
    pub fn forward(&self, now: Ktime, interval: u64) -> u64 {
        let exp = self.expires();
        if now < exp || interval == 0 {
            return 0;
        }
        let delta = now - exp;
        let mut orun = delta / interval + 1;
        let mut next = exp.saturating_add(orun.saturating_mul(interval));
        if next <= now {
            orun += 1;
            next = next.saturating_add(interval);
        }
        let slack = exp - self.softexpires();
        self.set_expires_range(next.saturating_sub(slack), slack);
        orun
    }
}

// ── per-CPU bases ───────────────────────────────────────────────────────

struct CpuBaseInner {
    clock_base: [TimerQueueHead; HRTIMER_MAX_CLOCK_BASES],
    active_bases: u8,
    /// Programmed next event, monotonic ns (`cpu_base->expires_next`).
    expires_next: Ktime,
    /// Earliest soft expiry, monotonic ns (`softirq_expires_next`).
    softirq_expires_next: Ktime,
    in_hrtirq: bool,
    softirq_activated: bool,
    nr_queued: usize,
}

/// One CPU's timer state (`struct hrtimer_cpu_base`).
pub struct HrTimerCpuBase {
    cpu: u32,
    inner: IrqSafeSpinLock<CpuBaseInner>,
    /// Lock-free copy of `expires_next` for the idle path and diagnostics.
    next_event: AtomicU64,
    /// Lock-free copy of `nr_queued`.
    queued: AtomicUsize,
    /// `HRTIMER_SOFTIRQ` raised.
    softirq_raised: AtomicBool,
    /// A remote enqueue asked this CPU to re-program (consumed by the IPI).
    retrigger: AtomicBool,
    /// Callbacks run from this base (diagnostic).
    nr_events: AtomicU64,
}

impl core::fmt::Debug for HrTimerCpuBase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HrTimerCpuBase")
            .field("cpu", &self.cpu)
            .field("next_event", &self.next_event.load(Ordering::Relaxed))
            .field("queued", &self.queued.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// SAFETY: the raw node pointers in `inner` are guarded by its lock.
unsafe impl Send for CpuBaseInner {}

type Guard = IrqSafeSpinLockGuard<'static, CpuBaseInner>;

impl HrTimerCpuBase {
    fn new(cpu: u32) -> Self {
        Self {
            cpu,
            inner: IrqSafeSpinLock::new(CpuBaseInner {
                clock_base: [const { TimerQueueHead::new() }; HRTIMER_MAX_CLOCK_BASES],
                active_bases: 0,
                expires_next: KTIME_MAX,
                softirq_expires_next: KTIME_MAX,
                in_hrtirq: false,
                softirq_activated: false,
                nr_queued: 0,
            }),
            next_event: AtomicU64::new(KTIME_MAX),
            queued: AtomicUsize::new(0),
            softirq_raised: AtomicBool::new(false),
            retrigger: AtomicBool::new(false),
            nr_events: AtomicU64::new(0),
        }
    }
}

/// Bases are allocated per CPU at bring-up (`hrtimers_prepare_cpu`), not
/// sized into a static: this array holds only the pointers.
static CPU_BASES: [AtomicPtr<HrTimerCpuBase>; MAX_CPUS] =
    [const { AtomicPtr::new(ptr::null_mut()) }; MAX_CPUS];

/// `hrtimers_prepare_cpu`: allocate `cpu`'s base if it has none. Must run in
/// a context that may allocate (not hard IRQ). Idempotent.
pub fn hrtimers_prepare_cpu(cpu: usize) {
    if cpu >= MAX_CPUS || !CPU_BASES[cpu].load(Ordering::Acquire).is_null() {
        return;
    }
    let fresh = Box::into_raw(Box::new(HrTimerCpuBase::new(cpu as u32)));
    if CPU_BASES[cpu]
        .compare_exchange(ptr::null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // SAFETY: `fresh` was never published; we still own it.
        drop(unsafe { Box::from_raw(fresh) });
    }
}

/// Base of `cpu`, if it has been prepared.
#[inline]
fn cpu_base(cpu: usize) -> Option<&'static HrTimerCpuBase> {
    let p = CPU_BASES.get(cpu)?.load(Ordering::Acquire);
    // SAFETY: bases are leaked on publication and never freed.
    (!p.is_null()).then(|| unsafe { &*p })
}

#[inline]
fn this_cpu() -> usize {
    narf_lib::percpu::current_cpu().min(MAX_CPUS - 1)
}

/// The calling CPU's base, allocating it on first use outside hard IRQ.
/// A CPU with no base in hard-IRQ context borrows CPU 0's (prepared at boot).
fn this_cpu_base() -> &'static HrTimerCpuBase {
    let cpu = this_cpu();
    if let Some(b) = cpu_base(cpu) {
        return b;
    }
    if !narf_lib::context::in_irq() {
        hrtimers_prepare_cpu(cpu);
        if let Some(b) = cpu_base(cpu) {
            return b;
        }
    }
    hrtimers_prepare_cpu_boot();
    cpu_base(0).expect("CPU 0 hrtimer base")
}

fn hrtimers_prepare_cpu_boot() {
    if cpu_base(0).is_none() && !narf_lib::context::in_irq() {
        hrtimers_prepare_cpu(0);
    }
}

/// Boot entry (`hrtimers_init`): prepare the boot CPU's base.
pub fn hrtimers_init() {
    hrtimers_prepare_cpu(this_cpu());
    hrtimers_prepare_cpu(0);
}

// ── hooks installed by the arch timer / scheduler ───────────────────────

static ARM_CB: AtomicUsize = AtomicUsize::new(0);
static KICK_CB: AtomicUsize = AtomicUsize::new(0);
static HARDIRQ_WAKER_CB: AtomicUsize = AtomicUsize::new(0);

/// Install the local clockevent programmer (`tick_program_event`): program
/// THIS CPU's timer interrupt no later than `deadline_cycles`. Called with
/// IRQs masked; must be short and allocation-free.
pub fn set_arm_callback(f: fn(deadline_cycles: u64)) {
    ARM_CB.store(f as usize, Ordering::Release);
}

/// Remove the clockevent programmer (tests).
pub fn clear_arm_callback() {
    ARM_CB.store(0, Ordering::Release);
}

/// Whether a clockevent programmer is installed. Without one, consumers fall
/// back to polling.
#[inline]
pub fn arm_callback_installed() -> bool {
    ARM_CB.load(Ordering::Relaxed) != 0
}

/// Install the "make `cpu` re-evaluate its next event" IPI sender.
pub fn set_remote_kick(f: fn(cpu: u32)) {
    KICK_CB.store(f as usize, Ordering::Release);
}

/// Install the scheduler's predicate for wakers whose `wake_by_ref` is safe
/// in hard-IRQ context (allocation- and free-free).
pub fn set_hardirq_waker_predicate(f: fn(&Waker) -> bool) {
    HARDIRQ_WAKER_CB.store(f as usize, Ordering::Release);
}

#[inline]
fn tick_program_event(deadline_ns: Ktime) {
    if deadline_ns == KTIME_MAX {
        return;
    }
    let raw = ARM_CB.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }
    // SAFETY: only `fn(u64)` values are stored by `set_arm_callback`.
    let f: fn(u64) = unsafe { core::mem::transmute(raw) };
    f(ns_to_deadline_cycles(deadline_ns));
}

/// Monotonic cycle count at which `ns` of monotonic time has certainly
/// passed. Clockevents that compare against the raw counter convert with
/// [`crate::mono_to_raw_cycles`].
#[inline]
pub fn ns_to_deadline_cycles(ns: Ktime) -> u64 {
    if ns == KTIME_MAX {
        return u64::MAX;
    }
    crate::ns_to_cycles(ns).saturating_add(1)
}

fn remote_kick(cpu: u32) {
    // An offline CPU takes no IPI; its timers move at offline time.
    if !narf_lib::smp::is_online(cpu) {
        return;
    }
    let raw = KICK_CB.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }
    // SAFETY: only `fn(u32)` values are stored by `set_remote_kick`.
    let f: fn(u32) = unsafe { core::mem::transmute(raw) };
    f(cpu);
}

fn waker_is_hardirq_safe(w: &Waker) -> bool {
    let raw = HARDIRQ_WAKER_CB.load(Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: only `fn(&Waker) -> bool` values are stored.
    let f: fn(&Waker) -> bool = unsafe { core::mem::transmute(raw) };
    f(w)
}

// ── clocks ──────────────────────────────────────────────────────────────

static TAI_OFFSET_NS: AtomicU64 = AtomicU64::new(0);

/// Set the TAI−UTC offset (`timekeeping_set_tai_offset`).
pub fn set_tai_offset_ns(off: u64) {
    TAI_OFFSET_NS.store(off, Ordering::Release);
    clock_was_set();
}

/// `base->offset`: base clock minus monotonic, in ns.
#[inline]
fn base_offset(index: usize) -> i64 {
    match index % HRTIMER_BASE_SOFT {
        1 => crate::wall_offset_ns(),
        2 => crate::boot_offset_ns() as i64,
        3 => crate::wall_offset_ns().saturating_add(TAI_OFFSET_NS.load(Ordering::Relaxed) as i64),
        _ => 0,
    }
}

#[inline]
fn add_offset(t: Ktime, off: i64) -> Ktime {
    if t == KTIME_MAX {
        return KTIME_MAX;
    }
    (t as i128 + off as i128).clamp(0, (KTIME_MAX - 1) as i128) as Ktime
}

#[inline]
fn sub_offset(t: Ktime, off: i64) -> Ktime {
    if t == KTIME_MAX {
        return KTIME_MAX;
    }
    (t as i128 - off as i128).clamp(0, (KTIME_MAX - 1) as i128) as Ktime
}

/// Current time of `clock` in ns (`base->get_time()`).
pub fn clock_now(clock: ClockId) -> Ktime {
    add_offset(crate::monotonic_ns(), base_offset(clock as usize))
}

// ── locking a timer's base ──────────────────────────────────────────────

enum Locked {
    Base(&'static HrTimerCpuBase, Guard),
    /// Never started; the caller holds the migration claim.
    Unbound,
}

/// `lock_hrtimer_base`. IRQs must be masked by the caller.
fn lock_hrtimer_base(timer: &HrTimer) -> Locked {
    loop {
        let c = timer.cpu.load(Ordering::Acquire);
        match c {
            CPU_MIGRATING => core::hint::spin_loop(),
            CPU_UNBOUND => {
                if timer
                    .cpu
                    .compare_exchange(
                        CPU_UNBOUND,
                        CPU_MIGRATING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return Locked::Unbound;
                }
            }
            _ => {
                let base = cpu_base(c as usize).expect("timer bound to an unprepared CPU base");
                let g = base.inner.lock();
                if timer.cpu.load(Ordering::Acquire) == c {
                    return Locked::Base(base, g);
                }
            }
        }
    }
}

// ── queue primitives (base lock held) ───────────────────────────────────

/// Monotonic-ns expiry of the earliest timer among `mask` bases
/// (`__hrtimer_next_event_base`).
fn next_event_bases(inner: &CpuBaseInner, mask: u8) -> Ktime {
    let mut next = KTIME_MAX;
    let mut bits = inner.active_bases & mask;
    while bits != 0 {
        let i = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        let first = inner.clock_base[i].first();
        if first.is_null() {
            continue;
        }
        // SAFETY: linked nodes are live while the base lock is held.
        let exp = unsafe { (*first).expires };
        next = next.min(sub_offset(exp, base_offset(i)));
    }
    next
}

/// `hrtimer_update_next_event`: soft events count unless the softirq is
/// already pending (it re-programs when it finishes).
fn update_next_event(base: &HrTimerCpuBase, inner: &mut CpuBaseInner) -> Ktime {
    let soft = if inner.softirq_activated {
        KTIME_MAX
    } else {
        next_event_bases(inner, HRTIMER_ACTIVE_SOFT)
    };
    inner.softirq_expires_next = soft;
    let next = next_event_bases(inner, HRTIMER_ACTIVE_HARD).min(soft);
    inner.expires_next = next;
    base.next_event.store(next, Ordering::Release);
    next
}

/// Link `timer` into `inner`'s clock base. Returns true when it is the new
/// earliest event of the whole CPU base.
///
/// # Safety
/// `timer` is unlinked, owned by the caller, and stays put while linked.
unsafe fn enqueue_hrtimer(
    base: &HrTimerCpuBase,
    inner: &mut CpuBaseInner,
    timer: &HrTimer,
) -> bool {
    let idx = timer.base_index.load(Ordering::Relaxed) as usize;
    inner.active_bases |= 1 << idx;
    timer.state.store(STATE_ENQUEUED, Ordering::Release);
    inner.nr_queued += 1;
    base.queued.store(inner.nr_queued, Ordering::Relaxed);
    // SAFETY: caller contract.
    let leftmost = unsafe { inner.clock_base[idx].add(timer.node_ptr()) };
    leftmost && sub_offset(timer.expires(), base_offset(idx)) < inner.expires_next
}

/// Unlink a queued `timer` (`__remove_hrtimer`).
fn remove_hrtimer(base: &HrTimerCpuBase, inner: &mut CpuBaseInner, timer: &HrTimer) -> bool {
    if timer.state.load(Ordering::Relaxed) != STATE_ENQUEUED {
        return false;
    }
    let idx = timer.base_index.load(Ordering::Relaxed) as usize;
    // SAFETY: ENQUEUED under this lock ⇒ linked into `clock_base[idx]`.
    let nonempty = unsafe { inner.clock_base[idx].remove(timer.node_ptr()) };
    if !nonempty {
        inner.active_bases &= !(1 << idx);
    }
    timer.state.store(STATE_INACTIVE, Ordering::Release);
    inner.nr_queued -= 1;
    base.queued.store(inner.nr_queued, Ordering::Relaxed);
    true
}

/// After an enqueue onto `base`: program the local clockevent, or ask a
/// remote CPU to re-program, when `expires` (monotonic ns) is the new first
/// event (`hrtimer_reprogram` / remote `trigger_dyntick_cpu`). Returns the
/// CPU to kick after the lock is dropped.
fn reprogram_after_enqueue(
    base: &HrTimerCpuBase,
    inner: &mut CpuBaseInner,
    timer: &HrTimer,
) -> Option<u32> {
    if inner.in_hrtirq {
        // The running interrupt recomputes the next event when it finishes.
        return None;
    }
    let idx = timer.base_index.load(Ordering::Relaxed) as usize;
    let expires = sub_offset(timer.expires(), base_offset(idx));
    if idx >= HRTIMER_BASE_SOFT {
        if inner.softirq_activated || expires >= inner.softirq_expires_next {
            return None;
        }
        inner.softirq_expires_next = expires;
    }
    if expires >= inner.expires_next {
        return None;
    }
    inner.expires_next = expires;
    base.next_event.store(expires, Ordering::Release);
    if base.cpu as usize == this_cpu() {
        tick_program_event(expires);
        None
    } else {
        base.retrigger.store(true, Ordering::Release);
        Some(base.cpu)
    }
}

// ── public timer operations ─────────────────────────────────────────────

/// `hrtimer_start_range_ns`: (re)arm `timer` to expire between `tim` and
/// `tim + delta_ns` (`mode` gives absolute/relative). The timer moves to the
/// calling CPU's base unless its callback is running.
///
/// # Safety
/// `timer` must stay at its address and not be freed until
/// [`hrtimer_cancel`] returned, or its callback returned `NoRestart` and it
/// was not restarted.
pub unsafe fn hrtimer_start_range_ns(
    timer: &HrTimer,
    tim: Ktime,
    delta_ns: u64,
    mode: HrtimerMode,
) {
    // SAFETY: caller contract.
    unsafe { start_on(timer, tim, delta_ns, mode, None) }
}

/// [`hrtimer_start_range_ns`] onto a named CPU's base (`add_timer_on`-style;
/// used by CPU offline migration and tests). The base must be prepared.
///
/// # Safety
/// As for [`hrtimer_start_range_ns`].
pub unsafe fn hrtimer_start_on(
    timer: &HrTimer,
    cpu: usize,
    tim: Ktime,
    delta_ns: u64,
    mode: HrtimerMode,
) {
    // SAFETY: caller contract.
    unsafe { start_on(timer, tim, delta_ns, mode, Some(cpu)) }
}

unsafe fn start_on(
    timer: &HrTimer,
    tim: Ktime,
    delta_ns: u64,
    mode: HrtimerMode,
    target: Option<usize>,
) {
    let kick = narf_lib::sync::without_interrupts(|| {
        // Resolve (and on first use allocate) the target before any base
        // lock is held.
        let want: &'static HrTimerCpuBase = match target {
            Some(cpu) => cpu_base(cpu).expect("hrtimer_start_on: CPU base not prepared"),
            None => this_cpu_base(),
        };
        let locked = lock_hrtimer_base(timer);
        let (old, mut g) = match locked {
            Locked::Base(b, mut g) => {
                remove_hrtimer(b, &mut g, timer);
                (Some(b), Some(g))
            }
            Locked::Unbound => (None, None),
        };
        let idx = timer.base_index.load(Ordering::Relaxed) as usize;
        let soft = if mode.contains(HrtimerMode::REL) {
            tim.saturating_add(add_offset(crate::monotonic_ns(), base_offset(idx)))
        } else {
            tim
        };
        timer.set_expires_range(soft, delta_ns);

        // switch_hrtimer_base: a running callback keeps the timer where it is.
        let keep = old.is_some_and(|b| timer.callback_running() || ptr::eq(b, want));
        let (base, mut guard) = if keep {
            (old.expect("kept base"), g.take().expect("kept guard"))
        } else {
            if g.is_some() {
                timer.cpu.store(CPU_MIGRATING, Ordering::Release);
                drop(g.take());
            }
            let ng = want.inner.lock();
            timer.cpu.store(want.cpu, Ordering::Release);
            (want, ng)
        };
        // SAFETY: the timer is unlinked and owned under `guard`; the caller
        // keeps it in place (function contract).
        let first = unsafe { enqueue_hrtimer(base, &mut guard, timer) };
        let kick = if first {
            reprogram_after_enqueue(base, &mut guard, timer)
        } else {
            None
        };
        drop(guard);
        kick
    });
    if let Some(cpu) = kick {
        // Publish (done under the remote lock), fence, then IPI — so the
        // target either sees the new event when it next programs or takes
        // the IPI after it did.
        fence(Ordering::SeqCst);
        REMOTE_KICKS.fetch_add(1, Ordering::Relaxed);
        remote_kick(cpu);
    }
}

/// Remote re-program IPIs sent (diagnostic / tests).
static REMOTE_KICKS: AtomicU64 = AtomicU64::new(0);

/// Number of remote re-program IPIs sent since boot.
pub fn remote_kicks() -> u64 {
    REMOTE_KICKS.load(Ordering::Relaxed)
}

/// `hrtimer_try_to_cancel`: 1 if it was queued and is now removed, 0 if it
/// was inactive, -1 if its callback is running.
pub fn hrtimer_try_to_cancel(timer: &HrTimer) -> i32 {
    if !timer.is_active() {
        return 0;
    }
    narf_lib::sync::without_interrupts(|| match lock_hrtimer_base(timer) {
        Locked::Unbound => {
            timer.cpu.store(CPU_UNBOUND, Ordering::Release);
            0
        }
        Locked::Base(b, mut g) => {
            if timer.callback_running() {
                return -1;
            }
            // A cancel never makes an event earlier; the programmed one may
            // fire spuriously and re-program (Linux skips reprogram too
            // unless the timer was the local first event).
            i32::from(remove_hrtimer(b, &mut g, timer))
        }
    })
}

/// `hrtimer_cancel`: cancel and wait for a running callback to finish. Must
/// not be called from the timer's own callback.
pub fn hrtimer_cancel(timer: &HrTimer) -> bool {
    loop {
        match hrtimer_try_to_cancel(timer) {
            -1 => core::hint::spin_loop(),
            r => return r == 1,
        }
    }
}

/// `hrtimer_get_remaining`: time to the soft expiry, 0 if due.
pub fn hrtimer_get_remaining(timer: &HrTimer) -> u64 {
    timer.softexpires().saturating_sub(clock_now(timer.clock()))
}

// ── expiry ──────────────────────────────────────────────────────────────

/// `__hrtimer_run_queues`: run every expired timer of `mask` bases.
fn run_queues(base: &'static HrTimerCpuBase, mut g: Guard, now: Ktime, mask: u8) -> Guard {
    let mut bits = g.active_bases & mask;
    while bits != 0 {
        let idx = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        let basenow = add_offset(now, base_offset(idx));
        loop {
            let node = g.clock_base[idx].first();
            if node.is_null() {
                break;
            }
            // SAFETY: linked ⇒ the owning timer is live (start contract).
            let timer = unsafe { &*HrTimer::from_node(node) };
            if basenow < timer.softexpires() {
                break;
            }
            g = run_hrtimer(base, g, timer, now);
        }
    }
    g
}

/// `__run_hrtimer`: unlink, run the callback unlocked, re-queue on restart.
fn run_hrtimer(base: &'static HrTimerCpuBase, mut g: Guard, timer: &HrTimer, now: Ktime) -> Guard {
    timer.running.store(true, Ordering::Release);
    remove_hrtimer(base, &mut g, timer);
    base.nr_events.fetch_add(1, Ordering::Relaxed);
    drop(g);
    let _ = now;
    let restart = (timer.function)(timer);
    let mut g = base.inner.lock();
    if restart == HrtimerRestart::Restart && timer.state.load(Ordering::Relaxed) == STATE_INACTIVE {
        // SAFETY: the restarting callback's owner keeps the timer alive.
        unsafe { enqueue_hrtimer(base, &mut g, timer) };
    }
    // Last touch of `timer`: after this a waiting `hrtimer_cancel` may free it.
    timer.running.store(false, Ordering::Release);
    g
}

/// Expire hard timers of `base` and flag due soft ones. Returns the next
/// event (monotonic ns).
fn expire_hard(base: &'static HrTimerCpuBase) -> Ktime {
    let mut g = base.inner.lock();
    g.in_hrtirq = true;
    let mut retries = 0;
    let next = loop {
        let now = crate::monotonic_ns();
        if !g.softirq_activated && now >= g.softirq_expires_next {
            g.softirq_expires_next = KTIME_MAX;
            g.softirq_activated = true;
            base.softirq_raised.store(true, Ordering::Release);
        }
        g = run_queues(base, g, now, HRTIMER_ACTIVE_HARD);
        let next = update_next_event(base, &mut g);
        // Linux retries a few times when callbacks ran past the next event.
        if next > crate::monotonic_ns() || retries >= 3 {
            break next;
        }
        retries += 1;
    };
    g.in_hrtirq = false;
    next
}

/// `hrtimer_interrupt`: the local timer interrupt. Expires this CPU's hard
/// timers, raises the soft expiry if due, and returns the next event in
/// clockevent cycles (`u64::MAX` when none) for the caller to program.
pub fn hrtimer_interrupt() -> u64 {
    // `run_local_timers`: raise the timer softirq when a wheel base is due.
    crate::timer::timer_tick();
    let Some(base) = cpu_base(this_cpu()) else {
        return ns_to_deadline_cycles(crate::timer::next_timer_event_ns_local());
    };
    let next = if base.next_event.load(Ordering::Acquire) > crate::monotonic_ns()
        && !base.retrigger.swap(false, Ordering::AcqRel)
    {
        base.next_event.load(Ordering::Acquire)
    } else {
        expire_hard(base)
    };
    // The clockevent also carries the timer wheel's next expiry.
    ns_to_deadline_cycles(next.min(crate::timer::next_timer_event_ns_local()))
}

/// Make `cpu` re-evaluate its next event now: set its retrigger flag, then
/// send it the reschedule IPI (`trigger_dyntick_cpu`). Used when a timer is
/// queued on another CPU's base.
pub fn kick_cpu_next_event(cpu: u32) {
    if let Some(base) = cpu_base(cpu as usize) {
        base.retrigger.store(true, Ordering::Release);
        fence(Ordering::SeqCst);
        remote_kick(cpu);
    }
}

/// `hrtimer_run_queues`: the periodic-tick (low-resolution) expiry path, for
/// clockevents that cannot be programmed per event. Programs the local
/// clockevent hook (if any) for the next event.
pub fn hrtimer_run_queues() {
    let Some(base) = cpu_base(this_cpu()) else {
        return;
    };
    if base.next_event.load(Ordering::Acquire) > crate::monotonic_ns() {
        return;
    }
    let next = expire_hard(base);
    tick_program_event(next);
}

/// `hrtimer_run_softirq`: expire this CPU's soft timers (executor context).
/// Also expires hard timers already due, so a missed or not-yet-delivered
/// interrupt never strands a local timer. Returns the callbacks run.
pub fn hrtimer_run_softirq() -> u64 {
    let Some(base) = cpu_base(this_cpu()) else {
        return 0;
    };
    let before = base.nr_events.load(Ordering::Relaxed);
    // `TIMER_SOFTIRQ`: the timer wheel expires in the same context.
    let wheel = crate::timer::run_timer_softirq();
    let now = crate::monotonic_ns();
    // Load first: this runs on every executor round, and an unconditional
    // swap would dirty the line each time.
    let raised = base.softirq_raised.load(Ordering::Relaxed)
        && base.softirq_raised.swap(false, Ordering::AcqRel);
    if raised || base.next_event.load(Ordering::Acquire) <= now {
        let next = narf_lib::sync::without_interrupts(|| {
            let mut g = base.inner.lock();
            if raised || now >= g.softirq_expires_next {
                g.softirq_activated = false;
                g = run_queues(base, g, now, HRTIMER_ACTIVE_SOFT);
            }
            drop(g);
            let next = expire_hard(base);
            tick_program_event(next);
            next
        });
        let _ = next;
    }
    base.nr_events.load(Ordering::Relaxed) - before + wheel
}

/// Expire every CPU's due hard timers from this CPU (tick broadcast for a
/// global fallback clockevent such as HPET, which has no per-CPU deadline).
/// Due soft timers are raised on their own CPU with a kick. Returns the
/// earliest remaining event across all bases (monotonic ns).
pub fn hrtimer_run_all_bases() -> Ktime {
    let me = this_cpu();
    let now = crate::monotonic_ns();
    let mut earliest = KTIME_MAX;
    for cpu in 0..MAX_CPUS {
        let Some(base) = cpu_base(cpu) else { continue };
        if base.next_event.load(Ordering::Acquire) <= now {
            let soft_was = base.softirq_raised.load(Ordering::Acquire);
            expire_hard(base);
            if cpu != me && !soft_was && base.softirq_raised.load(Ordering::Acquire) {
                remote_kick(cpu as u32);
            }
        }
        earliest = earliest.min(base.next_event.load(Ordering::Acquire));
    }
    earliest
}

/// `retrigger_next_event`: re-program this CPU's clockevent from its base.
/// Runs from the reschedule IPI; cheap no-op unless a remote enqueue or a
/// clock change asked for it.
pub fn retrigger_next_event() {
    let Some(base) = cpu_base(this_cpu()) else {
        return;
    };
    if !base.retrigger.load(Ordering::Relaxed) || !base.retrigger.swap(false, Ordering::AcqRel) {
        return;
    }
    let next = narf_lib::sync::without_interrupts(|| {
        let mut g = base.inner.lock();
        let next = update_next_event(base, &mut g);
        drop(g);
        let next = next.min(crate::timer::next_timer_event_ns_local());
        tick_program_event(next);
        next
    });
    let _ = next;
}

static CLOCK_WAS_SET_NOTIFIER: AtomicUsize = AtomicUsize::new(0);

/// Install the hook `clock_was_set` runs after the bases are re-evaluated
/// (the vDSO republishes its clock data from it).
pub fn set_clock_was_set_notifier(f: fn()) {
    CLOCK_WAS_SET_NOTIFIER.store(f as usize, Ordering::Release);
}

/// `clock_was_set`: REALTIME/TAI/BOOTTIME offsets changed; every CPU
/// re-evaluates its bases.
pub fn clock_was_set() {
    clock_was_set_bases();
    let raw = CLOCK_WAS_SET_NOTIFIER.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only `fn()` values are stored by the setter.
        let f: fn() = unsafe { core::mem::transmute(raw) };
        f();
    }
}

fn clock_was_set_bases() {
    let me = this_cpu();
    for cpu in 0..MAX_CPUS {
        let Some(base) = cpu_base(cpu) else { continue };
        base.retrigger.store(true, Ordering::Release);
        if cpu == me {
            retrigger_next_event();
        } else if base.queued.load(Ordering::Relaxed) != 0 {
            fence(Ordering::SeqCst);
            remote_kick(cpu as u32);
        }
    }
}

/// `hrtimer_get_next_event` for this CPU, in clockevent cycles: the event the
/// local clockevent must fire for (`None` when idle with no timers). Lock-free
/// and IRQ-safe; used by tickless idle and the timer interrupt.
pub fn next_event_cycles_local() -> Option<u64> {
    let hr = cpu_base(this_cpu()).map_or(KTIME_MAX, |b| b.next_event.load(Ordering::Acquire));
    // `tick_nohz_next_event`: the earlier of the next hrtimer and the next
    // timer-wheel expiry that may wake this CPU.
    let n = hr.min(crate::timer::next_timer_event_ns_local());
    (n != KTIME_MAX).then(|| ns_to_deadline_cycles(n))
}

/// Next event of `cpu`'s base, monotonic ns (diagnostics, tests).
pub fn next_event_ns_of(cpu: usize) -> Option<Ktime> {
    let n = cpu_base(cpu)?.next_event.load(Ordering::Acquire);
    (n != KTIME_MAX).then_some(n)
}

/// Earliest event across all CPU bases, in cycles (diagnostics; HPET arm).
pub fn next_event_cycles_any() -> Option<u64> {
    let n = (0..MAX_CPUS)
        .filter_map(cpu_base)
        .map(|b| b.next_event.load(Ordering::Acquire))
        .min()
        .unwrap_or(KTIME_MAX);
    (n != KTIME_MAX).then(|| ns_to_deadline_cycles(n))
}

/// Timers queued on this CPU (diagnostic).
pub fn nr_queued_local() -> usize {
    cpu_base(this_cpu()).map_or(0, |b| b.queued.load(Ordering::Relaxed))
}

/// Timers queued on `cpu` (diagnostic, tests).
pub fn nr_queued_on(cpu: usize) -> usize {
    cpu_base(cpu).map_or(0, |b| b.queued.load(Ordering::Relaxed))
}

/// Timers queued on every CPU (diagnostic).
pub fn nr_queued_all() -> usize {
    (0..MAX_CPUS)
        .filter_map(cpu_base)
        .map(|b| b.queued.load(Ordering::Relaxed))
        .sum()
}

/// `hrtimers_cpu_dying`: move every timer queued on `dying` to the calling
/// CPU's base (the CPU must be on its way offline, its interrupts no longer
/// expiring timers). Returns the timers moved.
pub fn hrtimers_cpu_dying(dying: usize) -> usize {
    let Some(old) = cpu_base(dying) else {
        return 0;
    };
    let new = this_cpu_base();
    if ptr::eq(old, new) {
        return 0;
    }
    let mut moved = 0;
    loop {
        let kick = narf_lib::sync::without_interrupts(|| {
            let mut og = old.inner.lock();
            let mut found = ptr::null::<HrTimer>();
            for idx in 0..HRTIMER_MAX_CLOCK_BASES {
                let n = og.clock_base[idx].first();
                if !n.is_null() {
                    found = HrTimer::from_node(n);
                    break;
                }
            }
            if found.is_null() {
                let _ = update_next_event(old, &mut og);
                return None;
            }
            // SAFETY: linked ⇒ live (start contract).
            let timer = unsafe { &*found };
            remove_hrtimer(old, &mut og, timer);
            timer.cpu.store(CPU_MIGRATING, Ordering::Release);
            drop(og);
            let mut ng = new.inner.lock();
            timer.cpu.store(new.cpu, Ordering::Release);
            // SAFETY: still owned by its starter, which keeps it in place.
            let first = unsafe { enqueue_hrtimer(new, &mut ng, timer) };
            let k = if first {
                reprogram_after_enqueue(new, &mut ng, timer)
            } else {
                None
            };
            Some(k)
        });
        match kick {
            None => break,
            Some(k) => {
                moved += 1;
                if let Some(cpu) = k {
                    fence(Ordering::SeqCst);
                    remote_kick(cpu);
                }
            }
        }
    }
    moved
}

// ── sleepers ────────────────────────────────────────────────────────────

/// `struct hrtimer_sleeper`: a timer that wakes a task.
#[repr(C)]
struct HrTimerSleeper {
    timer: HrTimer,
    waker: IrqSafeSpinLock<Option<Waker>>,
    fired: AtomicBool,
}

/// `hrtimer_wakeup`.
fn hrtimer_wakeup(t: &HrTimer) -> HrtimerRestart {
    // SAFETY: only sleepers use this callback; `timer` is their first field
    // of a `repr(C)` struct, so this is `container_of`.
    let sl = unsafe { &*(t as *const HrTimer as *const HrTimerSleeper) };
    sl.fired.store(true, Ordering::Release);
    // Wake by reference: the Waker stays owned by the sleeper, so no Arc is
    // released here. On a hard base the predicate proved the waker's
    // `wake_by_ref` IRQ-safe; soft bases run in executor context.
    if let Some(w) = sl.waker.lock().as_ref() {
        w.wake_by_ref();
    }
    HrtimerRestart::NoRestart
}

/// An armed or idle sleeper owned by its waiter (`hrtimer_sleeper` +
/// `schedule_hrtimeout_range`). Dropping it cancels the timer and waits out
/// a running callback; drop it only in task context.
pub struct SleepHandle(Box<HrTimerSleeper>);

impl core::fmt::Debug for SleepHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SleepHandle")
            .field("expires", &self.0.timer.expires())
            .field("queued", &self.0.timer.is_queued())
            .finish()
    }
}

impl SleepHandle {
    /// `hrtimer_setup_sleeper_on_stack`: an inactive sleeper on `clock`.
    /// Allocates; call from task context.
    pub fn new(clock: ClockId) -> Self {
        Self(Box::new(HrTimerSleeper {
            timer: HrTimer::new(hrtimer_wakeup, clock, HrtimerMode::ABS),
            waker: IrqSafeSpinLock::new(None),
            fired: AtomicBool::new(false),
        }))
    }

    /// New sleeper armed for monotonic `expires_ns` with `slack_ns` range.
    pub fn arm(expires_ns: Ktime, slack_ns: u64, waker: &Waker) -> Self {
        let h = Self::new(ClockId::Monotonic);
        h.start(expires_ns, slack_ns, HrtimerMode::ABS, waker);
        h
    }

    /// (Re)arm for `expires` (clock time; `mode` absolute or relative) with a
    /// `slack_ns` range, waking `waker`. Reuses the sleeper; no allocation.
    pub fn start(&self, expires: Ktime, slack_ns: u64, mode: HrtimerMode, waker: &Waker) {
        let sl = &*self.0;
        let hard = waker_is_hardirq_safe(waker);
        let old = {
            let mut slot = sl.waker.lock();
            match slot.as_ref() {
                Some(w) if w.will_wake(waker) => None,
                _ => slot.replace(waker.clone()),
            }
        };
        drop(old);
        sl.fired.store(false, Ordering::Release);
        let clock = sl.timer.clock() as u8;
        let want = clock + if hard { 0 } else { HRTIMER_BASE_SOFT as u8 };
        if sl.timer.base_index.load(Ordering::Relaxed) != want {
            // A base change needs the timer unlinked (it is re-linked by the
            // start below).
            hrtimer_cancel(&sl.timer);
            sl.timer.base_index.store(want, Ordering::Relaxed);
        }
        // SAFETY: the Box keeps the timer at a fixed address; Drop cancels
        // before it is freed.
        unsafe { hrtimer_start_range_ns(&sl.timer, expires, slack_ns, mode) };
    }

    /// Point a pending sleeper at `waker`. Returns false if it already fired
    /// or was never armed (the caller re-arms).
    pub fn refresh_waker(&self, waker: &Waker) -> bool {
        let sl = &*self.0;
        if !sl.timer.is_queued() {
            return false;
        }
        if waker_is_hardirq_safe(waker)
            != (sl.timer.base_index.load(Ordering::Relaxed) < HRTIMER_BASE_SOFT as u8)
        {
            // Different wake context: requeue on the right base.
            let exp = sl.timer.softexpires();
            let slack = sl.timer.expires() - exp;
            self.start(exp, slack, HrtimerMode::ABS, waker);
            return true;
        }
        let old = {
            let mut slot = sl.waker.lock();
            match slot.as_ref() {
                Some(w) if w.will_wake(waker) => None,
                _ => slot.replace(waker.clone()),
            }
        };
        drop(old);
        // Fired in between: it woke the previous waker; the caller re-arms.
        sl.timer.is_queued()
    }

    /// Whether the timer expired since it was last armed.
    pub fn fired(&self) -> bool {
        self.0.fired.load(Ordering::Acquire)
    }

    /// Whether the timer is queued.
    pub fn is_pending(&self) -> bool {
        self.0.timer.is_queued()
    }

    /// Cancel (no-op if not pending).
    pub fn cancel(&self) {
        hrtimer_cancel(&self.0.timer);
    }

    /// Hard expiry in clock ns.
    pub fn expires_ns(&self) -> Ktime {
        self.0.timer.expires()
    }

    /// CPU whose base holds the timer (tests).
    pub fn cpu(&self) -> Option<u32> {
        let c = self.0.timer.cpu.load(Ordering::Acquire);
        (c < CPU_MIGRATING).then_some(c)
    }

    /// The underlying timer (tests, migration).
    pub fn timer(&self) -> &HrTimer {
        &self.0.timer
    }
}

impl Drop for SleepHandle {
    fn drop(&mut self) {
        hrtimer_cancel(&self.0.timer);
    }
}

#[doc(hidden)]
pub fn __test_events_on(cpu: usize) -> u64 {
    cpu_base(cpu).map_or(0, |b| b.nr_events.load(Ordering::Relaxed))
}

/// Validate every clock base of `cpu` (test-only).
#[doc(hidden)]
pub fn __test_validate(cpu: usize) -> Result<usize, &'static str> {
    let Some(base) = cpu_base(cpu) else {
        return Ok(0);
    };
    let g = base.inner.lock();
    let mut n = 0;
    for head in &g.clock_base {
        // SAFETY: the base lock is held.
        n += unsafe { head.__validate()? };
    }
    if n != g.nr_queued {
        return Err("queued count disagrees with the trees");
    }
    Ok(n)
}
