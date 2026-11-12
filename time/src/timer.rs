//! Timer wheel — Linux `kernel/time/timer.c` (`timer_list`).
//!
//! Coarse kernel timeouts that are usually cancelled before they fire run
//! here rather than on hrtimers. Every CPU owns three [`TimerBase`]s:
//! `BASE_LOCAL` (pinned timers), `BASE_GLOBAL` (unpinned: an idle CPU hands
//! their expiry to timer migration, [`crate::timer_migration`]) and
//! `BASE_DEF` (deferrable: never wakes an idle CPU). Each base is Linux's
//! non-cascading hierarchical wheel: `LVL_DEPTH` levels × 64 buckets, level
//! `n` with a granularity of `8^n` jiffies (`calc_wheel_index`), each bucket
//! an intrusive doubly-linked list of [`TimerList`] nodes with a per-level
//! pending bitmap. Enqueue, dequeue and expiry neither allocate nor free and
//! have no capacity limit. A timer fires no earlier than its expiry and at
//! most one level granularity later (Linux's slack).
//!
//! Expiry (`run_timer_softirq`) runs in the executor round, NARF's softirq
//! context, so callbacks may allocate. The timer interrupt only notices that
//! a base is due (`timer_tick`); the CPU's next event — used to program its
//! clockevent and by tickless idle — includes the wheel's next expiry
//! ([`next_timer_event_ns_local`], Linux `get_next_timer_interrupt`), with
//! deferrable timers excluded while the CPU is idle.
//!
//! Lock order: one base lock at a time; no callback runs with a base lock
//! held. `del_timer_sync` waits out a running callback, so it must not be
//! called from that callback or with a lock the callback takes.

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::{IrqSafeSpinLock, IrqSafeSpinLockGuard};

/// `HZ`: jiffies per second.
pub const HZ: u64 = 1000;
const NSEC_PER_JIFFY: u64 = 1_000_000_000 / HZ;

/// `jiffies`: monotonic time in ticks.
#[inline]
pub fn jiffies() -> u64 {
    crate::monotonic_ns() / NSEC_PER_JIFFY
}

/// Monotonic ns at which jiffy `j` begins.
#[inline]
pub fn jiffies_to_ns(j: u64) -> u64 {
    j.saturating_mul(NSEC_PER_JIFFY)
}

/// Jiffies covering at least `ns` (rounded up, as `nsecs_to_jiffies` +1 in
/// `schedule_timeout` callers).
#[inline]
pub fn ns_to_jiffies(ns: u64) -> u64 {
    ns.div_ceil(NSEC_PER_JIFFY)
}

// ── wheel geometry (kernel/time/timer.c) ────────────────────────────────

const LVL_CLK_SHIFT: u32 = 3;
const LVL_CLK_DIV: u64 = 1 << LVL_CLK_SHIFT;
const LVL_CLK_MASK: u64 = LVL_CLK_DIV - 1;
const LVL_BITS: u32 = 6;
const LVL_SIZE: usize = 1 << LVL_BITS;
const LVL_MASK: u64 = LVL_SIZE as u64 - 1;
/// `LVL_DEPTH` for HZ > 100.
pub const LVL_DEPTH: usize = 9;
const WHEEL_SIZE: usize = LVL_SIZE * LVL_DEPTH;

#[inline]
const fn lvl_shift(n: usize) -> u32 {
    n as u32 * LVL_CLK_SHIFT
}
#[inline]
const fn lvl_gran(n: usize) -> u64 {
    1 << lvl_shift(n)
}
/// First delta that no longer fits level `n - 1`.
#[inline]
const fn lvl_start(n: usize) -> u64 {
    (LVL_SIZE as u64 - 1) << ((n as u32 - 1) * LVL_CLK_SHIFT)
}
const WHEEL_TIMEOUT_CUTOFF: u64 = lvl_start(LVL_DEPTH);
const WHEEL_TIMEOUT_MAX: u64 = WHEEL_TIMEOUT_CUTOFF - lvl_gran(LVL_DEPTH - 1);
const NEXT_TIMER_MAX_DELTA: u64 = (1 << 30) - 1;

/// `calc_index`.
#[inline]
fn calc_index(expires: u64, lvl: usize) -> (usize, u64) {
    let e = (expires >> lvl_shift(lvl)) + 1;
    (
        lvl * LVL_SIZE + (e & LVL_MASK) as usize,
        e << lvl_shift(lvl),
    )
}

/// `calc_wheel_index`: the bucket for `expires` relative to the base clock
/// `clk`, and the bucket's expiry.
pub fn calc_wheel_index(expires: u64, clk: u64) -> (usize, u64) {
    if expires < clk {
        return ((clk & LVL_MASK) as usize, clk);
    }
    let delta = expires - clk;
    for lvl in 0..LVL_DEPTH - 1 {
        if delta < lvl_start(lvl + 1) {
            return calc_index(expires, lvl);
        }
    }
    let expires = if delta >= WHEEL_TIMEOUT_CUTOFF {
        clk + WHEEL_TIMEOUT_MAX
    } else {
        expires
    };
    calc_index(expires, LVL_DEPTH - 1)
}

// ── timers ──────────────────────────────────────────────────────────────

/// `TIMER_PINNED`: stays on the CPU it is armed on (`BASE_LOCAL`).
pub const TIMER_PINNED: u32 = 1 << 0;
/// `TIMER_DEFERRABLE`: never wakes an idle CPU (`BASE_DEF`).
pub const TIMER_DEFERRABLE: u32 = 1 << 1;

/// Timer callback. Runs in the executor round with no base lock held.
pub type TimerFn = fn(&TimerList);

const NO_CPU: u32 = u32::MAX;
const MIGRATING: u32 = u32::MAX - 1;

const BASE_LOCAL: usize = 0;
const BASE_GLOBAL: usize = 1;
const BASE_DEF: usize = 2;
const NR_BASES: usize = 3;

/// `struct timer_list`. Caller-owned; must stay at its address while
/// pending and must not be freed until [`del_timer_sync`] returned.
#[repr(C)]
pub struct TimerList {
    /// Intrusive bucket links, guarded by the base lock.
    next: UnsafeCell<*mut TimerList>,
    prev: UnsafeCell<*mut TimerList>,
    expires: UnsafeCell<u64>,
    /// Bucket index while pending.
    idx: UnsafeCell<usize>,
    function: TimerFn,
    flags: u32,
    /// CPU whose base holds the timer, `NO_CPU`, or `MIGRATING`.
    cpu: AtomicU32,
    pending: AtomicBool,
    running: AtomicBool,
}

// SAFETY: the `UnsafeCell`s are touched only under the lock of the base the
// timer is on (`cpu`), by the holder of the `MIGRATING` claim, or by its own
// running callback while unlinked — the hrtimer rules.
unsafe impl Sync for TimerList {}
// SAFETY: as above.
unsafe impl Send for TimerList {}

impl core::fmt::Debug for TimerList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimerList")
            .field("flags", &self.flags)
            .field("pending", &self.pending.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl TimerList {
    /// `timer_setup(timer, function, flags)`.
    pub const fn new(function: TimerFn, flags: u32) -> Self {
        Self {
            next: UnsafeCell::new(ptr::null_mut()),
            prev: UnsafeCell::new(ptr::null_mut()),
            expires: UnsafeCell::new(0),
            idx: UnsafeCell::new(0),
            function,
            flags,
            cpu: AtomicU32::new(NO_CPU),
            pending: AtomicBool::new(false),
            running: AtomicBool::new(false),
        }
    }

    /// `timer_pending`.
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    /// Expiry in jiffies (racy unless the caller owns the timer's state).
    pub fn expires(&self) -> u64 {
        // SAFETY: aligned u64 read; staleness is the documented race.
        unsafe { ptr::read_volatile(self.expires.get()) }
    }

    /// CPU whose base holds the timer.
    pub fn cpu(&self) -> Option<u32> {
        let c = self.cpu.load(Ordering::Acquire);
        (c < MIGRATING).then_some(c)
    }

    #[inline]
    fn base_index(&self) -> usize {
        if self.flags & TIMER_DEFERRABLE != 0 {
            BASE_DEF
        } else if self.flags & TIMER_PINNED != 0 {
            BASE_LOCAL
        } else {
            BASE_GLOBAL
        }
    }
}

struct WheelInner {
    clk: u64,
    next_expiry: u64,
    timers_pending: bool,
    pending_map: [u64; LVL_DEPTH],
    vectors: [*mut TimerList; WHEEL_SIZE],
}

// SAFETY: raw node pointers are guarded by the base lock.
unsafe impl Send for WheelInner {}

/// `struct timer_base`.
pub struct TimerBase {
    cpu: u32,
    index: usize,
    inner: IrqSafeSpinLock<WheelInner>,
    /// Lock-free copy of `next_expiry` (jiffies; `u64::MAX` when empty).
    next_expiry: AtomicU64,
    /// Callbacks run (diagnostic, tests).
    nr_expired: AtomicU64,
}

impl core::fmt::Debug for TimerBase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimerBase")
            .field("cpu", &self.cpu)
            .field("index", &self.index)
            .field("next_expiry", &self.next_expiry.load(Ordering::Relaxed))
            .finish()
    }
}

type Guard = IrqSafeSpinLockGuard<'static, WheelInner>;

/// One CPU's three bases.
struct CpuTimerBases {
    bases: [TimerBase; NR_BASES],
    /// `TIMER_SOFTIRQ` raised by the tick.
    softirq_raised: AtomicBool,
}

static CPU_TIMER_BASES: [AtomicPtr<CpuTimerBases>; MAX_CPUS] =
    [const { AtomicPtr::new(ptr::null_mut()) }; MAX_CPUS];

/// `timers_prepare_cpu`: allocate `cpu`'s bases (not in hard IRQ).
pub fn timers_prepare_cpu(cpu: usize) {
    if cpu >= MAX_CPUS || !CPU_TIMER_BASES[cpu].load(Ordering::Acquire).is_null() {
        return;
    }
    let clk = jiffies();
    let mk = |index| TimerBase {
        cpu: cpu as u32,
        index,
        inner: IrqSafeSpinLock::new(WheelInner {
            clk,
            next_expiry: clk + NEXT_TIMER_MAX_DELTA,
            timers_pending: false,
            pending_map: [0; LVL_DEPTH],
            vectors: [ptr::null_mut(); WHEEL_SIZE],
        }),
        next_expiry: AtomicU64::new(u64::MAX),
        nr_expired: AtomicU64::new(0),
    };
    let fresh = Box::into_raw(Box::new(CpuTimerBases {
        bases: [mk(BASE_LOCAL), mk(BASE_GLOBAL), mk(BASE_DEF)],
        softirq_raised: AtomicBool::new(false),
    }));
    if CPU_TIMER_BASES[cpu]
        .compare_exchange(ptr::null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // SAFETY: never published; still ours.
        drop(unsafe { Box::from_raw(fresh) });
    }
}

#[inline]
fn cpu_bases(cpu: usize) -> Option<&'static CpuTimerBases> {
    let p = CPU_TIMER_BASES.get(cpu)?.load(Ordering::Acquire);
    // SAFETY: published bases are leaked, never freed.
    (!p.is_null()).then(|| unsafe { &*p })
}

#[inline]
fn this_cpu() -> usize {
    narf_lib::percpu::current_cpu().min(MAX_CPUS - 1)
}

fn this_cpu_bases() -> &'static CpuTimerBases {
    let cpu = this_cpu();
    if cpu_bases(cpu).is_none() && !narf_lib::context::in_irq() {
        timers_prepare_cpu(cpu);
    }
    cpu_bases(cpu)
        .or_else(|| {
            if !narf_lib::context::in_irq() {
                timers_prepare_cpu(0);
            }
            cpu_bases(0)
        })
        .expect("CPU 0 timer bases")
}

// ── wheel primitives (base lock held) ───────────────────────────────────

/// `enqueue_timer` at its computed bucket. Returns true when it became the
/// base's next expiry.
///
/// # Safety
/// `t` is unlinked, owned by the caller, and stays put while linked.
unsafe fn enqueue_timer(base: &TimerBase, w: &mut WheelInner, t: &TimerList) -> bool {
    // SAFETY: caller contract; links are guarded by the base lock.
    unsafe {
        let (idx, bucket_expiry) = calc_wheel_index(*t.expires.get(), w.clk);
        let me = t as *const TimerList as *mut TimerList;
        let head = w.vectors[idx];
        *t.next.get() = head;
        *t.prev.get() = ptr::null_mut();
        if !head.is_null() {
            *(*head).prev.get() = me;
        }
        w.vectors[idx] = me;
        *t.idx.get() = idx;
        w.pending_map[idx / LVL_SIZE] |= 1 << (idx % LVL_SIZE);
        t.pending.store(true, Ordering::Release);
        w.timers_pending = true;
        if bucket_expiry < w.next_expiry {
            w.next_expiry = bucket_expiry;
            base.next_expiry.store(bucket_expiry, Ordering::Release);
            return true;
        }
        false
    }
}

/// `detach_timer`. Returns false if `t` was not pending.
fn detach_timer(w: &mut WheelInner, t: &TimerList) -> bool {
    if !t.pending.load(Ordering::Relaxed) {
        return false;
    }
    // SAFETY: pending under this lock ⇒ linked into `vectors[idx]`.
    unsafe {
        let idx = *t.idx.get();
        let next = *t.next.get();
        let prev = *t.prev.get();
        if prev.is_null() {
            w.vectors[idx] = next;
        } else {
            *(*prev).next.get() = next;
        }
        if !next.is_null() {
            *(*next).prev.get() = prev;
        }
        if w.vectors[idx].is_null() {
            w.pending_map[idx / LVL_SIZE] &= !(1 << (idx % LVL_SIZE));
        }
        *t.next.get() = ptr::null_mut();
        *t.prev.get() = ptr::null_mut();
    }
    t.pending.store(false, Ordering::Release);
    true
}

/// `forward_timer_base`: a base whose softirq has not run lately has a
/// lagging clock; bring it up to now (never past a pending bucket) so a new
/// timer is indexed against the present, not filed at a coarse level.
fn forward_timer_base(w: &mut WheelInner) {
    let now = jiffies();
    if now > w.clk {
        w.clk = if w.next_expiry > now {
            now
        } else {
            w.next_expiry
        };
        if !w.timers_pending {
            w.next_expiry = w.clk + NEXT_TIMER_MAX_DELTA;
        }
    }
}

/// `next_pending_bucket`: distance from `clk` (within `lvl`) to the next
/// pending bucket, wrapping, or `None`.
fn next_pending_bucket(w: &WheelInner, lvl: usize, clk: u64) -> Option<u64> {
    let map = w.pending_map[lvl];
    if map == 0 {
        return None;
    }
    let start = (clk & LVL_MASK) as u32;
    let rotated = map.rotate_right(start);
    Some(u64::from(rotated.trailing_zeros()))
}

/// `__next_timer_interrupt`.
fn next_timer_interrupt(w: &mut WheelInner) -> u64 {
    let mut next = w.clk + NEXT_TIMER_MAX_DELTA;
    let mut clk = w.clk;
    for lvl in 0..LVL_DEPTH {
        let lvl_clk = clk & LVL_CLK_MASK;
        if let Some(pos) = next_pending_bucket(w, lvl, clk) {
            let tmp = (clk + pos) << lvl_shift(lvl);
            if tmp < next {
                next = tmp;
            }
            // A later level cannot hold anything earlier than this.
            if pos <= ((LVL_CLK_DIV - lvl_clk) & LVL_CLK_MASK) {
                break;
            }
        }
        let adj = u64::from(lvl_clk != 0);
        clk >>= LVL_CLK_SHIFT;
        clk += adj;
    }
    w.timers_pending = next != w.clk + NEXT_TIMER_MAX_DELTA;
    next
}

fn recalc_next_expiry(base: &TimerBase, w: &mut WheelInner) {
    let next = next_timer_interrupt(w);
    w.next_expiry = next;
    base.next_expiry.store(
        if w.timers_pending { next } else { u64::MAX },
        Ordering::Release,
    );
}

// ── locking a timer's base ──────────────────────────────────────────────

enum Locked {
    Base(&'static TimerBase, Guard),
    Unbound,
}

fn base_of(cpu: u32, index: usize) -> &'static TimerBase {
    &cpu_bases(cpu as usize)
        .expect("timer bound to an unprepared CPU")
        .bases[index]
}

/// `lock_timer_base`. IRQs masked by the caller.
fn lock_timer_base(t: &TimerList) -> Locked {
    loop {
        let c = t.cpu.load(Ordering::Acquire);
        match c {
            MIGRATING => core::hint::spin_loop(),
            NO_CPU => {
                if t.cpu
                    .compare_exchange(NO_CPU, MIGRATING, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Locked::Unbound;
                }
            }
            _ => {
                let base = base_of(c, t.base_index());
                let g = base.inner.lock();
                if t.cpu.load(Ordering::Acquire) == c {
                    return Locked::Base(base, g);
                }
            }
        }
    }
}

// ── public operations ───────────────────────────────────────────────────

/// `__mod_timer`: (re)arm `t` to expire at jiffy `expires`. A non-pinned
/// timer moves to the calling CPU's base (Linux queues on the local CPU and
/// lets timer migration handle it when the CPU goes idle); a pinned one is
/// queued here too. Returns whether it was pending before.
///
/// # Safety
/// `t` must stay at its address and not be freed until [`del_timer_sync`]
/// returned (or it fired and was not re-armed).
pub unsafe fn mod_timer(t: &TimerList, expires: u64) -> bool {
    // SAFETY: caller contract.
    unsafe { mod_timer_on(t, expires, None) }
}

/// `add_timer_on`: arm `t` on `cpu`'s base (offline migration, tests).
///
/// # Safety
/// As for [`mod_timer`].
pub unsafe fn add_timer_on(t: &TimerList, expires: u64, cpu: usize) -> bool {
    // SAFETY: caller contract.
    unsafe { mod_timer_on(t, expires, Some(cpu)) }
}

unsafe fn mod_timer_on(t: &TimerList, expires: u64, target: Option<usize>) -> bool {
    let (was_pending, kick) = narf_lib::sync::without_interrupts(|| {
        let bases: &'static CpuTimerBases = match target {
            Some(cpu) => cpu_bases(cpu).expect("add_timer_on: CPU not prepared"),
            None => this_cpu_bases(),
        };
        let want = &bases.bases[t.base_index()];
        let (old, mut g, was_pending) = match lock_timer_base(t) {
            Locked::Base(b, mut g) => {
                let p = detach_timer(&mut g, t);
                (Some(b), Some(g), p)
            }
            Locked::Unbound => (None, None, false),
        };
        let keep = old.is_some_and(|b| ptr::eq(b, want) || t.running.load(Ordering::Acquire));
        let (base, mut guard) = if keep {
            (old.expect("kept base"), g.take().expect("kept guard"))
        } else {
            if g.is_some() {
                t.cpu.store(MIGRATING, Ordering::Release);
                drop(g.take());
            }
            let ng = want.inner.lock();
            t.cpu.store(want.cpu, Ordering::Release);
            (want, ng)
        };
        // SAFETY: unlinked and owned under `guard`.
        unsafe { *t.expires.get() = expires };
        forward_timer_base(&mut guard);
        // SAFETY: caller contract keeps `t` in place.
        let first = unsafe { enqueue_timer(base, &mut guard, t) };
        drop(guard);
        // `trigger_dyntick_cpu`: a new first timer on another CPU's base
        // must reach that CPU's clockevent (deferrable ones never wake it).
        let kick = first && base.cpu as usize != this_cpu() && base.index != BASE_DEF;
        (was_pending, kick.then_some(base.cpu))
    });
    if let Some(cpu) = kick {
        crate::hrtimer::kick_cpu_next_event(cpu);
    }
    was_pending
}

/// `timer_delete` / `del_timer`: deactivate; returns whether it was pending.
/// A running callback is not waited for.
pub fn del_timer(t: &TimerList) -> bool {
    if !t.is_pending() {
        return false;
    }
    narf_lib::sync::without_interrupts(|| match lock_timer_base(t) {
        Locked::Unbound => {
            t.cpu.store(NO_CPU, Ordering::Release);
            false
        }
        Locked::Base(_, mut g) => detach_timer(&mut g, t),
    })
}

/// `timer_delete_sync` / `del_timer_sync`: deactivate and wait for a running
/// callback. Not from the timer's own callback.
pub fn del_timer_sync(t: &TimerList) -> bool {
    let r = del_timer(t);
    while t.running.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    r
}

// ── expiry ──────────────────────────────────────────────────────────────

/// Collect due timers of `base` at its clock, one bucket per level, into a
/// local list (`collect_expired_timers`). Returns the list head.
fn collect_expired(w: &mut WheelInner) -> *mut TimerList {
    let mut out: *mut TimerList = ptr::null_mut();
    let mut clk = w.clk;
    for lvl in 0..LVL_DEPTH {
        let idx = lvl * LVL_SIZE + (clk & LVL_MASK) as usize;
        let bit = 1u64 << (idx % LVL_SIZE);
        if w.pending_map[lvl] & bit != 0 {
            w.pending_map[lvl] &= !bit;
            // Splice the whole bucket onto `out`.
            let mut n = w.vectors[idx];
            w.vectors[idx] = ptr::null_mut();
            while !n.is_null() {
                // SAFETY: linked nodes are live (mod_timer contract) and
                // guarded by the base lock.
                unsafe {
                    let next = *(*n).next.get();
                    *(*n).next.get() = out;
                    out = n;
                    n = next;
                }
            }
        }
        if clk & LVL_CLK_MASK != 0 {
            break;
        }
        clk >>= LVL_CLK_SHIFT;
    }
    out
}

/// `__run_timers` for one base. Returns callbacks run.
fn run_base(base: &'static TimerBase) -> u64 {
    let now = jiffies();
    if base.next_expiry.load(Ordering::Acquire) > now {
        return 0;
    }
    let mut ran = 0;
    let mut g = base.inner.lock();
    while now >= g.clk && now >= g.next_expiry {
        // Jump an idle stretch straight to the next pending bucket.
        if g.next_expiry > g.clk {
            g.clk = g.next_expiry;
        }
        let mut list = collect_expired(&mut g);
        g.clk += 1;
        recalc_next_expiry(base, &mut g);
        while !list.is_null() {
            // SAFETY: collected nodes are live and still marked pending.
            let t = unsafe { &*list };
            // SAFETY: as above, under the base lock.
            list = unsafe { *t.next.get() };
            // SAFETY: as above.
            unsafe {
                *t.next.get() = ptr::null_mut();
                *t.prev.get() = ptr::null_mut();
            }
            t.pending.store(false, Ordering::Release);
            t.running.store(true, Ordering::Release);
            drop(g);
            (t.function)(t);
            ran += 1;
            g = base.inner.lock();
            // Last touch: a waiting `del_timer_sync` may free it after this.
            t.running.store(false, Ordering::Release);
        }
    }
    if !g.timers_pending {
        base.next_expiry.store(u64::MAX, Ordering::Release);
    }
    drop(g);
    base.nr_expired.fetch_add(ran, Ordering::Relaxed);
    ran
}

/// `run_timer_softirq`: expire this CPU's due timers on all three bases,
/// then (timer migration) any idle CPU's due global timers. Executor
/// context. Returns callbacks run.
pub fn run_timer_softirq() -> u64 {
    let Some(b) = cpu_bases(this_cpu()) else {
        return 0;
    };
    b.softirq_raised.store(false, Ordering::Relaxed);
    let mut ran = 0;
    for base in &b.bases {
        ran += run_base(base);
    }
    ran + crate::timer_migration::handle_remote()
}

/// Run the due timers of `cpu`'s GLOBAL base from this CPU (timer migration,
/// `timer_expire_remote`).
pub(crate) fn expire_remote_global(cpu: usize) -> u64 {
    cpu_bases(cpu).map_or(0, |b| run_base(&b.bases[BASE_GLOBAL]))
}

/// `run_local_timers` from the tick: raise the softirq when a base is due.
pub fn timer_tick() {
    let Some(b) = cpu_bases(this_cpu()) else {
        return;
    };
    let now = jiffies();
    if b.bases
        .iter()
        .any(|x| x.next_expiry.load(Ordering::Acquire) <= now)
    {
        b.softirq_raised.store(true, Ordering::Release);
    }
}

/// Next expiry (jiffies) of `cpu`'s base `index`, `u64::MAX` when empty.
fn base_next(cpu: usize, index: usize) -> u64 {
    cpu_bases(cpu).map_or(u64::MAX, |b| {
        b.bases[index].next_expiry.load(Ordering::Acquire)
    })
}

/// Next expiry of `cpu`'s GLOBAL base (timer migration publishes it).
pub(crate) fn global_next(cpu: usize) -> u64 {
    base_next(cpu, BASE_GLOBAL)
}

/// `get_next_timer_interrupt` for this CPU, in monotonic ns (`u64::MAX` when
/// none): LOCAL and, unless timer migration took them over, GLOBAL timers.
/// Deferrable timers count only while the CPU is active (they never wake
/// an idle CPU). Lock-free.
pub fn next_timer_event_ns_local() -> u64 {
    let cpu = this_cpu();
    let idle = !crate::timer_migration::cpu_active(cpu);
    let mut next = base_next(cpu, BASE_LOCAL);
    next = next.min(crate::timer_migration::global_next_for(cpu));
    if !idle {
        next = next.min(base_next(cpu, BASE_DEF));
    }
    if next == u64::MAX {
        u64::MAX
    } else {
        jiffies_to_ns(next)
    }
}

/// `timers_dead_cpu`: move every timer of a dead CPU to this CPU's bases.
/// Returns the timers moved.
pub fn timers_dead_cpu(dead: usize) -> usize {
    let Some(old) = cpu_bases(dead) else {
        return 0;
    };
    let new = this_cpu_bases();
    if ptr::eq(old, new) {
        return 0;
    }
    let mut moved = 0;
    for index in 0..NR_BASES {
        loop {
            let t = narf_lib::sync::without_interrupts(|| {
                let mut og = old.bases[index].inner.lock();
                let found = og.vectors.iter().copied().find(|p| !p.is_null());
                let Some(p) = found else {
                    recalc_next_expiry(&old.bases[index], &mut og);
                    return None;
                };
                // SAFETY: linked ⇒ live (mod_timer contract).
                let t = unsafe { &*p };
                detach_timer(&mut og, t);
                t.cpu.store(MIGRATING, Ordering::Release);
                drop(og);
                let nb = &new.bases[index];
                let mut ng = nb.inner.lock();
                forward_timer_base(&mut ng);
                t.cpu.store(nb.cpu, Ordering::Release);
                // SAFETY: still owned by its arming code.
                unsafe { enqueue_timer(nb, &mut ng, t) };
                Some(())
            });
            if t.is_none() {
                break;
            }
            moved += 1;
        }
    }
    moved
}

/// Callbacks run from `cpu`'s bases (tests).
#[doc(hidden)]
pub fn __test_expired_on(cpu: usize) -> u64 {
    cpu_bases(cpu).map_or(0, |b| {
        b.bases
            .iter()
            .map(|x| x.nr_expired.load(Ordering::Relaxed))
            .sum()
    })
}

// ── schedule_timeout ────────────────────────────────────────────────────

/// A coarse sleeper on the wheel (`schedule_timeout`'s `process_timeout`
/// timer): wakes its waker by reference at expiry. Owned by the waiter;
/// dropping it deletes the timer synchronously (task context only).
#[repr(C)]
struct TimeoutNode {
    timer: TimerList,
    waker: IrqSafeSpinLock<Option<core::task::Waker>>,
}

fn process_timeout(t: &TimerList) {
    // SAFETY: only `TimeoutNode` uses this callback; `timer` is its first
    // field (repr(C)).
    let n = unsafe { &*(t as *const TimerList as *const TimeoutNode) };
    if let Some(w) = n.waker.lock().as_ref() {
        w.wake_by_ref();
    }
}

/// `schedule_timeout`-style coarse timeout handle.
pub struct TimeoutHandle(Box<TimeoutNode>);

impl core::fmt::Debug for TimeoutHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimeoutHandle")
            .field("pending", &self.0.timer.is_pending())
            .finish()
    }
}

impl TimeoutHandle {
    /// A new, idle timeout. `flags` as for [`TimerList::new`].
    pub fn new(flags: u32) -> Self {
        Self(Box::new(TimeoutNode {
            timer: TimerList::new(process_timeout, flags),
            waker: IrqSafeSpinLock::new(None),
        }))
    }

    /// (Re)arm to wake `waker` at jiffy `expires`.
    pub fn arm(&self, expires: u64, waker: &core::task::Waker) {
        let old = {
            let mut w = self.0.waker.lock();
            match w.as_ref() {
                Some(cur) if cur.will_wake(waker) => None,
                _ => w.replace(waker.clone()),
            }
        };
        drop(old);
        // SAFETY: boxed; Drop deletes it synchronously before freeing.
        unsafe { mod_timer(&self.0.timer, expires) };
    }

    /// Whether the timeout is still pending.
    pub fn is_pending(&self) -> bool {
        self.0.timer.is_pending()
    }
}

impl Drop for TimeoutHandle {
    fn drop(&mut self) {
        del_timer_sync(&self.0.timer);
    }
}
