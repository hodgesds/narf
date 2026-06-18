//! Timer wheel — passive deadline registry that backs
//! `SleepUntil` and other deadline-driven futures.
//!
//! The wheel itself is just a fixed-size array of
//! `(deadline_cycles, Waker)` slots protected by an
//! `IrqSafeSpinLock`. It does not arm any hardware. The
//! IRQ-side glue (in `narf-interrupts::timer`) installs an
//! arm callback at boot, and the wheel invokes that callback
//! whenever the minimum deadline changes (a new earliest
//! registration, the previous earliest firing, or a cancel
//! that promoted a later deadline). The arm callback is
//! responsible for programming HPET to fire at that deadline.
//!
//! On HPET fire, the IRQ handler calls
//! [`fire_due`] with the current monotonic-cycles time. Every
//! slot whose deadline has passed is woken; expired slots are
//! cleared. The handler then queries [`next_deadline_cycles`]
//! and rearms HPET if any sleeper remains.
//!
//! Capacity is fixed (no allocation) so the wheel is safe to
//! touch from IRQ context. If a registration would overflow,
//! [`register`] returns `Err(WheelError::Full)` and the
//! caller falls back to a self-wake busy-poll (degraded but
//! not broken).
//!
//! Units: every deadline + `now` value passed to wheel fns is
//! a raw monotonic-counter tick (`Instant::as_cycles`). The
//! arm callback converts to whatever unit the underlying
//! timer hardware (HPET) wants.

use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Waker;

use narf_lib::sync::IrqSafeSpinLock;

/// Maximum number of in-flight sleepers. 64 is enough for the
/// per-CPU IRQ pump, the AML / driver init pumps, and a few
/// test smokes simultaneously. Bumping this up is a one-line
/// change if drivers grow.
pub const MAX_SLEEPERS: usize = 64;

#[derive(Debug)]
struct Slot {
    deadline_cycles: u64,
    waker: Waker,
    /// Generation counter — every Slot reuse bumps this.
    /// `SleepHandle` snapshots the gen at register time;
    /// `cancel`/`refresh` checks gen before touching the slot,
    /// so a stale handle from a fired sleeper can't cancel a
    /// newly-installed sleeper that recycled the index.
    gen: u32,
}

#[derive(Debug)]
struct WheelInner {
    slots: [Option<Slot>; MAX_SLEEPERS],
    /// Next gen value to assign at register time. Monotonic;
    /// wraps at u32::MAX (≈ 4.3 G registrations — fine in
    /// practice).
    next_gen: u32,
}

impl WheelInner {
    const fn new() -> Self {
        const NONE: Option<Slot> = None;
        Self {
            slots: [NONE; MAX_SLEEPERS],
            next_gen: 1,
        }
    }

    fn min_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref().map(|s| s.deadline_cycles))
            .min()
    }
}

static WHEEL: IrqSafeSpinLock<WheelInner> = IrqSafeSpinLock::new(WheelInner::new());

/// Function pointer the IRQ-side glue installs at boot. We
/// store it as `usize` because `fn(u64)` doesn't have an
/// `Atomic*` impl. A zero value means "no arm callback
/// installed yet" — registrations succeed but no hardware
/// timer is programmed (degraded fallback: callers will
/// re-poll into busy-wait).
static ARM_CB: AtomicUsize = AtomicUsize::new(0);

/// Errors `register` can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WheelError {
    /// All `MAX_SLEEPERS` slots are occupied.
    Full,
}

/// Opaque handle returned by [`register`]. Keep it alive for
/// the lifetime of the sleep so that drop / cancel can free
/// the slot.
#[derive(Copy, Clone, Debug)]
pub struct SleepHandle {
    index: u16,
    gen: u32,
}

impl SleepHandle {
    #[inline]
    pub fn index(self) -> u16 {
        self.index
    }
    #[inline]
    pub fn generation(self) -> u32 {
        self.gen
    }
}

/// Install the arm callback. Called once by `narf-interrupts`
/// after HPET + IDT + IOAPIC are wired up. Subsequent calls
/// replace the prior callback (idempotent for boot, useful
/// for tests).
///
/// The callback is invoked under the wheel's internal lock
/// whenever the earliest deadline changes — it must be
/// short, allocation-free, and IRQ-safe.
pub fn set_arm_callback(f: fn(deadline_cycles: u64)) {
    ARM_CB.store(f as usize, Ordering::Release);
}

/// Clear the arm callback. After this, registrations succeed
/// but no hardware timer is programmed; sleepers fall back
/// to whatever wake mechanism their consumer provides.
pub fn clear_arm_callback() {
    ARM_CB.store(0, Ordering::Release);
}

/// `true` once an arm callback has been installed. Consumers
/// (notably `SleepUntil`) check this to decide whether to
/// trust the wheel-driven wake or self-wake into a busy poll
/// fallback.
#[inline]
pub fn arm_callback_installed() -> bool {
    ARM_CB.load(Ordering::Relaxed) != 0
}

#[inline]
fn invoke_arm(deadline: u64) {
    let raw = ARM_CB.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }
    // SAFETY: only set via `set_arm_callback`, which takes
    // `fn(u64)`. Round-trip is sound for a non-zero value.
    // SAFETY: Valid memory or trusted environment
    let f: fn(u64) = unsafe { core::mem::transmute(raw) };
    f(deadline);
}

/// Register `waker` to fire at `deadline_cycles`. Returns a
/// handle that the caller must keep alive (drop = cancel).
/// Errors if the wheel is full.
///
/// If this registration becomes the new earliest deadline,
/// the arm callback is invoked synchronously to re-program
/// the underlying timer.
pub fn register(deadline_cycles: u64, waker: Waker) -> Result<SleepHandle, WheelError> {
    let (handle, new_min) = {
        let mut w = WHEEL.lock();
        let prev_min = w.min_deadline();

        let slot_idx = w
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(WheelError::Full)?;

        let gen = w.next_gen;
        // Skip 0 on wrap so SleepHandle::generation() can use 0
        // as a sentinel without ambiguity.
        w.next_gen = w.next_gen.wrapping_add(1).max(1);

        w.slots[slot_idx] = Some(Slot {
            deadline_cycles,
            waker,
            gen,
        });

        let new_min = w.min_deadline().expect("just inserted");
        let arm = match prev_min {
            None => Some(new_min),
            Some(p) if new_min < p => Some(new_min),
            _ => None,
        };

        (
            SleepHandle {
                index: slot_idx as u16,
                gen,
            },
            arm,
        )
    };
    if let Some(d) = new_min {
        invoke_arm(d);
    }
    Ok(handle)
}

/// Cancel a pending registration. No-op if the slot was
/// already fired or recycled. Does not invoke the arm
/// callback — a cancel can only push the next deadline
/// later, never earlier, so the previously-armed timer
/// remains valid (it'll fire spuriously and the IRQ handler
/// will re-arm to the new minimum).
pub fn cancel(handle: SleepHandle) {
    let mut w = WHEEL.lock();
    let idx = handle.index as usize;
    if idx >= MAX_SLEEPERS {
        return;
    }
    if let Some(s) = w.slots[idx].as_ref() {
        if s.gen == handle.gen {
            w.slots[idx] = None;
        }
    }
}

/// Refresh the waker stored against an existing handle. Used
/// when a future is re-polled with a different `Context` and
/// wants to ensure the new task gets the wake.
///
/// Returns `true` on success, `false` if the slot was
/// already fired/recycled (caller should re-register).
pub fn refresh_waker(handle: SleepHandle, waker: Waker) -> bool {
    let mut w = WHEEL.lock();
    let idx = handle.index as usize;
    if idx >= MAX_SLEEPERS {
        return false;
    }
    if let Some(s) = w.slots[idx].as_mut() {
        if s.gen == handle.gen {
            if !s.waker.will_wake(&waker) {
                s.waker = waker;
            }
            return true;
        }
    }
    false
}

/// Wake every sleeper whose deadline has passed. Returns the
/// number woken. Safe to call from non-IRQ context only —
/// calls wake() on each expired Waker, which consumes it and
/// drops the inner Arc; if that's the last reference the slab
/// dealloc trips `is_sleepable()`'s `in_irq` check.
///
/// IRQ-context callers (timer ISRs, dispatch::on_irq's handler
/// chain) MUST use [`take_due`] instead and call wake() AFTER
/// exiting IRQ context.
pub fn fire_due(now_cycles: u64) -> usize {
    let (taken, n) = take_due(now_cycles);
    for w in taken.into_iter().flatten() {
        w.wake();
    }
    n
}

/// Pull out every Waker whose deadline has passed but DO NOT
/// call wake() on them. Caller is responsible for calling wake()
/// outside IRQ context. Returns the (wakers, count) tuple — the
/// fixed-size array means no heap allocation, safe in any
/// context including from IRQ handlers.
///
/// Typical use from an IRQ handler:
/// ```ignore
/// fn isr() {
///     let (wakers, _n) = take_due(now_cycles());
///     // ... ack hardware, exit IRQ context ...
///     // Then outside IRQ:
///     for w in wakers.into_iter().flatten() { w.wake(); }
/// }
/// ```
pub fn take_due(now_cycles: u64) -> ([Option<Waker>; MAX_SLEEPERS], usize) {
    let mut w = WHEEL.lock();
    let mut taken: [Option<Waker>; MAX_SLEEPERS] = [const { None }; MAX_SLEEPERS];
    let mut n = 0usize;
    for (i, slot) in w.slots.iter_mut().enumerate() {
        if let Some(s) = slot.as_ref() {
            if s.deadline_cycles <= now_cycles {
                let s = slot.take().unwrap();
                taken[i] = Some(s.waker);
                n += 1;
            }
        }
    }
    (taken, n)
}

/// Earliest pending deadline, or `None` if the wheel is
/// empty. Used by the IRQ handler to decide whether to
/// rearm.
pub fn next_deadline_cycles() -> Option<u64> {
    WHEEL.lock().min_deadline()
}

/// Like `next_deadline_cycles` but uses `try_lock`. Safe to call from IRQ
/// context (e.g. the timer ISR's re-arm), where a blocking `lock()` would
/// deadlock against an interrupted `register()`/`fire_due` holding the wheel.
/// Returns None if the wheel is empty OR currently contended (the caller
/// then arms the periodic fallback; the contending path re-arms via the
/// arm-callback right after).
pub fn next_deadline_cycles_try() -> Option<u64> {
    WHEEL.try_lock().and_then(|w| w.min_deadline())
}

/// Diagnostic: number of currently-occupied slots.
pub fn occupied() -> usize {
    WHEEL.lock().slots.iter().filter(|s| s.is_some()).count()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    let mut w = WHEEL.lock();
    for s in w.slots.iter_mut() {
        *s = None;
    }
    w.next_gen = 1;
    drop(w);
    clear_arm_callback();
    ARM_FIRED.store(0, Ordering::Relaxed);
    LAST_ARM_DEADLINE.store(0, Ordering::Relaxed);
}

// Counters used by the test arm-callback below — kept here
// so tests in `tests.rs` can install + observe them.
#[doc(hidden)]
pub static ARM_FIRED: AtomicUsize = AtomicUsize::new(0);
#[doc(hidden)]
pub static LAST_ARM_DEADLINE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[doc(hidden)]
pub fn __test_arm_callback(deadline: u64) {
    ARM_FIRED.fetch_add(1, Ordering::Relaxed);
    LAST_ARM_DEADLINE.store(deadline, Ordering::Relaxed);
}
