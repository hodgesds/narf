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

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::Waker;

use narf_lib::sync::IrqSafeSpinLock;

/// Maximum number of in-flight sleepers.  A desktop userspace routinely has
/// hundreds of services blocked in epoll/poll at once; each needs a bounded
/// lost-wake backstop in addition to its primary event-source waker.  Keep the
/// fixed, IRQ-safe representation, but size it for that real workload rather
/// than the early-boot-only one.
pub const MAX_SLEEPERS: usize = 1024;

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

/// Cached minimum wheel deadline. `NEXT_DEADLINE_VALID` distinguishes an
/// empty wheel from a real timer at `u64::MAX`.
///
/// `fire_due` is called from every CPU's executor loop, including the hot
/// runnable path.  Walking all 1024 slots (and taking the global wheel lock
/// once per slot) merely to discover that the next deadline is still in the
/// future turns an SMP desktop workload into lock contention.  Keep the
/// spec-required next-deadline cache so the common case is a small lock-free
/// snapshot. All slot mutations publish while holding `WHEEL`; the sequence
/// counter prevents readers from combining an old valid bit with a new
/// deadline (or vice versa). A stale completed snapshot may be earlier than
/// the true minimum during a concurrent drain, causing at most one unnecessary
/// slow-path scan, but is never allowed to be later.
static NEXT_DEADLINE: AtomicU64 = AtomicU64::new(u64::MAX);
static NEXT_DEADLINE_VALID: AtomicBool = AtomicBool::new(false);
/// Even values describe a stable `(valid, deadline)` snapshot; odd values
/// mean a writer is publishing. Writers are serialized by `WHEEL`.
static NEXT_DEADLINE_SEQ: AtomicU64 = AtomicU64::new(0);

#[inline]
fn cached_min() -> Option<u64> {
    loop {
        let before = NEXT_DEADLINE_SEQ.load(Ordering::Acquire);
        if before & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let valid = NEXT_DEADLINE_VALID.load(Ordering::Relaxed);
        let deadline = NEXT_DEADLINE.load(Ordering::Relaxed);
        let after = NEXT_DEADLINE_SEQ.load(Ordering::Acquire);
        if before == after {
            return valid.then_some(deadline);
        }
    }
}

#[inline]
fn cached_min_write_begin() {
    // Acquire prevents the following wheel mutation and payload stores from
    // moving before the odd marker. Writers are serialized by WHEEL.
    let previous = NEXT_DEADLINE_SEQ.fetch_add(1, Ordering::AcqRel);
    debug_assert_eq!(previous & 1, 0, "nested timer-wheel cache publication");
}

#[inline]
fn cached_min_write_end(min: Option<u64>) {
    if let Some(deadline) = min {
        NEXT_DEADLINE.store(deadline, Ordering::Relaxed);
        NEXT_DEADLINE_VALID.store(true, Ordering::Relaxed);
    } else {
        NEXT_DEADLINE_VALID.store(false, Ordering::Relaxed);
    }
    NEXT_DEADLINE_SEQ.fetch_add(1, Ordering::Release);
}

#[inline]
fn publish_cached_min(min: Option<u64>) {
    cached_min_write_begin();
    cached_min_write_end(min);
}

#[inline]
fn publish_min_locked(wheel: &WheelInner) -> Option<u64> {
    let min = wheel.min_deadline();
    publish_cached_min(min);
    min
}

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
        let prev_min = cached_min();

        let slot_idx = w
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(WheelError::Full)?;

        let gen = w.next_gen;
        // Skip 0 on wrap so SleepHandle::generation() can use 0
        // as a sentinel without ambiguity.
        w.next_gen = w.next_gen.wrapping_add(1).max(1);

        // Mark the cache unstable before making an earlier deadline visible
        // in the wheel. Otherwise a lock-free reader could accept the old,
        // later cached minimum in the mutation-to-publication window.
        cached_min_write_begin();
        w.slots[slot_idx] = Some(Slot {
            deadline_cycles,
            waker,
            gen,
        });

        let new_min = prev_min.map_or(deadline_cycles, |p| p.min(deadline_cycles));
        cached_min_write_end(Some(new_min));
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
            let removed_deadline = s.deadline_cycles;
            w.slots[idx] = None;
            if cached_min() == Some(removed_deadline) {
                publish_min_locked(&w);
            }
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

/// Like [`refresh_waker`] but also updates the slot's DEADLINE. Park paths
/// that reuse one `SleepHandle` across successive parks with different
/// deadlines (the own-stack `park_should_block`, `UserTaskFuture::poll`)
/// must use this: plain `refresh_waker` keeps the ORIGINAL deadline, so a
/// handle that outlives its first park (e.g. a futex park broken by the
/// wake-generation guard, which clears the park state but leaves the wheel
/// slot live) silently pins every LATER park's fallback wake to the stale
/// first deadline — a far-out stale deadline turns the lost-wake backstop
/// into a strand.
///
/// If the new deadline becomes the wheel's earliest, the arm callback is
/// invoked (same as [`register`]). Returns `false` if the slot was already
/// fired/recycled (caller should re-register).
pub fn refresh_waker_at(handle: SleepHandle, deadline_cycles: u64, waker: Waker) -> bool {
    let arm = {
        let mut w = WHEEL.lock();
        let idx = handle.index as usize;
        if idx >= MAX_SLEEPERS {
            return false;
        }
        let prev_min = cached_min();
        let old_deadline = match w.slots[idx].as_ref() {
            Some(s) if s.gen == handle.gen => s.deadline_cycles,
            _ => return false,
        };
        // As in register(), an earlier replacement must not become visible
        // while readers can still accept the old, later cached minimum.
        cached_min_write_begin();
        let s = w.slots[idx]
            .as_mut()
            .expect("validated timer slot disappeared while WHEEL was locked");
        s.deadline_cycles = deadline_cycles;
        if !s.waker.will_wake(&waker) {
            s.waker = waker;
        }
        let new_min = if prev_min == Some(old_deadline) && deadline_cycles > old_deadline {
            w.min_deadline().expect("slot present")
        } else {
            prev_min.map_or(deadline_cycles, |p| p.min(deadline_cycles))
        };
        cached_min_write_end(Some(new_min));
        match prev_min {
            Some(p) if new_min < p => Some(new_min),
            None => Some(new_min),
            _ => None,
        }
    };
    if let Some(d) = arm {
        invoke_arm(d);
    }
    true
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
    if cached_min().is_none_or(|deadline| deadline > now_cycles) {
        return 0;
    }
    // O(1) stack + SINGLE PASS. Walk slot indices once with a cursor, taking +
    // waking each slot that is due at entry. Two invariants matter:
    //   - No ~1 KiB on-stack `[Option<Waker>; MAX_SLEEPERS]`: moving that array
    //     by value smashed the caller's return chain when this runs from a timer
    //     IRQ on a user task's own kernel stack (per-task-own-stack model).
    //   - Each currently-due timer fires AT MOST ONCE per call (matches the old
    //     `take_due` single pass). A `wake()` may re-register a fresh timer (the
    //     smoltcp net poll re-arms on every wake) into a now-freed LOWER slot;
    //     the cursor never revisits it, so that re-registration is deferred to
    //     the next tick. A re-scan-from-zero loop instead spins forever once a
    //     poller re-arms with deadline ≤ now, wedging the CPU — observed as
    //     accept() never completing in net-smoke.
    // `wake()` runs outside the lock (it re-acquires the wheel on re-register).
    //
    // Take WHEEL once per BATCH of scanned slots, not once per slot: the old
    // per-slot re-lock cost MAX_SLEEPERS (1024) global-lock acquisitions per
    // call, so on an SMP box every CPU firing due timers serialized on this one
    // lock — profiled as the dominant cost (58% of samples, the rest idle)
    // under a 256-connection TCP load. Collect each batch's due wakers into a
    // small fixed on-stack buffer, drop the lock, then wake. The cursor still
    // advances forward only, so each due timer fires at most once and a wake
    // that re-arms into a lower slot is deferred to the next tick (unchanged).
    // The 16-waker buffer is ~256 B — nowhere near the ~16 KiB full-slot array
    // the per-task-own-stack path forbids.
    const BATCH: usize = 16;
    let mut n = 0usize;
    let mut cursor = 0usize;
    while cursor < MAX_SLEEPERS {
        let mut batch: [Option<Waker>; BATCH] = [const { None }; BATCH];
        let mut count = 0usize;
        {
            let mut w = WHEEL.lock();
            while cursor < MAX_SLEEPERS && count < BATCH {
                let due = matches!(
                    w.slots[cursor].as_ref(),
                    Some(s) if s.deadline_cycles <= now_cycles
                );
                if due {
                    batch[count] = w.slots[cursor].take().map(|s| s.waker);
                    count += 1;
                }
                cursor += 1;
            }
        }
        for wk in batch.into_iter().take(count).flatten() {
            wk.wake();
            n += 1;
        }
    }
    // Publish while holding WHEEL so a concurrent registration cannot insert
    // an earlier timer between the recompute and the store.
    {
        let w = WHEEL.lock();
        publish_min_locked(&w);
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
    let mut taken: [Option<Waker>; MAX_SLEEPERS] = [const { None }; MAX_SLEEPERS];
    let n = take_due_into(now_cycles, &mut taken);
    (taken, n)
}

/// Like [`take_due`] but fills a caller-provided `out` buffer instead of
/// returning a `MAX_SLEEPERS`-element array by value. IRQ-context callers (the
/// HPET pump, the clockevent tick) MUST use this: returning the ~1 KiB array by
/// value forces an `sret` copy + a second on-stack buffer, and on a user task's
/// own kernel stack (the per-task-own-stack model) that fragile large-struct
/// return was observed to smash the handler's return address under fork/exec
/// churn (`rip=0x3` wild jumps). Writing in place into the caller's single
/// buffer avoids the copy entirely.
pub fn take_due_into(now_cycles: u64, out: &mut [Option<Waker>; MAX_SLEEPERS]) -> usize {
    let mut w = WHEEL.lock();
    let mut n = 0usize;
    for (i, slot) in w.slots.iter_mut().enumerate() {
        if let Some(s) = slot.as_ref() {
            if s.deadline_cycles <= now_cycles {
                let s = slot.take().unwrap();
                out[i] = Some(s.waker);
                n += 1;
            }
        }
    }
    publish_min_locked(&w);
    n
}

/// Drain every due waker straight into the per-CPU deferred-wake queue, using
/// **O(1) stack**. This is the IRQ-context wheel drain — the HPET pump and the
/// clockevent tick MUST use this, NOT [`take_due`]/[`take_due_into`].
///
/// Why: `take_due*` materialise a `MAX_SLEEPERS`-element `[Option<Waker>]`
/// (~1 KiB) on the stack. In the per-task-own-stack model the timer IRQ runs on
/// the *user task's own kernel stack* (`TSS.rsp0` points there), and that large
/// IRQ-path frame — returned/passed by value through the drain — smashed the
/// handler's return chain under fork/exec churn, producing the `rip=0x3` wild
/// jump. Draining one waker at a time keeps the IRQ frame tiny.
///
/// Wakers are *pushed*, never woken here: `wake()` would drop the `Arc` (a slab
/// free) in IRQ context. The scheduler's idle path (`drain_and_wake`) wakes +
/// drops them in a context where freeing is allowed.
///
/// Lock order is `WHEEL` then the current CPU's deferred-wake queue.  No path
/// takes those locks in the reverse order: `drain_and_wake` releases the queue
/// before invoking a waker.  Keeping `WHEEL` locked through `try_push_one` is
/// load-bearing: when the queue is full, the exact timer slot can be restored
/// without a concurrent registration stealing its only recovery location.
///
/// SINGLE PASS via an index cursor (same invariant as [`fire_due`]): each
/// currently-due timer is drained at most once; a re-registration into a freed
/// lower slot is deferred to the next tick, never re-drained this call.
pub fn drain_due_to_deferred(now_cycles: u64) {
    if cached_min().is_none_or(|deadline| deadline > now_cycles) {
        return;
    }
    let mut w = WHEEL.lock();
    for i in 0..MAX_SLEEPERS {
        let taken = match w.slots[i].as_ref() {
            Some(s) if s.deadline_cycles <= now_cycles => w.slots[i].take(),
            _ => None,
        };
        let Some(slot) = taken else { continue };
        let Slot {
            deadline_cycles,
            waker,
            gen,
        } = slot;
        if let Err(waker) = narf_lib::deferred_wake::try_push_one(waker) {
            // Queue full. Restore the same generation in the same slot while
            // WHEEL is still locked, so neither the wake nor its SleepHandle
            // identity can be lost. Leave later due slots untouched and retry
            // them after the executor drains the deferred queue.
            w.slots[i] = Some(Slot {
                deadline_cycles,
                waker,
                gen,
            });
            break;
        }
    }
    publish_min_locked(&w);
}

/// Earliest pending deadline, or `None` if the wheel is
/// empty. Used by the IRQ handler to decide whether to
/// rearm.
pub fn next_deadline_cycles() -> Option<u64> {
    cached_min()
}

/// IRQ-safe lock-free form of [`next_deadline_cycles`]. The versioned cache
/// prevents an interrupted or concurrent wheel mutation from exposing a
/// mixed snapshot, so this only returns `None` when the wheel is empty.
pub fn next_deadline_cycles_try() -> Option<u64> {
    cached_min()
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
    publish_cached_min(None);
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
