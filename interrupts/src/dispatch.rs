//! Generic IRQ-vector dispatch + waker bridge.
//!
//! Stage-3 / Stage-4 driver-readiness piece: every IRQ that lands in
//! the per-arch trap handler (vector ≥ 32 on x86_64, LPI/SPI INTID
//! mapped to a logical slot on aarch64) increments fire counts and
//! invokes the registered handlers + wakers.
//!
//! ## What this exposes
//!
//! - Per-vector global + per-CPU `fire_count` counters.
//! - **Multiple** synchronous handlers per vector (shared-INTx
//!   chain). Each returns `IrqStatus::Handled` or `IrqStatus::None`;
//!   if every handler returns `None`, the IRQ is recorded as
//!   spurious and the spurious counter advances.
//! - **Multiple** wakers per vector. Each `wait_for_irq` future
//!   gets its own waker entry; on IRQ delivery every entry wakes
//!   and the list clears.
//! - `synchronize_irq(vector)` — busy-wait until any in-flight
//!   handler for `vector` has returned. Symmetric with Linux's
//!   `synchronize_irq()`; called before tearing down device
//!   state a handler might still be reading.
//! - Per-vector mask flag — `disable_irq(vec)` short-circuits the
//!   dispatch (handlers + wakers + fire-count + spurious all skip).
//!   Drivers programming the controller mask directly still work;
//!   this is the generic layer.
//! - Named handler entries — `install_handler_named(vec, name,
//!   cookie, fn)` records the owner string so diagnostics
//!   (`/proc/interrupts`-equivalent) can attribute a vector to its
//!   driver.
//!
//! ## Concurrency
//!
//! `on_irq` reads handler / waker lists under each vector's
//! `IrqSafeSpinLock`. Calls happen with IRQs disabled on the
//! current CPU (interrupt gate clears IF), so the lock is
//! uncontested in IRQ context on the same CPU. Cross-CPU concurrent
//! delivery of the same vector serializes via the spinlock.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::Waker;

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// Number of logical vectors. Sized to cover the x86_64 IDT range;
/// the aarch64 ITS path stays under 256 LPIs by Stage-3 convention.
pub const NUM_VECTORS: usize = 256;

/// IRQ-handler outcome, matching Linux's `irqreturn_t` discipline.
/// Drivers chained on a shared INTx line each return `Handled` if
/// they observed and acked a real interrupt from THEIR device, or
/// `None` if the line went hot but their device wasn't the cause.
/// When every chained handler returns `None`, `on_irq` records the
/// fire as spurious — useful for diagnosing wedged level-triggered
/// lines.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IrqStatus {
    Handled,
    None,
}

/// Synchronous handler signature. Takes a per-handler cookie (any
/// opaque `u64` the driver passed at `install_handler_named`) so a
/// single function can be shared across multiple devices and key off
/// the cookie to find the right state. Matches the spirit of Linux's
/// `void *dev_id` second argument.
pub type SyncHandler = fn(cookie: u64) -> IrqStatus;

/// One handler entry in the per-vector chain.
#[derive(Clone, Copy)]
pub struct HandlerEntry {
    pub handler: SyncHandler,
    pub cookie: u64,
    /// Driver-supplied name. Surfaces in
    /// `installed_handler_names(vector)` for diagnostics. `'static`
    /// because the entry is stored for the lifetime of the bind.
    pub name: &'static str,
}

impl core::fmt::Debug for HandlerEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandlerEntry")
            .field("name", &self.name)
            .field("cookie", &self.cookie)
            .finish_non_exhaustive()
    }
}

/// Max CPUs we track per-vector fire counts for. Matches
/// `narf_lib::percpu::MAX_CPUS` but pinned locally so this crate
/// doesn't need the dep.
const PERCPU_FIRES_MAX: usize = 64;

// ── Re-entry guard ─────────────────────────────────────────────────
//
// Per-CPU "currently dispatching vector X" marker. `on_irq` sets
// it before acquiring the handlers spinlock and clears it after.
// `install_handler_named` / `remove_handler` / `clear_handler` /
// `set_waker` / `clear_waker` check it: if a handler running on
// the SAME CPU tries to mutate the dispatch state for the SAME
// vector it's currently running under, panic with a clear message
// (which is strictly better than the deadlock-on-spinlock-re-acquire
// the old code would produce silently).
//
// Cross-CPU mutation is still allowed — the spinlock serialises it
// correctly. Different-vector mutation from inside a handler is
// also allowed (it's the SAME-vector re-entry that deadlocks). The
// marker stores vector + 1 so 0 == "not dispatching" without
// needing a separate AtomicBool.

const NOT_DISPATCHING: u16 = 0;

/// Cache-line-padded per-CPU dispatch marker. Each `DispatchSlot`
/// occupies a full 64-byte line so CPU N's write to its slot
/// doesn't evict CPU M's slot from M's L1 cache (false sharing).
/// The atomic inside is single-CPU-accessed in practice — we
/// keep the AtomicU16 rather than `Cell<u16>` only because
/// `PerCpu`-style Sync wrappers want `Sync` cells and Cell isn't.
/// On x86 an aligned 16-bit AtomicU16 store is a single `mov`
/// (no lock prefix needed for Release), so the cost is the same
/// as a plain write.
#[repr(C, align(64))]
struct DispatchSlot {
    val: core::sync::atomic::AtomicU16,
    /// Pad to a full cache line. Size = 64 - sizeof(AtomicU16) - any
    /// alignment slack. AtomicU16 is 2 bytes; the repr(align(64))
    /// keeps the struct exactly 64 bytes when this pad is sized
    /// 62. (Const-checked below.)
    _pad: [u8; 62],
}

const _: () = {
    assert!(core::mem::size_of::<DispatchSlot>() == 64);
    assert!(core::mem::align_of::<DispatchSlot>() == 64);
};

/// Encoding: 0 = not dispatching; (vector + 1) = dispatching that
/// vector. `u16` covers the 256 vectors plus the sentinel.
static DISPATCHING_VECTOR: [DispatchSlot; PERCPU_FIRES_MAX] = [const {
    DispatchSlot {
        val: core::sync::atomic::AtomicU16::new(NOT_DISPATCHING),
        _pad: [0; 62],
    }
}; PERCPU_FIRES_MAX];

/// Panic with the standard same-vector re-entry message. Called
/// when install_handler_named / remove_handler / clear_handler /
/// set_waker / clear_waker is invoked from inside an on_irq
/// dispatch for the same vector on this CPU.
#[cold]
#[inline(never)]
fn panic_reentry(op: &'static str, vector: u8) -> ! {
    panic!(
        "narf-interrupts: {} called for vector {} from inside its own \
         on_irq handler chain — would deadlock the dispatch spinlock. \
         Restructure the handler to defer the mutation (queue it for the \
         next non-IRQ context, or call from a different vector's path).",
        op, vector
    );
}

/// If the current CPU is already dispatching `vector`, panic. Otherwise
/// no-op. Called by every mutator. Same-CPU check only — cross-CPU
/// callers serialise on the spinlock normally.
#[inline]
fn check_no_reentry(op: &'static str, vector: u8) {
    let cpu = current_cpu_index();
    let cur = DISPATCHING_VECTOR[cpu].val.load(Ordering::Acquire);
    if cur == (vector as u16) + 1 {
        panic_reentry(op, vector);
    }
}

/// RAII scope guard that marks this CPU as dispatching `vector`
/// for its lifetime. Drop clears the marker, so the per-CPU state
/// is consistent across early returns AND across panics that
/// unwind (if/when narf gets unwinding support — today the
/// panic_handler aborts, but the Drop still runs on regular early
/// returns). `on_irq` constructs one of these before walking the
/// chain; any mutator called from inside the chain on the SAME
/// CPU + SAME vector sees the marker and panics via the
/// `check_no_reentry` helper.
struct DispatchGuard {
    cpu: usize,
}

impl DispatchGuard {
    #[inline]
    fn new(vector: u8) -> Self {
        let cpu = current_cpu_index();
        DISPATCHING_VECTOR[cpu]
            .val
            .store((vector as u16) + 1, Ordering::Release);
        Self { cpu }
    }
}

impl Drop for DispatchGuard {
    #[inline]
    fn drop(&mut self) {
        DISPATCHING_VECTOR[self.cpu]
            .val
            .store(NOT_DISPATCHING, Ordering::Release);
    }
}

/// Per-vector dispatch state.
pub struct Slot {
    /// Total IRQs delivered on this vector since boot, across all
    /// CPUs. Never decreases.
    pub fired: AtomicU64,
    /// Per-CPU fire counts. Diagnoses IRQ-steering issues — Linux's
    /// `/proc/interrupts` shows the same shape.
    pub per_cpu_fired: [AtomicU64; PERCPU_FIRES_MAX],
    /// Spurious-IRQ count: incremented when every installed handler
    /// returned `IrqStatus::None`. A nonzero value points at a
    /// driver that's not claiming a shared line correctly, OR (more
    /// often) a level-triggered IRQ that never gets acked at the
    /// device.
    pub spurious: AtomicU64,
    /// Concurrent in-flight handler count. `on_irq` increments at
    /// entry, decrements at exit. `synchronize_irq` busy-waits
    /// until this hits zero.
    pub in_flight: AtomicU32,
    /// Soft mask. `disable_irq` sets this true; `on_irq` short-
    /// circuits (no handlers, no wakers, no fire-count). Drivers
    /// programming the controller mask directly still work; this is
    /// the generic-layer mask.
    pub masked: AtomicBool,
    /// Chain of synchronous handlers. Multiple installed handlers
    /// fire in install order; each can claim or pass the IRQ.
    pub handlers: IrqSafeSpinLock<Vec<HandlerEntry>>,
    /// List of pending wakers. `on_irq` swaps the list out, wakes
    /// every entry, leaves the slot empty for the futures to
    /// re-register on their next poll.
    pub wakers: IrqSafeSpinLock<Vec<Waker>>,
    /// Count of wake() / wake_by_ref() invocations on registered
    /// Wakers for this vector. Used to debug "future never resolved"
    /// failures where the test's Waker fires but `fired` for the
    /// expected vector doesn't move — the discrepancy points at a
    /// stale or mis-routed Waker registration.
    pub wakes_invoked: AtomicU64,
}

impl core::fmt::Debug for Slot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Slot")
            .field("fired", &self.fired.load(Ordering::Relaxed))
            .field("spurious", &self.spurious.load(Ordering::Relaxed))
            .field("in_flight", &self.in_flight.load(Ordering::Relaxed))
            .field("masked", &self.masked.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Slot {
    pub const fn new() -> Self {
        Self {
            fired: AtomicU64::new(0),
            per_cpu_fired: [const { AtomicU64::new(0) }; PERCPU_FIRES_MAX],
            spurious: AtomicU64::new(0),
            in_flight: AtomicU32::new(0),
            masked: AtomicBool::new(false),
            handlers: IrqSafeSpinLock::new(Vec::new()),
            wakers: IrqSafeSpinLock::new(Vec::new()),
            wakes_invoked: AtomicU64::new(0),
        }
    }
}

static SLOTS: [Slot; NUM_VECTORS] = [const { Slot::new() }; NUM_VECTORS];

// ── Handler install / clear ────────────────────────────────────────

/// Install a named synchronous handler for `vector`. Multiple
/// handlers can be installed on the same vector to support shared
/// INTx lines; they fire in install order, each can claim the IRQ
/// (return `Handled`) or pass it along (return `None`). When every
/// chained handler returns `None`, `on_irq` records the delivery as
/// spurious.
///
/// `name` is the driver / device identifier shown in diagnostics;
/// `cookie` is an opaque per-binding value passed back to the
/// handler (typically a pointer cast to u64).
pub fn install_handler_named(
    vector: u8,
    name: &'static str,
    cookie: u64,
    handler: SyncHandler,
) {
    check_no_reentry("install_handler_named", vector);
    let mut g = SLOTS[vector as usize].handlers.lock();
    g.push(HandlerEntry {
        handler,
        cookie,
        name,
    });
}

/// Back-compat shim: install with a `fn()` signature. Wraps the
/// caller's function to always return `IrqStatus::Handled` and
/// passes a zero cookie. Use this only for legacy callers that
/// can't yet plumb the cookie / name through; new code should use
/// `install_handler_named`.
pub fn install(vector: u8, handler: fn()) {
    // We need to bridge `fn()` to `SyncHandler` without an alloc-
    // backed closure trick. Stage 1: a global "legacy slot" per
    // vector storing the `fn()` pointer; the wrapper reads it via
    // cookie and calls. The cookie is the vector itself (legacy
    // handlers don't have a real cookie).
    legacy_install(vector, handler);
}

/// Legacy-handler shim. Stored per-vector; the bridge wrapper
/// `legacy_bridge` reads it and calls.
static LEGACY: [core::sync::atomic::AtomicUsize; NUM_VECTORS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; NUM_VECTORS];

fn legacy_install(vector: u8, handler: fn()) {
    LEGACY[vector as usize].store(handler as usize, Ordering::Release);
    // Only chain the bridge ONCE per vector — re-installing a
    // legacy handler just replaces the stored fn pointer.
    let chain_present = {
        let g = SLOTS[vector as usize].handlers.lock();
        g.iter().any(|h| h.handler as usize == legacy_bridge as usize)
    };
    if !chain_present {
        install_handler_named(vector, "legacy", vector as u64, legacy_bridge);
    }
}

fn legacy_bridge(cookie: u64) -> IrqStatus {
    let v = (cookie & 0xFF) as usize;
    let h = LEGACY[v].load(Ordering::Acquire);
    if h == 0 {
        return IrqStatus::None;
    }
    // SAFETY: stored as `fn() as usize` in `legacy_install`.
    let f: fn() = unsafe { core::mem::transmute(h) };
    f();
    IrqStatus::Handled
}

/// Remove a specific handler from the chain by name + cookie pair.
/// Returns `true` if a matching entry was removed. Use when the
/// driver tears down — combine with `synchronize_irq` BEFORE the
/// drop to ensure no in-flight call observes a freed `cookie`.
pub fn remove_handler(vector: u8, name: &str, cookie: u64) -> bool {
    check_no_reentry("remove_handler", vector);
    let mut g = SLOTS[vector as usize].handlers.lock();
    let len_before = g.len();
    g.retain(|h| !(h.name == name && h.cookie == cookie));
    g.len() < len_before
}

/// Clear all handlers for `vector`. Legacy shim kept for callers
/// that used the old `clear_handler` API.
pub fn clear_handler(vector: u8) {
    check_no_reentry("clear_handler", vector);
    SLOTS[vector as usize].handlers.lock().clear();
    LEGACY[vector as usize].store(0, Ordering::Release);
}

/// Snapshot the names of all installed handlers on `vector`. For
/// diagnostics — feeds the FB status panel's "vector X owned by
/// {drivers...}" line. The returned Vec is a copy; the lock is
/// dropped before return.
pub fn installed_handler_names(vector: u8) -> Vec<&'static str> {
    SLOTS[vector as usize]
        .handlers
        .lock()
        .iter()
        .map(|h| h.name)
        .collect()
}

// ── Per-vector mask ────────────────────────────────────────────────

/// Soft-disable a vector's dispatch. `on_irq` short-circuits (no
/// handlers run, no wakers fire, no fire-count advance). Drivers
/// programming the controller mask directly still work; this is the
/// generic mask layer for stop-the-world cases (driver teardown,
/// resume from suspend).
pub fn disable_irq(vector: u8) {
    SLOTS[vector as usize].masked.store(true, Ordering::Release);
}

/// Inverse of `disable_irq`. Subsequent `on_irq(vector)` calls
/// resume full dispatch.
pub fn enable_irq(vector: u8) {
    SLOTS[vector as usize].masked.store(false, Ordering::Release);
}

/// Returns true if the vector is currently soft-masked.
pub fn is_masked(vector: u8) -> bool {
    SLOTS[vector as usize].masked.load(Ordering::Acquire)
}

// ── synchronize_irq ────────────────────────────────────────────────

/// Wait until no `on_irq(vector)` call is in flight. Symmetric with
/// Linux's `synchronize_irq()`. Use BEFORE freeing device state a
/// handler might still be reading (BAR unmap, driver state Drop).
///
/// Busy-waits on `in_flight`. On a single CPU the in-flight count
/// can only be nonzero if we were preempted out of an IRQ handler
/// — uncommon but possible. The loop yields nothing because we're
/// expected to be at a teardown boundary where time matters less
/// than safety.
pub fn synchronize_irq(vector: u8) {
    while SLOTS[vector as usize].in_flight.load(Ordering::Acquire) > 0 {
        core::hint::spin_loop();
    }
}

/// Snapshot of how many `on_irq(vector)` calls are mid-dispatch.
/// Exposed for verification — production callers should use
/// [`synchronize_irq`] which encodes the busy-wait semantic.
pub fn in_flight(vector: u8) -> u32 {
    SLOTS[vector as usize].in_flight.load(Ordering::Acquire)
}

// ── Dispatch entry point ───────────────────────────────────────────

/// Called from the per-arch IRQ handler with the logical vector
/// that just fired. Increments the fire counts, invokes every
/// installed handler in chain order, and wakes every registered
/// waker.
///
/// If the vector is soft-masked (`disable_irq`), this is a no-op —
/// no counters move, no handlers run, no wakers fire.
#[inline]
pub fn on_irq(vector: u8) {
    let s = &SLOTS[vector as usize];

    // Soft mask check FIRST — gives `disable_irq` strict semantics.
    if s.masked.load(Ordering::Acquire) {
        return;
    }

    narf_lib::context::enter_irq();
    narf_lib::context::set_current_irq_vector(vector);
    s.in_flight.fetch_add(1, Ordering::AcqRel);

    s.fired.fetch_add(1, Ordering::Release);
    // Per-CPU bump — current_cpu may return out-of-range during
    // very-early boot; clamp.
    let cpu = current_cpu_index();
    s.per_cpu_fired[cpu].fetch_add(1, Ordering::Release);

    // Publish the dispatch marker for the lifetime of the chain
    // walk + waker drain. Any mutator (install_handler_named,
    // remove_handler, set_waker, etc.) called from inside a
    // handler on THIS CPU for THIS vector panics via
    // `check_no_reentry`, instead of deadlocking on the spinlock
    // re-acquire. The guard's Drop runs on every exit path —
    // normal fall-through OR (if/when narf gets unwinding) a
    // panic from inside a handler — so the per-CPU state stays
    // consistent.
    {
        let _dispatch = DispatchGuard::new(vector);

        // Walk the handler chain under the lock. No allocation
        // (clone()) here because we're in IRQ context — the
        // sleepable allocator path would panic. Same-vector
        // re-entry from a handler is now a clear panic via
        // check_no_reentry rather than a silent deadlock.
        let mut any_handled = false;
        let chain_was_nonempty;
        {
            let g = s.handlers.lock();
            chain_was_nonempty = !g.is_empty();
            for h in g.iter() {
                match (h.handler)(h.cookie) {
                    IrqStatus::Handled => {
                        any_handled = true;
                    }
                    IrqStatus::None => {}
                }
            }
        }
        if chain_was_nonempty && !any_handled {
            s.spurious.fetch_add(1, Ordering::Release);
        }

        // Wake registered futures. Two paths:
        //
        // 1. Real trap context (called from trap.rs which set
        //    `in_trap_handler`) — use `wake_by_ref` so we don't
        //    drop the Waker's Arc. Arc drops can trigger a
        //    sleepable allocator free, which panics in IRQ
        //    context. Wakers stay in the dispatch vec — futures
        //    re-register on each poll and call `clear_waker` on
        //    completion, so this doesn't leak in steady state.
        // 2. Synchronous call (smoke tests, non-trap callers) —
        //    drain + wake() (consume), since the caller is
        //    allowed to allocate and expects "after on_irq
        //    returns, the wakers have been notified".
        //
        // The discriminator is `in_trap_handler()`, set by the
        // arch trap entry. We can't use RFLAGS.IF — the test
        // harness disables IRQs for some smokes which would
        // mis-identify them as real trap context.
        if narf_lib::context::in_trap_handler() {
            let g = s.wakers.lock();
            let count = g.len();
            for w in g.iter() {
                w.wake_by_ref();
            }
            s.wakes_invoked.fetch_add(count as u64, Ordering::Relaxed);
            // Don't drain — wake_by_ref kept the Wakers in place.
            // Stale entries are cleaned up by `clear_waker` from
            // the future's Drop path or by the next IRQ's wake
            // (idempotent for already-completed tasks).
        } else {
            // Synchronous: drain + consume.
            let mut count = 0u64;
            for w in s.wakers.lock().drain(..) {
                w.wake();
                count += 1;
            }
            s.wakes_invoked.fetch_add(count, Ordering::Relaxed);
        }
        // _dispatch drops here → clears the per-CPU marker.
    }

    s.in_flight.fetch_sub(1, Ordering::AcqRel);
    narf_lib::context::clear_current_irq_vector();
    narf_lib::context::exit_irq();
}

#[inline]
fn current_cpu_index() -> usize {
    let c = narf_lib::percpu::current_cpu();
    if c < PERCPU_FIRES_MAX {
        c
    } else {
        0
    }
}

// ── Counters ───────────────────────────────────────────────────────

/// Snapshot of a vector's global fire count.
#[inline]
pub fn fire_count(vector: u8) -> u64 {
    SLOTS[vector as usize].fired.load(Ordering::Acquire)
}

/// Snapshot of a vector's per-CPU fire count.
#[inline]
pub fn fire_count_on_cpu(vector: u8, cpu: usize) -> u64 {
    if cpu >= PERCPU_FIRES_MAX {
        return 0;
    }
    SLOTS[vector as usize].per_cpu_fired[cpu].load(Ordering::Acquire)
}

/// Snapshot of how many wake() / wake_by_ref() calls `on_irq`
/// has issued on registered Wakers for `vector` since boot.
/// Diagnostic: a non-zero count for a vector your test isn't
/// waiting on, paired with a zero count for the vector it IS
/// waiting on, points at a Waker that's mis-registered (or a
/// stale wheel entry firing the same payload).
#[inline]
pub fn wakes_invoked(vector: u8) -> u64 {
    SLOTS[vector as usize].wakes_invoked.load(Ordering::Acquire)
}

/// Spurious-IRQ count for `vector`. Bumped when every chained
/// handler returned `None`. Use as a real-HW diagnostic: a non-zero
/// spurious count points at a missing handler or a stuck level-
/// triggered line.
#[inline]
pub fn spurious_count(vector: u8) -> u64 {
    SLOTS[vector as usize].spurious.load(Ordering::Acquire)
}

// ── Waker registration (multi-waker) ───────────────────────────────

/// Install a waker to be invoked once on the next IRQ at this
/// vector. Multiple `set_waker` calls accumulate — every waiter
/// gets woken on the next fire. The wakers list is taken out at
/// wake time so each waiter must re-register if it wants another
/// wake.
/// Install a waker for the next IRQ on `vector`. If an equivalent
/// waker (per `Waker::will_wake`) is already queued, this is a
/// no-op — `wait_for_irq` calls `set_waker` on every re-poll, so
/// without the dedup the list would grow unbounded on real-HW
/// where IRQs come slowly relative to the executor's re-poll
/// rate. Two distinct waiters with different wakers both get
/// pushed (that's the multi-waiter contract).
#[inline]
pub fn set_waker(vector: u8, w: Waker) {
    check_no_reentry("set_waker", vector);
    let mut g = SLOTS[vector as usize].wakers.lock();
    if g.iter().any(|existing| existing.will_wake(&w)) {
        return;
    }
    g.push(w);
}

/// Drop any waker matching `target` (by `Waker::will_wake`). Used
/// by `WaitForIrq::Drop` so a cancelled wait only removes its OWN
/// waker — multiple tasks sharing a vector (the standard case for
/// shared MSI-X / level-INTx) must not have each other's wakers
/// silently wiped when one of them drops its future.
pub fn clear_waker(vector: u8, target: &Waker) {
    check_no_reentry("clear_waker", vector);
    let mut g = SLOTS[vector as usize].wakers.lock();
    g.retain(|existing| !existing.will_wake(target));
}

/// Clear ALL wakers registered on `vector`. Reserved for tear-down
/// paths where the vector itself is being released (driver unbind,
/// per-test cleanup) — anything still parked on it is about to lose
/// the device anyway. Routine cancellation should go through
/// [`clear_waker`] with the caller's own waker.
pub fn clear_all_wakers(vector: u8) {
    check_no_reentry("clear_all_wakers", vector);
    SLOTS[vector as usize].wakers.lock().clear();
}

/// Diagnostic: number of distinct wakers currently queued for
/// `vector`. Exposed for tests (set_waker dedup regression) and
/// for the panel's per-vector dignostic line.
#[inline]
pub fn wakers_len(vector: u8) -> usize {
    SLOTS[vector as usize].wakers.lock().len()
}

// ── NMI dispatch ────────────────────────────────────────────────────
//
// NMIs (x86 vector 2; aarch64 has no direct equivalent) bypass the
// normal IRQ subsystem — they're delivered with IF=0 and edge-only,
// and the standard `on_irq` machinery is overkill plus unsafe in NMI
// context (the spinlock guards don't compose with NMI re-entrancy).
//
// Instead: a tiny fixed-size table of (handler, cookie) entries that
// `on_nmi()` walks LOCK-FREELY. Handlers run with IRQs disabled (NMI
// hardware guarantee). The standard NMI consumers in a real-world
// kernel are:
//   - perf counter sample handling (PMU overflow)
//   - hard-lockup watchdog (CPU-stuck detector)
//   - crash-dump trigger (oops-on-NMI)
// All of these are short, allocate nothing, and can tolerate strict
// no-locks discipline.
//
// Limited to MAX_NMI_HANDLERS = 8 entries. Install is `add_nmi_handler`
// returning an opaque id; remove is `remove_nmi_handler(id)`.

const MAX_NMI_HANDLERS: usize = 8;

/// NMI-handler signature — same return type as the IRQ flavour
/// (Handled / None for spurious-NMI accounting). Caller cookie is
/// passed through for per-binding state.
pub type NmiHandler = fn(cookie: u64) -> IrqStatus;

struct NmiSlot {
    used: AtomicBool,
    handler: AtomicU64,
    cookie: AtomicU64,
}

static NMI_SLOTS: [NmiSlot; MAX_NMI_HANDLERS] = [const {
    NmiSlot {
        used: AtomicBool::new(false),
        handler: AtomicU64::new(0),
        cookie: AtomicU64::new(0),
    }
}; MAX_NMI_HANDLERS];

static NMI_FIRED: AtomicU64 = AtomicU64::new(0);
static NMI_SPURIOUS: AtomicU64 = AtomicU64::new(0);

/// Opaque registration id returned by `add_nmi_handler`. Pass to
/// `remove_nmi_handler` to detach.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NmiHandlerId(u8);

/// Register an NMI handler. Returns the slot id on success or
/// `None` if all MAX_NMI_HANDLERS slots are taken.
pub fn add_nmi_handler(handler: NmiHandler, cookie: u64) -> Option<NmiHandlerId> {
    for (i, slot) in NMI_SLOTS.iter().enumerate() {
        if !slot.used.swap(true, Ordering::AcqRel) {
            slot.handler.store(handler as u64, Ordering::Release);
            slot.cookie.store(cookie, Ordering::Release);
            return Some(NmiHandlerId(i as u8));
        }
    }
    None
}

/// Remove a previously-registered NMI handler.
pub fn remove_nmi_handler(id: NmiHandlerId) {
    let i = id.0 as usize;
    if i >= MAX_NMI_HANDLERS {
        return;
    }
    NMI_SLOTS[i].handler.store(0, Ordering::Release);
    NMI_SLOTS[i].cookie.store(0, Ordering::Release);
    NMI_SLOTS[i].used.store(false, Ordering::Release);
}

/// Called from the per-arch NMI handler (x86: IDT entry 2). Walks
/// the registered handler chain and bumps the spurious counter if
/// none claim. Runs with IRQs disabled (NMI hardware contract).
/// LOCK-FREE — no spinlock guards because an NMI can interrupt
/// arbitrary code, including code holding the IRQ-side spinlocks.
#[inline]
pub fn on_nmi() {
    NMI_FIRED.fetch_add(1, Ordering::Release);
    let mut any_handled = false;
    let mut any_present = false;
    for slot in NMI_SLOTS.iter() {
        if !slot.used.load(Ordering::Acquire) {
            continue;
        }
        any_present = true;
        let h_raw = slot.handler.load(Ordering::Acquire);
        if h_raw == 0 {
            continue;
        }
        let cookie = slot.cookie.load(Ordering::Acquire);
        // SAFETY: stored as `NmiHandler as u64`; round-trip safe
        // because both are `fn(u64) -> IrqStatus`.
        let h: NmiHandler = unsafe { core::mem::transmute(h_raw as usize) };
        if h(cookie) == IrqStatus::Handled {
            any_handled = true;
        }
    }
    if any_present && !any_handled {
        NMI_SPURIOUS.fetch_add(1, Ordering::Release);
    }
}

/// Total NMIs delivered since boot.
#[inline]
pub fn nmi_fire_count() -> u64 {
    NMI_FIRED.load(Ordering::Acquire)
}

/// NMIs where no registered handler returned Handled.
#[inline]
pub fn nmi_spurious_count() -> u64 {
    NMI_SPURIOUS.load(Ordering::Acquire)
}
