//! Sync primitives (`SpinLock`, `IrqSafeSpinLock`, `TicketSpinLock`,
//! `IrqSafeTicketSpinLock`, `Once`, `OnceLock`).
//!
//! Spec: `lib/specification/spec.md` §3.1. Typestate IRQ safety (§4): holding
//! a `SpinLockGuard<'_, T, IrqsDisabled>` across code that re-enables IRQs is
//! a compile error. The `IrqsEnabled` vs `IrqsDisabled` split is enforced at
//! type-level here; the IRQ-context token threading lives in `frame/` /
//! `scheduler/` once those crates exist. For Stage 1 we expose both variants
//! plus a locked-state type parameter; consumers pick the variant that matches
//! the call context.

use core::cell::UnsafeCell;
use core::fmt;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

// ──────────────────────────────────────────────────────────────────
// Spin-wait hook — drain work that a masked spinner would otherwise
// stall (TLB shootdowns).
// ──────────────────────────────────────────────────────────────────

/// Optional hook the `IrqSafeSpinLock` busy-wait calls while spinning with
/// IRQs masked. `0` = none.
///
/// The x86_64 TLB-shootdown layer installs `ipi::poll_pending_shootdown` here
/// (from the x2APIC boot block). A CPU spinning on a lock has interrupts
/// disabled, so it can't take a shootdown IPI — a peer broadcasting a shootdown
/// would spin to its ack cap and then *give up*, leaving this CPU with a stale
/// TLB. On a shared address space (threads / migrated user tasks) that's a
/// use-after-unmap. Draining the pending shootdown from the spin loop keeps a
/// masked spinner responsive, so a shootdown is never stranded.
static LOCK_SPIN_HOOK: AtomicUsize = AtomicUsize::new(0);
const MAX_DIAGNOSTIC_CPUS: usize = 16;
static CONTENDED_IRQ_LOCK: [AtomicUsize; MAX_DIAGNOSTIC_CPUS] =
    [const { AtomicUsize::new(0) }; MAX_DIAGNOSTIC_CPUS];

/// Install the spin-wait hook (see [`LOCK_SPIN_HOOK`]). `hook` must be safe to
/// call from any CPL=0 context with IRQs masked. Idempotent.
pub fn set_lock_spin_hook(hook: fn()) {
    LOCK_SPIN_HOOK.store(hook as usize, Ordering::Release);
}

/// Address of the `IrqSafeSpinLock` on which `cpu` is currently spinning.
///
/// This is a diagnostic snapshot for fatal-path watchdogs. A zero value means
/// that the CPU has not crossed the throttled contention threshold, or has
/// since acquired the lock.
pub fn contended_irq_lock(cpu: usize) -> usize {
    CONTENDED_IRQ_LOCK
        .get(cpu)
        .map(|slot| slot.load(Ordering::Acquire))
        .unwrap_or(0)
}

/// Service the work a CPU spinning with interrupts masked would otherwise
/// strand: pending TLB-shootdown requests (the installed hook) and
/// `membarrier` rendezvous. Every spin-wait that can run with IRQs masked must
/// call this — `IrqSafeSpinLock` does, the shootdown sender does, and a
/// device request gate must too: a waiter that cannot take the shootdown IPI
/// and never drains it leaves the sender (who may hold the very gate being
/// waited on) spinning on its ack forever. Linux forbids the shape outright —
/// TLB-flush IPIs WARN under `irqs_disabled()`.
#[inline]
pub fn service_masked_spin() {
    run_lock_spin_hook();
}

/// Test-only: install `new` (or nothing) as the spin-wait hook, returning the
/// previous one so a test can restore what boot installed.
#[doc(hidden)]
pub fn __test_swap_lock_spin_hook(new: Option<fn()>) -> Option<fn()> {
    let raw = new.map_or(0, |f| f as usize);
    let prev = LOCK_SPIN_HOOK.swap(raw, Ordering::AcqRel);
    // SAFETY: only `set_lock_spin_hook` / this swap write the cell, always
    // with a valid `fn()` or 0.
    (prev != 0).then(|| unsafe { core::mem::transmute::<usize, fn()>(prev) })
}

/// Service the work a CPU with IRQs masked would otherwise strand: pending
/// TLB-shootdown requests (the installed spin-wait hook) and `membarrier(2)`
/// rendezvous. For a holder of an `IrqSafeSpinLock` that runs a long
/// operation, the counterpart of what the lock's own spin loop does for its
/// waiters: a peer waiting on this CPU's acknowledgement is answered between
/// the operation's steps instead of after all of them. Call from CPL=0 with
/// IRQs masked, at a point where servicing a shootdown is safe (no page
/// table of the current address space half-edited).
#[inline]
pub fn service_masked_work() {
    run_lock_spin_hook();
}

/// Run the installed spin-wait hook if any. Tiny by design — one acquire load
/// and an early return when nothing is wired (kernel-test, pre-boot, or the
/// xAPIC fallback where shootdowns aren't broadcast).
#[inline(always)]
fn run_lock_spin_hook() {
    // The `membarrier(2)` rendezvous has the same stranding problem the
    // installed shootdown hook solves, and one worse consequence: the sender
    // does not give up. A CPU spinning here with IRQs masked cannot take the
    // barrier IPI, so a peer waiting on its acknowledgement would spin
    // forever. This lives in the crate rather than behind LOCK_SPIN_HOOK
    // because the protocol is arch-neutral and must be drained on aarch64
    // too, which installs no hook. One relaxed load when nothing is pending.
    crate::smp::service_pending_barriers();
    let h = LOCK_SPIN_HOOK.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: only `set_lock_spin_hook` ever writes this cell, always with
        // a valid `fn()` pointer; a non-zero value is therefore callable.
        let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(h) };
        f();
    }
}

// ──────────────────────────────────────────────────────────────────
// IRQ-state typestate markers
// ──────────────────────────────────────────────────────────────────

mod private {
    pub trait Sealed {}
    impl Sealed for super::IrqsEnabled {}
    impl Sealed for super::IrqsDisabled {}
}

/// Marker trait for IRQ-state typestate. Sealed: only `IrqsEnabled` and
/// `IrqsDisabled` implement it.
pub trait IrqState: private::Sealed {}

/// Marker: call site has IRQs enabled.
#[derive(Debug)]
pub struct IrqsEnabled;

/// Marker: call site has IRQs disabled.
#[derive(Debug)]
pub struct IrqsDisabled;

impl IrqState for IrqsEnabled {}
impl IrqState for IrqsDisabled {}

// ──────────────────────────────────────────────────────────────────
// SpinLock<T> — plain spinlock, must be taken with IRQs enabled.
// ──────────────────────────────────────────────────────────────────

/// Plain ticket-free spinlock. Must be acquired with IRQs enabled; taking
/// it with IRQs disabled risks deadlock against an IRQ handler that tries
/// the same lock. Use `IrqSafeSpinLock` from IRQ-possible contexts.
pub struct SpinLock<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: `SpinLock` serialises access to `T`; if `T: Send`, the lock is
// `Send + Sync`. We never construct a `&T` alias while the lock is held.
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}
// SAFETY: exclusive access is serialized by the lock; `T: Send` makes sharing the guarded value across tasks sound.
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Acquire the lock. Caller asserts IRQs are enabled via the zero-sized
    /// witness `IrqsEnabled` — a future `frame/` will mint this from the
    /// per-CPU IRQ-state register as proof.
    #[inline]
    pub fn lock(&self, _: IrqsEnabled) -> SpinLockGuard<'_, T, IrqsEnabled> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
        SpinLockGuard {
            lock: self,
            _irq: IrqsEnabled,
        }
    }

    /// Raw pointer to the guarded value, without acquiring the lock.
    ///
    /// The only supported use is handing a *stable address* of the
    /// guarded data to code that cannot take the lock — hand-written
    /// asm that runs with no Rust runtime (an S3 wake trampoline, a
    /// CPU bring-up stub). Callers must not form a `&T`/`&mut T`
    /// through it while the lock is held elsewhere.
    ///
    /// This exists so such callers never have to *assume* the guarded
    /// value sits at offset 0 of the lock: neither `SpinLock` nor
    /// `IrqSafeSpinLock` is `repr(C)`, so field order is entirely up
    /// to the compiler and any hard-coded offset is a latent bug.
    #[inline]
    pub const fn as_ptr(&self) -> *mut T {
        self.data.get()
    }

    /// Attempt to acquire without blocking; returns `None` on contention.
    #[inline]
    pub fn try_lock(&self, _: IrqsEnabled) -> Option<SpinLockGuard<'_, T, IrqsEnabled>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard {
                lock: self,
                _irq: IrqsEnabled,
            })
    }
}

/// RAII guard. The `I: IrqState` parameter propagates the IRQ context under
/// which the lock was acquired, so downstream code cannot accidentally mix
/// them (e.g. acquire under `IrqsEnabled`, then call an `IrqsDisabled`-only
/// helper — compile error).
pub struct SpinLockGuard<'a, T: ?Sized, I: IrqState> {
    lock: &'a SpinLock<T>,
    _irq: I,
}

impl<T: ?Sized, I: IrqState> fmt::Debug for SpinLockGuard<'_, T, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpinLockGuard").finish_non_exhaustive()
    }
}

// Guards are `!Send`: unlocking must happen on the CPU that locked.
impl<T: ?Sized, I: IrqState> !Send for SpinLockGuard<'_, T, I> {}

impl<T: ?Sized, I: IrqState> Deref for SpinLockGuard<'_, T, I> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: lock is held.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized, I: IrqState> DerefMut for SpinLockGuard<'_, T, I> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: lock is held exclusively.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized, I: IrqState> Drop for SpinLockGuard<'_, T, I> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpinLock")
            .field("locked", &self.locked.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// ──────────────────────────────────────────────────────────────────
// IrqSafeSpinLock<T> — disables IRQs across the critical section.
// ──────────────────────────────────────────────────────────────────

/// Spinlock variant that disables IRQs for the duration of the critical
/// section. Required when the lock may be contended between a thread
/// holding it and an IRQ handler running on the same CPU — without IRQ
/// disable, the IRQ handler that tries to take the same lock spins
/// forever waiting for the holder it preempted.
///
/// The IRQ disable is implemented inline against the running CPU's
/// flags register (RFLAGS.IF on x86_64, DAIF.I on aarch64). We do
/// **not** route through a function-pointer hook installed by the
/// arch backend: a CPU-local mask is one instruction per arch with
/// no controller indirection, and a hook would add an indirection
/// without removing complexity. Multi-controller policy (GIC group
/// priorities, APIC TPR-based masking, etc.) is the IRQ
/// dispatcher's job, not the lock's.
pub struct IrqSafeSpinLock<T: ?Sized> {
    inner: SpinLock<T>,
}

// SAFETY: exclusive access is serialized by the lock; `T: Send` makes sharing the guarded value across tasks sound.
unsafe impl<T: ?Sized + Send> Send for IrqSafeSpinLock<T> {}
// SAFETY: exclusive access is serialized by the lock; `T: Send` makes sharing the guarded value across tasks sound.
unsafe impl<T: ?Sized + Send> Sync for IrqSafeSpinLock<T> {}

impl<T> IrqSafeSpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            inner: SpinLock::new(data),
        }
    }

    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> IrqSafeSpinLock<T> {
    /// Raw pointer to the guarded value, without acquiring the lock.
    /// See [`SpinLock::as_ptr`] for the (narrow) supported use and the
    /// reason a hard-coded "offset 0 of the lock" is not one.
    #[inline]
    pub const fn as_ptr(&self) -> *mut T {
        self.inner.as_ptr()
    }

    #[inline]
    pub fn lock(&self) -> IrqSafeSpinLockGuard<'_, T> {
        // SAFETY: save+disable inline asm is the canonical local IRQ-
        // disable sequence on each arch; no platform state is touched
        // beyond the IF / DAIF.I bit of the running CPU.
        // SAFETY: Valid memory or trusted environment
        let saved = unsafe { irq_save_disable() };
        // Spin count drives a throttled `run_lock_spin_hook` (every 256 pause
        // iterations): we hold IRQs masked here, so without draining we can't
        // service a peer's TLB-shootdown IPI — see LOCK_SPIN_HOOK. 256 pauses
        // (~µs) is far under a shootdown sender's ack cap, so the peer never
        // stalls, while uncontended locks (no inner spin) pay nothing.
        let mut spins: u32 = 0;
        // Whether this acquire published a contended-lock marker while spinning
        // (see below). Uncontended acquires never do, so they can skip the
        // marker clear — and, crucially, the `current_cpu()` read it needs.
        let mut marked = false;
        while self
            .inner
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.inner.locked.load(Ordering::Relaxed) {
                spin_loop();
                spins = spins.wrapping_add(1);
                if spins & 0xFF == 0 {
                    let cpu = crate::percpu::current_cpu();
                    if let Some(slot) = CONTENDED_IRQ_LOCK.get(cpu) {
                        slot.store(self as *const Self as *const () as usize, Ordering::Release);
                        marked = true;
                    }
                    run_lock_spin_hook();
                }
            }
        }
        // Only clear the per-CPU contended marker — and pay the `current_cpu()`
        // read it requires (RDTSCP on x86_64) — if this acquire actually set it
        // while spinning. The common uncontended acquire never spun, so it
        // publishes nothing and skips the read entirely. IRQs are masked for the
        // whole of `lock()`, so the CPU cannot change between marking and
        // clearing. An unconditional read here dominated the profile of
        // allocation-heavy workloads, where nearly every lock is uncontended.
        if marked {
            let cpu = crate::percpu::current_cpu();
            if let Some(slot) = CONTENDED_IRQ_LOCK.get(cpu) {
                slot.store(0, Ordering::Release);
            }
        }
        IrqSafeSpinLockGuard {
            lock: &self.inner,
            saved,
            _not_send: core::marker::PhantomData,
        }
    }

    /// Non-blocking acquire. Disables IRQs, attempts the lock exactly
    /// once; on failure restores the caller's IRQ state and returns
    /// `None` instead of spinning with interrupts masked.
    ///
    /// Critical on the work-steal hot path: a blocking `lock()` that
    /// loses the race spins with IRQs disabled, and on x86_64 a CPU with
    /// IRQs masked cannot service an inbound TLB-shootdown IPI — the
    /// shootdown sender then spins to its ack cap (observed: 10M spins
    /// per shootdown, livelocking dynamically-linked user tasks under
    /// `user-task-smp`). `try_lock` keeps the masked window to a single
    /// CAS, so a contended victim queue is skipped rather than spun on.
    #[inline]
    pub fn try_lock(&self) -> Option<IrqSafeSpinLockGuard<'_, T>> {
        // SAFETY: same canonical local IRQ save+disable as `lock`.
        // SAFETY: Valid memory or trusted environment
        let saved = unsafe { irq_save_disable() };
        if self
            .inner
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(IrqSafeSpinLockGuard {
                lock: &self.inner,
                saved,
                _not_send: core::marker::PhantomData,
            })
        } else {
            // SAFETY: pairs with the `irq_save_disable` above; we did not
            // take the lock, so restore the caller's IRQ state.
            // SAFETY: Valid memory or trusted environment
            unsafe { irq_restore(saved) };
            None
        }
    }
}

/// Guard for [`IrqSafeSpinLock`]. Restores the caller's IRQ state on
/// drop and releases the lock.
///
/// **Intentionally `!Send`** — `_not_send` field forces this guard
/// to live entirely on a single thread / CPU and, more importantly,
/// makes any `async fn` that holds it across `.await` itself
/// `!Send`. That breaks `narf_scheduler::spawn<F: Future + Send>`
/// at compile time, so the cursor-pump / driver-async deadlock
/// pattern from the audit (IrqSafeSpinLock guard held across the
/// IRQ wake the future is waiting for) becomes a build error
/// instead of a run-time hang. Use `narf_lib::mutex::Mutex` when
/// you need to hold a lock across `.await`.
pub struct IrqSafeSpinLockGuard<'a, T: ?Sized> {
    lock: &'a SpinLock<T>,
    saved: IrqSavedState,
    /// `*const ()` is `!Send`; the marker propagates that to the
    /// guard so any future capturing the guard becomes `!Send`.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<T: ?Sized> fmt::Debug for IrqSafeSpinLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrqSafeSpinLockGuard")
            .finish_non_exhaustive()
    }
}

impl<T: ?Sized> Deref for IrqSafeSpinLockGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: lock is held exclusively for the lifetime of the guard.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for IrqSafeSpinLockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: lock is held exclusively.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for IrqSafeSpinLockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        // SAFETY: pairs with `irq_save_disable` from the matching lock
        // call; restoring the saved state is always sound.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            irq_restore(self.saved);
        }
    }
}

/// Opaque saved IRQ state — the value stashed by `irq_save_disable`
/// and consumed by `irq_restore`.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(any(test, not(target_os = "none")), allow(dead_code))]
pub struct IrqSavedState(u64);

#[cfg(all(not(test), target_os = "none", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn irq_save_disable() -> IrqSavedState {
    let rflags: u64;
    // SAFETY: pushfq pushes RFLAGS to the stack; cli clears IF. We
    // intentionally do NOT pass `nostack` (pushfq adjusts RSP) or
    // `preserves_flags` (cli mutates IF) — those would license
    // miscompiles like the compiler putting a local in the red zone
    // or caching a flag across the cli.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "pushfq",
            "cli",
            "pop {0}",
            out(reg) rflags,
            options(),
        );
    }
    IrqSavedState(rflags)
}

#[cfg(all(not(test), target_os = "none", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn irq_restore(saved: IrqSavedState) {
    // If the caller had IRQs enabled (bit 9 = IF), re-enable. We avoid
    // a full popfq because we don't want to restore arithmetic flags
    // and risk surprising the surrounding code.
    if saved.0 & (1u64 << 9) != 0 {
        // SAFETY: sti just sets IF. Don't claim `preserves_flags` —
        // sti mutates IF — and don't claim `nomem`, since the
        // moment IF flips, an IRQ handler may run and observe
        // memory.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!("sti", options());
        }
    }
}

#[cfg(all(not(test), target_os = "none", target_arch = "aarch64"))]
#[inline(always)]
unsafe fn irq_save_disable() -> IrqSavedState {
    let daif: u64;
    // SAFETY: read DAIF, then mask I (IRQ). Pure local-CPU state.
    // `nomem` is fine (no memory accesses), but DAIFSet mutates
    // PSTATE — don't claim `preserves_flags`.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "mrs {0}, DAIF",
            "msr DAIFSet, #0x2",
            out(reg) daif,
            options(nostack),
        );
    }
    IrqSavedState(daif)
}

#[cfg(all(not(test), target_os = "none", target_arch = "aarch64"))]
#[inline(always)]
unsafe fn irq_restore(saved: IrqSavedState) {
    // If the caller had IRQs enabled (DAIF.I clear), unmask. We
    // restore only the I bit; touching the full DAIF would risk
    // re-enabling FIQ/SError/D unintentionally.
    if saved.0 & (1u64 << 7) == 0 {
        // SAFETY: clear DAIF.I. PSTATE-mutating, IRQ may fire after.
        unsafe {
            core::arch::asm!("msr DAIFClr, #0x2", options(nostack));
        }
    }
}

// Host builds (`cargo test`, and std tools such as `narf-btrfs-host` that
// link kernel crates as libraries) run in user mode, where `cli`/`msr DAIFSet`
// fault. A host process has no interrupts to mask, so the save/restore pair is
// a no-op there; the spin lock itself still provides mutual exclusion.
#[cfg(any(
    test,
    not(target_os = "none"),
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
#[inline(always)]
unsafe fn irq_save_disable() -> IrqSavedState {
    IrqSavedState(0)
}

// Host builds (`cargo test`, and std tools such as `narf-btrfs-host` that
// link kernel crates as libraries) run in user mode, where `cli`/`msr DAIFSet`
// fault. A host process has no interrupts to mask, so the save/restore pair is
// a no-op there; the spin lock itself still provides mutual exclusion.
#[cfg(any(
    test,
    not(target_os = "none"),
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
#[inline(always)]
unsafe fn irq_restore(_: IrqSavedState) {}

/// Run `f` with maskable interrupts disabled on the current CPU,
/// restoring the caller's prior IRQ state (IF / DAIF.I) afterward.
///
/// Use to protect a **CPU-local** critical section that an IRQ handler
/// on the same CPU could otherwise re-enter — e.g. a per-CPU allocator
/// magazine. This is the non-locking sibling of [`IrqSafeSpinLock`]:
/// same save/disable/restore sequence, no spin-lock. Nests correctly
/// with `IrqSafeSpinLock` (an inner lock's restore returns to "still
/// masked"; this call's restore returns to the original state).
///
/// Bounded, non-blocking work only — never `.await` or spin on another
/// CPU while masked. There is no unwinding in the kernel (panic
/// aborts), so a straight-line restore after `f` is sufficient.
#[inline]
pub fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    // SAFETY: save+disable / restore is the canonical local IRQ mask
    // on each arch; it touches only the running CPU's IF / DAIF.I.
    let saved = unsafe { irq_save_disable() };
    let r = f();
    // SAFETY: pairs with the save above.
    unsafe { irq_restore(saved) };
    r
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for IrqSafeSpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrqSafeSpinLock").finish_non_exhaustive()
    }
}

// ──────────────────────────────────────────────────────────────────
// TicketSpinLock<T> — FIFO-fair spinlock, must be taken with IRQs enabled.
// ──────────────────────────────────────────────────────────────────

/// FIFO-fair spinlock: waiters take monotonically increasing tickets and
/// are served strictly in ticket order, so a waiter can never be overtaken
/// indefinitely by later arrivals (the starvation mode of the plain
/// ticket-free [`SpinLock`]). Must be acquired with IRQs enabled; taking
/// it with IRQs disabled risks deadlock against an IRQ handler that tries
/// the same lock. Use [`IrqSafeTicketSpinLock`] from IRQ-possible contexts.
///
/// Fairness only: this changes *who* acquires the lock next under
/// contention, not how fast the critical section runs. No throughput gain
/// is claimed for it.
///
/// Ticket counters are `usize` and wrap after 2^64 acquisitions; a wrap
/// can only reorder waiters if more than 2^63 tickets are outstanding at
/// once, which cannot happen (outstanding waiters are bounded by the CPU
/// count).
pub struct TicketSpinLock<T: ?Sized> {
    next_ticket: AtomicUsize,
    now_serving: AtomicUsize,
    data: UnsafeCell<T>,
}

// SAFETY: `TicketSpinLock` serialises access to `T`; if `T: Send`, the lock is
// `Send + Sync`. We never construct a `&T` alias while the lock is held.
unsafe impl<T: ?Sized + Send> Send for TicketSpinLock<T> {}
// SAFETY: exclusive access is serialized by the lock; `T: Send` makes sharing the guarded value across tasks sound.
unsafe impl<T: ?Sized + Send> Sync for TicketSpinLock<T> {}

impl<T> TicketSpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            next_ticket: AtomicUsize::new(0),
            now_serving: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> TicketSpinLock<T> {
    /// Raw pointer to the guarded value, without acquiring the lock.
    /// See [`SpinLock::as_ptr`] for the (narrow) supported use.
    #[inline]
    pub const fn as_ptr(&self) -> *mut T {
        self.data.get()
    }

    /// Take the next ticket in line. The caller owns the lock only once
    /// `now_serving` reaches the returned ticket.
    #[inline]
    fn take_ticket(&self) -> usize {
        self.next_ticket.fetch_add(1, Ordering::AcqRel)
    }

    /// Spin until `now_serving` reaches `ticket`. IRQs are enabled here
    /// (this is the [`IrqsEnabled`] variant), so no shootdown drain is
    /// needed — an IPI can be taken while spinning.
    #[inline]
    fn wait_for_ticket(&self, ticket: usize) {
        while self.now_serving.load(Ordering::Acquire) != ticket {
            spin_loop();
        }
    }

    /// Hand the lock to the next ticket holder.
    #[inline]
    fn release_ticket(&self) {
        self.now_serving.fetch_add(1, Ordering::Release);
    }

    /// Take a ticket only if the lock is free *and* nobody is queued
    /// ahead of us. A contended `try_lock` never jumps the queue: if a
    /// waiter already holds a ticket, this returns `false` even when the
    /// current holder releases before we retry.
    fn try_take_ticket(&self) -> bool {
        loop {
            let serving = self.now_serving.load(Ordering::Acquire);
            let next = self.next_ticket.load(Ordering::Relaxed);
            if serving != next {
                return false;
            }
            match self.next_ticket.compare_exchange(
                serving,
                serving.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// Acquire the lock, in ticket order. Caller asserts IRQs are enabled
    /// via the zero-sized witness `IrqsEnabled`.
    #[inline]
    pub fn lock(&self, _: IrqsEnabled) -> TicketSpinLockGuard<'_, T, IrqsEnabled> {
        let ticket = self.take_ticket();
        self.wait_for_ticket(ticket);
        TicketSpinLockGuard {
            lock: self,
            _irq: IrqsEnabled,
        }
    }

    /// Attempt to acquire without blocking and without jumping the queue;
    /// returns `None` on contention.
    #[inline]
    pub fn try_lock(&self, _: IrqsEnabled) -> Option<TicketSpinLockGuard<'_, T, IrqsEnabled>> {
        self.try_take_ticket().then(|| TicketSpinLockGuard {
            lock: self,
            _irq: IrqsEnabled,
        })
    }
}

/// RAII guard for [`TicketSpinLock`]. The `I: IrqState` parameter
/// propagates the IRQ context under which the lock was acquired, exactly
/// as [`SpinLockGuard`] does.
pub struct TicketSpinLockGuard<'a, T: ?Sized, I: IrqState> {
    lock: &'a TicketSpinLock<T>,
    _irq: I,
}

impl<T: ?Sized, I: IrqState> fmt::Debug for TicketSpinLockGuard<'_, T, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketSpinLockGuard")
            .finish_non_exhaustive()
    }
}

// Guards are `!Send`: unlocking must happen on the CPU that locked.
impl<T: ?Sized, I: IrqState> !Send for TicketSpinLockGuard<'_, T, I> {}

impl<T: ?Sized, I: IrqState> Deref for TicketSpinLockGuard<'_, T, I> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: lock is held.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized, I: IrqState> DerefMut for TicketSpinLockGuard<'_, T, I> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: lock is held exclusively.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized, I: IrqState> Drop for TicketSpinLockGuard<'_, T, I> {
    #[inline]
    fn drop(&mut self) {
        self.lock.release_ticket();
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for TicketSpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketSpinLock")
            .field("now_serving", &self.now_serving.load(Ordering::Relaxed))
            .field("next_ticket", &self.next_ticket.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// ──────────────────────────────────────────────────────────────────
// IrqSafeTicketSpinLock<T> — FIFO-fair spinlock that disables IRQs
// across the critical section.
// ──────────────────────────────────────────────────────────────────

/// FIFO-fair variant of [`IrqSafeSpinLock`]: same IRQ save/disable/restore
/// discipline and the same masked-spin shootdown drain, but waiters are
/// served in ticket order instead of racing a test-and-set. The epoll
/// instance locks use this so a `ctl`/`wait` caller cannot be overtaken
/// indefinitely under contention.
///
/// Fairness only — see [`TicketSpinLock`]. This changes acquisition order
/// under contention, not critical-section speed; no throughput gain is
/// claimed.
pub struct IrqSafeTicketSpinLock<T: ?Sized> {
    inner: TicketSpinLock<T>,
}

// SAFETY: exclusive access is serialized by the lock; `T: Send` makes sharing the guarded value across tasks sound.
unsafe impl<T: ?Sized + Send> Send for IrqSafeTicketSpinLock<T> {}
// SAFETY: exclusive access is serialized by the lock; `T: Send` makes sharing the guarded value across tasks sound.
unsafe impl<T: ?Sized + Send> Sync for IrqSafeTicketSpinLock<T> {}

impl<T> IrqSafeTicketSpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            inner: TicketSpinLock::new(data),
        }
    }

    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> IrqSafeTicketSpinLock<T> {
    /// Raw pointer to the guarded value, without acquiring the lock.
    /// See [`SpinLock::as_ptr`] for the (narrow) supported use and the
    /// reason a hard-coded "offset 0 of the lock" is not one.
    #[inline]
    pub const fn as_ptr(&self) -> *mut T {
        self.inner.as_ptr()
    }

    #[inline]
    pub fn lock(&self) -> IrqSafeTicketSpinLockGuard<'_, T> {
        // SAFETY: save+disable inline asm is the canonical local IRQ-
        // disable sequence on each arch; no platform state is touched
        // beyond the IF / DAIF.I bit of the running CPU.
        // SAFETY: Valid memory or trusted environment
        let saved = unsafe { irq_save_disable() };
        let ticket = self.inner.take_ticket();
        // Spin count drives a throttled `run_lock_spin_hook` (every 256 pause
        // iterations): we hold IRQs masked here, so without draining we can't
        // service a peer's TLB-shootdown IPI — see LOCK_SPIN_HOOK. 256 pauses
        // (~µs) is far under a shootdown sender's ack cap, so the peer never
        // stalls, while uncontended locks (no inner spin) pay nothing.
        let mut spins: u32 = 0;
        // Whether this acquire published a contended-lock marker while spinning
        // (see below). Uncontended acquires never do, so they can skip the
        // marker clear — and, crucially, the `current_cpu()` read it needs.
        let mut marked = false;
        while self.inner.now_serving.load(Ordering::Acquire) != ticket {
            spin_loop();
            spins = spins.wrapping_add(1);
            if spins & 0xFF == 0 {
                let cpu = crate::percpu::current_cpu();
                if let Some(slot) = CONTENDED_IRQ_LOCK.get(cpu) {
                    slot.store(self as *const Self as *const () as usize, Ordering::Release);
                    marked = true;
                }
                run_lock_spin_hook();
            }
        }
        // Only clear the per-CPU contended marker — and pay the `current_cpu()`
        // read it requires (RDTSCP on x86_64) — if this acquire actually set it
        // while spinning. The common uncontended acquire never spun, so it
        // publishes nothing and skips the read entirely. IRQs are masked for the
        // whole of `lock()`, so the CPU cannot change between marking and
        // clearing.
        if marked {
            let cpu = crate::percpu::current_cpu();
            if let Some(slot) = CONTENDED_IRQ_LOCK.get(cpu) {
                slot.store(0, Ordering::Release);
            }
        }
        IrqSafeTicketSpinLockGuard {
            lock: &self.inner,
            saved,
            _not_send: core::marker::PhantomData,
        }
    }

    /// Non-blocking acquire. Disables IRQs, attempts the lock exactly
    /// once; on failure restores the caller's IRQ state and returns
    /// `None` instead of spinning with interrupts masked. Like
    /// [`TicketSpinLock::try_lock`], this never jumps the queue: it fails
    /// when a waiter already holds a ticket, even if the lock itself is
    /// momentarily free.
    #[inline]
    pub fn try_lock(&self) -> Option<IrqSafeTicketSpinLockGuard<'_, T>> {
        // SAFETY: same canonical local IRQ save+disable as `lock`.
        // SAFETY: Valid memory or trusted environment
        let saved = unsafe { irq_save_disable() };
        if self.inner.try_take_ticket() {
            Some(IrqSafeTicketSpinLockGuard {
                lock: &self.inner,
                saved,
                _not_send: core::marker::PhantomData,
            })
        } else {
            // SAFETY: pairs with the `irq_save_disable` above; we did not
            // take the lock, so restore the caller's IRQ state.
            // SAFETY: Valid memory or trusted environment
            unsafe { irq_restore(saved) };
            None
        }
    }
}

/// Guard for [`IrqSafeTicketSpinLock`]. Restores the caller's IRQ state on
/// drop and hands the lock to the next ticket holder.
///
/// **Intentionally `!Send`** — see [`IrqSafeSpinLockGuard`].
pub struct IrqSafeTicketSpinLockGuard<'a, T: ?Sized> {
    lock: &'a TicketSpinLock<T>,
    saved: IrqSavedState,
    /// `*const ()` is `!Send`; the marker propagates that to the
    /// guard so any future capturing the guard becomes `!Send`.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<T: ?Sized> fmt::Debug for IrqSafeTicketSpinLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrqSafeTicketSpinLockGuard")
            .finish_non_exhaustive()
    }
}

impl<T: ?Sized> Deref for IrqSafeTicketSpinLockGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: lock is held exclusively for the lifetime of the guard.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for IrqSafeTicketSpinLockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: lock is held exclusively.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for IrqSafeTicketSpinLockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.release_ticket();
        // SAFETY: pairs with the `irq_save_disable` from the matching lock
        // call; restoring the saved state is always sound.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            irq_restore(self.saved);
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for IrqSafeTicketSpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrqSafeTicketSpinLock")
            .finish_non_exhaustive()
    }
}

// ──────────────────────────────────────────────────────────────────
// Once / OnceLock — one-shot initialisation.
// ──────────────────────────────────────────────────────────────────

const ONCE_EMPTY: u8 = 0;
const ONCE_RUNNING: u8 = 1;
const ONCE_DONE: u8 = 2;

/// One-shot "has run" gate. For value storage use `OnceLock<T>`.
pub struct Once {
    state: AtomicU8,
}

impl Once {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(ONCE_EMPTY),
        }
    }

    /// Run `init` exactly once, the first time any caller reaches this call.
    /// Other callers spin until initialisation finishes.
    pub fn call_once<F: FnOnce()>(&self, init: F) {
        match self.state.compare_exchange(
            ONCE_EMPTY,
            ONCE_RUNNING,
            Ordering::Acquire,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                init();
                self.state.store(ONCE_DONE, Ordering::Release);
            }
            Err(ONCE_DONE) => {}
            Err(_) => {
                while self.state.load(Ordering::Acquire) != ONCE_DONE {
                    // Drain shootdowns in case this wait runs masked (the
                    // caller may hold IRQs off) — same reasoning as the
                    // IrqSafeSpinLock busy-wait. Cheap when nothing is pending.
                    run_lock_spin_hook();
                    spin_loop();
                }
            }
        }
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == ONCE_DONE
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Once {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Once")
            .field("completed", &self.is_completed())
            .finish()
    }
}

/// One-shot cell that stores a value after its first successful `set`.
pub struct OnceLock<T> {
    once: Once,
    data: UnsafeCell<core::mem::MaybeUninit<T>>,
}

// SAFETY: `OnceLock` publishes `T` only through `Release`/`Acquire` on
// `Once::state`; subsequent reads observe the initialised value.
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}
// SAFETY: `OnceLock` publishes `T` only after Release/Acquire on `Once::state`;
// `T: Send` makes moving the value to another task sound.
unsafe impl<T: Send> Send for OnceLock<T> {}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            once: Once::new(),
            data: UnsafeCell::new(core::mem::MaybeUninit::uninit()),
        }
    }

    /// Set the value; returns `Err(value)` if already initialised.
    pub fn set(&self, value: T) -> Result<(), T> {
        let mut value = Some(value);
        self.once.call_once(|| {
            // SAFETY: we're inside the `call_once` winning branch, so this
            // is the sole writer; no reader can observe the cell until
            // `call_once` stores ONCE_DONE.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                (*self.data.get()).write(value.take().unwrap());
            }
        });
        match value {
            Some(v) => Err(v),
            None => Ok(()),
        }
    }

    /// Return the value if initialised.
    pub fn get(&self) -> Option<&T> {
        if self.once.is_completed() {
            // SAFETY: `Once::is_completed` does an `Acquire` load; if true,
            // the writer's `Release` of `ONCE_DONE` happens-before this read,
            // so the `MaybeUninit` is initialised and stable.
            // SAFETY: Valid memory or trusted environment
            unsafe { Some((*self.data.get()).assume_init_ref()) }
        } else {
            None
        }
    }

    /// Get the value, initialising it with `init` if empty.
    pub fn get_or_init<F: FnOnce() -> T>(&self, init: F) -> &T {
        if !self.once.is_completed() {
            let _ = self.set(init());
        }
        // SAFETY: `set`/`call_once` guarantees initialisation completed.
        self.get().expect("OnceLock not initialised after set")
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for OnceLock<T> {
    fn drop(&mut self) {
        if self.once.is_completed() {
            // SAFETY: value is initialised and we are the sole owner.
            unsafe {
                (*self.data.get()).assume_init_drop();
            }
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for OnceLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get() {
            Some(v) => f.debug_tuple("OnceLock").field(v).finish(),
            None => f.debug_struct("OnceLock").field("state", &"empty").finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Host tests run under the std test harness; `std` is available here
    // even though this crate is `#![no_std]` (the threaded FIFO test
    // below needs it).
    extern crate std;

    #[test]
    fn spinlock_basic() {
        let l = SpinLock::new(42u32);
        {
            let mut g = l.lock(IrqsEnabled);
            assert_eq!(*g, 42);
            *g = 7;
        }
        assert_eq!(*l.lock(IrqsEnabled), 7);
    }

    #[test]
    fn try_lock_returns_none_when_held() {
        let l = SpinLock::new(0u32);
        let _g = l.lock(IrqsEnabled);
        assert!(l.try_lock(IrqsEnabled).is_none());
    }

    #[test]
    fn irq_safe_spinlock_compiles_without_token() {
        let l = IrqSafeSpinLock::new(0u32);
        let mut g = l.lock();
        *g = 123;
        drop(g);
        assert_eq!(*l.lock(), 123);
    }

    #[test]
    fn ticket_spinlock_basic() {
        let l = TicketSpinLock::new(42u32);
        {
            let mut g = l.lock(IrqsEnabled);
            assert_eq!(*g, 42);
            *g = 7;
        }
        assert_eq!(*l.lock(IrqsEnabled), 7);
    }

    #[test]
    fn ticket_try_lock_returns_none_when_held() {
        let l = TicketSpinLock::new(0u32);
        let _g = l.lock(IrqsEnabled);
        assert!(l.try_lock(IrqsEnabled).is_none());
    }

    #[test]
    fn ticket_try_lock_does_not_jump_queue() {
        // Tickets are handed out in order and served in order: taking two
        // tickets then releasing them advances `now_serving` 0 -> 1 -> 2,
        // and a try-take only succeeds once no ticket is outstanding.
        let l = TicketSpinLock::new(0u32);
        assert_eq!((l.take_ticket(), l.take_ticket()), (0, 1));
        assert!(!l.try_take_ticket());
        l.release_ticket();
        assert!(!l.try_take_ticket()); // second ticket still outstanding
        l.release_ticket();
        assert!(l.try_take_ticket());
        l.release_ticket();
    }

    #[test]
    fn irq_safe_ticket_spinlock_basic() {
        let l = IrqSafeTicketSpinLock::new(0u32);
        {
            let mut g = l.lock();
            *g = 123;
        }
        assert_eq!(*l.lock(), 123);
        assert!(l.try_lock().is_some());
        let _g = l.lock();
        assert!(l.try_lock().is_none());
    }

    #[test]
    fn irq_safe_ticket_spinlock_fifo_under_contention() {
        // Deterministic FIFO check: the main thread holds the lock while N
        // waiter threads take tickets in a fixed order (enforced by
        // observing `next_ticket` before releasing the next waiter), then
        // releases it. A ticket lock must then grant the lock in exactly
        // that order; a ticket-free TAS lock grants it in arrival-race
        // order instead.
        use core::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::Arc;
        use std::thread;

        const N: usize = 8;
        let lock = Arc::new(IrqSafeTicketSpinLock::new(()));
        let go = Arc::new([const { AtomicBool::new(false) }; N]);
        let order = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::new([const { AtomicUsize::new(usize::MAX) }; N]);

        // Hold the lock so every waiter blocks on its ticket.
        let holder = lock.lock();

        let mut handles = std::vec::Vec::new();
        for i in 0..N {
            let l = Arc::clone(&lock);
            let g = Arc::clone(&go);
            let o = Arc::clone(&order);
            let r = Arc::clone(&recorded);
            handles.push(thread::spawn(move || {
                while !g[i].load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                let _guard = l.lock();
                let slot = o.fetch_add(1, Ordering::SeqCst);
                r[slot].store(i, Ordering::Relaxed);
            }));
        }

        // Release waiters one at a time, waiting until each has taken its
        // ticket before releasing the next, so ticket order is exactly
        // 0..N. (This tests module is a child of the parent module, so
        // the private ticket counter is readable here.) The main thread
        // already holds ticket 0, so `next_ticket` starts at 1 and
        // waiter `i` takes ticket `i + 1`; the wait is `<=`, not `==`,
        // because an exact-equality wait can be skipped past if the
        // waiter takes its ticket between two loads.
        for i in 0..N {
            go[i].store(true, Ordering::Release);
            while lock.inner.next_ticket.load(Ordering::Acquire) <= i + 1 {
                std::hint::spin_loop();
            }
        }

        drop(holder);
        for h in handles {
            h.join().expect("waiter thread panicked");
        }
        for (slot, want) in recorded.iter().enumerate() {
            assert_eq!(
                want.load(Ordering::Relaxed),
                slot,
                "ticket lock granted out of order"
            );
        }
    }

    #[test]
    fn once_runs_exactly_once() {
        use core::sync::atomic::AtomicUsize;
        let o = Once::new();
        let n = AtomicUsize::new(0);
        for _ in 0..5 {
            o.call_once(|| {
                n.fetch_add(1, Ordering::Relaxed);
            });
        }
        assert_eq!(n.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn once_lock_set_then_get() {
        let c: OnceLock<u32> = OnceLock::new();
        assert!(c.get().is_none());
        c.set(99).unwrap();
        assert_eq!(c.get(), Some(&99));
        assert!(c.set(1).is_err());
    }

    #[test]
    fn once_lock_get_or_init() {
        let c: OnceLock<u32> = OnceLock::new();
        assert_eq!(*c.get_or_init(|| 3), 3);
        assert_eq!(*c.get_or_init(|| 4), 3); // init not rerun
    }
}
