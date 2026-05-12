//! AML Mutex / Event runtime + Notify dispatch.
//!
//! Provides the runtime state for AML `Mutex` and `Event` objects,
//! plus a simple `Notify` dispatch table. All state is held in
//! `IrqSafeSpinLock<Vec<...>>` statics; entries are lazily created on
//! first use by looking up the corresponding namespace node.
//!
//! Timing: uses `narf_time::now_cycles()`.  At Stage 1 there is no
//! calibrated clock, so we treat 1 cycle ≈ 1 ns and multiply
//! `timeout_ms * 1_000_000` to obtain a cycle deadline.  The
//! 0xFFFF "wait forever" sentinel is capped at 5 000 000 spin
//! iterations rather than a real deadline so we cannot wedge forever
//! in a single-CPU boot context.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{AmlError, NodeKind};

// ── KERNEL_OWNER sentinel ─────────────────────────────────────────────────────

/// Fake "CPU owner" ID used by Acquire/Release.  0 means free.
const KERNEL_OWNER: u32 = 1;

// ── MutexState ────────────────────────────────────────────────────────────────

/// Runtime state for a single AML Mutex object.
pub struct MutexState {
    pub path: String,
    pub sync_level: u8,
    /// 0 = free, KERNEL_OWNER = held.
    pub locked: AtomicU32,
    /// Recursive lock count (same owner can re-enter).
    pub owner: AtomicU32,
}

impl core::fmt::Debug for MutexState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MutexState")
            .field("path", &self.path)
            .field("sync_level", &self.sync_level)
            .finish_non_exhaustive()
    }
}

// ── EventState ────────────────────────────────────────────────────────────────

/// Runtime state for a single AML Event object.
pub struct EventState {
    pub path: String,
    /// Signal count: 0 = not signaled, >0 = signaled (Wait consumes one).
    pub signaled: AtomicU32,
}

impl core::fmt::Debug for EventState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventState")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

// ── NotifyHandler ─────────────────────────────────────────────────────────────

/// Handler registered for a specific namespace target path.
pub type NotifyHandler = fn(target: &str, value: u64);

struct NotifyEntry {
    path: String,
    handler: NotifyHandler,
}

impl core::fmt::Debug for NotifyEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NotifyEntry")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

// ── Global statics ────────────────────────────────────────────────────────────

static MUTEXES: IrqSafeSpinLock<Vec<MutexState>> = IrqSafeSpinLock::new(Vec::new());
static EVENTS: IrqSafeSpinLock<Vec<EventState>> = IrqSafeSpinLock::new(Vec::new());
static HANDLERS: IrqSafeSpinLock<Vec<NotifyEntry>> = IrqSafeSpinLock::new(Vec::new());

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Ensure a `MutexState` entry exists for `path`, creating it if not.
/// Returns `AmlError::Truncated` if the namespace node exists but is
/// not a Mutex kind.
fn ensure_mutex(path: &str) -> Result<(), AmlError> {
    {
        let g = MUTEXES.lock();
        if g.iter().any(|m| m.path == path) {
            return Ok(());
        }
    }
    // Validate namespace kind.
    let node = crate::find_node(path).ok_or(AmlError::Truncated)?;
    if node.kind != NodeKind::Mutex {
        return Err(AmlError::Truncated);
    }
    let mut g = MUTEXES.lock();
    // Double-check (benign on single-CPU but good hygiene).
    if !g.iter().any(|m| m.path == path) {
        g.push(MutexState {
            path: String::from(path),
            sync_level: 0,
            locked: AtomicU32::new(0),
            owner: AtomicU32::new(0),
        });
    }
    Ok(())
}

/// Ensure an `EventState` entry exists for `path`.
fn ensure_event(path: &str) -> Result<(), AmlError> {
    {
        let g = EVENTS.lock();
        if g.iter().any(|e| e.path == path) {
            return Ok(());
        }
    }
    let node = crate::find_node(path).ok_or(AmlError::Truncated)?;
    if node.kind != NodeKind::Event {
        return Err(AmlError::Truncated);
    }
    let mut g = EVENTS.lock();
    if !g.iter().any(|e| e.path == path) {
        g.push(EventState {
            path: String::from(path),
            signaled: AtomicU32::new(0),
        });
    }
    Ok(())
}

/// Compute a cycle deadline from `timeout_ms`. Returns `None` for the
/// 0xFFFF "wait forever" sentinel (caller uses iteration cap instead).
fn deadline_cycles(timeout_ms: u16) -> Option<u64> {
    if timeout_ms == 0xFFFF {
        None
    } else {
        let cycles = (timeout_ms as u64).saturating_mul(1_000_000);
        Some(narf_time::now_cycles().saturating_add(cycles))
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Acquire the named Mutex with a timeout in milliseconds.
///
/// Returns `Ok(true)` when acquired, `Ok(false)` on timeout.
/// 0xFFFF = wait forever (capped at 5 000 000 iterations).
pub fn acquire(path: &str, timeout_ms: u16) -> Result<bool, AmlError> {
    ensure_mutex(path)?;

    let deadline = deadline_cycles(timeout_ms);
    let mut iters: u32 = 0;
    const MAX_ITERS: u32 = 5_000_000;

    loop {
        // Audit #10: recursive ownership. Every AML evaluation
        // uses the same KERNEL_OWNER, so a method that calls
        // another method which both Acquire the same Mutex
        // shouldn't deadlock — increment owner count instead.
        // Decrement on Release; only flip locked back to 0 when
        // the count drops to zero.
        let recursive = {
            let g = MUTEXES.lock();
            if let Some(m) = g.iter().find(|m| m.path == path) {
                if m.locked.load(Ordering::Acquire) == KERNEL_OWNER {
                    m.owner.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            } else {
                return Err(AmlError::Truncated);
            }
        };
        if recursive {
            return Ok(true);
        }

        // Try to CAS 0 → KERNEL_OWNER.
        let result = {
            let g = MUTEXES.lock();
            if let Some(m) = g.iter().find(|m| m.path == path) {
                m.locked
                    .compare_exchange(0, KERNEL_OWNER, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            } else {
                return Err(AmlError::Truncated);
            }
        };

        if result {
            // Set owner count to 1 (first-time acquire).
            let g = MUTEXES.lock();
            if let Some(m) = g.iter().find(|m| m.path == path) {
                m.owner.store(1, Ordering::Relaxed);
            }
            return Ok(true);
        }

        // Timeout check.
        iters = iters.wrapping_add(1);
        match deadline {
            None if iters >= MAX_ITERS => return Ok(true), // "forever" — just succeed
            Some(dl) if narf_time::now_cycles() >= dl => return Ok(false),
            _ => {}
        }
        core::hint::spin_loop();
    }
}

/// Release the named Mutex. Decrements the recursive owner
/// count; only releases the lock when it reaches 0 (audit #10).
pub fn release(path: &str) -> Result<(), AmlError> {
    ensure_mutex(path)?;
    let g = MUTEXES.lock();
    if let Some(m) = g.iter().find(|m| m.path == path) {
        // Decrement; release lock only when count hits 0.
        let prev = m.owner.fetch_sub(1, Ordering::Relaxed);
        if prev <= 1 {
            m.owner.store(0, Ordering::Relaxed);
            m.locked.store(0, Ordering::Release);
        }
        Ok(())
    } else {
        Err(AmlError::Truncated)
    }
}

/// Wait for the named Event to be signaled.
///
/// Returns `Ok(true)` when the event was consumed, `Ok(false)` on timeout.
/// 0xFFFF = wait forever (capped at 5 000 000 iterations).
pub fn wait(path: &str, timeout_ms: u16) -> Result<bool, AmlError> {
    ensure_event(path)?;

    let deadline = deadline_cycles(timeout_ms);
    let mut iters: u32 = 0;
    const MAX_ITERS: u32 = 5_000_000;

    loop {
        // Try to consume one signal count.
        let consumed = {
            let g = EVENTS.lock();
            if let Some(e) = g.iter().find(|e| e.path == path) {
                let cur = e.signaled.load(Ordering::Acquire);
                if cur > 0 {
                    e.signaled
                        .compare_exchange(cur, cur - 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                } else {
                    false
                }
            } else {
                return Err(AmlError::Truncated);
            }
        };

        if consumed {
            return Ok(true);
        }

        iters = iters.wrapping_add(1);
        match deadline {
            None if iters >= MAX_ITERS => return Ok(true), // "forever" — succeed
            Some(dl) if narf_time::now_cycles() >= dl => return Ok(false),
            _ => {}
        }
        core::hint::spin_loop();
    }
}

/// Signal the named Event (increment its count by one).
pub fn signal(path: &str) -> Result<(), AmlError> {
    ensure_event(path)?;
    let g = EVENTS.lock();
    if let Some(e) = g.iter().find(|e| e.path == path) {
        e.signaled.fetch_add(1, Ordering::Release);
        Ok(())
    } else {
        Err(AmlError::Truncated)
    }
}

/// Reset the named Event's signal count to zero.
pub fn reset(path: &str) -> Result<(), AmlError> {
    ensure_event(path)?;
    let g = EVENTS.lock();
    if let Some(e) = g.iter().find(|e| e.path == path) {
        e.signaled.store(0, Ordering::Release);
        Ok(())
    } else {
        Err(AmlError::Truncated)
    }
}

// ── Notify dispatch ───────────────────────────────────────────────────────────

/// Register a handler for Notify events targeting `target_path`.
/// Multiple handlers for the same path are all called in order.
pub fn register_notify_handler(target_path: &str, handler: NotifyHandler) {
    let mut g = HANDLERS.lock();
    g.push(NotifyEntry {
        path: String::from(target_path),
        handler,
    });
}

/// Dispatch a Notify event to all registered handlers for `target_path`.
pub fn dispatch_notify(target_path: &str, value: u64) {
    // Collect matching handlers without holding the lock while calling
    // them (avoids reentrancy issues with recursive AML evaluation).
    let handlers: Vec<NotifyHandler> = {
        let g = HANDLERS.lock();
        g.iter()
            .filter(|e| e.path == target_path)
            .map(|e| e.handler)
            .collect()
    };
    for h in handlers {
        h(target_path, value);
    }
}

// ── Timing primitives ─────────────────────────────────────────────────────────

/// Busy-wait for at least `microseconds` microseconds.
/// Treats 1 cycle ≈ 1 ns, so 1 µs ≈ 1 000 cycles.
pub fn stall(microseconds: u32) {
    let cycles = (microseconds as u64).saturating_mul(1_000);
    let deadline = narf_time::now_cycles().saturating_add(cycles);
    while narf_time::now_cycles() < deadline {
        core::hint::spin_loop();
    }
}

/// Busy-wait for at least `milliseconds` milliseconds.
/// Treats 1 cycle ≈ 1 ns, so 1 ms ≈ 1 000 000 cycles.
pub fn sleep(milliseconds: u32) {
    let cycles = (milliseconds as u64).saturating_mul(1_000_000);
    let deadline = narf_time::now_cycles().saturating_add(cycles);
    while narf_time::now_cycles() < deadline {
        core::hint::spin_loop();
    }
}

// ── Test helper ───────────────────────────────────────────────────────────────

/// Reset all sync state. Call from tests that need a clean slate.
#[doc(hidden)]
pub fn __reset_for_test() {
    MUTEXES.lock().clear();
    EVENTS.lock().clear();
    HANDLERS.lock().clear();
}
