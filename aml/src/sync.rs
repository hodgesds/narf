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
//! in a single-CPU boot context.  `Sleep`/`Stall` are bounded the
//! same way (SEC-F6, #1301): `Sleep` clamps to `MAX_SLEEP_MS`,
//! `Stall` rejects operands over `MAX_STALL_US` — both mirror
//! ACPICA's `acpi_ex_system_do_sleep` / `acpi_ex_system_do_stall`.

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

/// Unregister a previously registered notify handler.
///
/// Removes the entry for (`target_path`, `handler`); other handlers
/// on the same path and the same handler on other paths are
/// untouched. Returns `true` iff an entry was removed. This is the
/// core-side primitive behind the KABI's
/// `narf_acpi_unregister_notify_handler` (tracker #2448): module
/// notify handlers are unregistered from the exit path and from the
/// loader backstop before the module's text is unmapped.
pub fn unregister_notify_handler(target_path: &str, handler: NotifyHandler) -> bool {
    let mut g = HANDLERS.lock();
    let before = g.len();
    // fn-pointer identity by address: `==` on fn pointers is
    // unpredictable across codegen units (the pinned nightly warns
    // on it), so compare addresses instead.
    g.retain(|e| !(e.path == target_path && core::ptr::fn_addr_eq(e.handler, handler)));
    g.len() != before
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

/// Maximum `Stall` operand in microseconds (SEC-F6, #1301). ACPI 6.2
/// Errata A §19.6.128: "delays longer than 100 microseconds must use
/// Sleep instead of Stall". ACPICA (`acpi_ex_system_do_stall`) allows
/// up to 255 µs for compatibility with existing BIOSes and rejects
/// anything larger with `AE_AML_OPERAND_VALUE`; we mirror that bound
/// and the rejection.
pub const MAX_STALL_US: u64 = 255;

/// Maximum `Sleep` duration in milliseconds (SEC-F6, #1301).
/// ACPICA `ACPI_MAX_SLEEP` (`acconfig.h`: "Maximum sleep allowed via
/// Sleep() operator", 2000 ms == two seconds);
/// `acpi_ex_system_do_sleep` clamps over-long sleeps to it "to
/// prevent accidental deep sleeps". We mirror the clamp.
pub const MAX_SLEEP_MS: u64 = 2000;

/// Clamp a `Sleep` operand to [`MAX_SLEEP_MS`]. Pure, so tests can
/// pin the bound without waiting out a real sleep.
pub(crate) fn clamped_sleep_ms(milliseconds: u64) -> u64 {
    milliseconds.min(MAX_SLEEP_MS)
}

/// Busy-wait for at least `microseconds` microseconds.
/// Treats 1 cycle ≈ 1 ns, so 1 µs ≈ 1 000 cycles.
///
/// Rejects operands over [`MAX_STALL_US`] with
/// [`AmlError::OperandValue`] instead of spinning (SEC-F6, #1301):
/// a `Stall(0xFFFFFFFF)` used to busy-wait ~71 minutes. Mirrors
/// ACPICA `acpi_ex_system_do_stall`, which errors with
/// `AE_AML_OPERAND_VALUE` above 255 µs. The operand is `u64` (the
/// full TermArg) so values over `u32::MAX` are rejected, not
/// truncated to a small stall.
pub fn stall(microseconds: u64) -> Result<(), AmlError> {
    if microseconds > MAX_STALL_US {
        return Err(AmlError::OperandValue);
    }
    let cycles = microseconds.saturating_mul(1_000);
    let deadline = narf_time::now_cycles().saturating_add(cycles);
    while narf_time::now_cycles() < deadline {
        core::hint::spin_loop();
    }
    Ok(())
}

/// Busy-wait for at least `milliseconds` milliseconds.
/// Treats 1 cycle ≈ 1 ns, so 1 ms ≈ 1 000 000 cycles.
///
/// Clamps the operand to [`MAX_SLEEP_MS`] (SEC-F6, #1301): a
/// `Sleep(0xFFFFFFFF)` used to busy-wait ~49.7 days. Mirrors ACPICA
/// `acpi_ex_system_do_sleep`, which clamps to `ACPI_MAX_SLEEP`.
///
/// NOTE: this is still a busy-wait, not a scheduler sleep — Linux
/// implements `Sleep` via `msleep`, and ACPICA releases the
/// interpreter around `acpi_os_sleep`. Converting NARF's `Sleep` to
/// a timer sleep needs an async evaluator (or a `block_on` audit of
/// every evaluation call site, which today includes sync driver
/// paths that cannot block on the executor); that is follow-up work,
/// not part of this cap.
pub fn sleep(milliseconds: u64) {
    let ms = clamped_sleep_ms(milliseconds);
    let cycles = ms.saturating_mul(1_000_000);
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

// ── Tests (SEC-F6, #1301) ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// `Stall` operands over the ACPICA bound are rejected, never spun:
/// `Stall(256)` and anything larger must fail without waiting.
fn sync_stall_rejects_over_cap() -> TestResult {
    if stall(256).is_ok() {
        return TestResult::Fail("stall(256) must be rejected");
    }
    if stall(0xFFFF_FFFF).is_ok() {
        return TestResult::Fail("stall(0xFFFFFFFF) must be rejected");
    }
    if stall(u64::MAX).is_ok() {
        return TestResult::Fail("stall(u64::MAX) must be rejected");
    }
    TestResult::Pass
}
kernel_test_in!("aml/sync", sync_stall_rejects_over_cap);

/// `Stall` operands inside the ACPICA bound still stall: 0, the
/// 100 µs spec max, and the 255 µs compatibility allowance.
fn sync_stall_accepts_spec_range() -> TestResult {
    if stall(0).is_err() {
        return TestResult::Fail("stall(0) must succeed");
    }
    if stall(100).is_err() {
        return TestResult::Fail("stall(100) must succeed");
    }
    if stall(MAX_STALL_US).is_err() {
        return TestResult::Fail("stall(255) must succeed");
    }
    TestResult::Pass
}
kernel_test_in!("aml/sync", sync_stall_accepts_spec_range);

/// The `Sleep` clamp pins the ACPICA bound without waiting: small
/// values pass through, anything over 2000 ms clamps to 2000 ms.
fn sync_sleep_clamp_bound() -> TestResult {
    if clamped_sleep_ms(0) != 0 {
        return TestResult::Fail("clamp(0) must be 0");
    }
    if clamped_sleep_ms(1) != 1 {
        return TestResult::Fail("clamp(1) must be 1");
    }
    if clamped_sleep_ms(MAX_SLEEP_MS) != MAX_SLEEP_MS {
        return TestResult::Fail("clamp(2000) must be 2000");
    }
    if clamped_sleep_ms(2001) != MAX_SLEEP_MS {
        return TestResult::Fail("clamp(2001) must be 2000");
    }
    if clamped_sleep_ms(0xFFFF_FFFF) != MAX_SLEEP_MS {
        return TestResult::Fail("clamp(0xFFFFFFFF) must be 2000");
    }
    if clamped_sleep_ms(u64::MAX) != MAX_SLEEP_MS {
        return TestResult::Fail("clamp(u64::MAX) must be 2000");
    }
    TestResult::Pass
}
kernel_test_in!("aml/sync", sync_sleep_clamp_bound);

/// Notify unregistration removes only the matching (path, handler)
/// pair: other handlers on the same path and the same handler on
/// other paths keep firing. Core-side pin for the KABI's
/// `narf_acpi_unregister_notify_handler` (tracker #2448).
static NOTIFY_UNREG_A_COUNT: AtomicU32 = AtomicU32::new(0);
static NOTIFY_UNREG_B_COUNT: AtomicU32 = AtomicU32::new(0);

fn sync_notify_count_a(_target: &str, _value: u64) {
    NOTIFY_UNREG_A_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn sync_notify_count_b(_target: &str, _value: u64) {
    NOTIFY_UNREG_B_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn sync_notify_unregister_removes_only_matching_handler() -> TestResult {
    __reset_for_test();
    NOTIFY_UNREG_A_COUNT.store(0, Ordering::Relaxed);
    NOTIFY_UNREG_B_COUNT.store(0, Ordering::Relaxed);
    register_notify_handler("/SB.HKEY", sync_notify_count_a);
    register_notify_handler("/SB.HKEY", sync_notify_count_b);
    register_notify_handler("/SB.EC", sync_notify_count_a);
    dispatch_notify("/SB.HKEY", 0x60C0);
    if NOTIFY_UNREG_A_COUNT.load(Ordering::Relaxed) != 1
        || NOTIFY_UNREG_B_COUNT.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("dispatch must call both handlers on the path");
    }
    if !unregister_notify_handler("/SB.HKEY", sync_notify_count_a) {
        return TestResult::Fail("unregister must report a removal");
    }
    if unregister_notify_handler("/SB.HKEY", sync_notify_count_a) {
        return TestResult::Fail("second unregister of the same handler must report nothing");
    }
    dispatch_notify("/SB.HKEY", 0x60C0);
    dispatch_notify("/SB.EC", 0x60C0);
    if NOTIFY_UNREG_A_COUNT.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("A must still fire on /SB.EC after removal from /SB.HKEY");
    }
    if NOTIFY_UNREG_B_COUNT.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("B must still fire on /SB.HKEY after A is removed");
    }
    if unregister_notify_handler("/SB.NOPE", sync_notify_count_a) {
        return TestResult::Fail("unregister on an unknown path must report nothing");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "aml/sync",
    sync_notify_unregister_removes_only_matching_handler
);
