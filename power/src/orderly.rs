//! Orderly power-off from contexts that must not power off themselves —
//! Linux `kernel/reboot.c::orderly_poweroff` / `hw_protection_shutdown`.
//!
//! Linux never powers the machine off from the code that noticed the reason:
//! the ACPI power button only reports `KEY_POWER` (`acpi_button_notify`) and
//! logind decides; a thermal trip calls `orderly_poweroff(force)` /
//! `hw_protection_shutdown`, which queue `poweroff_work` so the shutdown runs
//! from a workqueue (task context), first trying the userspace `poweroff`
//! helper and, if that fails and `force` is set, falling back to
//! `emergency_sync()` + `kernel_power_off()`. `hw_protection_shutdown`
//! additionally arms `hw_failure_emergency_poweroff(ms)`: if nothing has
//! powered the machine off when the delay expires, it is forced.
//!
//! NARF has no usermode helper, so the worker here is that forced fallback,
//! made orderly: sync every mounted filesystem (bounded), then
//! [`crate::system::power_off_synced`], which still runs the device shutdown
//! hooks (NVMe Flush + CC.SHN). [`orderly_poweroff`] only records the request
//! and wakes the worker, so it is safe from interrupt context and from under
//! IRQ-disabling spinlocks.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

/// Why an orderly power-off was requested.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OrderlyReason {
    /// ACPI power button pressed with no userspace consumer of `KEY_POWER`.
    PowerButton,
    /// A hardware-protection trip (critical temperature).
    HwProtection,
    /// `reboot()` / `power_off()` was called from interrupt context, which
    /// is refused and turned into this request.
    IrqContextRequest,
}

impl OrderlyReason {
    fn encode(self) -> u8 {
        match self {
            OrderlyReason::PowerButton => 1,
            OrderlyReason::HwProtection => 2,
            OrderlyReason::IrqContextRequest => 3,
        }
    }

    fn decode(v: u8) -> Option<Self> {
        match v {
            1 => Some(OrderlyReason::PowerButton),
            2 => Some(OrderlyReason::HwProtection),
            3 => Some(OrderlyReason::IrqContextRequest),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            OrderlyReason::PowerButton => "power button",
            OrderlyReason::HwProtection => "hardware protection",
            OrderlyReason::IrqContextRequest => "power-off requested from interrupt context",
        }
    }
}

/// Bound on the filesystem sync when the requester gave none. A sync that
/// has not finished by then is abandoned with a loud log and the device
/// shutdown hooks run anyway (NVMe CC.SHN still commits the drive's cache).
pub const DEFAULT_SYNC_BUDGET_MS: u64 = 60_000;

/// Pending request (`OrderlyReason::encode`), 0 = none.
static REQUEST: AtomicU8 = AtomicU8::new(0);
/// Sync budget for the pending request, ms (0 = [`DEFAULT_SYNC_BUDGET_MS`]).
/// A later request can only shorten it.
static BUDGET_MS: AtomicU64 = AtomicU64::new(0);
/// The worker's waker, parked while no request is pending.
static WAKER: IrqSafeSpinLock<Option<Waker>> = IrqSafeSpinLock::new(None);
static WORKER_SPAWNED: AtomicBool = AtomicBool::new(false);
/// Test-only: while set, the worker does not act on a pending request, so a
/// model test can raise one without powering the test machine off.
static HOLD: AtomicBool = AtomicBool::new(false);

/// Request an orderly power-off: record `reason` (the first one wins) and
/// the sync budget, then wake the worker. Returns `true` when this call made
/// the request, `false` when one was already pending.
///
/// Safe from any context, including interrupt handlers: no allocation, no
/// sleeping, one IRQ-safe lock for the waker. If the worker is not running
/// yet (early boot) the request waits for it.
pub fn orderly_poweroff(reason: OrderlyReason, sync_budget_ms: Option<u64>) -> bool {
    if let Some(ms) = sync_budget_ms {
        let ms = ms.max(1);
        let _ = BUDGET_MS.fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
            (cur == 0 || ms < cur).then_some(ms)
        });
    }
    let first = REQUEST
        .compare_exchange(0, reason.encode(), Ordering::AcqRel, Ordering::Acquire)
        .is_ok();
    let waker = WAKER.lock().take();
    if let Some(w) = waker {
        if narf_lib::context::in_irq() {
            // Never run the wake (and its Arc traffic) inside the IRQ.
            narf_lib::deferred_wake::push_pending(core::iter::once(Some(w)));
        } else {
            w.wake();
        }
    }
    first
}

/// The pending request, if any.
pub fn pending() -> Option<OrderlyReason> {
    OrderlyReason::decode(REQUEST.load(Ordering::Acquire))
}

/// Sync budget the worker would use for the pending request.
pub fn sync_budget_ms() -> u64 {
    match BUDGET_MS.load(Ordering::Acquire) {
        0 => DEFAULT_SYNC_BUDGET_MS,
        ms => ms,
    }
}

/// Clear any pending request. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    REQUEST.store(0, Ordering::Release);
    BUDGET_MS.store(0, Ordering::Release);
}

/// Hold (or release) the worker. Test-only; see [`HOLD`].
#[doc(hidden)]
pub fn __hold_worker_for_test(hold: bool) {
    HOLD.store(hold, Ordering::Release);
}

/// Resolves once a request is pending.
#[derive(Debug)]
struct RequestPending;

impl Future for RequestPending {
    type Output = OrderlyReason;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<OrderlyReason> {
        let ready = || pending().filter(|_| !HOLD.load(Ordering::Acquire));
        if let Some(r) = ready() {
            return Poll::Ready(r);
        }
        *WAKER.lock() = Some(cx.waker().clone());
        // Re-check after publishing the waker: a request that landed between
        // the first check and the store would otherwise sleep forever.
        match ready() {
            Some(r) => Poll::Ready(r),
            None => Poll::Pending,
        }
    }
}

/// Spawn the worker task (idempotent). Called from a Stage::Late initcall,
/// once the executor runs.
pub fn start_worker() {
    if WORKER_SPAWNED.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_scheduler::spawn(async {
        let reason = RequestPending.await;
        run(reason).await;
    });
}

/// The worker body after a request: sync (bounded), then power off.
async fn run(reason: OrderlyReason) {
    use core::fmt::Write as _;
    let budget = sync_budget_ms();
    let _ = writeln!(
        narf_console::Writer,
        "power: orderly power-off ({}): syncing filesystems (budget {} ms)",
        reason.as_str(),
        budget
    );
    let deadline = narf_time::Deadline::after_ms(budget);
    match narf_time::timeout(deadline, narf_filesystem::sync_all::sync_all()).await {
        Ok(r) => {
            let _ = writeln!(
                narf_console::Writer,
                "power: synced {} filesystem(s) ({} failed), flushed {} disk(s) ({} failed)",
                r.filesystems,
                r.fs_errors,
                r.disks_flushed,
                r.flush_errors
            );
        }
        Err(_) => {
            let _ = writeln!(
                narf_console::Writer,
                "power: WARNING: filesystem sync did not finish in {budget} ms; \
                 powering off anyway (device shutdown still flushes the disks)"
            );
        }
    }
    crate::system::power_off_synced();
}

/// Linux `hw_protection_shutdown(reason, ms_until_forced)`: request an
/// orderly power-off whose filesystem sync gets at most `ms_until_forced`,
/// and — when called from task context — arm an independent timer that
/// forces the power-off if no transition has started `ms_until_forced`
/// later still (Linux `hw_failure_emergency_poweroff`): the worker may be
/// starved, or stuck in a filesystem that never yields. The forced path
/// skips the filesystem sync but still runs the device shutdown hooks.
///
/// Returns immediately; never powers off from the caller's own frame.
pub fn hw_protection_shutdown(reason: &str, ms_until_forced: u64) {
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "power: hardware protection shutdown ({reason})"
    );
    orderly_poweroff(OrderlyReason::HwProtection, Some(ms_until_forced));
    if narf_lib::context::in_irq() {
        // No allocation from an IRQ; the worker's own sync bound applies.
        return;
    }
    static FORCED_ARMED: AtomicBool = AtomicBool::new(false);
    if FORCED_ARMED.swap(true, Ordering::AcqRel) {
        return;
    }
    let delay = ms_until_forced.saturating_mul(2).max(1_000);
    narf_scheduler::spawn(async move {
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(delay).as_instant()).await;
        if crate::system::transition_started() {
            return;
        }
        let _ = writeln!(
            narf_console::Writer,
            "power: EMERGENCY: orderly power-off did not start within {delay} ms; forcing power-off"
        );
        crate::system::power_off_synced();
    });
}
