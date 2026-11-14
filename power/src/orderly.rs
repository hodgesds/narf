//! Orderly power-off — Linux `kernel/reboot.c::orderly_poweroff` /
//! `__hw_protection_trigger`.
//!
//! Linux never powers the machine off from the code that noticed the reason.
//! `orderly_poweroff(force)` (callable from any context) only queues
//! `poweroff_work`; the work runs `__orderly_poweroff(force)`, which starts
//! the userspace `kernel.poweroff_cmd` (default `/sbin/poweroff`) as a
//! usermode helper with `UMH_WAIT_EXEC`. When the helper starts, userspace
//! (systemd) owns the shutdown: it stops services, syncs, unmounts / remounts
//! read-only and finally calls `reboot(LINUX_REBOOT_CMD_POWER_OFF)`. Only if
//! the helper could not be started and `force` is set does the kernel take
//! over: `emergency_sync()` then `kernel_power_off()`.
//! `__hw_protection_trigger` (thermal trips) additionally arms
//! `hw_failure_emergency_action_work`: if the machine is still up
//! `ms_until_forced` later, `kernel_power_off()` (no sync) is forced.
//!
//! NARF mirrors that:
//!
//! - [`orderly_poweroff`] records the request and wakes the worker; it is
//!   safe from interrupt context and from under IRQ-disabling spinlocks.
//! - The worker ([`start_worker`]) runs the command through the usermode
//!   helper the userspace layer installs ([`install_usermode_helper`]).
//! - The forced fallback ([`emergency_sync`] + [`crate::system::power_off`])
//!   runs only when the helper failed and the request was forced. NARF's
//!   emergency sync is bounded and finishes BEFORE the device shutdown hooks
//!   run, where Linux's `emergency_sync()` only queues `do_sync_work` and
//!   `kernel_power_off()` proceeds concurrently with it — a deliberate
//!   strengthening: a filesystem commit that lands after NVMe CC.SHN never
//!   reaches the media. Like Linux, the forced path neither freezes nor kills
//!   user tasks; I/O already in flight when the device shutdown starts is
//!   drained by the driver (NVMe waits `NVME_IO_TIMEOUT` for it, as
//!   `nvme_dev_disable(shutdown = true)` does).

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use narf_filesystem::sync_all::SyncReport;
use narf_lib::sync::IrqSafeSpinLock;

/// Why an orderly power-off was requested.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OrderlyReason {
    /// ACPI power button pressed with no userspace consumer of `KEY_POWER`.
    PowerButton,
    /// A hardware-protection trip (critical temperature).
    HwProtection,
    /// `reboot()` / `power_off()` was called from interrupt context, which
    /// is refused and turned into this request. The worker runs the kernel
    /// power-off the caller asked for — no helper, no sync, as
    /// `kernel_power_off` itself does neither.
    IrqContextRequest,
    /// The power service's policy requested a power-off (e.g. a
    /// re-policied button action); executed by the service's action
    /// executor in task context.
    PowerService,
}

impl OrderlyReason {
    fn encode(self) -> u8 {
        match self {
            OrderlyReason::PowerButton => 1,
            OrderlyReason::HwProtection => 2,
            OrderlyReason::IrqContextRequest => 3,
            OrderlyReason::PowerService => 4,
        }
    }

    fn decode(v: u8) -> Option<Self> {
        match v {
            1 => Some(OrderlyReason::PowerButton),
            2 => Some(OrderlyReason::HwProtection),
            3 => Some(OrderlyReason::IrqContextRequest),
            4 => Some(OrderlyReason::PowerService),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            OrderlyReason::PowerButton => "power button",
            OrderlyReason::HwProtection => "hardware protection",
            OrderlyReason::IrqContextRequest => "power-off requested from interrupt context",
            OrderlyReason::PowerService => "power service request",
        }
    }
}

/// Bound on the forced fallback's [`emergency_sync`]. Linux's
/// `emergency_sync` is unbounded but asynchronous (the power-off does not
/// wait for it); NARF waits for it, so it must be bounded: a sync that has
/// not finished by then is abandoned with a loud log and the device shutdown
/// hooks run anyway (NVMe CC.SHN still commits the drive's cache).
pub const EMERGENCY_SYNC_BUDGET_MS: u64 = 60_000;

/// Pending request (`OrderlyReason::encode`), 0 = none.
static REQUEST: AtomicU8 = AtomicU8::new(0);
/// Linux `poweroff_force`: sticky once any request asked for it, so a later
/// unforced request never clears a pending forced one.
static FORCE: AtomicBool = AtomicBool::new(false);
/// The worker's waker, parked while no request is pending.
static WAKER: IrqSafeSpinLock<Option<Waker>> = IrqSafeSpinLock::new(None);
static WORKER_SPAWNED: AtomicBool = AtomicBool::new(false);
/// Test-only: while set, the worker and the emergency watchdog do not act,
/// so a model test can raise a request without powering the test machine
/// off.
static HOLD: AtomicBool = AtomicBool::new(false);

/// Linux `orderly_poweroff(force)`: record `reason` (the first pending one
/// wins) and `force`, then wake the worker. Returns `true` when this call
/// made the request, `false` when one was already pending (Linux
/// `schedule_work` on a pending work is a no-op too).
///
/// Safe from any context, including interrupt handlers: no allocation, no
/// sleeping, one IRQ-safe lock for the waker. If the worker is not running
/// yet (early boot) the request waits for it.
pub fn orderly_poweroff(reason: OrderlyReason, force: bool) -> bool {
    if force {
        // "do not override the pending "true"".
        FORCE.store(true, Ordering::Release);
    }
    let first = REQUEST
        .compare_exchange(0, reason.encode(), Ordering::AcqRel, Ordering::Acquire)
        .is_ok();
    wake(&WAKER);
    first
}

fn wake(slot: &IrqSafeSpinLock<Option<Waker>>) {
    let waker = slot.lock().take();
    if let Some(w) = waker {
        if narf_lib::context::in_irq() {
            // Never run the wake (and its Arc traffic) inside the IRQ.
            narf_lib::deferred_wake::push_pending(core::iter::once(Some(w)));
        } else {
            w.wake();
        }
    }
}

/// The pending request, if any.
pub fn pending() -> Option<OrderlyReason> {
    OrderlyReason::decode(REQUEST.load(Ordering::Acquire))
}

/// Whether the pending request is forced.
pub fn pending_forced() -> bool {
    FORCE.load(Ordering::Acquire)
}

/// Take the pending request: its reason and whether it is forced.
pub(crate) fn take_request() -> Option<(OrderlyReason, bool)> {
    let force = FORCE.swap(false, Ordering::AcqRel);
    match OrderlyReason::decode(REQUEST.swap(0, Ordering::AcqRel)) {
        Some(r) => Some((r, force)),
        None => {
            if force {
                FORCE.store(true, Ordering::Release);
            }
            None
        }
    }
}

/// Clear any pending request and the hardware-protection latch. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    REQUEST.store(0, Ordering::Release);
    FORCE.store(false, Ordering::Release);
    HW_PROTECTION_TRIGGERED.store(false, Ordering::Release);
    EMERGENCY_DELAY_MS.store(0, Ordering::Release);
}

/// Hold (or release) the worker and the emergency watchdog. Test-only; see
/// [`HOLD`].
#[doc(hidden)]
pub fn __hold_worker_for_test(hold: bool) {
    HOLD.store(hold, Ordering::Release);
}

/// Resolves once a request is pending.
#[derive(Debug)]
struct RequestPending;

impl Future for RequestPending {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let ready = || pending().is_some() && !HOLD.load(Ordering::Acquire);
        if ready() {
            return Poll::Ready(());
        }
        *WAKER.lock() = Some(cx.waker().clone());
        // Re-check after publishing the waker: a request that landed between
        // the first check and the store would otherwise sleep forever.
        if ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Spawn the worker and the hardware-protection watchdog (idempotent).
/// Called from a Stage::Late initcall, once the executor runs.
pub fn start_worker() {
    if WORKER_SPAWNED.swap(true, Ordering::AcqRel) {
        return;
    }
    // Linux `poweroff_work`: one request at a time, and a request after a
    // helper that started (a second button press while systemd is already
    // shutting down) runs the command again.
    narf_scheduler::spawn(async {
        loop {
            RequestPending.await;
            let Some((reason, force)) = take_request() else {
                continue;
            };
            let _ = orderly_poweroff_work(
                reason,
                force,
                run_poweroff_cmd,
                emergency_sync,
                kernel_power_off,
            )
            .await;
        }
    });
    narf_scheduler::spawn(hw_failure_emergency_watchdog());
}

// ── Usermode helper (Linux `call_usermodehelper(.., UMH_WAIT_EXEC)`) ──

/// Start `argv[0]` as a user process with `argv` / `envp` and return once
/// it has been exec'd (Linux `UMH_WAIT_EXEC`): `Ok` when the program is
/// running, `Err(errno)` when it could not be started. Installed by
/// `narf_userspace`, which owns process creation.
pub type UsermodeHelper = fn(argv: &[&str], envp: &[&str]) -> Result<(), i32>;

static USERMODE_HELPER: AtomicUsize = AtomicUsize::new(0);

/// Install the usermode helper. Idempotent.
pub fn install_usermode_helper(helper: UsermodeHelper) {
    USERMODE_HELPER.store(helper as usize, Ordering::Release);
}

/// Swap the helper, returning the old one. Test-only.
#[doc(hidden)]
pub fn __swap_usermode_helper_for_test(helper: Option<UsermodeHelper>) -> Option<UsermodeHelper> {
    let old = USERMODE_HELPER.swap(helper.map_or(0, |h| h as usize), Ordering::AcqRel);
    // SAFETY: only `UsermodeHelper` pointers (or 0) are stored.
    (old != 0).then(|| unsafe { core::mem::transmute::<usize, UsermodeHelper>(old) })
}

fn usermode_helper() -> Option<UsermodeHelper> {
    let raw = USERMODE_HELPER.load(Ordering::Acquire);
    // SAFETY: only `UsermodeHelper` pointers (or 0) are stored.
    (raw != 0).then(|| unsafe { core::mem::transmute::<usize, UsermodeHelper>(raw) })
}

/// The helper's environment (`kernel/reboot.c::run_cmd`).
pub const HELPER_ENVP: [&str; 2] = ["HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin"];

/// `ENOENT`: what the helper reports for a missing program.
const ENOENT: i32 = 2;

/// Linux `run_cmd(cmd)`: `argv_split` on whitespace, then the usermode
/// helper with [`HELPER_ENVP`]. An empty command has no program (`ENOENT`,
/// as `call_usermodehelper_exec` with a NULL path reports); no helper
/// installed (no userspace layer) reports the same.
pub fn run_cmd(cmd: &str) -> Result<(), i32> {
    let argv: Vec<&str> = cmd.split_ascii_whitespace().collect();
    if argv.is_empty() {
        return Err(ENOENT);
    }
    match usermode_helper() {
        Some(helper) => helper(&argv, &HELPER_ENVP),
        None => Err(ENOENT),
    }
}

/// `run_cmd(poweroff_cmd)`, reading the live `kernel.poweroff_cmd`.
pub(crate) fn run_poweroff_cmd() -> Result<(), i32> {
    let cmd: String = narf_filesystem::procfs::sys_kernel::poweroff_cmd();
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "power: running '{cmd}'");
    run_cmd(&cmd)
}

// ── The work ───────────────────────────────────────────────────────

/// What one orderly power-off request did (the worker's return value; the
/// forced path does not return in production).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OrderlyOutcome {
    /// The poweroff command was started: userspace now owns the shutdown.
    HelperStarted,
    /// The command could not be started and the request was not forced:
    /// nothing more happens (Linux `__orderly_poweroff(false)`).
    HelperFailed(i32),
    /// The command could not be started and the request was forced: the
    /// emergency sync ran, then the kernel power-off.
    Forced(i32),
    /// An interrupt-context `power_off()`: the kernel power-off ran.
    KernelPowerOff,
}

/// Linux `__orderly_poweroff(force)`, with the three steps it takes passed
/// in so a model test can run it without powering the machine off: `run`
/// starts the poweroff command, `sync` is the emergency sync, `power_off`
/// the kernel power-off (in production [`crate::system::power_off`], which
/// does not return).
pub(crate) async fn orderly_poweroff_work<S, F>(
    reason: OrderlyReason,
    force: bool,
    run: impl FnOnce() -> Result<(), i32>,
    sync: S,
    power_off: impl FnOnce(),
) -> OrderlyOutcome
where
    S: FnOnce() -> F,
    F: Future<Output = ()>,
{
    use core::fmt::Write as _;
    if reason == OrderlyReason::IrqContextRequest {
        power_off();
        return OrderlyOutcome::KernelPowerOff;
    }
    let _ = writeln!(
        narf_console::Writer,
        "power: orderly power-off ({})",
        reason.as_str()
    );
    let err = match run() {
        Ok(()) => return OrderlyOutcome::HelperStarted,
        Err(e) => e,
    };
    if !force {
        let _ = writeln!(
            narf_console::Writer,
            "power: failed to start orderly shutdown (errno {err}); not forced, nothing more to do"
        );
        return OrderlyOutcome::HelperFailed(err);
    }
    let _ = writeln!(
        narf_console::Writer,
        "power: failed to start orderly shutdown (errno {err}): forcing the issue"
    );
    sync().await;
    power_off();
    OrderlyOutcome::Forced(err)
}

/// The forced fallback's kernel power-off (Linux `kernel_power_off`).
fn kernel_power_off() {
    crate::system::power_off();
}

// ── Emergency sync (Linux `fs/sync.c::emergency_sync`) ────────────

/// Writes back the file data that lives only in the kernel's own caches
/// above the filesystems — dirty `MAP_SHARED` pages — so that a filesystem
/// sync after it covers it. Installed by `narf_userspace`, which owns that
/// cache.
pub type MappedPageSync = fn() -> Pin<alloc::boxed::Box<dyn Future<Output = ()> + Send>>;

static MAPPED_PAGE_SYNC: AtomicUsize = AtomicUsize::new(0);

/// Install the [`MappedPageSync`] hook. Idempotent.
pub fn install_mapped_page_sync(hook: MappedPageSync) {
    MAPPED_PAGE_SYNC.store(hook as usize, Ordering::Release);
}

/// Swap the hook, returning the old one. Test-only.
#[doc(hidden)]
pub fn __swap_mapped_page_sync_for_test(hook: Option<MappedPageSync>) -> Option<MappedPageSync> {
    let old = MAPPED_PAGE_SYNC.swap(hook.map_or(0, |h| h as usize), Ordering::AcqRel);
    // SAFETY: only `MappedPageSync` pointers (or 0) are stored.
    (old != 0).then(|| unsafe { core::mem::transmute::<usize, MappedPageSync>(old) })
}

fn mapped_page_sync() -> Option<MappedPageSync> {
    let raw = MAPPED_PAGE_SYNC.load(Ordering::Acquire);
    // SAFETY: only `MappedPageSync` pointers (or 0) are stored.
    (raw != 0).then(|| unsafe { core::mem::transmute::<usize, MappedPageSync>(raw) })
}

/// The emergency sync's write-back: first the mapped pages (the hook), then
/// `filesystems` — the order of Linux's `do_sync_work`, which writes the
/// inodes' pages before `sync_fs`. Both are bounded together by `deadline`:
/// a device that stops answering must not keep a forced power-off from
/// happening. Returns `None` when the deadline cut it short.
pub(crate) async fn shutdown_sync<F: Future>(
    deadline: narf_time::Deadline,
    filesystems: F,
) -> Option<F::Output> {
    let hook = mapped_page_sync();
    narf_time::timeout(deadline, async move {
        if let Some(hook) = hook {
            hook().await;
        }
        filesystems.await
    })
    .await
    .ok()
}

/// The console line for a finished sync. Counts what actually succeeded: a
/// filesystem whose `syncfs` failed (an aborted btrfs) is reported as failed,
/// never as synced.
pub fn sync_report_line(r: &SyncReport) -> String {
    alloc::format!(
        "power: synced {} of {} filesystem(s) ({} failed), flushed {} of {} disk(s) ({} failed)",
        r.filesystems.saturating_sub(r.fs_errors),
        r.filesystems,
        r.fs_errors,
        r.disks_flushed.saturating_sub(r.flush_errors),
        r.disks_flushed,
        r.flush_errors
    )
}

/// Linux `emergency_sync()`: write back what can still be written — mapped
/// pages, then every mounted filesystem's `syncfs`, then a flush per disk —
/// bounded by [`EMERGENCY_SYNC_BUDGET_MS`].
pub async fn emergency_sync() {
    use core::fmt::Write as _;
    let deadline = narf_time::Deadline::after_ms(EMERGENCY_SYNC_BUDGET_MS);
    match shutdown_sync(deadline, narf_filesystem::sync_all::sync_all()).await {
        Some(r) => {
            let _ = writeln!(narf_console::Writer, "{}", sync_report_line(&r));
            let _ = writeln!(narf_console::Writer, "power: emergency sync complete");
        }
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "power: WARNING: emergency sync did not finish in {EMERGENCY_SYNC_BUDGET_MS} ms; \
                 powering off anyway (device shutdown still flushes the disks)"
            );
        }
    }
}

// ── Hardware protection (Linux `__hw_protection_trigger`) ──────────

/// Linux `__hw_protection_trigger`'s `allow_proceed`: a protection shutdown
/// is initiated once.
static HW_PROTECTION_TRIGGERED: AtomicBool = AtomicBool::new(false);
/// Armed delay of `hw_failure_emergency_action_work`, ms (0 = unarmed).
static EMERGENCY_DELAY_MS: AtomicU64 = AtomicU64::new(0);
static EMERGENCY_WAKER: IrqSafeSpinLock<Option<Waker>> = IrqSafeSpinLock::new(None);

/// Resolves to the armed delay once the watchdog has been armed.
#[derive(Debug)]
struct EmergencyArmed;

impl Future for EmergencyArmed {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
        let ready = || match EMERGENCY_DELAY_MS.load(Ordering::Acquire) {
            0 => None,
            ms => Some(ms),
        };
        if let Some(ms) = ready() {
            return Poll::Ready(ms);
        }
        *EMERGENCY_WAKER.lock() = Some(cx.waker().clone());
        match ready() {
            Some(ms) => Poll::Ready(ms),
            None => Poll::Pending,
        }
    }
}

/// Linux `hw_failure_emergency_action_func`: `ms_until_forced` after a
/// protection trip, if the machine is still up — the helper hung, or
/// userspace's shutdown is stuck — force `kernel_power_off()`. Like Linux it
/// does not sync. Spawned once by [`start_worker`], so arming it needs no
/// allocation and works from interrupt context.
async fn hw_failure_emergency_watchdog() {
    use core::fmt::Write as _;
    let delay = loop {
        let delay = EmergencyArmed.await;
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(delay).as_instant()).await;
        // Disarmed meanwhile (a model test's reset), or held: wait again.
        if EMERGENCY_DELAY_MS.load(Ordering::Acquire) == 0 || HOLD.load(Ordering::Acquire) {
            EMERGENCY_DELAY_MS.store(0, Ordering::Release);
            continue;
        }
        break delay;
    };
    if crate::system::transition_started() {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "power: EMERGENCY: hardware protection timed out after {delay} ms; trying forced shutdown"
    );
    kernel_power_off();
}

/// Linux `hw_protection_shutdown(reason, ms_until_forced)`
/// (`__hw_protection_trigger(.., HWPROT_ACT_SHUTDOWN)`): once per boot, arm
/// the forced power-off for `ms_until_forced` later (0 = never) and request a
/// forced orderly power-off — the poweroff command, or, if it cannot be
/// started, the emergency sync and the kernel power-off.
///
/// Returns immediately; never powers off from the caller's own frame. Safe
/// from interrupt context.
///
/// LINUX-GAP: the `hw_protection=reboot` action (`orderly_reboot`) is not
/// implemented; the protection action is always a shutdown.
pub fn hw_protection_shutdown(reason: &str, ms_until_forced: u64) {
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "power: HARDWARE PROTECTION shutdown ({reason})"
    );
    // "Shutdown should be initiated only once."
    if HW_PROTECTION_TRIGGERED.swap(true, Ordering::AcqRel) {
        return;
    }
    if ms_until_forced > 0 {
        EMERGENCY_DELAY_MS.store(ms_until_forced, Ordering::Release);
        wake(&EMERGENCY_WAKER);
    }
    orderly_poweroff(OrderlyReason::HwProtection, true);
}

/// The armed emergency delay (0 = unarmed). Test-only.
#[doc(hidden)]
pub fn __emergency_delay_ms_for_test() -> u64 {
    EMERGENCY_DELAY_MS.load(Ordering::Acquire)
}
