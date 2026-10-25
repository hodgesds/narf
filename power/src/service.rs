//! Power service — the event → policy → action actor for laptop power.
//!
//! The pieces this module connects already exist, but until now nothing
//! connected them:
//!
//! - **Event sources** — the platform lid driver (`drivers/platform/lid`)
//!   and button driver (`drivers/platform/buttons`) expose subscriber
//!   APIs over EC / AML Notify events. Their only subscribers were tests.
//! - **The suspend core** — [`crate::suspend`] implements the full S3
//!   sequence, but `suspend()` / `s3_enter()` had no caller outside
//!   tests: no trigger ever fired.
//! - **The fused snapshot** — [`crate::laptop_state::LaptopStateSnapshot`]
//!   documents "the power service" draining button counters and gating
//!   suspend-on-close policy. No such service existed, and the snapshot
//!   was never produced in production.
//!
//! This module is that service. It owns:
//!
//! - **Event intake** ([`on_lid_changed`], [`on_power_button_press`],
//!   [`on_sleep_button_press`], [`on_ac_changed`]) — IRQ-safe, no AML
//!   evaluation, no allocation beyond a waker clone on the wake edge.
//! - **Policy** ([`PowerPolicy`]) — what an event means: suspend on lid
//!   close, what the sleep / power buttons request, whether a critical
//!   battery raises the warning hook. Configuration is cap-gated on
//!   `Cap<Power, Grant>`, matching this crate's other registries.
//! - **Action queue + worker** — intake only *records* a
//!   [`PowerAction`] and wakes the worker (the [`crate::orderly`]
//!   pattern); the worker executes from task context via
//!   [`pump_pending`]. Duplicate requests coalesce: a second suspend
//!   request while one is pending is the same request.
//! - **Snapshot production** ([`snapshot`]) — fuses the registered
//!   [`StateProviders`] (with event-cached AC / lid state as fallback),
//!   drains the button counters, and edge-triggers the critical-battery
//!   warning.
//!
//! **Capability discipline:** the service holds no `Cap`. Executing an
//! action is delegated to an installed [`ActionExecutor`] whose owner
//! holds whatever authority execution needs (the platform composition
//! mints the suspend `Cap<Power, Invoke>` at its call site). The
//! existing production-S3 gate in [`crate::suspend`] still decides
//! whether a suspend request actually sleeps the machine — the service
//! requests; it cannot arm.

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};

use narf_acpi::ac_adapter::AcAdapterState;
use narf_acpi::battery::{BatteryInfo, BatteryState};
use narf_acpi::lid::LidState;
use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::laptop_state::LaptopStateSnapshot;
use crate::{Power, PowerError};

// ── Actions ─────────────────────────────────────────────────────────

/// A system power action the service can request. Requests are queued
/// as bits and coalesce; execution is the installed
/// [`ActionExecutor`]'s job, from task context.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerAction {
    /// Enter system sleep via the suspend core ([`crate::suspend`]).
    Suspend,
    /// Orderly power-off (filesystem sync, then device shutdown).
    PowerOff,
}

impl PowerAction {
    fn bit(self) -> u8 {
        match self {
            PowerAction::Suspend => 1 << 0,
            PowerAction::PowerOff => 1 << 1,
        }
    }

    /// Deterministic execution order when both are pending: suspend
    /// first (a power-off request that lands during suspend wins on
    /// the next pump, after resume).
    const ORDER: [PowerAction; 2] = [PowerAction::Suspend, PowerAction::PowerOff];
}

/// What a button press requests. The power button defaults to
/// [`ButtonAction::Ignore`] because it is already owned by
/// [`crate::button`] (KEY_POWER to userspace, orderly power-off when
/// nobody listens); the service counts those presses for the snapshot
/// and only requests an action when a deployment re-policies it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ButtonAction {
    /// Count the press; request nothing.
    Ignore,
    /// Request [`PowerAction::Suspend`].
    Suspend,
    /// Request [`PowerAction::PowerOff`].
    PowerOff,
}

impl ButtonAction {
    fn action(self) -> Option<PowerAction> {
        match self {
            ButtonAction::Ignore => None,
            ButtonAction::Suspend => Some(PowerAction::Suspend),
            ButtonAction::PowerOff => Some(PowerAction::PowerOff),
        }
    }
}

// ── Policy ──────────────────────────────────────────────────────────

/// Event → action policy for the power service. Installed with
/// [`set_policy`] (cap-gated); read with [`policy`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PowerPolicy {
    /// A lid-close event requests [`PowerAction::Suspend`].
    pub suspend_on_lid_close: bool,
    /// What a sleep-button press requests. The sleep button exists
    /// to sleep the machine, so this defaults to
    /// [`ButtonAction::Suspend`].
    pub sleep_button: ButtonAction,
    /// What a power-button press requests *in addition* to the
    /// KEY_POWER / orderly handling in [`crate::button`]. Defaults
    /// to [`ButtonAction::Ignore`] so the two paths never double-act.
    pub power_button: ButtonAction,
    /// A snapshot that observes "critical battery, AC offline" (see
    /// [`LaptopStateSnapshot::is_running_low_on_battery`]) fires the
    /// warning hook, once per transition into that state.
    pub warn_on_critical_battery: bool,
}

impl Default for PowerPolicy {
    fn default() -> Self {
        PowerPolicy {
            suspend_on_lid_close: true,
            sleep_button: ButtonAction::Suspend,
            power_button: ButtonAction::Ignore,
            warn_on_critical_battery: true,
        }
    }
}

// ── Executor + hooks ────────────────────────────────────────────────

/// Executes a requested [`PowerAction`] from task context. Installed
/// by the composition root (the platform layer) with
/// [`install_action_executor`]; the implementor owns the authority
/// execution needs. Called by [`pump_pending`] with no service lock
/// held; implementations may block (the suspend core does).
pub trait ActionExecutor: Send + Sync {
    fn execute(&self, action: PowerAction);
}

/// Battery provider (`_BIF` + `_BST`): the static info and the
/// dynamic state, polled as a pair.
pub type BatteryProvider = Arc<dyn Fn() -> Option<(BatteryInfo, BatteryState)> + Send + Sync>;

/// Providers for the fused [`LaptopStateSnapshot`]. Each is polled by
/// [`snapshot`]; providers may evaluate AML (battery `_BIF`/`_BST`,
/// AC `_PSR`) and are therefore **never called under the service
/// lock**. A provider returning `None` leaves the field unknown —
/// desktops without a battery or lid register nothing and get an
/// all-`None` snapshot. Registration merges: a later
/// [`register_state_providers`] replaces only the fields it sets.
#[derive(Clone, Default)]
pub struct StateProviders {
    /// AC adapter state (`_PSR`).
    pub ac_adapter: Option<Arc<dyn Fn() -> Option<AcAdapterState> + Send + Sync>>,
    /// Lid state (`_LID`).
    pub lid: Option<Arc<dyn Fn() -> Option<LidState> + Send + Sync>>,
    /// Battery static info + dynamic state (`_BIF` + `_BST`).
    pub battery: Option<BatteryProvider>,
    /// CPU package temperature, milli-degrees Celsius.
    pub cpu_temp_mc: Option<Arc<dyn Fn() -> Option<i32> + Send + Sync>>,
    /// GPU package temperature, milli-degrees Celsius.
    pub gpu_temp_mc: Option<Arc<dyn Fn() -> Option<i32> + Send + Sync>>,
}

impl core::fmt::Debug for StateProviders {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateProviders")
            .field("ac_adapter", &self.ac_adapter.is_some())
            .field("lid", &self.lid.is_some())
            .field("battery", &self.battery.is_some())
            .field("cpu_temp_mc", &self.cpu_temp_mc.is_some())
            .field("gpu_temp_mc", &self.gpu_temp_mc.is_some())
            .finish()
    }
}

// ── Stats ───────────────────────────────────────────────────────────

/// Counters for diagnostics and tests. `*_requests` count queued
/// requests (coalesced duplicates included — they measure demand,
/// not executions); `actions_executed` counts executor invocations.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceStats {
    pub lid_closes: u64,
    pub lid_opens: u64,
    pub power_presses: u64,
    pub sleep_presses: u64,
    pub suspend_requests: u64,
    pub poweroff_requests: u64,
    pub actions_executed: u64,
    pub warnings_fired: u64,
}

// ── State ───────────────────────────────────────────────────────────

#[derive(Default)]
struct ServiceState {
    policy: PowerPolicy,
    executor: Option<Arc<dyn ActionExecutor>>,
    warning_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    providers: StateProviders,
    /// Last AC state seen via [`on_ac_changed`] (fallback when no
    /// provider is registered or it returns `None`).
    cached_ac: Option<AcAdapterState>,
    /// Last lid state seen via [`on_lid_changed`] (same fallback role).
    cached_lid: Option<LidState>,
    /// Press counters not yet drained by [`snapshot`].
    power_presses_undrained: u64,
    sleep_presses_undrained: u64,
    /// Edge latch for the critical-battery warning.
    low_battery_alerted: bool,
    stats: ServiceStats,
}

static STATE: IrqSafeSpinLock<ServiceState> = IrqSafeSpinLock::new(ServiceState {
    policy: PowerPolicy {
        suspend_on_lid_close: true,
        sleep_button: ButtonAction::Suspend,
        power_button: ButtonAction::Ignore,
        warn_on_critical_battery: true,
    },
    executor: None,
    warning_hook: None,
    providers: StateProviders {
        ac_adapter: None,
        lid: None,
        battery: None,
        cpu_temp_mc: None,
        gpu_temp_mc: None,
    },
    cached_ac: None,
    cached_lid: None,
    power_presses_undrained: 0,
    sleep_presses_undrained: 0,
    low_battery_alerted: false,
    stats: ServiceStats {
        lid_closes: 0,
        lid_opens: 0,
        power_presses: 0,
        sleep_presses: 0,
        suspend_requests: 0,
        poweroff_requests: 0,
        actions_executed: 0,
        warnings_fired: 0,
    },
});

/// Pending action bits ([`PowerAction::bit`]). Set by intake, drained
/// by [`pump_pending`]. Atomic (not under `STATE`) so IRQ-context
/// intake never contends on the state lock for the queue itself.
static PENDING: AtomicU8 = AtomicU8::new(0);

/// The worker's waker, parked while nothing executable is pending.
static WAKER: IrqSafeSpinLock<Option<Waker>> = IrqSafeSpinLock::new(None);

static WORKER_SPAWNED: AtomicBool = AtomicBool::new(false);

// ── Configuration (cap-gated) ───────────────────────────────────────

/// Replace the active policy. Cap-gated on `Cap<Power, Grant>`, like
/// this crate's other registries.
pub fn set_policy(cap: &Cap<Power, Grant>, policy: PowerPolicy) -> Result<(), PowerError> {
    cap.check_live()?;
    STATE.lock().policy = policy;
    Ok(())
}

/// The active policy.
pub fn policy() -> PowerPolicy {
    STATE.lock().policy
}

/// Install the action executor (replacing any previous one). The
/// executor owns the authority its actions need; installing one is
/// therefore cap-gated on `Cap<Power, Grant>`.
pub fn install_action_executor(
    cap: &Cap<Power, Grant>,
    executor: Arc<dyn ActionExecutor>,
) -> Result<(), PowerError> {
    cap.check_live()?;
    STATE.lock().executor = Some(executor);
    // An executor arriving after requests were queued makes them
    // executable — wake the worker so they are not stranded.
    wake_worker();
    Ok(())
}

/// Install the critical-battery warning hook (replacing any previous
/// one). The hook fires from [`snapshot`] evaluation, in the
/// caller's context, with no service lock held; it must be cheap and
/// non-blocking (log, set a flag, post to a queue).
pub fn install_warning_hook(
    cap: &Cap<Power, Grant>,
    hook: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), PowerError> {
    cap.check_live()?;
    STATE.lock().warning_hook = Some(hook);
    Ok(())
}

/// Merge `providers` into the registered set: each `Some` field
/// replaces the previous provider for that source, `None` fields
/// leave existing providers in place. Cap-gated on
/// `Cap<Power, Grant>`.
pub fn register_state_providers(
    cap: &Cap<Power, Grant>,
    providers: StateProviders,
) -> Result<(), PowerError> {
    cap.check_live()?;
    let mut state = STATE.lock();
    if providers.ac_adapter.is_some() {
        state.providers.ac_adapter = providers.ac_adapter;
    }
    if providers.lid.is_some() {
        state.providers.lid = providers.lid;
    }
    if providers.battery.is_some() {
        state.providers.battery = providers.battery;
    }
    if providers.cpu_temp_mc.is_some() {
        state.providers.cpu_temp_mc = providers.cpu_temp_mc;
    }
    if providers.gpu_temp_mc.is_some() {
        state.providers.gpu_temp_mc = providers.gpu_temp_mc;
    }
    Ok(())
}

// ── Event intake ────────────────────────────────────────────────────

/// Record a lid transition and apply policy. Called by the platform
/// lid driver's event feed; IRQ-safe (one short lock, no AML, no
/// allocation on the common path).
pub fn on_lid_changed(closed: bool) {
    let action = {
        let mut state = STATE.lock();
        state.cached_lid = Some(if closed {
            LidState::Closed
        } else {
            LidState::Open
        });
        if closed {
            state.stats.lid_closes += 1;
            state
                .policy
                .suspend_on_lid_close
                .then_some(PowerAction::Suspend)
        } else {
            state.stats.lid_opens += 1;
            None
        }
    };
    if let Some(action) = action {
        request_action(action);
    }
}

/// Record an AC adapter state change (cached for the snapshot
/// fallback). No policy attaches to AC transitions today; the
/// critical-battery warning reads AC state via the snapshot.
pub fn on_ac_changed(state: AcAdapterState) {
    STATE.lock().cached_ac = Some(state);
}

/// Record a power-button press. Counted for the snapshot; requests
/// the policy's `power_button` action (default: none — see
/// [`ButtonAction`] docs for why [`crate::button`] owns this key).
pub fn on_power_button_press() {
    let action = {
        let mut state = STATE.lock();
        state.stats.power_presses += 1;
        state.power_presses_undrained += 1;
        state.policy.power_button.action()
    };
    if let Some(action) = action {
        request_action(action);
    }
}

/// Record a sleep-button press. Counted for the snapshot; requests
/// the policy's `sleep_button` action (default: suspend).
pub fn on_sleep_button_press() {
    let action = {
        let mut state = STATE.lock();
        state.stats.sleep_presses += 1;
        state.sleep_presses_undrained += 1;
        state.policy.sleep_button.action()
    };
    if let Some(action) = action {
        request_action(action);
    }
}

// ── Action queue ────────────────────────────────────────────────────

/// Queue an action directly, bypassing event policy. The request is
/// still executor-mediated: it executes from task context via
/// [`pump_pending`] / the worker, and the suspend core's own gates
/// still apply. Safe from any context, including interrupt handlers.
pub fn request_action(action: PowerAction) {
    {
        let mut state = STATE.lock();
        match action {
            PowerAction::Suspend => state.stats.suspend_requests += 1,
            PowerAction::PowerOff => state.stats.poweroff_requests += 1,
        }
    }
    PENDING.fetch_or(action.bit(), Ordering::AcqRel);
    wake_worker();
}

/// The pending action bitmask (bits per [`PowerAction::bit`]).
/// Mostly for tests and diagnostics.
pub fn pending_actions() -> u8 {
    PENDING.load(Ordering::Acquire)
}

/// Execute every pending action through the installed executor, in
/// [`PowerAction::ORDER`] order, returning how many ran. Called by
/// the worker; also directly callable from task context (tests,
/// a future synchronous caller).
///
/// With no executor installed the queue is left untouched and 0 is
/// returned — requests are never silently dropped; they execute
/// when an executor arrives.
pub fn pump_pending() -> u32 {
    let executor = STATE.lock().executor.clone();
    let Some(executor) = executor else {
        return 0;
    };
    let bits = PENDING.swap(0, Ordering::AcqRel);
    let mut ran = 0;
    for action in PowerAction::ORDER {
        if bits & action.bit() != 0 {
            executor.execute(action);
            ran += 1;
        }
    }
    if ran > 0 {
        STATE.lock().stats.actions_executed += ran as u64;
    }
    ran
}

/// Wake the worker if it is parked. Mirrors [`crate::orderly`]: the
/// wake is deferred out of IRQ context so no Arc traffic runs inside
/// an interrupt handler.
fn wake_worker() {
    let waker = WAKER.lock().take();
    if let Some(w) = waker {
        if narf_lib::context::in_irq() {
            narf_lib::deferred_wake::push_pending(core::iter::once(Some(w)));
        } else {
            w.wake();
        }
    }
}

/// Resolves once an action is pending *and* an executor is installed
/// (pending bits without an executor are not executable, so the
/// worker keeps sleeping until [`install_action_executor`] wakes it).
#[derive(Debug)]
struct ActionPending;

impl Future for ActionPending {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let ready = || PENDING.load(Ordering::Acquire) != 0 && STATE.lock().executor.is_some();
        if ready() {
            return Poll::Ready(());
        }
        *WAKER.lock() = Some(cx.waker().clone());
        // Re-check after publishing the waker: a request that landed
        // between the first check and the store would otherwise
        // sleep forever.
        if ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Spawn the service worker (idempotent). Called from a Stage::Late
/// initcall, once the executor runs. The worker pumps the action
/// queue from task context for the life of the system.
pub fn start_worker() {
    if WORKER_SPAWNED.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_scheduler::spawn(async {
        loop {
            ActionPending.await;
            while pump_pending() > 0 {}
        }
    });
}

// ── Snapshot production ─────────────────────────────────────────────

/// Produce the fused laptop power-state snapshot. Providers are
/// invoked with no service lock held (they may evaluate AML); the
/// button counters are drained into the snapshot (a press is
/// reported by exactly one snapshot, matching
/// [`LaptopStateSnapshot`]'s "since the last drain" contract).
///
/// Side effect, by design: if the fused state is "critical battery,
/// AC offline" and policy enables it, the warning hook fires —
/// once per transition into that state, not per snapshot.
pub fn snapshot() -> LaptopStateSnapshot {
    let (providers, cached_ac, cached_lid) = {
        let state = STATE.lock();
        (state.providers.clone(), state.cached_ac, state.cached_lid)
    };

    // Poll providers in the service's fixed order (ac, lid, battery,
    // cpu, gpu) into locals, then build the snapshot in one literal.
    let ac_adapter = providers
        .ac_adapter
        .as_ref()
        .and_then(|p| p())
        .or(cached_ac);
    let lid = providers.lid.as_ref().and_then(|p| p()).or(cached_lid);
    let (battery_info, battery_state) = match providers.battery.as_ref().and_then(|p| p()) {
        Some((info, state)) => (Some(info), Some(state)),
        None => (None, None),
    };
    let cpu_tdie_mc = providers.cpu_temp_mc.as_ref().and_then(|p| p());
    let gpu_temp_mc = providers.gpu_temp_mc.as_ref().and_then(|p| p());
    let mut snap = LaptopStateSnapshot {
        ac_adapter,
        lid,
        battery_info,
        battery_state,
        cpu_tdie_mc,
        gpu_temp_mc,
        ..Default::default()
    };

    let warning_hook = {
        let mut state = STATE.lock();
        // Drain: presses are human-scale; saturate at u8::MAX rather
        // than wrap if a snapshot was somehow delayed for 256+
        // presses.
        snap.power_button_presses =
            core::mem::take(&mut state.power_presses_undrained).min(u8::MAX as u64) as u8;
        snap.sleep_button_presses =
            core::mem::take(&mut state.sleep_presses_undrained).min(u8::MAX as u64) as u8;

        let low = snap.is_running_low_on_battery();
        let fire = low && !state.low_battery_alerted && state.policy.warn_on_critical_battery;
        state.low_battery_alerted = low;
        if fire {
            state.stats.warnings_fired += 1;
            state.warning_hook.clone()
        } else {
            None
        }
    };
    if let Some(hook) = warning_hook {
        hook();
    }
    snap
}

/// Counters snapshot for diagnostics and tests.
pub fn stats() -> ServiceStats {
    STATE.lock().stats
}

/// Test-only reset: default policy, no executor / hook / providers,
/// empty caches and counters, no pending actions. The worker, once
/// spawned, is process-global and is not un-spawned.
#[doc(hidden)]
pub fn __reset_for_test() {
    *STATE.lock() = ServiceState::default();
    PENDING.store(0, Ordering::Release);
}
