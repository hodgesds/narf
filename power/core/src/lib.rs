//! CPU idle governors and hardware entry.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
extern crate alloc;
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::Ordering;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

pub mod executor;
mod tests;
pub use executor::{IdleContext, IdleDecision, IdleEntry, IdleHints, IdlePlan, IdleState};
#[cfg(target_arch = "x86_64")]
pub mod x86;

// ── PowerError ──────────────────────────────────────────────────────

/// Errors returned by the cap-gated entry points. `From<CapError>`
/// collapses every cap failure to `AuthorityRevoked` because Stage-3
/// only checks one thing on the authority cap (its epoch); a richer
/// mapping lands when the registry grows additional cap-gated ops.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerError {
    /// The authority cap has been revoked (epoch mismatch).
    AuthorityRevoked,
    /// Tried to register a C-state with an `id` that already exists.
    DuplicateCState,
    /// `select_idle_state` could not find a state matching the deadline
    /// constraint — should be impossible after `init()` registers C0.
    NoMatchingState,
    /// Asked for the active governor before any was installed. The
    /// default `Performance` governor is set up at `init()`, so this
    /// only fires if a caller jumps the gun.
    GovernorMissing,
}

impl From<CapError> for PowerError {
    fn from(_: CapError) -> Self {
        PowerError::AuthorityRevoked
    }
}

/// Authority to install governors / register C-states / register runtime
/// PM devices. The actual rights split is `Grant`; see `install_governor`
/// et al for the receivers.
#[derive(Copy, Clone, Debug)]
pub struct Power;
impl CapType for Power {
    const KIND: CapKind = CapKind::Power;
}

/// Authority to install a CPU idle governor.
#[derive(Copy, Clone, Debug)]
pub struct IdleGov;
impl CapType for IdleGov {
    const KIND: CapKind = CapKind::IdleGovernor;
}

// ── C-state ─────────────────────────────────────────────────────────

/// Registered CPU idle state and entry callback.
#[derive(Copy, Clone)]
pub struct CState {
    /// 0 = C0 (running), 1+ = progressively deeper idle states.
    pub id: u8,
    /// Worst-case wake latency in microseconds. The idle governor uses
    /// this against the next-tick deadline to bound its choice.
    pub exit_latency_us: u32,
    /// Typical power draw in milliwatts while parked in this state.
    /// Lower is deeper. Stage-3 doesn't act on this beyond ordering;
    /// `EnergyAware` (Stage 4) will.
    pub power_draw_mw: u32,
    /// Minimum residency (microseconds) for entering this state to
    /// "pay back" the wake-up cost. The `MenuGovernor` refuses to
    /// pick a state whose `target_residency_us` exceeds the predicted
    /// idle duration. Stage-3 default `LinearScan` ignores this.
    pub target_residency_us: u32,
    /// Entry must accept and return with IRQs masked, preserving pending
    /// interrupt wakeups. No lock may be held across hardware idle.
    pub entry: fn(),
}

impl core::fmt::Debug for CState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CState")
            .field("id", &self.id)
            .field("exit_latency_us", &self.exit_latency_us)
            .field("power_draw_mw", &self.power_draw_mw)
            .field("target_residency_us", &self.target_residency_us)
            .finish_non_exhaustive()
    }
}

// ── C-state registry ────────────────────────────────────────────────

static CSTATES: IrqSafeSpinLock<Vec<CState>> = IrqSafeSpinLock::new(Vec::new());

/// Register a C-state with the global table. Cap-gated on
/// `Cap<Power, Grant>`. Returns `Err(DuplicateCState)` if a state with
/// the same `id` is already registered.
pub fn register_cstate(cap: &Cap<Power, Grant>, state: CState) -> Result<(), PowerError> {
    cap.check_live()?;
    let mut t = CSTATES.lock();
    if t.iter().any(|s| s.id == state.id) {
        return Err(PowerError::DuplicateCState);
    }
    t.push(state);
    // Keep ascending by id so `select_idle_state` can scan from the
    // back to find the deepest fit in O(n).
    t.sort_by_key(|s| s.id);
    executor::STATE_GENERATION.fetch_add(1, Ordering::Release);
    Ok(())
}

/// Number of registered C-states. Mostly for tests.
pub fn cstate_count() -> usize {
    CSTATES.lock().len()
}

/// Snapshot the registered C-state set. Returned vec is owned so the
/// caller doesn't hold the lock across other power calls.
pub fn cstates() -> Vec<CState> {
    CSTATES.lock().clone()
}

// ── Default C-state entries ─────────────────────────────────────────

/// C0: running. Entry is a no-op — the CPU is by definition awake.
fn cstate_c0_entry() { /* never parked here */
}

/// C1: shallow idle. On x86_64 this is `HLT`; on aarch64 `WFI`. The
/// arch wrapper picks correctly based on `cfg`.
fn cstate_c1_entry() {
    // SAFETY: C-state entry requires IRQs masked and a completed wake check.
    unsafe { narf_arch::idle_halt_then_disable() };
}

/// Compatibility budget for the no-argument registry selector. Executor idle
/// passes actual deadlines through `IdleHints`.
const LEGACY_SELECT_BUDGET_US: u32 = 1_000;

/// Wrapper around a chosen C-state `id`. The pluggable `IdleGovernor`
/// returns one of these; the free `select_idle_state` then resolves it
/// against the live `CSTATES` table to hand back a full `CState`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CStateIdx(pub u8);

/// Pluggable idle-state selection policy. Mirrors `GovernorPolicy`
/// exactly — `name()` for tooling, `select_idle_state` for the hot
/// path. The installed impl reads the live C-state registry; the free
/// `select_idle_state` below dispatches through whatever is in the
/// `IDLE_GOVERNOR` slot.
///
/// `latency_budget_us` bounds the worst-case wake latency the caller
/// is willing to tolerate (e.g. next-tick deadline). `predicted_idle_us`
/// is the caller's best guess at how long the CPU will actually idle
/// before the next wake event — the `MenuGovernor` keys off this to
/// refuse states whose `target_residency_us` exceeds it.
pub trait IdleGovernor: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn select_idle_state(&self, latency_budget_us: u64, predicted_idle_us: u64) -> CStateIdx;

    /// Select from this CPU's validated state table. Called outside task
    /// polls; implementations must not block or reenter idle selection.
    fn select(&self, context: &IdleContext, _states: &[IdleState]) -> IdleDecision {
        IdleDecision {
            state: self.select_idle_state(context.latency_limit_us, context.predicted_idle_us),
            stop_tick: true,
        }
    }

    /// Actual residency after wakeup. Must not block or reenter idle selection.
    fn reflect(&self, _cpu: usize, _state: CStateIdx, _residency_us: u64) {}
}

/// Stage-3 default. Scan ascending-by-id, keep the deepest state whose
/// `exit_latency_us` is <= the latency budget. Ignores predicted idle
/// time; this is the algorithm the inline `select_idle_state` used
/// before the trait was extracted.
#[derive(Copy, Clone, Debug, Default)]
pub struct LinearScan;
impl IdleGovernor for LinearScan {
    fn name(&self) -> &'static str {
        "linear-scan"
    }
    fn select(&self, context: &IdleContext, states: &[IdleState]) -> IdleDecision {
        choose_state(context, states, false)
    }
    fn select_idle_state(&self, latency_budget_us: u64, _predicted_idle_us: u64) -> CStateIdx {
        let t = CSTATES.lock();
        let mut best: u8 = 0;
        for s in t.iter() {
            if (s.exit_latency_us as u64) <= latency_budget_us {
                best = s.id;
            }
        }
        CStateIdx(best)
    }
}

/// Tiny Linux-`menu`-style heuristic. If the predicted idle time is
/// shorter than the shallowest non-C0 state's `target_residency_us`,
/// pick C0; otherwise pick the deepest state whose `exit_latency_us`
/// fits the budget AND whose `target_residency_us` is still shorter
/// than the prediction. Distinct from `LinearScan` because the
/// `target_residency_us` filter rejects "too deep for too short an
/// idle" picks, which is the whole point of the real menu governor.
#[derive(Copy, Clone, Debug, Default)]
pub struct MenuGovernor;
impl IdleGovernor for MenuGovernor {
    fn name(&self) -> &'static str {
        "menu"
    }
    fn select(&self, context: &IdleContext, states: &[IdleState]) -> IdleDecision {
        choose_state(context, states, true)
    }
    fn select_idle_state(&self, latency_budget_us: u64, predicted_idle_us: u64) -> CStateIdx {
        let t = CSTATES.lock();
        // Find the shallowest non-C0 state (smallest id > 0). If
        // predicted idle is shorter than its target residency, the
        // wake-up cost won't be paid back; stay in C0.
        let shallow_target = t
            .iter()
            .filter(|s| s.id != 0)
            .map(|s| s.target_residency_us as u64)
            .min();
        if let Some(min_residency) = shallow_target {
            if predicted_idle_us < min_residency {
                return CStateIdx(0);
            }
        } else {
            // Only C0 registered; nothing else to pick.
            return CStateIdx(0);
        }
        // Deepest state that (a) fits the latency budget and (b) has
        // a target residency shorter than the prediction.
        let mut best: u8 = 0;
        for s in t.iter() {
            if (s.exit_latency_us as u64) < latency_budget_us
                && (s.target_residency_us as u64) < predicted_idle_us
            {
                best = s.id;
            }
        }
        CStateIdx(best)
    }
}

struct IdleGovernorEntry {
    generation: Option<u64>,
    governor: Arc<dyn IdleGovernor>,
}

fn choose_state(context: &IdleContext, states: &[IdleState], predictive: bool) -> IdleDecision {
    let state = states.iter().rev().find(|state| {
        u64::from(state.exit_latency_us) <= context.latency_limit_us
            && (state.id <= 1
                || !predictive
                || u64::from(state.target_residency_us) <= context.predicted_idle_us)
    });
    IdleDecision {
        state: CStateIdx(state.map_or(0, |s| s.id)),
        stop_tick: true,
    }
}

/// Arc-backed live slot. A query clones the active governor under this short
/// lock and invokes it only after releasing the lock.
static IDLE_GOVERNOR: IrqSafeSpinLock<Option<IdleGovernorEntry>> = IrqSafeSpinLock::new(None);

/// Idle-governor selection. Asks the installed `IdleGovernor` for an
/// index and resolves it against the live C-state table. C0 always
/// satisfies the constraint (latency = 0) and is the fallback if the
/// returned index doesn't match a registered state.
pub fn select_idle_state() -> Result<CState, PowerError> {
    let governor = {
        let slot = IDLE_GOVERNOR.lock();
        slot.as_ref()
            .ok_or(PowerError::GovernorMissing)?
            .governor
            .clone()
    };
    let latency_budget_us = LEGACY_SELECT_BUDGET_US as u64;
    let predicted_idle_us = LEGACY_SELECT_BUDGET_US as u64;
    let idx = governor.select_idle_state(latency_budget_us, predicted_idle_us);
    let t = CSTATES.lock();
    t.iter()
        .find(|state| {
            state.id == idx.0
                && u64::from(state.exit_latency_us) <= latency_budget_us
                && u64::from(state.target_residency_us) <= predicted_idle_us
        })
        .or_else(|| {
            t.iter().find(|state| {
                state.id == 0
                    && u64::from(state.exit_latency_us) <= latency_budget_us
                    && u64::from(state.target_residency_us) <= predicted_idle_us
            })
        })
        .copied()
        .ok_or(PowerError::NoMatchingState)
}

/// Legacy standalone idle helper. Executor idle uses `prepare_idle` so state
/// selection includes the next real deadline and the CPU's residency history.
pub fn idle_loop() {
    if let Ok(state) = select_idle_state() {
        let enabled = narf_arch::interrupts_enabled();
        if !enabled {
            return;
        }
        // SAFETY: preserve the caller's enabled interrupt state.
        unsafe { narf_arch::disable_interrupts() };
        (state.entry)();
        // SAFETY: restore the caller's enabled interrupt state.
        unsafe { narf_arch::enable_interrupts() };
    } else {
        // Last-resort: registry was empty. Fall back to the arch halt
        // primitive so we don't busy-spin the boot CPU.
        narf_arch::halt_until_irq();
    }
}

/// Install an idle governor. Cap-gated on `Cap<IdleGov, Grant>`.
/// Replaces the previous active idle governor; the displaced `Arc` is dropped
/// after releasing the live-slot lock. Mirrors `install_governor` exactly.
pub fn install_idle_governor<G: IdleGovernor>(
    cap: &Cap<IdleGov, Grant>,
    g: G,
) -> Result<(), PowerError> {
    cap.check_live()?;
    let next = IdleGovernorEntry {
        generation: None,
        governor: Arc::new(g),
    };
    let old = {
        let mut slot = IDLE_GOVERNOR.lock();
        executor::POLICY_GENERATION.fetch_add(1, Ordering::Release);
        slot.replace(next)
    };
    drop(old);
    Ok(())
}

/// Commit an Arc-backed struct-ops idle governor generation.
///
/// This is the entry a `struct_ops!` committer uses. The committer is generic
/// over the cap marker (the macro makes it so), so it cannot present the
/// concrete `Cap<IdleGov, Grant>` that [`install_idle_governor`] wants; the
/// struct_ops layer has already proved the cap's kind matches the trait's
/// declared `CapKind::IdleGovernor` before the committer runs. The runtime
/// kind re-check here is the same belt-and-braces validation the generated
/// installer applies, so a caller reaching this directly still cannot install
/// under the wrong authority.
pub fn install_idle_governor_struct_ops<M: CapType>(
    cap: &Cap<M, Grant>,
    generation: u64,
    governor: Arc<dyn IdleGovernor>,
) -> Result<(), PowerError> {
    if M::KIND != CapKind::IdleGovernor || generation == 0 {
        return Err(PowerError::AuthorityRevoked);
    }
    cap.check_live()?;
    let next = IdleGovernorEntry {
        generation: Some(generation),
        governor,
    };
    let old = {
        let mut slot = IDLE_GOVERNOR.lock();
        executor::POLICY_GENERATION.fetch_add(1, Ordering::Release);
        slot.replace(next)
    };
    drop(old);
    Ok(())
}

/// Detach `generation` if it is still live and restore the native default.
/// A displaced older generation is a no-op.
#[must_use]
pub fn detach_idle_governor_struct_ops(generation: u64) -> bool {
    let fallback = IdleGovernorEntry {
        generation: None,
        governor: Arc::new(LinearScan),
    };
    let (detached, old) = {
        let mut slot = IDLE_GOVERNOR.lock();
        if slot
            .as_ref()
            .is_some_and(|entry| entry.generation == Some(generation))
        {
            executor::POLICY_GENERATION.fetch_add(1, Ordering::Release);
            (true, slot.replace(fallback))
        } else {
            (false, None)
        }
    };
    drop(old);
    detached
}

/// Snapshot the active idle governor's name. Returns `None` if `init()`
/// hasn't run yet. Mirrors `current_governor_name`.
pub fn current_idle_governor_name() -> Option<&'static str> {
    let governor = IDLE_GOVERNOR
        .lock()
        .as_ref()
        .map(|entry| entry.governor.clone());
    governor.map(|governor| governor.name())
}

pub fn bootstrap_power_authority() -> Cap<Power, Grant> {
    Cap::bootstrap()
}
pub fn bootstrap_idle_governor_authority() -> Cap<IdleGov, Grant> {
    Cap::bootstrap()
}
pub fn init() {
    executor::reset();
    // Reset the C-state table to the defaults this `init` installs.
    // Production calls `init` once at boot (table already empty); the
    // in-kernel test harness may have left states registered by an
    // earlier test, and `register_cstate`'s dup-check would otherwise
    // preserve them and skew governor selection. Keeps `init` truly
    // "safe to call again" → a defined default set.
    CSTATES.lock().clear();
    // C-state defaults. `register_cstate`'s duplicate check makes the
    // call safe to repeat; we mint a fresh authority so a previously-
    // revoked one from a prior test doesn't poison init.
    let power = bootstrap_power_authority();
    let _ = register_cstate(
        &power,
        CState {
            id: 0,
            exit_latency_us: 0,
            power_draw_mw: 50_000,
            target_residency_us: 0,
            entry: cstate_c0_entry,
        },
    );
    let _ = register_cstate(
        &power,
        CState {
            id: 1,
            exit_latency_us: 1,
            power_draw_mw: 5_000,
            target_residency_us: 2,
            entry: cstate_c1_entry,
        },
    );

    // Default idle governor: LinearScan — preserves Stage-3
    // pre-trait-extraction behaviour.
    let ig = bootstrap_idle_governor_authority();
    let _ = install_idle_governor(&ig, LinearScan);
}
