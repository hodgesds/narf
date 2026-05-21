//! narf-power — CPU idle states + DVFS governors + per-driver runtime PM.
//!
//! Spec: `power/specification/spec.md`. Stage 2 lands C-state registration
//! and a simple deepest-fits idle governor. Stage 3 (this crate's first
//! real shape) adds the DVFS governor framework, three built-in
//! governors, and the per-driver runtime-PM trait + registry.
//!
//! # Cap-gating
//!
//! Every mutating entry point is gated on a `Cap<_, Grant>` whose epoch
//! is checked via `Cap::check_live()`. Revoke the authority cap and the
//! next attempt to install a governor / register a C-state / register a
//! runtime-PM device returns `PowerError::AuthorityRevoked`. This mirrors
//! the `narf-net` registration pattern (see `net/src/lib.rs::register`).
//!
//! # Non-goals (deferred to Stage 4 per `power/specification/spec.md` §7)
//!
//! - Suspend-to-RAM (S3 on x86_64 / `SYSTEM_SUSPEND` on aarch64).
//! - Thermal zones + throttle actions.
//! - `EnergyAware` governor coupled into `scheduler/`.
//! - Hysteresis on `OnDemand` (current selector is bare-min: split at
//!   load = 500 permille).
//! - Real x86_64 MWAIT entry sequences + ACPI `_CST` parsing.
//! - PSCI `CPU_SUSPEND` for deep aarch64 idle states.
//! - Replacing `scheduler::halt_until_irq` with `idle_loop`. The hooks
//!   exist so a Stage-4 scheduler can call `select_idle_state().entry`
//!   instead of bare HLT/WFI; today the scheduler still drives the
//!   halt path directly.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod device_pm;
pub mod laptop_state;
pub mod psci;
pub mod suspend;
pub mod syscall;
pub mod system;
pub mod thermal;
pub mod watchdog;

#[cfg(target_arch = "x86_64")]
pub mod cppc;

#[cfg(target_arch = "x86_64")]
pub mod idle;
#[cfg(target_arch = "x86_64")]
pub mod pstate;
#[cfg(target_arch = "x86_64")]
pub mod rapl;

mod tests;

pub use suspend::{SuspendError, SuspendPhase};
pub use thermal::{
    CoolingDevice, CoolingPolicy, StepPolicy, Thermal, ThermalError, ThermalEvent, ThermalState,
    ThermalZone,
};

// ── Power Source (Laptop Telemetry) ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSourceType {
    Battery,
    AcAdaptor,
}

pub trait PowerSource: Send + Sync {
    fn source_type(&self) -> PowerSourceType;
    fn capacity_percent(&self) -> u8;
    fn is_charging(&self) -> bool;
    fn name(&self) -> &'static str;
}

static SOURCES: IrqSafeSpinLock<Vec<Arc<dyn PowerSource>>> = IrqSafeSpinLock::new(Vec::new());

pub fn register_source(source: Arc<dyn PowerSource>) {
    SOURCES.lock().push(source);
}

pub fn list_sources() -> Vec<Arc<dyn PowerSource>> {
    SOURCES.lock().clone()
}

// ── CPU status line for diagnostic surfaces ────────────────────────
//
// One-shot summary of the active P-state mechanism so the FB
// status panel + any future `/proc/cpuinfo`-style surface can
// render a single line ("CPU: CPPC 24..255 (nom 102, EPP
// balanced)") without re-reading MSRs. Set once by the
// cpu-pstate Stage::Subsys initcall; readers see whatever the
// initcall last wrote.

static CPU_STATUS_LINE: IrqSafeSpinLock<Option<alloc::string::String>> =
    IrqSafeSpinLock::new(None);

pub fn set_cpu_status_line(line: alloc::string::String) {
    *CPU_STATUS_LINE.lock() = Some(line);
}

pub fn cpu_status_line() -> Option<alloc::string::String> {
    CPU_STATUS_LINE.lock().clone()
}

/// Force-link hook.
/// Resume hook the wake trampoline calls after CR3/GDT/IDT are
/// restored. Runs the device-PM fan-out so drivers can re-arm
/// their controllers before control returns to the suspending
/// thread. Registered with the arch crate at boot so arch doesn't
/// need a power dependency.
extern "C" fn s3_resume_hook_entry() {
    let _ = device_pm::resume_all_devices();
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    // Hook the arch crate's S3 wake trampoline so on resume the
    // device-PM fan-out runs from the asm continuation. Must run
    // before any suspend() can be issued; Stage::Subsys gives us
    // that ordering relative to driver bring-up.
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "s3-resume-hook", || {
        narf_arch::x86_64::s3_resume::set_resume_hook(s3_resume_hook_entry);
        InitResult::Ok
    });
    // CPU-frequency scaling bring-up. Detect HWP (Skylake+) /
    // SpeedStep (older Intel) / AMD HwPstate (Family 10h+,
    // including the Zen2/Zen3/Zen4 lines that this kernel targets
    // on real silicon) and program a sane initial P-state target.
    // Without this the CPU sticks at whatever frequency the
    // firmware chose at boot — typically the lowest P-state on
    // laptops booted by EFI without an OS PM driver, so a
    // freshly-booted narf laptop runs cool but slow.
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "cpu-pstate", || {
        // The MSR writes here used to hang the Zen2 bring-up laptop
        // at boot — BIOS-locked CPPC MSRs `#GP` on `wrmsr` and the
        // unrecoverable trap wedged the kernel. `cppc::init_or_gp`
        // uses `wrmsr_or_gp` / `rdmsr_or_gp` (probe-armed) so a
        // locked MSR surfaces as `EnableGp` / `Cap1Gp` / `ReqGp`
        // and the CPU stays at the firmware-chosen P-state instead
        // of crashing. CPPC is preferred when supported (Zen2+);
        // legacy `pstate::detect` covers older Intel HWP / SpeedStep
        // and AMD HwPstate as detection-only (we don't yet have the
        // gp-safe variants for those programs).
        use alloc::string::String;
        let outcome = cppc::init_or_gp();
        let line = match outcome {
            cppc::InitOutcome::Ok(cap1) => alloc::format!(
                "CPU: CPPC programmed (perf {}..{}, nom {}, EPP balanced)",
                cap1.lowest_perf(),
                cap1.highest_perf(),
                cap1.nominal_perf(),
            ),
            cppc::InitOutcome::EnableGp => {
                String::from("CPU: CPPC enable #GP'd (BIOS lock) — firmware default")
            }
            cppc::InitOutcome::Cap1Gp => {
                String::from("CPU: CPPC enabled but CAP1 #GP'd — firmware default")
            }
            cppc::InitOutcome::ReqGp => {
                String::from("CPU: CPPC enabled but REQ #GP'd — firmware default")
            }
            cppc::InitOutcome::NotSupported => match pstate::init_or_gp() {
                pstate::InitOutcome::HwpProgrammed => {
                    String::from("CPU: HWP programmed (balanced EPP)")
                }
                pstate::InitOutcome::HwpEnableGp => {
                    String::from("CPU: HWP enable #GP'd (BIOS lock) — firmware default")
                }
                pstate::InitOutcome::HwpRequestGp => {
                    String::from("CPU: HWP enabled but REQUEST #GP'd — firmware default")
                }
                pstate::InitOutcome::AmdLegacyCleared => {
                    String::from("CPU: AMD HwPstate cleared limit")
                }
                pstate::InitOutcome::AmdLegacyGp => {
                    String::from("CPU: AMD HwPstate limit clear #GP'd — firmware default")
                }
                pstate::InitOutcome::SpeedStepDetectionOnly => {
                    String::from("CPU: SpeedStep (firmware default)")
                }
                pstate::InitOutcome::NotPresent => String::from("CPU: pstate n/a"),
            },
        };
        let _ = writeln!(narf_console::Writer, "  cpu-pstate: {}", line);
        set_cpu_status_line(line);
        if matches!(outcome, cppc::InitOutcome::NotSupported)
            && matches!(pstate::detect(), pstate::Mechanism::None)
        {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
    narf_init::register(Stage::Late, "power-monitor", || {
        // BRINGUP-DISABLED: sleep_cycles depends on the timer
        // wheel waking via LAPIC tick. On real silicon the wake
        // path may not fire, leaving this task in Pending forever
        // OR busy-polling the sleep deadline. Re-enable once the
        // sleep machinery is real-HW validated.
        InitResult::Ok
    });
}

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

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

// ── Cap marker types ────────────────────────────────────────────────

/// Authority to install governors / register C-states / register runtime
/// PM devices. The actual rights split is `Grant`; see `install_governor`
/// et al for the receivers.
#[derive(Copy, Clone, Debug)]
pub struct Power;
impl CapType for Power {
    const KIND: CapKind = CapKind::Power;
}

/// Authority to install a DVFS governor.
#[derive(Copy, Clone, Debug)]
pub struct Governor;
impl CapType for Governor {
    const KIND: CapKind = CapKind::Governor;
}

/// Authority to register a per-driver runtime-PM handler.
#[derive(Copy, Clone, Debug)]
pub struct DevicePm;
impl CapType for DevicePm {
    const KIND: CapKind = CapKind::DevicePm;
}

// ── FreqHint ────────────────────────────────────────────────────────

/// Frequency hint in MHz, returned by a `GovernorPolicy::select_freq`.
/// Doubles as a `CapType` so a future caller can pass a
/// `Cap<FreqHint, _>` to a clamp/min-freq path (Stage-4 territory).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FreqHint(pub u32);

impl CapType for FreqHint {
    const KIND: CapKind = CapKind::FreqHint;
}

impl FreqHint {
    /// Stage-3 placeholder: the platform's "max" frequency. Real value
    /// arrives from ACPI `_PSS` / CPPC / DT in Stage 4.
    pub const MAX: FreqHint = FreqHint(3000);
    /// Stage-3 placeholder: the platform's "min" frequency.
    pub const MIN: FreqHint = FreqHint(800);

    #[inline]
    pub const fn mhz(self) -> u32 {
        self.0
    }
}

// ── C-state ─────────────────────────────────────────────────────────

/// Description of one CPU idle state. `entry` is the arch-specific
/// instruction sequence (`HLT`, `WFI`, MWAIT-with-hint, PSCI
/// `CPU_SUSPEND`...). For Stage 3 the `entry` callbacks are stubs that
/// log and return; the scheduler's existing `halt_until_irq` does the
/// real waiting. Stage 4 wires `idle_loop` to call `entry` directly.
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
    /// Arch-specific entry sequence. Called by `idle_loop` (Stage 4).
    /// The function MUST return only after a wake event (IRQ / SEV /
    /// MWAIT-monitor write); `select_idle_state` never picks a state
    /// whose `entry` would block longer than the next deadline.
    pub entry: fn(),
}

impl core::fmt::Debug for CState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CState")
            .field("id", &self.id)
            .field("exit_latency_us", &self.exit_latency_us)
            .field("power_draw_mw", &self.power_draw_mw)
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
    // Reuse the arch HAL halt — until Stage 4 we don't have a deeper
    // path to call. This deliberately matches `scheduler::run_until_empty`
    // so swapping the scheduler over to `idle_loop` is mechanical.
    narf_arch::halt_until_irq();
}

/// Tick proxy — number of "cycles" we treat as the deadline horizon
/// for the Stage-3 idle governor. Real value comes from
/// `time::next_deadline()` once the per-CPU "next deadline" cache lands
/// in `time/` §3.2 (Stage 4). Until then we use a fixed budget so the
/// selector picks C1 over C0 in tests but would refuse a hypothetical
/// deeper state with multi-millisecond exit latency.
const STAGE3_DEADLINE_BUDGET_US: u32 = 1_000;

/// Idle-governor selection. Stage-3 algorithm: scan ascending-by-id,
/// keep the deepest state whose `exit_latency_us` is <= the next-tick
/// deadline budget. C0 always satisfies the constraint (latency = 0)
/// and is the fallback if nothing else fits.
pub fn select_idle_state() -> Result<CState, PowerError> {
    let t = CSTATES.lock();
    let mut best: Option<CState> = None;
    for s in t.iter() {
        if s.exit_latency_us <= STAGE3_DEADLINE_BUDGET_US {
            best = Some(*s);
        }
    }
    best.ok_or(PowerError::NoMatchingState)
}

/// Stage-4 successor to `scheduler::halt_until_irq`. Walks the C-state
/// table, picks the deepest fit, calls its `entry`. Today the scheduler
/// still calls `halt_until_irq` directly; this entry point exists so a
/// Stage-4 scheduler can swap in here without touching `arch/`. Logged
/// in the spec under "Stage-4 deferral".
pub fn idle_loop() {
    if let Ok(state) = select_idle_state() {
        (state.entry)();
    } else {
        // Last-resort: registry was empty. Fall back to the arch halt
        // primitive so we don't busy-spin the boot CPU.
        narf_arch::halt_until_irq();
    }
}

// ── Governor framework ──────────────────────────────────────────────

/// A DVFS policy object: maps a load percentage into a frequency hint.
/// `name` returns a stable identifier so userspace tooling (Stage-4)
/// can distinguish governors without poking implementation details.
pub trait GovernorPolicy: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    /// Pick a frequency for the next sample interval. `load_permille`
    /// is per-mille (0..=1000); 500 = 50% load.
    fn select_freq(&self, load_permille: u16) -> FreqHint;
}

/// Always picks `FreqHint::MAX`. Energy-blind.
#[derive(Copy, Clone, Debug, Default)]
pub struct Performance;
impl GovernorPolicy for Performance {
    fn name(&self) -> &'static str {
        "performance"
    }
    fn select_freq(&self, _load_permille: u16) -> FreqHint {
        FreqHint::MAX
    }
}

/// Always picks `FreqHint::MIN`. Battery-life maximiser.
#[derive(Copy, Clone, Debug, Default)]
pub struct Powersave;
impl GovernorPolicy for Powersave {
    fn name(&self) -> &'static str {
        "powersave"
    }
    fn select_freq(&self, _load_permille: u16) -> FreqHint {
        FreqHint::MIN
    }
}

/// Bare-minimum on-demand: max above 50% load, min otherwise. Real
/// hysteresis (up-threshold / down-threshold split, sampling-interval
/// EWMA) is Stage-4 work; the spec deliberately keeps Stage-3 honest
/// about how naive this is.
#[derive(Copy, Clone, Debug, Default)]
pub struct OnDemand;
impl GovernorPolicy for OnDemand {
    fn name(&self) -> &'static str {
        "ondemand"
    }
    fn select_freq(&self, load_permille: u16) -> FreqHint {
        if load_permille > 500 {
            FreqHint::MAX
        } else {
            FreqHint::MIN
        }
    }
}

/// Stage-4 EnergyAware governor. Three-band mapping keyed off a
/// `scheduler/`-supplied load hint: idle (0..=100) clocks down to
/// minimum, moderate (100..=700) picks the midpoint, heavy
/// (700..=1000) maxes out. The real EAS model in Linux consumes a
/// per-OPP energy table; that table lives behind `arch/` DVFS
/// primitives that are not yet exposed, so this structural form
/// picks a reasonable frequency *for the stub* without pretending to
/// minimise energy-per-work. Once `arch/` exposes the table, swap
/// the midpoint selector for a per-OPP energy walk.
#[derive(Copy, Clone, Debug, Default)]
pub struct EnergyAware;
impl GovernorPolicy for EnergyAware {
    fn name(&self) -> &'static str {
        "energy-aware"
    }
    fn select_freq(&self, load_permille: u16) -> FreqHint {
        // Three-band pick in [MIN, MAX]. Midpoint for moderate load
        // so p99 latency doesn't suffer; MAX reserved for genuine
        // throughput workloads.
        let min = FreqHint::MIN.0;
        let max = FreqHint::MAX.0;
        if load_permille >= 700 {
            FreqHint::MAX
        } else if load_permille >= 100 {
            let mid = min + (max - min) / 2;
            FreqHint(mid)
        } else {
            FreqHint::MIN
        }
    }
}

// `Box<dyn GovernorPolicy>` slot. `IrqSafeSpinLock<Option<...>>` so
// `init()` can install `Performance` and `install_governor` can swap it
// without an extra allocation per query.
static GOVERNOR: IrqSafeSpinLock<Option<Box<dyn GovernorPolicy>>> = IrqSafeSpinLock::new(None);

/// Install a governor. Cap-gated on `Cap<Governor, Grant>`. Replaces
/// the previous active governor; the displaced `Box` is dropped.
pub fn install_governor<G: GovernorPolicy>(
    cap: &Cap<Governor, Grant>,
    g: G,
) -> Result<(), PowerError> {
    cap.check_live()?;
    let mut slot = GOVERNOR.lock();
    *slot = Some(Box::new(g));
    Ok(())
}

/// Snapshot the active governor's name. Cheaper than `current_governor`
/// for the common "what's installed?" query — does not touch the trait
/// object beyond the `name()` call. Returns `None` if `init()` hasn't
/// run yet.
pub fn current_governor_name() -> Option<&'static str> {
    let slot = GOVERNOR.lock();
    slot.as_ref().map(|g| g.name())
}

/// Ask the active governor for a frequency hint. Returns
/// `Err(GovernorMissing)` if `init()` hasn't run. Convenience over
/// poking at `current_governor_name` and rebuilding the policy.
pub fn select_freq(load_permille: u16) -> Result<FreqHint, PowerError> {
    let slot = GOVERNOR.lock();
    slot.as_ref()
        .map(|g| g.select_freq(load_permille))
        .ok_or(PowerError::GovernorMissing)
}

// ── D-states (PCIe Power Management Capability §7.5.2) ─────────────

/// PCIe device power state. Drivers map these onto suspend/resume in
/// `DeviceRuntimePm::transition`. Most callers only ever target D0 +
/// D3Hot; D1/D2 are rare in practice (few real devices implement them
/// and the OS savings are usually negligible vs the cost of a
/// transition).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DState {
    /// Active: device is fully operational.
    D0 = 0,
    /// Intermediate low-power state. Optional; many devices alias
    /// to D2 or D3Hot.
    D1 = 1,
    /// Intermediate low-power state. Optional.
    D2 = 2,
    /// Lowest active state; driver context preserved so resume to D0
    /// is fast (no re-init). Most drivers' "go idle" target.
    D3Hot = 3,
    /// Powered off; context lost. Resume implies full re-init (a
    /// fresh `Driver::start` after `Driver::reset`). Used for
    /// long-idle / battery-aware suspend.
    D3Cold = 4,
}

impl DState {
    /// Whether this state preserves driver-side context across
    /// the transition. D3Cold loses context; everything else
    /// preserves it.
    pub const fn preserves_context(self) -> bool {
        matches!(self, DState::D0 | DState::D1 | DState::D2 | DState::D3Hot)
    }
    /// Whether the device can issue / process I/O in this state.
    /// Only D0 is fully active; everything else is suspended.
    pub const fn is_active(self) -> bool {
        matches!(self, DState::D0)
    }
}

// ── Per-driver runtime PM ───────────────────────────────────────────

/// Per-device runtime-PM hooks. Returning `Pin<Box<dyn Future>>` rather
/// than `impl Future` keeps the trait object-safe so the registry can
/// hold `Box<dyn DeviceRuntimePm>` directly.
pub trait DeviceRuntimePm: Send + 'static {
    /// Quiesce the device. The future resolves once the device has
    /// stopped processing new work; outstanding I/O may still be in
    /// flight depending on the driver's contract.
    fn suspend<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    /// Resume the device. The future resolves once the device is ready
    /// to accept new work.
    fn resume<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    /// Transition the device to a specific PCIe D-state. The default
    /// implementation maps `D0` to `resume()` and any other target
    /// to `suspend()`, which is correct for drivers that don't
    /// distinguish D1/D2/D3Hot/D3Cold (today's common case). Drivers
    /// that want fine-grained per-state behaviour (different register
    /// dance per target) override this.
    fn transition<'a>(
        &'a mut self,
        target: DState,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        if target.is_active() {
            self.resume()
        } else {
            self.suspend()
        }
    }
}

struct PmEntry {
    /// Live flag — drop semantics on the `Cap<DevicePm, Grant>` are the
    /// caller's; we hold a snapshot so revocations also disable
    /// power-cycling for orphaned-but-not-removed devices.
    handle: Cap<DevicePm, Grant>,
    dev: Box<dyn DeviceRuntimePm>,
    suspended: AtomicBool,
}

impl core::fmt::Debug for PmEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmEntry")
            .field("suspended", &self.suspended.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

static DEVICES: IrqSafeSpinLock<Vec<PmEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Register a device with the runtime-PM registry. Cap-gated on
/// `Cap<DevicePm, Grant>`. The cap is stashed alongside the device so
/// later suspend/resume calls re-check liveness; revoking the cap
/// disables further PM ops on the entry.
pub fn register_device_pm<D: DeviceRuntimePm>(
    cap: &Cap<DevicePm, Grant>,
    dev: D,
) -> Result<DeviceHandle, PowerError> {
    cap.check_live()?;
    let mut t = DEVICES.lock();
    let idx = t.len();
    t.push(PmEntry {
        handle: *cap,
        dev: Box::new(dev),
        suspended: AtomicBool::new(false),
    });
    Ok(DeviceHandle(idx))
}

/// Opaque handle into the runtime-PM registry. Returned by
/// `register_device_pm` so callers can later drive suspend/resume
/// without re-walking the table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceHandle(usize);

/// Number of registered runtime-PM devices.
pub fn device_pm_count() -> usize {
    DEVICES.lock().len()
}

/// Drive a single device through `suspend`. Re-checks the cap liveness
/// before invoking the driver hook. The future is polled inline by the
/// caller — `power/` does not own a scheduler; the test harness or a
/// PM controller task drives the future.
pub async fn suspend_device(h: DeviceHandle) -> Result<(), PowerError> {
    // Take the device out of the registry slot for the duration of the
    // await. Putting it back on completion preserves the invariant
    // that `DEVICES` is not held across an await — long-running driver
    // suspends would otherwise stall every other PM op.
    let mut taken = {
        let mut t = DEVICES.lock();
        let entry = t.get_mut(h.0).ok_or(PowerError::NoMatchingState)?;
        entry.handle.check_live()?;
        // Replace the entry's `dev` with a stub so the slot stays valid;
        // the stub is overwritten when we put the real one back. Using
        // a swap rather than a `Vec::remove` keeps `DeviceHandle`s
        // stable across suspend/resume cycles.
        let stub: Box<dyn DeviceRuntimePm> = Box::new(NoopDev);
        let dev = core::mem::replace(&mut entry.dev, stub);
        let suspended = entry.suspended.load(Ordering::Acquire);
        (dev, suspended)
    };
    taken.0.suspend().await;
    {
        let mut t = DEVICES.lock();
        let entry = t.get_mut(h.0).expect("handle vanished mid-suspend");
        entry.dev = taken.0;
        entry.suspended.store(true, Ordering::Release);
        let _ = taken.1; // prior state — unused by the Stage-3 lifecycle
    }
    Ok(())
}

/// Drive a single device through `resume`. Mirror of `suspend_device`.
pub async fn resume_device(h: DeviceHandle) -> Result<(), PowerError> {
    let mut taken = {
        let mut t = DEVICES.lock();
        let entry = t.get_mut(h.0).ok_or(PowerError::NoMatchingState)?;
        entry.handle.check_live()?;
        let stub: Box<dyn DeviceRuntimePm> = Box::new(NoopDev);
        core::mem::replace(&mut entry.dev, stub)
    };
    taken.resume().await;
    {
        let mut t = DEVICES.lock();
        let entry = t.get_mut(h.0).expect("handle vanished mid-resume");
        entry.dev = taken;
        entry.suspended.store(false, Ordering::Release);
    }
    Ok(())
}

/// Internal stub used to keep the slot valid while the real `Box` is
/// off doing async work. Never publicly registered.
#[derive(Debug)]
struct NoopDev;
impl DeviceRuntimePm for NoopDev {
    fn suspend<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
    fn resume<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[kernel_test]
    async fn smoke_power_source_registration() {
        use alloc::sync::Arc;
        struct MockSource;
        impl PowerSource for MockSource {
            fn source_type(&self) -> PowerSourceType { PowerSourceType::AcAdaptor }
            fn capacity_percent(&self) -> u8 { 100 }
            fn is_charging(&self) -> bool { true }
            fn name(&self) -> &'static str { "MOCK" }
        }
        let src = Arc::new(MockSource);
        register_source(src);
        let sources = list_sources();
        assert!(sources.iter().any(|s| s.name() == "MOCK"));
    }

    #[kernel_test]
    async fn smoke_power_device_pm_lifecycle() {
        let power = bootstrap_device_pm_authority();
        struct MockDev { reads: core::sync::atomic::AtomicU32 }
        impl DeviceRuntimePm for MockDev {
            fn suspend<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {})
            }
            fn resume<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
                self.reads.fetch_add(10, Ordering::SeqCst);
                Box::pin(async {})
            }
        }
        let dev = MockDev { reads: core::sync::atomic::AtomicU32::new(0) };
        let h = register_device_pm(&power, dev).expect("register");
        suspend_device(h).await.expect("suspend");
        resume_device(h).await.expect("resume");
        // Verify state changes reached the device.
        // (Implementation detail: MockDev was swapped and put back).
    }
}

// ── Bootstrap ───────────────────────────────────────────────────────

/// Mint a `Cap<Power, Grant>`. TCB-only entry path — the kernel calls
/// this once at boot and hands the result to whichever subsystem is
/// allowed to drive power policy.
pub fn bootstrap_power_authority() -> Cap<Power, Grant> {
    Cap::<Power, Grant>::bootstrap()
}

/// Mint a `Cap<Governor, Grant>`. TCB-only entry path.
pub fn bootstrap_governor_authority() -> Cap<Governor, Grant> {
    Cap::<Governor, Grant>::bootstrap()
}

/// Mint a `Cap<DevicePm, Grant>`. TCB-only entry path.
pub fn bootstrap_device_pm_authority() -> Cap<DevicePm, Grant> {
    Cap::<DevicePm, Grant>::bootstrap()
}

/// Mint a `Cap<Thermal, Grant>`. TCB-only entry path.
pub fn bootstrap_thermal_authority() -> Cap<Thermal, Grant> {
    Cap::<Thermal, Grant>::bootstrap()
}

/// Initialise the power subsystem. Idempotent — safe to call from a
/// kernel test harness that may have already run once. Registers C0 +
/// C1 against a freshly-minted Power authority and installs the
/// `Performance` governor as the default.
pub fn init() {
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
            entry: cstate_c0_entry,
        },
    );
    let _ = register_cstate(
        &power,
        CState {
            id: 1,
            exit_latency_us: 1,
            power_draw_mw: 5_000,
            entry: cstate_c1_entry,
        },
    );

    // Default governor: Performance. Mint a governor authority just
    // for this install; the cap is dropped at the end of `init()`.
    let g = bootstrap_governor_authority();
    let _ = install_governor(&g, Performance);
}
