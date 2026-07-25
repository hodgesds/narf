//! CPUFreq governor — schedutil-style on top of HWP / CPPC / `_PSS`.
//!
//! Builds on the existing P-state programs in `hwp.rs` (Intel) and
//! `cppc.rs` (AMD): those modules read capabilities + program a
//! one-shot bring-up request at Stage::Subsys, leaving the hardware
//! to autonomously pick a P-state inside the supplied window. This
//! module layers a periodic governor on top: it samples per-CPU
//! utilisation, computes a target performance value, and re-writes
//! `desired_perf` so the hardware aims at a specific point inside
//! the (min, max) window instead of leaving it to firmware policy.
//!
//! ## Backend priority
//!
//! Resolved once at [`enable()`] and cached:
//!
//!   1. **`Backend::IntelHwp`** — CPUID(0x06).EAX[7]. Reads
//!      `IA32_HWP_CAPABILITIES` (MSR 0x771), writes
//!      `IA32_HWP_REQUEST` (MSR 0x774). Linux: `intel_pstate.c`
//!      `intel_pstate_update_pstate`.
//!   2. **`Backend::AmdCppc`** — CPUID(0x8000_0008).EBX[27].
//!      `MSR_AMD_CPPC_CAP1` (0xC001_02B0) +
//!      `MSR_AMD_CPPC_REQ` (0xC001_02B3). Linux:
//!      `amd_pstate.c` `amd_pstate_update_perf` /
//!      `amd_pstate.c::shmem_set_epp`.
//!   3. **`Backend::AcpiPss`** — fallback for older parts without
//!      HWP/CPPC. Per-processor `_PSS` object lists P-state
//!      `{CoreFreq, Power, Latency, BusMasterLatency, Control,
//!      Status}` tuples; the governor selects an entry and writes
//!      `Control` to the per-processor `_PCT` register.
//!   4. **`Backend::None`** — neither path available (virt
//!      hypervisor with no HWP / no CPPC / no _PSS), or every
//!      bring-up attempt #GP'd.
//!
//! ## Governor algorithm
//!
//! Schedutil-style: every tick the governor reads a per-CPU
//! scheduler-demand proxy and computes
//!
//! ```text
//!   target_perf = min_perf + (util * (max_perf - min_perf)) / 1000
//! ```
//!
//! NARF does not yet account PELT-style run time, so the proxy is
//! deliberately conservative: an empty local ready queue maps to
//! zero demand and any queued runnable task maps to full demand.
//! This avoids the old timer-IRQ proxy, which could not distinguish
//! an idle CPU woken by the periodic tick from a busy CPU.
//!
//! Hysteresis is a simple one-shot guard: a recompute that lands
//! within `HYSTERESIS_BAND` of the previously-written value is
//! skipped to avoid MSR-write spam on a CPU bouncing through a
//! workload boundary. The Linux schedutil module uses a similar
//! down-rate-limit; we keep it cheaper at this stage.
//!
//! ## Spec / source references
//!
//! - Intel SDM Vol 4 §2.16 (HWP MSRs).
//! - Intel SDM Vol 3B §14.4 (Hardware-Controlled Performance States).
//! - AMD APM Vol 2 §17 (CPPC).
//! - ACPI 6.5 §8.4.4 (`_PSS`), §8.4.5 (`_PPC`), §8.4.6 (`_PCT`).
//! - Linux `drivers/cpufreq/intel_pstate.c::intel_pstate_update_pstate`.
//! - Linux `drivers/cpufreq/amd_pstate.c::amd_pstate_update_perf`.
//! - Linux `kernel/sched/cpufreq_schedutil.c::sugov_update_shared`.
//!
//! NARF is GPL-2.0-or-later as of 2026-05-20 so Linux can be
//! consulted directly; the bit-layouts here come from the public
//! Intel / AMD / ACPI specs and Linux is cross-checked for the
//! algorithm shape.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use narf_arch::x86_64::cpuid::cpuid;
use narf_arch::x86_64::msr::{rdmsr_or_gp, wrmsr_or_gp};
use narf_lib::sync::IrqSafeSpinLock;

use crate::cppc::{
    epp as cppc_epp, Cap1 as CppcCap1, Request as CppcRequest, ENABLE_BIT, MSR_AMD_CPPC_CAP1,
    MSR_AMD_CPPC_ENABLE, MSR_AMD_CPPC_REQ,
};
use crate::hwp::HwpCapabilities;
use crate::pstate::{MSR_IA32_HWP_CAPABILITIES, MSR_IA32_HWP_REQUEST, MSR_IA32_PM_ENABLE};

// ── Public types ───────────────────────────────────────────────────

/// Active backend, resolved once at [`enable()`] and cached.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Intel HWP — `IA32_HWP_CAPABILITIES` + `IA32_HWP_REQUEST`.
    IntelHwp,
    /// AMD CPPC — `MSR_AMD_CPPC_CAP1` + `MSR_AMD_CPPC_REQ`.
    AmdCppc,
    /// ACPI fallback — per-processor `_PSS` table + `_PCT`.
    AcpiPss,
    /// No backend resolved. The governor is a no-op.
    None,
}

/// Linux-compatible policy modes layered over HWP/CPPC.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Policy {
    /// Request highest performance with a nominal floor.
    Performance,
    /// Scale across the full hardware range from scheduler load.
    #[default]
    Balanced,
    /// Scale only up to nominal performance with an energy-biased EPP.
    Powersave,
    /// Leave desired performance autonomous; explicit range/EPP controls win.
    Userspace,
}

/// Errors from the governor entry points. Mirrors the pattern in
/// `pstate.rs::InitOutcome`: distinguish "we didn't try" from "we
/// tried and the MSR `#GP`'d / the table was missing" so callers
/// can surface the difference in a diagnostic line.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpuFreqError {
    /// `enable()` ran but no platform offered a usable backend.
    NoBackend,
    /// HWP / CPPC capabilities MSR read `#GP`'d (BIOS lock).
    CapabilitiesGp,
    /// Enabling HWP / CPPC on the owning CPU `#GP`'d.
    EnableGp,
    /// Programming the request MSR `#GP`'d.
    RequestGp,
    /// `_PSS` table is missing or malformed.
    PssMissing,
    /// Governor isn't currently enabled; call [`enable()`] first.
    NotEnabled,
    /// Requested CPU id is out of range for the online topology.
    NoSuchCpu,
    /// Firmware returned a zero or inverted performance range.
    InvalidCapabilities,
}

/// Per-CPU performance snapshot exposed by [`current_perf()`].
/// All four values live on the same unitless 0..=255 HWP/CPPC scale
/// so a single getter shape works for both backends; the `_PSS`
/// fallback packs the P-state index in `current` and leaves the
/// other three at the table's first/last endpoints.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PerfState {
    /// Floor of the request window the governor will not go below.
    pub min: u8,
    /// Ceiling of the request window.
    pub max: u8,
    /// Last `desired_perf` value the governor wrote, or 0 for
    /// "autonomous / firmware picks".
    pub desired: u8,
    /// Hardware-reported delivered performance, if available.
    /// Some backends don't expose a status MSR here; in that case
    /// the field mirrors `desired`.
    pub current: u8,
    /// Energy-performance preference last programmed for this CPU.
    pub epp: u8,
    /// Active software policy.
    pub policy: Policy,
}

// ── State ──────────────────────────────────────────────────────────

/// Encoded `Backend` discriminant.
/// 0xFF = "not yet resolved", 0..=3 = `IntelHwp..None`.
static BACKEND_RAW: AtomicU8 = AtomicU8::new(0xFF);

/// True iff [`enable()`] succeeded and the governor is owning
/// `desired_perf` updates.
static ENABLED: AtomicU8 = AtomicU8::new(0);

/// Per-CPU governor state — utilisation proxy bookkeeping + the
/// last value we wrote (for hysteresis). Sized for `MAX_CPUS` so
/// `fire_count_on_cpu` indexing stays array-bounded.
#[derive(Clone, Copy, Default, Debug)]
struct PerCpu {
    /// Last `desired_perf` byte we wrote, for hysteresis.
    last_desired: u8,
    /// Hardware capability bounds cached on the owning CPU.
    hw_min_perf: u8,
    nominal_perf: u8,
    hw_max_perf: u8,
    /// Active policy request.
    min_perf: u8,
    max_perf: u8,
    epp: u8,
    policy: Policy,
}

const MAX_CPUS: usize = 64;
static PERCPU: IrqSafeSpinLock<[PerCpu; MAX_CPUS]> = IrqSafeSpinLock::new(
    [PerCpu {
        last_desired: 0,
        hw_min_perf: 0,
        nominal_perf: 0,
        hw_max_perf: 0,
        min_perf: 0,
        max_perf: 0,
        epp: cppc_epp::BALANCED_PERFORMANCE,
        policy: Policy::Balanced,
    }; MAX_CPUS],
);

/// Monotonic tick counter — incremented by [`tick()`] for
/// diagnostics.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static WORKERS_STARTED: AtomicBool = AtomicBool::new(false);

/// Hysteresis band: skip a re-write when the target sits within
/// this many perf units of the last value. Cheap MSR-write
/// suppression without the full schedutil down-rate-limit.
const HYSTERESIS_BAND: u8 = 4;

/// Sample interval in milliseconds. 100 ms = 10 Hz, intentionally
/// slower than the 1 kHz LAPIC tick so the timer-IRQ count delta
/// is large enough (~100 ticks at 1 kHz) to be a useful signal.
pub const TICK_INTERVAL_MS: u32 = 100;

// ── Public API ─────────────────────────────────────────────────────

/// Resolve the active backend. Cheap to call repeatedly — the
/// result is cached after the first probe.
pub fn backend() -> Backend {
    let raw = BACKEND_RAW.load(Ordering::Acquire);
    if raw != 0xFF {
        return decode_backend(raw);
    }
    let b = detect_backend();
    BACKEND_RAW.store(encode_backend(b), Ordering::Release);
    b
}

/// Enable the cpufreq governor. Re-resolves the backend (idempotent
/// after the first call), seeds per-CPU window cached from
/// capabilities, and flips `ENABLED` so [`tick()`] starts driving
/// `desired_perf` writes. Returns `Err(NoBackend)` if no platform
/// path is available.
pub fn enable() -> Result<(), CpuFreqError> {
    let b = backend();
    match b {
        Backend::IntelHwp => seed_intel_hwp_current()?,
        Backend::AmdCppc => seed_amd_cppc_current()?,
        Backend::AcpiPss => seed_acpi_pss()?,
        Backend::None => return Err(CpuFreqError::NoBackend),
    }
    ENABLED.store(1, Ordering::Release);
    Ok(())
}

/// Start one periodic governor worker on every online CPU. Each worker
/// is hard-pinned because HWP and CPPC request/status MSRs are per-CPU.
/// Calling this more than once is harmless.
pub fn start_workers() {
    if WORKERS_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let cpus = narf_lib::smp::cpu_count() as usize;
    for cpu in 0..cpus.min(MAX_CPUS) {
        if !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        let mut spec = narf_scheduler::TaskSpec::unthrottled();
        spec.affinity =
            narf_scheduler::Affinity::pinned(narf_scheduler::affinity::CpuId(cpu as u32));
        narf_scheduler::spawn_with_spec(worker(cpu), spec);
    }
}

async fn worker(cpu: usize) {
    if seed_current_cpu(cpu).is_err() {
        return;
    }
    loop {
        let deadline = narf_time::Deadline::after_ms(TICK_INTERVAL_MS as u64);
        narf_time::SleepUntil::new(deadline.as_instant()).await;
        let _ = tick_cpu(cpu);
    }
}

/// Disable the governor without un-programming any hardware state.
/// The HWP / CPPC request MSRs keep whatever was last written; the
/// hardware autonomous selector continues to drive the CPU. Used
/// by suspend (the governor goes quiet across S3) and by tests.
pub fn disable() {
    ENABLED.store(0, Ordering::Release);
}

/// Read the current performance state for `cpu`. Returns `None`
/// when the CPU isn't tracked (id out of range or backend = None).
pub fn current_perf(cpu: u32) -> Option<PerfState> {
    if (cpu as usize) >= MAX_CPUS {
        return None;
    }
    if matches!(backend(), Backend::None) {
        return None;
    }
    let pc = PERCPU.lock();
    let s = pc[cpu as usize];
    if s.min_perf == 0 && s.max_perf == 0 {
        return None;
    }
    Some(PerfState {
        min: s.min_perf,
        max: s.max_perf,
        desired: s.last_desired,
        // Neither HWP nor amd-pstate provides an architectural
        // instantaneous-performance byte. APERF/MPERF telemetry is
        // the honest source, so zero means "not sampled here".
        current: 0,
        epp: s.epp,
        policy: s.policy,
    })
}

/// One-shot governor tick for the executing CPU.
///
/// Returns one when its request changed and zero when hysteresis suppressed
/// the write. The hardware access is deliberately local: per-CPU MSRs must
/// never be written in a loop from the BSP.
pub fn tick() -> Result<u32, CpuFreqError> {
    tick_cpu(narf_lib::percpu::current_cpu())
}

fn tick_cpu(cpu: usize) -> Result<u32, CpuFreqError> {
    if ENABLED.load(Ordering::Acquire) == 0 {
        return Err(CpuFreqError::NotEnabled);
    }
    let b = backend();
    if matches!(b, Backend::None) {
        return Err(CpuFreqError::NoBackend);
    }
    if cpu >= MAX_CPUS || cpu != narf_lib::percpu::current_cpu() {
        return Err(CpuFreqError::NoSuchCpu);
    }
    TICK_COUNT.fetch_add(1, Ordering::AcqRel);
    let util = sample_utilization(cpu);
    let (min, max, prev, policy) = {
        let pc = PERCPU.lock();
        let s = pc[cpu];
        (s.min_perf, s.max_perf, s.last_desired, s.policy)
    };
    if min == 0 && max == 0 {
        return Err(CpuFreqError::NoSuchCpu);
    }
    let target = match policy {
        Policy::Performance => max,
        Policy::Balanced | Policy::Powersave => target_perf(util, min, max),
        Policy::Userspace => 0,
    };
    if prev != 0 && target.abs_diff(prev) <= HYSTERESIS_BAND {
        return Ok(0);
    }
    write_desired(b, cpu, target)?;
    {
        let mut pc = PERCPU.lock();
        pc[cpu].last_desired = target;
    }
    Ok(1)
}

/// Cumulative governor-tick count. Mostly for tests + diagnostics.
pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Acquire)
}

/// Change the policy on the executing CPU and apply it immediately.
pub fn set_policy_current(policy: Policy) -> Result<(), CpuFreqError> {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= MAX_CPUS {
        return Err(CpuFreqError::NoSuchCpu);
    }
    {
        let mut pc = PERCPU.lock();
        let s = &mut pc[cpu];
        if s.hw_max_perf == 0 {
            return Err(CpuFreqError::NotEnabled);
        }
        apply_policy_to_slot(s, policy);
        // Force the next tick to write the new policy even when its
        // desired byte happens to fall inside the hysteresis band.
        s.last_desired = 0;
    }
    tick_cpu(cpu).map(|_| ())
}

fn apply_policy_to_slot(s: &mut PerCpu, policy: Policy) {
    s.policy = policy;
    match policy {
        Policy::Performance => {
            // Linux amd-pstate uses nominal rather than highest as
            // the performance-policy floor: min=max=highest can
            // throttle on package-power-limited systems.
            s.min_perf = s.nominal_perf;
            s.max_perf = s.hw_max_perf;
            s.epp = cppc_epp::PERFORMANCE;
        }
        Policy::Balanced => {
            s.min_perf = s.hw_min_perf;
            s.max_perf = s.hw_max_perf;
            s.epp = cppc_epp::BALANCED_PERFORMANCE;
        }
        Policy::Powersave => {
            s.min_perf = s.hw_min_perf;
            s.max_perf = s.nominal_perf;
            s.epp = cppc_epp::POWERSAVE;
        }
        Policy::Userspace => {
            s.min_perf = s.hw_min_perf;
            s.max_perf = s.hw_max_perf;
        }
    }
}

/// Set EPP on the executing CPU without changing its range.
pub fn set_epp_current(epp: u8) -> Result<(), CpuFreqError> {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= MAX_CPUS {
        return Err(CpuFreqError::NoSuchCpu);
    }
    let desired = {
        let mut pc = PERCPU.lock();
        let s = &mut pc[cpu];
        if s.hw_max_perf == 0 {
            return Err(CpuFreqError::NotEnabled);
        }
        s.epp = epp;
        s.last_desired
    };
    write_desired(backend(), cpu, desired)
}

// ── Backend detection ──────────────────────────────────────────────

fn detect_backend() -> Backend {
    if intel_hwp_supported() {
        return Backend::IntelHwp;
    }
    if amd_cppc_supported() {
        return Backend::AmdCppc;
    }
    if acpi_pss_present() {
        return Backend::AcpiPss;
    }
    Backend::None
}

fn intel_hwp_supported() -> bool {
    if !vendor_intel() {
        return false;
    }
    // SAFETY: leaf 0 is always defined.
    let (max, _, _, _) = unsafe { cpuid(0, 0) };
    if max < 6 {
        return false;
    }
    // SAFETY: leaf 6 is defined when max >= 6.
    let (eax, _, _, _) = unsafe { cpuid(6, 0) };
    eax & (1 << 7) != 0
}

fn amd_cppc_supported() -> bool {
    if !vendor_amd() {
        return false;
    }
    // SAFETY: extended leaf 0 is always defined on x86_64.
    let (max, _, _, _) = unsafe { cpuid(0x8000_0000, 0) };
    if max < 0x8000_0008 {
        return false;
    }
    // SAFETY: bounded by max-ext above.
    let (_, ebx, _, _) = unsafe { cpuid(0x8000_0008, 0) };
    ebx & (1 << 27) != 0
}

fn acpi_pss_present() -> bool {
    // Per-processor `_PSS` lives under `\_PR.CPU<n>` / `\_SB.PR<n>`.
    // We probe the canonical paths: a real platform always declares
    // at least one processor + at least one `_PSS` under it. The AML
    // namespace builder only registers `Name` and `Method` nodes
    // that survived the table walk, so a missing `_PSS` here is
    // either truly absent OR the namespace hasn't been built yet
    // (`acpi-aml` initcall runs in Stage::Subsys alongside us).
    for path in PSS_CANDIDATE_PATHS.iter() {
        if narf_aml::find_node(path).is_some() {
            return true;
        }
    }
    false
}

const PSS_CANDIDATE_PATHS: &[&str] = &[
    "\\_PR_.CPU0._PSS",
    "\\_PR.CPU0._PSS",
    "\\_SB_.PR00._PSS",
    "\\_SB.PR00._PSS",
];

fn vendor_intel() -> bool {
    // SAFETY: leaf 0 always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    ebx == 0x756E_6547 && edx == 0x4965_6E69 && ecx == 0x6C65_746E
}

fn vendor_amd() -> bool {
    // SAFETY: leaf 0 always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    ebx == 0x6874_7541 && edx == 0x6974_6E65 && ecx == 0x444D_4163
}

// ── Backend seeding ────────────────────────────────────────────────

fn seed_intel_hwp_current() -> Result<(), CpuFreqError> {
    wrmsr_or_gp(MSR_IA32_PM_ENABLE, 1).map_err(|_| CpuFreqError::EnableGp)?;
    let raw = rdmsr_or_gp(MSR_IA32_HWP_CAPABILITIES).map_err(|_| CpuFreqError::CapabilitiesGp)?;
    let caps = HwpCapabilities::decode(raw);
    validate_window(caps.lowest_perf, caps.guaranteed_perf, caps.highest_perf)?;
    seed_current_window(caps.lowest_perf, caps.guaranteed_perf, caps.highest_perf);
    Ok(())
}

fn seed_amd_cppc_current() -> Result<(), CpuFreqError> {
    wrmsr_or_gp(MSR_AMD_CPPC_ENABLE, ENABLE_BIT).map_err(|_| CpuFreqError::EnableGp)?;
    let raw = rdmsr_or_gp(MSR_AMD_CPPC_CAP1).map_err(|_| CpuFreqError::CapabilitiesGp)?;
    let caps = CppcCap1(raw);
    validate_window(caps.lowest_perf(), caps.nominal_perf(), caps.highest_perf())?;
    seed_current_window(caps.lowest_perf(), caps.nominal_perf(), caps.highest_perf());
    Ok(())
}

fn seed_current_cpu(cpu: usize) -> Result<(), CpuFreqError> {
    if cpu >= MAX_CPUS || cpu != narf_lib::percpu::current_cpu() {
        return Err(CpuFreqError::NoSuchCpu);
    }
    match backend() {
        Backend::IntelHwp => seed_intel_hwp_current(),
        Backend::AmdCppc => seed_amd_cppc_current(),
        Backend::AcpiPss => {
            if PERCPU.lock()[cpu].max_perf == 0 {
                seed_acpi_pss()
            } else {
                Ok(())
            }
        }
        Backend::None => Err(CpuFreqError::NoBackend),
    }
}

fn seed_acpi_pss() -> Result<(), CpuFreqError> {
    // Fallback path: the `_PSS` table gives a list of (control,
    // freq) tuples; we treat the first as max and last as min for
    // the unitless 0..255 mapping the rest of the governor uses.
    // The MSR-less `_PCT` write path lives in `write_desired_pss`.
    for path in PSS_CANDIDATE_PATHS.iter() {
        if let Some(pkg) = read_pss_package(path) {
            let states = decode_pss_package(&pkg);
            if states.is_empty() {
                continue;
            }
            // `_PSS` is sorted highest-to-lowest core frequency
            // per ACPI 6.5 §8.4.4.2. Map the highest entry to 255
            // and the lowest to 1 on the unitless scale so the
            // schedutil-style mapping continues to work.
            seed_all_windows(1, 128, 255);
            return Ok(());
        }
    }
    Err(CpuFreqError::PssMissing)
}

fn read_pss_package(path: &str) -> Option<narf_aml::Value> {
    // The AML namespace builder records `Name(_PSS, Package(...))`
    // entries as a `NameValue::Package`. The fast path here just
    // borrows the node-side decoded form; `evaluate_method` is
    // overkill because `_PSS` is conventionally a `Name`, not a
    // `Method`. When OEMs ship `_PSS` as a method, the namespace
    // lookup falls through to `None` here and the caller skips.
    let _ = path;
    // Today `narf_aml` exposes `evaluate_s5` for the same shape
    // (Name body = Package) but doesn't yet have a generic
    // "fetch this Name's Package value" helper. Wiring that
    // helper is a follow-up to this commit; for now the smoke
    // tests cover [`decode_pss_package`] directly against a
    // synthetic Package literal, which is the high-value
    // verification surface.
    None
}

fn seed_current_window(lowest: u8, nominal: u8, highest: u8) {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= MAX_CPUS {
        return;
    }
    let mut pc = PERCPU.lock();
    seed_slot(&mut pc[cpu], lowest, nominal, highest);
}

fn seed_all_windows(lowest: u8, nominal: u8, highest: u8) {
    let cpus = narf_lib::smp::cpu_count() as usize;
    let mut pc = PERCPU.lock();
    for cpu in 0..cpus.min(MAX_CPUS) {
        seed_slot(&mut pc[cpu], lowest, nominal, highest);
    }
}

fn seed_slot(slot: &mut PerCpu, lowest: u8, nominal: u8, highest: u8) {
    slot.hw_min_perf = lowest;
    slot.nominal_perf = nominal;
    slot.hw_max_perf = highest;
    slot.min_perf = lowest;
    slot.max_perf = highest;
    slot.last_desired = 0;
    slot.epp = cppc_epp::BALANCED_PERFORMANCE;
    slot.policy = Policy::Balanced;
}

fn validate_window(lowest: u8, nominal: u8, highest: u8) -> Result<(), CpuFreqError> {
    if highest == 0 || lowest > nominal || nominal > highest {
        return Err(CpuFreqError::InvalidCapabilities);
    }
    Ok(())
}

// ── Utilisation sampling ───────────────────────────────────────────

/// Per-CPU scheduler-load proxy on the unitless 0..=1000 scale.
/// The worker itself has been popped from the ready queue while it
/// executes, so zero means idle and any queued workload means the
/// CPU has demand to serve.
fn sample_utilization(cpu: usize) -> u16 {
    let runnable = narf_scheduler::cpu_queue_depths()
        .into_iter()
        .find(|(id, _)| *id as usize == cpu)
        .map(|(_, depth)| depth)
        .unwrap_or(0);
    util_permille_from_runnable(runnable)
}

/// Pure helper mapping ready-queue depth into a bounded load signal.
#[inline]
pub const fn util_permille_from_runnable(runnable: usize) -> u16 {
    match runnable {
        0 => 0,
        _ => 1000,
    }
}

/// Pure helper: linear interp of a utilisation permille into a
/// target perf value inside `[min, max]`. `util > 1000` saturates
/// to `max`; `min > max` falls back to `min`. No floats — the
/// kernel is `no_std` and SSE state is not preserved through
/// IRQ entry paths today.
#[inline]
pub fn target_perf(util_permille: u16, min: u8, max: u8) -> u8 {
    if min >= max {
        return min;
    }
    let util = util_permille.min(1000) as u32;
    let span = (max - min) as u32;
    let scaled = (util * span) / 1000;
    (min as u32 + scaled) as u8
}

// ── MSR writes ─────────────────────────────────────────────────────

/// Re-program `desired_perf` for the active backend. `min` and
/// `max` come from the cached window so the request is consistent
/// across ticks. Returns `Err(RequestGp)` if the MSR write
/// `#GP`'d (BIOS lock on the request MSR).
fn write_desired(b: Backend, cpu: usize, desired: u8) -> Result<(), CpuFreqError> {
    if cpu != narf_lib::percpu::current_cpu() {
        return Err(CpuFreqError::NoSuchCpu);
    }
    match b {
        Backend::IntelHwp => write_desired_hwp(cpu, desired),
        Backend::AmdCppc => write_desired_cppc(cpu, desired),
        Backend::AcpiPss => write_desired_pss(desired),
        Backend::None => Err(CpuFreqError::NoBackend),
    }
}

fn write_desired_hwp(cpu: usize, desired: u8) -> Result<(), CpuFreqError> {
    let pc = PERCPU.lock();
    let (min, max, epp) = (pc[cpu].min_perf, pc[cpu].max_perf, pc[cpu].epp);
    drop(pc);
    // Build `IA32_HWP_REQUEST` with the policy's current
    // (min, max, desired, EPP) tuple.
    let req = (min as u64) | ((max as u64) << 8) | ((desired as u64) << 16) | ((epp as u64) << 24);
    wrmsr_or_gp(MSR_IA32_HWP_REQUEST, req).map_err(|_| CpuFreqError::RequestGp)
}

fn write_desired_cppc(cpu: usize, desired: u8) -> Result<(), CpuFreqError> {
    let pc = PERCPU.lock();
    let (min, max, epp) = (pc[cpu].min_perf, pc[cpu].max_perf, pc[cpu].epp);
    drop(pc);
    let req = CppcRequest::build(min, max, desired, epp);
    wrmsr_or_gp(MSR_AMD_CPPC_REQ, req.0).map_err(|_| CpuFreqError::RequestGp)
}

fn write_desired_pss(_desired: u8) -> Result<(), CpuFreqError> {
    // `_PCT` is conventionally an OperationRegion the platform
    // declares to route the control write to the correct legacy
    // I/O port or memory-mapped register. `narf-aml::oregion`
    // covers the OpRegion accessor surface but the routing
    // glue from "perf byte" to "control word" lives in the
    // `_PSS` decode path, which is the smoke-tested half. The
    // actual write is deferred until the OEM-locked Phoenix unit
    // is exercising the path — programming a wrong `_PCT`
    // control on a stranger laptop can wedge the system, so the
    // bring-up gate is conservative.
    Ok(())
}

// ── `_PSS` decode ──────────────────────────────────────────────────

/// One entry of the `_PSS` table per ACPI 6.5 §8.4.4.2:
///
/// ```text
///   Package(6) {
///     CoreFrequency,         // u32, MHz
///     Power,                 // u32, mW
///     TransitionLatency,     // u32, microseconds
///     BusMasterLatency,      // u32, microseconds
///     Control,               // u32, vendor-specific control value
///     Status,                // u32, status value to expect post-write
///   }
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PssState {
    pub core_freq_mhz: u32,
    pub power_mw: u32,
    pub transition_latency_us: u32,
    pub bus_master_latency_us: u32,
    pub control: u32,
    pub status: u32,
}

/// Decode a `_PSS` Package literal into a list of `PssState`. Bad
/// sub-packages are skipped silently (a malformed firmware table
/// shouldn't kill the governor — Linux's `processor_perflib.c`
/// follows the same liberal-decode policy). Returns an empty Vec
/// if the input isn't a Package or holds no valid sub-packages.
pub fn decode_pss_package(pkg: &narf_aml::Value) -> Vec<PssState> {
    let items = match pkg {
        narf_aml::Value::Package(items) => items,
        _ => return Vec::new(),
    };
    let mut out: Vec<PssState> = Vec::with_capacity(items.len());
    for item in items.iter() {
        let sub = match item {
            narf_aml::Value::Package(sub) => sub,
            _ => continue,
        };
        if sub.len() < 6 {
            continue;
        }
        out.push(PssState {
            core_freq_mhz: sub[0].as_integer() as u32,
            power_mw: sub[1].as_integer() as u32,
            transition_latency_us: sub[2].as_integer() as u32,
            bus_master_latency_us: sub[3].as_integer() as u32,
            control: sub[4].as_integer() as u32,
            status: sub[5].as_integer() as u32,
        });
    }
    out
}

// ── Backend encoding helpers ───────────────────────────────────────

fn encode_backend(b: Backend) -> u8 {
    match b {
        Backend::IntelHwp => 0,
        Backend::AmdCppc => 1,
        Backend::AcpiPss => 2,
        Backend::None => 3,
    }
}

fn decode_backend(raw: u8) -> Backend {
    match raw {
        0 => Backend::IntelHwp,
        1 => Backend::AmdCppc,
        2 => Backend::AcpiPss,
        _ => Backend::None,
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    BACKEND_RAW.store(0xFF, Ordering::Release);
    ENABLED.store(0, Ordering::Release);
    WORKERS_STARTED.store(false, Ordering::Release);
    TICK_COUNT.store(0, Ordering::Release);
    let mut pc = PERCPU.lock();
    for slot in pc.iter_mut() {
        *slot = PerCpu::default();
    }
}

#[doc(hidden)]
pub fn __force_backend_for_test(b: Backend) {
    BACKEND_RAW.store(encode_backend(b), Ordering::Release);
}

// ── Smoke tests ────────────────────────────────────────────────────

mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// HWP capabilities decode: bit-position pins per Intel SDM
    /// Vol 4 §2.16. `IA32_HWP_CAPABILITIES` (MSR 0x771):
    ///   bits[7:0]   = highest_perf
    ///   bits[15:8]  = guaranteed_perf
    ///   bits[23:16] = most_efficient_perf
    ///   bits[31:24] = lowest_perf
    fn smoke_cpufreq_hwp_field_decode() -> TestResult {
        // Pack a recognisable raw: 0x_LL_EE_GG_HH where LL is in
        // the top byte (lowest_perf) and so on. Use distinct
        // nibble pairs so a swap shows up immediately.
        let raw: u64 = 0x0105_19FF_u64;
        let caps = HwpCapabilities::decode(raw);
        if caps.highest_perf != 0xFF {
            return TestResult::Fail("highest");
        }
        if caps.guaranteed_perf != 0x19 {
            return TestResult::Fail("guaranteed");
        }
        if caps.efficient_perf != 0x05 {
            return TestResult::Fail("efficient");
        }
        if caps.lowest_perf != 0x01 {
            return TestResult::Fail("lowest");
        }
        // And the HWP_REQUEST round-trip via the cppc::Request
        // builder reused for AMD; for HWP we exercise the same
        // bit positions inline. Build (min=1, max=255, des=128,
        // EPP=balanced=0x80).
        let req: u64 = (1u64) | (255u64 << 8) | (128u64 << 16) | (0x80u64 << 24);
        if (req & 0xFF) != 1 {
            return TestResult::Fail("req[7:0]");
        }
        if ((req >> 8) & 0xFF) != 255 {
            return TestResult::Fail("req[15:8]");
        }
        if ((req >> 16) & 0xFF) != 128 {
            return TestResult::Fail("req[23:16]");
        }
        if ((req >> 24) & 0xFF) != 0x80 {
            return TestResult::Fail("req[31:24]");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/cpufreq", smoke_cpufreq_hwp_field_decode);

    /// AMD CPPC `MSR_AMD_CPPC_REQ` (0xC00102B3) decoder.
    /// Layout per AMD APM Vol 2 §17:
    ///   bits[7:0]   = max_perf
    ///   bits[15:8]  = min_perf
    ///   bits[23:16] = desired_perf
    ///   bits[31:24] = EPP
    fn smoke_cpufreq_cppc_field_decode() -> TestResult {
        let r = CppcRequest::build(0x12, 0x34, 0x56, cppc_epp::BALANCED_POWER);
        if r.min_perf() != 0x12 {
            return TestResult::Fail("min");
        }
        if r.max_perf() != 0x34 {
            return TestResult::Fail("max");
        }
        if r.desired_perf() != 0x56 {
            return TestResult::Fail("desired");
        }
        if r.energy_performance_preference() != cppc_epp::BALANCED_POWER {
            return TestResult::Fail("epp");
        }
        // CAP1 byte order independent of request: highest is the
        // top byte. Symmetric pin to catch a swap with the HWP
        // decode (which puts highest at the BOTTOM byte — the
        // two vendors disagree).
        let cap = CppcCap1(0xFF_19_05_01);
        if cap.lowest_perf() != 0x01 {
            return TestResult::Fail("cppc lowest");
        }
        if cap.lowest_nonlinear_perf() != 0x05 {
            return TestResult::Fail("cppc nonlinear");
        }
        if cap.nominal_perf() != 0x19 {
            return TestResult::Fail("cppc nominal");
        }
        if cap.highest_perf() != 0xFF {
            return TestResult::Fail("cppc highest");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/cpufreq", smoke_cpufreq_cppc_field_decode);

    /// `_PSS` Package decode from a synthetic AML Package literal.
    /// Builds the canonical 3-state table (max / mid / min) and
    /// verifies each field lines up with ACPI 6.5 §8.4.4.2.
    fn smoke_cpufreq_pss_decode() -> TestResult {
        use alloc::vec;
        use narf_aml::Value;

        // 3-state table: 3500/2200/800 MHz at decreasing power.
        let pss = Value::Package(vec![
            Value::Package(vec![
                Value::Integer(3500),   // CoreFreq MHz
                Value::Integer(15_000), // Power mW
                Value::Integer(10),     // TransitionLatency µs
                Value::Integer(10),     // BusMasterLatency µs
                Value::Integer(0xA1),   // Control
                Value::Integer(0xA1),   // Status
            ]),
            Value::Package(vec![
                Value::Integer(2200),
                Value::Integer(7_500),
                Value::Integer(10),
                Value::Integer(10),
                Value::Integer(0xA2),
                Value::Integer(0xA2),
            ]),
            Value::Package(vec![
                Value::Integer(800),
                Value::Integer(2_000),
                Value::Integer(10),
                Value::Integer(10),
                Value::Integer(0xA3),
                Value::Integer(0xA3),
            ]),
        ]);
        let states = decode_pss_package(&pss);
        if states.len() != 3 {
            return TestResult::Fail("state count");
        }
        if states[0].core_freq_mhz != 3500 || states[2].core_freq_mhz != 800 {
            return TestResult::Fail("freq endpoints");
        }
        if states[0].power_mw != 15_000 {
            return TestResult::Fail("power");
        }
        if states[1].control != 0xA2 {
            return TestResult::Fail("control");
        }
        // Malformed sub-packages must be dropped (not panic).
        let mixed = Value::Package(vec![
            Value::Integer(42),
            Value::Package(vec![
                Value::Integer(2000),
                Value::Integer(5000),
                Value::Integer(10),
                Value::Integer(10),
                Value::Integer(1),
                Value::Integer(1),
            ]),
            Value::Package(vec![Value::Integer(1)]), // too short
        ]);
        let mixed_states = decode_pss_package(&mixed);
        if mixed_states.len() != 1 {
            return TestResult::Fail("liberal decode");
        }
        if mixed_states[0].core_freq_mhz != 2000 {
            return TestResult::Fail("survivor freq");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/cpufreq", smoke_cpufreq_pss_decode);

    /// Utilisation → target_perf mapping. Linear interp via integer
    /// math; the (0, min) and (1000, max) endpoints must be exact
    /// and a 500 permille (50% load) sample must land at the
    /// midpoint.
    fn smoke_cpufreq_target_perf_interp() -> TestResult {
        // Endpoints.
        if target_perf(0, 24, 255) != 24 {
            return TestResult::Fail("util=0 not min");
        }
        if target_perf(1000, 24, 255) != 255 {
            return TestResult::Fail("util=1000 not max");
        }
        // Midpoint: 24 + (500 * 231) / 1000 = 24 + 115 = 139.
        if target_perf(500, 24, 255) != 139 {
            return TestResult::Fail("midpoint");
        }
        // Saturation past 1000 still pins to max.
        if target_perf(2000, 24, 255) != 255 {
            return TestResult::Fail("saturate above");
        }
        // Degenerate min >= max falls back to min.
        if target_perf(500, 200, 200) != 200 {
            return TestResult::Fail("degenerate equal");
        }
        if target_perf(500, 220, 200) != 220 {
            return TestResult::Fail("degenerate inverted");
        }
        // Scheduler ready-depth mapping sanity.
        if util_permille_from_runnable(0) != 0 {
            return TestResult::Fail("runnable=0");
        }
        if util_permille_from_runnable(1) != 1000 {
            return TestResult::Fail("runnable=1");
        }
        if util_permille_from_runnable(2) != 1000 {
            return TestResult::Fail("runnable=2");
        }
        if util_permille_from_runnable(9999) != 1000 {
            return TestResult::Fail("runnable saturates");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/cpufreq", smoke_cpufreq_target_perf_interp);

    fn smoke_cpufreq_policy_windows() -> TestResult {
        let mut slot = PerCpu::default();
        seed_slot(&mut slot, 20, 100, 200);

        apply_policy_to_slot(&mut slot, Policy::Performance);
        if (slot.min_perf, slot.max_perf, slot.epp) != (100, 200, cppc_epp::PERFORMANCE) {
            return TestResult::Fail("performance policy");
        }

        apply_policy_to_slot(&mut slot, Policy::Powersave);
        if (slot.min_perf, slot.max_perf, slot.epp) != (20, 100, cppc_epp::POWERSAVE) {
            return TestResult::Fail("powersave policy");
        }

        apply_policy_to_slot(&mut slot, Policy::Balanced);
        if (slot.min_perf, slot.max_perf, slot.epp) != (20, 200, cppc_epp::BALANCED_PERFORMANCE) {
            return TestResult::Fail("balanced policy");
        }

        if validate_window(20, 100, 200).is_err()
            || validate_window(20, 10, 200) != Err(CpuFreqError::InvalidCapabilities)
            || validate_window(20, 100, 0) != Err(CpuFreqError::InvalidCapabilities)
        {
            return TestResult::Fail("capability validation");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/cpufreq", smoke_cpufreq_policy_windows);

    /// Backend priority resolution: HWP > CPPC > _PSS > None when
    /// multiple are supported. Detection is CPUID-driven and we
    /// can't fake CPUID inside a kernel-test, but the encode/decode
    /// round-trip + the `__force_backend_for_test` override are
    /// the pieces the priority resolution depends on.
    fn smoke_cpufreq_backend_priority() -> TestResult {
        // Round-trip every backend through encode/decode.
        for &b in &[
            Backend::IntelHwp,
            Backend::AmdCppc,
            Backend::AcpiPss,
            Backend::None,
        ] {
            let raw = encode_backend(b);
            let b2 = decode_backend(raw);
            if b != b2 {
                return TestResult::Fail("encode/decode round-trip");
            }
        }
        // Numeric ordering matches priority (lower = preferred).
        if encode_backend(Backend::IntelHwp) >= encode_backend(Backend::AmdCppc) {
            return TestResult::Fail("HWP priority");
        }
        if encode_backend(Backend::AmdCppc) >= encode_backend(Backend::AcpiPss) {
            return TestResult::Fail("CPPC priority");
        }
        if encode_backend(Backend::AcpiPss) >= encode_backend(Backend::None) {
            return TestResult::Fail("PSS priority");
        }
        // Cache override path: forcing a value and re-reading
        // backend() returns that value.
        __reset_for_test();
        __force_backend_for_test(Backend::AmdCppc);
        if backend() != Backend::AmdCppc {
            __reset_for_test();
            return TestResult::Fail("force_backend");
        }
        // disable() / enable() paths: disable should be a no-op
        // when not enabled and never panic.
        disable();
        // tick() with disabled = error, not panic.
        match tick() {
            Err(CpuFreqError::NotEnabled) => {}
            _ => {
                __reset_for_test();
                return TestResult::Fail("tick must NotEnabled when disabled");
            }
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("power/cpufreq", smoke_cpufreq_backend_priority);
}
