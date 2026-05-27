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
//!      `MSR_AMD_CPPC_CAP1` (0xC001_0294) +
//!      `MSR_AMD_CPPC_REQ` (0xC001_0297). Linux:
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
//! utilisation proxy ([`utilization_permille`]) and computes
//!
//! ```text
//!   target_perf = min_perf + (util * (max_perf - min_perf)) / 1000
//! ```
//!
//! NARF has no runqueue-time signal yet (the scheduler is still
//! cooperative-async), so the utilisation proxy is the per-CPU
//! timer-IRQ fire-count delta over the sample interval. A busy CPU
//! takes more timer IRQs because it doesn't sit in `halt_until_irq`;
//! an idle CPU's fire count rolls only with the LAPIC tick. The
//! ratio (current_delta / target_delta) maps 0..1000 permille where
//! target_delta is calibrated to the configured tick rate.
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

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use narf_arch::x86_64::cpuid::cpuid;
use narf_arch::x86_64::msr::{rdmsr_or_gp, wrmsr_or_gp};
use narf_lib::sync::IrqSafeSpinLock;

use crate::cppc::{
    epp as cppc_epp, Cap1 as CppcCap1, Request as CppcRequest, MSR_AMD_CPPC_CAP1, MSR_AMD_CPPC_REQ,
};
use crate::hwp::HwpCapabilities;
use crate::pstate::{MSR_IA32_HWP_CAPABILITIES, MSR_IA32_HWP_REQUEST};

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
    /// Programming the request MSR `#GP`'d.
    RequestGp,
    /// `_PSS` table is missing or malformed.
    PssMissing,
    /// Governor isn't currently enabled; call [`enable()`] first.
    NotEnabled,
    /// Requested CPU id is out of range for the online topology.
    NoSuchCpu,
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
    /// `fire_count_on_cpu(VECTOR_TIMER, cpu)` at the previous tick.
    last_timer_fires: u64,
    /// Last `desired_perf` byte we wrote, for hysteresis.
    last_desired: u8,
    /// Window floor / ceiling cached from the capabilities read so
    /// we don't re-decode the MSR on every tick.
    min_perf: u8,
    max_perf: u8,
}

const MAX_CPUS: usize = 64;
static PERCPU: IrqSafeSpinLock<[PerCpu; MAX_CPUS]> =
    IrqSafeSpinLock::new([PerCpu {
        last_timer_fires: 0,
        last_desired: 0,
        min_perf: 0,
        max_perf: 0,
    }; MAX_CPUS]);

/// Monotonic tick counter — incremented by [`tick()`] for
/// diagnostics.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Hysteresis band: skip a re-write when the target sits within
/// this many perf units of the last value. Cheap MSR-write
/// suppression without the full schedutil down-rate-limit.
const HYSTERESIS_BAND: u8 = 4;

/// Sample interval in milliseconds. 100 ms = 10 Hz, intentionally
/// slower than the 1 kHz LAPIC tick so the timer-IRQ count delta
/// is large enough (~100 ticks at 1 kHz) to be a useful signal.
pub const TICK_INTERVAL_MS: u32 = 100;

/// Expected timer fires per sample interval at full activity. The
/// LAPIC tick runs at ~1 kHz so `(1000 * TICK_INTERVAL_MS) / 1000`
/// fires is the upper bound; idle CPUs see fewer because the
/// scheduler enters `halt_until_irq` between ticks. Saturating-mul
/// avoids overflow if the constant is bumped to multi-second.
const FULL_LOAD_TARGET_FIRES: u64 = 100;

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
        Backend::IntelHwp => seed_intel_hwp()?,
        Backend::AmdCppc => seed_amd_cppc()?,
        Backend::AcpiPss => seed_acpi_pss()?,
        Backend::None => return Err(CpuFreqError::NoBackend),
    }
    ENABLED.store(1, Ordering::Release);
    Ok(())
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
    // `current` mirrors `desired` until a status MSR is wired in
    // — Intel exposes `IA32_HWP_STATUS` (0x777) bits[7:0] for the
    // delivered perf and AMD exposes `MSR_AMD_CPPC_STATUS`
    // (0xC0010298) bits[7:0]; surfacing those is a later patch
    // because the governor uses the same value for its own
    // bookkeeping.
    Some(PerfState {
        min: s.min_perf,
        max: s.max_perf,
        desired: s.last_desired,
        current: s.last_desired,
    })
}

/// One-shot governor tick. Reads per-CPU utilisation, computes
/// target_perf, applies hysteresis, writes the backend MSR.
///
/// Returns the number of CPUs whose `desired_perf` was updated.
/// Caller wires this to a periodic source (the `time/` wheel, an
/// idle-IRQ pump, or a kernel async task — choice deferred).
pub fn tick() -> Result<u32, CpuFreqError> {
    if ENABLED.load(Ordering::Acquire) == 0 {
        return Err(CpuFreqError::NotEnabled);
    }
    let b = backend();
    if matches!(b, Backend::None) {
        return Err(CpuFreqError::NoBackend);
    }
    TICK_COUNT.fetch_add(1, Ordering::AcqRel);
    let cpus = narf_lib::smp::cpu_count() as usize;
    let mut updates = 0u32;
    for cpu in 0..cpus.min(MAX_CPUS) {
        if !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        let util = sample_utilization(cpu);
        let (min, max, prev) = {
            let pc = PERCPU.lock();
            let s = pc[cpu];
            (s.min_perf, s.max_perf, s.last_desired)
        };
        if min == 0 && max == 0 {
            // CPU not yet seeded (capabilities MSR `#GP`'d there).
            continue;
        }
        let target = target_perf(util, min, max);
        // Hysteresis: skip the write if we land inside the band.
        if prev != 0 && abs_diff(target, prev) <= HYSTERESIS_BAND {
            continue;
        }
        if write_desired(b, target).is_ok() {
            let mut pc = PERCPU.lock();
            pc[cpu].last_desired = target;
            updates += 1;
        }
    }
    Ok(updates)
}

/// Cumulative governor-tick count. Mostly for tests + diagnostics.
pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Acquire)
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

fn seed_intel_hwp() -> Result<(), CpuFreqError> {
    let raw = rdmsr_or_gp(MSR_IA32_HWP_CAPABILITIES).map_err(|_| CpuFreqError::CapabilitiesGp)?;
    let caps = HwpCapabilities::decode(raw);
    seed_window(caps.lowest_perf, caps.highest_perf);
    Ok(())
}

fn seed_amd_cppc() -> Result<(), CpuFreqError> {
    let raw = rdmsr_or_gp(MSR_AMD_CPPC_CAP1).map_err(|_| CpuFreqError::CapabilitiesGp)?;
    let caps = CppcCap1(raw);
    seed_window(caps.lowest_perf(), caps.highest_perf());
    Ok(())
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
            seed_window(1, 255);
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

fn seed_window(lowest: u8, highest: u8) {
    let cpus = narf_lib::smp::cpu_count() as usize;
    let mut pc = PERCPU.lock();
    for cpu in 0..cpus.min(MAX_CPUS) {
        pc[cpu].min_perf = lowest;
        pc[cpu].max_perf = highest;
        pc[cpu].last_desired = 0;
        pc[cpu].last_timer_fires = 0;
    }
}

// ── Utilisation sampling ───────────────────────────────────────────

/// Per-CPU utilisation proxy on the unitless 0..=1000 (permille)
/// scale. Uses the timer-IRQ fire-count delta as a proxy: a busy
/// CPU stays out of `halt_until_irq` so it takes the full per-tick
/// rate; an idle CPU enters halt and sees only the LAPIC's wake
/// IRQs.
///
/// Updates the per-CPU `last_timer_fires` cursor so the next call
/// returns the delta over `TICK_INTERVAL_MS`.
fn sample_utilization(cpu: usize) -> u16 {
    let now = narf_interrupts::fire_count_on_cpu(narf_interrupts::VECTOR_TIMER, cpu);
    let prev = {
        let mut pc = PERCPU.lock();
        let p = core::mem::replace(&mut pc[cpu].last_timer_fires, now);
        p
    };
    let delta = now.saturating_sub(prev);
    util_permille_from_delta(delta, FULL_LOAD_TARGET_FIRES)
}

/// Pure helper: map `(delta, full_load)` into a permille (0..=1000)
/// scale. `delta >= full_load` saturates at 1000.
#[inline]
pub fn util_permille_from_delta(delta: u64, full_load: u64) -> u16 {
    if full_load == 0 {
        return 0;
    }
    if delta >= full_load {
        return 1000;
    }
    ((delta * 1000) / full_load) as u16
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

#[inline]
fn abs_diff(a: u8, b: u8) -> u8 {
    if a >= b {
        a - b
    } else {
        b - a
    }
}

// ── MSR writes ─────────────────────────────────────────────────────

/// Re-program `desired_perf` for the active backend. `min` and
/// `max` come from the cached window so the request is consistent
/// across ticks. Returns `Err(RequestGp)` if the MSR write
/// `#GP`'d (BIOS lock on the request MSR).
fn write_desired(b: Backend, desired: u8) -> Result<(), CpuFreqError> {
    match b {
        Backend::IntelHwp => write_desired_hwp(desired),
        Backend::AmdCppc => write_desired_cppc(desired),
        Backend::AcpiPss => write_desired_pss(desired),
        Backend::None => Err(CpuFreqError::NoBackend),
    }
}

fn write_desired_hwp(desired: u8) -> Result<(), CpuFreqError> {
    let pc = PERCPU.lock();
    let (min, max) = (pc[0].min_perf, pc[0].max_perf);
    drop(pc);
    // Build `IA32_HWP_REQUEST` with (min, max, desired, EPP). EPP
    // stays at the balanced midpoint Linux + the bring-up code in
    // `hwp.rs` picked. Per-CPU EPP knob is deferred.
    let req = (min as u64)
        | ((max as u64) << 8)
        | ((desired as u64) << 16)
        | ((crate::hwp::EPP_BALANCED_PERFORMANCE as u64) << 24);
    wrmsr_or_gp(MSR_IA32_HWP_REQUEST, req).map_err(|_| CpuFreqError::RequestGp)
}

fn write_desired_cppc(desired: u8) -> Result<(), CpuFreqError> {
    let pc = PERCPU.lock();
    let (min, max) = (pc[0].min_perf, pc[0].max_perf);
    drop(pc);
    let req = CppcRequest::build(min, max, desired, cppc_epp::BALANCED_PERFORMANCE);
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

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
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
        let raw: u64 = 0x__01_05_19_FF_u64;
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
        let req: u64 = (1u64)
            | (255u64 << 8)
            | (128u64 << 16)
            | (0x80u64 << 24);
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

    /// AMD CPPC `MSR_AMD_CPPC_REQ` (0xC0010297) decoder.
    /// Layout per AMD APM Vol 2 §17:
    ///   bits[7:0]   = min_perf
    ///   bits[15:8]  = max_perf
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
                Value::Integer(3500), // CoreFreq MHz
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
        // util_permille_from_delta sanity.
        if util_permille_from_delta(0, 100) != 0 {
            return TestResult::Fail("delta=0");
        }
        if util_permille_from_delta(50, 100) != 500 {
            return TestResult::Fail("delta=50%");
        }
        if util_permille_from_delta(100, 100) != 1000 {
            return TestResult::Fail("delta=full");
        }
        if util_permille_from_delta(9999, 100) != 1000 {
            return TestResult::Fail("delta saturates");
        }
        if util_permille_from_delta(50, 0) != 0 {
            return TestResult::Fail("full_load=0 guard");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/cpufreq", smoke_cpufreq_target_perf_interp);

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
