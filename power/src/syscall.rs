//! CPU power-management syscall surface — clean-room.
//!
//! Hangs off the existing `narf-abi` Submission/Completion ring
//! via a per-OpCode bridge function. Userspace pushes a
//! `Submission { op: OpCode::Cpu*, inline: [...] }`; the kernel
//! routes through [`dispatch`] which checks the relevant cap +
//! current-CPU policy and forwards to the right `power` module.
//!
//! ## Cap-types
//!
//! - [`CpuTelemetry`] — read-only access to perf state, RAPL
//!   energy, C-state residency. Granted broadly (every process
//!   gets one at exec).
//! - [`CpuLatency`] — PM-QOS-style latency hints. The most a
//!   non-TCB process can do; can only *increase* power, not
//!   bypass anything.
//! - [`CpuPower`] — frequency range, EPP, governor write. Granted
//!   to the system-wide power-management daemon and (narrowed) to
//!   apps that opt into self-tuning.
//! - [`CpuBudget`] — RAPL-backed energy quota. Phase 4.
//!
//! ## Per-CPU scoping
//!
//! For non-TCB cap holders, the requested `cpu_id` MUST equal
//! `narf_arch::current_cpu_id()` at syscall time — i.e. each
//! thread can only tune the CPU it's running on. TCB cap holders
//! (`Cap<CpuPower, Grant>`) bypass this; the power daemon uses
//! that to adjust any CPU.
//!
//! Targeting other-than-current via a non-TCB cap returns
//! `NarfStatus::Forbidden`.

extern crate alloc;
use alloc::vec::Vec;

use narf_capabilities::{CapKind, CapType};

// ── Cap-type markers ─────────────────────────────────────────────

#[derive(Copy, Clone, Debug)]
pub struct CpuTelemetry;

impl CapType for CpuTelemetry {
    const KIND: CapKind = CapKind::CpuTelemetry;
}

#[derive(Copy, Clone, Debug)]
pub struct CpuLatency;

impl CapType for CpuLatency {
    const KIND: CapKind = CapKind::FreqHint;
}

#[derive(Copy, Clone, Debug)]
pub struct CpuPower;

impl CapType for CpuPower {
    const KIND: CapKind = CapKind::Power;
}

#[derive(Copy, Clone, Debug)]
pub struct CpuBudget;

impl CapType for CpuBudget {
    const KIND: CapKind = CapKind::CpuBudget;
}

// ── Submission inline-arg layout ─────────────────────────────────

/// `cpu_id` value sent in `Submission::inline[0]`. The constant
/// `CPU_ID_CURRENT` is a sentinel that means "the CPU I'm running
/// on right now"; any other value is treated as a specific id.
pub const CPU_ID_CURRENT: u64 = u64::MAX;

/// Whether a request that names a specific cpu_id is allowed.
/// Encapsulates the TCB-bypass + current-cpu-only policy in one
/// helper.
pub fn cpu_id_allowed(cpu_id: u64, is_tcb: bool, current: u64) -> bool {
    if cpu_id == CPU_ID_CURRENT {
        return true;
    }
    is_tcb || cpu_id == current
}

/// Resolve a request's `cpu_id` to a concrete numeric id. Returns
/// `None` if the policy denies the request.
pub fn resolve_cpu_id(cpu_id: u64, is_tcb: bool, current: u64) -> Option<u64> {
    if !cpu_id_allowed(cpu_id, is_tcb, current) {
        return None;
    }
    Some(if cpu_id == CPU_ID_CURRENT {
        current
    } else {
        cpu_id
    })
}

// ── Decoded perf-state shape (Phase 1) ────────────────────────────

/// Snapshot of a CPU's runtime performance state. Returned by
/// `OpCode::CpuPerfState`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PerfState {
    /// Reported delivered performance, 0..=255 (CPPC). For Intel
    /// this is the firmware's HWP_STATUS.Current_Performance byte
    /// scaled to 0..=255.
    pub delivered_perf: u8,
    /// EPP (Energy Performance Preference), 0..=255.
    pub epp: u8,
    /// Last-known C-state hint depth (0 = active).
    pub c_state: u8,
    /// APERF / MPERF / TSC at sample time. Userspace can take
    /// successive samples to compute the ratio
    /// (APERF_delta / MPERF_delta) which is the CPU's actual
    /// frequency relative to TSC.
    pub aperf: u64,
    pub mperf: u64,
    pub tsc: u64,
}

/// Pack `PerfState` into the 6 `result[]` slots of a Completion.
/// Layout:
///
/// ```text
///   result[0]  = (delivered_perf as u8) | (epp << 8) | (c_state << 16)
///   result[1]  = aperf
///   result[2]  = mperf
///   result[3]  = tsc
///   result[4]  = 0 (reserved)
///   result[5]  = 0 (reserved)
/// ```
pub fn pack_perf_state(s: PerfState) -> [u64; 6] {
    let bundled = (s.delivered_perf as u64) | ((s.epp as u64) << 8) | ((s.c_state as u64) << 16);
    [bundled, s.aperf, s.mperf, s.tsc, 0, 0]
}

pub fn unpack_perf_state(r: [u64; 6]) -> PerfState {
    PerfState {
        delivered_perf: (r[0] & 0xFF) as u8,
        epp: ((r[0] >> 8) & 0xFF) as u8,
        c_state: ((r[0] >> 16) & 0xFF) as u8,
        aperf: r[1],
        mperf: r[2],
        tsc: r[3],
    }
}

// ── RAPL domain (Phase 1 / Phase 4) ──────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RaplDomain {
    /// Whole-package energy (`MSR_PKG_ENERGY_STATUS` on Intel,
    /// `MSR_AMD_PKG_ENERGY_STAT` on AMD).
    Package = 0,
    /// PP0 — cores. Intel only.
    Cores = 1,
    /// PP1 — graphics. Intel client parts.
    Graphics = 2,
    /// DRAM — server platforms.
    Dram = 3,
}

impl RaplDomain {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Package,
            1 => Self::Cores,
            2 => Self::Graphics,
            3 => Self::Dram,
            _ => return None,
        })
    }
}

// ── Topology (Phase 1) ───────────────────────────────────────────

/// Whole-system CPU topology. Returned by `OpCode::CpuTopology` —
/// userspace consumes `count`+`cpus` to drive its own per-CPU
/// loops.
#[derive(Clone, Debug, Default)]
pub struct CpuTopology {
    pub count: u32,
    pub package_count: u32,
    /// `count` entries; index `i` describes logical CPU `i`.
    pub cpus: Vec<CpuDescriptor>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuDescriptor {
    pub package_id: u16,
    pub core_id: u16,
    /// SMT id within `core_id`, 0 = primary thread.
    pub smt_id: u8,
    /// `true` if the CPU is currently online (parked CPUs are
    /// listed but `online == false`).
    pub online: bool,
    /// Lowest / nominal / highest declared performance (CPPC
    /// 0..=255 normalised). For Intel HWP, derived from
    /// HWP_CAPABILITIES; for AMD CPPC, from the CAP1 MSR.
    pub lowest_perf: u8,
    pub nominal_perf: u8,
    pub highest_perf: u8,
}

// ── Latency hint (Phase 2) ───────────────────────────────────────

/// Token returned by `OpCode::CpuIdleLatencyHint`. The hint stays
/// active until the token is dropped by `OpCode::CpuIdleRelease`
/// (or until the holder process exits, which the kernel reaps).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LatencyToken(pub u64);

// ── Governor (Phase 3) ───────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Governor {
    /// Performance: max EPP, min == max == highest_perf.
    Performance = 0,
    /// Balanced (default): EPP = 0x40, range = lowest..=highest.
    Balanced = 1,
    /// Powersave: EPP = 0xFF, range = lowest..=nominal.
    Powersave = 2,
    /// Userspace: leaves the firmware in autonomous mode but
    /// allows the holder to override EPP / range manually.
    Userspace = 3,
}

impl Governor {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Performance,
            1 => Self::Balanced,
            2 => Self::Powersave,
            3 => Self::Userspace,
            _ => return None,
        })
    }
}

// ── Bridge handler ────────────────────────────────────────────────

pub use narf_abi::{CpuOpArgs, CpuOpKind, CpuOpReturn};

/// `NarfStatus` discriminants — kept in sync with the enum in
/// `narf-abi`. Duplicated rather than `as u32`-cast so we don't
/// transitively depend on the enum layout.
const STATUS_OK: u32 = 0;
const STATUS_INVALID_OP: u32 = 5;
const STATUS_FORBIDDEN: u32 = 8;
const STATUS_UNSUPPORTED: u32 = 9;

// ── Capability probes (overridable for deterministic tests) ──────
//
// On QEMU TCG the host typically lacks HWP / CPPC / RAPL, so the
// live probes report "no DVFS" and write paths return Unsupported.
// Tests inject a synthetic mechanism via `__set_caps_for_test` to
// exercise the Ok path independent of the host CPU.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PowerCaps {
    /// `true` when at least one DVFS mechanism (HWP / CPPC / EIST /
    /// AMD legacy / PSCI cpufreq) is present.
    pub has_dvfs: bool,
    /// `true` when RAPL energy counters are accessible.
    pub has_rapl: bool,
}

static CAPS_OVERRIDE: narf_lib::sync::IrqSafeSpinLock<Option<PowerCaps>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn detect_caps() -> PowerCaps {
    if let Some(o) = *CAPS_OVERRIDE.lock() {
        return o;
    }
    detect_caps_live()
}

#[cfg(target_arch = "x86_64")]
fn detect_caps_live() -> PowerCaps {
    use crate::pstate::Mechanism;
    PowerCaps {
        has_dvfs: !matches!(crate::pstate::detect(), Mechanism::None),
        has_rapl: crate::rapl::is_supported(),
    }
}

#[cfg(target_arch = "aarch64")]
fn detect_caps_live() -> PowerCaps {
    // ARM cpufreq is exposed through PSCI / SCMI on real hardware;
    // the kernel doesn't yet probe either at boot, so the honest
    // answer for now is "no DVFS." Tests that need the Ok path
    // override.
    PowerCaps {
        has_dvfs: false,
        has_rapl: false,
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn detect_caps_live() -> PowerCaps {
    PowerCaps {
        has_dvfs: false,
        has_rapl: false,
    }
}

#[doc(hidden)]
pub fn __set_caps_for_test(caps: Option<PowerCaps>) {
    *CAPS_OVERRIDE.lock() = caps;
}

/// Kernel-side bridge handler for ring-issued CPU power ops.
/// Resolves cpu_id, applies the current-CPU policy (non-TCB only
/// hits the CPU it's running on), forwards to the matching
/// `power` module, packs the result.
///
/// `current_cpu` is the CPU the syscall is currently running on
/// (caller-supplied so this fn stays pure / testable).
pub fn handle(kind: CpuOpKind, args: &CpuOpArgs, current_cpu: u64) -> CpuOpReturn {
    // Userspace bridge: always non-TCB. Kernel-internal callers use
    // `power::*` directly, bypassing the cap+cpu policy.
    let is_tcb = false;

    match kind {
        // ── Phase 1: read-only telemetry ────────────────────────
        CpuOpKind::Topology => {
            // Topology is whole-system data; no per-CPU policy
            // (every process can read it). The bridge hands back
            // (cpu_count, package_count) inline + leaves the
            // detailed CPU-descriptor slab to a Future addition
            // that takes a user-supplied output buffer.
            let topo = read_topology();
            let mut result = [0u64; 6];
            result[0] = topo.count as u64;
            result[1] = topo.package_count as u64;
            CpuOpReturn {
                status: STATUS_OK,
                result,
            }
        }
        CpuOpKind::PerfState => {
            let cpu = match resolve_cpu_id(args.a0, is_tcb, current_cpu) {
                Some(c) => c,
                None => return forbidden(),
            };
            let s = read_perf_state(cpu);
            CpuOpReturn {
                status: STATUS_OK,
                result: pack_perf_state(s),
            }
        }
        CpuOpKind::RaplEnergy => {
            let cpu = match resolve_cpu_id(args.a0, is_tcb, current_cpu) {
                Some(c) => c,
                None => return forbidden(),
            };
            let domain = match RaplDomain::from_u8(args.a1 as u8) {
                Some(d) => d,
                None => {
                    return CpuOpReturn {
                        status: STATUS_INVALID_OP,
                        result: [0; 6],
                    }
                }
            };
            if !detect_caps().has_rapl {
                return unsupported();
            }
            let uj = read_rapl_energy_uj(cpu, domain);
            let mut result = [0u64; 6];
            result[0] = uj;
            CpuOpReturn {
                status: STATUS_OK,
                result,
            }
        }

        // ── Phase 2: latency hints ──────────────────────────────
        CpuOpKind::LatencyHint => {
            let max_idle_us = args.a0 as u32;
            let token = register_latency_hint(max_idle_us);
            let mut result = [0u64; 6];
            result[0] = token.0;
            CpuOpReturn {
                status: STATUS_OK,
                result,
            }
        }
        CpuOpKind::LatencyRelease => {
            release_latency_hint(LatencyToken(args.a0));
            CpuOpReturn {
                status: STATUS_OK,
                result: [0; 6],
            }
        }

        // ── Phase 3: frequency control (write path) ─────────────
        CpuOpKind::SetFreqRange => {
            let cpu = match resolve_cpu_id(args.a0, is_tcb, current_cpu) {
                Some(c) => c,
                None => return forbidden(),
            };
            if !detect_caps().has_dvfs {
                return unsupported();
            }
            let min_khz = args.a1 as u32;
            let max_khz = args.a2 as u32;
            let (applied_min, applied_max) = apply_freq_range(cpu, min_khz, max_khz);
            let mut result = [0u64; 6];
            result[0] = applied_min as u64;
            result[1] = applied_max as u64;
            CpuOpReturn {
                status: STATUS_OK,
                result,
            }
        }
        CpuOpKind::SetEpp => {
            let cpu = match resolve_cpu_id(args.a0, is_tcb, current_cpu) {
                Some(c) => c,
                None => return forbidden(),
            };
            if !detect_caps().has_dvfs {
                return unsupported();
            }
            apply_epp(cpu, args.a1 as u8);
            CpuOpReturn {
                status: STATUS_OK,
                result: [0; 6],
            }
        }
        CpuOpKind::SetGovernor => {
            let cpu = match resolve_cpu_id(args.a0, is_tcb, current_cpu) {
                Some(c) => c,
                None => return forbidden(),
            };
            let gov = match Governor::from_u8(args.a1 as u8) {
                Some(g) => g,
                None => {
                    return CpuOpReturn {
                        status: STATUS_INVALID_OP,
                        result: [0; 6],
                    }
                }
            };
            if !detect_caps().has_dvfs {
                return unsupported();
            }
            apply_governor(cpu, gov);
            CpuOpReturn {
                status: STATUS_OK,
                result: [0; 6],
            }
        }

        // ── Phase 4: energy budget ──────────────────────────────
        CpuOpKind::SetEnergyBudget => {
            let domain = match RaplDomain::from_u8(args.a0 as u8) {
                Some(d) => d,
                None => {
                    return CpuOpReturn {
                        status: STATUS_INVALID_OP,
                        result: [0; 6],
                    }
                }
            };
            if !detect_caps().has_rapl {
                return unsupported();
            }
            let window_ms = args.a1 as u32;
            let energy_mj = args.a2 as u32;
            apply_energy_budget(domain, window_ms, energy_mj);
            CpuOpReturn {
                status: STATUS_OK,
                result: [0; 6],
            }
        }
        CpuOpKind::ClearEnergyBudget => {
            let domain = match RaplDomain::from_u8(args.a0 as u8) {
                Some(d) => d,
                None => {
                    return CpuOpReturn {
                        status: STATUS_INVALID_OP,
                        result: [0; 6],
                    }
                }
            };
            if !detect_caps().has_rapl {
                return unsupported();
            }
            clear_energy_budget(domain);
            CpuOpReturn {
                status: STATUS_OK,
                result: [0; 6],
            }
        }
    }
}

fn unsupported() -> CpuOpReturn {
    CpuOpReturn {
        status: STATUS_UNSUPPORTED,
        result: [0; 6],
    }
}

fn forbidden() -> CpuOpReturn {
    CpuOpReturn {
        status: STATUS_FORBIDDEN,
        result: [0; 6],
    }
}

// ── Concrete handlers — Phase 1 ──────────────────────────────────
//
// Stage-1 implementations: read what the existing power/ modules
// already expose. RAPL / per-CPU MSR access is currently kernel-
// only on x86_64; on aarch64 we return zeros until PSCI / per-SoC
// glue is wired.

fn read_topology() -> CpuTopology {
    // Stage-1: report a single online CPU until we wire the SMP
    // topology walker (frame::measure already counts cores; this
    // module will pick that up in a follow-up). Higher-level code
    // can rely on a non-zero count to mean "topology API is live".
    CpuTopology {
        count: 1,
        package_count: 1,
        cpus: alloc::vec![CpuDescriptor {
            online: true,
            ..Default::default()
        }],
    }
}

fn read_perf_state(_cpu: u64) -> PerfState {
    // Stage-1: return zeroed state until the per-CPU MSR pump
    // is wired through arch::msr. Userspace uses non-zero
    // delivered_perf as a "capability live" probe.
    PerfState::default()
}

fn read_rapl_energy_uj(_cpu: u64, _domain: RaplDomain) -> u64 {
    // Stage-1: zero until rapl::read_domain wires through.
    0
}

// ── Concrete handlers — Phase 2 ──────────────────────────────────

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_LATENCY_TOKEN: AtomicU64 = AtomicU64::new(1);
static LATENCY_HINTS: narf_lib::sync::IrqSafeSpinLock<Vec<(LatencyToken, u32)>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

fn register_latency_hint(max_idle_us: u32) -> LatencyToken {
    let id = NEXT_LATENCY_TOKEN.fetch_add(1, Ordering::Relaxed);
    let t = LatencyToken(id);
    LATENCY_HINTS.lock().push((t, max_idle_us));
    t
}

fn release_latency_hint(token: LatencyToken) {
    let mut g = LATENCY_HINTS.lock();
    if let Some(pos) = g.iter().position(|(t, _)| *t == token) {
        g.swap_remove(pos);
    }
}

/// Strictest active hint — minimum of every registered max-idle.
/// Returned as `Some(microseconds)` or `None` if no hints active.
/// The C-state selector consults this every time it picks a depth.
pub fn current_latency_floor_us() -> Option<u32> {
    LATENCY_HINTS.lock().iter().map(|(_, us)| *us).min()
}

#[doc(hidden)]
pub fn __reset_latency_hints_for_test() {
    LATENCY_HINTS.lock().clear();
    NEXT_LATENCY_TOKEN.store(1, Ordering::Relaxed);
}

// ── Concrete handlers — Phase 3 ──────────────────────────────────

fn apply_freq_range(_cpu: u64, min_khz: u32, max_khz: u32) -> (u32, u32) {
    // Stage-1: echo the requested range. Live MSR write goes
    // through arch::msr + IPI when wired; until then the
    // userspace contract is "value applied; readback may differ".
    (min_khz, max_khz)
}

fn apply_epp(_cpu: u64, _epp: u8) {
    // Stage-1: no-op, see above.
}

fn apply_governor(_cpu: u64, _gov: Governor) {}

// ── Concrete handlers — Phase 4 ──────────────────────────────────

static ENERGY_BUDGETS: narf_lib::sync::IrqSafeSpinLock<Vec<(RaplDomain, u32, u32)>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

fn apply_energy_budget(domain: RaplDomain, window_ms: u32, energy_mj: u32) {
    let mut g = ENERGY_BUDGETS.lock();
    if let Some(pos) = g.iter().position(|(d, _, _)| *d == domain) {
        g[pos] = (domain, window_ms, energy_mj);
    } else {
        g.push((domain, window_ms, energy_mj));
    }
}

fn clear_energy_budget(domain: RaplDomain) {
    let mut g = ENERGY_BUDGETS.lock();
    if let Some(pos) = g.iter().position(|(d, _, _)| *d == domain) {
        g.swap_remove(pos);
    }
}

/// Read the current budget for a RAPL domain, if any. Used by
/// the RAPL pump to decide when to throttle.
pub fn current_energy_budget(domain: RaplDomain) -> Option<(u32, u32)> {
    ENERGY_BUDGETS
        .lock()
        .iter()
        .find(|(d, _, _)| *d == domain)
        .map(|(_, w, e)| (*w, *e))
}

#[doc(hidden)]
pub fn __reset_energy_budgets_for_test() {
    ENERGY_BUDGETS.lock().clear();
}

// ── Bridge installation ───────────────────────────────────────────

/// Install the `narf-abi` cpu-op bridge so ring-submitted CPU
/// power ops route here. Boot calls this once.
pub fn install_bridge() {
    narf_abi::install_cpu_op_bridge(bridge_thunk);
}

fn bridge_thunk(kind: CpuOpKind, args: &CpuOpArgs, cx: &narf_abi::CancelCtx<'_>) -> CpuOpReturn {
    if cx.is_cancel_requested() {
        return CpuOpReturn {
            status: 2, /* Cancelled */
            result: [0; 6],
        };
    }
    // Boot order may install us before SMP brings up the per-CPU
    // id register; treat "no current cpu" as cpu 0 + non-TCB so
    // the early bring-up path can probe the API.
    let current = narf_arch::current_cpu_id().raw() as u64;
    handle(kind, args, current)
}
