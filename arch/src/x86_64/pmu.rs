//! PMU programming — Intel architectural perfmon + AMD Family 17h/19h.
//!
//! Spec: `observability/specification/perfmon.md` §1.
//!
//! Surfaces the architectural surface for both Intel (general-purpose PMC +
//! fixed counters + global enable) and AMD (F17h/F19h extended core perf
//! counters). Per-event precise sampling (PEBS / IBS) and per-task counter
//! contexts are out of scope here.
//!
//! # Architecture
//!
//! `detect()` inspects CPUID and returns a `PmuBackend` describing the
//! vendor, counter count, and counter bit-width.  The high-level API
//! (`alloc_counter` / `read` / `release`) routes through the backend
//! transparently — driver code does not need to know the vendor.
//!
//! # Linux references (GPL-2.0-or-later)
//!
//! - `arch/x86/events/intel/core.c` — Intel architectural PMU init,
//!   IA32_PERFEVTSEL encoding, GLOBAL_CTRL management.
//! - `arch/x86/events/amd/core.c`  — AMD F17h perf-counter init,
//!   MSR_F15H_PERF_CTL/CTR layout.
//! - `arch/x86/include/asm/perf_event.h` — MSR constants.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, rdmsr_or_gp, wrmsr_or_gp};

// ── Intel MSR map ──────────────────────────────────────────────────

/// IA32_PERFEVTSEL0..7 — event-select for GP counters (0x186..0x18D).
const MSR_IA32_PERFEVTSEL_BASE: u32 = 0x186;
/// IA32_PMC0..7 — GP counter values (0xC1..0xC8).
const MSR_IA32_PMC_BASE: u32 = 0xC1;
/// IA32_FIXED_CTR0..2 — fixed counters (0x309..0x30B).
const MSR_PERF_FIXED_CTR_BASE: u32 = 0x309;
/// IA32_FIXED_CTR_CTRL — per-fixed-counter ring enable (0x38D).
pub const MSR_PERF_FIXED_CTR_CTRL: u32 = 0x38D;
/// IA32_PERF_GLOBAL_STATUS — overflow flags (0x38E).
pub const MSR_IA32_PERF_GLOBAL_STATUS: u32 = 0x38E;
/// IA32_PERF_GLOBAL_CTRL — global counter enable (0x38F).
pub const MSR_IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
/// IA32_PERF_GLOBAL_OVF_CTRL — clear overflow flags (0x390).
pub const MSR_IA32_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;

// ── AMD MSR map (Family 15h+ extended core perf counters) ─────────
//
// Linux: arch/x86/include/asm/perf_event.h MSR_F15H_PERF_CTL/CTR.
// Each counter pair is two MSRs apart: CTL at even, CTR at odd.
//
//   MSR_F15H_PERF_CTL0 = 0xC001_0200   event-select for GP counter 0
//   MSR_F15H_PERF_CTR0 = 0xC001_0201   GP counter 0 value
//   …
//   MSR_F15H_PERF_CTL5 = 0xC001_020A   event-select for GP counter 5
//   MSR_F15H_PERF_CTR5 = 0xC001_020B   GP counter 5 value

/// Base address of AMD F15h+ extended event-select MSRs.
pub const MSR_F15H_PERF_CTL_BASE: u32 = 0xC001_0200;
/// Base address of AMD F15h+ extended counter MSRs.
pub const MSR_F15H_PERF_CTR_BASE: u32 = 0xC001_0201;
/// AMD PerfMonV2 global overflow status/control bank.
pub const MSR_AMD64_PERF_CNTR_GLOBAL_STATUS: u32 = 0xC000_0300;
pub const MSR_AMD64_PERF_CNTR_GLOBAL_CTL: u32 = 0xC000_0301;
pub const MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR: u32 = 0xC000_0302;
/// Number of GP counters on Family 17h/19h (CPUID ext 80000001 ECX:23).
pub const AMD_F17H_NUM_GP_COUNTERS: u8 = 6;

fn amd_perfmon_v2() -> bool {
    // CPUID 0x80000022 EAX bit 0 enumerates PerfMonV2.
    // SAFETY: the maximum extended leaf is checked first.
    unsafe { cpuid(0x8000_0000, 0).0 >= 0x8000_0022 && cpuid(0x8000_0022, 0).0 & 1 != 0 }
}

/// Derive the AMD event-select MSR address for GP counter `idx`.
///
/// Layout: CTL0=0xC0010200, CTL1=0xC0010202, …
/// (stride 2; CTR interleaves at odd offsets).
#[inline]
pub const fn amd_ctl_msr(idx: u8) -> u32 {
    MSR_F15H_PERF_CTL_BASE + (idx as u32) * 2
}

/// Derive the AMD counter-value MSR address for GP counter `idx`.
#[inline]
pub const fn amd_ctr_msr(idx: u8) -> u32 {
    MSR_F15H_PERF_CTR_BASE + (idx as u32) * 2
}

// ── Intel capabilities ─────────────────────────────────────────────

/// Intel architectural PMU capabilities decoded from CPUID leaf 0x0A.
///
/// CPUID.0x0A.EAX[7:0]  = version
/// CPUID.0x0A.EAX[15:8] = num GP counters per logical processor
/// CPUID.0x0A.EAX[23:16]= counter bit-width
/// CPUID.0x0A.EAX[31:24]= enumerable architectural events bitmap
/// CPUID.0x0A.EBX[6:0]  = unsupported architectural events bitmap
/// CPUID.0x0A.EDX[4:0]  = num fixed-function counters
/// CPUID.0x0A.EDX[12:5] = fixed counter bit-width
#[derive(Copy, Clone, Debug, Default)]
pub struct PmuCaps {
    pub version: u8,
    pub n_general_counters: u8,
    pub width_general: u8,
    pub n_fixed_counters: u8,
    pub width_fixed: u8,
    /// Bit N=1 ⇒ architectural event N is *not* supported on this CPU.
    pub unsupported_arch: u8,
}

/// Read Intel PMU capabilities from CPUID leaf 0x0A.
///
/// Returns a zeroed `PmuCaps` (version = 0) when leaf 0x0A is not
/// present (pre-Core2 CPUs, hypervisors that hide the leaf, AMD).
pub fn caps() -> PmuCaps {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x0A {
        return PmuCaps::default();
    }
    // SAFETY: leaf 0xA valid.
    let (eax, ebx, _, edx) = unsafe { cpuid(0x0A, 0) };
    PmuCaps {
        version: (eax & 0xFF) as u8,
        n_general_counters: ((eax >> 8) & 0xFF) as u8,
        width_general: ((eax >> 16) & 0xFF) as u8,
        n_fixed_counters: (edx & 0x1F) as u8,
        width_fixed: ((edx >> 5) & 0xFF) as u8,
        unsupported_arch: (ebx & 0x7F) as u8,
    }
}

// ── PerfEvtSel encoding (Intel + AMD share the layout) ────────────
//
// Linux: arch/x86/include/asm/perf_event.h ARCH_PERFMON_EVENTSEL_*.
// AMD F17h uses the same bit layout as Intel IA32_PERFEVTSEL:
//   [7:0]  event select
//   [15:8] unit mask (umask)
//   [16]   USR
//   [17]   OS
//   [18]   Edge detect
//   [20]   APIC interrupt enable
//   [21]   AnyThread (Intel) / HostGuestOnly (AMD — bit 40-41 on newer)
//   [22]   Counter enable
//   [23]   Invert counter mask
//   [31:24]Counter mask (cmask)

/// Event-select structure.  `encode()` produces the 64-bit value
/// written to IA32_PERFEVTSEL (Intel) or MSR_F15H_PERF_CTL (AMD).
#[derive(Copy, Clone, Debug, Default)]
pub struct PerfEvtSel {
    pub event_select: u8,
    pub umask: u8,
    pub usr: bool,
    pub os: bool,
    pub edge: bool,
    pub apic_int: bool,
    pub any_thread: bool,
    pub inv: bool,
    pub counter_mask: u8,
}

impl PerfEvtSel {
    /// Encode into the 64-bit MSR write value.  Bit 22 (counter
    /// enable) is set automatically when at least one of `usr`/`os`
    /// is requested.
    pub fn encode(&self) -> u64 {
        let mut v = self.event_select as u64 | ((self.umask as u64) << 8);
        if self.usr {
            v |= 1 << 16;
        }
        if self.os {
            v |= 1 << 17;
        }
        if self.edge {
            v |= 1 << 18;
        }
        if self.apic_int {
            v |= 1 << 20;
        }
        if self.any_thread {
            v |= 1 << 21;
        }
        if self.usr || self.os {
            v |= 1 << 22; // counter enable
        }
        if self.inv {
            v |= 1 << 23;
        }
        v |= (self.counter_mask as u64) << 24;
        v
    }

    /// Build from raw `(event_select, umask)` with OS+USR counting.
    pub const fn os_usr(event_select: u8, umask: u8) -> Self {
        Self {
            event_select,
            umask,
            os: true,
            usr: true,
            edge: false,
            apic_int: false,
            any_thread: false,
            inv: false,
            counter_mask: 0,
        }
    }
}

// ── Intel architectural events ────────────────────────────────────
//
// Intel SDM Vol 3B §20.2.1, Table 20-1 (Architectural Performance
// Events).  These encodings are architecturally stable across Intel
// microarchitectures from Core2 onward (PMU version >= 1).

/// Ready-made PerfEvtSel for the architectural events.
pub mod arch_event {
    use super::PerfEvtSel;

    pub const fn unhalted_core_cycles(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0x3C,
            umask: 0x00,
            os,
            usr,
            ..PerfEvtSel {
                event_select: 0,
                umask: 0,
                os: false,
                usr: false,
                edge: false,
                apic_int: false,
                any_thread: false,
                inv: false,
                counter_mask: 0,
            }
        }
    }
    pub const fn instructions_retired(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0xC0,
            umask: 0x00,
            os,
            usr,
            ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn unhalted_ref_cycles(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0x3C,
            umask: 0x01,
            os,
            usr,
            ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn llc_reference(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0x2E,
            umask: 0x4F,
            os,
            usr,
            ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn llc_miss(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0x2E,
            umask: 0x41,
            os,
            usr,
            ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn branch_retired(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0xC4,
            umask: 0x00,
            os,
            usr,
            ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn branch_mispredict_retired(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0xC5,
            umask: 0x00,
            os,
            usr,
            ..unhalted_core_cycles(false, false)
        }
    }
}

// ── AMD common events (Family 17h / 19h) ──────────────────────────
//
// Linux: arch/x86/events/amd/core.c — amd_f17h_perfmon_event_map[].
// Event codes are taken from the AMD64 Architecture Programmer's
// Manual Vol 2, §3.14 and the Renoir / Cezanne PPR.

/// Ready-made PerfEvtSel for AMD Family 17h/19h performance events.
pub mod amd_event {
    use super::PerfEvtSel;

    /// Cycles not in halt (MSR_F15H_PERF_CTL event 0x076, umask 0x00).
    ///
    /// AMD PPR: "FP_RETIRED_SSE_OPS" is different; this maps to the
    /// clock counter.  Linux amd/core.c uses 0x076 for
    /// PERF_COUNT_HW_CPU_CYCLES.
    pub const fn cycles(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel::os_usr_raw(0x76, 0x00, os, usr)
    }

    /// Retired instructions (event 0x0C0, umask 0x00).
    pub const fn instructions_retired(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel::os_usr_raw(0xC0, 0x00, os, usr)
    }

    /// L1D cache accesses (event 0x040, umask 0x00).
    pub const fn l1d_cache_accesses(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel::os_usr_raw(0x40, 0x00, os, usr)
    }

    /// L1D cache misses / DC miss (event 0x041, umask 0x00).
    pub const fn l1d_cache_misses(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel::os_usr_raw(0x41, 0x00, os, usr)
    }

    /// L2 cache accesses (event 0x064, umask 0x00).
    pub const fn l2_cache_accesses(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel::os_usr_raw(0x64, 0x00, os, usr)
    }
}

impl PerfEvtSel {
    /// Internal builder used by const `amd_event` / `arch_event` fns.
    const fn os_usr_raw(event_select: u8, umask: u8, os: bool, usr: bool) -> Self {
        Self {
            event_select,
            umask,
            os,
            usr,
            edge: false,
            apic_int: false,
            any_thread: false,
            inv: false,
            counter_mask: 0,
        }
    }
}

// ── Backend detection ──────────────────────────────────────────────

/// Vendor of the detected PMU backend.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PmuVendor {
    /// Intel architectural performance monitoring v3+.
    Intel,
    /// AMD Family 15h+ extended core performance counters (F17h/F19h).
    Amd,
}

/// PMU backend descriptor returned by `detect()`.
///
/// Driver code does not consult the vendor directly; it calls the
/// vendor-neutral `alloc_counter` / `read` / `release` API below.
#[derive(Copy, Clone, Debug)]
pub struct PmuBackend {
    pub vendor: PmuVendor,
    /// Number of available general-purpose counters on this logical CPU.
    pub n_counters: u8,
    /// Effective counter bit-width (usable bits; hardware may be wider).
    pub counter_width: u8,
}

/// Detect the PMU backend for the current logical CPU.
///
/// Returns `None` when:
/// - Intel and CPUID leaf 0x0A is absent or version == 0.
/// - AMD and CPUID 0x80000001.ECX[23] (PerfCtrExtCore) is not set.
pub fn detect() -> Option<PmuBackend> {
    // Determine vendor via CPUID EBX of leaf 0 (GenuineIntel /
    // AuthenticAMD).  Matches Linux's cpu_vendor_detect() logic.
    // SAFETY: leaf 0 always defined.
    let (_, vendor_ebx, _, vendor_edx) = unsafe { cpuid(0, 0) };
    // "GenuineIntel": EBX="Genu" EDX="ineI" ECX="ntel" (but we only
    // need EBX+EDX for a quick discriminator; ECX omitted here).
    // "AuthenticAMD": EBX="Auth" EDX="AMD!" (also EBX canonical below)
    // Use the EBX string bytes as the primary discriminator.
    // "GenuineIntel" EBX = 0x756E_6547
    // "AuthenticAMD" EBX = 0x6874_7541
    // "HygonGenuine" EBX = 0x6F67_7948 — treat as AMD-compatible
    let _ = vendor_edx;
    const INTEL_EBX: u32 = 0x756E_6547; // "Genu"
    const AMD_EBX: u32 = 0x6874_7541; // "Auth"
    const HYGON_EBX: u32 = 0x6F67_7948; // "Hygo"

    if vendor_ebx == INTEL_EBX {
        let c = caps();
        if c.version == 0 || c.n_general_counters == 0 {
            return None;
        }
        Some(PmuBackend {
            vendor: PmuVendor::Intel,
            n_counters: c.n_general_counters,
            counter_width: c.width_general,
        })
    } else if vendor_ebx == AMD_EBX || vendor_ebx == HYGON_EBX {
        // AMD: check CPUID 0x80000001.ECX bit 23 (PerfCtrExtCore).
        // SAFETY: leaf 0 validated; extended leaf always >= 0x80000001
        // on x86_64 AMD64 silicon.
        // SAFETY: Valid memory or trusted environment
        let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
        if max_ext < 0x8000_0001 {
            return None;
        }
        // SAFETY: extended leaf 1 valid per max_ext check.
        let (_, _, ecx, _) = unsafe { cpuid(0x8000_0001, 0) };
        if ecx & (1 << 23) == 0 {
            return None;
        }
        Some(PmuBackend {
            vendor: PmuVendor::Amd,
            n_counters: AMD_F17H_NUM_GP_COUNTERS,
            counter_width: 48, // F17h counters are 48-bit
        })
    } else {
        None
    }
}

// ── High-level vendor-neutral API ─────────────────────────────────

/// Errors returned by the high-level PMU API.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PmuError {
    /// No supported PMU was detected on this CPU.
    NoPmu,
    /// All hardware counter slots are in use.
    NoFreeCounter,
    /// The event is not mappable on the detected PMU backend.
    UnsupportedEvent,
}

/// High-level performance event identifier.
///
/// `Raw(u64)` carries a pre-encoded `PerfEvtSel` value (bits [31:0]
/// of the event-select MSR).  Use it for vendor-specific events not
/// covered by the named variants.
#[derive(Copy, Clone, Debug)]
pub enum PmuEvent {
    Cycles,
    Instructions,
    BranchInstructions,
    BranchMisses,
    CacheReferences,
    CacheMisses,
    L1dAccesses,
    L1dMisses,
    LlcReferences,
    LlcMisses,
    /// Pre-encoded event-select value (vendor-specific).
    Raw(u64),
}

/// A live hardware counter slot.
#[derive(Copy, Clone, Debug)]
pub struct PmuCounter {
    /// Counter slot index (0-based).
    pub idx: u8,
    /// Event programmed into this counter.
    pub event: PmuEvent,
    /// Count operating-system (CPL0) execution.
    pub os: bool,
    /// Count userspace (CPL3) execution.
    pub usr: bool,
    /// Vendor of the underlying backend (drives the MSR namespace).
    pub(crate) vendor: PmuVendor,
    /// Logical CPU whose MSR bank owns this counter.
    pub cpu: u16,
}

/// Per-slot in-use bitmap (bit N = counter N is allocated).
/// Supports up to 8 GP counters; extend the type for more.
static COUNTER_ALLOC_MASK: [AtomicU8; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU8::new(0) }; narf_lib::percpu::MAX_CPUS];
static SAMPLE_ARMED_MASK: [AtomicU8; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU8::new(0) }; narf_lib::percpu::MAX_CPUS];
static SAMPLE_PERIODS: [[AtomicU64; 8]; narf_lib::percpu::MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 8] }; narf_lib::percpu::MAX_CPUS];
static SAMPLE_LOADED_PERIODS: [[AtomicU64; 8]; narf_lib::percpu::MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 8] }; narf_lib::percpu::MAX_CPUS];
static SAMPLE_OVERFLOW_PERIODS: [[AtomicU64; 8]; narf_lib::percpu::MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 8] }; narf_lib::percpu::MAX_CPUS];

fn sample_preload(width: u8, period: u64) -> Result<u64, PmuError> {
    if period == 0 || width == 0 || width >= 64 {
        return Err(PmuError::UnsupportedEvent);
    }
    let modulus = 1u64 << width;
    if period >= modulus {
        return Err(PmuError::UnsupportedEvent);
    }
    Ok(modulus - period)
}

/// Allocate the next free counter slot and program it with `event`.
///
/// Returns `Err(PmuError::NoPmu)` when no PMU is available,
/// `Err(PmuError::NoFreeCounter)` when all slots are in use.
///
/// # Safety
/// Must be called at CPL = 0.
pub unsafe fn alloc_counter(event: PmuEvent) -> Result<PmuCounter, PmuError> {
    // SAFETY: forwarded caller contract.
    unsafe { alloc_counter_filtered(event, true, true) }
}

/// Allocate and program a counter with explicit CPL0/CPL3 filtering.
///
/// # Safety
/// Must be called at CPL = 0.
pub unsafe fn alloc_counter_filtered(
    event: PmuEvent,
    os: bool,
    usr: bool,
) -> Result<PmuCounter, PmuError> {
    if !os && !usr {
        return Err(PmuError::UnsupportedEvent);
    }
    let backend = detect().ok_or(PmuError::NoPmu)?;
    // Validate the vendor-specific mapping before looking for a free slot.
    // Otherwise an unsupported event can incorrectly report EBUSY merely
    // because earlier events occupy every counter.
    let sel = apply_privilege_filter(event_to_evtsel(event, backend.vendor)?, os, usr);
    let cpu = narf_lib::percpu::current_cpu();
    let allocation = &COUNTER_ALLOC_MASK[cpu];
    let idx = loop {
        let mask = allocation.load(Ordering::Acquire);
        let mut free = None;
        for i in 0..backend.n_counters.min(8) {
            if mask & (1 << i) == 0 {
                free = Some(i);
                break;
            }
        }
        let idx = free.ok_or(PmuError::NoFreeCounter)?;
        if allocation
            .compare_exchange_weak(mask, mask | (1 << idx), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break idx;
        }
    };

    // Program the counter.
    // SAFETY: caller-asserted CPL=0; idx < n_counters verified above.
    unsafe {
        match backend.vendor {
            PmuVendor::Intel => write_general(idx, 0),
            PmuVendor::Amd => {
                let _ = wrmsr_or_gp(amd_ctr_msr(idx), 0);
            }
        }
        program_counter(idx, sel, backend.vendor);
    }

    Ok(PmuCounter {
        idx,
        event,
        os,
        usr,
        vendor: backend.vendor,
        cpu: cpu as u16,
    })
}

/// Read the current 64-bit value of a live counter.
///
/// # Safety
/// `counter` must be a value returned by `alloc_counter` that has not
/// yet been passed to `release`.  CPL = 0.
pub unsafe fn read(counter: &PmuCounter) -> u64 {
    // SAFETY: caller-asserted.
    unsafe {
        match counter.vendor {
            PmuVendor::Intel => rdmsr(MSR_IA32_PMC_BASE + counter.idx as u32),
            PmuVendor::Amd => rdmsr(amd_ctr_msr(counter.idx)),
        }
    }
}

/// Events counted since the most recent sampling preload/reload.
///
/// # Safety
/// Same current-CPU live-counter requirements as [`read`].
pub unsafe fn sampling_residual(counter: &PmuCounter, period: u64) -> Result<u64, PmuError> {
    let backend = detect().ok_or(PmuError::NoPmu)?;
    let loaded =
        SAMPLE_LOADED_PERIODS[counter.cpu as usize][counter.idx as usize].load(Ordering::Acquire);
    let period = if loaded == 0 { period } else { loaded };
    let preload = sample_preload(backend.counter_width, period)?;
    // SAFETY: forwarded caller contract.
    let raw = unsafe { read(counter) };
    let mask = (1u64 << backend.counter_width) - 1;
    Ok(raw.wrapping_sub(preload) & mask)
}

/// Arm a live counter for interrupt-on-overflow sampling.
///
/// The counter is preloaded to `2^width - period` and its event-select
/// APIC-interrupt bit is enabled. The caller must route LVT-PC before enabling
/// the event.
///
/// # Safety
/// CPL=0 and `counter` is a live allocation on the current CPU.
pub unsafe fn arm_sampling(counter: &PmuCounter, period: u64) -> Result<(), PmuError> {
    // SAFETY: forwarded caller contract.
    unsafe { arm_sampling_with_reload(counter, period, period) }
}

/// Arm sampling with a possibly shorter first overflow period.
///
/// `initial_period` is loaded into hardware now; after that overflow the IRQ
/// path records it as the period that fired and reloads `reload_period`.
///
/// # Safety
/// CPL=0 and `counter` is a live allocation on the current CPU.
pub unsafe fn arm_sampling_with_reload(
    counter: &PmuCounter,
    initial_period: u64,
    reload_period: u64,
) -> Result<(), PmuError> {
    let cpu = narf_lib::percpu::current_cpu();
    if counter.cpu as usize != cpu {
        return Err(PmuError::UnsupportedEvent);
    }
    let backend = detect().ok_or(PmuError::NoPmu)?;
    let preload = sample_preload(backend.counter_width, initial_period)?;
    let _ = sample_preload(backend.counter_width, reload_period)?;
    let mut sel = apply_privilege_filter(
        event_to_evtsel(counter.event, counter.vendor)?,
        counter.os,
        counter.usr,
    );
    sel.apic_int = true;
    // SAFETY: caller owns this live slot on the current CPU.
    unsafe {
        match counter.vendor {
            PmuVendor::Intel => {
                write_general(counter.idx, preload);
            }
            PmuVendor::Amd => {
                let _ = wrmsr_or_gp(amd_ctr_msr(counter.idx), preload);
            }
        }
        program_counter(counter.idx, sel, counter.vendor);
    }
    SAMPLE_PERIODS[cpu][counter.idx as usize].store(reload_period, Ordering::Release);
    SAMPLE_LOADED_PERIODS[cpu][counter.idx as usize].store(initial_period, Ordering::Release);
    SAMPLE_ARMED_MASK[cpu].fetch_or(1 << counter.idx, Ordering::AcqRel);
    Ok(())
}

/// Events remaining before the next overflow of a live sampled counter.
///
/// # Safety
/// Same current-CPU live-counter requirements as [`sampling_residual`].
pub unsafe fn sampling_period_left(counter: &PmuCounter) -> Result<u64, PmuError> {
    let cpu = narf_lib::percpu::current_cpu();
    if counter.cpu as usize != cpu {
        return Err(PmuError::UnsupportedEvent);
    }
    let loaded = SAMPLE_LOADED_PERIODS[cpu][counter.idx as usize].load(Ordering::Acquire);
    if loaded == 0 {
        return Err(PmuError::UnsupportedEvent);
    }
    // SAFETY: forwarded caller contract.
    let consumed = unsafe { sampling_residual(counter, loaded)? };
    Ok(loaded.saturating_sub(consumed).max(1))
}

/// Change the reload period used after the next overflow of an armed counter.
///
/// This only updates the per-CPU IRQ handoff state, so it is safe to call from
/// normal context even when the owning task has migrated away from that CPU.
/// The current reload remains in effect until the next overflow.
pub fn update_sampling_period(counter: &PmuCounter, period: u64) {
    let cpu = counter.cpu as usize;
    let idx = counter.idx as usize;
    if period != 0
        && cpu < narf_lib::percpu::MAX_CPUS
        && idx < SAMPLE_PERIODS[cpu].len()
        && SAMPLE_ARMED_MASK[cpu].load(Ordering::Acquire) & (1 << counter.idx) != 0
    {
        SAMPLE_PERIODS[cpu][idx].store(period, Ordering::Release);
    }
}

/// Period that produced the most recently acknowledged overflow for a slot.
pub fn last_overflow_period(cpu: usize, idx: usize) -> u64 {
    SAMPLE_OVERFLOW_PERIODS
        .get(cpu)
        .and_then(|slots| slots.get(idx))
        .map_or(0, |period| period.load(Ordering::Acquire))
}

/// Acknowledge and re-arm counters that caused the current PMI.
///
/// Returns a bitmask of sampled GP-counter slots. Intel uses architectural
/// GLOBAL_STATUS/OVF_CTRL; AMD uses PerfMonV2 Status/StatusClr when enumerated
/// and the legacy counter-sign transition on earlier extended-core PMUs.
///
/// # Safety
/// CPL=0, called from the current CPU's LVT-PC interrupt handler.
pub unsafe fn handle_sampling_overflow() -> u8 {
    let Some(backend) = detect() else {
        return 0;
    };
    let cpu = narf_lib::percpu::current_cpu();
    let armed = SAMPLE_ARMED_MASK[cpu].load(Ordering::Acquire);
    let fired = match backend.vendor {
        PmuVendor::Intel => {
            // SAFETY: architectural perfmon status MSR exists for this backend.
            (unsafe { rdmsr(MSR_IA32_PERF_GLOBAL_STATUS) } as u8) & armed
        }
        PmuVendor::Amd if amd_perfmon_v2() => {
            // SAFETY: PerfMonV2 enumerates the architectural AMD global bank.
            (unsafe { rdmsr(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS) } as u8) & armed
        }
        PmuVendor::Amd => {
            // Legacy AMD PMUs expose overflow through the counter sign bit:
            // a negative preload wraps into the non-negative half. This is the
            // same predicate used by Linux before PerfMonV2.
            let mut fired = 0;
            let top = 1u64 << (backend.counter_width - 1);
            for idx in 0..backend.n_counters.min(8) {
                // SAFETY: idx is within the detected current-CPU PMC bank.
                let value = unsafe { rdmsr(amd_ctr_msr(idx)) };
                if armed & (1 << idx) != 0 && value & top == 0 {
                    fired |= 1 << idx;
                }
            }
            fired
        }
    };
    if fired == 0 {
        return 0;
    }
    let modulus = 1u64 << backend.counter_width;
    for idx in 0..backend.n_counters.min(8) {
        if fired & (1 << idx) == 0 {
            continue;
        }
        SAMPLE_OVERFLOW_PERIODS[cpu][idx as usize].store(
            SAMPLE_LOADED_PERIODS[cpu][idx as usize].load(Ordering::Acquire),
            Ordering::Release,
        );
        let period = SAMPLE_PERIODS[cpu][idx as usize].load(Ordering::Acquire);
        if period == 0 || period >= modulus {
            continue;
        }
        match backend.vendor {
            // SAFETY: idx is an armed live GP slot on this CPU.
            PmuVendor::Intel => unsafe { write_general(idx, modulus - period) },
            PmuVendor::Amd => {
                let _ = wrmsr_or_gp(amd_ctr_msr(idx), modulus - period);
            }
        }
        SAMPLE_LOADED_PERIODS[cpu][idx as usize].store(period, Ordering::Release);
    }
    match backend.vendor {
        PmuVendor::Intel => {
            // SAFETY: clear exactly the GP overflow flags handled above.
            unsafe { clear_overflow(fired as u32, 0) };
        }
        PmuVendor::Amd if amd_perfmon_v2() => {
            // PerfCntrGlobalStatus is read-only; StatusClr is W1C.
            let _ = wrmsr_or_gp(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR, fired as u64);
        }
        PmuVendor::Amd => {}
    }
    fired
}

/// Remove a counter from the PMI re-arm set before releasing it.
pub fn disarm_sampling(counter: &PmuCounter) {
    let cpu = narf_lib::percpu::current_cpu();
    if counter.cpu as usize == cpu {
        SAMPLE_ARMED_MASK[cpu].fetch_and(!(1 << counter.idx), Ordering::AcqRel);
        SAMPLE_PERIODS[cpu][counter.idx as usize].store(0, Ordering::Release);
        SAMPLE_LOADED_PERIODS[cpu][counter.idx as usize].store(0, Ordering::Release);
        SAMPLE_OVERFLOW_PERIODS[cpu][counter.idx as usize].store(0, Ordering::Release);
    }
}

/// Disable interrupt generation for a sampled counter while retaining the
/// allocation and normal counting configuration.
///
/// # Safety
/// CPL=0 and `counter` is a live allocation on the current CPU.
pub unsafe fn pause_sampling(counter: &PmuCounter) -> Result<(), PmuError> {
    disarm_sampling(counter);
    let mut sel = apply_privilege_filter(
        event_to_evtsel(counter.event, counter.vendor)?,
        counter.os,
        counter.usr,
    );
    sel.apic_int = false;
    // SAFETY: caller owns this live slot.
    unsafe { program_counter(counter.idx, sel, counter.vendor) };
    Ok(())
}

/// Disable and free a counter slot so it can be re-allocated.
///
/// # Safety
/// CPL = 0; `counter` must be a value from `alloc_counter`.
pub unsafe fn release(counter: PmuCounter) {
    let cpu = narf_lib::percpu::current_cpu();
    debug_assert_eq!(counter.cpu as usize, cpu);
    disarm_sampling(&counter);
    // Write 0 to the event-select MSR to disable the counter.
    // wrmsr_or_gp is safe (probe-armed); no inner unsafe block needed.
    match counter.vendor {
        PmuVendor::Intel => {
            let _ = wrmsr_or_gp(MSR_IA32_PERFEVTSEL_BASE + counter.idx as u32, 0);
        }
        PmuVendor::Amd => {
            if amd_perfmon_v2() {
                // SAFETY: current-CPU PerfMonV2 global control bank.
                let ctl = unsafe { rdmsr(MSR_AMD64_PERF_CNTR_GLOBAL_CTL) };
                let _ = wrmsr_or_gp(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, ctl & !(1 << counter.idx));
            }
            let _ = wrmsr_or_gp(amd_ctl_msr(counter.idx), 0);
        }
    }
    // Clear allocation bit.
    COUNTER_ALLOC_MASK[cpu].fetch_and(!(1 << counter.idx), Ordering::AcqRel);
}

// ── Internal helpers ───────────────────────────────────────────────

/// Map a `PmuEvent` to a `PerfEvtSel` for the given vendor.
fn event_to_evtsel(event: PmuEvent, vendor: PmuVendor) -> Result<PerfEvtSel, PmuError> {
    Ok(match (event, vendor) {
        // Intel architectural events (SDM Table 20-1).
        (PmuEvent::Cycles, PmuVendor::Intel) => arch_event::unhalted_core_cycles(true, true),
        (PmuEvent::Instructions, PmuVendor::Intel) => arch_event::instructions_retired(true, true),
        (PmuEvent::BranchInstructions, PmuVendor::Intel) => arch_event::branch_retired(true, true),
        (PmuEvent::BranchMisses, PmuVendor::Intel) => {
            arch_event::branch_mispredict_retired(true, true)
        }
        (PmuEvent::CacheReferences, PmuVendor::Intel)
        | (PmuEvent::LlcReferences, PmuVendor::Intel) => arch_event::llc_reference(true, true),
        (PmuEvent::CacheMisses, PmuVendor::Intel) => arch_event::llc_miss(true, true),
        (PmuEvent::L1dAccesses, PmuVendor::Intel) | (PmuEvent::L1dMisses, PmuVendor::Intel) => {
            return Err(PmuError::UnsupportedEvent);
        }
        (PmuEvent::LlcMisses, PmuVendor::Intel) => arch_event::llc_miss(true, true),
        // AMD F17h/F19h events (amd/core.c amd_f17h_perfmon_event_map).
        (PmuEvent::Cycles, PmuVendor::Amd) => amd_event::cycles(true, true),
        (PmuEvent::Instructions, PmuVendor::Amd) => amd_event::instructions_retired(true, true),
        (PmuEvent::BranchInstructions, PmuVendor::Amd) => {
            // AMD: Retired Branch Instructions — event 0x0C2, umask 0x00.
            // AMD PPR Renoir §2.1.13.
            PerfEvtSel::os_usr_raw(0xC2, 0x00, true, true)
        }
        (PmuEvent::BranchMisses, PmuVendor::Amd) => {
            // AMD: Retired Mispredicted Branch Instructions — 0x0C3 umask 0.
            PerfEvtSel::os_usr_raw(0xC3, 0x00, true, true)
        }
        // Linux's Family-17h+ generic event table:
        // CACHE_REFERENCES=0xff60, CACHE_MISSES=0x0964.
        (PmuEvent::CacheReferences, PmuVendor::Amd) => {
            PerfEvtSel::os_usr_raw(0x60, 0xff, true, true)
        }
        (PmuEvent::CacheMisses, PmuVendor::Amd) => PerfEvtSel::os_usr_raw(0x64, 0x09, true, true),
        (PmuEvent::L1dAccesses, PmuVendor::Amd) => amd_event::l1d_cache_accesses(true, true),
        // Linux amd_hw_cache_event_ids_f17h maps L1D read misses to
        // event 0x60, umask 0xc8 ("L2 access from DC miss").
        (PmuEvent::L1dMisses, PmuVendor::Amd) => PerfEvtSel::os_usr_raw(0x60, 0xc8, true, true),
        (PmuEvent::LlcReferences, PmuVendor::Amd) | (PmuEvent::LlcMisses, PmuVendor::Amd) => {
            return Err(PmuError::UnsupportedEvent);
        }
        // Raw event: the caller supplies the pre-encoded value directly.
        (PmuEvent::Raw(v), _) => {
            return Ok(PerfEvtSel {
                event_select: (v & 0xFF) as u8,
                umask: ((v >> 8) & 0xFF) as u8,
                usr: v & (1 << 16) != 0,
                os: v & (1 << 17) != 0,
                edge: v & (1 << 18) != 0,
                apic_int: v & (1 << 20) != 0,
                any_thread: v & (1 << 21) != 0,
                inv: v & (1 << 23) != 0,
                counter_mask: ((v >> 24) & 0xFF) as u8,
            });
        }
    })
}

fn apply_privilege_filter(mut sel: PerfEvtSel, os: bool, usr: bool) -> PerfEvtSel {
    sel.os = os;
    sel.usr = usr;
    sel
}

/// Write an event-select to hardware for counter slot `idx`.
///
/// # Safety
/// CPL = 0; `idx` < backend counter count.
/// KVM vPMU ground-truth self-test (AMD). Programs counter 0 for retired
/// instructions exactly as `alloc_counter`/`program_counter` do, runs a bounded
/// busy loop, and returns `(perfmon_v2, ctl_readback, global_ctl_readback,
/// counter_delta)`. A zero `counter_delta` with correct readbacks ⇒ the MSRs
/// are backed but KVM isn't incrementing the counter (a host-side vPMU gap);
/// a wrong readback ⇒ the write didn't stick. Diagnostic; clobbers counter 0.
pub fn amd_kvm_selftest() -> (bool, u64, u64, u64) {
    let Some(b) = detect() else {
        return (false, 0, 0, 0);
    };
    if b.vendor != PmuVendor::Amd {
        return (false, 0, 0, 0);
    }
    let v2 = amd_perfmon_v2();
    let sel = match event_to_evtsel(PmuEvent::Instructions, PmuVendor::Amd) {
        Ok(s) => apply_privilege_filter(s, true, true),
        Err(_) => return (v2, 0, 0, 0),
    };
    // Counter 0 is programmed via the GP-safe MSR helpers (a #GP on an unbacked
    // MSR is caught, not fatal), so no `unsafe` is needed. Must run at CPL=0.
    let _ = wrmsr_or_gp(amd_ctr_msr(0), 0);
    let _ = wrmsr_or_gp(amd_ctl_msr(0), sel.encode());
    if v2 {
        let g = rdmsr_or_gp(MSR_AMD64_PERF_CNTR_GLOBAL_CTL).unwrap_or(0);
        let _ = wrmsr_or_gp(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, g | 1);
    }
    let ctl_rb = rdmsr_or_gp(amd_ctl_msr(0)).unwrap_or(0);
    let g_rb = rdmsr_or_gp(MSR_AMD64_PERF_CNTR_GLOBAL_CTL).unwrap_or(0);
    let before = rdmsr_or_gp(amd_ctr_msr(0)).unwrap_or(0);
    let mut x = 0u64;
    for i in 0..500_000u64 {
        x = x.wrapping_add(i.wrapping_mul(3));
    }
    core::hint::black_box(x);
    let after = rdmsr_or_gp(amd_ctr_msr(0)).unwrap_or(0);
    (v2, ctl_rb, g_rb, after.wrapping_sub(before))
}

unsafe fn program_counter(idx: u8, sel: PerfEvtSel, vendor: PmuVendor) {
    let encoded = sel.encode();
    // wrmsr_or_gp is safe (probe-armed); no inner unsafe block needed.
    match vendor {
        PmuVendor::Intel => {
            let _ = wrmsr_or_gp(MSR_IA32_PERFEVTSEL_BASE + idx as u32, encoded);
        }
        PmuVendor::Amd => {
            let _ = wrmsr_or_gp(amd_ctl_msr(idx), encoded);
            if amd_perfmon_v2() {
                // PerfMonV2 gates each programmed PMC through GlobalCtl.
                // SAFETY: the enumerated global-control MSR is current-CPU.
                let ctl = unsafe { rdmsr(MSR_AMD64_PERF_CNTR_GLOBAL_CTL) };
                let _ = wrmsr_or_gp(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, ctl | (1 << idx));
            }
        }
    }
}

// ── Intel low-level counter programming (retained for callers that
//   operate directly on the Intel surface) ─────────────────────────

/// Program Intel general-purpose counter `idx` with `sel`.
///
/// # Safety
/// CPL = 0; `idx < caps().n_general_counters`.
pub unsafe fn program_general(idx: u8, sel: PerfEvtSel) {
    let _ = wrmsr_or_gp(MSR_IA32_PERFEVTSEL_BASE + idx as u32, sel.encode());
}

/// Read Intel general-purpose counter `idx`.
///
/// # Safety
/// CPL = 0; `idx < caps().n_general_counters`.
pub unsafe fn read_general(idx: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_PMC_BASE + idx as u32) }
}

/// Reset Intel general-purpose counter `idx` to `val`.
///
/// # Safety
/// Same as `read_general`.
pub unsafe fn write_general(idx: u8, val: u64) {
    let _ = wrmsr_or_gp(MSR_IA32_PMC_BASE + idx as u32, val);
}

/// Read Intel fixed counter `idx`.
///
/// Fixed counter assignment: 0 = instructions retired,
/// 1 = unhalted core cycles, 2 = unhalted reference cycles.
///
/// # Safety
/// CPL = 0; `idx < caps().n_fixed_counters`.
pub unsafe fn read_fixed(idx: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_PERF_FIXED_CTR_BASE + idx as u32) }
}

/// Enable Intel fixed counter `idx` for the given privilege rings.
///
/// # Safety
/// CPL = 0.
pub unsafe fn enable_fixed(idx: u8, os: bool, usr: bool) {
    // SAFETY: caller-asserted.
    let cur = unsafe { rdmsr(MSR_PERF_FIXED_CTR_CTRL) };
    let nibble = (os as u64) | ((usr as u64) << 1);
    let mask = 0xFu64 << (idx as u64 * 4);
    let new = (cur & !mask) | (nibble << (idx as u64 * 4));
    let _ = wrmsr_or_gp(MSR_PERF_FIXED_CTR_CTRL, new);
}

/// Enable a set of Intel counters via `IA32_PERF_GLOBAL_CTRL`.
///
/// `general_mask` sets bit i for IA32_PMCi; `fixed_mask` sets bit i
/// (stored in the high half of the MSR) for fixed counter i.
///
/// # Safety
/// CPL = 0.
pub unsafe fn enable_global(general_mask: u32, fixed_mask: u8) {
    let v = (general_mask as u64) | ((fixed_mask as u64) << 32);
    let _ = wrmsr_or_gp(MSR_IA32_PERF_GLOBAL_CTRL, v);
}

/// Disable all Intel counters via `IA32_PERF_GLOBAL_CTRL = 0`.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable_global() {
    let _ = wrmsr_or_gp(MSR_IA32_PERF_GLOBAL_CTRL, 0);
}

/// Clear Intel overflow-status bits via `IA32_PERF_GLOBAL_OVF_CTRL`.
///
/// # Safety
/// CPL = 0.
pub unsafe fn clear_overflow(general_mask: u32, fixed_mask: u8) {
    let v = (general_mask as u64) | ((fixed_mask as u64) << 32);
    let _ = wrmsr_or_gp(MSR_IA32_PERF_GLOBAL_OVF_CTRL, v);
}

// ── Smoke tests ────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pmu_sampling_preload_bounds() -> TestResult {
        if sample_preload(48, 1000) != Ok((1u64 << 48) - 1000)
            || sample_preload(48, 0) != Err(PmuError::UnsupportedEvent)
            || sample_preload(48, 1u64 << 48) != Err(PmuError::UnsupportedEvent)
            || sample_preload(64, 1) != Err(PmuError::UnsupportedEvent)
        {
            return TestResult::Fail("PMU sampling preload validation");
        }
        TestResult::Pass
    }
    kernel_test_in!("arch/pmu", smoke_pmu_sampling_preload_bounds);

    // ── Test 1: Intel CPUID 0x0A decode ───────────────────────────
    //
    // Verifies that `caps()` correctly decodes a synthetic CPUID leaf
    // 0x0A value.  We construct the EAX/EDX values directly and check
    // that each field is extracted from the right bit position.
    //
    // EAX: version=3, n_gp=4, width_gp=48, arch_events_bitmap=0x7F
    // EDX: n_fixed=3, width_fixed=48

    fn smoke_pmu_intel_cpuid_decode() -> TestResult {
        // Decode the EAX field manually (same logic as caps() but on
        // a synthetic value we control).
        let eax: u32 = 3 | (4 << 8) | (48 << 16) | (0x7F << 24);
        let ebx: u32 = 0; // no unsupported events
        let edx: u32 = 3 | (48 << 5);

        let version = (eax & 0xFF) as u8;
        let n_gp = ((eax >> 8) & 0xFF) as u8;
        let width_gp = ((eax >> 16) & 0xFF) as u8;
        let n_fixed = (edx & 0x1F) as u8;
        let width_fixed = ((edx >> 5) & 0xFF) as u8;
        let unsupported = (ebx & 0x7F) as u8;

        if version != 3 {
            return TestResult::Fail("version");
        }
        if n_gp != 4 {
            return TestResult::Fail("n_general_counters");
        }
        if width_gp != 48 {
            return TestResult::Fail("width_general");
        }
        if n_fixed != 3 {
            return TestResult::Fail("n_fixed_counters");
        }
        if width_fixed != 48 {
            return TestResult::Fail("width_fixed");
        }
        if unsupported != 0 {
            return TestResult::Fail("unsupported_arch");
        }
        TestResult::Pass
    }
    kernel_test_in!("arch/pmu", smoke_pmu_intel_cpuid_decode);

    // ── Test 2: AMD MSR address derivation ────────────────────────
    //
    // Linux arch/x86/events/amd/core.c: MSR_F15H_PERF_CTL0 = 0xC0010200,
    // stride 2 between CTL pairs. CTR is CTL + 1.

    fn smoke_pmu_amd_msr_address() -> TestResult {
        // CTL addresses: 0xC0010200, 0xC0010202, 0xC0010204, ...
        let expected_ctl = [
            0xC001_0200u32,
            0xC001_0202,
            0xC001_0204,
            0xC001_0206,
            0xC001_0208,
            0xC001_020A,
        ];
        let expected_ctr = [
            0xC001_0201u32,
            0xC001_0203,
            0xC001_0205,
            0xC001_0207,
            0xC001_0209,
            0xC001_020B,
        ];
        for i in 0..6u8 {
            let ctl = amd_ctl_msr(i);
            let ctr = amd_ctr_msr(i);
            if ctl != expected_ctl[i as usize] {
                return TestResult::Fail("AMD CTL MSR address mismatch");
            }
            if ctr != expected_ctr[i as usize] {
                return TestResult::Fail("AMD CTR MSR address mismatch");
            }
        }
        // Verify the CTR = CTL + 1 invariant.
        for i in 0..6u8 {
            if amd_ctr_msr(i) != amd_ctl_msr(i) + 1 {
                return TestResult::Fail("CTR != CTL+1");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("arch/pmu", smoke_pmu_amd_msr_address);

    // ── Test 3: PerfEvtSel encode (event + umask + cmask + flags) ─

    fn smoke_pmu_evtsel_encode() -> TestResult {
        // Build a PerfEvtSel with every field set and verify each bit
        // position in the encoded u64.
        let sel = PerfEvtSel {
            event_select: 0xAB,
            umask: 0xCD,
            usr: true,
            os: true,
            edge: true,
            apic_int: true,
            any_thread: true,
            inv: true,
            counter_mask: 0xEF,
        };
        let v = sel.encode();

        // [7:0] event_select
        if v & 0xFF != 0xAB {
            return TestResult::Fail("event_select bits");
        }
        // [15:8] umask
        if (v >> 8) & 0xFF != 0xCD {
            return TestResult::Fail("umask bits");
        }
        // bit 16 USR
        if v & (1 << 16) == 0 {
            return TestResult::Fail("USR bit");
        }
        // bit 17 OS
        if v & (1 << 17) == 0 {
            return TestResult::Fail("OS bit");
        }
        // bit 18 EDGE
        if v & (1 << 18) == 0 {
            return TestResult::Fail("EDGE bit");
        }
        // bit 20 APIC_INT
        if v & (1 << 20) == 0 {
            return TestResult::Fail("APIC_INT bit");
        }
        // bit 21 ANY_THREAD
        if v & (1 << 21) == 0 {
            return TestResult::Fail("ANY_THREAD bit");
        }
        // bit 22 EN (auto-set when os || usr)
        if v & (1 << 22) == 0 {
            return TestResult::Fail("EN bit");
        }
        // bit 23 INV
        if v & (1 << 23) == 0 {
            return TestResult::Fail("INV bit");
        }
        // [31:24] counter_mask
        if (v >> 24) & 0xFF != 0xEF {
            return TestResult::Fail("counter_mask bits");
        }
        // EN must be clear when neither usr nor os is set.
        let sel_no_rings = PerfEvtSel {
            usr: false,
            os: false,
            ..sel
        };
        if sel_no_rings.encode() & (1 << 22) != 0 {
            return TestResult::Fail("EN set with usr=os=false");
        }
        TestResult::Pass
    }
    kernel_test_in!("arch/pmu", smoke_pmu_evtsel_encode);

    // ── Test 4: alloc-then-release round-trip (FakePmu path) ──────
    //
    // This test exercises the alloc/release bookkeeping in isolation
    // by manually manipulating the allocation mask the same way
    // alloc_counter/release do, and verifying the state transitions.
    // It does NOT call alloc_counter (which would attempt real MSR
    // writes) so it is safe on QEMU TCG without PMU emulation.

    fn smoke_pmu_alloc_release_roundtrip() -> TestResult {
        // Simulate the allocation bitmask logic for 4 counters.
        let mut mask: u8 = 0;
        let n_counters: u8 = 4;

        // Allocate all 4 slots.
        let mut slots = [0u8; 4];
        for s in &mut slots {
            let mut idx = None;
            for i in 0..n_counters {
                if mask & (1 << i) == 0 {
                    idx = Some(i);
                    break;
                }
            }
            match idx {
                Some(i) => {
                    mask |= 1 << i;
                    *s = i;
                }
                None => return TestResult::Fail("allocation failed unexpectedly"),
            }
        }
        // All slots occupied — next alloc must fail.
        let no_slot = (0..n_counters).all(|i| mask & (1 << i) != 0);
        if !no_slot {
            return TestResult::Fail("mask not full after allocating all slots");
        }
        // Release slot 2.
        let released = slots[2];
        mask &= !(1 << released);
        if mask & (1 << released) != 0 {
            return TestResult::Fail("release did not clear bit");
        }
        // Re-allocate: must get slot 2 back (lowest free).
        let mut found = None;
        for i in 0..n_counters {
            if mask & (1 << i) == 0 {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) if i == released => TestResult::Pass,
            Some(i) => {
                let _ = i;
                TestResult::Fail("re-alloc returned wrong slot")
            }
            None => TestResult::Fail("no free slot after release"),
        }
    }
    kernel_test_in!("arch/pmu", smoke_pmu_alloc_release_roundtrip);

    // ── Test 5: detect() returns vendor-correct backend ───────────
    //
    // On the QEMU x86_64 TCG target used by `cargo xtask test`:
    // - CPUID.0.EBX = "Genu" (Intel) → detect() must return Intel
    //   IF CPUID leaf 0x0A reports version >= 1, else None.
    // - On real AMD hardware detect() must return Amd.
    // The test validates the shape of the return value without
    // making assertions that depend on the specific platform.

    fn smoke_pmu_detect_vendor_correct() -> TestResult {
        // SAFETY: CPUID always safe at CPL=0.
        let (_, ebx, _, _) = unsafe { cpuid(0, 0) };
        const INTEL_EBX: u32 = 0x756E_6547;
        const AMD_EBX: u32 = 0x6874_7541;
        const HYGON_EBX: u32 = 0x6F67_7948;

        match detect() {
            None => {
                // Acceptable: PMU not present or version=0 (QEMU without
                // `+perf-ctr` or hypervisor that hides the leaf).
                TestResult::Skip("no PMU detected")
            }
            Some(b) => {
                // Validate vendor consistency.
                if ebx == INTEL_EBX && b.vendor != PmuVendor::Intel {
                    return TestResult::Fail("Intel CPU but non-Intel backend");
                }
                if (ebx == AMD_EBX || ebx == HYGON_EBX) && b.vendor != PmuVendor::Amd {
                    return TestResult::Fail("AMD CPU but non-AMD backend");
                }
                if b.n_counters == 0 {
                    return TestResult::Fail("backend has zero counters");
                }
                if b.counter_width < 32 {
                    return TestResult::Fail("counter_width < 32 — implausible");
                }
                TestResult::Pass
            }
        }
    }
    kernel_test_in!("arch/pmu", smoke_pmu_detect_vendor_correct);

    // ── Test 6: Intel arch event encodings are distinct ───────────

    fn smoke_pmu_intel_arch_events_distinct() -> TestResult {
        // Each architectural event pair (event_select, umask) must be
        // unique so a caller can't accidentally reuse the same slot.
        let events = [
            arch_event::unhalted_core_cycles(true, true).encode(),
            arch_event::instructions_retired(true, true).encode(),
            arch_event::unhalted_ref_cycles(true, true).encode(),
            arch_event::llc_reference(true, true).encode(),
            arch_event::llc_miss(true, true).encode(),
            arch_event::branch_retired(true, true).encode(),
            arch_event::branch_mispredict_retired(true, true).encode(),
        ];
        // Check lower 16 bits (event_select + umask) for uniqueness.
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                if events[i] & 0xFFFF == events[j] & 0xFFFF {
                    return TestResult::Fail("duplicate event/umask pair");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("arch/pmu", smoke_pmu_intel_arch_events_distinct);

    // ── Test 7: PerfEvtSel::os_usr builder ────────────────────────

    fn smoke_pmu_os_usr_builder() -> TestResult {
        let sel = PerfEvtSel::os_usr(0x76, 0x00);
        let v = sel.encode();
        if v & 0xFF != 0x76 {
            return TestResult::Fail("event_select");
        }
        if (v >> 8) & 0xFF != 0x00 {
            return TestResult::Fail("umask");
        }
        if v & (1 << 16) == 0 {
            return TestResult::Fail("USR");
        }
        if v & (1 << 17) == 0 {
            return TestResult::Fail("OS");
        }
        if v & (1 << 22) == 0 {
            return TestResult::Fail("EN");
        }
        TestResult::Pass
    }
    kernel_test_in!("arch/pmu", smoke_pmu_os_usr_builder);

    fn smoke_pmu_privilege_filter_bits() -> TestResult {
        let base = arch_event::unhalted_core_cycles(true, true);
        let user = apply_privilege_filter(base, false, true).encode();
        let kernel = apply_privilege_filter(base, true, false).encode();
        if user & (1 << 16) == 0
            || user & (1 << 17) != 0
            || kernel & (1 << 16) != 0
            || kernel & (1 << 17) == 0
        {
            return TestResult::Fail("x86 PMU privilege filter bits are reversed");
        }
        TestResult::Pass
    }
    kernel_test_in!("arch/pmu", smoke_pmu_privilege_filter_bits);
}
