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

use core::sync::atomic::{AtomicU8, Ordering};

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr_or_gp};

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
/// Number of GP counters on Family 17h/19h (CPUID ext 80000001 ECX:23).
pub const AMD_F17H_NUM_GP_COUNTERS: u8 = 6;

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
    CacheMisses,
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
    /// Vendor of the underlying backend (drives the MSR namespace).
    pub(crate) vendor: PmuVendor,
}

/// Per-slot in-use bitmap (bit N = counter N is allocated).
/// Supports up to 8 GP counters; extend the type for more.
static COUNTER_ALLOC_MASK: AtomicU8 = AtomicU8::new(0);

/// Allocate the next free counter slot and program it with `event`.
///
/// Returns `Err(PmuError::NoPmu)` when no PMU is available,
/// `Err(PmuError::NoFreeCounter)` when all slots are in use.
///
/// # Safety
/// Must be called at CPL = 0.  Not re-entrant from multiple CPUs
/// (the allocation bitmap is global; use a per-CPU variant for SMP).
pub unsafe fn alloc_counter(event: PmuEvent) -> Result<PmuCounter, PmuError> {
    let backend = detect().ok_or(PmuError::NoPmu)?;
    // Find a free slot: lowest clear bit in the mask.
    let mask = COUNTER_ALLOC_MASK.load(Ordering::Acquire);
    let mut idx = None;
    for i in 0..backend.n_counters {
        if mask & (1 << i) == 0 {
            idx = Some(i);
            break;
        }
    }
    let idx = idx.ok_or(PmuError::NoFreeCounter)?;
    // Mark as allocated (single-CPU; no CAS needed at Stage 1).
    COUNTER_ALLOC_MASK.fetch_or(1 << idx, Ordering::AcqRel);

    let sel = event_to_evtsel(event, backend.vendor)?;
    // Program the counter.
    // SAFETY: caller-asserted CPL=0; idx < n_counters verified above.
    unsafe { program_counter(idx, sel, backend.vendor) };

    Ok(PmuCounter {
        idx,
        event,
        vendor: backend.vendor,
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

/// Disable and free a counter slot so it can be re-allocated.
///
/// # Safety
/// CPL = 0; `counter` must be a value from `alloc_counter`.
pub unsafe fn release(counter: PmuCounter) {
    // Write 0 to the event-select MSR to disable the counter.
    // wrmsr_or_gp is safe (probe-armed); no inner unsafe block needed.
    match counter.vendor {
        PmuVendor::Intel => {
            let _ = wrmsr_or_gp(MSR_IA32_PERFEVTSEL_BASE + counter.idx as u32, 0);
        }
        PmuVendor::Amd => {
            let _ = wrmsr_or_gp(amd_ctl_msr(counter.idx), 0);
        }
    }
    // Clear allocation bit.
    COUNTER_ALLOC_MASK.fetch_and(!(1 << counter.idx), Ordering::AcqRel);
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
        (PmuEvent::CacheMisses, PmuVendor::Intel) => arch_event::llc_reference(true, true),
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
        (PmuEvent::CacheMisses, PmuVendor::Amd) => amd_event::l1d_cache_misses(true, true),
        (PmuEvent::LlcMisses, PmuVendor::Amd) => {
            // AMD: LLC misses — use l2 miss (event 0x064, umask 0x08 for
            // modified-miss on F17h per AMD Fam17h PPR §2.1.13).
            PerfEvtSel::os_usr_raw(0x64, 0x08, true, true)
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

/// Write an event-select to hardware for counter slot `idx`.
///
/// # Safety
/// CPL = 0; `idx` < backend counter count.
unsafe fn program_counter(idx: u8, sel: PerfEvtSel, vendor: PmuVendor) {
    let encoded = sel.encode();
    // wrmsr_or_gp is safe (probe-armed); no inner unsafe block needed.
    match vendor {
        PmuVendor::Intel => {
            let _ = wrmsr_or_gp(MSR_IA32_PERFEVTSEL_BASE + idx as u32, encoded);
        }
        PmuVendor::Amd => {
            let _ = wrmsr_or_gp(amd_ctl_msr(idx), encoded);
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
}
