//! PMU programming — Intel architectural perfmon.
//!
//! Spec: `observability/specification/perfmon.md` §1.
//!
//! Surfaces the architectural surface (general-purpose PMC +
//! fixed counters + global enable). Per-event precise sampling
//! (PEBS) is out of scope here.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

// ── MSR map ────────────────────────────────────────────────────────

const MSR_IA32_PERFEVTSEL_BASE: u32 = 0x186;
const MSR_IA32_PMC_BASE:        u32 = 0xC1;
const MSR_PERF_FIXED_CTR_BASE:  u32 = 0x309;
pub const MSR_PERF_FIXED_CTR_CTRL:    u32 = 0x38D;
pub const MSR_IA32_PERF_GLOBAL_STATUS: u32 = 0x38E;
pub const MSR_IA32_PERF_GLOBAL_CTRL:   u32 = 0x38F;
pub const MSR_IA32_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;

// ── Capabilities ───────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct PmuCaps {
    pub version:            u8,
    pub n_general_counters: u8,
    pub width_general:      u8,
    pub n_fixed_counters:   u8,
    pub width_fixed:        u8,
    pub unsupported_arch:   u8,
}

pub fn caps() -> PmuCaps {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x0A { return PmuCaps::default(); }
    // SAFETY: leaf 0xA valid.
    let (eax, ebx, _, edx) = unsafe { cpuid(0x0A, 0) };
    PmuCaps {
        version:             (eax & 0xFF) as u8,
        n_general_counters: ((eax >> 8)  & 0xFF) as u8,
        width_general:      ((eax >> 16) & 0xFF) as u8,
        n_fixed_counters:   (edx & 0x1F) as u8,
        width_fixed:        ((edx >> 5)  & 0xFF) as u8,
        unsupported_arch:   (ebx & 0x7F) as u8,
    }
}

// ── PerfEvtSel encoding ────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct PerfEvtSel {
    pub event_select: u8,
    pub umask:        u8,
    pub usr:          bool,
    pub os:           bool,
    pub edge:         bool,
    pub apic_int:     bool,
    pub any_thread:   bool,
    pub inv:          bool,
    pub counter_mask: u8,
}

impl PerfEvtSel {
    /// Encode into the 64-bit MSR write value with bit 22 (enable)
    /// set when at least one of `usr` / `os` is asked for.
    pub fn encode(&self) -> u64 {
        let mut v = self.event_select as u64
                  | ((self.umask as u64) << 8);
        if self.usr        { v |= 1 << 16; }
        if self.os         { v |= 1 << 17; }
        if self.edge       { v |= 1 << 18; }
        if self.apic_int   { v |= 1 << 20; }
        if self.any_thread { v |= 1 << 21; }
        if self.usr || self.os { v |= 1 << 22; } // enable
        if self.inv        { v |= 1 << 23; }
        v |= (self.counter_mask as u64) << 24;
        v
    }
}

// ── Architectural events ───────────────────────────────────────────

/// Ready-made PerfEvtSel for the architectural events from
/// `observability/specification/perfmon.md` §1.1.
pub mod arch_event {
    use super::PerfEvtSel;

    pub const fn unhalted_core_cycles(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0x3C, umask: 0x00,
            os, usr, ..PerfEvtSel { event_select: 0, umask: 0,
                os: false, usr: false, edge: false, apic_int: false,
                any_thread: false, inv: false, counter_mask: 0 }
        }
    }
    pub const fn instructions_retired(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0xC0, umask: 0x00,
            os, usr, ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn unhalted_ref_cycles(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0x3C, umask: 0x01,
            os, usr, ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn llc_reference(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0x2E, umask: 0x4F,
            os, usr, ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn llc_miss(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0x2E, umask: 0x41,
            os, usr, ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn branch_retired(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0xC4, umask: 0x00,
            os, usr, ..unhalted_core_cycles(false, false)
        }
    }
    pub const fn branch_mispredict_retired(os: bool, usr: bool) -> PerfEvtSel {
        PerfEvtSel {
            event_select: 0xC5, umask: 0x00,
            os, usr, ..unhalted_core_cycles(false, false)
        }
    }
}

// ── Counter programming ────────────────────────────────────────────

/// Program general-purpose counter `idx` with `sel`. Caller is
/// responsible for clearing the counter via `write_general(idx, 0)`
/// before / after if it wants a defined start.
///
/// # Safety
/// CPL = 0; `idx < caps().n_general_counters`.
pub unsafe fn program_general(idx: u8, sel: PerfEvtSel) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_PERFEVTSEL_BASE + idx as u32, sel.encode()); }
}

/// Read general-purpose counter `idx`.
///
/// # Safety
/// CPL = 0; `idx < caps().n_general_counters`.
pub unsafe fn read_general(idx: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_PMC_BASE + idx as u32) }
}

/// Reset general-purpose counter `idx`.
///
/// # Safety
/// Same as `read_general`.
pub unsafe fn write_general(idx: u8, val: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_PMC_BASE + idx as u32, val); }
}

/// Read fixed counter `idx` (0 = instructions retired,
/// 1 = unhalted core cycles, 2 = ref cycles).
///
/// # Safety
/// CPL = 0; `idx < caps().n_fixed_counters`.
pub unsafe fn read_fixed(idx: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_PERF_FIXED_CTR_BASE + idx as u32) }
}

/// Enable fixed counter `idx` for `os` / `usr` rings.
///
/// # Safety
/// CPL = 0.
pub unsafe fn enable_fixed(idx: u8, os: bool, usr: bool) {
    // SAFETY: caller-asserted.
    let cur = unsafe { rdmsr(MSR_PERF_FIXED_CTR_CTRL) };
    let nibble = (os as u64) | ((usr as u64) << 1);
    let mask   = 0xFu64 << (idx as u64 * 4);
    let new    = (cur & !mask) | (nibble << (idx as u64 * 4));
    // SAFETY: same.
    unsafe { wrmsr(MSR_PERF_FIXED_CTR_CTRL, new); }
}

/// Atomically enable a set of counters via `IA32_PERF_GLOBAL_CTRL`.
/// `general_mask` enables `IA32_PMC{i}` (bit i); `fixed_mask`
/// enables `MSR_PERF_FIXED_CTR{i}` (bit i in the high half).
///
/// # Safety
/// CPL = 0.
pub unsafe fn enable_global(general_mask: u32, fixed_mask: u8) {
    let v = (general_mask as u64) | ((fixed_mask as u64) << 32);
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_PERF_GLOBAL_CTRL, v); }
}

/// Disable every counter via `IA32_PERF_GLOBAL_CTRL = 0`.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable_global() {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_PERF_GLOBAL_CTRL, 0); }
}

/// Clear overflow-status bits via `IA32_PERF_GLOBAL_OVF_CTRL`.
///
/// # Safety
/// CPL = 0.
pub unsafe fn clear_overflow(general_mask: u32, fixed_mask: u8) {
    let v = (general_mask as u64) | ((fixed_mask as u64) << 32);
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_PERF_GLOBAL_OVF_CTRL, v); }
}
