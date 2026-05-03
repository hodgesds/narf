//! PEBS — Precise Event-Based Sampling.
//!
//! Spec: `arch/specification/security-hardening.md` §2.
//!
//! PEBS streams per-event records (GPR snapshot + EIP + counts)
//! into an OS-supplied buffer described by the `IA32_DS_AREA`
//! Debug-Store save area. NARF v0.1 wires the install + enable
//! surface; consumers (the perf-event recorder) build the
//! `DebugStoreSaveArea` + the PEBS ring + interrupt-on-threshold
//! glue.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_DS_AREA:       u32 = 0x600;
pub const MSR_PEBS_ENABLE:        u32 = 0x3F1;
pub const MSR_PEBS_DATA_CFG:      u32 = 0x3F7;
pub const MSR_IA32_MISC_ENABLE:   u32 = 0x1A0;
const MISC_ENABLE_PEBS_UNAVAIL:   u64 = 1 << 12;

/// `true` iff PEBS is plausibly available — PMU advertised at
/// version >= 1 AND `IA32_MISC_ENABLE.PEBS_UNAVAILABLE` is clear.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x0A { return false; }
    // SAFETY: leaf 0xA valid.
    let (eax, _, _, _) = unsafe { cpuid(0x0A, 0) };
    if eax & 0xFF == 0 { return false; }
    // SAFETY: caller is in CPL=0; MSR architectural since P4.
    let me = unsafe { rdmsr(MSR_IA32_MISC_ENABLE) };
    me & MISC_ENABLE_PEBS_UNAVAIL == 0
}

/// PEBS buffer descriptor — the part of the DS save area the
/// caller cares about.
#[derive(Copy, Clone, Debug)]
pub struct PebsBuffer {
    pub base:                u64,
    pub capacity_records:    u32,
    pub record_size:         u32,
    pub interrupt_threshold: u64,
}

impl PebsBuffer {
    /// Convenience builder for a basic Skylake-style 192-byte
    /// record buffer. `n_records` records placed contiguously
    /// starting at `base`; PMI fires when the index reaches
    /// 75% capacity.
    pub fn skylake_basic(base: u64, n_records: u32) -> Self {
        let record_size = 192;
        let capacity = base + (n_records as u64 * record_size as u64);
        let pmi_at = base + ((n_records as u64 * 3 / 4) * record_size as u64);
        let _ = capacity;
        Self {
            base,
            capacity_records: n_records,
            record_size,
            interrupt_threshold: pmi_at,
        }
    }
}

/// Install the DS save area at `ds_area_phys`. The caller has
/// pre-populated the 80-byte save area with the BTS + PEBS
/// pointers (NARF leaves BTS unused; pebs_buffer_base /
/// pebs_index / pebs_absolute_max / pebs_interrupt_threshold
/// must be set per `pebs`).
///
/// # Safety
/// CPL = 0; the DS save area is identity-mapped + persistent.
pub unsafe fn install_ds(ds_area_phys: u64, pebs: PebsBuffer) {
    // Populate the PEBS portion of the DS save area (offsets
    // 0x20..0x40 per SDM §19.6.1.1).
    // SAFETY: caller-asserted DS area mapping.
    unsafe {
        core::ptr::write_volatile((ds_area_phys + 0x20) as *mut u64, pebs.base);
        core::ptr::write_volatile((ds_area_phys + 0x28) as *mut u64, pebs.base);
        core::ptr::write_volatile(
            (ds_area_phys + 0x30) as *mut u64,
            pebs.base + (pebs.capacity_records as u64 * pebs.record_size as u64),
        );
        core::ptr::write_volatile((ds_area_phys + 0x38) as *mut u64, pebs.interrupt_threshold);
    }
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_DS_AREA, ds_area_phys); }
}

/// Enable PEBS for the counters in `general_mask` (bit i = PMC i).
///
/// # Safety
/// CPL = 0; `install_ds` was called; PEBS supported.
pub unsafe fn enable(general_mask: u32) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_PEBS_ENABLE, general_mask as u64); }
}

/// Disable PEBS on every counter.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable() {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_PEBS_ENABLE, 0); }
}

/// Current write index of the PEBS buffer (for diagnostics —
/// reads `pebs_index` from the DS save area at `ds_area_phys`).
///
/// # Safety
/// `ds_area_phys` is a previously-installed DS save area.
pub unsafe fn current_index(ds_area_phys: u64) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { core::ptr::read_volatile((ds_area_phys + 0x28) as *const u64) }
}
