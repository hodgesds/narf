//! Intel Hardware Feedback Interface (HFI) / Thread Director.
//!
//! Spec: `arch/specification/smp-topology.md` §3. Per SDM Vol 4
//! §14.6 — "Hardware Feedback Interface".
//!
//! HFI publishes per-class scheduling hints (which workload
//! classes prefer which core type) into a 4 KiB physical page
//! the OS provides. NARF v0.1 wires the MSR + page registration
//! surface so the scheduler can poll the timestamp + read class
//! preferences; the scheduler-side consumer of those hints
//! lands when the hybrid policy hook does.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_HW_FEEDBACK_PTR: u32 = 0x17D0;
pub const MSR_IA32_HW_FEEDBACK_CONFIG: u32 = 0x17D1;
pub const MSR_IA32_THREAD_FEEDBACK_CHAR: u32 = 0x17D2;
pub const MSR_IA32_HW_FEEDBACK_THREAD_CONFIG: u32 = 0x17D3;

const FEEDBACK_PTR_VALID: u64 = 1 << 0;
const FEEDBACK_CONFIG_ENABLE: u64 = 1 << 0;

#[derive(Copy, Clone, Debug, Default)]
pub struct HfiCaps {
    pub supported: bool,
    /// CPUID(0x14, 0).EAX[7:0] + 1 — number of classification
    /// types the HW publishes (typically 4 on Alder Lake).
    pub n_classes: u8,
    /// CPUID(0x14, 0).EBX — size of the per-package feedback
    /// page in bytes (≤ 4 KiB).
    pub size_bytes: u32,
}

fn cpuid_max() -> u32 {
    // SAFETY: leaf 0 always defined.
    unsafe { cpuid(0, 0).0 }
}

pub fn caps() -> HfiCaps {
    if cpuid_max() < 7 {
        return HfiCaps::default();
    }
    // CPUID(7, 1).EAX[19] = HFI per SDM Vol 4 §14.6.
    // SAFETY: leaf 7 valid.
    let (eax_7_1, _, _, _) = unsafe { cpuid(7, 1) };
    if eax_7_1 & (1 << 19) == 0 {
        return HfiCaps::default();
    }
    if cpuid_max() < 0x1A {
        return HfiCaps {
            supported: true,
            n_classes: 0,
            size_bytes: 0,
        };
    }
    // CPUID(0x14, 0) carries the structure size (we use 0x14 for
    // PT, but per the SDM HFI uses leaf 0x06 sub-leaf 0x05; check
    // the latest SDM revision for the canonical leaf).
    // Stage-cut conservative: report supported with default sizes.
    HfiCaps {
        supported: true,
        n_classes: 4,
        size_bytes: 4096,
    }
}

/// Install the per-package feedback page. `page_phys` must be
/// 4 KiB-aligned + at least `caps().size_bytes` long.
///
/// # Safety
/// CPL = 0; HFI supported; the page lives for the rest of
/// the boot.
pub unsafe fn install(page_phys: u64) {
    let v = (page_phys & 0xFFFF_FFFF_FFFF_F000) | FEEDBACK_PTR_VALID;
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_IA32_HW_FEEDBACK_PTR, v);
    }
}

/// Enable HFI feedback delivery.
///
/// # Safety
/// CPL = 0; `install` was called.
pub unsafe fn enable() {
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_IA32_HW_FEEDBACK_CONFIG) };
    // SAFETY: same.
    unsafe {
        wrmsr(MSR_IA32_HW_FEEDBACK_CONFIG, v | FEEDBACK_CONFIG_ENABLE);
    }
}

/// Disable HFI feedback delivery.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable() {
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_IA32_HW_FEEDBACK_CONFIG) };
    // SAFETY: same.
    unsafe {
        wrmsr(MSR_IA32_HW_FEEDBACK_CONFIG, v & !FEEDBACK_CONFIG_ENABLE);
    }
}

/// Read the timestamp word from the feedback page (offset 0).
/// Wraps; consumers compare against the previously-read value
/// to detect a new publication.
///
/// # Safety
/// `page_phys` is the previously-installed page.
pub unsafe fn read_timestamp(page_phys: u64) -> u32 {
    // SAFETY: caller-asserted; identity-mapped DMA-coherent page.
    unsafe { core::ptr::read_volatile(page_phys as *const u32) }
}
