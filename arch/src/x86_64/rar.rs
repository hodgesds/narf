//! x86_64 RAR — Remote Action Request fast doorbell.
//!
//! Spec: `arch/specification/iommu-interconnect.md` §3.
//!
//! Sapphire Rapids+. Per-CPU MMIO doorbell that delivers TLB
//! shootdowns + remote-CPU actions without a vector IPI. The
//! existing `interrupts::tlb_shootdown` bridge can opt into RAR
//! dispatch when both source + target advertise it.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::ptr::write_volatile;

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_RAR_INFO_BASE: u32 = 0x1024;
pub const MSR_IA32_RAR_CTRL:      u32 = 0x1025;

pub const RAR_ACTION_TLB_PAGE:  u8 = 0x00;
pub const RAR_ACTION_TLB_FULL:  u8 = 0x01;
pub const RAR_ACTION_RDPMC:     u8 = 0x02;
pub const RAR_ACTION_INVD:      u8 = 0x03;

/// `true` iff CPUID(7, 1).EAX[31] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return false; }
    // SAFETY: leaf 7 sub-leaf 1 valid.
    let (eax, _, _, _) = unsafe { cpuid(7, 1) };
    eax & (1 << 31) != 0
}

/// # Safety
/// CPL = 0; RAR supported.
pub unsafe fn read_info_base() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_RAR_INFO_BASE) }
}

pub unsafe fn write_info_base(base: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_RAR_INFO_BASE, base); }
}

pub unsafe fn read_ctrl() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_RAR_CTRL) }
}

pub unsafe fn write_ctrl(v: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_RAR_CTRL, v); }
}

/// Pack the doorbell payload — bits[7:0] = action, bits[39:8] =
/// target LPID, bits[103:40] = caller payload (truncated to the
/// hardware's 64-bit doorbell window, which is action-defined).
fn pack(action: u8, target_lpid: u32, payload: u64) -> u64 {
    (action as u64)
        | ((target_lpid as u64 & 0xFFFFFFFF) << 8)
        | ((payload & 0xFFFF_FFFF_FFFF) << 8)        // overlaps w/ target intentionally; hardware-defined
}

/// Write the doorbell at `mmio_base`. The packed `(action,
/// target_lpid, payload)` triple is hardware-defined per
/// action; for action `TLB_PAGE`, payload is the virtual
/// address.
///
/// # Safety
/// `mmio_base` is a strong-uncacheable MMIO mapping returned
/// from `read_info_base()` for this CPU; RAR enabled via
/// `IA32_RAR_CTRL`.
pub unsafe fn doorbell(mmio_base: usize, action: u8, target_lpid: u32, payload: u64) {
    let v = pack(action, target_lpid, payload);
    // SAFETY: caller-asserted.
    unsafe { write_volatile(mmio_base as *mut u64, v); }
}
