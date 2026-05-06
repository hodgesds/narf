//! AMD-Vi IOMMU register layout + caps decode.
//!
//! Spec: `arch/specification/iommu-interconnect.md` §2.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

pub const AMD_VI_DEV_TAB_BASE: usize = 0x00;
pub const AMD_VI_CMD_BUF_BASE: usize = 0x08;
pub const AMD_VI_EVT_LOG_BASE: usize = 0x10;
pub const AMD_VI_CTRL: usize = 0x18;
pub const AMD_VI_EXT_FEATURES: usize = 0x30;
pub const AMD_VI_PPR_LOG_BASE: usize = 0x40;

pub const CTRL_IOMMUEN: u64 = 1 << 0;
pub const CTRL_HTTUNEN: u64 = 1 << 1;
pub const CTRL_EVTLOGEN: u64 = 1 << 2;
pub const CTRL_EVTINTEN: u64 = 1 << 3;
pub const CTRL_COMWAITINTEN: u64 = 1 << 4;
pub const CTRL_CMDBUFEN: u64 = 1 << 8;
pub const CTRL_PPRLOGEN: u64 = 1 << 12;

pub const EFR_PREFSUP: u64 = 1 << 0;
pub const EFR_PPRSUP: u64 = 1 << 1;
pub const EFR_XTSUP: u64 = 1 << 2;
pub const EFR_NXSUP: u64 = 1 << 4;
pub const EFR_GTSUP: u64 = 1 << 5;
pub const EFR_IASUP: u64 = 1 << 7;
pub const EFR_GASUP: u64 = 1 << 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct AmdViCaps {
    pub iommu_enabled: bool,
    pub event_log_enabled: bool,
    pub command_buf_enabled: bool,
    pub ppr_supported: bool,
    pub gt_supported: bool,
    pub xts_supported: bool,
}

unsafe fn r64(base: usize, off: usize) -> u64 {
    // SAFETY: caller-asserted MMIO mapping covers the offset.
    unsafe { read_volatile((base + off) as *const u64) }
}

unsafe fn w64(base: usize, off: usize, v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        write_volatile((base + off) as *mut u64, v);
    }
}

/// Decode the caps that matter for boot-time bring-up.
///
/// # Safety
/// `reg_base` is a strong-uncacheable MMIO mapping of an AMD-Vi
/// engine register block.
pub unsafe fn read_caps(reg_base: usize) -> AmdViCaps {
    // SAFETY: caller-asserted.
    let ctrl = unsafe { r64(reg_base, AMD_VI_CTRL) };
    let efr = unsafe { r64(reg_base, AMD_VI_EXT_FEATURES) };
    decode_caps(ctrl, efr)
}

pub fn decode_caps(ctrl: u64, efr: u64) -> AmdViCaps {
    AmdViCaps {
        iommu_enabled: ctrl & CTRL_IOMMUEN != 0,
        event_log_enabled: ctrl & CTRL_EVTLOGEN != 0,
        command_buf_enabled: ctrl & CTRL_CMDBUFEN != 0,
        ppr_supported: efr & EFR_PPRSUP != 0,
        gt_supported: efr & EFR_GTSUP != 0,
        xts_supported: efr & EFR_XTSUP != 0,
    }
}

/// # Safety
/// `reg_base` is the engine's MMIO mapping.
pub unsafe fn read_ctrl(reg_base: usize) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { r64(reg_base, AMD_VI_CTRL) }
}

pub unsafe fn write_ctrl(reg_base: usize, value: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        w64(reg_base, AMD_VI_CTRL, value);
    }
}
