//! Intel iwlwifi — PRPH (peripheral) indirect-access wrapper.
//!
//! Adapted from Linux `drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/
//! trans.c` — `iwl_trans_pcie_read_prph` / `iwl_trans_pcie_write_prph`.
//! GPL-2.0-or-later, citable directly now that NARF relicensed.
//!
//! PRPH registers don't sit in a directly-mapped BAR window. Instead
//! the driver writes the target address to `HBUS_TARG_PRPH_RADDR`
//! (or `_WADDR`) plus a 2-bit "byte count − 1" tag, then reads/writes
//! the data register at `HBUS_TARG_PRPH_RDAT` / `_WDAT`. The MAC must
//! be awake (see `apm_init` and `CSR_GP_CNTRL`'s MAC_ACCESS_REQ +
//! MAC_CLOCK_READY handshake) before any of this works — the driver
//! is responsible for that.
//!
//! Stage-2 lands the offset-packing math and the actual MMIO
//! sequence. Bring-up and bit-flip helpers (`set_bits_prph` etc.)
//! arrive in Stage 3 alongside the firmware load.

#![allow(dead_code)]

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::MmioRegion;

use super::csr;

/// "Size" code stored in bits 25..24 of the PRPH address register.
/// `3` = "4 bytes" (32-bit op); the lower values are byte/word.
/// Linux always uses 3 in `iwl_trans_pcie_{read,write}_prph`.
const PRPH_SIZE_4B: u32 = 3 << 24;

/// PRPH address mask — pre-AX210 (`iwl-prph.h` `PRPH_END = 0xFFFFF`).
const PRPH_MASK_PRE_AX210: u32 = 0x000F_FFFF;
/// PRPH address mask — AX210+ (extended PRPH window).
const PRPH_MASK_AX210: u32 = 0x00FF_FFFF;

/// Which PRPH address-window mask applies to this part. AX200/AX201
/// use 20 bits; AX210/AX211/AX411 use 24 bits — per
/// `iwl_trans_pcie_prph_msk()`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrphMask {
    /// 20-bit PRPH (`device_family < AX210`).
    Mask20,
    /// 24-bit PRPH (`device_family >= AX210`).
    Mask24,
}

impl PrphMask {
    #[inline]
    pub const fn raw(self) -> u32 {
        match self {
            PrphMask::Mask20 => PRPH_MASK_PRE_AX210,
            PrphMask::Mask24 => PRPH_MASK_AX210,
        }
    }
}

/// Pack a PRPH address + size-code into the 32-bit value the
/// HBUS_TARG_PRPH_*ADDR register expects. Implementation matches
/// `iwl_trans_pcie_read_prph`:
///
/// ```text
/// HBUS_TARG_PRPH_RADDR = (reg & mask) | (3 << 24)
/// ```
#[inline]
pub const fn pack_addr(reg: u32, mask: PrphMask) -> u32 {
    (reg & mask.raw()) | PRPH_SIZE_4B
}

/// Read a PRPH register through the HBUS_TARG_* indirect window.
///
/// # Safety
///
/// - The MAC must be awake (driver has done `apm_init` and the
///   MAC_CLOCK_READY bit is set in `CSR_GP_CNTRL`).
/// - `mmio` must be the BAR0 mapping owned exclusively by this
///   driver instance — concurrent PRPH access from another thread
///   would corrupt the address register.
#[inline]
pub unsafe fn read_prph(mmio: &MmioRegion, mask: PrphMask, reg: u32) -> u32 {
    // SAFETY: caller-owned device + awake MAC. The CSR offsets are
    // bounded by the BAR0 mapping size (4 KiB+ on every AX-class
    // part).
    unsafe {
        mmio.write32(csr::HBUS_TARG_PRPH_RADDR as u64, pack_addr(reg, mask));
        compiler_fence(Ordering::SeqCst);
        mmio.read32(csr::HBUS_TARG_PRPH_RDAT as u64)
    }
}

/// Write a PRPH register through the HBUS_TARG_* indirect window.
///
/// # Safety
///
/// Same as `read_prph` — MAC awake, exclusive access.
#[inline]
pub unsafe fn write_prph(mmio: &MmioRegion, mask: PrphMask, reg: u32, val: u32) {
    // SAFETY: caller-owned device + awake MAC.
    unsafe {
        mmio.write32(csr::HBUS_TARG_PRPH_WADDR as u64, pack_addr(reg, mask));
        compiler_fence(Ordering::SeqCst);
        mmio.write32(csr::HBUS_TARG_PRPH_WDAT as u64, val);
    }
}

/// Set the bits in `mask` in PRPH register `reg`. Read-modify-write.
///
/// # Safety
///
/// See `read_prph`. Caller must hold the bus exclusively for the
/// read+write pair — there is no lock here.
#[inline]
pub unsafe fn set_bits_prph(mmio: &MmioRegion, m: PrphMask, reg: u32, bits: u32) {
    // SAFETY: caller-asserted.
    unsafe {
        let cur = read_prph(mmio, m, reg);
        write_prph(mmio, m, reg, cur | bits);
    }
}

/// Clear the bits in `mask` in PRPH register `reg`. Read-modify-write.
///
/// # Safety
///
/// Same as `set_bits_prph`.
#[inline]
pub unsafe fn clear_bits_prph(mmio: &MmioRegion, m: PrphMask, reg: u32, bits: u32) {
    // SAFETY: caller-asserted.
    unsafe {
        let cur = read_prph(mmio, m, reg);
        write_prph(mmio, m, reg, cur & !bits);
    }
}

// ── PRPH register offsets (subset for Stage 2) ────────────────────
//
// Linux `iwl-prph.h`. APMG sub-block lives at `0x3000`; the registers
// we'll actually touch in Stage 2 are the clock-enable + power-mgmt
// controls used by `iwl_pcie_apm_init`.

/// APMG (power management) base within the PRPH window.
pub const APMG_BASE: u32 = 0x3000;
/// Clock control — read-only mirror of the clock enables.
pub const APMG_CLK_CTRL_REG: u32 = APMG_BASE;
/// Clock enable — write `1` bits to enable; `0` bits don't disable.
/// Driver sets `APMG_CLK_VAL_DMA_CLK_RQT` in `apm_init`.
pub const APMG_CLK_EN_REG: u32 = APMG_BASE + 0x0004;
/// Clock disable — write `1` bits to disable.
pub const APMG_CLK_DIS_REG: u32 = APMG_BASE + 0x0008;
/// Power-source / standby control.
pub const APMG_PS_CTRL_REG: u32 = APMG_BASE + 0x000C;
/// PCI device state — disable L1-active here in `apm_init`.
pub const APMG_PCIDEV_STT_REG: u32 = APMG_BASE + 0x0010;
/// RF-kill state mirror.
pub const APMG_RFKILL_REG: u32 = APMG_BASE + 0x0014;
/// RTC interrupt status.
pub const APMG_RTC_INT_STT_REG: u32 = APMG_BASE + 0x001C;
/// RTC interrupt mask.
pub const APMG_RTC_INT_MSK_REG: u32 = APMG_BASE + 0x0020;

/// Bit driver writes to `APMG_CLK_EN_REG` to enable the DMA clock.
pub const APMG_CLK_VAL_DMA_CLK_RQT: u32 = 0x0000_0200;
/// Bit driver writes to `APMG_CLK_EN_REG` to enable the BSM clock.
pub const APMG_CLK_VAL_BSM_CLK_RQT: u32 = 0x0000_0800;

/// Bit in `APMG_PCIDEV_STT_REG` driver sets to disable L1-active
/// during firmware load.
pub const APMG_PCIDEV_STT_VAL_L1_ACT_DIS: u32 = 0x0000_0800;
/// Bit in `APMG_PCIDEV_STT_REG` indicating "wake me" — read-only.
pub const APMG_PCIDEV_STT_VAL_WAKE_ME: u32 = 0x0000_4000;
/// Bit in `APMG_PCIDEV_STT_REG` for "disable persist" — driver clears
/// this in the lp-xtal-enable workaround.
pub const APMG_PCIDEV_STT_VAL_PERSIST_DIS: u32 = 0x0000_0200;

/// Bit in `APMG_RTC_INT_STT_REG` written to clear a pending RFKILL.
pub const APMG_RTC_INT_STT_RFKILL: u32 = 0x1000_0000;
