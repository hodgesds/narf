//! rtlwifi power-sequence command parser + per-chip power-on tables.
//!
//! The rtlwifi family encodes its power-state transitions as arrays of
//! `WlanPwrCfg` structs.  Linux walks the array with
//! `rtl_hal_pwrseqcmdparsing` (`rtlwifi/pwrseqcmd.c`).  Each entry is a
//! (offset, cut-mask, fab/interface-mask, base, cmd, mask, value) tuple
//! and the parser dispatches on `cmd` to do a register write, register
//! polling read, microsecond/millisecond delay, or end-of-table marker.
//!
//! The PCIe-only chips in this driver only ever drive the MAC base
//! (`PWR_BASEADDR_MAC`); SDIO/USB bases are present in the Linux tables
//! for shared driver use but are skipped via the interface mask.
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/pwrseqcmd.h` — struct + command IDs + base addresses
//! - `rtlwifi/pwrseqcmd.c::rtl_hal_pwrseqcmdparsing` — command parser
//! - `rtlwifi/rtl8192ee/pwrseq.{c,h}` — RTL8192EE NIC enable table
//! - `rtlwifi/rtl8188ee/pwrseq.{c,h}` — RTL8188EE table
//! - `rtlwifi/rtl8723be/pwrseq.{c,h}` — RTL8723BE table
//! - `rtlwifi/rtl8821ae/pwrseq.{c,h}` — RTL8821AE table

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

// ── Command IDs (pwrseqcmd.h:12–16) ───────────────────────────────────────

/// `PWR_CMD_READ` — read register at `offset` (informational).
pub const PWR_CMD_READ: u8 = 0x00;
/// `PWR_CMD_WRITE` — read-modify-write `(value & mask)` at `offset`.
pub const PWR_CMD_WRITE: u8 = 0x01;
/// `PWR_CMD_POLLING` — poll `(reg & mask) == (value & mask)`.
pub const PWR_CMD_POLLING: u8 = 0x02;
/// `PWR_CMD_DELAY` — sleep `offset` units of time (us/ms per `value`).
pub const PWR_CMD_DELAY: u8 = 0x03;
/// `PWR_CMD_END` — end of sequence.
pub const PWR_CMD_END: u8 = 0x04;

// ── Base addresses (pwrseqcmd.h:19–22) ────────────────────────────────────

/// `PWR_BASEADDR_MAC` — MMIO MAC register block (the only one used here).
pub const PWR_BASEADDR_MAC: u8 = 0x00;
/// USB / SDIO bases — skipped by PCIe driver but kept for table fidelity.
pub const PWR_BASEADDR_USB: u8 = 0x01;
pub const PWR_BASEADDR_PCIE: u8 = 0x02;
pub const PWR_BASEADDR_SDIO: u8 = 0x03;

// ── Interface mask bits (pwrseqcmd.h:24–27) ───────────────────────────────

pub const PWR_INTF_SDIO_MSK: u8 = 1 << 0;
pub const PWR_INTF_USB_MSK: u8 = 1 << 1;
pub const PWR_INTF_PCI_MSK: u8 = 1 << 2;
pub const PWR_INTF_ALL_MSK: u8 = 0x0F;

// ── Fab mask bits (pwrseqcmd.h:29–31) ─────────────────────────────────────

pub const PWR_FAB_TSMC_MSK: u8 = 1 << 0;
pub const PWR_FAB_UMC_MSK: u8 = 1 << 1;
pub const PWR_FAB_ALL_MSK: u8 = 0x0F;

// ── Cut mask bits (pwrseqcmd.h:33–41) ─────────────────────────────────────

pub const PWR_CUT_TESTCHIP_MSK: u8 = 1 << 0;
pub const PWR_CUT_A_MSK: u8 = 1 << 1;
pub const PWR_CUT_B_MSK: u8 = 1 << 2;
pub const PWR_CUT_C_MSK: u8 = 1 << 3;
pub const PWR_CUT_D_MSK: u8 = 1 << 4;
pub const PWR_CUT_E_MSK: u8 = 1 << 5;
pub const PWR_CUT_ALL_MSK: u8 = 0xFF;

// ── Delay-unit identifier (pwrseqcmd.h:43–46) ─────────────────────────────

pub const PWRSEQ_DELAY_US: u8 = 0;
pub const PWRSEQ_DELAY_MS: u8 = 1;

/// One row of a power sequence.  Mirrors Linux `struct wlan_pwr_cfg`
/// (`pwrseqcmd.h:48-57`) — kept as `#[repr(C)]` so the field layout maps
/// 1:1 to the C source for code-review parity.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WlanPwrCfg {
    pub offset: u16,
    pub cut_msk: u8,
    /// Bits[3:0] = `fab_msk`, bits[7:4] = `interface_msk`.
    pub fab_intf: u8,
    /// Bits[3:0] = `base`, bits[7:4] = `cmd`.
    pub base_cmd: u8,
    pub msk: u8,
    pub value: u8,
}

impl WlanPwrCfg {
    // Eight arguments mirror the eight packed fields of the Linux
    // `wlan_pwr_cfg` table entry; splitting them would obscure the 1:1 mapping.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        offset: u16,
        cut: u8,
        fab: u8,
        intf: u8,
        base: u8,
        cmd: u8,
        msk: u8,
        value: u8,
    ) -> Self {
        Self {
            offset,
            cut_msk: cut,
            fab_intf: (fab & 0x0F) | ((intf & 0x0F) << 4),
            base_cmd: (base & 0x0F) | ((cmd & 0x0F) << 4),
            msk,
            value,
        }
    }

    #[inline]
    pub const fn fab(&self) -> u8 {
        self.fab_intf & 0x0F
    }
    #[inline]
    pub const fn intf(&self) -> u8 {
        (self.fab_intf >> 4) & 0x0F
    }
    #[inline]
    pub const fn base(&self) -> u8 {
        self.base_cmd & 0x0F
    }
    #[inline]
    pub const fn cmd(&self) -> u8 {
        (self.base_cmd >> 4) & 0x0F
    }
}

/// Failure modes from the power-sequence parser.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PwrSeqError {
    /// Polling loop did not converge.  Linux returns `false`; we surface it.
    PollingTimeout,
    /// Unknown command/base, invalid delay unit or missing END — table corruption.
    BadCmd,
    /// Register access could not be authorized or lies outside the aperture.
    Access,
}

/// Register seam shared by the production MMIO parser and traced models.
/// No method may wait on another executor task while the synchronous parser runs.
pub trait Io {
    fn read8(&self, offset: u16) -> Result<u8, PwrSeqError>;
    fn write8(&self, offset: u16, value: u8) -> Result<(), PwrSeqError>;
    fn delay_us(&self, micros: u64) {
        narf_scheduler::responsive_spin_until(|| false, Deadline::after_us(micros));
    }
}
struct MmioIo<'a>(&'a MmioRegion);
impl Io for MmioIo<'_> {
    fn read8(&self, offset: u16) -> Result<u8, PwrSeqError> {
        if u64::from(offset) >= self.0.len {
            return Err(PwrSeqError::Access);
        }
        // SAFETY: run_pwrseq caller owns the mapped register aperture.
        Ok(unsafe { self.0.read8(u64::from(offset)) })
    }
    fn write8(&self, offset: u16, value: u8) -> Result<(), PwrSeqError> {
        if u64::from(offset) >= self.0.len {
            return Err(PwrSeqError::Access);
        }
        // SAFETY: same ownership and checked aperture.
        unsafe { self.0.write8(u64::from(offset), value) };
        Ok(())
    }
}

/// Execute the exact selected rows, preserving unrelated byte fields.
/// PCI matching rows must address MAC registers. Unknown commands, missing END,
/// and access failures stop before any later row is dispatched.
pub fn run_with(
    io: &impl Io,
    cut_version: u8,
    fab_version: u8,
    interface_type: u8,
    table: &[WlanPwrCfg],
) -> Result<(), PwrSeqError> {
    for cfg in table {
        if cfg.fab() & fab_version == 0
            || cfg.cut_msk & cut_version == 0
            || cfg.intf() & interface_type == 0
        {
            continue;
        }
        if cfg.cmd() == PWR_CMD_END {
            return Ok(());
        }
        if cfg.base() != PWR_BASEADDR_MAC {
            return Err(PwrSeqError::BadCmd);
        }
        match cfg.cmd() {
            PWR_CMD_READ => {
                io.read8(cfg.offset)?;
            }
            PWR_CMD_WRITE => {
                let value = io.read8(cfg.offset)?;
                io.write8(cfg.offset, (value & !cfg.msk) | (cfg.value & cfg.msk))?;
            }
            PWR_CMD_POLLING => {
                let mut access = Ok(());
                let done = narf_scheduler::responsive_spin_until(
                    || match io.read8(cfg.offset) {
                        Ok(value) => value & cfg.msk == cfg.value & cfg.msk,
                        Err(error) => {
                            access = Err(error);
                            true
                        }
                    },
                    Deadline::after_ms(100),
                );
                access?;
                if !done {
                    return Err(PwrSeqError::PollingTimeout);
                }
            }
            PWR_CMD_DELAY => {
                let micros = match cfg.value {
                    PWRSEQ_DELAY_US => u64::from(cfg.offset),
                    PWRSEQ_DELAY_MS => u64::from(cfg.offset) * 1000,
                    _ => return Err(PwrSeqError::BadCmd),
                };
                io.delay_us(micros);
            }
            _ => return Err(PwrSeqError::BadCmd),
        }
    }
    Err(PwrSeqError::BadCmd)
}

/// Execute a bounded synchronous power flow over the real register aperture.
///
/// # Safety
/// Caller exclusively owns the BAR2 control region and keeps PCI bus mastering
/// parked until a complete runtime owns all DMA mappings and reset lifecycle.
pub unsafe fn run_pwrseq(
    mmio: &MmioRegion,
    cut_version: u8,
    fab_version: u8,
    interface_type: u8,
    table: &[WlanPwrCfg],
) -> Result<(), PwrSeqError> {
    run_with(
        &MmioIo(mmio),
        cut_version,
        fab_version,
        interface_type,
        table,
    )
}

// ── Per-chip power-on tables ──────────────────────────────────────────────
//
// These mirror the Linux `RTL8XXX_TRANS_CARDEMU_TO_ACT` sequences from
// each chip's `pwrseq.h`.  Cardemu→Active is the only transition the
// driver needs at boot; suspend/resume/disable tables are deferred to a
// follow-up that wires up the WiFi power-management agent.
//
// `BIT(n)` from Linux maps to `1 << n` here; all entries are tagged
// `PWR_CUT_ALL_MSK` / `PWR_FAB_ALL_MSK` / `PWR_INTF_PCI_MSK` for the
// PCIe binding.

/// Convenience: PCIe + all-cuts + all-fabs MAC base.
#[inline]
const fn pci_w(offset: u16, msk: u8, value: u8) -> WlanPwrCfg {
    WlanPwrCfg::new(
        offset,
        PWR_CUT_ALL_MSK,
        PWR_FAB_ALL_MSK,
        PWR_INTF_PCI_MSK,
        PWR_BASEADDR_MAC,
        PWR_CMD_WRITE,
        msk,
        value,
    )
}

/// PCIe + all-cuts + all-fabs MAC base polling row.
#[inline]
const fn pci_p(offset: u16, msk: u8, value: u8) -> WlanPwrCfg {
    WlanPwrCfg::new(
        offset,
        PWR_CUT_ALL_MSK,
        PWR_FAB_ALL_MSK,
        PWR_INTF_PCI_MSK,
        PWR_BASEADDR_MAC,
        PWR_CMD_POLLING,
        msk,
        value,
    )
}

/// End-of-table sentinel (matches Linux `RTL8XXX_TRANS_END`).
#[inline]
const fn pci_end() -> WlanPwrCfg {
    WlanPwrCfg::new(
        0xFFFF,
        PWR_CUT_ALL_MSK,
        PWR_FAB_ALL_MSK,
        PWR_INTF_ALL_MSK,
        0,
        PWR_CMD_END,
        0,
        0,
    )
}

/// RTL8192EE Cardemu→Active power-on flow.
///
/// Source: `rtl8192ee/pwrseq.h::RTL8192E_TRANS_CARDEMU_TO_ACT`.
pub static RTL8192EE_PWR_ON: &[WlanPwrCfg] = &[
    // disable HWPDN 0x04[15]=0
    pci_w(0x0005, 1 << 7, 0),
    // disable SW LPS 0x04[10]=0
    pci_w(0x0005, 1 << 2, 0),
    // disable WL suspend 0x04[12:11]=00
    pci_w(0x0005, (1 << 4) | (1 << 3), 0),
    // wait till 0x04[17] = 1   power ready
    pci_p(0x0006, 1 << 1, 1 << 1),
    // release WLON reset 0x04[16]=1
    pci_w(0x0006, 1 << 0, 1 << 0),
    // 0x04[0]=1
    pci_w(0x0005, 1 << 0, 1 << 0),
    // polling until return 0
    pci_p(0x0005, 1 << 0, 0),
    pci_end(),
];

/// Complete RTL8188EE PCI NIC-enable flow, including CardDisabled→CardEmu.
/// Linux rtl8188ee/pwrseq.c::rtl8188ee_card_enable_flow and pwrseq.h.
/// SDIO-only rows have no PCI match and are omitted.
pub static RTL8188EE_PWR_ON: &[WlanPwrCfg] = &[
    // CardDisabled→CardEmu: disable WL suspend before waiting for ready.
    pci_w(0x0005, 0x18, 0),
    // CardEmu→Active, in source order.
    pci_p(0x0006, 0x02, 0x02),
    pci_w(0x0002, 0x03, 0),    // Reset BB.
    pci_w(0x0026, 0x80, 0x80), // Schmitt trigger.
    pci_w(0x0005, 0x80, 0),    // Disable HWPDN.
    pci_w(0x0005, 0x18, 0),    // Disable WL suspend.
    pci_w(0x0005, 0x01, 0x01), // Request hardware state transition.
    pci_p(0x0005, 0x01, 0),
    pci_w(0x0023, 0x10, 0), // LDO normal mode.
    pci_end(),
];

/// RTL8723BE Cardemu→Active power-on flow.  Source:
/// `rtl8723be/pwrseq.h::RTL8723BE_TRANS_CARDEMU_TO_ACT`.
pub static RTL8723BE_PWR_ON: &[WlanPwrCfg] = &[
    pci_w(0x0005, 1 << 7, 0),
    pci_w(0x0005, 1 << 2, 0),
    pci_w(0x0005, (1 << 4) | (1 << 3), 0),
    pci_p(0x0006, 1 << 1, 1 << 1),
    pci_w(0x0006, 1 << 0, 1 << 0),
    pci_w(0x0005, 1 << 0, 1 << 0),
    pci_p(0x0005, 1 << 0, 0),
    pci_end(),
];

/// RTL8821AE Cardemu→Active power-on flow.  Source:
/// `rtl8821ae/pwrseq.h::RTL8812_TRANS_CARDEMU_TO_ACT`.
pub static RTL8821AE_PWR_ON: &[WlanPwrCfg] = &[
    // 0x20[0]=1  enable LDO
    pci_w(0x0020, 1 << 0, 1 << 0),
    // 0x67[0]=0
    pci_w(0x0067, 1 << 0, 0),
    pci_w(0x0005, 1 << 7, 0),
    pci_p(0x0006, 1 << 1, 1 << 1),
    pci_w(0x0006, 1 << 0, 1 << 0),
    pci_w(0x0005, (1 << 4) | (1 << 3), 0),
    pci_w(0x0005, 1 << 0, 1 << 0),
    pci_p(0x0005, 1 << 0, 0),
    pci_w(0x0023, 1 << 4, 1 << 4),
    pci_end(),
];

/// RTL8192CE Cardemu→Active power-on flow.  Source:
/// `rtl8192ce/pwrseq.h::RTL8192C_TRANS_CARDEMU_TO_ACT`.
pub static RTL8192CE_PWR_ON: &[WlanPwrCfg] = &[
    pci_w(0x0005, 1 << 7, 0),
    pci_p(0x0006, 1 << 1, 1 << 1),
    pci_w(0x0006, 1 << 0, 1 << 0),
    pci_w(0x0005, 1 << 0, 1 << 0),
    pci_p(0x0005, 1 << 0, 0),
    pci_end(),
];

/// RTL8822BE Cardemu→Active power-on flow.  Closely tracks 8821AE since
/// the legacy rtlwifi binding shares the driver class; the table is a
/// trimmed version of `rtl8821ae/pwrseq.h` with the 8822BE-specific
/// rows from the kernel diff (BIT(0) at 0x21 to enable VHT-80 LDO).
pub static RTL8822BE_PWR_ON: &[WlanPwrCfg] = &[
    pci_w(0x0020, 1 << 0, 1 << 0),
    pci_w(0x0021, 1 << 0, 1 << 0),
    pci_w(0x0005, 1 << 7, 0),
    pci_p(0x0006, 1 << 1, 1 << 1),
    pci_w(0x0006, 1 << 0, 1 << 0),
    pci_w(0x0005, (1 << 4) | (1 << 3), 0),
    pci_w(0x0005, 1 << 0, 1 << 0),
    pci_p(0x0005, 1 << 0, 0),
    pci_end(),
];

/// Return the chip's power-on table.  Mirrors how `_rtl<ver>_init_mac`
/// calls `rtl_hal_pwrseqcmdparsing(..., RTL8XXX_NIC_ENABLE_FLOW)` in
/// Linux.
pub fn power_on_table_for(did: u16) -> Option<&'static [WlanPwrCfg]> {
    use super::regs::*;
    match did {
        RTL_DEV_8188EE => Some(RTL8188EE_PWR_ON),
        RTL_DEV_8192CE | RTL_DEV_8192CE_ALT | RTL_DEV_8192DE => Some(RTL8192CE_PWR_ON),
        RTL_DEV_8192EE => Some(RTL8192EE_PWR_ON),
        RTL_DEV_8723AE | RTL_DEV_8723BE => Some(RTL8723BE_PWR_ON),
        RTL_DEV_8821AE => Some(RTL8821AE_PWR_ON),
        RTL_DEV_8822BE => Some(RTL8822BE_PWR_ON),
        _ => None,
    }
}

/// Source-matched per-profile enable entry. RTL8188EE includes the three
/// _rtl88ee_init_mac prefix transactions needed before the NIC-enable table:
/// disable XTAL output/HWPDN and unlock reserved control registers.
pub fn power_on_with(io: &impl Io, did: u16) -> Result<(), PwrSeqError> {
    let table = power_on_table_for(did).ok_or(PwrSeqError::BadCmd)?;
    if did == super::regs::RTL_DEV_8188EE {
        let value = io.read8(0x7c)?;
        io.write8(0x7c, value & !1)?;
        let value = io.read8(5)?;
        io.write8(5, value & !0x80)?;
        io.write8(0x1c, 0)?;
    }
    run_with(
        io,
        PWR_CUT_ALL_MSK,
        PWR_FAB_ALL_MSK,
        PWR_INTF_PCI_MSK,
        table,
    )
}

/// High-level power-on entry. Walks the chip's enable table over PCIe.
///
/// # Safety
/// Caller exclusively owns BAR2 with MEM decoding enabled and bus mastering
/// parked, and dispatches this operation within the live PCI capability.
pub unsafe fn power_on(mmio: &MmioRegion, did: u16) -> Result<(), PwrSeqError> {
    power_on_with(&MmioIo(mmio), did)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "power_tests.rs"]
mod tests;
