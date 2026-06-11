//! rtlwifi power-sequence command parser + per-chip power-on tables.
//!
//! The rtlwifi family encodes its power-state transitions as arrays of
//! `WlanPwrCfg` structs.  Linux walks the array with
//! `rtl_hal_pwrseqcmdparsing` (`rtlwifi/core.c:1746`).  Each entry is a
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
//! - `rtlwifi/core.c::rtl_hal_pwrseqcmdparsing` — command parser
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
    /// Unknown command word — table corruption.
    BadCmd,
}

/// Walk a power-sequence table.  Mirrors
/// `rtlwifi/core.c::rtl_hal_pwrseqcmdparsing` (line 1746).
///
/// - `cut_version`: e.g. `PWR_CUT_A_MSK` for an A-cut chip.
/// - `fab_version`: e.g. `PWR_FAB_TSMC_MSK`.
/// - `interface_type`: always `PWR_INTF_PCI_MSK` here.
/// - `table`: array of `WlanPwrCfg` ending in `PWR_CMD_END`.
///
/// # Safety
/// Caller must own the BAR0 MMIO region exclusively.
pub unsafe fn run_pwrseq(
    mmio: &MmioRegion,
    cut_version: u8,
    fab_version: u8,
    interface_type: u8,
    table: &[WlanPwrCfg],
) -> Result<(), PwrSeqError> {
    // Linux's `max_polling_cnt = 5000` at 10 µs/step ≈ 50 ms; round to
    // 100 ms for headroom on slower silicon.
    const POLLING_BUDGET_MS: u64 = 100;

    for cfg in table {
        // Linux iterates with `do { ... } while (1)` and breaks on
        // `PWR_CMD_END`; we instead terminate the loop body.
        if cfg.fab() & fab_version == 0
            || cfg.cut_msk & cut_version == 0
            || cfg.intf() & interface_type == 0
        {
            if cfg.cmd() == PWR_CMD_END {
                return Ok(());
            }
            continue;
        }

        match cfg.cmd() {
            PWR_CMD_READ => {
                // Informational only in Linux; preserved for parity.
                // SAFETY: caller-asserted MMIO ownership.
                let _ = unsafe { mmio.read8(cfg.offset as u64) };
            }
            PWR_CMD_WRITE => {
                // SAFETY: same.
                unsafe {
                    let v = mmio.read8(cfg.offset as u64);
                    let v = (v & !cfg.msk) | (cfg.value & cfg.msk);
                    mmio.write8(cfg.offset as u64, v);
                }
            }
            PWR_CMD_POLLING => {
                let mut hit = false;
                let target = cfg.value & cfg.msk;
                let offset = cfg.offset as u64;
                let msk = cfg.msk;
                let done = narf_scheduler::responsive_spin_until(
                    || {
                        // SAFETY: same.
                        let v = unsafe { mmio.read8(offset) } & msk;
                        hit = v == target;
                        hit
                    },
                    Deadline::after_ms(POLLING_BUDGET_MS),
                );
                if !done || !hit {
                    return Err(PwrSeqError::PollingTimeout);
                }
            }
            PWR_CMD_DELAY => {
                // `offset` holds the count, `value` selects unit.
                // Linux uses `udelay` / `mdelay` (busy-wait).  We do the
                // same so the sequence remains synchronous on bring-up
                // paths where the scheduler hasn't started yet.
                let count = cfg.offset as u64;
                let cpns = narf_time::cycles_per_ns().max(1) as u64;
                let cycles = match cfg.value {
                    PWRSEQ_DELAY_MS => count.saturating_mul(1_000_000).saturating_mul(cpns),
                    _ /* PWRSEQ_DELAY_US */ => count.saturating_mul(1_000).saturating_mul(cpns),
                };
                narf_time::busy_wait_cycles(cycles);
            }
            PWR_CMD_END => return Ok(()),
            _ => return Err(PwrSeqError::BadCmd),
        }
    }
    // Fell off the end without `PWR_CMD_END` — treat as success since
    // every legitimate table is terminated.
    Ok(())
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

/// RTL8188EE Cardemu→Active power-on flow.  Source:
/// `rtl8188ee/pwrseq.h::RTL8188EE_TRANS_CARDEMU_TO_ACT`.
pub static RTL8188EE_PWR_ON: &[WlanPwrCfg] = &[
    pci_w(0x0006, 1 << 0, 1 << 0),
    pci_p(0x0006, 1 << 1, 1 << 1),
    pci_w(0x0005, (1 << 4) | (1 << 7), 0),
    pci_w(0x0005, 1 << 0, 1 << 0),
    pci_p(0x0005, 1 << 0, 0),
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

/// High-level power-on entry.  Walks the chip's enable table over PCIe.
///
/// # Safety
/// Caller owns BAR0 exclusively and has already enabled bus-master + MEM.
pub unsafe fn power_on(mmio: &MmioRegion, did: u16) -> Result<(), PwrSeqError> {
    let table = match power_on_table_for(did) {
        Some(t) => t,
        None => return Err(PwrSeqError::BadCmd),
    };
    // Run with the broadest possible chip/fab masks — the driver doesn't
    // sniff cut/fab from EFUSE in this scaffold, and every row in our
    // tables is `PWR_CUT_ALL_MSK | PWR_FAB_ALL_MSK` so the broad mask
    // matches them all.
    // SAFETY: forwarded.
    unsafe {
        run_pwrseq(
            mmio,
            PWR_CUT_ALL_MSK,
            PWR_FAB_ALL_MSK,
            PWR_INTF_PCI_MSK,
            table,
        )
    }
}
