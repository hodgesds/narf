// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922AE PCIe `mac_pre_init` register programs.
//!
//! The pieces of Linux `rtw89_pci_ops_mac_pre_init_be`
//! (`pci_be.c:484`) that sit around the DMA halves owned by
//! `dma_8922a` / `Prepared8922a`:
//!
//! ```text
//! set_io_rcy_be                      -> io_rcy
//! _patch_pcie_power_wake_be(true)    -> power_wake
//! _patch_pre_init_be                 -> (8922D CID7090 only; no-op here)
//! wpdma/trxdma off, clr_idx, idle, mode_op -> pre_init_dma_before_reset
//! rtw89_pci_ops_reset                -> Prepared8922a::program_rings
//! rtw89_pci_rst_bdram_be             -> dma_8922a::rst_bdram
//! debounce / ldo_low_pwr / pcie_setting / ser_setting -> settings
//! txdma_ch off, fw_ch on, trxdma on  -> dma_8922a::pre_init_dma_enable
//! ```
//!
//! Only the RTL8922A arms are transcribed: the 8922D / CID7090
//! branches are not reachable from this driver. `cv` is
//! `rtwdev->hal.cv` (`enum rtw89_cv`, `CHIP_CAV` = 0).
//!
//! ## References (GPL-2.0, linux-7.2 `drivers/net/wireless/realtek/rtw89`)
//!
//! - `pci_be.c:17..20` — `PL0_TMR_*`; `pci_be.c:78..135`
//!   `_patch_pcie_power_wake_be`, `_patch_pre_init_be`,
//!   `rtw89_pci_set_io_rcy_be`; `pci_be.c:296..400` debounce,
//!   LDO low power, PCIe setting, SER setting.
//! - `rtw8922ae.c:33..34` — `io_rcy_en = ENABLE`,
//!   `io_rcy_tmr = MAC_AX_IO_RCY_ANA_TMR_DEF`.
//! - `reg.h` / `pci.h` — every register below, cited per constant.

use super::dma_be::Regs;

/// `R_BE_SYS_PW_CTRL`. `reg.h:3828`.
const R_BE_SYS_PW_CTRL: u32 = 0x0004;
/// `B_BE_PSUS_OFF_CAPC_EN`. `reg.h:3846`.
const B_BE_PSUS_OFF_CAPC_EN: u32 = 1 << 14;
/// `R_BE_SYS_PAGE_CLK_GATED`. `reg.h:3876`.
const R_BE_SYS_PAGE_CLK_GATED: u32 = 0x000C;
/// `B_BE_CPHY_POWER_READY_CHK`. `reg.h:3880`.
const B_BE_CPHY_POWER_READY_CHK: u32 = 1 << 24;
/// `B_BE_PCIE_PRST_DEBUNC_PERIOD_MASK` = GENMASK(23, 22). `reg.h:3881`.
const B_BE_PCIE_PRST_DEBUNC_PERIOD_MASK: u32 = 0b11 << 22;
/// `B_BE_SYM_PRST_DEBUNC_SEL`. `reg.h:3882`.
const B_BE_SYM_PRST_DEBUNC_SEL: u32 = 1 << 21;
/// `B_BE_CPHY_AUXCLK_OP`. `reg.h:3883`.
const B_BE_CPHY_AUXCLK_OP: u32 = 1 << 20;
/// `B_BE_SOP_OFFPOOBS_PC`. `reg.h:3885`.
const B_BE_SOP_OFFPOOBS_PC: u32 = 1 << 18;
/// `R_BE_SYS_SDIO_CTRL`. `reg.h:4055`.
const R_BE_SYS_SDIO_CTRL: u32 = 0x0070;
/// `B_BE_PCIE_DIS_L2__CTRL_LDO_HCI`. `reg.h:4065`.
const B_BE_PCIE_DIS_L2_CTRL_LDO_HCI: u32 = 1 << 15;
/// `B_BE_PCIE_DIS_L2_RTK_PERST`. `reg.h:4066`.
const B_BE_PCIE_DIS_L2_RTK_PERST: u32 = 1 << 14;
/// `B_BE_PCIE_FORCE_IBX_EN`. `reg.h:4068`.
const B_BE_PCIE_FORCE_IBX_EN: u32 = 1 << 12;
/// `R_BE_HCI_OPT_CTRL`. `reg.h:4082`.
const R_BE_HCI_OPT_CTRL: u32 = 0x0074;
/// `BIT_WAKE_CTRL_V1`. `reg.h:129`.
const BIT_WAKE_CTRL_V1: u32 = 1 << 23;
/// `R_BE_EFUSE_CTRL_2_V1`. `reg.h:4231`.
const R_BE_EFUSE_CTRL_2_V1: u32 = 0x00A4;
/// `B_BE_R_SYM_AUTOLOAD_WITH_PMC_SEL`. `reg.h:4236`.
const B_BE_R_SYM_AUTOLOAD_WITH_PMC_SEL: u32 = 1 << 24;
/// `R_BE_PCIE_FRZ_CLK`. `pci.h:284`.
const R_BE_PCIE_FRZ_CLK: u32 = 0x3004;
/// `B_BE_PCIE_EN_AUX_CLK`. `pci.h:307`.
const B_BE_PCIE_EN_AUX_CLK: u32 = 1 << 0;
/// `R_BE_PCIE_PS_CTRL`. `pci.h:309`.
const R_BE_PCIE_PS_CTRL: u32 = 0x3008;
/// `B_BE_CMAC_EXIT_L1_EN`. `pci.h:315`.
const B_BE_CMAC_EXIT_L1_EN: u32 = 1 << 7;
/// `R_BE_PCIE_LAT_CTRL`. `pci.h:340`.
const R_BE_PCIE_LAT_CTRL: u32 = 0x3044;
/// `B_BE_SYM_AUX_CLK_SEL`. `pci.h:344`.
const B_BE_SYM_AUX_CLK_SEL: u32 = 1 << 15;
/// `R_BE_L1_2_CTRL_HCILDO`. `pci.h:968`.
const R_BE_L1_2_CTRL_HCILDO: u32 = 0x3110;
/// `B_BE_PCIE_DIS_L1_2_CTRL_HCILDO`. `pci.h:975`.
const B_BE_PCIE_DIS_L1_2_CTRL_HCILDO: u32 = 1 << 0;
/// `R_BE_PL1_DBG_INFO`. `pci.h:977`.
const R_BE_PL1_DBG_INFO: u32 = 0x3120;
/// `R_BE_SER_PL1_CTRL`. `pci.h:1020`.
const R_BE_SER_PL1_CTRL: u32 = 0x34A8;
/// `B_BE_PL1_SER_PL1_EN`. `pci.h:1021`.
const B_BE_PL1_SER_PL1_EN: u32 = 1 << 31;
/// `B_BE_PL1_TIMER_UNIT_MASK` = GENMASK(19, 17). `pci.h:1023`.
const B_BE_PL1_TIMER_UNIT_MASK: u32 = 0b111 << 17;
/// `PCIE_SER_TIMER_UNIT`. `pci.h:1024`.
const PCIE_SER_TIMER_UNIT: u32 = 0x2;
/// `R_BE_REG_PL1_MASK`. `pci.h:1028`.
const R_BE_REG_PL1_MASK: u32 = 0x34B0;
/// `B_BE_SER_*` mask bits. `pci.h:1030..1035`.
const B_BE_SER_PCLKREQ_ACK_MASK: u32 = 1 << 5;
const B_BE_SER_PM_CLK_MASK: u32 = 1 << 4;
const B_BE_SER_LTSSM_IMR: u32 = 1 << 3;
const B_BE_SER_PM_MASTER_IMR: u32 = 1 << 2;
const B_BE_SER_L1SUB_IMR: u32 = 1 << 1;
const B_BE_SER_PMU_IMR: u32 = 1 << 0;
/// `R_BE_REG_PL1_ISR`. `pci.h:1037`.
const R_BE_REG_PL1_ISR: u32 = 0x34B4;

/// IO-recovery watchdog timers (`reg.h:4758..4768`) in the order
/// `rtw89_pci_set_io_rcy_be` writes them, with the `PL0_TMR_*`
/// default each takes (`pci_be.c:17..20`; `PL0_TMR_SCALE_ASIC` = 1).
pub(super) const IO_RCY_TIMERS: [(u32, u32); 11] = [
    (0x306C, 0x800),   // AON_WDT_TMR       ANA_172US
    (0x3090, 0x800),   // MDIO_WDT_TMR
    (0x309C, 0x800),   // LA_MODE_WDT_TMR
    (0x3144, 0x800),   // WDT_AR_TMR
    (0x3150, 0x800),   // WDT_AW_TMR
    (0x315C, 0x800),   // WDT_W_TMR
    (0x3164, 0x800),   // WDT_B_TMR
    (0x316C, 0x800),   // WDT_R_TMR
    (0x3054, 0x27100), // WLAN_WDT_TMR      MAC_1MS
    (0x3060, 0x27100), // AXIDMA_WDT_TMR
    (0x3084, 0x1E848), // LOCAL_WDT_TMR     AUX_1MS
];

/// `PCIE SER clear poll` bound: 1 us × 1000 (`read_poll_timeout_atomic`).
const SER_CLEAR_ATTEMPTS: u32 = 1000;

fn set32(regs: &mut impl Regs, addr: u32, bits: u32) {
    let v = regs.read32(addr);
    regs.write32(addr, v | bits);
}

fn clr32(regs: &mut impl Regs, addr: u32, bits: u32) {
    let v = regs.read32(addr);
    regs.write32(addr, v & !bits);
}

/// `rtw89_pci_set_io_rcy_be` with the 8922AE `io_rcy_en = ENABLE`,
/// `io_rcy_tmr = ANA_TMR_DEF` arm.
pub(super) fn io_rcy(regs: &mut impl Regs) {
    for (addr, value) in IO_RCY_TIMERS {
        regs.write32(addr, value);
    }
}

/// `_patch_pcie_power_wake_be(power_up)`.
pub(super) fn power_wake(regs: &mut impl Regs, power_up: bool) {
    if power_up {
        set32(regs, R_BE_HCI_OPT_CTRL, BIT_WAKE_CTRL_V1);
    } else {
        clr32(regs, R_BE_HCI_OPT_CTRL, BIT_WAKE_CTRL_V1);
    }
}

/// `rtw89_pci_debounce_be`.
pub(super) fn debounce(regs: &mut impl Regs) {
    let v = regs.read32(R_BE_SYS_PAGE_CLK_GATED);
    let v = (v & !B_BE_PCIE_PRST_DEBUNC_PERIOD_MASK) | B_BE_SYM_PRST_DEBUNC_SEL;
    regs.write32(R_BE_SYS_PAGE_CLK_GATED, v);
}

/// `rtw89_pci_ldo_low_pwr_be`, non-8922D arm.
pub(super) fn ldo_low_pwr(regs: &mut impl Regs) {
    set32(regs, R_BE_SYS_PW_CTRL, B_BE_PSUS_OFF_CAPC_EN);
    set32(
        regs,
        R_BE_SYS_PAGE_CLK_GATED,
        B_BE_SOP_OFFPOOBS_PC | B_BE_CPHY_AUXCLK_OP | B_BE_CPHY_POWER_READY_CHK,
    );
    clr32(
        regs,
        R_BE_SYS_SDIO_CTRL,
        B_BE_PCIE_FORCE_IBX_EN | B_BE_PCIE_DIS_L2_RTK_PERST | B_BE_PCIE_DIS_L2_CTRL_LDO_HCI,
    );
    clr32(regs, R_BE_L1_2_CTRL_HCILDO, B_BE_PCIE_DIS_L1_2_CTRL_HCILDO);
}

/// `rtw89_pci_pcie_setting_be`, 8922A arm (CAV stops after the
/// first two writes).
pub(super) fn pcie_setting(regs: &mut impl Regs, cv: u8) {
    set32(regs, R_BE_PCIE_FRZ_CLK, B_BE_PCIE_EN_AUX_CLK);
    clr32(regs, R_BE_PCIE_PS_CTRL, B_BE_CMAC_EXIT_L1_EN);
    if cv == 0 {
        return;
    }
    set32(regs, R_BE_EFUSE_CTRL_2_V1, B_BE_R_SYM_AUTOLOAD_WITH_PMC_SEL);
    set32(regs, R_BE_PCIE_LAT_CTRL, B_BE_SYM_AUX_CLK_SEL);
}

/// `rtw89_pci_ser_setting_be`, 8922A arm. The CCV-and-later SER
/// clear poll only warns in Linux on timeout; here too it is not an
/// error (the return reports whether the ISR cleared).
pub(super) fn ser_setting(regs: &mut impl Regs, cv: u8) -> bool {
    regs.write32(R_BE_PL1_DBG_INFO, 0);
    if cv <= 1 {
        // CHIP_CAV / CHIP_CBV.
        clr32(regs, R_BE_SER_PL1_CTRL, B_BE_PL1_SER_PL1_EN);
        let v = regs.read32(R_BE_SER_PL1_CTRL);
        regs.write32(
            R_BE_SER_PL1_CTRL,
            (v & !B_BE_PL1_TIMER_UNIT_MASK) | (PCIE_SER_TIMER_UNIT << 17),
        );
        let v = regs.read32(R_BE_REG_PL1_MASK)
            & !(B_BE_SER_PMU_IMR
                | B_BE_SER_L1SUB_IMR
                | B_BE_SER_PM_MASTER_IMR
                | B_BE_SER_LTSSM_IMR
                | B_BE_SER_PM_CLK_MASK
                | B_BE_SER_PCLKREQ_ACK_MASK);
        regs.write32(R_BE_REG_PL1_MASK, v);
        return true;
    }
    clr32(regs, R_BE_SER_PL1_CTRL, B_BE_PL1_SER_PL1_EN);
    let mut cleared = false;
    for _ in 0..SER_CLEAR_ATTEMPTS {
        if regs.read32(R_BE_REG_PL1_ISR) == 0 {
            cleared = true;
            break;
        }
    }
    let v = regs.read32(R_BE_SER_PL1_CTRL);
    regs.write32(
        R_BE_SER_PL1_CTRL,
        (v & !B_BE_PL1_TIMER_UNIT_MASK) | (PCIE_SER_TIMER_UNIT << 17),
    );
    set32(regs, R_BE_SER_PL1_CTRL, B_BE_PL1_SER_PL1_EN);
    let v = (regs.read32(R_BE_REG_PL1_MASK)
        | B_BE_SER_PMU_IMR
        | B_BE_SER_PM_MASTER_IMR
        | B_BE_SER_LTSSM_IMR
        | B_BE_SER_PM_CLK_MASK
        | B_BE_SER_PCLKREQ_ACK_MASK)
        & !B_BE_SER_L1SUB_IMR;
    regs.write32(R_BE_REG_PL1_MASK, v);
    cleared
}

/// The settings block between the BDRAM reset and the TX DMA
/// channel gates in `rtw89_pci_ops_mac_pre_init_be`.
pub(super) fn settings(regs: &mut impl Regs, cv: u8) -> bool {
    debounce(regs);
    ldo_low_pwr(regs);
    pcie_setting(regs, cv);
    ser_setting(regs, cv)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "pci_pre_init_8922a_tests.rs"]
mod tests;
