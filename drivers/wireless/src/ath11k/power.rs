//! Chip power-up: the register sequence Linux runs before starting
//! MHI.
//!
//! `power_up` is Linux `ath11k_pci_power_up` minus `ath11k_mhi_start`
//! (the MHI host is a later phase): `ath11k_pci_sw_reset(ab, true)`,
//! ASPM off for the firmware download, MSI on. The register sequence
//! runs against a [`ChipIo`] so a recording fake can check it
//! offline against Linux — QEMU emulates no ath11k part.
//!
//! Linux references:
//! - `drivers/net/wireless/ath/ath11k/pci.c` — `ath11k_pci_sw_reset`,
//!   `ath11k_pci_enable_ltssm`, `ath11k_pci_clear_all_intrs`,
//!   `ath11k_pci_set_wlaon_pwr_ctrl`, `ath11k_pci_fix_l1ss`,
//!   `ath11k_pci_set_link_reg`, `ath11k_pci_clear_dbg_registers`,
//!   `ath11k_pci_soc_global_reset`, `ath11k_pci_power_up`.
//! - `drivers/net/wireless/ath/ath11k/mhi.c` —
//!   `ath11k_mhi_clear_vector`, `ath11k_mhi_set_mhictrl_reset`.
//! - `drivers/net/wireless/ath/ath11k/pci.h`, `mhi.h` — offsets.

use super::hw::L1ssRegs;
use super::mhi::{
    MHICTRL, MHICTRL_RESET_MASK, MHISTATUS, PCIE_RXVECDB, PCIE_RXVECSTATUS, PCIE_TXVECDB,
    PCIE_TXVECSTATUS,
};

// ── pci.h ──────────────────────────────────────────────────────────

pub const PCIE_SOC_GLOBAL_RESET: u32 = 0x3008;
pub const PCIE_SOC_GLOBAL_RESET_V: u32 = 1;
pub const WLAON_WARM_SW_ENTRY: u32 = 0x01f8_0504;
pub const WLAON_SOC_RESET_CAUSE_REG: u32 = 0x01f8_060c;
pub const PCIE_Q6_COOKIE_ADDR: u32 = 0x01f8_0500;
pub const PCIE_SOC_WAKE_PCIE_LOCAL_REG: u32 = 0x3004;
pub const PCIE_PCIE_PARF_LTSSM: u32 = 0x01e0_81b0;
pub const PARM_LTSSM_VALUE: u32 = 0x111;
pub const GCC_GCC_PCIE_HOT_RST: u32 = 0x01e4_02bc;
pub const GCC_GCC_PCIE_HOT_RST_VAL: u32 = 0x10;
pub const PCIE_PCIE_INT_ALL_CLEAR: u32 = 0x01e0_8228;
pub const PCIE_INT_CLEAR_ALL: u32 = 0xffff_ffff;
pub const PCIE_QSERDES_COM_SYSCLK_EN_SEL_VAL: u32 = 0x10;
pub const PCIE_QSERDES_COM_SYSCLK_EN_SEL_MSK: u32 = 0xffff_ffff;
pub const PCIE_PCS_OSC_DTCT_CONFIG1_VAL: u32 = 0x02;
pub const PCIE_PCS_OSC_DTCT_CONFIG2_VAL: u32 = 0x52;
pub const PCIE_PCS_OSC_DTCT_CONFIG4_VAL: u32 = 0xff;
pub const PCIE_PCS_OSC_DTCT_CONFIG_MSK: u32 = 0x0000_00ff;
pub const WLAON_QFPROM_PWR_CTRL_REG: u32 = 0x01f8_031c;
pub const QFPROM_PWR_CTRL_VDD4BLOW_MASK: u32 = 0x4;

/// Register + delay access the power-up sequence needs. The real
/// implementation is `pci::Bar0Io`; tests substitute a recorder.
pub trait ChipIo {
    /// Linux `ath11k_pcic_read32` (direct below the window start,
    /// windowed above).
    fn read32(&self, offset: u32) -> u32;
    /// Linux `ath11k_pcic_write32`.
    fn write32(&self, offset: u32, value: u32);
    /// Linux `mdelay`.
    fn delay_ms(&self, ms: u32);
    /// The hardware window register was cleared by a global reset;
    /// re-select the cached window (Linux `ath11k_pci_restore_window`).
    fn restore_window(&self);
}

/// Non-fatal anomalies the sequence observed. Linux only warns on
/// each of these (`ath11k_warn` / `ath11k_dbg`) and carries on, so
/// power-up does too; probe logs them.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PowerUpReport {
    /// `PCIE_PCIE_PARF_LTSSM` after the retry loop.
    pub ltssm: u32,
    /// `GCC_GCC_PCIE_HOT_RST` read-back.
    pub hot_rst: u32,
    /// L1SS fix: `Some(offset)` of the first link register that
    /// never took its value (`ath11k_pci_set_link_reg` -ETIMEDOUT).
    pub l1ss_failed_reg: Option<u32>,
    /// `WLAON_SOC_RESET_CAUSE_REG` (read-to-clear).
    pub reset_cause: u32,
    /// `PCIE_SOC_GLOBAL_RESET` read back 0xffffffff after reset —
    /// Linux "link down error during global reset".
    pub link_down_after_reset: bool,
    /// `MHISTATUS` before `MHICTRL_RESET` (SYSERR may be latched).
    pub mhistatus: u32,
}

/// Linux `ath11k_pci_enable_ltssm`.
pub fn enable_ltssm(io: &impl ChipIo, report: &mut PowerUpReport) {
    let mut val = io.read32(PCIE_PCIE_PARF_LTSSM);
    // "PCIE link seems very unstable after the Hot Reset"
    let mut i = 0;
    while val != PARM_LTSSM_VALUE && i < 5 {
        if val == 0xffff_ffff {
            io.delay_ms(5);
        }
        io.write32(PCIE_PCIE_PARF_LTSSM, PARM_LTSSM_VALUE);
        val = io.read32(PCIE_PCIE_PARF_LTSSM);
        i += 1;
    }
    report.ltssm = val;

    let val = io.read32(GCC_GCC_PCIE_HOT_RST) | GCC_GCC_PCIE_HOT_RST_VAL;
    io.write32(GCC_GCC_PCIE_HOT_RST, val);
    report.hot_rst = io.read32(GCC_GCC_PCIE_HOT_RST);

    io.delay_ms(5);
}

/// Linux `ath11k_pci_clear_all_intrs`: the target latches an
/// interrupt on hot reset, and SBL crashes if it sees it on boot.
pub fn clear_all_intrs(io: &impl ChipIo) {
    io.write32(PCIE_PCIE_INT_ALL_CLEAR, PCIE_INT_CLEAR_ALL);
}

/// Linux `ath11k_pci_set_wlaon_pwr_ctrl`.
pub fn set_wlaon_pwr_ctrl(io: &impl ChipIo) {
    let val = io.read32(WLAON_QFPROM_PWR_CTRL_REG) & !QFPROM_PWR_CTRL_VDD4BLOW_MASK;
    io.write32(WLAON_QFPROM_PWR_CTRL_REG, val);
}

/// Linux `ath11k_pci_set_link_reg`: `Ok` once `(reg & mask) ==
/// value`, after up to 10 write attempts 2 ms apart.
pub fn set_link_reg(io: &impl ChipIo, offset: u32, value: u32, mask: u32) -> Result<(), u32> {
    let mut v = io.read32(offset);
    if v & mask == value {
        return Ok(());
    }
    for _ in 0..10 {
        io.write32(offset, (v & !mask) | value);
        v = io.read32(offset);
        if v & mask == value {
            return Ok(());
        }
        io.delay_ms(2);
    }
    Err(offset)
}

/// Linux `ath11k_pci_fix_l1ss`. Stops at the first register that
/// fails, as Linux does.
pub fn fix_l1ss(io: &impl ChipIo, regs: &L1ssRegs) -> Result<(), u32> {
    set_link_reg(
        io,
        regs.qserdes_sysclk_en_sel,
        PCIE_QSERDES_COM_SYSCLK_EN_SEL_VAL,
        PCIE_QSERDES_COM_SYSCLK_EN_SEL_MSK,
    )?;
    for (off, val) in [
        (0x0, PCIE_PCS_OSC_DTCT_CONFIG1_VAL),
        (0x4, PCIE_PCS_OSC_DTCT_CONFIG2_VAL),
        (0xc, PCIE_PCS_OSC_DTCT_CONFIG4_VAL),
    ] {
        set_link_reg(
            io,
            regs.pcs_osc_dtct_config_base + off,
            val,
            PCIE_PCS_OSC_DTCT_CONFIG_MSK,
        )?;
    }
    Ok(())
}

/// Linux `ath11k_mhi_clear_vector`.
pub fn mhi_clear_vector(io: &impl ChipIo) {
    io.write32(PCIE_TXVECDB, 0);
    io.write32(PCIE_TXVECSTATUS, 0);
    io.write32(PCIE_RXVECDB, 0);
    io.write32(PCIE_RXVECSTATUS, 0);
}

/// Linux `ath11k_pci_clear_dbg_registers`.
pub fn clear_dbg_registers(io: &impl ChipIo, report: &mut PowerUpReport) {
    let _cookie = io.read32(PCIE_Q6_COOKIE_ADDR);
    let _warm = io.read32(WLAON_WARM_SW_ENTRY);
    io.delay_ms(10);
    // Stop Q6 continuing the warm path into a dead loop.
    io.write32(WLAON_WARM_SW_ENTRY, 0);
    io.delay_ms(10);
    let _warm = io.read32(WLAON_WARM_SW_ENTRY);
    // Read-to-clear, so Q6 doesn't take the wrong path.
    report.reset_cause = io.read32(WLAON_SOC_RESET_CAUSE_REG);
}

/// Linux `ath11k_pci_soc_global_reset`.
pub fn soc_global_reset(io: &impl ChipIo, report: &mut PowerUpReport) {
    let val = io.read32(PCIE_SOC_GLOBAL_RESET) | PCIE_SOC_GLOBAL_RESET_V;
    io.write32(PCIE_SOC_GLOBAL_RESET, val);
    io.delay_ms(10);
    // The V bit must be toggled back or the SoC stays in reset.
    io.write32(PCIE_SOC_GLOBAL_RESET, val & !PCIE_SOC_GLOBAL_RESET_V);
    io.delay_ms(10);
    if io.read32(PCIE_SOC_GLOBAL_RESET) == 0xffff_ffff {
        report.link_down_after_reset = true;
    }
    // Reset cleared the window register; re-sync it with the cache.
    io.restore_window();
}

/// Linux `ath11k_mhi_set_mhictrl_reset`: after a global reset
/// MHISTATUS may still carry SYSERR, which MHICTRL_RESET clears.
pub fn mhi_set_mhictrl_reset(io: &impl ChipIo, report: &mut PowerUpReport) {
    report.mhistatus = io.read32(MHISTATUS);
    io.write32(MHICTRL, MHICTRL_RESET_MASK);
    io.delay_ms(10);
}

/// Linux `ath11k_pci_sw_reset(ab, power_on)`.
pub fn sw_reset(io: &impl ChipIo, power_on: bool, l1ss: Option<&L1ssRegs>) -> PowerUpReport {
    let mut report = PowerUpReport::default();
    io.delay_ms(100);
    if power_on {
        enable_ltssm(io, &mut report);
        clear_all_intrs(io);
        set_wlaon_pwr_ctrl(io);
        if let Some(regs) = l1ss {
            report.l1ss_failed_reg = fix_l1ss(io, regs).err();
        }
    }
    mhi_clear_vector(io);
    clear_dbg_registers(io, &mut report);
    soc_global_reset(io, &mut report);
    mhi_set_mhictrl_reset(io, &mut report);
    report
}

/// Linux `ath11k_pci_force_wake`.
pub fn force_wake(io: &impl ChipIo) {
    io.write32(PCIE_SOC_WAKE_PCIE_LOCAL_REG, 1);
    io.delay_ms(5);
}
