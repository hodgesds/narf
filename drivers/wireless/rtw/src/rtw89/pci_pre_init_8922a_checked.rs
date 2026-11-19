// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fallible, packet-closed DLFW DLE/HFC + PCI preinit composition.
//!
//! Source programs are those in fwdl_be / this parent (mac.c:1194,2274,
//! mac_be.c:202..410 and pci_be.c:78..135,296..400,484). The deliberate
//! native divergence retains ALL HAXI TX/WPDMA stops until the owned CH12
//! path is enabled. No source TX-channel unstop, data/RX/station grant or
//! assumption that a default-clear BDRAM bit retired memory is made here.
use super::*;
use crate::rtw89::{cold_8922a as cold, fwdl_be as f, power};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Error {
    Io(power::Error),
    State,
    DleSize,
    Readback(u32),
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Io(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    New,
    Dle,
    Recovery,
    Configured,
    Failed,
}

/// Retained original preinit attempt; no caller-created completion receipt.
pub(in crate::rtw89) struct Preinit {
    binding: Option<cold::Binding>,
    stage: Stage,
    cv: u8,
    ser_cleared: bool,
}
impl Preinit {
    pub(in crate::rtw89) const fn new(cv: u8) -> Self {
        Self {
            binding: None,
            stage: Stage::New,
            cv,
            ser_cleared: false,
        }
    }
    fn bind(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        io.current()?;
        if self.binding.is_some_and(|b| b != io.binding()) {
            return Err(Error::State);
        }
        self.binding = Some(io.binding());
        closed(io)
    }
    fn finish(&mut self, r: Result<(), Error>, next: Stage) -> Result<(), Error> {
        self.stage = if r.is_ok() { next } else { Stage::Failed };
        r
    }
    /// Follows Cold::prepare_bbmcu0; neither PCI BME nor a DMA channel is opened.
    pub(in crate::rtw89) fn dle_hfc(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.stage != Stage::New {
            return Err(Error::State);
        }
        let r = (|| {
            self.bind(io)?;
            // Denial-only native sequencing, before DLE work. No ordinary
            // channel is briefly unstopped by source dmac_func_pre_en.
            change(io, f::R_BE_HAXI_DMA_STOP1, 0, 0x8000_7fff)?;
            change(io, f::R_BE_HAXI_INIT_CFG1, 0x30, 0x80)?;
            check(io, f::R_BE_HAXI_DMA_STOP1, 0x8000_7fff, 0x8000_7fff)?;
            check(io, f::R_BE_HAXI_INIT_CFG1, 0xb0, 0x80)?;
            change(
                io,
                f::R_BE_HCI_FUNC_EN,
                0,
                f::B_BE_HCI_TXDMA_EN | f::B_BE_HCI_RXDMA_EN,
            )?;
            change(
                io,
                f::R_BE_HAXI_INIT_CFG1,
                f::B_BE_DMA_MODE_MASK,
                f::S_BE_DMA_MOD_PCIE_NO_DATA_CPU << 8,
            )?;
            change(io, f::R_BE_DMAC_TABLE_CTRL, 0, f::B_BE_DMAC_ADDR_MODE)?;
            dle(io)?;
            change(
                io,
                f::R_BE_HCI_FC_CTRL,
                f::B_BE_HCI_FC_EN | f::B_BE_HCI_FC_CH12_EN,
                0,
            )?;
            let prec = (u32::from(f::HFC_DLFW_H2C_PREC) << 16) & f::B_BE_PREC_PAGE_CH12_V1_MASK;
            write(io, f::R_BE_CH_PAGE_CTRL, prec)?;
            change(
                io,
                f::R_BE_HCI_FC_CTRL,
                f::B_BE_HCI_FC_EN,
                f::B_BE_HCI_FC_CH12_EN,
            )?;
            observe_dle_hfc(io)?;
            closed(io)
        })();
        self.finish(r, Stage::Dle)
    }
    /// Source IO recovery + wake prefix, before owned ring programming.
    pub(in crate::rtw89) fn recovery(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.stage != Stage::Dle {
            return Err(Error::State);
        }
        let r = (|| {
            self.bind(io)?;
            for (a, v) in IO_RCY_TIMERS {
                write(io, a, v)?;
                check(io, a, u32::MAX, v)?;
            }
            change(io, R_BE_HCI_OPT_CTRL, 0, BIT_WAKE_CTRL_V1)?;
            check(io, R_BE_HCI_OPT_CTRL, BIT_WAKE_CTRL_V1, BIT_WAKE_CTRL_V1)?;
            closed(io)
        })();
        self.finish(r, Stage::Recovery)
    }
    /// Source settings AFTER the owned ring/readback + BDRAM configuration.
    /// SER ISR timeout is a Linux warning; failed access still stops effects.
    pub(in crate::rtw89) fn settings(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.stage != Stage::Recovery {
            return Err(Error::State);
        }
        let r = (|| {
            self.bind(io)?;
            change(
                io,
                R_BE_SYS_PAGE_CLK_GATED,
                B_BE_PCIE_PRST_DEBUNC_PERIOD_MASK,
                B_BE_SYM_PRST_DEBUNC_SEL,
            )?;
            change(io, R_BE_SYS_PW_CTRL, 0, B_BE_PSUS_OFF_CAPC_EN)?;
            change(
                io,
                R_BE_SYS_PAGE_CLK_GATED,
                0,
                B_BE_SOP_OFFPOOBS_PC | B_BE_CPHY_AUXCLK_OP | B_BE_CPHY_POWER_READY_CHK,
            )?;
            change(
                io,
                R_BE_SYS_SDIO_CTRL,
                B_BE_PCIE_FORCE_IBX_EN | B_BE_PCIE_DIS_L2_RTK_PERST | B_BE_PCIE_DIS_L2_CTRL_LDO_HCI,
                0,
            )?;
            change(io, R_BE_L1_2_CTRL_HCILDO, B_BE_PCIE_DIS_L1_2_CTRL_HCILDO, 0)?;
            change(io, R_BE_PCIE_FRZ_CLK, 0, B_BE_PCIE_EN_AUX_CLK)?;
            change(io, R_BE_PCIE_PS_CTRL, B_BE_CMAC_EXIT_L1_EN, 0)?;
            if self.cv != 0 {
                change(
                    io,
                    R_BE_EFUSE_CTRL_2_V1,
                    0,
                    B_BE_R_SYM_AUTOLOAD_WITH_PMC_SEL,
                )?;
                change(io, R_BE_PCIE_LAT_CTRL, 0, B_BE_SYM_AUX_CLK_SEL)?;
            }
            write(io, R_BE_PL1_DBG_INFO, 0)?;
            change(io, R_BE_SER_PL1_CTRL, B_BE_PL1_SER_PL1_EN, 0)?;
            if self.cv <= 1 {
                self.ser_cleared = true;
            } else {
                let mut fault = None;
                self.ser_cleared = narf_scheduler::responsive_spin_until(
                    || match io.read32(R_BE_REG_PL1_ISR) {
                        Ok(v) => v == 0,
                        Err(e) => {
                            fault = Some(e);
                            true
                        }
                    },
                    narf_time::Deadline::after_us(1000),
                );
                if let Some(e) = fault {
                    return Err(e.into());
                }
            }
            change(
                io,
                R_BE_SER_PL1_CTRL,
                B_BE_PL1_TIMER_UNIT_MASK,
                PCIE_SER_TIMER_UNIT << 17,
            )?;
            let mask = B_BE_SER_PMU_IMR
                | B_BE_SER_PM_MASTER_IMR
                | B_BE_SER_LTSSM_IMR
                | B_BE_SER_PM_CLK_MASK
                | B_BE_SER_PCLKREQ_ACK_MASK;
            if self.cv <= 1 {
                change(io, R_BE_REG_PL1_MASK, mask | B_BE_SER_L1SUB_IMR, 0)?;
            } else {
                change(io, R_BE_SER_PL1_CTRL, 0, B_BE_PL1_SER_PL1_EN)?;
                change(io, R_BE_REG_PL1_MASK, B_BE_SER_L1SUB_IMR, mask)?;
            }
            closed(io)
        })();
        self.finish(r, Stage::Configured)
    }
    /// Reobserve prerequisites, never minting a new preinit attempt on failure.
    pub(in crate::rtw89) fn ready(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.stage != Stage::Configured {
            return Err(Error::State);
        }
        let r = (|| {
            self.bind(io)?;
            observe_dle_hfc(io)?;
            for (a, v) in IO_RCY_TIMERS {
                check(io, a, u32::MAX, v)?;
            }
            check(io, R_BE_HCI_OPT_CTRL, BIT_WAKE_CTRL_V1, BIT_WAKE_CTRL_V1)
        })();
        self.finish(r, Stage::Configured)
    }
}
fn closed(io: &mut impl cold::Regs) -> Result<(), Error> {
    // The complete source power prefix was observed before this stage; DLE
    // owns only its two engine bits, never the other DMAC function gates.
    check(io, f::R_BE_DMAC_FUNC_EN, 0x7b7f_4f80, 0x7b7f_4f80)?;
    check(
        io,
        f::R_BE_AFE_CTRL1,
        f::B_BE_R_SYM_WLCMAC0_ALL_EN | f::B_BE_R_SYM_WLCMAC1_ALL_EN,
        f::B_BE_R_SYM_WLCMAC0_ALL_EN,
    )?;
    check(
        io,
        f::R_BE_FEN_RST_ENABLE,
        0x0303_0303,
        f::B_BE_CMAC0_FEN | f::B_BE_R_SYM_ISO_CMAC12PP | f::B_BE_FEN_BB_IP_RSTN,
    )?;
    check(
        io,
        f::R_BE_PLATFORM_ENABLE,
        f::B_BE_WCPU_EN | f::B_BE_HOLD_AFTER_RESET,
        f::B_BE_WCPU_EN | f::B_BE_HOLD_AFTER_RESET,
    )?;
    check(io, f::R_BE_CMAC_FUNC_EN, 0x3000_0000, 0)
}
fn write(io: &mut impl cold::Regs, a: u32, v: u32) -> Result<(), Error> {
    closed(io)?;
    io.write32(a, v)?;
    closed(io)
}
fn change(io: &mut impl cold::Regs, a: u32, clear: u32, set: u32) -> Result<(), Error> {
    let v = io.read32(a)?;
    write(io, a, (v & !clear) | set)
}
fn check(io: &mut impl cold::Regs, a: u32, mask: u32, want: u32) -> Result<(), Error> {
    io.current()?;
    if io.read32(a)? & mask != want {
        return Err(Error::Readback(a));
    }
    Ok(())
}
fn quota(io: &mut impl cold::Regs, base: u32, idx: u32, min: u16, max: u16) -> Result<(), Error> {
    let value = (u32::from(min) & 0xfff) | ((u32::from(max) & 0xfff) << 16);
    write(io, base + idx * 4, value)?;
    check(io, base + idx * 4, 0x0fff_0fff, value)
}
fn dle(io: &mut impl cold::Regs) -> Result<(), Error> {
    let cfg = &f::DLE_DLFW_8922A_PCIE;
    if f::dle_used_size(cfg) != f::FIFO_SIZE_8922A {
        return Err(Error::DleSize);
    }
    let mask = f::B_BE_DLE_WDE_EN | f::B_BE_DLE_PLE_EN;
    change(io, f::R_BE_DMAC_FUNC_EN, mask, 0)?;
    change(
        io,
        f::R_BE_DMAC_CLK_EN,
        0,
        f::B_BE_DLE_WDE_CLK_EN | f::B_BE_DLE_PLE_CLK_EN,
    )?;
    for (a, size, select) in [
        (f::R_BE_WDE_PKTBUF_CFG, &cfg.wde_size, 0u32),
        (f::R_BE_PLE_PKTBUF_CFG, &cfg.ple_size, 1u32),
    ] {
        // The fixed source DLFW table is WDE64 / PLE128, no guessed alternative.
        if (select == 0 && size.pge_size != 64) || (select == 1 && size.pge_size != 128) {
            return Err(Error::DleSize);
        }
        let v = (io.read32(a)? & !0x1fff_7f03)
            | select
            | (((size.srt_ofst / 8192) << 8) & 0x7f00)
            | ((u32::from(size.lnk_pge_num) << 16) & 0x1fff_0000);
        write(io, a, v)?;
        check(io, a, 0x1fff_7f03, v & 0x1fff_7f03)?;
    }
    let (min, max) = (&cfg.wde_min_qt, &cfg.wde_max_qt);
    quota(io, f::R_BE_WDE_QTA0_CFG, 0, min.hif, max.hif)?;
    quota(
        io,
        f::R_BE_WDE_QTA0_CFG,
        1,
        f::EXT_WDE_MIN_QT_WCPU_8922A,
        core::cmp::max(max.wcpu, f::EXT_WDE_MIN_QT_WCPU_8922A),
    )?;
    quota(io, f::R_BE_WDE_QTA0_CFG, 2, 0, 0)?;
    quota(io, f::R_BE_WDE_QTA0_CFG, 3, min.pkt_in, max.pkt_in)?;
    quota(io, f::R_BE_WDE_QTA0_CFG, 4, min.cpu_io, max.cpu_io)?;
    for idx in 0..13 {
        quota(
            io,
            f::R_BE_PLE_QTA0_CFG,
            idx as u32,
            cfg.ple_min_qt.0[idx],
            cfg.ple_max_qt.0[idx],
        )?;
    }
    change(io, f::R_BE_DMAC_FUNC_EN, 0, mask)?;
    io.poll32(
        f::R_AX_WDE_INI_STATUS,
        f::DLE_MGN_INI_RDY,
        f::DLE_MGN_INI_RDY,
        2000,
    )?;
    io.poll32(
        f::R_AX_PLE_INI_STATUS,
        f::DLE_MGN_INI_RDY,
        f::DLE_MGN_INI_RDY,
        2000,
    )?;
    Ok(())
}
fn observe_dle_hfc(io: &mut impl cold::Regs) -> Result<(), Error> {
    check(io, f::R_BE_HCI_FUNC_EN, 3, 3)?;
    check(
        io,
        f::R_BE_HAXI_INIT_CFG1,
        f::B_BE_DMA_MODE_MASK,
        f::S_BE_DMA_MOD_PCIE_NO_DATA_CPU << 8,
    )?;
    check(
        io,
        f::R_BE_DMAC_TABLE_CTRL,
        f::B_BE_DMAC_ADDR_MODE,
        f::B_BE_DMAC_ADDR_MODE,
    )?;
    check(
        io,
        f::R_BE_DMAC_CLK_EN,
        f::B_BE_DLE_WDE_CLK_EN | f::B_BE_DLE_PLE_CLK_EN,
        f::B_BE_DLE_WDE_CLK_EN | f::B_BE_DLE_PLE_CLK_EN,
    )?;
    check(
        io,
        f::R_BE_DMAC_FUNC_EN,
        f::B_BE_DLE_WDE_EN | f::B_BE_DLE_PLE_EN,
        f::B_BE_DLE_WDE_EN | f::B_BE_DLE_PLE_EN,
    )?;
    check(
        io,
        f::R_AX_WDE_INI_STATUS,
        f::DLE_MGN_INI_RDY,
        f::DLE_MGN_INI_RDY,
    )?;
    check(
        io,
        f::R_AX_PLE_INI_STATUS,
        f::DLE_MGN_INI_RDY,
        f::DLE_MGN_INI_RDY,
    )?;
    check(
        io,
        f::R_BE_HCI_FC_CTRL,
        f::B_BE_HCI_FC_EN | f::B_BE_HCI_FC_CH12_EN,
        f::B_BE_HCI_FC_CH12_EN,
    )?;
    check(io, f::R_BE_CH_PAGE_CTRL, f::B_BE_PREC_PAGE_CH12_V1_MASK, 0)
}
/// Exact additional register surface; control/status words are all-ones denied
/// by the native ports. No CMAC1 bank, RF or ordinary channel producer is added.
pub(in crate::rtw89) fn permits32(a: u32, write: bool) -> bool {
    let controls = [
        f::R_BE_HCI_FUNC_EN,
        f::R_BE_HAXI_INIT_CFG1,
        f::R_BE_HAXI_DMA_STOP1,
        f::R_BE_DMAC_TABLE_CTRL,
        f::R_BE_DMAC_FUNC_EN,
        f::R_BE_DMAC_CLK_EN,
        f::R_BE_WDE_PKTBUF_CFG,
        f::R_BE_PLE_PKTBUF_CFG,
        f::R_BE_HCI_FC_CTRL,
        f::R_BE_CH_PAGE_CTRL,
        R_BE_HCI_OPT_CTRL,
        R_BE_SYS_PAGE_CLK_GATED,
        R_BE_SYS_PW_CTRL,
        R_BE_SYS_SDIO_CTRL,
        R_BE_L1_2_CTRL_HCILDO,
        R_BE_PCIE_FRZ_CLK,
        R_BE_PCIE_PS_CTRL,
        R_BE_EFUSE_CTRL_2_V1,
        R_BE_PCIE_LAT_CTRL,
        R_BE_PL1_DBG_INFO,
        R_BE_SER_PL1_CTRL,
        R_BE_REG_PL1_MASK,
    ];
    controls.contains(&a)
        || IO_RCY_TIMERS.iter().any(|(r, _)| *r == a)
        || (f::R_BE_WDE_QTA0_CFG..=f::R_BE_WDE_QTA0_CFG + 16).contains(&a) && a % 4 == 0
        || (f::R_BE_PLE_QTA0_CFG..=f::R_BE_PLE_QTA0_CFG + 48).contains(&a) && a % 4 == 0
        || !write
            && [
                f::R_AX_WDE_INI_STATUS,
                f::R_AX_PLE_INI_STATUS,
                R_BE_REG_PL1_ISR,
            ]
            .contains(&a)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "pci_pre_init_8922a_checked_tests.rs"]
mod tests;
