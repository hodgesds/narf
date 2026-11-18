// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact RTL8852A PCI SCC configuration of Linux mac.c + rtw8852a.c.
//! The shared AX system/STA/MPDU/security/CMAC routines receive the actual A
//! configuration/cut; this is not B's small SCC or XTAL enable sequence.
use super::{field, Access};
use crate::rtw89::{
    mac_runtime_regs::*,
    power::{Error, Io},
};

pub(in crate::rtw89) const RECIPE: &[u8] = b"NARF RTL8852A closed post-WCPU MAC v1; source generic enable_bb_rf SYS_FUNC_EN3 WLRF_CTRL8282 PHYREG8; sys_init_ax CMAC0 TXEN withheld, OCP; A SCC wde_size0 64/4095+1 ple_size0 128/1520+16 bound32, wde_qt0 3792/196/0/107 ple_qt4,5; HFC all12 ACH128/1896 group0,1 MG32 HI128 public1896/1896/all3792 POH pre2/40; common AX sta_sch (ss2f no-op), MPDU/security TX_PARTIAL clear, CMAC response-check clear, SIFS52A21 RXcap23 actualCBV CCA0 RCR12, A PTCL IMR clearff80df01; host RPQ POH30/255; MAC entry packet DMA+host IRQ closed and MAC1 off; retained source Rx::prepare_for64 ordinary-TX-closed polling RXQ/RPQ AX bases,36bit negotiated coherent maps, actual bounded original ECAM PCIe capability/version/DEVCTL2 LTR and A software LTR8410bit5, original grants on every access, no DBI fallback or invented config; actual A GET_FEATURE register-mailbox receipt after polling RX before radio; no RFK/ordinary grant";
const GROUP: u32 = 1 << 31;
const PUB_G1: u32 = 0x1fff_0000;
impl<I: Io> Access<'_, I> {
    pub(super) fn mac1_off_a(&mut self) -> Result<(), Error> {
        let functions = B_AX_CMAC_EN
            | B_AX_CMAC_TXEN
            | B_AX_CMAC_RXEN
            | B_AX_PHYINTF_EN
            | B_AX_CMAC_DMA_EN
            | B_AX_PTCLTOP_EN
            | B_AX_SCHEDULER_EN
            | B_AX_TMAC_EN
            | B_AX_RMAC_EN
            | B_AX_CMAC_CRPRT;
        let clocks = B_AX_CMAC_CKEN
            | B_AX_PHYINTF_CKEN
            | B_AX_CMAC_DMA_CKEN
            | B_AX_PTCLTOP_CKEN
            | B_AX_SCHEDULER_CKEN
            | B_AX_TMAC_CKEN
            | B_AX_RMAC_CKEN;
        if self.r32(0xe000)? & functions != 0 || self.r32(0xe004)? & clocks != 0 {
            return Err(Error::Access);
        }
        Ok(())
    }
    pub(super) fn enable_bb_rf_a(&mut self) -> Result<(), Error> {
        self.m8(R_AX_SYS_FUNC_EN, 3, 3)?;
        self.m32(R_AX_WLRF_CTRL, 0x8282, 0x8282)?;
        self.m8(R_AX_PHYREG_SET, 8, 8)
    }
    pub(super) async fn scc_a(&mut self) -> Result<(), Error> {
        let dle = B_AX_DLE_WDE_EN | B_AX_DLE_PLE_EN;
        self.m32(R_AX_DMAC_FUNC_EN, dle, 0)?;
        let clk = B_AX_DLE_WDE_CLK_EN | B_AX_DLE_PLE_CLK_EN;
        self.m32(R_AX_DMAC_CLK_EN, clk, clk)?;
        // (4095+1)*64 + (1520+16)*128 =458752; no SCC reservation.
        self.m32(
            R_AX_WDE_PKTBUF_CFG,
            B_AX_WDE_PAGE_SEL_MASK | B_AX_WDE_START_BOUND_MASK | B_AX_WDE_FREE_PAGE_NUM_MASK,
            field(B_AX_WDE_FREE_PAGE_NUM_MASK, 4095),
        )?;
        self.m32(
            R_AX_PLE_PKTBUF_CFG,
            B_AX_PLE_PAGE_SEL_MASK | B_AX_PLE_START_BOUND_MASK | B_AX_PLE_FREE_PAGE_NUM_MASK,
            field(B_AX_PLE_PAGE_SEL_MASK, 1)
                | field(B_AX_PLE_START_BOUND_MASK, 32)
                | field(B_AX_PLE_FREE_PAGE_NUM_MASK, 1520),
        )?;
        for (address, pages) in [
            (R_AX_WDE_QTA0_CFG, 3792),
            (R_AX_WDE_QTA1_CFG, 196),
            (R_AX_WDE_QTA3_CFG, 0),
            (R_AX_WDE_QTA4_CFG, 107),
        ] {
            self.0.write32(
                address,
                field(B_AX_WDE_MIN_SIZE_MASK, pages) | field(B_AX_WDE_MAX_SIZE_MASK, pages),
            )?;
        }
        for (i, (minimum, maximum)) in [
            (264, 264),
            (0, 0),
            (16, 32),
            (20, 20),
            (26, 64),
            (13, 13),
            (356, 1101),
            (0, 0),
            (32, 64),
            (40, 128),
            (8, 120),
        ]
        .into_iter()
        .enumerate()
        {
            self.0.write32(
                R_AX_PLE_QTA0_CFG + 4 * i as u32,
                field(B_AX_PLE_MIN_SIZE_MASK, minimum) | field(B_AX_PLE_MAX_SIZE_MASK, maximum),
            )?;
        }
        self.m32(R_AX_DMAC_FUNC_EN, dle, dle)?;
        self.poll(R_AX_WDE_INI_STATUS, WDE_MGN_INI_RDY, WDE_MGN_INI_RDY, 2000)
            .await?;
        self.poll(R_AX_PLE_INI_STATUS, PLE_MGN_INI_RDY, PLE_MGN_INI_RDY, 2000)
            .await?;
        // preload_init is a real A no-op. Source A dma_ch_mask==0.
        self.m32(R_AX_HCI_FC_CTRL, B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN, 0)?;
        for channel in 0..12u32 {
            let minimum = if channel == 8 || channel == 10 {
                32
            } else {
                128
            };
            let group = if (4..8).contains(&channel) || channel >= 10 {
                GROUP
            } else {
                0
            };
            self.0.write32(
                R_AX_ACH0_PAGE_CTRL + 4 * channel,
                field(B_AX_MIN_PG_MASK, minimum) | field(B_AX_MAX_PG_MASK, 1896) | group,
            )?;
        }
        self.0.write32(
            R_AX_PUB_PAGE_CTRL1,
            field(B_AX_PUBPG_G0_MASK, 1896) | field(PUB_G1, 1896),
        )?;
        self.0.write32(R_AX_WP_PAGE_CTRL2, 0)?;
        self.0.write32(
            R_AX_CH_PAGE_CTRL,
            field(B_AX_PREC_PAGE_CH011_MASK, 2) | field(B_AX_PREC_PAGE_CH12_MASK, 40),
        )?;
        self.0
            .write32(R_AX_PUB_PAGE_CTRL2, field(B_AX_PUBPG_ALL_MASK, 3792))?;
        self.0.write32(R_AX_WP_PAGE_CTRL1, 0)?;
        self.m32(
            R_AX_HCI_FC_CTRL,
            B_AX_HCI_FC_MODE_MASK
                | B_AX_HCI_FC_WD_FULL_COND_MASK
                | B_AX_HCI_FC_CH12_FULL_COND_MASK
                | B_AX_HCI_FC_WP_CH07_FULL_COND_MASK
                | B_AX_HCI_FC_WP_CH811_FULL_COND_MASK,
            field(B_AX_HCI_FC_WD_FULL_COND_MASK, 1),
        )?;
        self.m32(
            R_AX_HCI_FC_CTRL,
            B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN,
            B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN,
        )?;
        self.0.delay_us(10).await;
        for channel in 0..12 {
            self.r32(R_AX_ACH0_PAGE_INFO + 4 * channel)?;
        }
        let used = self.r32(R_AX_PUB_PAGE_INFO1)?;
        self.r32(R_AX_PUB_PAGE_INFO3)?;
        let available = self.r32(R_AX_PUB_PAGE_INFO2)?;
        self.r32(R_AX_WP_PAGE_INFO1)?;
        let ctrl = self.r32(R_AX_HCI_FC_CTRL)?;
        self.r32(R_AX_CH_PAGE_CTRL)?;
        let public = self.r32(R_AX_PUB_PAGE_CTRL2)?;
        self.r32(R_AX_WP_PAGE_CTRL1)?;
        self.r32(R_AX_WP_PAGE_CTRL2)?;
        let groups = self.r32(R_AX_PUB_PAGE_CTRL1)?;
        let get = |v: u32, m: u32| (v & m) >> m.trailing_zeros();
        if get(used, B_AX_G0_USE_PG_MASK)
            + get(used, B_AX_G1_USE_PG_MASK)
            + get(available, B_AX_PUB_AVAL_PG_MASK)
            != get(public, B_AX_PUBPG_ALL_MASK)
            || ctrl & (B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN) != B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN
            || get(groups, B_AX_PUBPG_G0_MASK) != 1896
            || get(groups, PUB_G1) != 1896
            || get(public, B_AX_PUBPG_ALL_MASK) != 3792
            || get(self.r32(R_AX_WDE_PKTBUF_CFG)?, B_AX_WDE_FREE_PAGE_NUM_MASK) != 4095
            || get(self.r32(R_AX_PLE_PKTBUF_CFG)?, B_AX_PLE_FREE_PAGE_NUM_MASK) != 1520
        {
            return Err(Error::Access);
        }
        Ok(())
    }
}
