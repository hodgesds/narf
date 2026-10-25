// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B SCC post-WCPU MAC preparation. Packet DMA and IRQs stay closed.
use super::{
    mac::ChipId,
    mac_runtime_regs::*,
    power::{Error, Io},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    New,
    Preparing,
    Ready,
}
#[derive(Debug)]
pub(super) struct Mac {
    state: State,
}
impl Default for Mac {
    fn default() -> Self {
        Self { state: State::New }
    }
}
struct Access<'a, I>(&'a mut I);
fn field(mask: u32, value: u32) -> u32 {
    (value << mask.trailing_zeros()) & mask
}
impl<I: Io> Access<'_, I> {
    fn r8(&mut self, a: u32) -> Result<u8, Error> {
        self.0.read8(a)
    }
    fn r16(&mut self, a: u32) -> Result<u16, Error> {
        self.0.read16(a)
    }
    fn r32(&mut self, a: u32) -> Result<u32, Error> {
        let value = self.0.read32(a)?;
        if value == u32::MAX {
            Err(Error::Gone)
        } else {
            Ok(value)
        }
    }
    fn m8(&mut self, a: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.r8(a)?;
        self.0
            .write8(a, (u32::from(old) & !mask | value & mask) as u8)
    }
    fn m16(&mut self, a: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.r16(a)?;
        self.0
            .write16(a, (u32::from(old) & !mask | value & mask) as u16)
    }
    fn m32(&mut self, a: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.r32(a)?;
        self.0.write32(a, old & !mask | value & mask)
    }
    fn f32(&mut self, a: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.m32(a, mask, field(mask, value))
    }
    async fn poll(&mut self, a: u32, mask: u32, wanted: u32, budget: u64) -> Result<(), Error> {
        let start = self.0.now_us();
        loop {
            if self.r32(a)? & mask == wanted {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= budget {
                return Err(Error::Timeout);
            }
            self.0.delay_us(1).await;
        }
    }
    async fn xtal(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.0.write32(
            R_AX_WLAN_XTAL_SI_CTRL,
            1 << 31 | 255 << 16 | value << 8 | address,
        )?;
        let start = self.0.now_us();
        loop {
            if self.r32(R_AX_WLAN_XTAL_SI_CTRL)? & (1 << 31) == 0 {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= 50_000 {
                return Err(Error::Timeout);
            }
            self.0.delay_us(50).await;
        }
    }
    async fn enable_bb_rf(&mut self) -> Result<(), Error> {
        self.m8(
            R_AX_SYS_FUNC_EN,
            B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN,
            B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN,
        )?;
        self.f32(R_AX_SPS_DIG_ON_CTRL0, B_AX_REG_ZCDC_H_MASK, 1)?;
        self.m32(R_AX_WLRF_CTRL, B_AX_AFC_AFEDIG, B_AX_AFC_AFEDIG)?;
        self.m32(R_AX_WLRF_CTRL, B_AX_AFC_AFEDIG, 0)?;
        self.m32(R_AX_WLRF_CTRL, B_AX_AFC_AFEDIG, B_AX_AFC_AFEDIG)?;
        self.xtal(XTAL_SI_WL_RFC_S0, 0xc7).await?;
        self.xtal(XTAL_SI_WL_RFC_S1, 0xc7).await?;
        self.0.write8(R_AX_PHYREG_SET, PHYREG_SET_XYN_CYCLE as u8)
    }
    fn system(&mut self) -> Result<(), Error> {
        self.0.write32(
            R_AX_DMAC_FUNC_EN,
            B_AX_MAC_FUNC_EN
                | B_AX_DMAC_FUNC_EN
                | B_AX_MAC_SEC_EN
                | B_AX_DISPATCHER_EN
                | B_AX_DLE_CPUIO_EN
                | B_AX_PKT_IN_EN
                | B_AX_DMAC_TBL_EN
                | B_AX_PKT_BUF_EN
                | B_AX_STA_SCH_EN
                | B_AX_TXPKT_CTRL_EN
                | B_AX_WD_RLS_EN
                | B_AX_MPDU_PROC_EN
                | B_AX_DMAC_CRPRT,
        )?;
        self.0.write32(
            R_AX_DMAC_CLK_EN,
            B_AX_MAC_SEC_CLK_EN
                | B_AX_DISPATCHER_CLK_EN
                | B_AX_DLE_CPUIO_CLK_EN
                | B_AX_PKT_IN_CLK_EN
                | B_AX_STA_SCH_CLK_EN
                | B_AX_TXPKT_CTRL_CLK_EN
                | B_AX_WD_RLS_CLK_EN
                | B_AX_BBRPT_CLK_EN,
        )?;
        let clock = B_AX_CMAC_CKEN
            | B_AX_PHYINTF_CKEN
            | B_AX_CMAC_DMA_CKEN
            | B_AX_PTCLTOP_CKEN
            | B_AX_SCHEDULER_CKEN
            | B_AX_TMAC_CKEN
            | B_AX_RMAC_CKEN;
        let function = B_AX_CMAC_EN
            | B_AX_CMAC_TXEN
            | B_AX_CMAC_RXEN
            | B_AX_PHYINTF_EN
            | B_AX_CMAC_DMA_EN
            | B_AX_PTCLTOP_EN
            | B_AX_SCHEDULER_EN
            | B_AX_TMAC_EN
            | B_AX_RMAC_EN
            | B_AX_CMAC_CRPRT;
        self.m32(R_AX_CK_EN, clock, clock)?;
        // Packet DMA stops do not suppress autonomous ACK/CTS. Keep global
        // CMAC TX parked from this first enable until a measured current
        // channel/response envelope authorizes ordinary RF transmission.
        self.m32(R_AX_CMAC_FUNC_EN, function, function & !B_AX_CMAC_TXEN)?;
        self.m32(R_AX_SPS_DIG_ON_CTRL0, B_AX_OCP_L1_MASK, B_AX_OCP_L1_MASK)
    }
    async fn scc(&mut self) -> Result<(), Error> {
        let dle = B_AX_DLE_WDE_EN | B_AX_DLE_PLE_EN;
        self.m32(R_AX_DMAC_FUNC_EN, dle, 0)?;
        self.m32(
            R_AX_DMAC_CLK_EN,
            B_AX_DLE_WDE_CLK_EN | B_AX_DLE_PLE_CLK_EN,
            B_AX_DLE_WDE_CLK_EN | B_AX_DLE_PLE_CLK_EN,
        )?;
        // B PCI SCC: (510+2)*64 + (496+16)*128 =98304 bytes, with
        // Linux's remaining98304-byte SCC reservation, not the DLFW carve.
        self.m32(
            R_AX_WDE_PKTBUF_CFG,
            B_AX_WDE_PAGE_SEL_MASK | B_AX_WDE_START_BOUND_MASK | B_AX_WDE_FREE_PAGE_NUM_MASK,
            field(B_AX_WDE_FREE_PAGE_NUM_MASK, 510),
        )?;
        self.m32(
            R_AX_PLE_PKTBUF_CFG,
            B_AX_PLE_PAGE_SEL_MASK | B_AX_PLE_START_BOUND_MASK | B_AX_PLE_FREE_PAGE_NUM_MASK,
            field(B_AX_PLE_PAGE_SEL_MASK, 1)
                | field(B_AX_PLE_START_BOUND_MASK, 4)
                | field(B_AX_PLE_FREE_PAGE_NUM_MASK, 496),
        )?;
        for (a, pages) in [
            (R_AX_WDE_QTA0_CFG, 446),
            (R_AX_WDE_QTA1_CFG, 48),
            (R_AX_WDE_QTA3_CFG, 0),
            (R_AX_WDE_QTA4_CFG, 16),
        ] {
            self.0.write32(
                a,
                field(B_AX_WDE_MIN_SIZE_MASK, pages) | field(B_AX_WDE_MAX_SIZE_MASK, pages),
            )?;
        }
        for (i, (minimum, maximum)) in [
            (147, 147),
            (0, 0),
            (16, 16),
            (20, 20),
            (17, 157),
            (13, 13),
            (89, 229),
            (0, 0),
            (32, 172),
            (14, 14),
            (8, 24),
        ]
        .into_iter()
        .enumerate()
        {
            self.0.write32(
                R_AX_PLE_QTA0_CFG + i as u32 * 4,
                field(B_AX_PLE_MIN_SIZE_MASK, minimum) | field(B_AX_PLE_MAX_SIZE_MASK, maximum),
            )?;
        }
        self.m32(R_AX_DMAC_FUNC_EN, dle, dle)?;
        self.poll(R_AX_WDE_INI_STATUS, WDE_MGN_INI_RDY, WDE_MGN_INI_RDY, 2000)
            .await?;
        self.poll(R_AX_PLE_INI_STATUS, PLE_MGN_INI_RDY, PLE_MGN_INI_RDY, 2000)
            .await?;
        // preload_init is a real no-op for8852B's PCI POH path.
        self.m32(R_AX_HCI_FC_CTRL, B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN, 0)?;
        for (channel, (minimum, maximum)) in [
            (5, 341),
            (5, 341),
            (4, 342),
            (4, 342),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (4, 342),
            (4, 342),
            (0, 0),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            // The exact B DMA mask excludes ACH4..7 and band1 management/high.
            if (0x0cf0u32 >> channel) & 1 != 0 {
                continue;
            }
            self.0.write32(
                R_AX_ACH0_PAGE_CTRL + channel as u32 * 4,
                field(B_AX_MIN_PG_MASK, minimum) | field(B_AX_MAX_PG_MASK, maximum),
            )?;
        }
        self.0
            .write32(R_AX_PUB_PAGE_CTRL1, field(B_AX_PUBPG_G0_MASK, 446))?;
        self.0.write32(R_AX_WP_PAGE_CTRL2, 0)?;
        self.0.write32(
            R_AX_CH_PAGE_CTRL,
            field(B_AX_PREC_PAGE_CH011_MASK, 2) | field(B_AX_PREC_PAGE_CH12_MASK, 40),
        )?;
        self.0
            .write32(R_AX_PUB_PAGE_CTRL2, field(B_AX_PUBPG_ALL_MASK, 446))?;
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
        // Read the actual status lanes used by hfc_upd_ch_info/mix_info.
        for channel in [0, 1, 2, 3, 8, 9] {
            self.r32(R_AX_ACH0_PAGE_INFO + channel * 4)?;
        }
        let used = self.r32(R_AX_PUB_PAGE_INFO1)?;
        self.r32(R_AX_PUB_PAGE_INFO3)?;
        let available = self.r32(R_AX_PUB_PAGE_INFO2)?;
        self.r32(R_AX_WP_PAGE_INFO1)?;
        self.r32(R_AX_HCI_FC_CTRL)?;
        self.r32(R_AX_CH_PAGE_CTRL)?;
        let public = self.r32(R_AX_PUB_PAGE_CTRL2)?;
        self.r32(R_AX_WP_PAGE_CTRL1)?;
        self.r32(R_AX_WP_PAGE_CTRL2)?;
        self.r32(R_AX_PUB_PAGE_CTRL1)?;
        let get = |v: u32, m: u32| (v & m) >> m.trailing_zeros();
        if get(used, B_AX_G0_USE_PG_MASK)
            + get(used, B_AX_G1_USE_PG_MASK)
            + get(available, B_AX_PUB_AVAL_PG_MASK)
            != get(public, B_AX_PUBPG_ALL_MASK)
        {
            return Err(Error::Access);
        }
        if self.r32(R_AX_HCI_FC_CTRL)? & (B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN)
            != B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN
            || get(self.r32(R_AX_WDE_PKTBUF_CFG)?, B_AX_WDE_FREE_PAGE_NUM_MASK) != 510
            || get(self.r32(R_AX_PLE_PKTBUF_CFG)?, B_AX_PLE_FREE_PAGE_NUM_MASK) != 496
        {
            return Err(Error::Access);
        }
        Ok(())
    }
    async fn dmac(&mut self) -> Result<(), Error> {
        self.scc().await?;
        self.m8(R_AX_SS_CTRL, B_AX_SS_EN, B_AX_SS_EN)?;
        self.poll(R_AX_SS_CTRL, B_AX_SS_INIT_DONE_1, B_AX_SS_INIT_DONE_1, 2000)
            .await?;
        self.m32(R_AX_SS_CTRL, B_AX_SS_WARM_INIT_FLG, B_AX_SS_WARM_INIT_FLG)?;
        self.m32(R_AX_SS_CTRL, B_AX_SS_NONEMPTY_SS2FINFO_EN, 0)?;
        // The SS2F patch is a documented no-op for8852B.
        self.0
            .write32(R_AX_ACTION_FWD0, TRXCFG_MPDU_PROC_ACT_FRWD)?;
        self.0.write32(R_AX_TF_FWD, TRXCFG_MPDU_PROC_TF_FRWD)?;
        self.m32(
            R_AX_MPDU_PROC,
            B_AX_APPEND_FCS | B_AX_A_ICV_ERR,
            B_AX_APPEND_FCS | B_AX_A_ICV_ERR,
        )?;
        self.0
            .write32(R_AX_CUT_AMSDU_CTRL, TRXCFG_MPDU_PROC_CUT_CTRL)?;
        let security = B_AX_CLK_EN_CGCMP
            | B_AX_CLK_EN_WAPI
            | B_AX_CLK_EN_WEP_TKIP
            | B_AX_SEC_TX_ENC
            | B_AX_SEC_RX_DEC
            | B_AX_MC_DEC
            | B_AX_BC_DEC;
        self.m32(R_AX_SEC_ENG_CTRL, security | B_AX_TX_PARTIAL_MODE, security)?;
        self.m32(
            R_AX_SEC_MPDU_PROC,
            B_AX_APPEND_ICV | B_AX_APPEND_MIC,
            B_AX_APPEND_ICV | B_AX_APPEND_MIC,
        )
    }
    async fn cmac(&mut self) -> Result<(), Error> {
        self.f32(
            R_AX_PREBKF_CFG_1,
            B_AX_SIFS_MACTXEN_T1_MASK,
            SIFS_MACTXEN_T1,
        )?;
        self.m32(
            R_AX_SCH_EXT_CTRL,
            B_AX_PORT_RST_TSF_ADV,
            B_AX_PORT_RST_TSF_ADV,
        )?;
        self.m32(R_AX_CCA_CFG_0, B_AX_BTCCA_EN, 0)?;
        self.f32(R_AX_PREBKF_CFG_0, B_AX_PREBKF_TIME_MASK, SCH_PREBKF_24US)?;
        let cam = field(B_AX_ADDR_CAM_RANGE_MASK, 0x7f) | B_AX_ADDR_CAM_CLR | B_AX_ADDR_CAM_EN;
        self.m32(R_AX_ADDR_CAM_CTRL, cam, cam)?;
        // Linux uses a16-bit read for this self-clearing command.
        let start = self.0.now_us();
        loop {
            if u32::from(self.r16(R_AX_ADDR_CAM_CTRL)?) & B_AX_ADDR_CAM_CLR == 0 {
                break;
            }
            if self.0.now_us().saturating_sub(start) >= 2000 {
                return Err(Error::Timeout);
            }
            self.0.delay_us(1).await;
        }
        for reg in [R_AX_MGNT_FLTR, R_AX_CTRL_FLTR, R_AX_DATA_FLTR] {
            self.0.write32(reg, RX_FLTR_FRAME_TO_HOST)?;
        }
        self.0.write32(R_AX_RX_FLTR_OPT, DEFAULT_AX_RX_FLTR)?;
        self.0.write16(
            R_AX_PLCP_HDR_FLTR,
            (B_AX_CCK_CRC_CHK
                | B_AX_CCK_SIG_CHK
                | B_AX_LSIG_PARITY_CHK_EN
                | B_AX_SIGA_CRC_CHK
                | B_AX_VHT_SU_SIGB_CRC_CHK
                | B_AX_VHT_MU_SIGB_CRC_CHK
                | B_AX_HE_SIGB_CRC_CHK) as u16,
        )?;
        let cca_set = B_AX_TB_CHK_BASIC_NAV
            | B_AX_TB_CHK_BTCCA
            | B_AX_TB_CHK_EDCCA
            | B_AX_TB_CHK_CCA_P20
            | B_AX_SIFS_CHK_BTCCA
            | B_AX_SIFS_CHK_CCA_P20
            | B_AX_CTN_CHK_INTRA_NAV
            | B_AX_CTN_CHK_BASIC_NAV
            | B_AX_CTN_CHK_BTCCA
            | B_AX_CTN_CHK_EDCCA
            | B_AX_CTN_CHK_CCA_S80
            | B_AX_CTN_CHK_CCA_S40
            | B_AX_CTN_CHK_CCA_S20
            | B_AX_CTN_CHK_CCA_P20;
        let cca_clear = B_AX_TB_CHK_TX_NAV
            | B_AX_TB_CHK_CCA_S80
            | B_AX_TB_CHK_CCA_S40
            | B_AX_TB_CHK_CCA_S20
            | B_AX_SIFS_CHK_CCA_S80
            | B_AX_SIFS_CHK_CCA_S40
            | B_AX_SIFS_CHK_CCA_S20
            | B_AX_CTN_CHK_TXNAV
            | B_AX_SIFS_CHK_EDCCA;
        self.m32(R_AX_CCA_CONTROL, cca_set | cca_clear, cca_set)?;
        self.m32(
            R_AX_RSP_CHK_SIG,
            B_AX_RSP_CHK_TXNAV | B_AX_RSP_CHK_INTRA_NAV | B_AX_RSP_CHK_BASIC_NAV,
            0,
        )?;
        self.m32(
            R_AX_TRXPTCL_RESP_0,
            B_AX_RSP_CHK_SEC_CCA_80
                | B_AX_RSP_CHK_SEC_CCA_40
                | B_AX_RSP_CHK_SEC_CCA_20
                | B_AX_RSP_CHK_BTCCA
                | B_AX_RSP_CHK_EDCCA
                | B_AX_RSP_CHK_CCA,
            0,
        )?;
        self.m32(
            R_AX_WMAC_NAV_CTL,
            B_AX_WMAC_PLCP_UP_NAV_EN | B_AX_WMAC_TF_UP_NAV_EN | B_AX_WMAC_NAV_UPPER_EN,
            B_AX_WMAC_PLCP_UP_NAV_EN | B_AX_WMAC_TF_UP_NAV_EN | B_AX_WMAC_NAV_UPPER_EN,
        )?;
        self.f32(R_AX_WMAC_NAV_CTL, B_AX_WMAC_NAV_UPPER_MASK, NAV_25MS)?;
        self.m8(R_AX_RX_SR_CTRL, B_AX_SR_EN, 0)?;
        self.m8(R_AX_BSSID_SRC_CTRL, B_AX_PLCP_SRC_EN, B_AX_PLCP_SRC_EN)?;
        self.m32(R_AX_MAC_LOOPBACK, B_AX_MACLBK_EN, 0)?;
        self.f32(R_AX_TCR0, B_AX_TCR_UDF_THSD_MASK, TCR_UDF_THSD)?;
        self.f32(
            R_AX_TXD_FIFO_CTRL,
            B_AX_TXDFIFO_HIGH_MCS_THRE_MASK,
            TXDFIFO_HIGH_MCS_THRE,
        )?;
        self.f32(
            R_AX_TXD_FIFO_CTRL,
            B_AX_TXDFIFO_LOW_MCS_THRE_MASK,
            TXDFIFO_LOW_MCS_THRE,
        )?;
        self.m32(
            R_AX_TRXPTCL_RESP_0,
            B_AX_WMAC_SPEC_SIFS_CCK_MASK | B_AX_WMAC_SPEC_SIFS_OFDM_MASK,
            field(B_AX_WMAC_SPEC_SIFS_CCK_MASK, WMAC_SPEC_SIFS_CCK)
                | field(B_AX_WMAC_SPEC_SIFS_OFDM_MASK, WMAC_SPEC_SIFS_OFDM_52B),
        )?;
        self.m32(
            R_AX_RXTRIG_TEST_USER_2,
            B_AX_RXTRIG_FCSCHK_EN,
            B_AX_RXTRIG_FCSCHK_EN,
        )?;
        self.f32(R_AX_TRXPTCL_RRSR_CTL_0, B_AX_WMAC_RESP_REF_RATE_SEL, 0)?;
        self.f32(R_AX_TRXPTCL_RRSR_CTL_0, B_AX_WMAC_RESP_RSC_MASK, 2)?;
        self.f32(
            R_AX_RESPBA_CAM_CTRL,
            B_AX_BACAM_RST_MASK,
            S_AX_BACAM_RST_ALL,
        )?;
        // Linux only warns on BA-CAM reset timeout; a retained readiness owner
        // cannot publish Ready for an unconfirmed hardware reset.
        self.poll(R_AX_RESPBA_CAM_CTRL, B_AX_BACAM_RST_MASK, 0, 1000)
            .await?;
        self.m8(R_AX_RESPBA_CAM_CTRL, B_AX_SSN_SEL, B_AX_SSN_SEL)?;
        self.m16(
            R_AX_DLK_PROTECT_CTL,
            B_AX_RX_DLK_DATA_TIME_MASK | B_AX_RX_DLK_CCA_TIME_MASK,
            field(B_AX_RX_DLK_DATA_TIME_MASK, 15) | field(B_AX_RX_DLK_CCA_TIME_MASK, 32),
        )?;
        self.m8(R_AX_RCR, B_AX_CH_EN_MASK, field(B_AX_CH_EN_MASK, 1))?;
        // B SCC cma0_dma minimum89*128=11392 bytes is below Linux's
        //11454+512 cap. Flooring to512-byte units therefore yields22.
        self.f32(R_AX_RX_FLTR_OPT, B_AX_RX_MPDU_MAX_LEN_MASK, 22)?;
        self.m8(R_AX_PLCP_HDR_FLTR, B_AX_VHT_SU_SIGB_CRC_CHK, 0)?;
        self.m32(
            R_AX_TX_SUB_CARRIER_VALUE,
            B_AX_TXSC_20M_MASK | B_AX_TXSC_40M_MASK | B_AX_TXSC_80M_MASK,
            0,
        )?;
        self.f32(R_AX_PTCL_RRSR1, B_AX_RRSR_RATE_EN_MASK, RRSR_OFDM_CCK_EN)?;
        self.m32(
            R_AX_SIFS_SETTING,
            B_AX_HW_CTS2SELF_PKT_LEN_TH_MASK
                | B_AX_HW_CTS2SELF_PKT_LEN_TH_TWW_MASK
                | B_AX_HW_CTS2SELF_EN,
            field(B_AX_HW_CTS2SELF_PKT_LEN_TH_MASK, S_AX_CTS2S_TH_1K)
                | field(B_AX_HW_CTS2SELF_PKT_LEN_TH_TWW_MASK, S_AX_CTS2S_TH_SEC_256B)
                | B_AX_HW_CTS2SELF_EN,
        )?;
        self.m32(
            R_AX_PTCL_FSM_MON,
            B_AX_PTCL_TX_ARB_TO_THR_MASK | B_AX_PTCL_TX_ARB_TO_MODE,
            field(B_AX_PTCL_TX_ARB_TO_THR_MASK, S_AX_PTCL_TO_2MS),
        )?;
        self.m8(
            R_AX_PTCL_COMMON_SETTING_0,
            B_AX_CMAC_TX_MODE_0 | B_AX_CMAC_TX_MODE_1,
            B_AX_CMAC_TX_MODE_0 | B_AX_CMAC_TX_MODE_1,
        )?;
        self.m8(
            R_AX_PTCL_COMMON_SETTING_0,
            B_AX_PTCL_TRIGGER_SS_EN_0 | B_AX_PTCL_TRIGGER_SS_EN_1 | B_AX_PTCL_TRIGGER_SS_EN_UL,
            0,
        )?;
        self.m8(
            R_AX_PTCLRPT_FULL_HDL,
            B_AX_SPE_RPT_PATH_MASK,
            field(B_AX_SPE_RPT_PATH_MASK, FWD_TO_WLCPU),
        )?;
        self.f32(R_AX_AGG_LEN_VHT_0, B_AX_AMPDU_MAX_LEN_VHT_MASK, 0x3ff80)?;
        self.m8(R_AX_RXDMA_CTRL_0, RX_FULL_MODE, 0)
    }
    fn interrupts(&mut self) -> Result<(), Error> {
        // These are internal MAC error masks, not PCI/MSI delivery. Preserve
        // original per-register clr/set ordering, including Linux's zero sets.
        for (reg, clear, set) in [
            (
                R_AX_WDRLS_ERR_IMR,
                B_AX_WDRLS_IMR_EN_CLR,
                B_AX_WDRLS_IMR_SET,
            ),
            (R_AX_SEC_DEBUG, 0, B_AX_IMR_ERROR),
            (
                R_AX_MPDU_TX_ERR_IMR,
                B_AX_TX_GET_ERRPKTID_INT_EN
                    | B_AX_TX_NXT_ERRPKTID_INT_EN
                    | B_AX_TX_MPDU_SIZE_ZERO_INT_EN
                    | B_AX_TX_OFFSET_ERR_INT_EN
                    | B_AX_TX_HDR3_SIZE_ERR_INT_EN,
                0,
            ),
            (
                R_AX_MPDU_RX_ERR_IMR,
                B_AX_GETPKTID_ERR_INT_EN | B_AX_MHDRLEN_ERR_INT_EN | B_AX_RPT_ERR_INT_EN,
                0,
            ),
            (
                R_AX_STA_SCHEDULER_ERR_IMR,
                B_AX_SEARCH_HANG_TIMEOUT_INT_EN
                    | B_AX_RPT_HANG_TIMEOUT_INT_EN
                    | B_AX_PLE_B_PKTID_ERR_INT_EN,
                B_AX_STA_SCHEDULER_IMR_SET,
            ),
            (
                R_AX_TXPKTCTL_ERR_IMR_ISR,
                B_AX_TXPKTCTL_IMR_B0_CLR,
                B_AX_TXPKTCTL_IMR_B0_SET,
            ),
            (
                R_AX_TXPKTCTL_ERR_IMR_ISR_B1,
                B_AX_TXPKTCTL_IMR_B1_CLR,
                B_AX_TXPKTCTL_IMR_B1_SET,
            ),
            (R_AX_WDE_ERR_IMR, B_AX_WDE_IMR_CLR, B_AX_WDE_IMR_SET),
            (R_AX_PLE_ERR_IMR, B_AX_PLE_IMR_CLR, B_AX_PLE_IMR_SET),
            (R_AX_PKTIN_ERR_IMR, 0, B_AX_PKTIN_GETPKTID_ERR_INT_EN),
            (
                R_AX_HOST_DISPATCHER_ERR_IMR,
                B_AX_HOST_DISP_IMR_CLR,
                B_AX_HOST_DISP_IMR_SET,
            ),
            (
                R_AX_CPU_DISPATCHER_ERR_IMR,
                B_AX_CPU_DISP_IMR_CLR,
                B_AX_CPU_DISP_IMR_SET,
            ),
            (R_AX_OTHER_DISPATCHER_ERR_IMR, B_AX_OTHER_DISP_IMR_CLR, 0),
            (R_AX_CPUIO_ERR_IMR, B_AX_CPUIO_IMR_CLR, B_AX_CPUIO_IMR_SET),
            (
                R_AX_BBRPT_COM_ERR_IMR_ISR,
                0,
                B_AX_BBRPT_COM_NULL_PLPKTID_ERR_INT_EN,
            ),
            (R_AX_BBRPT_CHINFO_ERR_IMR_ISR, B_AX_BBRPT_CHINFO_IMR_CLR, 0),
            (R_AX_BBRPT_DFS_ERR_IMR_ISR, 0, B_AX_BBRPT_DFS_TO_ERR_INT_EN),
            (R_AX_LA_ERRFLAG, 0, B_AX_LA_IMR_DATA_LOSS_ERR),
            (
                R_AX_SCHEDULE_ERR_IMR,
                B_AX_SORT_NON_IDLE_ERR_INT_EN | B_AX_FSM_TIMEOUT_ERR_INT_EN,
                B_AX_FSM_TIMEOUT_ERR_INT_EN,
            ),
            (R_AX_PTCL_IMR0, B_AX_PTCL_IMR_CLR_ALL, B_AX_PTCL_IMR_SET),
            (R_AX_DLE_CTRL, B_AX_DLE_IMR_CLR, B_AX_DLE_IMR_SET),
            (R_AX_PHYINFO_ERR_IMR, 0, 0),
            (R_AX_RMAC_ERR_ISR, B_AX_RMAC_IMR_CLR, B_AX_RMAC_IMR_SET),
            (R_AX_TMAC_ERR_IMR_ISR, B_AX_TMAC_IMR_CLR, B_AX_TMAC_IMR_SET),
        ] {
            // Set-only helpers do not issue a synthetic zero clear.
            if !matches!(
                reg,
                R_AX_SEC_DEBUG
                    | R_AX_PKTIN_ERR_IMR
                    | R_AX_BBRPT_COM_ERR_IMR_ISR
                    | R_AX_BBRPT_DFS_ERR_IMR_ISR
                    | R_AX_LA_ERRFLAG
            ) {
                self.m32(reg, clear, 0)?;
            }
            self.m32(reg, set, set)?;
        }
        self.0.write32(R_AX_DMAC_ERR_IMR, DMAC_ERR_IMR_EN)?;
        self.0.write32(R_AX_CMAC_ERR_IMR, CMAC0_ERR_IMR_EN)
    }
    fn host_rpq(&mut self) -> Result<(), Error> {
        self.f32(R_AX_WDRLS_CFG, B_AX_WDRLS_MODE_MASK, 0)?; // RTW89_RPR_MODE_POH
        self.m32(
            R_AX_RLSRPT0_CFG0,
            B_AX_RLSRPT0_FLTR_MAP_MASK,
            B_AX_RLSRPT0_FLTR_MAP_MASK,
        )?;
        self.f32(R_AX_RLSRPT0_CFG1, B_AX_RLSRPT0_AGGNUM_MASK, 30)?;
        self.f32(R_AX_RLSRPT0_CFG1, B_AX_RLSRPT0_TO_MASK, 255)
    }
}
impl Mac {
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Same exclusive/current device backend as the completed cold+firmware
    /// owner. WCPU is actually initialized and CH12 consumption is drained;
    /// no packet DMA, IRQ, radio/channel, key, reset or station producer exists.
    /// The caller retains all previously published DMA even on error or drop.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Io,
        factory: &super::factory::Factory,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        let identity = factory.identity().ok_or(Error::Unsupported)?;
        if identity.chip() != ChipId::Rtl8852B
            || !identity.calibration().valid
            || identity.calibration().rfe_type == 255
            || factory.b_phycap().is_none()
        {
            return Err(Error::Unsupported);
        }
        self.state = State::Preparing;
        let mut a = Access(io);
        let firmware = a.r8(0x1e0)?;
        if firmware == 255 {
            return Err(Error::Gone);
        }
        if (firmware >> 5) & 7 != 7 {
            return Err(Error::Access);
        }
        // Existing TX-only download geometry remains closed to packet/RX DMA
        // throughout MAC preparation; no ring base or host IRQ is written here.
        let stops = a.r32(0x1010)?;
        let init = a.r32(0x1000)?;
        let hci = a.r32(0x8380)?;
        if stops & 0x000b_0f00 != 0x000b_0f00 || init & (1 << 13) != 0 || hci & 2 != 0 {
            return Err(Error::Access);
        }
        a.enable_bb_rf().await?;
        a.system()?;
        a.dmac().await?;
        a.cmac().await?;
        a.interrupts()?;
        a.host_rpq()?;
        let dmac = B_AX_MAC_FUNC_EN
            | B_AX_DMAC_FUNC_EN
            | B_AX_MAC_SEC_EN
            | B_AX_DISPATCHER_EN
            | B_AX_DLE_CPUIO_EN
            | B_AX_PKT_IN_EN
            | B_AX_DMAC_TBL_EN
            | B_AX_PKT_BUF_EN
            | B_AX_STA_SCH_EN
            | B_AX_TXPKT_CTRL_EN
            | B_AX_WD_RLS_EN
            | B_AX_MPDU_PROC_EN
            | B_AX_DMAC_CRPRT
            | B_AX_DLE_WDE_EN
            | B_AX_DLE_PLE_EN;
        let cmac = B_AX_CMAC_EN
            | B_AX_CMAC_TXEN
            | B_AX_CMAC_RXEN
            | B_AX_PHYINTF_EN
            | B_AX_CMAC_DMA_EN
            | B_AX_PTCLTOP_EN
            | B_AX_SCHEDULER_EN
            | B_AX_TMAC_EN
            | B_AX_RMAC_EN
            | B_AX_CMAC_CRPRT;
        let functions = a.r32(R_AX_CMAC_FUNC_EN)?;
        if a.r32(R_AX_DMAC_FUNC_EN)? & dmac != dmac || functions & cmac != cmac & !B_AX_CMAC_TXEN {
            return Err(Error::Access);
        }
        if a.r32(0x1010)? & 0x000b_0f00 != 0x000b_0f00
            || a.r32(0x1000)? & (1 << 13) != 0
            || a.r32(0x8380)? & 2 != 0
        {
            return Err(Error::Access);
        }
        self.state = State::Ready;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mac_runtime/tests.rs"]
mod tests;
