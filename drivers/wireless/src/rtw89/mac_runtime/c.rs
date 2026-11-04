// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C PCIe SCC post-WCPU MAC preparation: the `RTL8852C` branches of
//! Linux mac.c `rtw89_mac_init` (after `rtw89_mac_partial_init`), i.e.
//! rtw8852c.c `rtw8852c_mac_enable_bb_rf`, `sys_init_ax`, `trx_init_ax`
//! (`dmac_init_ax`, `cmac_init_ax(MAC_0)`, `enable_imr_ax` DMAC/CMAC0 with
//! `rtw8852c_imr_info`, `err_imr_ctrl_ax`, `set_host_rpr_ax` and the 8852C
//! `B_AX_RSP_STATIC_RTS_CHK_SERV_BW_EN` clear). `rtw89_mac_feat_init` is a
//! no-op for C (`bacam_ver` is `RTW89_BACAM_V0_EXT`, not V1). Packet DMA and
//! IRQs stay closed exactly as on B; global CMAC TX stays parked.
use super::{field, Access};
use crate::rtw89::{
    mac_runtime_regs::*,
    power::{Error, Io},
};

// reg.h / mac.h values used only by the 8852C branches.
pub(super) const R_AX_AFE_OFF_CTRL1: u32 = 0x0444;
pub(super) const B_AX_S0_LDO_VSEL_F_MASK: u32 = 0x0060_0000;
pub(super) const B_AX_S1_LDO_VSEL_F_MASK: u32 = 0x0300_0000;
pub(super) const XTAL0: u32 = 0x00;
pub(super) const XTAL3: u32 = 0x03;
pub(super) const XTAL_SI_ANAPAR_WL: u32 = 0x90;
pub(super) const B_AX_H_AXIDMA_EN: u32 = 0x4000;
pub(super) const R_AX_HCI_FC_CTRL_V1: u32 = 0x1700;
pub(super) const R_AX_CH_PAGE_CTRL_V1: u32 = 0x1704;
pub(super) const R_AX_ACH0_PAGE_CTRL_V1: u32 = 0x1710;
pub(super) const R_AX_ACH0_PAGE_INFO_V1: u32 = 0x1750;
pub(super) const R_AX_PUB_PAGE_INFO3_V1: u32 = 0x178c;
pub(super) const R_AX_PUB_PAGE_CTRL1_V1: u32 = 0x1790;
pub(super) const R_AX_PUB_PAGE_CTRL2_V1: u32 = 0x1794;
pub(super) const R_AX_PUB_PAGE_INFO1_V1: u32 = 0x1798;
pub(super) const R_AX_PUB_PAGE_INFO2_V1: u32 = 0x179c;
pub(super) const R_AX_WP_PAGE_CTRL1_V1: u32 = 0x17a0;
pub(super) const R_AX_WP_PAGE_CTRL2_V1: u32 = 0x17a4;
pub(super) const R_AX_WP_PAGE_INFO1_V1: u32 = 0x17a8;
pub(super) const B_AX_GRP: u32 = 1 << 31;
pub(super) const B_AX_PUBPG_G1_MASK: u32 = 0x1fff_0000;
pub(super) const R_AX_TXPKTCTL_B0_PRELD_CFG0: u32 = 0x9f48;
pub(super) const B_AX_B0_PRELD_FEN: u32 = 1 << 31;
pub(super) const B_AX_B0_PRELD_USEMAXSZ_MASK: u32 = 0x03ff_0000;
pub(super) const R_AX_TXPKTCTL_B0_PRELD_CFG1: u32 = 0x9f4c;
pub(super) const B_AX_B0_PRELD_NXT_TXENDWIN_MASK: u32 = 0x0f00;
pub(super) const B_AX_B0_PRELD_NXT_RSVMINSZ_MASK: u32 = 0x00ff;
pub(super) const PRELD_B0_ENT_NUM: u32 = 10;
pub(super) const PRELD_AMSDU_SIZE: u32 = 52;
pub(super) const PRELD_NEXT_WND: u32 = 1;
pub(super) const R_AX_SS2FINFO_PATH: u32 = 0x9e50;
pub(super) const B_AX_SS_DEST_QUEUE_MASK: u32 = 0x3f00;
pub(super) const SS2F_PATH_WLCPU: u32 = 0x0a;
pub(super) const B_AX_UC_MGNT_DEC: u32 = 0x10;
pub(super) const R_AX_SEC_DEBUG1: u32 = 0x9d1c;
pub(super) const B_AX_TX_TIMEOUT_SEL_MASK: u32 = 0xc000_0000;
pub(super) const AX_TX_TO_VAL: u32 = 0x2;
pub(super) const SIFS_MACTXEN_T1_V1: u32 = 0x41;
pub(super) const WMAC_SPEC_SIFS_OFDM_52C: u32 = 0x11;
pub(super) const R_AX_PTCL_RRSR1: u32 = 0xc090;
pub(super) const B_AX_RSC_MASK: u32 = 0xc0;
pub(super) const B_AX_RSP_STATIC_RTS_CHK_SERV_BW_EN: u32 = 1 << 30;
// rtw8852c_imr_info and the 8852C-only mpdu_trx clears.
pub(super) const B_AX_WDRLS_IMR_SET_V1: u32 = 0x3337;
pub(super) const R_AX_SEC_ERROR_FLAG_IMR: u32 = 0x9d2c;
pub(super) const B_AX_TX_HANG_IMR: u32 = 1 << 0;
pub(super) const B_AX_RX_HANG_IMR: u32 = 1 << 1;
pub(super) const B_AX_TX_ETH_TYPE_ERR_EN: u32 = 1 << 6;
pub(super) const B_AX_TX_LLC_PRE_ERR_EN: u32 = 1 << 7;
pub(super) const B_AX_TX_NW_TYPE_ERR_EN: u32 = 1 << 8;
pub(super) const B_AX_TX_KSRCH_ERR_EN: u32 = 1 << 9;
pub(super) const B_AX_MPDU_TX_IMR_SET_V1: u32 = 0x036e;
pub(super) const B_AX_MPDU_RX_IMR_SET_V1: u32 = 0x0008;
pub(super) const R_AX_TXPKTCTL_B0_ERRFLAG_IMR: u32 = 0x9f78;
pub(super) const B_AX_TXPKTCTL_IMR_B0_CLR_V1: u32 = 0x0035_0f0f;
pub(super) const B_AX_TXPKTCTL_IMR_B0_SET_V1: u32 = 0x0035_0b03;
pub(super) const R_AX_TXPKTCTL_B1_ERRFLAG_IMR: u32 = 0x9fb8;
pub(super) const B_AX_TXPKTCTL_IMR_B1_CLR_V1: u32 = 0x0035_0f0f;
pub(super) const B_AX_TXPKTCTL_IMR_B1_SET_V1: u32 = 0x0035_0f03;
pub(super) const B_AX_WDE_IMR_CLR_V1: u32 = 0x3f0f_f3ff;
pub(super) const B_AX_WDE_IMR_SET_V1: u32 = 0x3f0f_f3ff;
pub(super) const B_AX_PLE_IMR_CLR_V1: u32 = 0x3f0f_f3ff;
pub(super) const B_AX_PLE_IMR_SET_V1: u32 = 0x3f0f_f3ff;
pub(super) const B_AX_HOST_DISP_IMR_CLR_V1: u32 = 0xffd7_ffff;
pub(super) const B_AX_HOST_DISP_IMR_SET_V1: u32 = 0x0c10_0060;
pub(super) const B_AX_CPU_DISP_IMR_CLR_V1: u32 = 0x7f7b_fffd;
pub(super) const B_AX_CPU_DISP_IMR_SET_V1: u32 = 0x3600_0060;
pub(super) const B_AX_OTHER_DISP_IMR_CLR_V1: u32 = 0xffff_dfdf;
pub(super) const B_AX_OTHER_DISP_IMR_SET_V1: u32 = 0x303c_c000;
pub(super) const R_AX_BBRPT_COM_ERR_IMR: u32 = 0x9608;
pub(super) const R_AX_BBRPT_CHINFO_ERR_IMR: u32 = 0x9628;
pub(super) const R_AX_BBRPT_CHINFO_IMR_SET_V1: u32 = 0xff;
pub(super) const R_AX_BBRPT_DFS_ERR_IMR: u32 = 0x9638;
pub(super) const B_AX_PTCL_IMR_CLR_V1: u32 = 0x3;
pub(super) const B_AX_PTCL_IMR_SET_V1: u32 = 0x3;
pub(super) const R_AX_RX_ERR_FLAG_IMR: u32 = 0xc804;
pub(super) const B_AX_RX_ERR_IMR_CLR_V1: u32 = 0x7fff_ff06;
pub(super) const B_AX_RX_ERR_IMR_SET_V1: u32 = 0x7fff_ff06;
pub(super) const R_AX_TX_ERR_FLAG_IMR: u32 = 0xc870;
pub(super) const B_AX_TX_ERR_IMR_CLR_V1: u32 = 0xff00_c000;
pub(super) const B_AX_TX_ERR_IMR_SET_V1: u32 = 0xff00_c000;
pub(super) const R_AX_PHYINFO_ERR_IMR_V1: u32 = 0xccf8;
pub(super) const B_AX_PHYINFO_IMR_CLR_V1: u32 = 0x3f;
pub(super) const B_AX_PHYINFO_IMR_SET_V1: u32 = 0x3f;
pub(super) const R_AX_RX_ERR_IMR: u32 = 0xcef8;
pub(super) const B_AX_RMAC_IMR_CLR_V1: u32 = 0x03ff;
pub(super) const B_AX_RMAC_IMR_SET_V1: u32 = 0x03ff;
pub(super) const R_AX_TRXPTCL_ERROR_INDICA_MASK: u32 = 0xccbc;
pub(super) const B_AX_TMAC_IMR_CLR_V1: u32 = 0x01ff;
pub(super) const B_AX_TMAC_IMR_SET_V1: u32 = 0x017f;

/// rtw8852c.c `rtw8852c_dle_mem_pcie[RTW89_QTA_SCC]`: `wde_size19`
/// (64-byte pages, 3328 linked, 0 unlinked), `ple_size19` (128-byte pages,
/// 1904 linked, 16 unlinked), `wde_qt18` as both min and max, `ple_qt46` min
/// and `ple_qt47` max. `dle_scc_rsvd_size` is 0, so the used size must equal
/// the whole 458752-byte `fifo_size`.
pub(super) const WDE_LINKED: u32 = 3328;
pub(super) const PLE_LINKED: u32 = 1904;
pub(super) const PLE_UNLINKED: u32 = 16;
pub(super) const WDE_QT18: [(u32, u32); 4] = [
    (R_AX_WDE_QTA0_CFG, 3228),
    (R_AX_WDE_QTA1_CFG, 60),
    (R_AX_WDE_QTA3_CFG, 0),
    (R_AX_WDE_QTA4_CFG, 40),
];
pub(super) const PLE_QT46_QT47: [(u32, u32); 12] = [
    (525, 525),
    (0, 0),
    (16, 32),
    (20, 20),
    (13, 1034),
    (13, 13),
    (178, 1199),
    (0, 0),
    (32, 1053),
    (62, 62),
    (8, 160),
    (16, 1037),
];
/// `rtw8852c_hfc_chcfg_pcie` ACH0..B1HIQ: min 13, max 1614, group 0 for
/// ACH0..3/B0MGQ/B0HIQ and group 1 otherwise; `dma_ch_mask` is 0.
pub(super) const HFC_GROUP1: u32 = 0b1100_1111_0000;
pub(super) const HFC_MIN: u32 = 13;
pub(super) const HFC_MAX: u32 = 1614;
/// `rtw8852c_hfc_pubcfg_pcie`.
pub(super) const PUB_GROUP: u32 = 1614;
pub(super) const PUB_MAX: u32 = 3228;
/// `ple_qt46.cma0_dma` 178 capped at `PLD_RLS_MAX_PG` 127 pages of 128 bytes
/// (16256), capped at `RX_SPEC_MAX_LEN` 11454+512, in 512-byte units.
pub(super) const RX_MPDU_MAX_LEN: u32 = (11454 + 512) / 512;

impl<I: Io> Access<'_, I> {
    /// rtw8852c.c `rtw8852c_mac_enable_bb_rf`.
    pub(super) async fn enable_bb_rf_c(&mut self) -> Result<(), Error> {
        self.m8(
            R_AX_SYS_FUNC_EN,
            B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN,
            B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN,
        )?;
        self.m32(R_AX_WLRF_CTRL, B_AX_AFC_AFEDIG, B_AX_AFC_AFEDIG)?;
        self.m32(R_AX_WLRF_CTRL, B_AX_AFC_AFEDIG, 0)?;
        self.m32(R_AX_WLRF_CTRL, B_AX_AFC_AFEDIG, B_AX_AFC_AFEDIG)?;
        self.f32(R_AX_AFE_OFF_CTRL1, B_AX_S0_LDO_VSEL_F_MASK, 1)?;
        self.f32(R_AX_AFE_OFF_CTRL1, B_AX_S1_LDO_VSEL_F_MASK, 1)?;
        self.xtal(XTAL0, 0x7).await?;
        self.xtal(XTAL_SI_ANAPAR_WL, 0x6c).await?;
        self.xtal(XTAL_SI_WL_RFC_S0, 0xc7).await?;
        self.xtal(XTAL_SI_WL_RFC_S1, 0xc7).await?;
        self.xtal(XTAL3, 0xd).await
    }
    /// mac.c `sys_init_ax` for C: `dmac_func_en_ax` (with `B_AX_H_AXIDMA_EN`),
    /// `cmac_func_en_ax(MAC_0)` with CMAC TX parked as on B, and no
    /// `chip_func_en_ax` OCP write (8852A/885xB only).
    pub(super) fn system_c(&mut self) -> Result<(), Error> {
        self.0.write32(R_AX_DMAC_FUNC_EN, c_dmac_functions())?;
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
        self.m32(R_AX_CK_EN, clock, clock)?;
        let function = c_cmac_functions();
        self.m32(R_AX_CMAC_FUNC_EN, function, function & !B_AX_CMAC_TXEN)
    }
    /// mac.c `rtw89_mac_dle_init(RTW89_QTA_SCC)` with the C PCIe SCC quotas,
    /// `rtw89_mac_preload_init(MAC_0)` (`preload_init_set_ax`, PCIe POH) and
    /// `rtw89_mac_hfc_init(reset, en, h2c_en)` over the V1 page registers.
    async fn scc_c(&mut self) -> Result<(), Error> {
        if WDE_LINKED * 64 + (PLE_LINKED + PLE_UNLINKED) * 128 != 458_752 {
            return Err(Error::Unsupported);
        }
        let dle = B_AX_DLE_WDE_EN | B_AX_DLE_PLE_EN;
        self.m32(R_AX_DMAC_FUNC_EN, dle, 0)?;
        self.m32(
            R_AX_DMAC_CLK_EN,
            B_AX_DLE_WDE_CLK_EN | B_AX_DLE_PLE_CLK_EN,
            B_AX_DLE_WDE_CLK_EN | B_AX_DLE_PLE_CLK_EN,
        )?;
        self.m32(
            R_AX_WDE_PKTBUF_CFG,
            B_AX_WDE_PAGE_SEL_MASK | B_AX_WDE_START_BOUND_MASK | B_AX_WDE_FREE_PAGE_NUM_MASK,
            field(B_AX_WDE_FREE_PAGE_NUM_MASK, WDE_LINKED),
        )?;
        self.m32(
            R_AX_PLE_PKTBUF_CFG,
            B_AX_PLE_PAGE_SEL_MASK | B_AX_PLE_START_BOUND_MASK | B_AX_PLE_FREE_PAGE_NUM_MASK,
            field(B_AX_PLE_PAGE_SEL_MASK, 1)
                | field(B_AX_PLE_START_BOUND_MASK, WDE_LINKED * 64 / 8192)
                | field(B_AX_PLE_FREE_PAGE_NUM_MASK, PLE_LINKED),
        )?;
        for (a, pages) in WDE_QT18 {
            self.0.write32(
                a,
                field(B_AX_WDE_MIN_SIZE_MASK, pages) | field(B_AX_WDE_MAX_SIZE_MASK, pages),
            )?;
        }
        for (i, (minimum, maximum)) in PLE_QT46_QT47.into_iter().enumerate() {
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
        // preload_init_set_ax(MAC_0): 8852C over PCIe is not skipped.
        self.f32(
            R_AX_TXPKTCTL_B0_PRELD_CFG0,
            B_AX_B0_PRELD_USEMAXSZ_MASK,
            PRELD_B0_ENT_NUM * PRELD_AMSDU_SIZE,
        )?;
        self.m32(
            R_AX_TXPKTCTL_B0_PRELD_CFG0,
            B_AX_B0_PRELD_FEN,
            B_AX_B0_PRELD_FEN,
        )?;
        self.f32(
            R_AX_TXPKTCTL_B0_PRELD_CFG1,
            B_AX_B0_PRELD_NXT_TXENDWIN_MASK,
            PRELD_NEXT_WND,
        )?;
        self.f32(
            R_AX_TXPKTCTL_B0_PRELD_CFG1,
            B_AX_B0_PRELD_NXT_RSVMINSZ_MASK,
            PRELD_AMSDU_SIZE,
        )?;
        // hfc_func_en_ax(false, false), then every channel (mask 0).
        self.m32(R_AX_HCI_FC_CTRL_V1, B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN, 0)?;
        for channel in 0..12u32 {
            self.0.write32(
                R_AX_ACH0_PAGE_CTRL_V1 + channel * 4,
                field(B_AX_MIN_PG_MASK, HFC_MIN)
                    | field(B_AX_MAX_PG_MASK, HFC_MAX)
                    | if HFC_GROUP1 >> channel & 1 != 0 {
                        B_AX_GRP
                    } else {
                        0
                    },
            )?;
        }
        // hfc_pub_ctrl, then hfc_mix_cfg_ax with hfc_preccfg_pcie.
        self.0.write32(
            R_AX_PUB_PAGE_CTRL1_V1,
            field(B_AX_PUBPG_G0_MASK, PUB_GROUP) | field(B_AX_PUBPG_G1_MASK, PUB_GROUP),
        )?;
        self.0.write32(R_AX_WP_PAGE_CTRL2_V1, 0)?;
        self.0.write32(
            R_AX_CH_PAGE_CTRL_V1,
            field(B_AX_PREC_PAGE_CH011_MASK, 2) | field(B_AX_PREC_PAGE_CH12_MASK, 40),
        )?;
        self.0
            .write32(R_AX_PUB_PAGE_CTRL2_V1, field(B_AX_PUBPG_ALL_MASK, PUB_MAX))?;
        self.0.write32(R_AX_WP_PAGE_CTRL1_V1, 0)?;
        self.m32(
            R_AX_HCI_FC_CTRL_V1,
            B_AX_HCI_FC_MODE_MASK
                | B_AX_HCI_FC_WD_FULL_COND_MASK
                | B_AX_HCI_FC_CH12_FULL_COND_MASK
                | B_AX_HCI_FC_WP_CH07_FULL_COND_MASK
                | B_AX_HCI_FC_WP_CH811_FULL_COND_MASK,
            field(B_AX_HCI_FC_WD_FULL_COND_MASK, 1),
        )?;
        self.m32(
            R_AX_HCI_FC_CTRL_V1,
            B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN,
            B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN,
        )?;
        self.0.delay_us(10).await;
        // hfc_upd_ch_info per channel, then hfc_get_mix_info_ax.
        for channel in 0..12u32 {
            self.r32(R_AX_ACH0_PAGE_INFO_V1 + channel * 4)?;
        }
        let used = self.r32(R_AX_PUB_PAGE_INFO1_V1)?;
        self.r32(R_AX_PUB_PAGE_INFO3_V1)?;
        let available = self.r32(R_AX_PUB_PAGE_INFO2_V1)?;
        self.r32(R_AX_WP_PAGE_INFO1_V1)?;
        self.r32(R_AX_HCI_FC_CTRL_V1)?;
        self.r32(R_AX_CH_PAGE_CTRL_V1)?;
        let public = self.r32(R_AX_PUB_PAGE_CTRL2_V1)?;
        self.r32(R_AX_WP_PAGE_CTRL1_V1)?;
        self.r32(R_AX_WP_PAGE_CTRL2_V1)?;
        self.r32(R_AX_PUB_PAGE_CTRL1_V1)?;
        let get = |v: u32, m: u32| (v & m) >> m.trailing_zeros();
        // hfc_pub_info_chk is fatal for every chip except 8852A.
        if get(used, B_AX_G0_USE_PG_MASK)
            + get(used, B_AX_G1_USE_PG_MASK)
            + get(available, B_AX_PUB_AVAL_PG_MASK)
            != get(public, B_AX_PUBPG_ALL_MASK)
        {
            return Err(Error::Access);
        }
        if self.r32(R_AX_HCI_FC_CTRL_V1)? & (B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN)
            != B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN
            || get(self.r32(R_AX_WDE_PKTBUF_CFG)?, B_AX_WDE_FREE_PAGE_NUM_MASK) != WDE_LINKED
            || get(self.r32(R_AX_PLE_PKTBUF_CFG)?, B_AX_PLE_FREE_PAGE_NUM_MASK) != PLE_LINKED
        {
            return Err(Error::Access);
        }
        Ok(())
    }
    /// mac.c `dmac_init_ax` for C: DLE/preload/HFC above, `sta_sch_init_ax`
    /// with `_patch_ss2f_path`, `mpdu_proc_init_ax`, and `sec_eng_init_ax`
    /// with `B_AX_UC_MGNT_DEC`, the PCIe TX partial mode left as read, and
    /// `R_AX_SEC_DEBUG1` TX timeout select.
    pub(super) async fn dmac_c(&mut self) -> Result<(), Error> {
        self.scc_c().await?;
        self.m8(R_AX_SS_CTRL, B_AX_SS_EN, B_AX_SS_EN)?;
        self.poll(R_AX_SS_CTRL, B_AX_SS_INIT_DONE_1, B_AX_SS_INIT_DONE_1, 2000)
            .await?;
        self.m32(R_AX_SS_CTRL, B_AX_SS_WARM_INIT_FLG, B_AX_SS_WARM_INIT_FLG)?;
        self.m32(R_AX_SS_CTRL, B_AX_SS_NONEMPTY_SS2FINFO_EN, 0)?;
        self.f32(R_AX_SS2FINFO_PATH, B_AX_SS_DEST_QUEUE_MASK, SS2F_PATH_WLCPU)?;
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
            | B_AX_BC_DEC
            | B_AX_UC_MGNT_DEC;
        self.m32(R_AX_SEC_ENG_CTRL, security, security)?;
        self.m32(
            R_AX_SEC_MPDU_PROC,
            B_AX_APPEND_ICV | B_AX_APPEND_MIC,
            B_AX_APPEND_ICV | B_AX_APPEND_MIC,
        )?;
        self.f32(R_AX_SEC_DEBUG1, B_AX_TX_TIMEOUT_SEL_MASK, AX_TX_TO_VAL)
    }
    /// mac.c `cmac_init_ax(MAC_0)` for C.
    pub(super) async fn cmac_c(&mut self) -> Result<(), Error> {
        // scheduler_init_ax: V1 SIFS MACTXEN T1, no SCH_EXT_CTRL (885xB
        // only), pre-backoff 24us only while TX partial mode is clear.
        self.f32(
            R_AX_PREBKF_CFG_1,
            B_AX_SIFS_MACTXEN_T1_MASK,
            SIFS_MACTXEN_T1_V1,
        )?;
        self.m32(R_AX_CCA_CFG_0, B_AX_BTCCA_EN, 0)?;
        if self.r32(R_AX_SEC_ENG_CTRL)? & B_AX_TX_PARTIAL_MODE == 0 {
            self.f32(R_AX_PREBKF_CFG_0, B_AX_PREBKF_TIME_MASK, SCH_PREBKF_24US)?;
        }
        let cam = field(B_AX_ADDR_CAM_RANGE_MASK, 0x7f) | B_AX_ADDR_CAM_CLR | B_AX_ADDR_CAM_EN;
        self.m32(R_AX_ADDR_CAM_CTRL, cam, cam)?;
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
        // _patch_dis_resp_chk default branch: 8852C *sets* the checks.
        let nav = B_AX_RSP_CHK_TXNAV | B_AX_RSP_CHK_INTRA_NAV | B_AX_RSP_CHK_BASIC_NAV;
        self.m32(R_AX_RSP_CHK_SIG, nav, nav)?;
        let cca = B_AX_RSP_CHK_SEC_CCA_80
            | B_AX_RSP_CHK_SEC_CCA_40
            | B_AX_RSP_CHK_SEC_CCA_20
            | B_AX_RSP_CHK_BTCCA
            | B_AX_RSP_CHK_EDCCA
            | B_AX_RSP_CHK_CCA;
        self.m32(R_AX_TRXPTCL_RESP_0, cca, cca)?;
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
        // trxptcl_init_ax: SIFS OFDM 52C, rtw8852c_rrsr_cfgs.
        self.m32(
            R_AX_TRXPTCL_RESP_0,
            B_AX_WMAC_SPEC_SIFS_CCK_MASK | B_AX_WMAC_SPEC_SIFS_OFDM_MASK,
            field(B_AX_WMAC_SPEC_SIFS_CCK_MASK, WMAC_SPEC_SIFS_CCK)
                | field(B_AX_WMAC_SPEC_SIFS_OFDM_MASK, WMAC_SPEC_SIFS_OFDM_52C),
        )?;
        self.m32(
            R_AX_RXTRIG_TEST_USER_2,
            B_AX_RXTRIG_FCSCHK_EN,
            B_AX_RXTRIG_FCSCHK_EN,
        )?;
        self.f32(R_AX_TRXPTCL_RRSR_CTL_0, B_AX_WMAC_RESP_REF_RATE_SEL, 0)?;
        self.f32(R_AX_PTCL_RRSR1, B_AX_RSC_MASK, 2)?;
        // rmac_init_ax; a retained owner cannot publish Ready over an
        // unconfirmed BA-CAM reset (Linux only warns), as on B.
        self.f32(
            R_AX_RESPBA_CAM_CTRL,
            B_AX_BACAM_RST_MASK,
            S_AX_BACAM_RST_ALL,
        )?;
        self.poll(R_AX_RESPBA_CAM_CTRL, B_AX_BACAM_RST_MASK, 0, 1000)
            .await?;
        self.m8(R_AX_RESPBA_CAM_CTRL, B_AX_SSN_SEL, B_AX_SSN_SEL)?;
        self.m16(
            R_AX_DLK_PROTECT_CTL,
            B_AX_RX_DLK_DATA_TIME_MASK | B_AX_RX_DLK_CCA_TIME_MASK,
            field(B_AX_RX_DLK_DATA_TIME_MASK, 15) | field(B_AX_RX_DLK_CCA_TIME_MASK, 32),
        )?;
        self.m8(R_AX_RCR, B_AX_CH_EN_MASK, field(B_AX_CH_EN_MASK, 1))?;
        self.f32(R_AX_RX_FLTR_OPT, B_AX_RX_MPDU_MAX_LEN_MASK, RX_MPDU_MAX_LEN)?;
        self.m8(R_AX_PLCP_HDR_FLTR, B_AX_VHT_SU_SIGB_CRC_CHK, 0)?;
        // cmac_com_init_ax: no RRSR1 rate enable on C.
        self.m32(
            R_AX_TX_SUB_CARRIER_VALUE,
            B_AX_TXSC_20M_MASK | B_AX_TXSC_40M_MASK | B_AX_TXSC_80M_MASK,
            0,
        )?;
        // ptcl_init_ax (PCIe, MAC_0): no VHT A-MPDU length on C, and
        // cmac_dma_init_ax is 885xB-only.
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
        )
    }
    /// mac.c `enable_imr_ax` DMAC then CMAC0 with `rtw8852c_imr_info`, then
    /// `err_imr_ctrl_ax(true)` (no CMAC1: `ple_qt46.cma1_dma` is 0).
    pub(super) fn interrupts_c(&mut self) -> Result<(), Error> {
        // (register, clear, set, has_clear): `rtw89_write32_clr` then `_set`.
        for (reg, clear, set, cleared) in [
            (
                R_AX_WDRLS_ERR_IMR,
                B_AX_WDRLS_IMR_EN_CLR,
                B_AX_WDRLS_IMR_SET_V1,
                true,
            ),
            (
                R_AX_SEC_ERROR_FLAG_IMR,
                0,
                B_AX_TX_HANG_IMR | B_AX_RX_HANG_IMR,
                false,
            ),
            (
                R_AX_MPDU_TX_ERR_IMR,
                B_AX_TX_GET_ERRPKTID_INT_EN
                    | B_AX_TX_NXT_ERRPKTID_INT_EN
                    | B_AX_TX_MPDU_SIZE_ZERO_INT_EN
                    | B_AX_TX_OFFSET_ERR_INT_EN
                    | B_AX_TX_HDR3_SIZE_ERR_INT_EN,
                0,
                true,
            ),
            (
                R_AX_MPDU_TX_ERR_IMR,
                B_AX_TX_ETH_TYPE_ERR_EN
                    | B_AX_TX_LLC_PRE_ERR_EN
                    | B_AX_TX_NW_TYPE_ERR_EN
                    | B_AX_TX_KSRCH_ERR_EN,
                B_AX_MPDU_TX_IMR_SET_V1,
                true,
            ),
            (
                R_AX_MPDU_RX_ERR_IMR,
                B_AX_GETPKTID_ERR_INT_EN | B_AX_MHDRLEN_ERR_INT_EN | B_AX_RPT_ERR_INT_EN,
                B_AX_MPDU_RX_IMR_SET_V1,
                true,
            ),
            (
                R_AX_STA_SCHEDULER_ERR_IMR,
                B_AX_SEARCH_HANG_TIMEOUT_INT_EN
                    | B_AX_RPT_HANG_TIMEOUT_INT_EN
                    | B_AX_PLE_B_PKTID_ERR_INT_EN,
                B_AX_STA_SCHEDULER_IMR_SET,
                true,
            ),
            (
                R_AX_TXPKTCTL_B0_ERRFLAG_IMR,
                B_AX_TXPKTCTL_IMR_B0_CLR_V1,
                B_AX_TXPKTCTL_IMR_B0_SET_V1,
                true,
            ),
            (
                R_AX_TXPKTCTL_B1_ERRFLAG_IMR,
                B_AX_TXPKTCTL_IMR_B1_CLR_V1,
                B_AX_TXPKTCTL_IMR_B1_SET_V1,
                true,
            ),
            (
                R_AX_WDE_ERR_IMR,
                B_AX_WDE_IMR_CLR_V1,
                B_AX_WDE_IMR_SET_V1,
                true,
            ),
            (
                R_AX_PLE_ERR_IMR,
                B_AX_PLE_IMR_CLR_V1,
                B_AX_PLE_IMR_SET_V1,
                true,
            ),
            (R_AX_PKTIN_ERR_IMR, 0, B_AX_PKTIN_GETPKTID_ERR_INT_EN, false),
            (
                R_AX_HOST_DISPATCHER_ERR_IMR,
                B_AX_HOST_DISP_IMR_CLR_V1,
                B_AX_HOST_DISP_IMR_SET_V1,
                true,
            ),
            (
                R_AX_CPU_DISPATCHER_ERR_IMR,
                B_AX_CPU_DISP_IMR_CLR_V1,
                B_AX_CPU_DISP_IMR_SET_V1,
                true,
            ),
            (
                R_AX_OTHER_DISPATCHER_ERR_IMR,
                B_AX_OTHER_DISP_IMR_CLR_V1,
                B_AX_OTHER_DISP_IMR_SET_V1,
                true,
            ),
            (
                R_AX_CPUIO_ERR_IMR,
                B_AX_CPUIO_IMR_CLR,
                B_AX_CPUIO_IMR_SET,
                true,
            ),
            (
                R_AX_BBRPT_COM_ERR_IMR,
                0,
                B_AX_BBRPT_COM_NULL_PLPKTID_ERR_INT_EN,
                false,
            ),
            (
                R_AX_BBRPT_CHINFO_ERR_IMR,
                B_AX_BBRPT_CHINFO_IMR_CLR,
                R_AX_BBRPT_CHINFO_IMR_SET_V1,
                true,
            ),
            (
                R_AX_BBRPT_DFS_ERR_IMR,
                0,
                B_AX_BBRPT_DFS_TO_ERR_INT_EN,
                false,
            ),
            (R_AX_LA_ERRFLAG, 0, B_AX_LA_IMR_DATA_LOSS_ERR, false),
            (
                R_AX_SCHEDULE_ERR_IMR,
                B_AX_SORT_NON_IDLE_ERR_INT_EN | B_AX_FSM_TIMEOUT_ERR_INT_EN,
                B_AX_FSM_TIMEOUT_ERR_INT_EN,
                true,
            ),
            (
                R_AX_PTCL_IMR0,
                B_AX_PTCL_IMR_CLR_V1,
                B_AX_PTCL_IMR_SET_V1,
                true,
            ),
            (
                R_AX_RX_ERR_FLAG_IMR,
                B_AX_RX_ERR_IMR_CLR_V1,
                B_AX_RX_ERR_IMR_SET_V1,
                true,
            ),
            (
                R_AX_TX_ERR_FLAG_IMR,
                B_AX_TX_ERR_IMR_CLR_V1,
                B_AX_TX_ERR_IMR_SET_V1,
                true,
            ),
            (
                R_AX_PHYINFO_ERR_IMR_V1,
                B_AX_PHYINFO_IMR_CLR_V1,
                B_AX_PHYINFO_IMR_SET_V1,
                true,
            ),
            (
                R_AX_RX_ERR_IMR,
                B_AX_RMAC_IMR_CLR_V1,
                B_AX_RMAC_IMR_SET_V1,
                true,
            ),
            (
                R_AX_TRXPTCL_ERROR_INDICA_MASK,
                B_AX_TMAC_IMR_CLR_V1,
                B_AX_TMAC_IMR_SET_V1,
                true,
            ),
        ] {
            if cleared {
                self.m32(reg, clear, 0)?;
            }
            // The 8852C mpdu_trx sequence issues its second TX clear before
            // the single TX set; a zero set never follows the first clear.
            if !(reg == R_AX_MPDU_TX_ERR_IMR && set == 0) {
                self.m32(reg, set, set)?;
            }
        }
        self.0.write32(R_AX_DMAC_ERR_IMR, DMAC_ERR_IMR_EN)?;
        self.0.write32(R_AX_CMAC_ERR_IMR, CMAC0_ERR_IMR_EN)
    }
    /// mac.c `trx_init_ax` tail for 8852C, after `set_host_rpr_ax`.
    pub(super) fn trx_tail_c(&mut self) -> Result<(), Error> {
        self.m32(R_AX_RSP_CHK_SIG, B_AX_RSP_STATIC_RTS_CHK_SERV_BW_EN, 0)
    }
}

/// `dmac_func_en_ax` for 8852C (includes `B_AX_H_AXIDMA_EN`).
pub(super) fn c_dmac_functions() -> u32 {
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
        | B_AX_DMAC_CRPRT
        | B_AX_H_AXIDMA_EN
}

/// `cmac_func_en_ax` function bits (TX is masked by the caller).
pub(super) fn c_cmac_functions() -> u32 {
    B_AX_CMAC_EN
        | B_AX_CMAC_TXEN
        | B_AX_CMAC_RXEN
        | B_AX_PHYINTF_EN
        | B_AX_CMAC_DMA_EN
        | B_AX_PTCLTOP_EN
        | B_AX_SCHEDULER_EN
        | B_AX_TMAC_EN
        | B_AX_RMAC_EN
        | B_AX_CMAC_CRPRT
}
