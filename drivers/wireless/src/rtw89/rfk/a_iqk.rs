// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A channel IQK: rtw8852a_rfk.c `rtw8852a_iqk` for the non-DBCC
//! PHY_0 (`_kpath` = RF_AB), wideband (`_iqk_init`: `is_nbiqk = false`,
//! debug flags false), both paths, on one typed [`Profile`].
//!
//! Linux only logs a 0xbff8 timeout in `_iqk_check_cal` (it always
//! returns false); NARF fails the attempt closed instead, like the C
//! port. The BTC ONESHOT notifications inside `_doiqk`/`_iqk_one_shot`
//! return without I/O (coex.c `rtw89_btc_ntfy_wl_rfk`); only the outer
//! START/STOP are emitted, as `Kind::Iqk` / `Kind::IqkPath` brackets.
//! The MCC table index is always 0: the first retuned entity takes the
//! first idle `rtw89_rfk_chan_lookup` slot, and NARF carries no MCC
//! table (same simplification as the C port).
//!
//! DBCC tables (`IQK_SET/RESTORE_DBCC_PATH0/PATH1`) are landed as defs
//! but unused by this flow: DBCC calibration (`_iqk_dbcc`) is a
//! separate follow-on.
use super::super::operating_channel_c::{Band, Profile, Width};
use super::{power, Access, Entry, Error, Interface, Kind};

const B_ADC_FIFO_RXK: u32 = 0xffff0000; // Linux reg.h: GENMASK(31, 16)
const B_ANAPAR_15: u32 = 0xffff0000; // Linux reg.h: GENMASK(31, 16)
const B_ANAPAR_FLTRST: u32 = 0x400000; // Linux reg.h: BIT(22)
const B_ANAPAR_PW15: u32 = 0xff000000; // Linux reg.h: GENMASK(31, 24)
const B_ANAPAR_PW15_H2: u32 = 0xc000000; // Linux reg.h: GENMASK(27, 26)
const B_CFIR_LUT_G2: u32 = 0x4; // Linux reg.h: BIT(2)
const B_CFIR_LUT_G3: u32 = 0x8; // Linux reg.h: BIT(3)
const B_CFIR_LUT_GP: u32 = 0x3; // Linux reg.h: GENMASK(1, 0)
const B_CFIR_LUT_SEL: u32 = 0x100; // Linux reg.h: BIT(8)
const B_COEF_SEL_IQC: u32 = 0x1; // Linux reg.h: BIT(0)
const B_DPK_CTL_EN: u32 = 0x10000000; // Linux reg.h: BIT(28)
const B_GAPK_ADR: u32 = 0x1; // Linux reg.h: BIT(0)
const B_IOQ_IQK_DPK_EN: u32 = 0x2; // Linux reg.h: BIT(1)
const B_IQKINF2_KCNT: u32 = 0xff00; // Linux reg.h: GENMASK(15, 8)
const B_IQKINF_VER: u32 = 0xff000000; // Linux reg.h: GENMASK(31, 24)
const B_IQK_CFG_SET: u32 = 0x30; // Linux reg.h: GENMASK(5, 4)
const B_IQK_DIF1_TXPI: u32 = 0xfffff; // Linux reg.h: GENMASK(19, 0)
const B_IQK_DIF2_RXPI: u32 = 0xfffff; // Linux reg.h: GENMASK(19, 0)
const B_IQK_DIF4_RXT: u32 = 0xfff0000; // Linux reg.h: GENMASK(27, 16)
const B_IQK_DIF4_TXT: u32 = 0xfff; // Linux reg.h: GENMASK(11, 0)
const B_IQK_RES_RXCFIR: u32 = 0xf; // Linux reg.h: GENMASK(3, 0)
const B_IQK_RES_TXCFIR: u32 = 0xf00; // Linux reg.h: GENMASK(11, 8)
const B_KIP_IQP_IQSW: u32 = 0x3f; // Linux reg.h: GENMASK(5, 0)
const B_KIP_RFGAIN: u32 = 0x100; // Linux reg.h: BIT(8)
const B_NCTL_N1_CIP: u32 = 0xff; // Linux reg.h: GENMASK(7, 0)
const B_P0_NRBW_DBG: u32 = 0x40000000; // Linux reg.h: BIT(30)
const B_P0_RXCK_ON: u32 = 0x80000; // Linux reg.h: BIT(19)
const B_P0_RXCK_VAL: u32 = 0x70000; // Linux reg.h: GENMASK(18, 16)
const B_RFGAIN_BND: u32 = 0x1f; // Linux reg.h: GENMASK(4, 0)
const B_UPD_CLK_ADC_ON: u32 = 0x1000000; // Linux reg.h: BIT(24)
const B_UPD_CLK_ADC_VAL: u32 = 0x6000000; // Linux reg.h: GENMASK(26, 25)
const RR_BIAS: u32 = 0x5e; // Linux reg.h: 0x5e
const RR_BIASA: u32 = 0x60; // Linux reg.h: 0x60
const RR_BIASA_A: u32 = 0x7; // Linux reg.h: GENMASK(2, 0)
const RR_BIAS_GAPK: u32 = 0x80000; // Linux reg.h: BIT(19)
const RR_CFGCH: u32 = 0x18; // Linux reg.h: 0x18
const RR_DTXLOK: u32 = 0x8; // Linux reg.h: 0x08
const RR_GAINTX: u32 = 0x56; // Linux reg.h: 0x56
const RR_GAINTX_ALL: u32 = 0xffff; // Linux reg.h: GENMASK(15, 0)
const RR_LUTDBG: u32 = 0xdf; // Linux reg.h: 0xdf
const RR_LUTDBG_LOK: u32 = 0x4; // Linux reg.h: BIT(2)
const RR_LUTWA: u32 = 0x33; // Linux reg.h: 0x33
const RR_LUTWA_MASK: u32 = 0x3ff; // Linux reg.h: GENMASK(9, 0)
const RR_LUTWD0: u32 = 0x3f; // Linux reg.h: 0x3f
const RR_LUTWE: u32 = 0xef; // Linux reg.h: 0xef
const RR_LUTWE_LOK: u32 = 0x4; // Linux reg.h: BIT(2)
const RR_MOD: u32 = 0x0; // Linux reg.h: 0x00
const RR_MOD_MASK: u32 = 0xf0000; // Linux reg.h: GENMASK(19, 16)
const RR_MOD_M_RXG: u32 = 0x3ff0; // Linux reg.h: GENMASK(13, 4)
const RR_MOD_V_RX: u32 = 0x3; // Linux reg.h: 0x3
const RR_MOD_V_RXK2: u32 = 0x7; // Linux reg.h: 0x7
const RR_RCKD: u32 = 0xde; // Linux reg.h: 0xde
const RR_RCKD_POW: u32 = 0xfe000; // Linux reg.h: GENMASK(19, 13)
const RR_RSV1: u32 = 0x5; // Linux reg.h: 0x05
const RR_RSV1_RST: u32 = 0x1; // Linux reg.h: BIT(0)
const RR_RSV2: u32 = 0x9; // Linux reg.h: 0x09
const RR_RSV4: u32 = 0x1f; // Linux reg.h: 0x1f
const RR_RXA2: u32 = 0x8c; // Linux reg.h: 0x8c
const RR_RXA2_C1: u32 = 0x1c00; // Linux reg.h: GENMASK(12, 10)
const RR_RXA2_C2: u32 = 0x3f8; // Linux reg.h: GENMASK(9, 3)
const RR_RXBB: u32 = 0x83; // Linux reg.h: 0x83
const RR_RXBB_C1G: u32 = 0x300; // Linux reg.h: GENMASK(9, 8)
const RR_RXBB_C2G: u32 = 0x1fc00; // Linux reg.h: GENMASK(16, 10)
const RR_RXK: u32 = 0x20; // Linux reg.h: 0x20
const RR_RXKPLL: u32 = 0x1e; // Linux reg.h: 0x1e
const RR_RXKPLL_OFF: u32 = 0x3f; // Linux reg.h: GENMASK(5, 0)
const RR_RXKPLL_POW: u32 = 0x80000; // Linux reg.h: BIT(19)
const RR_RXK_SEL2G: u32 = 0x100; // Linux reg.h: BIT(8)
const RR_RXK_SEL5G: u32 = 0x80; // Linux reg.h: BIT(7)
const RR_TXG1: u32 = 0x51; // Linux reg.h: 0x51
const RR_TXG1_ATT1: u32 = 0x800; // Linux reg.h: BIT(11)
const RR_TXG1_ATT2: u32 = 0x80000; // Linux reg.h: BIT(19)
const RR_TXG2: u32 = 0x52; // Linux reg.h: 0x52
const RR_TXG2_ATT0: u32 = 0x800; // Linux reg.h: BIT(11)
const RR_TXGA: u32 = 0x55; // Linux reg.h: 0x55
const RR_TXGA_LOK_EN: u32 = 0x1; // Linux reg.h: BIT(0)
const RR_TXMO: u32 = 0x58; // Linux reg.h: 0x58
const RR_TXMO_COI: u32 = 0xf8000; // Linux reg.h: GENMASK(19, 15)
const RR_TXMO_COQ: u32 = 0x7c00; // Linux reg.h: GENMASK(14, 10)
const RR_TXRSV: u32 = 0x5c; // Linux reg.h: 0x5c
const RR_TXRSV_GAPK: u32 = 0x80000; // Linux reg.h: BIT(19)
const RR_WLSEL: u32 = 0x2; // Linux reg.h: 0x02
const RR_WLSEL_AG: u32 = 0x70000; // Linux reg.h: GENMASK(18, 16)
const RR_XALNA2: u32 = 0x90; // Linux reg.h: 0x90
const RR_XALNA2_SW: u32 = 0x3; // Linux reg.h: GENMASK(1, 0)
const RR_XGLNA2: u32 = 0x85; // Linux reg.h: 0x85
const RR_XGLNA2_SW: u32 = 0x3; // Linux reg.h: GENMASK(1, 0)
const R_ADC_FIFO: u32 = 0x20fc; // Linux reg.h: 0x20fc
const R_ANAPAR: u32 = 0x32c; // Linux reg.h: 0x032C
const R_ANAPAR_PW15: u32 = 0x30c; // Linux reg.h: 0x030C
const R_CFIR_LUT: u32 = 0x8154; // Linux reg.h: 0x8154
const R_CFIR_MAP: u32 = 0x8150; // Linux reg.h: 0x8150
const R_CFIR_SYS: u32 = 0x8120; // Linux reg.h: 0x8120
const R_COEF_SEL: u32 = 0x8104; // Linux reg.h: 0x8104
const R_DPK_CTL: u32 = 0x80b0; // Linux reg.h: 0x80B0
const R_GAPK: u32 = 0x80e0; // Linux reg.h: 0x80E0
const R_IOQ_IQK_DPK: u32 = 0xc60; // Linux reg.h: 0x0C60
const R_IQKCH: u32 = 0x9fe4; // Linux reg.h: 0x9FE4
const R_IQKINF: u32 = 0x9fe0; // Linux reg.h: 0x9FE0
const R_IQKINF2: u32 = 0x9fe8; // Linux reg.h: 0x9FE8
const R_IQK_CFG: u32 = 0x8034; // Linux reg.h: 0x8034
const R_IQK_COM: u32 = 0x8018; // Linux reg.h: 0x8018
const R_IQK_DIF1: u32 = 0x8020; // Linux reg.h: 0x8020
const R_IQK_DIF2: u32 = 0x8024; // Linux reg.h: 0x8024
const R_IQK_DIF4: u32 = 0x802c; // Linux reg.h: 0x802C
const R_IQK_RES: u32 = 0x8124; // Linux reg.h: 0x8124
const R_KIP: u32 = 0x8140; // Linux reg.h: 0x8140
const R_KIP_IQP: u32 = 0x81cc; // Linux reg.h: 0x81CC
const R_KIP_SYSCFG: u32 = 0x8088; // Linux reg.h: 0x8088
const R_KPATH_CFG: u32 = 0x80d0; // Linux reg.h: 0x80D0
const R_LOAD_COEF: u32 = 0x81dc; // Linux reg.h: 0x81DC
const R_MDPK_RX_DCK: u32 = 0x8074; // Linux reg.h: 0x8074
const R_NCTL_CFG: u32 = 0x8000; // Linux reg.h: 0x8000
const R_NCTL_N1: u32 = 0x8010; // Linux reg.h: 0x8010
const R_NCTL_RPT: u32 = 0x8008; // Linux reg.h: 0x8008
const R_NCTL_RW: u32 = 0x8080; // Linux reg.h: 0x8080
const R_P0_NRBW: u32 = 0x12b8; // Linux reg.h: 0x12B8
const R_P0_RXCK: u32 = 0x12a0; // Linux reg.h: 0x12A0
const R_RFGAIN_BND: u32 = 0x8148; // Linux reg.h: 0x8148
const R_RXIQC: u32 = 0x813c; // Linux reg.h: 0x813c
const R_TXIQC: u32 = 0x8138; // Linux reg.h: 0x8138
const R_UPD_CLK_ADC: u32 = 0x700; // Linux reg.h: 0x0700

/// `RTW8852A_IQK_VER` (rtw8852a_rfk.c:535).
const IQK_VER: u32 = 0x2a;
/// `RTW8852A_NCTL_VER` (rtw8852a_rfk.c:536).
const NCTL_VER: u32 = 0xd;
/// Full-RF-register mask (Linux `RFREG_MASK`).
const RFREG_MASK: u32 = 0xfffff;
/// `addr_rfc_ctl` in `_iqk_one_shot`: path A/B RFCTM address (a literal
/// in Linux, not a named register).
const RFC_CTL: [u32; 2] = [0x5864, 0x7864];
/// Bit set/cleared at `addr_rfc_ctl` around every one-shot.
const RFC_BIT: u32 = 0x20000000;

/// One-shot kinds driven by this flow (`enum rtw8852a_iqk_type`).
/// `ID_TXAGC`/`ID_RXAGC` are never driven by the channel flow, so they
/// have no variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shot {
    FlokCoarse,
    FlokFine,
    Txk,
    Rxk,
    NbTxk,
    NbRxk,
}

/// Per-path IQK results (`struct rtw89_iqk_info`, one table index).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Path {
    pub lok_cor_fail: bool,
    pub lok_fin_fail: bool,
    /// `_lok_finetune_check` result; `run` refuses a LOK failure.
    pub lok_fail: bool,
    pub tx_fail: bool,
    pub rx_fail: bool,
    pub nb_txcfir: u32,
    pub nb_rxcfir: u32,
    pub is_wb_txiqk: bool,
    pub is_wb_rxiqk: bool,
    /// `bp_iqkenable[path]` (`R_IQK_RES`).
    pub iqk_enable: u32,
    /// `bp_txkresult[path]` (`R_TXIQC`).
    pub tx_result: u32,
    /// `bp_rxkresult[path]` (`R_RXIQC`).
    pub rx_result: u32,
}

/// Channel IQK owner (`struct rtw89_iqk_info`, non-DBCC slice).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Iqk {
    /// `iqk_times`: incremented once per `_doiqk` (twice per run).
    pub times: u8,
    /// `iqk_fail_cnt`.
    pub fail_count: u32,
    pub paths: [Path; 2],
    pub channel: Option<Profile>,
    calibrated: bool,
}

impl<I: Interface> Access<'_, I> {
    /// `_iqk_check_cal`: poll 0xbff8 byte0 == 0x55 (1us step, 8200us),
    /// clear `R_NCTL_N1` byte0, sample `R_NCTL_RPT`. Linux always
    /// returns "pass"; a timeout fails the attempt closed here.
    async fn a_iqk_check_cal(&mut self) -> Result<(), Error> {
        let start = self.0.now_us();
        while self.bb(0xbff8, 0xff)? != 0x55 {
            if self.0.now_us().saturating_sub(start) >= 8200 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(1).await?;
        }
        self.wm(R_NCTL_N1, 0xff, 0)?;
        let _ = self.bb(R_NCTL_RPT, u32::MAX)?;
        Ok(())
    }

    /// `_iqk_one_shot`: per-shot `R_IQK_DIF4` program + `addr_rfc_ctl`
    /// bit, `R_NCTL_CFG` full word (`iqk_cmd + 1`), `R_DPK_CTL_EN`,
    /// 1us, `_iqk_check_cal`, clear the rfc bit. The debug reads
    /// (`_iqk_read_xym/fft/sram/cfir`) are gated on `iqk_*_en`, false
    /// after `_iqk_init`, and are omitted. The BTC ONESHOT
    /// notifications return without I/O.
    async fn a_iqk_one_shot(&mut self, path: u8, shot: Shot, bw: u32) -> Result<(), Error> {
        let rfc = RFC_CTL[usize::from(path)];
        let p = 1u32 << (4 + path);
        match shot {
            Shot::FlokCoarse => {
                self.wm(rfc, RFC_BIT, 1)?;
                self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x009)?;
                self.a_iqk_fire(0x108 | p).await?;
            }
            Shot::FlokFine => {
                self.wm(rfc, RFC_BIT, 1)?;
                self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x009)?;
                self.a_iqk_fire(0x208 | p).await?;
            }
            Shot::Txk => {
                self.wm(rfc, RFC_BIT, 0)?;
                self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x025)?;
                self.a_iqk_fire(0x008 | p | (((0x8 + bw) & 0xf) << 8))
                    .await?;
            }
            Shot::Rxk => {
                self.wm(rfc, RFC_BIT, 1)?;
                self.wm(R_IQK_DIF4, B_IQK_DIF4_RXT, 0x011)?;
                self.a_iqk_fire(0x008 | p | (((0xb + bw) & 0xf) << 8))
                    .await?;
            }
            Shot::NbTxk => {
                self.wm(rfc, RFC_BIT, 0)?;
                self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x025)?;
                self.a_iqk_fire(0x308 | p).await?;
            }
            Shot::NbRxk => {
                self.wm(rfc, RFC_BIT, 1)?;
                self.wm(R_IQK_DIF4, B_IQK_DIF4_RXT, 0x011)?;
                self.a_iqk_fire(0x608 | p).await?;
            }
        }
        self.wm(rfc, RFC_BIT, 0)
    }

    /// Shared tail of `_iqk_one_shot`: command word, enable, 1us,
    /// check, in the order Linux issues them.
    async fn a_iqk_fire(&mut self, command: u32) -> Result<(), Error> {
        self.wm(R_NCTL_CFG, u32::MAX, command + 1)?;
        self.wm(R_DPK_CTL, B_DPK_CTL_EN, 1)?;
        self.delay(1).await?;
        self.a_iqk_check_cal().await
    }

    /// `_iqk_rxk_setting`.
    async fn a_iqk_rxk_setting(&mut self, path: u8, band: Band) -> Result<(), Error> {
        self.wm(R_P0_NRBW + (u32::from(path) << 13), B_P0_NRBW_DBG, 1)?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x3)?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0xa041)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15_H2, 0x3)?;
        self.wm(R_ANAPAR, B_ANAPAR_FLTRST, 0)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR, B_ANAPAR_FLTRST, 1)?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15_H2, 0)?;
        self.delay(1).await?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, 0x0303)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, 0x0000)?;
        match band {
            Band::Ghz2 => {
                self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RXK2).await?;
                self.wr(path, RR_RXK, RR_RXK_SEL2G, 0x1).await?;
            }
            Band::Ghz5 => {
                self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RXK2).await?;
                self.wr(path, RR_WLSEL, RR_WLSEL_AG, 0x5).await?;
                self.wr(path, RR_RXK, RR_RXK_SEL5G, 0x1).await?;
            }
            Band::Ghz6 => return Err(Error::Policy),
        }
        let tmp = self.rr(path, RR_CFGCH, RFREG_MASK).await?;
        self.wr(path, RR_RSV4, RFREG_MASK, tmp).await?;
        self.wr(path, RR_RXKPLL, RR_RXKPLL_OFF, 0x13).await?;
        self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x0).await?;
        self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x1).await?;
        self.delay(128).await
    }

    /// `_rxk_group_sel`: four wideband groups; `syn1to2` from
    /// `_iqk_get_ch_info`.
    async fn a_rxk_group_sel(
        &mut self,
        path: u8,
        band: Band,
        bw: u32,
        syn1to2: u32,
        state: &mut Path,
    ) -> Result<(), Error> {
        const RXGN_A: [u32; 4] = [0x18c, 0x1a0, 0x28c, 0x2a0];
        const ATTC2_A: [u32; 4] = [0x0, 0x0, 0x07, 0x30];
        const ATTC1_A: [u32; 4] = [0x7, 0x5, 0x1, 0x1];
        const RXGN_G: [u32; 4] = [0x1cc, 0x1e0, 0x2cc, 0x2e0];
        const ATTC2_G: [u32; 4] = [0x0, 0x15, 0x3, 0x1a];
        const ATTC1_G: [u32; 4] = [0x1, 0x0, 0x1, 0x0];
        for gp in 0..4u8 {
            let g = usize::from(gp);
            match band {
                Band::Ghz2 => {
                    self.wr(path, RR_MOD, RR_MOD_M_RXG, RXGN_G[g]).await?;
                    self.wr(path, RR_RXBB, RR_RXBB_C2G, ATTC2_G[g]).await?;
                    self.wr(path, RR_RXBB, RR_RXBB_C1G, ATTC1_G[g]).await?;
                }
                Band::Ghz5 => {
                    self.wr(path, RR_MOD, RR_MOD_M_RXG, RXGN_A[g]).await?;
                    self.wr(path, RR_RXA2, RR_RXA2_C2, ATTC2_A[g]).await?;
                    self.wr(path, RR_RXA2, RR_RXA2_C1, ATTC1_A[g]).await?;
                }
                Band::Ghz6 => return Err(Error::Policy),
            }
            self.wm(R_IQK_CFG, B_IQK_CFG_SET, 1)?;
            let rf0 = self.rr(path, RR_MOD, RFREG_MASK).await?;
            self.wm(R_IQK_DIF2, B_IQK_DIF2_RXPI, rf0 | syn1to2)?;
            self.wm(R_IQK_COM, u32::MAX, 0x40010100)?;
            self.wm(R_IQK_RES + (u32::from(path) << 8), B_IQK_RES_RXCFIR, 0)?;
            self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_SEL, 1)?;
            self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_G3, 0)?;
            self.wm(
                R_CFIR_LUT + (u32::from(path) << 8),
                B_CFIR_LUT_GP,
                u32::from(gp),
            )?;
            self.wm(R_IOQ_IQK_DPK, B_IOQ_IQK_DPK_EN, 0x1)?;
            self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
            self.a_iqk_one_shot(path, Shot::Rxk, bw).await?;
            self.wm(
                R_IQKINF,
                1u32 << (16 + u32::from(gp) + u32::from(path) * 4),
                0,
            )?;
        }
        match band {
            Band::Ghz2 => {
                self.wr(path, RR_RXK, RR_RXK_SEL2G, 0x0).await?;
                self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x0).await?;
            }
            Band::Ghz5 => {
                self.wr(path, RR_RXK, RR_RXK_SEL5G, 0x0).await?;
                self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x0).await?;
                self.wr(path, RR_WLSEL, RR_WLSEL_AG, 0x0).await?;
            }
            Band::Ghz6 => return Err(Error::Policy),
        }
        state.nb_rxcfir = 0x40000000;
        self.wm(R_IQK_RES + (u32::from(path) << 8), B_IQK_RES_RXCFIR, 0x5)?;
        state.is_wb_rxiqk = true;
        state.rx_fail = false;
        Ok(())
    }

    /// `_iqk_nbrxk`: the single narrowband group (group 0).
    async fn a_iqk_nbrxk(
        &mut self,
        path: u8,
        band: Band,
        bw: u32,
        syn1to2: u32,
        state: &mut Path,
    ) -> Result<(), Error> {
        match band {
            Band::Ghz2 => {
                self.wr(path, RR_MOD, RR_MOD_M_RXG, 0x1e0).await?;
                self.wr(path, RR_RXBB, RR_RXBB_C2G, 0x15).await?;
                self.wr(path, RR_RXBB, RR_RXBB_C1G, 0x0).await?;
            }
            Band::Ghz5 => {
                self.wr(path, RR_MOD, RR_MOD_M_RXG, 0x1a0).await?;
                self.wr(path, RR_RXA2, RR_RXA2_C2, 0x00).await?;
                self.wr(path, RR_RXA2, RR_RXA2_C1, 0x5).await?;
            }
            Band::Ghz6 => return Err(Error::Policy),
        }
        self.wm(R_IQK_CFG, B_IQK_CFG_SET, 1)?;
        let rf0 = self.rr(path, RR_MOD, RFREG_MASK).await?;
        self.wm(R_IQK_DIF2, B_IQK_DIF2_RXPI, rf0 | syn1to2)?;
        self.wm(R_IQK_COM, u32::MAX, 0x40010100)?;
        self.wm(R_IQK_RES + (u32::from(path) << 8), B_IQK_RES_RXCFIR, 0)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_SEL, 1)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_G3, 0)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_GP, 0)?;
        self.wm(R_IOQ_IQK_DPK, B_IOQ_IQK_DPK_EN, 1)?;
        self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
        self.a_iqk_one_shot(path, Shot::NbRxk, bw).await?;
        match band {
            Band::Ghz2 => {
                self.wr(path, RR_RXK, RR_RXK_SEL2G, 0x0).await?;
                self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x0).await?;
            }
            Band::Ghz5 => {
                self.wr(path, RR_RXK, RR_RXK_SEL5G, 0x0).await?;
                self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x0).await?;
                self.wr(path, RR_WLSEL, RR_WLSEL_AG, 0x0).await?;
            }
            Band::Ghz6 => return Err(Error::Policy),
        }
        let tmp = self.bb(R_RXIQC + (u32::from(path) << 8), u32::MAX)?;
        state.nb_rxcfir = tmp | 0x2;
        state.rx_fail = false;
        Ok(())
    }

    /// `_iqk_rxclk_setting`: 80MHz programs the 0x4d000a08 clock, other
    /// widths the 0x44000a08 clock.
    fn a_iqk_rxclk_setting(&mut self, path: u8, width: Width) -> Result<(), Error> {
        let base = R_CFIR_SYS + (u32::from(path) << 8);
        let rxck = R_P0_RXCK + (u32::from(path) << 13);
        if width == Width::Mhz80 {
            self.wm(base, u32::MAX, 0x4d000a08)?;
            self.wm(rxck, B_P0_RXCK_VAL, 0x2)?;
            self.wm(rxck, B_P0_RXCK_ON, 1)?;
            self.wm(R_UPD_CLK_ADC, B_UPD_CLK_ADC_ON, 1)?;
            self.wm(R_UPD_CLK_ADC, B_UPD_CLK_ADC_VAL, 0x1)
        } else {
            self.wm(base, u32::MAX, 0x44000a08)?;
            self.wm(rxck, B_P0_RXCK_VAL, 0x1)?;
            self.wm(rxck, B_P0_RXCK_ON, 1)?;
            self.wm(R_UPD_CLK_ADC, B_UPD_CLK_ADC_ON, 1)?;
            self.wm(R_UPD_CLK_ADC, B_UPD_CLK_ADC_VAL, 0)
        }
    }

    /// `_txk_group_sel`: four wideband groups.
    async fn a_txk_group_sel(
        &mut self,
        path: u8,
        band: Band,
        bw: u32,
        state: &mut Path,
    ) -> Result<(), Error> {
        const A_TXGAIN: [u32; 4] = [0xe466, 0x646d, 0xe4e2, 0x64ed];
        const G_TXGAIN: [u32; 4] = [0x60e8, 0x60f0, 0x61e8, 0x61ed];
        const A_ITQT: [u32; 4] = [0x12, 0x12, 0x12, 0x1b];
        const G_ITQT: [u32; 4] = [0x09, 0x12, 0x12, 0x12];
        const G_ATTSMXR: [u32; 4] = [0x0, 0x1, 0x1, 0x1];
        for gp in 0..4u8 {
            let g = usize::from(gp);
            match band {
                Band::Ghz2 => {
                    self.wm(R_RFGAIN_BND + (u32::from(path) << 8), B_RFGAIN_BND, 0x08)?;
                    self.wr(path, RR_GAINTX, RR_GAINTX_ALL, G_TXGAIN[g]).await?;
                    self.wr(path, RR_TXG1, RR_TXG1_ATT1, G_ATTSMXR[g]).await?;
                    self.wr(path, RR_TXG2, RR_TXG2_ATT0, G_ATTSMXR[g]).await?;
                    self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, G_ITQT[g])?;
                }
                Band::Ghz5 => {
                    self.wm(R_RFGAIN_BND + (u32::from(path) << 8), B_RFGAIN_BND, 0x04)?;
                    self.wr(path, RR_GAINTX, RR_GAINTX_ALL, A_TXGAIN[g]).await?;
                    self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, A_ITQT[g])?;
                }
                Band::Ghz6 => return Err(Error::Policy),
            }
            self.wm(R_IQK_RES + (u32::from(path) << 8), B_IQK_RES_TXCFIR, 0)?;
            self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_SEL, 1)?;
            self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_G3, 1)?;
            self.wm(
                R_CFIR_LUT + (u32::from(path) << 8),
                B_CFIR_LUT_GP,
                u32::from(gp),
            )?;
            self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
            self.a_iqk_one_shot(path, Shot::Txk, bw).await?;
            self.wm(
                R_IQKINF,
                1u32 << (8 + u32::from(gp) + u32::from(path) * 4),
                0,
            )?;
        }
        state.nb_txcfir = 0x40000000;
        self.wm(R_IQK_RES + (u32::from(path) << 8), B_IQK_RES_TXCFIR, 0x5)?;
        state.is_wb_txiqk = true;
        let _ = self.bb(R_TXIQC + (u32::from(path) << 8), u32::MAX)?;
        state.tx_fail = false;
        Ok(())
    }

    /// `_iqk_nbtxk`: the single narrowband group (group 2).
    async fn a_iqk_nbtxk(
        &mut self,
        path: u8,
        band: Band,
        bw: u32,
        state: &mut Path,
    ) -> Result<(), Error> {
        match band {
            Band::Ghz2 => {
                self.wm(R_RFGAIN_BND + (u32::from(path) << 8), B_RFGAIN_BND, 0x08)?;
                self.wr(path, RR_GAINTX, RR_GAINTX_ALL, 0x61e8).await?;
                self.wr(path, RR_TXG1, RR_TXG1_ATT1, 0x1).await?;
                self.wr(path, RR_TXG2, RR_TXG2_ATT0, 0x1).await?;
            }
            Band::Ghz5 => {
                self.wm(R_RFGAIN_BND + (u32::from(path) << 8), B_RFGAIN_BND, 0x04)?;
                self.wr(path, RR_GAINTX, RR_GAINTX_ALL, 0x64e2).await?;
            }
            Band::Ghz6 => return Err(Error::Policy),
        }
        self.wm(R_IQK_RES + (u32::from(path) << 8), B_IQK_RES_TXCFIR, 0)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_SEL, 1)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_G3, 1)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_GP, 2)?;
        self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, 0x12)?;
        self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
        self.a_iqk_one_shot(path, Shot::NbTxk, bw).await?;
        let tmp = self.bb(R_TXIQC + (u32::from(path) << 8), u32::MAX)?;
        state.nb_txcfir = tmp | 0x2;
        let _ = self.bb(R_TXIQC + (u32::from(path) << 8), u32::MAX)?;
        state.tx_fail = false;
        Ok(())
    }

    /// `_lok_res_table`.
    async fn a_lok_res_table(&mut self, path: u8, band: Band, ibias: u8) -> Result<(), Error> {
        self.wr(path, RR_LUTWE, RFREG_MASK, 0x2).await?;
        if band == Band::Ghz2 {
            self.wr(path, RR_LUTWA, RFREG_MASK, 0x0).await?;
        } else {
            self.wr(path, RR_LUTWA, RFREG_MASK, 0x1).await?;
        }
        self.wr(path, RR_LUTWD0, RFREG_MASK, u32::from(ibias))
            .await?;
        self.wr(path, RR_LUTWE, RFREG_MASK, 0x0).await
    }

    /// `_lok_finetune_check`: both TXMO cores must land in [0x2, 0x1d].
    async fn a_lok_finetune_check(&mut self, path: u8) -> Result<bool, Error> {
        let tmp = self.rr(path, RR_TXMO, RFREG_MASK).await?;
        let core_i = (tmp & RR_TXMO_COI) >> RR_TXMO_COI.trailing_zeros();
        let core_q = (tmp & RR_TXMO_COQ) >> RR_TXMO_COQ.trailing_zeros();
        Ok(core_i < 0x2 || core_i > 0x1d || core_q < 0x2 || core_q > 0x1d)
    }

    /// `_iqk_lok`: coarse + fine one-shots with a 10us gap; returns the
    /// fine-tune check. The one-shot results land in
    /// `lok_cor_fail`/`lok_fin_fail` (always false here: `_iqk_check_cal`
    /// fails closed on timeout instead of returning true).
    async fn a_iqk_lok(
        &mut self,
        path: u8,
        band: Band,
        syn1to2: u32,
        state: &mut Path,
    ) -> Result<bool, Error> {
        let itqt = match band {
            Band::Ghz2 => {
                self.wr(path, RR_GAINTX, RR_GAINTX_ALL, 0xe5e0).await?;
                0x09
            }
            Band::Ghz5 => {
                self.wr(path, RR_GAINTX, RR_GAINTX_ALL, 0xe4e0).await?;
                0x12
            }
            Band::Ghz6 => return Err(Error::Policy),
        };
        self.wm(R_IQK_CFG, B_IQK_CFG_SET, 1)?;
        let rf0 = self.rr(path, RR_MOD, RFREG_MASK).await?;
        self.wm(R_IQK_DIF1, B_IQK_DIF1_TXPI, rf0 | syn1to2)?;
        self.wm(R_IQK_RES + (u32::from(path) << 8), B_IQK_RES_TXCFIR, 0)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_SEL, 0x1)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_G3, 0x1)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_GP, 0x0)?;
        self.wm(R_IOQ_IQK_DPK, B_IOQ_IQK_DPK_EN, 1)?;
        self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
        self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, itqt)?;
        self.a_iqk_one_shot(path, Shot::FlokCoarse, 0).await?;
        state.lok_cor_fail = false;
        self.delay(10).await?;
        self.wm(R_KIP_IQP + (u32::from(path) << 8), u32::MAX, itqt)?;
        self.a_iqk_one_shot(path, Shot::FlokFine, 0).await?;
        state.lok_fin_fail = false;
        self.a_lok_finetune_check(path).await
    }

    /// `_iqk_txk_setting`.
    async fn a_iqk_txk_setting(&mut self, path: u8, band: Band, syn1to2: u32) -> Result<(), Error> {
        self.wm(R_P0_NRBW + (u32::from(path) << 13), B_P0_NRBW_DBG, 1)?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x1f)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x13)?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0x0001)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0x0041)?;
        self.delay(1).await?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, 0x0303)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, 0x0000)?;
        match band {
            Band::Ghz2 => {
                self.wr(path, RR_XALNA2, RR_XALNA2_SW, 0x00).await?;
                self.wr(path, RR_RCKD, RR_RCKD_POW, 0x3f).await?;
                self.wr(path, RR_TXG1, RR_TXG1_ATT2, 0x0).await?;
                self.wr(path, RR_TXG1, RR_TXG1_ATT1, 0x1).await?;
                self.wr(path, RR_TXG2, RR_TXG2_ATT0, 0x1).await?;
                self.wr(path, RR_TXGA, RR_TXGA_LOK_EN, 0x0).await?;
                self.wr(path, RR_LUTWE, RR_LUTWE_LOK, 0x1).await?;
                self.wr(path, RR_LUTDBG, RR_LUTDBG_LOK, 0x0).await?;
                self.wr(path, RR_LUTWA, RR_LUTWA_MASK, 0x000).await?;
                self.wr(path, RR_RSV2, RFREG_MASK, 0x80200).await?;
                self.wr(path, RR_DTXLOK, RFREG_MASK, 0x80200).await?;
                self.wr(path, RR_MOD, RFREG_MASK, 0x403e0 | syn1to2).await?;
                self.delay(1).await?;
            }
            Band::Ghz5 => {
                self.wr(path, RR_XGLNA2, RR_XGLNA2_SW, 0x00).await?;
                self.wr(path, RR_RCKD, RR_RCKD_POW, 0x3f).await?;
                self.wr(path, RR_BIASA, RR_BIASA_A, 0x7).await?;
                self.wr(path, RR_TXGA, RR_TXGA_LOK_EN, 0x0).await?;
                self.wr(path, RR_LUTWE, RR_LUTWE_LOK, 0x1).await?;
                self.wr(path, RR_LUTDBG, RR_LUTDBG_LOK, 0x0).await?;
                self.wr(path, RR_LUTWA, RR_LUTWA_MASK, 0x100).await?;
                self.wr(path, RR_RSV2, RFREG_MASK, 0x80200).await?;
                self.wr(path, RR_DTXLOK, RFREG_MASK, 0x80200).await?;
                self.wr(path, RR_LUTWD0, RFREG_MASK, 0x1).await?;
                self.wr(path, RR_LUTWD0, RFREG_MASK, 0x0).await?;
                self.wr(path, RR_MOD, RFREG_MASK, 0x403e0 | syn1to2).await?;
                self.delay(1).await?;
            }
            Band::Ghz6 => return Err(Error::Policy),
        }
        Ok(())
    }

    /// `_iqk_txclk_setting`.
    fn a_iqk_txclk_setting(&mut self, path: u8) -> Result<(), Error> {
        self.wm(R_CFIR_SYS + (u32::from(path) << 8), u32::MAX, 0xce000a08)
    }

    /// `_iqk_info_iqk`: publish the fail bits, sample the result
    /// registers, count a non-zero fail nibble.
    fn a_iqk_info(&mut self, path: u8, state: &mut Path, iqk: &mut Iqk) -> Result<(), Error> {
        let shift = u32::from(path) * 4;
        self.wm(R_IQKINF, 1u32 << shift, u32::from(state.lok_cor_fail))?;
        self.wm(R_IQKINF, 1u32 << (1 + shift), u32::from(state.lok_fin_fail))?;
        self.wm(R_IQKINF, 1u32 << (2 + shift), u32::from(state.tx_fail))?;
        self.wm(R_IQKINF, 1u32 << (3 + shift), u32::from(state.rx_fail))?;
        state.iqk_enable = self.bb(R_IQK_RES + (u32::from(path) << 8), u32::MAX)?;
        state.tx_result = self.bb(R_TXIQC + (u32::from(path) << 8), u32::MAX)?;
        state.rx_result = self.bb(R_RXIQC + (u32::from(path) << 8), u32::MAX)?;
        self.wm(R_IQKINF2, B_IQKINF2_KCNT, u32::from(iqk.times))?;
        if self.bb(R_IQKINF, 0xf << shift)? != 0 {
            iqk.fail_count += 1;
        }
        self.wm(R_IQKINF2, 0x00ff0000u32 << shift, iqk.fail_count)
    }

    /// `_iqk_get_ch_info`: read `RR_CFGCH` (diagnostic), read 0x35c for
    /// `syn1to2`, publish band/bw/channel + versions. The MCC table
    /// index is always 0 (see the module doc).
    async fn a_iqk_get_ch_info(&mut self, path: u8, channel: Profile) -> Result<u32, Error> {
        let _ = self.rr(path, RR_CFGCH, RFREG_MASK).await?;
        let syn1to2 = if self.bb(0x35c, 0xc00)? == 0x01 { 1 } else { 0 };
        self.wm(R_IQKINF, B_IQKINF_VER, IQK_VER)?;
        let shift = u32::from(path) * 16;
        self.wm(R_IQKCH, 0x000fu32 << shift, channel.band() as u32)?;
        self.wm(R_IQKCH, 0x00f0u32 << shift, channel.width() as u32)?;
        self.wm(R_IQKCH, 0xff00u32 << shift, u32::from(channel.center()))?;
        self.wm(R_IQKINF2, 0xff, NCTL_VER)?;
        Ok(syn1to2)
    }

    /// `_iqk_restore`: restore the per-path CFIR results and park the
    /// KIP/LOK state.
    async fn a_iqk_restore(&mut self, path: u8, state: &Path) -> Result<(), Error> {
        self.wm(R_TXIQC + (u32::from(path) << 8), u32::MAX, state.nb_txcfir)?;
        self.wm(R_RXIQC + (u32::from(path) << 8), u32::MAX, state.nb_rxcfir)?;
        self.wm(R_NCTL_RPT, u32::MAX, 0)?;
        self.wm(R_MDPK_RX_DCK, u32::MAX, 0)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x80000000)?;
        self.wm(R_KPATH_CFG, u32::MAX, 0)?;
        self.wm(R_GAPK, B_GAPK_ADR, 0)?;
        self.wm(R_CFIR_SYS + (u32::from(path) << 8), u32::MAX, 0x10010000)?;
        self.wm(R_KIP + (u32::from(path) << 8), B_KIP_RFGAIN, 0)?;
        self.wm(R_CFIR_MAP + (u32::from(path) << 8), u32::MAX, 0xe4e4e4e4)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_SEL, 0)?;
        self.wm(R_KIP_IQP + (u32::from(path) << 8), B_KIP_IQP_IQSW, 0)?;
        self.wm(R_LOAD_COEF + (u32::from(path) << 8), u32::MAX, 0x00000002)?;
        self.wr(path, RR_LUTWE, RR_LUTWE_LOK, 0x0).await?;
        self.wr(path, RR_RCKD, RR_RCKD_POW, 0x0).await?;
        self.wr(path, RR_LUTWE, RR_LUTWE_LOK, 0x0).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
        self.wr(path, RR_TXRSV, RR_TXRSV_GAPK, 0x0).await?;
        self.wr(path, RR_BIAS, RR_BIAS_GAPK, 0x0).await?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 0x1).await
    }

    /// `_iqk_afebb_restore`: non-DBCC `_kpath` = RF_AB programs the
    /// NONDBCC restore table.
    async fn a_iqk_afebb_restore(&mut self, _path: u8) -> Result<(), Error> {
        self.table(IQK_RESTORE_NONDBCC).await
    }

    /// `_iqk_preset`: non-DBCC, table index 0.
    async fn a_iqk_preset(&mut self, path: u8) -> Result<(), Error> {
        self.wm(R_COEF_SEL + (u32::from(path) << 8), B_COEF_SEL_IQC, 0)?;
        self.wm(R_CFIR_LUT + (u32::from(path) << 8), B_CFIR_LUT_G2, 0)?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 0x0).await?;
        self.wm(R_NCTL_RPT, u32::MAX, 0x00000080)?;
        self.wm(R_NCTL_RW, u32::MAX, 0)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x81ff010a)?;
        self.wm(R_KPATH_CFG, u32::MAX, 0x00200000)?;
        self.wm(R_MDPK_RX_DCK, u32::MAX, 0x80000000)?;
        self.wm(R_LOAD_COEF + (u32::from(path) << 8), u32::MAX, 0)
    }

    /// `_iqk_macbb_setting`: non-DBCC `_kpath` = RF_AB programs the
    /// NONDBCC set table.
    async fn a_iqk_macbb(&mut self, _path: u8) -> Result<(), Error> {
        self.table(IQK_SET_NONDBCC).await
    }

    /// `_iqk_by_path`: TX clock, LOK up to 3x (ibias 1..3), wideband TX
    /// group select (`is_nbiqk` is false), RX clock, RXK setting, then
    /// narrowband RXK on 2G (`is_nbiqk || dbcc || 2G`) or the wideband
    /// RX group select on 5G, then `_iqk_info_iqk`.
    async fn a_iqk_by_path(
        &mut self,
        path: u8,
        channel: Profile,
        syn1to2: u32,
        state: &mut Path,
    ) -> Result<(), Error> {
        let band = channel.band();
        let bw = channel.width() as u32;
        self.a_iqk_txclk_setting(path)?;
        let mut ibias = 0x1u8;
        let mut lok_fail = false;
        for _ in 0..3 {
            self.a_lok_res_table(path, band, ibias).await?;
            ibias += 1;
            self.a_iqk_txk_setting(path, band, syn1to2).await?;
            lok_fail = self.a_iqk_lok(path, band, syn1to2, state).await?;
            if !lok_fail {
                break;
            }
        }
        state.lok_fail = lok_fail;
        self.a_txk_group_sel(path, band, bw, state).await?;
        self.a_iqk_rxclk_setting(path, channel.width())?;
        self.a_iqk_rxk_setting(path, band).await?;
        if band == Band::Ghz2 {
            self.a_iqk_nbrxk(path, band, bw, syn1to2, state).await?;
        } else {
            self.a_rxk_group_sel(path, band, bw, syn1to2, state).await?;
        }
        Ok(())
    }

    /// `_doiqk`: times++, channel info, BB/RF backup, MACBB set,
    /// preset, `_iqk_by_path`, restore, AFE/BB restore, BB/RF restore.
    /// The BTC ONESHOT START/STOP return without I/O.
    async fn a_doiqk(&mut self, path: u8, channel: Profile, iqk: &mut Iqk) -> Result<(), Error> {
        iqk.times = iqk.times.wrapping_add(1);
        let syn1to2 = self.a_iqk_get_ch_info(path, channel).await?;
        let bb = self.a_backup_bb()?;
        let rf = self.a_backup_rf(path).await?;
        self.a_iqk_macbb(path).await?;
        self.a_iqk_preset(path).await?;
        let mut state = Path::default();
        self.a_iqk_by_path(path, channel, syn1to2, &mut state)
            .await?;
        self.a_iqk_info(path, &mut state, iqk)?;
        iqk.paths[usize::from(path)] = state;
        self.a_iqk_restore(path, &state).await?;
        self.a_iqk_afebb_restore(path).await?;
        self.a_restore_bb(&bb)?;
        self.a_restore_rf(path, &rf).await
    }
}

impl Iqk {
    /// Latest per-path results, only after a completed IQK without a LOK
    /// failure on either path.
    pub fn results(&self) -> Option<&[Path; 2]> {
        self.calibrated.then_some(&self.paths)
    }
    /// `_iqk_times`: one `_doiqk` per path.
    pub fn times(&self) -> u8 {
        self.times
    }
    /// rtw8852a_rfk.c `rtw8852a_iqk(PHY_0)`: `BTC_WRFKT_IQK` START,
    /// `rtw89_chip_stop_sch_tx`, `_wait_rx_mode(RF_AB)` (2us step,
    /// 5000us), `_iqk_init` (`R_IQKINF` cleared), then `_doiqk` path A
    /// and path B, each between ONESHOT START/STOP, then resume and
    /// STOP. 8852A is Wi-Fi 6: a 6GHz channel is refused with
    /// `Error::Policy`.
    ///
    /// # Safety
    /// Actual RTL8852A PHY0 (non-DBCC) after `rfk::a::Init::prepare`,
    /// the BB/RF retune to THIS `channel` and its RX DCK; current
    /// admission (emission recipe, board policy, coexistence) is
    /// enforced by Interface at every access. No concurrent
    /// PHY/packet/reset/PM owner; the outer attempt closes and retains
    /// DMA on failure/cancellation.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
    ) -> Result<(), Error> {
        if channel.band() == Band::Ghz6 {
            return Err(Error::Policy);
        }
        self.calibrated = false;
        self.channel = Some(channel);
        io.admit()?;
        io.begin(Kind::Iqk).await?;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        access.a_wait_rx_mode().await?;
        access.wm(R_IQKINF, u32::MAX, 0)?;
        for path in 0..2u8 {
            access.0.admit()?;
            access.0.begin(Kind::IqkPath).await?;
            access.a_doiqk(path, channel, self).await?;
            access.0.admit()?;
            access.0.end(Kind::IqkPath).await?;
        }
        access.0.admit()?;
        access.0.resume(saved).await?;
        access.0.admit()?;
        access.0.end(Kind::Iqk).await?;
        if self.paths.iter().any(|p| p.lok_fail) {
            return Err(Error::Terminal);
        }
        self.calibrated = true;
        Ok(())
    }
}

#[rustfmt::skip]
pub(super) const IQK_SET_NONDBCC: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x303),Entry(1,0,0x5864,0x18000000,0x3),
Entry(1,0,0x7864,0x18000000,0x3),Entry(1,0,0x12b8,0x40000000,0x1),
Entry(1,0,0x32b8,0x40000000,0x1),Entry(1,0,0x30c,0xff000000,0x13),
Entry(1,0,0x32c,0xffff0000,0x1),Entry(1,0,0x12b8,0x10000000,0x1),
Entry(1,0,0x58c8,0x1000000,0x1),Entry(1,0,0x78c8,0x1000000,0x1),
Entry(1,0,0x5864,0xc0000000,0x3),Entry(1,0,0x7864,0xc0000000,0x3),
Entry(1,0,0x2008,0x1ffffff,0x1ffffff),Entry(1,0,0xc1c,0x4,0x1),
Entry(1,0,0x700,0x8000000,0x1),Entry(1,0,0xc70,0x3ff,0x3ff),
Entry(1,0,0xc60,0x3,0x3),Entry(1,0,0xc6c,0x1,0x1),
Entry(1,0,0x58ac,0x8000000,0x1),Entry(1,0,0x78ac,0x8000000,0x1),
Entry(1,0,0xc3c,0x200,0x1),Entry(1,0,0x2344,0x80000000,0x1),
Entry(1,0,0x4490,0x80000000,0x1),Entry(1,0,0x12a0,0x7000,0x7),
Entry(1,0,0x12a0,0x8000,0x1),Entry(1,0,0x12a0,0x70000,0x3),
Entry(1,0,0x12a0,0x80000,0x1),Entry(1,0,0x32a0,0x70000,0x3),
Entry(1,0,0x32a0,0x80000,0x1),Entry(1,0,0x700,0x1000000,0x1),
Entry(1,0,0x700,0x6000000,0x2),Entry(1,0,0x20fc,0xffff0000,0x3333),
Entry(1,0,0x58f0,0x80000,0x0),Entry(1,0,0x78f0,0x80000,0x0),
];
#[rustfmt::skip]
pub(super) const IQK_SET_DBCC_PATH0: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x101),Entry(1,0,0x5864,0x18000000,0x3),
Entry(1,0,0x7864,0x18000000,0x3),Entry(1,0,0x12b8,0x40000000,0x1),
Entry(1,0,0x30c,0xff000000,0x13),Entry(1,0,0x32c,0xffff0000,0x1),
Entry(1,0,0x12b8,0x10000000,0x1),Entry(1,0,0x58c8,0x1000000,0x1),
Entry(1,0,0x5864,0xc0000000,0x3),Entry(1,0,0x2008,0x1ffffff,0x1ffffff),
Entry(1,0,0xc1c,0x4,0x1),Entry(1,0,0x700,0x8000000,0x1),
Entry(1,0,0xc70,0x3ff,0x3ff),Entry(1,0,0xc60,0x3,0x3),
Entry(1,0,0xc6c,0x1,0x1),Entry(1,0,0x58ac,0x8000000,0x1),
Entry(1,0,0xc3c,0x200,0x1),Entry(1,0,0x2320,0x1,0x1),
Entry(1,0,0x4490,0x80000000,0x1),Entry(1,0,0x12a0,0x7000,0x7),
Entry(1,0,0x12a0,0x8000,0x1),Entry(1,0,0x12a0,0x70000,0x3),
Entry(1,0,0x12a0,0x80000,0x1),Entry(1,0,0x700,0x1000000,0x1),
Entry(1,0,0x700,0x6000000,0x2),Entry(1,0,0x20fc,0xffff0000,0x1111),
Entry(1,0,0x58f0,0x80000,0x0),
];
#[rustfmt::skip]
pub(super) const IQK_SET_DBCC_PATH1: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x202),Entry(1,0,0x7864,0x18000000,0x3),
Entry(1,0,0x32b8,0x40000000,0x1),Entry(1,0,0x30c,0xff000000,0x13),
Entry(1,0,0x32c,0xffff0000,0x1),Entry(1,0,0x32b8,0x10000000,0x1),
Entry(1,0,0x78c8,0x1000000,0x1),Entry(1,0,0x7864,0xc0000000,0x3),
Entry(1,0,0x2008,0x1ffffff,0x1ffffff),Entry(1,0,0x2c1c,0x4,0x1),
Entry(1,0,0x2700,0x8000000,0x1),Entry(1,0,0xc70,0x3ff,0x3ff),
Entry(1,0,0xc60,0x3,0x3),Entry(1,0,0xc6c,0x1,0x1),
Entry(1,0,0x78ac,0x8000000,0x1),Entry(1,0,0x2c3c,0x200,0x1),
Entry(1,0,0x6490,0x80000000,0x1),Entry(1,0,0x32a0,0x7000,0x7),
Entry(1,0,0x32a0,0x8000,0x1),Entry(1,0,0x32a0,0x70000,0x3),
Entry(1,0,0x32a0,0x80000,0x1),Entry(1,0,0x2700,0x1000000,0x1),
Entry(1,0,0x2700,0x6000000,0x2),Entry(1,0,0x20fc,0xffff0000,0x2222),
Entry(1,0,0x78f0,0x80000,0x0),
];
#[rustfmt::skip]
pub(super) const IQK_RESTORE_NONDBCC: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x303),Entry(1,0,0x12b8,0x40000000,0x0),
Entry(1,0,0x32b8,0x40000000,0x0),Entry(1,0,0x5864,0xc0000000,0x0),
Entry(1,0,0x7864,0xc0000000,0x0),Entry(1,0,0x2008,0x1ffffff,0x0),
Entry(1,0,0xc1c,0x4,0x0),Entry(1,0,0x700,0x8000000,0x0),
Entry(1,0,0xc70,0x1f,0x3),Entry(1,0,0xc70,0x3e0,0x3),
Entry(1,0,0x12a0,0xff000,0x0),Entry(1,0,0x32a0,0xff000,0x0),
Entry(1,0,0x700,0x7000000,0x0),Entry(1,0,0x5864,0x20000000,0x0),
Entry(1,0,0x7864,0x20000000,0x0),Entry(1,0,0xc3c,0x200,0x0),
Entry(1,0,0x2320,0x1,0x0),Entry(1,0,0x20fc,0xffff0000,0x0),
Entry(1,0,0x58c8,0x1000000,0x0),Entry(1,0,0x78c8,0x1000000,0x0),
];
#[rustfmt::skip]
pub(super) const IQK_RESTORE_DBCC_PATH0: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x101),Entry(1,0,0x12b8,0x40000000,0x0),
Entry(1,0,0x5864,0xc0000000,0x0),Entry(1,0,0x2008,0x1ffffff,0x0),
Entry(1,0,0xc1c,0x4,0x0),Entry(1,0,0x700,0x8000000,0x0),
Entry(1,0,0xc70,0x1f,0x3),Entry(1,0,0xc70,0x3e0,0x3),
Entry(1,0,0x12a0,0xff000,0x0),Entry(1,0,0x700,0x7000000,0x0),
Entry(1,0,0x5864,0x20000000,0x0),Entry(1,0,0xc3c,0x200,0x0),
Entry(1,0,0x20fc,0xffff0000,0x0),Entry(1,0,0x58c8,0x1000000,0x0),
];
#[rustfmt::skip]
pub(super) const IQK_RESTORE_DBCC_PATH1: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x202),Entry(1,0,0x32b8,0x40000000,0x0),
Entry(1,0,0x7864,0xc0000000,0x0),Entry(1,0,0x2008,0x1ffffff,0x0),
Entry(1,0,0x2c1c,0x4,0x0),Entry(1,0,0x2700,0x8000000,0x0),
Entry(1,0,0xc70,0x1f,0x3),Entry(1,0,0xc70,0x3e0,0x3),
Entry(1,0,0x32a0,0xff000,0x0),Entry(1,0,0x2700,0x7000000,0x0),
Entry(1,0,0x7864,0x20000000,0x0),Entry(1,0,0x2c3c,0x200,0x0),
Entry(1,0,0x20fc,0xffff0000,0x0),Entry(1,0,0x78c8,0x1000000,0x0),
];
