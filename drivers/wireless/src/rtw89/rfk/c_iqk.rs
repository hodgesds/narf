// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C channel IQK: rtw8852c_rfk.c `rtw8852c_iqk` for the non-DBCC
//! PHY_0 (`_kpath` = RF_AB) on one typed [`Profile`], wideband
//! (`_iqk_init`: `is_nbiqk = false`). RFK MCC table index 0 is used: the
//! first retuned entity takes the first idle `rtw89_rfk_chan_lookup` slot.
//!
//! Linux `_iqk_check_cal` only logs a 0xbff8 timeout and always reports
//! success, so the wideband TX/RX group results are always "pass"; only
//! `_lok_finetune_check` can fail. NARF fails the attempt closed on any
//! poll timeout and refuses a LOK failure as not calibrated.
use super::super::operating_channel_c::{Band, Profile, Width};
use super::{power, Access, Entry, Error, Interface, Kind};

const RFREG_MASK: u32 = 0xfffff;
const RR_MOD: u32 = 0x00;
const RR_MOD_MASK: u32 = 0xf0000;
const RR_MOD_M_RXG: u32 = 0x3ff0;
const RR_MOD_NBW: u32 = 0xc000;
const RR_MOD_V_RX: u32 = 0x3;
const RR_RSV1: u32 = 0x05;
const RR_RSV1_RST: u32 = 1;
const RR_LOKVB: u32 = 0x0a;
const RR_LOKVB_COI: u32 = 0xf_c000;
const RR_LOKVB_COQ: u32 = 0x3f0;
const RR_TXIG: u32 = 0x11;
const RR_TXIG_GR0: u32 = 0x3;
const RR_TXIG_GR1: u32 = 0x70;
const RR_TXIG_TG: u32 = 0x1_f000;
const RR_CHTR: u32 = 0x17;
const RR_CHTR_MOD: u32 = 0xc00;
const RR_CHTR_TXRX: u32 = 0x3ff;
const RR_RSV4: u32 = 0x1f;
const RR_RSV4_AGH: u32 = 0x3_0000;
const RR_RSV4_PLLCH: u32 = 0x3ff;
const RR_TXG1: u32 = 0x51;
const RR_TXG1_ATT1: u32 = 1 << 11;
const RR_TXG1_ATT2: u32 = 1 << 19;
const RR_TXG2: u32 = 0x52;
const RR_TXG2_ATT0: u32 = 1 << 11;
const RR_TXGA: u32 = 0x55;
const RR_TXGA_LOK_EXT: u32 = 0x1f;
const RR_TXMO: u32 = 0x58;
const RR_TXMO_COI: u32 = 0xf_8000;
const RR_TXMO_COQ: u32 = 0x7c00;
const RR_TXATANK: u32 = 0x64;
const RR_TXATANK_LBSW2: u32 = 0x3_8000;
const RR_TXA2: u32 = 0x65;
const RR_TXA2_LDO: u32 = 0xf_0000;
const RR_TXPOW: u32 = 0x7f;
const RR_TXPOW_TXAS: u32 = 1 << 7;
const RR_RXBB: u32 = 0x83;
const RR_RXBB_VOBUF: u32 = 0xf000;
const RR_RXG: u32 = 0x84;
const RR_RXG_IQKMOD: u32 = 0xf_0000;
const RR_RXAE: u32 = 0x89;
const RR_RXAE_IQKMOD: u32 = 0xf;
const RR_RXA2: u32 = 0x8c;
const RR_RXA2_IATT: u32 = 0xf0;
const RR_RXBB2: u32 = 0x8f;
const RR_RXBB2_CKT: u32 = 1 << 12;
const RR_IQKPLL: u32 = 0xdc;
const RR_IQKPLL_MOD: u32 = 0x300;
const RR_LUTWE: u32 = 0xef;
const RR_LUTWE_LOK: u32 = 1 << 2;
const RR_BBDC: u32 = 0x10005;
const RR_BBDC_SEL: u32 = 1;

const R_ANAPAR_PW15: u32 = 0x030c;
const B_ANAPAR_PW15: u32 = 0xff00_0000;
const R_ANAPAR: u32 = 0x032c;
const B_ANAPAR_15: u32 = 0xffff_0000;
const R_P0_RXCK: u32 = 0x12a0;
const B_P0_RXCK_ON: u32 = 1 << 19;
const B_P0_RXCK_VAL: u32 = 0x7_0000;
const B_P0_TXCK_ON: u32 = 1 << 15;
const B_P0_TXCK_VAL: u32 = 0x7000;
const R_P0_NRBW: u32 = 0x12b8;
const B_P0_NRBW_DBG: u32 = 1 << 30;
const R_ADC_FIFO: u32 = 0x20fc;
const B_ADC_FIFO_RXK: u32 = 0xffff_0000;
const B_ADC_FIFO_A0: u32 = 1 << 16;
const B_ADC_FIFO_A1: u32 = 1 << 20;
const B_ADC_FIFO_A2: u32 = 1 << 24;
const B_ADC_FIFO_A3: u32 = 1 << 28;
const R_P0_AGC_CTL: u32 = 0x4730;
const R_P1_AGC_CTL: u32 = 0x4a9c;
const B_AGC_EN: u32 = 1 << 31;
const R_UPD_CLK: u32 = 0x5670;
const B_DAC_VAL: u32 = 1 << 31;
const B_ACK_VAL: u32 = 0x6000_0000;
const B_DPD_DIS: u32 = 1 << 14;
const B_DPD_GDIS: u32 = 1 << 13;
const R_NCTL_CFG: u32 = 0x8000;
const R_NCTL_RPT: u32 = 0x8008;
const R_NCTL_N1: u32 = 0x8010;
const B_NCTL_N1_CIP: u32 = 0xff;
const R_IQK_DIF4: u32 = 0x802c;
const B_IQK_DIF4_TXT: u32 = 0xfff;
const IQK_DF4_TXT_8_25MHZ: u32 = 0x021;
const R_KIP_SYSCFG: u32 = 0x8088;
const R_COEF_SEL: u32 = 0x8104;
const B_COEF_SEL_IQC: u32 = 1;
const R_IQK_RES: u32 = 0x8124;
const R_TXIQC: u32 = 0x8138;
const R_RXIQC: u32 = 0x813c;
const R_CFIR_LUT: u32 = 0x8154;
const B_CFIR_LUT_SEL: u32 = 1 << 8;
const B_CFIR_LUT_SET: u32 = 1 << 4;
const B_CFIR_LUT_G3: u32 = 1 << 3;
const B_CFIR_LUT_G2: u32 = 1 << 2;
const B_CFIR_LUT_GP_V1: u32 = 0x7;
const B_CFIR_LUT_GP: u32 = 0x3;
const R_KIP_IQP: u32 = 0x81cc;
const B_KIP_IQP_IQSW: u32 = 0x3f;
const R_IQKINF: u32 = 0x9fe0;
const B_IQKINF_VER: u32 = 0xff00_0000;
const B_IQKINF_FAIL: u32 = 0xf;
const B_IQKINF_FCOR: u32 = 1;
const B_IQKINF_FFIN: u32 = 1 << 1;
const B_IQKINF_FTX: u32 = 1 << 2;
const B_IQKINF_F_RX: u32 = 1 << 3;
const R_IQKCH: u32 = 0x9fe4;
const B_IQKCH_BAND: u32 = 0xf;
const B_IQKCH_BW: u32 = 0xf0;
const B_IQKCH_CH: u32 = 0xff00;
const R_IQKINF2: u32 = 0x9fe8;
const B_IQKINF2_NCTLV: u32 = 0xff;
const B_IQKINF2_KCNT: u32 = 0xff00;
const B_IQKINF2_FCNT: u32 = 0xff_0000;
const R_P0_CFCH_BW0: u32 = 0xc0d4;
const B_P0_CFCH_CTL: u32 = 0x780;
const B_P0_CFCH_EN: u32 = 0x7800;
const B_P0_CFCH_BW0: u32 = 0x0c00_0000;
const R_P0_CFCH_BW1: u32 = 0xc0d8;
const B_P0_CFCH_BW1: u32 = 0x1e0;
const R_DRCK: u32 = 0xc0c4;
const B_DRCK_MUL: u32 = 0x003e_0000;
const R_ADCMOD: u32 = 0xc0e8;
const B_ADCMOD_LP: u32 = 0xffff_0000;

const RTW8852C_IQK_VER: u32 = 0x2a;
const RTW8852C_NCTL_VER: u32 = 0xd;
/// `enum adc_ck`.
const ADC_480M: u32 = 1;
const ADC_960M: u32 = 2;
const ADC_1920M: u32 = 3;
/// `enum dac_ck` DAC_960M.
const DAC_960M: u32 = 7;

/// `rtw8852c_backup_bb_regs` / `rtw8852c_backup_rf_regs`.
const BACKUP_BB: [u32; 8] = [
    0x8120, 0xc0d4, 0xc0d8, 0xc0e8, 0x8220, 0xc1d4, 0xc1d8, 0xc1e8,
];
const BACKUP_RF: [u32; 7] = [0xdf, 0x5f, 0x8f, 0x97, 0xa3, 0x5, 0x10005];

/// `_rxk_{g,a,a6}_idxrxgain` / `_idxattc2` (RXK_GROUP_NR = 4).
const RXK_G: ([u32; 4], [u32; 4]) = ([0x252, 0x26c, 0x350, 0x360], [0x00, 0x07, 0x00, 0x3]);
const RXK_A: ([u32; 4], [u32; 4]) = ([0x190, 0x198, 0x310, 0x318], [0; 4]);
const RXK_A6: ([u32; 4], [u32; 4]) = ([0x190, 0x196, 0x290, 0x316], [0; 4]);
/// `_txk_*_{power_range,track_range,gain_bb,itqt}` (TXK_GROUP_NR = 3),
/// one `[power_range, track_range, gain_bb, itqt]` row per group.
const TXK_G: [[u32; 4]; 3] = [[0, 5, 0x0e, 0x12], [0, 6, 0x0a, 0x12], [0, 6, 0x0e, 0x12]];
const TXK_A: [[u32; 4]; 3] = [[0, 5, 0x12, 0x12], [0, 6, 0x09, 0x12], [0, 7, 0x0e, 0x12]];
const TXK_A6: [[u32; 4]; 3] = [[0, 6, 0x12, 0x12], [0, 7, 0x09, 0x12], [0, 7, 0x0e, 0x12]];

/// `_ck480M` / `_ck960M` / `_ck1920M`: (ctl, en, bw0, bw1, mul, lp).
const fn rxck_def(ck: u32) -> [u32; 6] {
    match ck {
        ADC_480M => [0x8, 0x2, 0x3, 0xf, 0x0, 0x9],
        ADC_960M => [0x8, 0x2, 0x2, 0x8, 0x0, 0x9],
        _ => [0x8, 0x0, 0x2, 0x4, 0x6, 0x9],
    }
}

/// rtw8852c_rfk_table.c `rtw8852c_iqk_rxk_cfg_defs`.
const RXK_CFG: [Entry; 4] = [
    Entry(1, 0, 0x030c, 0xff00_0000, 0x0f),
    Entry(1, 0, 0x030c, 0xff00_0000, 0x03),
    Entry(1, 0, 0x032c, 0xffff_0000, 0x0001),
    Entry(1, 0, 0x032c, 0xffff_0000, 0x0041),
];
/// `rtw8852c_iqk_afebb_restore_defs_a` / `_b`.
const AFEBB_RESTORE: [[Entry; 10]; 2] = [
    [
        Entry(1, 0, 0x12b8, 0x4000_0000, 0x0),
        Entry(1, 0, 0x20fc, 0x0001_0000, 0x1),
        Entry(1, 0, 0x20fc, 0x0010_0000, 0x0),
        Entry(1, 0, 0x20fc, 0x0100_0000, 0x1),
        Entry(1, 0, 0x20fc, 0x1000_0000, 0x0),
        Entry(1, 0, 0x5670, u32::MAX, 0x0000_0000),
        Entry(1, 0, 0x12a0, 0x000f_f000, 0x00),
        Entry(1, 0, 0x20fc, 0x0001_0000, 0x0),
        Entry(1, 0, 0x20fc, 0x0100_0000, 0x0),
        Entry(0, 0, 0x10005, 0x00001, 0x1),
    ],
    [
        Entry(1, 0, 0x32b8, 0x4000_0000, 0x0),
        Entry(1, 0, 0x20fc, 0x0002_0000, 0x1),
        Entry(1, 0, 0x20fc, 0x0020_0000, 0x0),
        Entry(1, 0, 0x20fc, 0x0200_0000, 0x1),
        Entry(1, 0, 0x20fc, 0x2000_0000, 0x0),
        Entry(1, 0, 0x7670, u32::MAX, 0x0000_0000),
        Entry(1, 0, 0x32a0, 0x000f_f000, 0x00),
        Entry(1, 0, 0x20fc, 0x0002_0000, 0x0),
        Entry(1, 0, 0x20fc, 0x0200_0000, 0x0),
        Entry(0, 1, 0x10005, 0x00001, 0x1),
    ],
];

/// `enum rtw8852c_iqk_type` one-shot commands used by the wideband flow.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shot {
    AFlokCoarse,
    GFlokCoarse,
    AFlokFine,
    GFlokFine,
    FlokVbuffer,
    Txk,
    Rxk,
}

/// Per-path `rtw89_iqk_info` fields of one C IQK.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Path {
    pub lok_cor_fail: bool,
    pub lok_fin_fail: bool,
    pub lok_fail: bool,
    pub tx_fail: bool,
    pub rx_fail: bool,
    pub nb_txcfir: u32,
    pub nb_rxcfir: u32,
    pub is_wb_txiqk: bool,
    pub is_wb_rxiqk: bool,
    /// `lok_idac[0][path]` / `lok_vbuf[0][path]` (raw RR_TXMO / RR_LOKVB).
    pub lok_idac: u32,
    pub lok_vbuf: u32,
    /// `bp_iqkenable` / `bp_txkresult` / `bp_rxkresult`.
    pub iqk_enable: u32,
    pub tx_result: u32,
    pub rx_result: u32,
}

/// `rtw89_iqk_info` for RTL8852C: device-lifetime counters plus the
/// latest per-path results. `iqk_times`/`iqk_fail_cnt` persist across
/// channels (Linux zeroes them only at device allocation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Iqk {
    pub times: u8,
    pub fail_count: u32,
    pub paths: [Path; 2],
    pub channel: Option<Profile>,
    calibrated: bool,
}

impl<I: Interface> Access<'_, I> {
    /// `rtw8852c_rxck_force`.
    pub(super) fn c_rxck(&mut self, path: u8, force: bool, ck: u32) -> Result<(), Error> {
        let rxck = R_P0_RXCK | (u32::from(path) << 13);
        self.wm(rxck, B_P0_RXCK_ON, 0)?;
        if !force {
            return Ok(());
        }
        self.wm(rxck, B_P0_RXCK_VAL, ck)?;
        self.wm(rxck, B_P0_RXCK_ON, 1)?;
        let [ctl, en, bw0, bw1, mul, lp] = rxck_def(ck);
        let off = u32::from(path) << 8;
        self.wm(R_P0_CFCH_BW0 | off, B_P0_CFCH_CTL, ctl)?;
        self.wm(R_P0_CFCH_BW0 | off, B_P0_CFCH_EN, en)?;
        self.wm(R_P0_CFCH_BW0 | off, B_P0_CFCH_BW0, bw0)?;
        self.wm(R_P0_CFCH_BW1 | off, B_P0_CFCH_BW1, bw1)?;
        self.wm(R_DRCK | off, B_DRCK_MUL, mul)?;
        self.wm(R_ADCMOD | off, B_ADCMOD_LP, lp)
    }
    /// `rtw8852c_txck_force(path, true, ck)`.
    pub(super) fn c_txck_force(&mut self, path: u8, ck: u32) -> Result<(), Error> {
        let address = R_P0_RXCK | (u32::from(path) << 13);
        self.wm(address, B_P0_TXCK_ON, 0)?;
        self.wm(address, B_P0_TXCK_VAL, ck)?;
        self.wm(address, B_P0_TXCK_ON, 1)
    }
    /// `rtw8852c_disable_rxagc`.
    pub(super) fn c_rxagc(&mut self, path: u8, enable: u32) -> Result<(), Error> {
        let address = if path == 0 {
            R_P0_AGC_CTL
        } else {
            R_P1_AGC_CTL
        };
        self.wm(address, B_AGC_EN, enable)
    }
    /// `_iqk_check_cal`: poll 0xbff8 byte0 == 0x55 (1us step, 8200us),
    /// clear R_NCTL_N1 byte0, sample R_NCTL_RPT. Linux always returns
    /// "pass"; a timeout fails the attempt closed here.
    async fn c_iqk_check_cal(&mut self) -> Result<(), Error> {
        let start = self.0.now_us();
        while self.bb(0xbff8, 0xff)? != 0x55 {
            if self.0.now_us().saturating_sub(start) >= 8200 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(1).await?;
        }
        self.wm(R_NCTL_N1, 0xff, 0)?;
        self.bb(R_NCTL_RPT, u32::MAX)?;
        Ok(())
    }
    /// `_iqk_one_shot`.
    async fn c_iqk_one_shot(&mut self, path: u8, shot: Shot, bw: u32) -> Result<(), Error> {
        let rfc = R_UPD_CLK + (u32::from(path) << 13);
        let p = 1u32 << (4 + path);
        let (rfc_ctl, command) = match shot {
            Shot::AFlokCoarse => (1, 0x008 | p),
            Shot::GFlokCoarse => (1, 0x108 | p),
            Shot::AFlokFine => (1, 0x508 | p),
            Shot::GFlokFine => (1, 0x208 | p),
            Shot::FlokVbuffer => (1, 0x308 | p),
            Shot::Txk => (0, 0x008 | p | ((0x8 + bw) << 8)),
            Shot::Rxk => (1, 0x008 | p | ((0xc + bw) << 8)),
        };
        self.wm(rfc, 0x2, rfc_ctl)?;
        self.wm(R_NCTL_CFG, u32::MAX, command + 1)?;
        self.delay(15).await?;
        self.c_iqk_check_cal().await?;
        self.wm(rfc, 0x2, 0)
    }
    /// `_iqk_rxk_setting`.
    async fn c_iqk_rxk_setting(&mut self, path: u8, width: Width) -> Result<(), Error> {
        let fifo = if path == 0 { 0x0101 } else { 0x0202 };
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, fifo)?;
        // Linux `_iqk_rxk_setting` switches on 20/40/80/160 only; its
        // `default:` arm programs no RX clock / ACK / RXBB2 / NRBW
        // write, so 320MHz skips the middle block (the ADC FIFO writes
        // and the RXK config table still run).
        let setting = match width {
            Width::Mhz20 | Width::Mhz40 => Some((ADC_480M, 0)),
            Width::Mhz80 => Some((ADC_960M, 1)),
            Width::Mhz160 => Some((ADC_1920M, 2)),
            Width::Mhz320 => None,
        };
        if let Some((ck, ack)) = setting {
            let off = u32::from(path) << 13;
            self.wm(R_UPD_CLK + off, B_DPD_GDIS, 1)?;
            self.c_rxck(path, true, ck)?;
            self.wm(R_UPD_CLK + off, B_ACK_VAL, ack)?;
            self.wr(path, RR_RXBB2, RR_RXBB2_CKT, 1).await?;
            self.wm(R_P0_NRBW + off, B_P0_NRBW_DBG, 1)?;
        }
        self.table(&RXK_CFG).await?;
        let fifo = if path == 0 { 0x1101 } else { 0x2202 };
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, fifo)
    }
    /// The common prologue of `_rxk_group_sel` / `_iqk_nbrxk`; returns
    /// the RR_MOD_NBW backup.
    async fn c_rxk_enter(&mut self, path: u8, band: Band) -> Result<u32, Error> {
        let saved = self.rr(path, RR_MOD, RR_MOD_NBW).await?;
        if path == 1 {
            self.wr(1, RR_IQKPLL, RR_IQKPLL_MOD, 0x3).await?;
            let tmp = self.rr(1, RR_CHTR, RR_CHTR_MOD).await?;
            self.wr(1, RR_RSV4, RR_RSV4_AGH, tmp).await?;
            let tmp = self.rr(1, RR_CHTR, RR_CHTR_TXRX).await?;
            self.wr(1, RR_RSV4, RR_RSV4_PLLCH, tmp).await?;
        }
        self.wr(path, RR_MOD, RR_MOD_MASK, 0xc).await?;
        self.wr(path, RR_MOD, RR_MOD_NBW, 0).await?;
        match band {
            Band::Ghz2 => self.wr(path, RR_RXG, RR_RXG_IQKMOD, 0x9).await?,
            Band::Ghz5 => self.wr(path, RR_RXAE, RR_RXAE_IQKMOD, 0x8).await?,
            Band::Ghz6 => self.wr(path, RR_RXAE, RR_RXAE_IQKMOD, 0x9).await?,
        }
        self.delay(10).await?;
        Ok(saved)
    }
    /// `_rxk_group_sel` (wideband RX IQK over the four RX gain groups).
    async fn c_rxk_group_sel(
        &mut self,
        path: u8,
        channel: Profile,
        state: &mut Path,
    ) -> Result<(), Error> {
        let saved = self.c_rxk_enter(path, channel.band()).await?;
        let lut = R_CFIR_LUT + (u32::from(path) << 8);
        for gp in 0..4usize {
            let (gain, attc, (address, mask)) = match channel.band() {
                Band::Ghz2 => (RXK_G.0[gp], RXK_G.1[gp], (RR_RXBB, RR_RXBB_VOBUF)),
                Band::Ghz5 => (RXK_A.0[gp], RXK_A.1[gp], (RR_RXA2, RR_RXA2_IATT)),
                Band::Ghz6 => (RXK_A6.0[gp], RXK_A6.1[gp], (RR_RXA2, RR_RXA2_IATT)),
            };
            self.wr(path, RR_MOD, RR_MOD_M_RXG, gain).await?;
            self.wr(path, address, mask, attc).await?;
            self.wm(lut, B_CFIR_LUT_SEL, 1)?;
            self.wm(lut, B_CFIR_LUT_SET, 0)?;
            self.wm(lut, B_CFIR_LUT_GP_V1, gp as u32)?;
            self.c_iqk_one_shot(path, Shot::Rxk, channel.width() as u32)
                .await?;
        }
        if path == 1 {
            self.wr(path, RR_IQKPLL, RR_IQKPLL_MOD, 0).await?;
        }
        self.wr(path, RR_MOD, RR_MOD_NBW, saved).await?;
        // `fail` is always false (`_iqk_check_cal`).
        state.nb_rxcfir = 0x4000_0000;
        state.is_wb_rxiqk = true;
        state.rx_fail = false;
        Ok(())
    }
    /// `_txk_group_sel` (wideband TX IQK over the three TX gain groups).
    async fn c_txk_group_sel(
        &mut self,
        path: u8,
        channel: Profile,
        state: &mut Path,
    ) -> Result<(), Error> {
        let table = match channel.band() {
            Band::Ghz2 => &TXK_G,
            Band::Ghz5 => &TXK_A,
            Band::Ghz6 => &TXK_A6,
        };
        let off = u32::from(path) << 8;
        for (gp, &[range, track, gain, itqt]) in table.iter().enumerate() {
            self.wr(path, RR_TXIG, RR_TXIG_GR0, range).await?;
            self.wr(path, RR_TXIG, RR_TXIG_GR1, track).await?;
            self.wr(path, RR_TXIG, RR_TXIG_TG, gain).await?;
            self.wm(R_KIP_IQP + off, u32::MAX, itqt)?;
            self.wm(R_CFIR_LUT + off, B_CFIR_LUT_SEL, 1)?;
            self.wm(R_CFIR_LUT + off, B_CFIR_LUT_SET, 1)?;
            self.wm(R_CFIR_LUT + off, B_CFIR_LUT_G2, 0)?;
            self.wm(R_CFIR_LUT + off, B_CFIR_LUT_GP, gp as u32 + 1)?;
            self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x00b)?;
            self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
            self.c_iqk_one_shot(path, Shot::Txk, channel.width() as u32)
                .await?;
        }
        state.nb_txcfir = 0x4000_0000;
        state.is_wb_txiqk = true;
        state.tx_fail = false;
        Ok(())
    }
    /// `_iqk_lok` incl. `_lok_finetune_check` (table index 0).
    async fn c_iqk_lok(&mut self, path: u8, band: Band, state: &mut Path) -> Result<(), Error> {
        let iqp = R_KIP_IQP + (u32::from(path) << 8);
        let (coarse, fine) = if band == Band::Ghz2 {
            (Shot::GFlokCoarse, Shot::GFlokFine)
        } else {
            (Shot::AFlokCoarse, Shot::AFlokFine)
        };
        self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, IQK_DF4_TXT_8_25MHZ)?;
        for (tg, iqsw, shot) in [
            (0x6, 0x9, coarse),
            (0x12, 0x1b, Shot::FlokVbuffer),
            (0x6, 0x9, fine),
            (0x12, 0x1b, Shot::FlokVbuffer),
        ] {
            self.wr(path, RR_TXIG, RR_TXIG_TG, tg).await?;
            self.wm(iqp, B_KIP_IQP_IQSW, iqsw)?;
            self.c_iqk_one_shot(path, shot, 0).await?;
        }
        state.lok_cor_fail = false;
        state.lok_fin_fail = false;
        let field = |value: u32, mask: u32| (value & mask) >> mask.trailing_zeros();
        let idac = self.rr(path, RR_TXMO, RFREG_MASK).await?;
        let (ci, cq) = (field(idac, RR_TXMO_COI), field(idac, RR_TXMO_COQ));
        let fail1 = !(0x2..=0x1d).contains(&ci) || !(0x2..=0x1d).contains(&cq);
        state.lok_idac = idac;
        let vbuf = self.rr(path, RR_LOKVB, RFREG_MASK).await?;
        let (vi, vq) = (field(vbuf, RR_LOKVB_COI), field(vbuf, RR_LOKVB_COQ));
        let fail2 = !(0x2..=0x3d).contains(&vi) || !(0x2..=0x3d).contains(&vq);
        state.lok_vbuf = vbuf;
        state.lok_fail = fail1 || fail2;
        Ok(())
    }
    /// `_iqk_txk_setting` (`syn1to2` = 1 for non-DBCC).
    async fn c_iqk_txk_setting(&mut self, path: u8, band: Band) -> Result<(), Error> {
        if band == Band::Ghz2 {
            self.wr(path, RR_TXG1, RR_TXG1_ATT2, 0).await?;
            self.wr(path, RR_TXG1, RR_TXG1_ATT1, 0).await?;
            self.wr(path, RR_TXG2, RR_TXG2_ATT0, 1).await?;
        } else {
            self.wr(path, RR_TXATANK, RR_TXATANK_LBSW2, 0).await?;
            self.wr(path, RR_TXPOW, RR_TXPOW_TXAS, 1).await?;
        }
        self.wr(path, RR_TXA2, RR_TXA2_LDO, 0xf).await?;
        self.wr(path, RR_TXGA, RR_TXGA_LOK_EXT, 0).await?;
        self.wr(path, RR_LUTWE, RR_LUTWE_LOK, 1).await?;
        self.wr(path, RR_MOD, RFREG_MASK, 0x403e0 | 0x1).await?;
        self.delay(10).await?;
        self.wr(path, RR_TXIG, RR_TXIG_GR0, 0).await?;
        self.wr(path, RR_TXIG, RR_TXIG_GR1, 0x6).await
    }
    /// `_iqk_info_iqk`.
    fn c_iqk_info(&mut self, path: u8, iqk: &mut Iqk) -> Result<(), Error> {
        let p = usize::from(path);
        let shift = u32::from(path) * 4;
        let state = iqk.paths[p];
        self.wm(
            R_IQKINF,
            B_IQKINF_FCOR << shift,
            u32::from(state.lok_cor_fail),
        )?;
        self.wm(
            R_IQKINF,
            B_IQKINF_FFIN << shift,
            u32::from(state.lok_fin_fail),
        )?;
        self.wm(R_IQKINF, B_IQKINF_FTX << shift, u32::from(state.tx_fail))?;
        self.wm(R_IQKINF, B_IQKINF_F_RX << shift, u32::from(state.rx_fail))?;
        let off = u32::from(path) << 8;
        iqk.paths[p].iqk_enable = self.bb(R_IQK_RES + off, u32::MAX)?;
        iqk.paths[p].tx_result = self.bb(R_TXIQC + off, u32::MAX)?;
        iqk.paths[p].rx_result = self.bb(R_RXIQC + off, u32::MAX)?;
        self.wm(R_IQKINF2, B_IQKINF2_KCNT, u32::from(iqk.times))?;
        if self.bb(R_IQKINF, B_IQKINF_FAIL << shift)? != 0 {
            iqk.fail_count = iqk.fail_count.wrapping_add(1);
        }
        self.wm(R_IQKINF2, B_IQKINF2_FCNT << shift, iqk.fail_count)
    }
    /// `_iqk_restore`.
    async fn c_iqk_restore(&mut self, path: u8, state: &Path) -> Result<(), Error> {
        let off = u32::from(path) << 8;
        self.wm(R_TXIQC + off, u32::MAX, state.nb_txcfir)?;
        self.wm(R_RXIQC + off, u32::MAX, state.nb_rxcfir)?;
        self.wm(R_NCTL_CFG, u32::MAX, 0x0000_1219 + (u32::from(path) << 4))?;
        self.delay(200).await?;
        self.c_iqk_check_cal().await?;
        self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
        self.wm(R_NCTL_RPT, u32::MAX, 0)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x8000_0000)?;
        self.wr(path, RR_LUTWE, RR_LUTWE_LOK, 0).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 1).await
    }
    /// `_iqk_macbb_setting`.
    async fn c_iqk_macbb(&mut self, path: u8) -> Result<(), Error> {
        let upd = R_UPD_CLK | (u32::from(path) << 13);
        self.wr(path, RR_BBDC, RR_BBDC_SEL, 0).await?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A0 << path, 1)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A1 << path, 0)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A2 << path, 1)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A3 << path, 0)?;
        self.c_rxagc(path, 0)?;
        self.wm(upd, u32::MAX, 0xf801_fffd)?;
        self.wm(upd, B_DPD_DIS, 1)?;
        self.wm(upd, B_DAC_VAL, 1)?;
        self.c_txck_force(path, DAC_960M)?;
        self.wm(upd, B_DPD_GDIS, 1)?;
        self.c_rxck(path, true, ADC_1920M)?;
        self.wm(upd, B_ACK_VAL, 2)?;
        self.wm(R_P0_NRBW | (u32::from(path) << 13), B_P0_NRBW_DBG, 1)?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x1f)?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x13)?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0x0001)?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0x0041)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A1 << path, 1)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A3 << path, 1)
    }
    /// `_doiqk(path)` between the per-path ONESHOT notifications.
    async fn c_doiqk(&mut self, path: u8, channel: Profile, iqk: &mut Iqk) -> Result<(), Error> {
        let p = usize::from(path);
        iqk.times = iqk.times.wrapping_add(1);
        // `_iqk_get_ch_info` (`syn1to2` = 1).
        let shift = u32::from(path) * 16;
        self.wm(R_IQKINF, B_IQKINF_VER, RTW8852C_IQK_VER)?;
        self.wm(R_IQKCH, B_IQKCH_BAND << shift, channel.band() as u32)?;
        self.wm(R_IQKCH, B_IQKCH_BW << shift, channel.width() as u32)?;
        self.wm(R_IQKCH, B_IQKCH_CH << shift, u32::from(channel.center()))?;
        self.wm(R_IQKINF2, B_IQKINF2_NCTLV, RTW8852C_NCTL_VER)?;
        let mut bb = [0u32; 8];
        for (slot, &register) in bb.iter_mut().zip(BACKUP_BB.iter()) {
            *slot = self.bb(register, u32::MAX)?;
        }
        let mut rf = [0u32; 7];
        for (slot, &register) in rf.iter_mut().zip(BACKUP_RF.iter()) {
            *slot = self.rr(path, register, RFREG_MASK).await?;
        }
        self.c_iqk_macbb(path).await?;
        // `_iqk_preset` (table index 0).
        let off = u32::from(path) << 8;
        self.wm(R_COEF_SEL + off, B_COEF_SEL_IQC, 0)?;
        self.wm(R_CFIR_LUT + off, B_CFIR_LUT_G3, 0)?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wm(R_NCTL_RPT, u32::MAX, 0x0000_0080)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x81ff_010a)?;
        // `_iqk_by_path` (wideband).
        let mut state = Path::default();
        self.c_iqk_txk_setting(path, channel.band()).await?;
        self.c_iqk_lok(path, channel.band(), &mut state).await?;
        self.c_txk_group_sel(path, channel, &mut state).await?;
        self.c_iqk_rxk_setting(path, channel.width()).await?;
        self.c_rxk_group_sel(path, channel, &mut state).await?;
        iqk.paths[p] = state;
        self.c_iqk_info(path, iqk)?;
        self.c_iqk_restore(path, &state).await?;
        // `_iqk_afebb_restore`.
        self.table(&AFEBB_RESTORE[p]).await?;
        self.c_rxagc(path, 1)?;
        for (&value, &register) in bb.iter().zip(BACKUP_BB.iter()) {
            self.wm(register, u32::MAX, value)?;
        }
        for (&value, &register) in rf.iter().zip(BACKUP_RF.iter()) {
            self.wr(path, register, RFREG_MASK, value).await?;
        }
        Ok(())
    }
}

impl Iqk {
    /// Latest per-path results, only after a completed IQK without a LOK
    /// failure on either path.
    pub fn results(&self) -> Option<&[Path; 2]> {
        self.calibrated.then_some(&self.paths)
    }
    /// rtw8852c_rfk.c `rtw8852c_iqk(PHY_0)`: `BTC_WRFKT_IQK` START,
    /// `rtw89_chip_stop_sch_tx`, `_wait_rx_mode(RF_AB)` (2us step,
    /// 5000us), `_iqk_init` (R_IQKINF cleared), then `_doiqk` path A and
    /// path B, each between ONESHOT START/STOP, then resume and STOP.
    ///
    /// # Safety
    /// Actual RTL8852C PHY0 (non-DBCC) after `rfk::c::Init::prepare`, the
    /// BB/RF retune to THIS `channel` and its RX DCK; current admission
    /// (emission recipe, board policy, coexistence) is enforced by
    /// Interface at every access. No concurrent PHY/packet/reset/PM owner;
    /// the outer attempt closes and retains DMA on failure/cancellation.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
    ) -> Result<(), Error> {
        self.calibrated = false;
        self.channel = Some(channel);
        io.admit()?;
        io.begin(Kind::Iqk).await?;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        for path in 0..2 {
            let start = access.0.now_us();
            while access.rr(path, RR_MOD, RR_MOD_MASK).await? == 2 {
                if access.0.now_us().saturating_sub(start) >= 5000 {
                    return Err(power::Error::Timeout.into());
                }
                access.delay(2).await?;
            }
        }
        access.wm(R_IQKINF, u32::MAX, 0)?;
        for path in 0..2 {
            access.0.admit()?;
            access.0.begin(Kind::IqkPath).await?;
            access.c_doiqk(path, channel, self).await?;
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
