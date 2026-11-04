// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B channel IQK: rtw8851b_rfk.c `rtw8851b_iqk(PHY_0)` on RF path A
//! (`_kpath` = RF_A, `RTW8851B_IQK_SS` 1) for one typed B [`Profile`],
//! wideband as Linux `_iqk_init` leaves it (`is_nbiqk`, `iqk_sram_en`
//! false, so the `_iqk_{2g,5g}_nb{tx,rx}k` variants are unreachable and not
//! carried): `_doiqk` = `_rfk_backup_bb_reg`/`_rfk_backup_rf_reg`,
//! `_iqk_macbb_setting`, `_iqk_preset`, `_iqk_by_path` (`_iqk_txk_setting`,
//! `_iqk_{2g,5g}_lok`, `_txk_{2g,5g}_group_sel`, `_iqk_rxclk_setting`,
//! `_iqk_rxk_setting`, `_adc_fifo_rst`, `_rxk_{2g,5g}_group_sel` with the
//! `_iqk_sram` dump on an RX failure), `_iqk_restore`,
//! `_iqk_afebb_restore` and the BB/RF restore.
//!
//! Linux `_iqk_check_cal` only logs its two poll timeouts (and a not-ready
//! shot then skips the `B_NCTL_RPT_FLG` check); NARF fails the attempt
//! closed on any poll timeout instead. A `B_NCTL_RPT_FLG` group failure is
//! Linux's defined narrowband-CFIR fallback and is recorded, not refused.
//! Diagnostic-only reads inside `rtw89_debug` arguments are not issued.
use super::super::operating_channel::{Profile, Width};
use super::{power, Access, Entry, Error, Interface, Kind};

const RFREG_MASK: u32 = 0xfffff;
const RR_MOD: u32 = 0x00;
const RR_MOD_MASK: u32 = 0xf0000;
const RR_MOD_RGM: u32 = 0x3ff0;
const RR_RSV1: u32 = 0x05;
const RR_RSV1_RST: u32 = 1;
const RR_TXIG: u32 = 0x11;
const RR_TXIG_GR0: u32 = 0x3;
const RR_TXIG_GR1: u32 = 0x70;
const RR_TXIG_TG: u32 = 0x1_f000;
const RR_RXKPLL: u32 = 0x1e;
const RR_RXKPLL_OFF: u32 = 0x3f;
const RR_RXKPLL_POW: u32 = 1 << 19;
const RR_LUTWA: u32 = 0x33;
const RR_LUTWA_M1: u32 = 0xff;
const RR_LUTWD0: u32 = 0x3f;
const RR_BIASA: u32 = 0x60;
const RR_BIASA_A: u32 = 0x7;
const RR_RXBB: u32 = 0x83;
const RR_RXBB_C2: u32 = 0xf00;
const RR_RXA2: u32 = 0x8c;
const RR_RXA2_ATT: u32 = 0xf;
const RR_RXBB2: u32 = 0x8f;
const RR_RXBB2_CKT: u32 = 1 << 12;
const RR_LUTDBG: u32 = 0xdf;
const RR_LUTDBG_TIA: u32 = 1 << 12;
const RR_LUTDBG_LOK: u32 = 1 << 2;
const RR_LUTWE: u32 = 0xef;
const RR_LUTWE_LOK: u32 = 1 << 2;

const R_P0_RXCK: u32 = 0x12a0;
const B_P0_RXCK_ADJ: u32 = 0xff80_0000;
const B_P0_RXCK_ON: u32 = 1 << 19;
const B_P0_RXCK_VAL: u32 = 0x7_0000;
const B_P0_TXCK_ON: u32 = 1 << 15;
const B_P0_TXCK_VAL: u32 = 0x7000;
const R_ADC_FIFO: u32 = 0x20fc;
const B_ADC_FIFO_RXK: u32 = 0xffff_0000;
const R_UPD_CLK: u32 = 0x5670;
const B_IQK_RFC_ON: u32 = 1 << 1;
const B_DPD_GDIS: u32 = 1 << 13;
const R_NCTL_CFG: u32 = 0x8000;
const R_NCTL_RPT: u32 = 0x8008;
const B_NCTL_RPT_FLG: u32 = 1 << 26;
const R_NCTL_N1: u32 = 0x8010;
const B_NCTL_N1_CIP: u32 = 0xff;
const R_IQK_DIF2: u32 = 0x8024;
const B_IQK_DIF2_RXPI: u32 = 0xf_ffff;
const R_IQK_DIF4: u32 = 0x802c;
const B_IQK_DIF4_RXT: u32 = 0x0fff_0000;
const B_IQK_DIF4_TXT: u32 = 0xfff;
const R_IQK_RXA: u32 = 0x8044;
const B_IQK_RXAGC: u32 = 0xe000;
const R_MDPK_RX_DCK: u32 = 0x8074;
const R_KIP_SYSCFG: u32 = 0x8088;
const R_KIP_RPT1: u32 = 0x80d4;
const R_SRAM_IQRX: u32 = 0x80d8;
const R_SRAM_IQRX2: u32 = 0x80e8;
const R_RPT_COM: u32 = 0x80fc;
const B_RPT_COM_RDY: u32 = 0xffff;
const B_PRT_COM_DCI: u32 = 0x0fff_0000;
const B_PRT_COM_DCQ: u32 = 0xfff;
const R_CFIR_COEF: u32 = 0x810c;
const R_IQK_RES: u32 = 0x8124;
const B_IQK_RES_RXCFIR: u32 = 0xf;
const R_TXIQC: u32 = 0x8138;
const R_RXIQC: u32 = 0x813c;
const R_CFIR_LUT: u32 = 0x8154;
const B_CFIR_LUT_SEL: u32 = 1 << 8;
const B_CFIR_LUT_G3: u32 = 1 << 3;
const B_CFIR_LUT_G2: u32 = 1 << 2;
const B_CFIR_LUT_GP_V1: u32 = 0x7;
const B_CFIR_LUT_GP: u32 = 0x3;
const R_KIP_IQP: u32 = 0x81cc;
const B_KIP_IQP_IQSW: u32 = 0x3f;
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

/// `RTW8851B_IQK_VER`.
const RTW8851B_IQK_VER: u8 = 0x14;
/// `enum adc_ck` / `enum dac_ck` values used here.
const ADC_960M: u32 = 2;
const ADC_1920M: u32 = 3;
const DAC_960M: u32 = 7;

/// `rtw8851b_backup_bb_regs` / `rtw8851b_backup_rf_regs`.
const BACKUP_BB: [u32; 7] = [0xc0d4, 0xc0d8, 0xc0c4, 0xc0ec, 0xc0e8, 0x12a0, 0xc0f0];
const BACKUP_RF: [u32; 8] = [0xef, 0xde, 0x0, 0x1e, 0x2, 0x85, 0x90, 0x5];

/// `g_idxrxgain` / `g_idxattc2` / `g_idxrxagc` (RTW8851B_RXK_GROUP_NR 4).
const G_RXK: [[u32; 3]; 4] = [
    [0x10e, 0x0, 0x0],
    [0x116, 0xf, 0x1],
    [0x28e, 0x0, 0x2],
    [0x296, 0xf, 0x3],
];
/// `a_idxrxgain` / `a_idxattc2` / `a_idxrxagc` (RTW8851B_RXK_GROUP_IDX_NR 4).
const A_RXK: [[u32; 3]; 4] = [
    [0x10c, 0xf, 0x4],
    [0x112, 0xf, 0x5],
    [0x28c, 0xf, 0x6],
    [0x292, 0xf, 0x7],
];
/// `a_power_range` / `a_track_range` / `a_gain_bb` / `a_itqt` /
/// `a_att_smxr` and `_txk_5g_group_sel`'s `a_idx` (A_TXK_GROUP_NR 2).
const A_TXK: [[u32; 6]; 2] = [
    [0x0, 0x7, 0x08, 0x12, 0x0, 2],
    [0x0, 0x7, 0x0d, 0x12, 0x2, 3],
];
/// `g_power_range` / `g_track_range` / `g_gain_bb` / `g_itqt`
/// (G_TXK_GROUP_NR 1).
const G_TXK: [[u32; 4]; 1] = [[0x0, 0x6, 0x10, 0x12]];
/// `_iqk_2g_lok` `g_txbb` / `g_itqt` / `g_wa` (RTW8851B_LOK_GRAM 10).
const G_LOK: [[u32; 10]; 3] = [
    [0x02, 0x06, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x17],
    [0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x12, 0x12, 0x12, 0x1b],
    [0x00, 0x04, 0x08, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x17],
];
/// `_iqk_5g_lok` `a_txbb` / `a_itqt` / `a_wa`.
const A_LOK: [[u32; 10]; 3] = [
    [0x02, 0x06, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x17],
    [0x09, 0x09, 0x09, 0x12, 0x12, 0x12, 0x1b, 0x1b, 0x1b, 0x1b],
    [0x80, 0x84, 0x88, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x97],
];

const fn wm(address: u32, mask: u32, value: u32) -> Entry {
    Entry(1, 0, address, mask, value)
}
const fn wrf(address: u32, mask: u32, value: u32) -> Entry {
    Entry(0, 0, address, mask, value)
}
const fn delay(us: u32) -> Entry {
    Entry(4, 0, 0, 0, us)
}
/// rtw8851b_rfk_table.c `rtw8851b_iqk_rxclk_80_defs`.
const RXCLK_80: [Entry; 8] = [
    wm(0x5670, 0x6000_0000, 0x1),
    wm(0xc0ec, 0x0000_6000, 0x0),
    wm(0x12b8, 0x4000_0000, 0x1),
    wm(0x030c, 0xff00_0000, 0x0f),
    wm(0x030c, 0xff00_0000, 0x03),
    wm(0x032c, 0xffff_0000, 0x0001),
    wm(0x032c, 0xffff_0000, 0x0041),
    wm(0x20fc, 0xffff_0000, 0x1101),
];
/// `rtw8851b_iqk_rxclk_others_defs`.
const RXCLK_OTHERS: [Entry; 8] = [
    wm(0x5670, 0x6000_0000, 0x0),
    wm(0xc0ec, 0x0000_6000, 0x2),
    wm(0x12b8, 0x4000_0000, 0x1),
    wm(0x030c, 0xff00_0000, 0x0f),
    wm(0x030c, 0xff00_0000, 0x03),
    wm(0x032c, 0xffff_0000, 0x0001),
    wm(0x032c, 0xffff_0000, 0x0041),
    wm(0x20fc, 0xffff_0000, 0x1101),
];
/// `rtw8851b_iqk_txk_2ghz_defs`.
const TXK_2GHZ: [Entry; 10] = [
    wrf(0x51, 0x80000, 0x0),
    wrf(0x51, 0x00800, 0x0),
    wrf(0x52, 0x00800, 0x0),
    wrf(0x55, 0x0001f, 0x4),
    wrf(0xef, 0x00004, 0x1),
    wrf(0x00, 0xffff0, 0x403e),
    wrf(0x11, 0x00003, 0x0),
    wrf(0x11, 0x00070, 0x6),
    wrf(0x11, 0x1f000, 0x10),
    delay(1),
];
/// `rtw8851b_iqk_txk_5ghz_defs`.
const TXK_5GHZ: [Entry; 8] = [
    wrf(0x60, 0x00007, 0x0),
    wrf(0x55, 0x0001f, 0x4),
    wrf(0xef, 0x00004, 0x1),
    wrf(0x00, 0xffff0, 0x403e),
    wrf(0x11, 0x00003, 0x0),
    wrf(0x11, 0x00070, 0x7),
    wrf(0x11, 0x1f000, 0x7),
    delay(1),
];
/// `rtw8851b_iqk_afebb_restore_defs`.
const AFEBB_RESTORE: [Entry; 10] = [
    wm(0x12b8, 0x4000_0000, 0x0),
    wm(0x20fc, 0x0001_0000, 0x1),
    wm(0x20fc, 0x0010_0000, 0x0),
    wm(0x20fc, 0x0100_0000, 0x1),
    wm(0x20fc, 0x1000_0000, 0x0),
    wm(0x5670, u32::MAX, 0x0000_0000),
    wm(0x12a0, 0x000f_f000, 0x00),
    wm(0x20fc, 0x0001_0000, 0x0),
    wm(0x20fc, 0x0100_0000, 0x0),
    wrf(0x10005, 0x00001, 0x1),
];
/// `rtw8851b_iqk_macbb_defs`.
const MACBB: [Entry; 8] = [
    wrf(0x10005, 0x00001, 0x0),
    wm(0x20fc, 0x0001_0000, 0x1),
    wm(0x20fc, 0x0010_0000, 0x0),
    wm(0x20fc, 0x0100_0000, 0x1),
    wm(0x20fc, 0x1000_0000, 0x0),
    wm(0x5670, u32::MAX, 0xf801_fffd),
    wm(0x5670, 0x0000_4000, 0x1),
    wm(0x5670, 0x8000_0000, 0x1),
];
/// `rtw8851b_iqk_macbb_bh_defs`.
const MACBB_BH: [Entry; 23] = [
    wm(0x5670, 0x6000_0000, 0x2),
    wm(0x12b8, 0x4000_0000, 0x1),
    delay(2),
    wm(0x030c, 0xff00_0000, 0x1f),
    delay(10),
    wm(0x030c, 0xff00_0000, 0x13),
    delay(2),
    wm(0x032c, 0xffff_0000, 0x0001),
    delay(2),
    wm(0x032c, 0xffff_0000, 0x0041),
    delay(10),
    wm(0x12b8, 0x4000_0000, 0x1),
    delay(2),
    wm(0x030c, 0xff00_0000, 0x1f),
    delay(10),
    wm(0x030c, 0xff00_0000, 0x13),
    delay(2),
    wm(0x032c, 0xffff_0000, 0x0001),
    delay(2),
    wm(0x032c, 0xffff_0000, 0x0041),
    delay(10),
    wm(0x20fc, 0x0010_0000, 0x1),
    wm(0x20fc, 0x1000_0000, 0x1),
];

/// `enum rtw8851b_iqk_type` one-shot commands reached by the wideband flow.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shot {
    Txk,
    Rxagc,
    Rxk,
    Nbtxk,
    Nbrxk,
}

/// Path-A `rtw89_iqk_info` fields of one RTL8851B IQK.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Path {
    /// `_iqk_{2g,5g}_lok` result (only a poll timeout, which fails closed).
    pub lok_fail: bool,
    /// `iqk_tx_fail[0][A]` / `iqk_rx_fail[0][A]`: `B_NCTL_RPT_FLG` after the
    /// last group shot; true selects the narrowband CFIR fallback.
    pub tx_fail: bool,
    pub rx_fail: bool,
    pub nb_txcfir: u32,
    pub nb_rxcfir: u32,
    /// Linux `_rxk_*_group_sel` writes `is_wb_txiqk` (not `is_wb_rxiqk`);
    /// retained as written.
    pub is_wb_txiqk: bool,
    pub is_wb_rxiqk: bool,
}

/// RTL8851B `rtw89_iqk_info`: `iqk_times` persists across channels
/// (`_iqk_init` runs once per device).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Iqk {
    pub times: u8,
    /// `iqk_info->version`.
    pub version: u8,
    pub path: Path,
    pub channel: Option<Profile>,
    calibrated: bool,
}

impl<I: Interface> Access<'_, I> {
    /// `_txck_force(A, true, ck)`.
    pub(super) fn n51_txck_force(&mut self, ck: u32) -> Result<(), Error> {
        self.wm(R_P0_RXCK, B_P0_TXCK_ON, 0)?;
        self.wm(R_P0_RXCK, B_P0_TXCK_VAL, ck)?;
        self.wm(R_P0_RXCK, B_P0_TXCK_ON, 1)
    }
    /// `_rxck_force(A, true, ck)` with the 8851B `ck960_8851b` /
    /// `ck1920_8851b` rows.
    pub(super) fn n51_rxck_force(&mut self, ck: u32) -> Result<(), Error> {
        let data: [u32; 7] = if ck == ADC_960M {
            [0x8, 0x2, 0x2, 0x4, 0xf, 0xa, 0x92]
        } else {
            [0x9, 0x0, 0x0, 0x3, 0xf, 0xa, 0x49]
        };
        self.wm(R_P0_RXCK, B_P0_RXCK_ON, 0)?;
        self.wm(R_P0_RXCK, B_P0_RXCK_VAL, ck)?;
        self.wm(R_P0_RXCK, B_P0_RXCK_ON, 1)?;
        self.wm(R_P0_CFCH_BW0, B_P0_CFCH_CTL, data[0])?;
        self.wm(R_P0_CFCH_BW0, B_P0_CFCH_EN, data[1])?;
        self.wm(R_P0_CFCH_BW0, B_P0_CFCH_BW0, data[2])?;
        self.wm(R_P0_CFCH_BW1, B_P0_CFCH_BW1, data[3])?;
        self.wm(R_DRCK, B_DRCK_MUL, data[4])?;
        self.wm(R_ADCMOD, B_ADCMOD_LP, data[5])?;
        self.wm(R_P0_RXCK, B_P0_RXCK_ADJ, data[6])
    }
    /// `read_poll_timeout_atomic(rtw89_phy_read32_mask, val == want, step,
    /// budget)`.
    pub(super) async fn n51_poll_eq(
        &mut self,
        address: u32,
        mask: u32,
        want: u32,
        step: u64,
        budget: u64,
    ) -> Result<(), Error> {
        let start = self.0.now_us();
        loop {
            if self.bb(address, mask)? == want {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= budget {
                return Err(power::Error::Timeout.into());
            }
            self.delay(step).await?;
        }
    }
    /// `_iqk_check_cal`: 0xbff8 byte0 == 0x55 (10us/8200us), 10us,
    /// `R_RPT_COM` [15:0] == 0x8000 (10us/200us), 10us, clear N1 byte0.
    async fn n51_check_cal(&mut self) -> Result<(), Error> {
        self.n51_poll_eq(0xbff8, 0xff, 0x55, 10, 8200).await?;
        self.delay(10).await?;
        self.n51_poll_eq(R_RPT_COM, B_RPT_COM_RDY, 0x8000, 10, 200)
            .await?;
        self.delay(10).await?;
        self.wm(R_NCTL_N1, 0xff, 0)
    }
    /// `_iqk_one_shot(A, ktype)` (`iqk_sram_en` false); `bw` is
    /// `iqk_bw[A]`.
    async fn n51_one_shot(&mut self, shot: Shot, bw: u32) -> Result<(), Error> {
        let p = 1 << 4;
        let command = match shot {
            Shot::Txk => {
                self.wm(R_UPD_CLK, B_IQK_RFC_ON, 0)?;
                0x008 | p | (((0x8 + bw) & 0xf) << 8)
            }
            Shot::Rxagc => {
                self.wm(R_UPD_CLK, B_IQK_RFC_ON, 1)?;
                0x708 | p
            }
            Shot::Rxk => {
                self.wm(R_UPD_CLK, B_IQK_RFC_ON, 1)?;
                0x008 | p | (((0xc + bw) & 0xf) << 8)
            }
            Shot::Nbtxk => {
                self.wm(R_UPD_CLK, B_IQK_RFC_ON, 0)?;
                self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x11)?;
                0x408 | p
            }
            Shot::Nbrxk => {
                self.wm(R_UPD_CLK, B_IQK_RFC_ON, 1)?;
                self.wm(R_IQK_DIF4, B_IQK_DIF4_RXT, 0x011)?;
                0x608 | p
            }
        };
        self.wm(R_NCTL_CFG, u32::MAX, command + 1)?;
        self.n51_check_cal().await?;
        self.wm(R_UPD_CLK, B_IQK_RFC_ON, 0)
    }
    /// `_iqk_sram(A)`: the 0x00..=0x9f DCI then DCQ readout.
    fn n51_iqk_sram(&mut self) -> Result<(), Error> {
        self.wm(R_KIP_RPT1, u32::MAX, 0x0002_0000)?;
        self.wm(R_MDPK_RX_DCK, u32::MAX, 0x8000_0000)?;
        self.wm(R_SRAM_IQRX2, u32::MAX, 0x0000_0080)?;
        self.wm(R_SRAM_IQRX, u32::MAX, 0x0001_0000)?;
        self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x009)?;
        for mask in [B_PRT_COM_DCI, B_PRT_COM_DCQ] {
            for i in 0..=0x9f {
                self.wm(R_SRAM_IQRX, u32::MAX, 0x0001_0000 + i)?;
                self.bb(R_RPT_COM, mask)?;
            }
        }
        self.wm(R_SRAM_IQRX2, u32::MAX, 0)?;
        self.wm(R_SRAM_IQRX, u32::MAX, 0)
    }
    /// `_iqk_{2g,5g}_lok`.
    async fn n51_lok(&mut self, a_band: bool) -> Result<bool, Error> {
        let table = if a_band { &A_LOK } else { &G_LOK };
        self.wr(0, RR_LUTDBG, RR_LUTDBG_LOK, 0).await?;
        self.wr(0, RR_TXIG, RR_TXIG_GR0, 0).await?;
        self.wr(0, RR_TXIG, RR_TXIG_GR1, if a_band { 0x7 } else { 0x6 })
            .await?;
        let [txbbs, itqts, was] = table;
        for ((&txbb, &itqt), &wa) in txbbs.iter().zip(itqts).zip(was) {
            self.wr(0, RR_TXIG, RR_TXIG_TG, txbb).await?;
            self.wr(0, RR_LUTWA, RR_LUTWA_M1, wa).await?;
            self.wm(R_UPD_CLK, B_IQK_RFC_ON, 1)?;
            self.wm(R_KIP_IQP, B_KIP_IQP_IQSW, itqt)?;
            self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x021)?;
            self.wm(R_NCTL_CFG, u32::MAX, 0x0000_0109 | (1 << 4))?;
            self.n51_check_cal().await?;
            self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
            self.wm(R_KIP_IQP, B_KIP_IQP_IQSW, itqt)?;
            if a_band {
                self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x021)?;
            }
            self.wm(R_NCTL_CFG, u32::MAX, 0x0000_0309 | (1 << 4))?;
            self.n51_check_cal().await?;
            self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
            self.wm(R_UPD_CLK, B_IQK_RFC_ON, 0)?;
        }
        // Each `_iqk_check_cal` timeout failed closed above.
        Ok(false)
    }
    /// The common `kfail` tail of the TX group selections.
    fn n51_txk_tail(&mut self, state: &mut Path) -> Result<(), Error> {
        let kfail = self.bb(R_NCTL_RPT, B_NCTL_RPT_FLG)? != 0;
        if kfail {
            self.wm(R_TXIQC, u32::MAX, state.nb_txcfir | 0x2)?;
        } else {
            self.wm(R_TXIQC, u32::MAX, 0x4000_0000)?;
        }
        state.is_wb_txiqk = !kfail;
        state.tx_fail = kfail;
        Ok(())
    }
    /// `_txk_5g_group_sel`.
    async fn n51_txk_5g(&mut self, bw: u32, state: &mut Path) -> Result<(), Error> {
        self.wm(R_CFIR_COEF, u32::MAX, 0x3333_2222)?;
        for &[range, track, gain, itqt, smxr, idx] in A_TXK.iter() {
            self.wr(0, RR_TXIG, RR_TXIG_GR0, range).await?;
            self.wr(0, RR_TXIG, RR_TXIG_GR1, track).await?;
            self.wr(0, RR_TXIG, RR_TXIG_TG, gain).await?;
            self.wr(0, RR_BIASA, RR_BIASA_A, smxr).await?;
            self.wm(R_CFIR_LUT, B_CFIR_LUT_SEL, 1)?;
            self.wm(R_CFIR_LUT, B_CFIR_LUT_G3, 1)?;
            self.wm(R_CFIR_LUT, B_CFIR_LUT_G2, 0)?;
            self.wm(R_CFIR_LUT, B_CFIR_LUT_GP, idx)?;
            self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
            self.wm(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x11)?;
            self.wm(R_KIP_IQP, u32::MAX, itqt)?;
            self.n51_one_shot(Shot::Nbtxk, bw).await?;
            state.nb_txcfir = self.bb(R_TXIQC, u32::MAX)? | 0x2;
            self.wm(R_KIP_IQP, u32::MAX, itqt)?;
            self.n51_one_shot(Shot::Txk, bw).await?;
        }
        self.n51_txk_tail(state)
    }
    /// `_txk_2g_group_sel`.
    async fn n51_txk_2g(&mut self, bw: u32, state: &mut Path) -> Result<(), Error> {
        self.wm(R_CFIR_COEF, u32::MAX, 0)?;
        for (gp, &[range, track, gain, itqt]) in G_TXK.iter().enumerate() {
            self.wr(0, RR_TXIG, RR_TXIG_GR0, range).await?;
            self.wr(0, RR_TXIG, RR_TXIG_GR1, track).await?;
            self.wr(0, RR_TXIG, RR_TXIG_TG, gain).await?;
            self.wm(R_KIP_IQP, u32::MAX, itqt)?;
            self.wm(R_CFIR_LUT, B_CFIR_LUT_SEL, 1)?;
            self.wm(R_CFIR_LUT, B_CFIR_LUT_G3, 1)?;
            self.wm(R_CFIR_LUT, B_CFIR_LUT_G2, 0)?;
            self.wm(R_CFIR_LUT, B_CFIR_LUT_GP, gp as u32)?;
            self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
            self.n51_one_shot(Shot::Nbtxk, bw).await?;
            state.nb_txcfir = self.bb(R_TXIQC, u32::MAX)? | 0x2;
            self.wm(R_KIP_IQP, u32::MAX, itqt)?;
            self.n51_one_shot(Shot::Txk, bw).await?;
        }
        self.n51_txk_tail(state)
    }
    /// `_iqk_rxclk_setting` (80MHz vs other `rxclk` tables).
    async fn n51_rxclk(&mut self, width: Width) -> Result<(), Error> {
        self.wr(0, RR_RXBB2, RR_RXBB2_CKT, 1).await?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, 0x0101)?;
        self.wm(R_UPD_CLK, B_DPD_GDIS, 1)?;
        self.n51_rxck_force(ADC_960M)?;
        self.table(if width == Width::Mhz80 {
            &RXCLK_80
        } else {
            &RXCLK_OTHERS
        })
        .await
    }
    /// `_5g_group_sel` / `_5g_nbrxk` LUT bracket on RF path A.
    async fn n51_rxk_5g_lut(&mut self, first: u32) -> Result<(), Error> {
        self.wr(0, RR_LUTWE, RFREG_MASK, 0x1000).await?;
        self.wr(0, RR_LUTWA, RFREG_MASK, 0x4).await?;
        self.wr(0, RR_LUTWD0, RFREG_MASK, first).await?;
        self.wr(0, RR_LUTWA, RFREG_MASK, 0x5).await?;
        self.wr(0, RR_LUTWD0, RFREG_MASK, 0x27).await?;
        self.wr(0, RR_LUTWE, RFREG_MASK, 0x0).await
    }
    /// One `_rxk_{2g,5g}_group_sel` group: RXAGC, NBRXK, then WB RXK.
    async fn n51_rxk_group(
        &mut self,
        gp: u32,
        rxagc: u32,
        settle: u64,
        bw: u32,
        state: &mut Path,
    ) -> Result<(), Error> {
        self.wm(R_CFIR_LUT, B_CFIR_LUT_SEL, 1)?;
        self.wm(R_CFIR_LUT, B_CFIR_LUT_G3, 0)?;
        self.wm(R_CFIR_LUT, B_CFIR_LUT_GP_V1, gp)?;
        self.wr(0, RR_RXKPLL, RFREG_MASK, 0x80013).await?;
        self.delay(settle).await?;
        let rf_0 = self.rr(0, RR_MOD, RFREG_MASK).await?;
        self.wm(R_IQK_DIF2, B_IQK_DIF2_RXPI, rf_0)?;
        self.wm(R_IQK_RXA, B_IQK_RXAGC, rxagc)?;
        self.wm(R_IQK_DIF4, B_IQK_DIF4_RXT, 0x11)?;
        self.n51_one_shot(Shot::Rxagc, bw).await?;
        self.wr(0, RR_RXKPLL, RR_RXKPLL_OFF, 0x13).await?;
        self.wm(R_IQK_DIF4, B_IQK_DIF4_RXT, 0x011)?;
        self.n51_one_shot(Shot::Nbrxk, bw).await?;
        state.nb_rxcfir = self.bb(R_RXIQC, u32::MAX)? | 0x2;
        self.n51_one_shot(Shot::Rxk, bw).await
    }
    /// `_rxk_2g_group_sel` / `_rxk_5g_group_sel`.
    async fn n51_rxk(&mut self, a_band: bool, bw: u32, state: &mut Path) -> Result<(), Error> {
        let mut saved = 0;
        if a_band {
            self.n51_rxk_5g_lut(0x17).await?;
            saved = self.rr(0, RR_RXA2, 0x20).await?;
            self.wr(0, RR_MOD, RR_MOD_MASK, 0xc).await?;
        }
        for gp in 0..4usize {
            if a_band {
                let [gain, attc, rxagc] = A_RXK[gp];
                self.wr(0, RR_MOD, RR_MOD_RGM, gain).await?;
                self.wr(0, RR_RXA2, RR_RXA2_ATT, attc).await?;
                self.wr(0, RR_RXA2, 0x20, 0x1).await?;
                self.n51_rxk_group(gp as u32, rxagc, 100, bw, state).await?;
            } else {
                let [gain, attc, rxagc] = G_RXK[gp];
                self.wr(0, RR_MOD, RR_MOD_RGM, gain).await?;
                self.wr(0, RR_RXBB, RR_RXBB_C2, attc).await?;
                self.n51_rxk_group(gp as u32, rxagc, 10, bw, state).await?;
            }
        }
        let kfail = self.bb(R_NCTL_RPT, B_NCTL_RPT_FLG)? != 0;
        if kfail {
            self.n51_iqk_sram()?;
            if a_band {
                self.wm(R_IQK_RES, B_IQK_RES_RXCFIR, 0)?;
            }
            self.wm(R_RXIQC, u32::MAX, state.nb_rxcfir | 0x2)?;
        } else {
            self.wm(R_RXIQC, u32::MAX, 0x4000_0000)?;
        }
        state.is_wb_txiqk = !kfail;
        state.rx_fail = kfail;
        if a_band {
            self.wr(0, RR_RXA2, 0x20, saved).await?;
            self.n51_rxk_5g_lut(0x37).await?;
        }
        Ok(())
    }
    /// `_iqk_by_path(A)` (wideband, `IQK_LOK_RETRY` 1).
    async fn n51_iqk_by_path(&mut self, channel: Profile, state: &mut Path) -> Result<(), Error> {
        let a_band = channel.is_5ghz();
        let bw = channel.width() as u32;
        self.table(if a_band { &TXK_5GHZ } else { &TXK_2GHZ })
            .await?;
        state.lok_fail = self.n51_lok(a_band).await?;
        if a_band {
            self.n51_txk_5g(bw, state).await?;
        } else {
            self.n51_txk_2g(bw, state).await?;
        }
        self.n51_rxclk(channel.width()).await?;
        // `_iqk_rxk_setting`.
        self.wr(0, RR_MOD, RR_MOD_MASK, 0xc).await?;
        self.wr(0, RR_RXKPLL, RR_RXKPLL_POW, 0x0).await?;
        self.wr(0, RR_RXKPLL, RR_RXKPLL_POW, 0x1).await?;
        // `_adc_fifo_rst`.
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, 0x0101)?;
        self.delay(10).await?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_RXK, 0x1111)?;
        self.n51_rxk(a_band, bw, state).await
    }
    /// `_doiqk(A)` between the ONESHOT START/STOP notifications.
    async fn n51_doiqk(&mut self, channel: Profile, iqk: &mut Iqk) -> Result<(), Error> {
        iqk.times = iqk.times.wrapping_add(1);
        iqk.version = RTW8851B_IQK_VER;
        // `_iqk_get_ch_info` has no register writes on RTL8851B.
        iqk.channel = Some(channel);
        let mut bb = [0u32; BACKUP_BB.len()];
        for (slot, &register) in bb.iter_mut().zip(BACKUP_BB.iter()) {
            *slot = self.bb(register, u32::MAX)?;
        }
        let mut rf = [0u32; BACKUP_RF.len()];
        for (slot, &register) in rf.iter_mut().zip(BACKUP_RF.iter()) {
            *slot = self.rr(0, register, RFREG_MASK).await?;
        }
        // `_iqk_macbb_setting`.
        self.table(&MACBB).await?;
        self.n51_txck_force(DAC_960M)?;
        self.wm(R_UPD_CLK, B_DPD_GDIS, 1)?;
        self.n51_rxck_force(ADC_1920M)?;
        self.table(&MACBB_BH).await?;
        // `_iqk_preset`.
        self.wr(0, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wm(R_NCTL_RPT, u32::MAX, 0x0000_0080)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x81ff_010a)?;
        let mut state = Path::default();
        self.n51_iqk_by_path(channel, &mut state).await?;
        iqk.path = state;
        // `_iqk_restore`.
        self.wm(R_NCTL_CFG, u32::MAX, 0x0000_1219)?;
        self.delay(10).await?;
        self.n51_check_cal().await?;
        self.wr(0, RR_LUTWE, RR_LUTWE_LOK, 0).await?;
        self.wr(0, RR_LUTDBG, RR_LUTDBG_TIA, 0).await?;
        self.wm(R_NCTL_N1, B_NCTL_N1_CIP, 0)?;
        self.wm(R_NCTL_RPT, u32::MAX, 0)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x8000_0000)?;
        self.table(&AFEBB_RESTORE).await?;
        for (&value, &register) in bb.iter().zip(BACKUP_BB.iter()) {
            self.wm(register, u32::MAX, value)?;
        }
        for (&value, &register) in rf.iter().zip(BACKUP_RF.iter()) {
            self.wr(0, register, RFREG_MASK, value).await?;
        }
        Ok(())
    }
}

impl Iqk {
    /// Latest path-A result, only after a completed IQK.
    pub fn results(&self) -> Option<&Path> {
        self.calibrated.then_some(&self.path)
    }
    /// rtw8851b_rfk.c `rtw8851b_iqk(PHY_0)`: `BTC_WRFKT_IQK` START,
    /// `rtw89_chip_stop_sch_tx`, `_wait_rx_mode(RF_A)` (2us/5000us),
    /// `_iqk_init`, `_doiqk(A)` between ONESHOT START/STOP, resume, STOP.
    /// 160MHz (unsupported by RTL8851B) is refused before any access.
    ///
    /// # Safety
    /// Actual RTL8851B PHY_0 after `n51::Init::prepare`, the BB/RF program
    /// for THIS `channel` and its RX DCK; current admission is enforced by
    /// Interface at every access. No concurrent PHY/packet/reset/PM owner;
    /// the outer attempt closes and retains DMA on failure/cancellation.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
    ) -> Result<(), Error> {
        self.calibrated = false;
        if channel.width() == Width::Mhz160 {
            return Err(Error::Policy);
        }
        io.admit()?;
        io.begin(Kind::Iqk).await?;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        let start = access.0.now_us();
        while access.rr(0, RR_MOD, RR_MOD_MASK).await? == 2 {
            if access.0.now_us().saturating_sub(start) >= 5000 {
                return Err(power::Error::Timeout.into());
            }
            access.delay(2).await?;
        }
        access.0.admit()?;
        access.0.begin(Kind::IqkPath).await?;
        access.n51_doiqk(channel, self).await?;
        access.0.admit()?;
        access.0.end(Kind::IqkPath).await?;
        access.0.admit()?;
        access.0.resume(saved).await?;
        access.0.admit()?;
        access.0.end(Kind::Iqk).await?;
        self.calibrated = true;
        Ok(())
    }
}
