// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B `rtw8851b_rfk_init` (rtw8851b.c) and the per-channel RX DCK of
//! `rtw8851b_rfk_channel`, from rtw8851b_rfk.c for the single RF path A
//! (`_kpath` = RF_A): `rtw8851b_lck_init`, `rtw8851b_dpk_init`
//! (`rtw8851b_by_rate_dpd`), `rtw8851b_aack`, `rtw8851b_rck`,
//! `rtw8851b_dack` (`_dac_cal`: DRCK, ADDCK, S0 DACK with MSBK backup and
//! reload, `_new_dadck`) and `rtw8851b_rx_dck` (BTC RXDCK START, TX pause,
//! `_wait_rx_mode`, `_rx_dck` with `_rxbb_ofst_swap`, resume, STOP). Linux
//! only logs the AACK/RCK/DRCK/ADDCK/DADCK/DACK/RX DCK poll timeouts; NARF
//! fails the attempt closed instead. Linux `rtw8851b_dack` has no BTC DACK
//! notification, so none is emitted.
use super::{power, Access, Entry, Error, Interface, Kind, State};

// RF registers/fields (reg.h).
const RFREG_MASK: u32 = 0xfffff;
const RR_MOD: u32 = 0x00;
const RR_MOD_MASK: u32 = 0xf0000;
/// rtw8851b_rfk.c `enum rf_mode` RF_RX (= RR_MOD_V_RX).
const RF_RX: u32 = 0x3;
const RR_RSV1: u32 = 0x05;
const RR_RSV1_RST: u32 = 1;
const RR_RCKC: u32 = 0x1b;
const RR_RCKC_CA: u32 = 0x7c00;
const RR_RCKS: u32 = 0x1c;
const RR_LCK_TRG: u32 = 0xd3;
const RR_LCK_ST: u32 = 1 << 4;
const RR_AACK: u32 = 0xca;
const RR_VCI: u32 = 0xb3;
const RR_VCI_ON: u32 = 1 << 7;
const RR_VCO: u32 = 0xb2;
const RR_VCO_SEL: u32 = 0x300;
const RR_IBD: u32 = 0xc9;
const RR_IBD_VAL: u32 = 0x1f;
const RR_DCK: u32 = 0x92;
const RR_DCK_LV: u32 = 1;
const RR_DCK_S1: u32 = 0xf_0000;
const RR_DCK1: u32 = 0x93;
const RR_DCK1_S1: u32 = 0xf_0000;
const RR_LUTWE2: u32 = 0xee;
const RR_LUTWE2_DIS: u32 = 1 << 6;
const RR_LUTWA: u32 = 0x33;
const RR_LUTWD0: u32 = 0x3f;

// BB registers (reg.h), PHY-relative.
const R_DRCK: u32 = 0xc0c4;
const B_DRCK_IDLE: u32 = 1 << 9;
const B_DRCK_EN: u32 = 1 << 6;
const B_DRCK_VAL: u32 = 0x1f;
const R_DRCK_RES: u32 = 0xc0c8;
const B_DRCK_POL: u32 = 1 << 3;
const R_DRCK_FH: u32 = 0xc094;
const B_DRCK_LAT: u32 = 1 << 9;
const R_ADDCK0: u32 = 0xc0f4;
const B_ADDCK0: u32 = 0x300;
const B_ADDCK0_RST: u32 = 1 << 2;
const B_ADDCK0_EN: u32 = 1 << 4;
const B_ADDCK0_IQ: u32 = 1 << 10;
const R_ADDCKR0: u32 = 0xc0fc;
const B_ADDCKR0_A0: u32 = 0xffc00;
const B_ADDCKR0_A1: u32 = 0x3ff;
const B_ADDCKR0_DC: u32 = 0xfff0;
const R_ADDCK0_RL: u32 = 0xc0f8;
const B_ADDCK0_RL1: u32 = 0x0ffc_0000;
const B_ADDCK0_RL0: u32 = 0x0003_ff00;
const B_ADDCK0_RLS: u32 = 0x3000_0000;
const R_P0_NRBW: u32 = 0x12b8;
const B_P0_NRBW_DBG: u32 = 1 << 30;
const R_DCOF0: u32 = 0xc000;
const B_DCOF0_V: u32 = 0x1e;
const B_DCOF0_RST: u32 = 1 << 17;
const R_DCOF1: u32 = 0xc004;
const B_DCOF1_RST: u32 = 1 << 17;
const B_DCOF1_S: u32 = 1;
const R_DCOF8: u32 = 0xc020;
const B_DCOF8_V: u32 = 0x1e;
const R_DCOF9: u32 = 0xc024;
const B_DCOF9_RST: u32 = 1 << 17;
const R_DACK_S0P0: u32 = 0xc040;
const R_DACK_S0P1: u32 = 0xc064;
const R_DACK_S0P2: u32 = 0xc05c;
const R_DACK_S0P3: u32 = 0xc080;
const B_DACK_S0M: u32 = 0xff00_0000;
const R_DACK_BIAS00: u32 = 0xc048;
const R_DACK_BIAS01: u32 = 0xc06c;
const B_DACK_BIAS: u32 = 0xffc;
const R_DACK_DADCK00: u32 = 0xc060;
const R_DACK_DADCK01: u32 = 0xc084;
const B_DACK_DADCK: u32 = 0xff00_0000;
const R_DACKN0_CTL: u32 = 0xc210;
const B_DACKN0_EN: u32 = 1;
const B_DACKN0_V: u32 = 0x003f_c000;
const R_DACKN1_CTL: u32 = 0xc224;
const B_DACKN1_V: u32 = 0x003f_c000;
const R_P0_TSSI_TRK: u32 = 0x5818;
const B_P0_TSSI_TRK_EN: u32 = 1 << 30;

/// MAC R_AX_PWR_SWING_OTHER_CTRL0 / B_AX_CFIR_BY_RATE_OFF_MASK.
const R_AX_PWR_SWING_OTHER_CTRL0: u32 = 0xd230;
const B_AX_CFIR_BY_RATE_OFF_MASK: u32 = 0x3_ffff;

const fn wm(address: u32, mask: u32, value: u32) -> Entry {
    Entry(1, 0, address, mask, value)
}
/// rtw8851b_rfk_table.c `rtw8851b_dack_manual_off_defs`.
const DACK_MANUAL_OFF: [Entry; 3] = [
    wm(0xc0f8, 0x3000_0000, 0x0),
    wm(0xc210, 1, 0x0),
    wm(0xc224, 1, 0x0),
];
/// `rtw8851b_dack_s0_1_defs`.
const DACK_S0_1: [Entry; 5] = [
    wm(0x12a0, 1 << 15, 0x1),
    wm(0x12a0, 0x7000, 0x3),
    wm(0x12b8, 1 << 30, 0x1),
    wm(0x030c, 1 << 28, 0x1),
    wm(0x032c, 0x8000_0000, 0x0),
];
/// `rtw8851b_dack_s0_2_defs`.
const DACK_S0_2: [Entry; 3] = [
    wm(0xc004, 1, 0x0),
    wm(0x12a0, 1 << 15, 0x0),
    wm(0x12a0, 0x7000, 0x7),
];
/// `rtw8851b_dadck_setup_defs`.
const DADCK_SETUP: [Entry; 17] = [
    wm(0xc210, 0x003f_c000, 0x80),
    wm(0xc224, 0x003f_c000, 0x80),
    wm(0xc0f8, 0x3000_0000, 0x3),
    wm(0x12b8, 1 << 30, 0x1),
    wm(0x030c, 0x1f00_0000, 0x1f),
    wm(0x032c, 0xc000_0000, 0x0),
    wm(0x032c, 1 << 22, 0x0),
    wm(0x032c, 1 << 22, 0x1),
    wm(0x032c, 1 << 16, 0x0),
    wm(0x032c, 1 << 20, 0x1),
    wm(0x030c, 0x0f00_0000, 0x3),
    wm(0xc0f4, 1 << 2, 0x0),
    wm(0xc0f4, 1 << 4, 0x0),
    wm(0xc0f4, 1 << 11, 0x1),
    wm(0xc0f4, 1 << 11, 0x0),
    Entry(4, 0, 0, 0, 1),
    wm(0xc0f4, 0x300, 0x1),
];
/// `rtw8851b_dadck_post_defs`.
const DADCK_POST: [Entry; 5] = [
    wm(0x032c, 1 << 16, 0x1),
    wm(0x032c, 1 << 20, 0x0),
    wm(0x030c, 0x1f00_0000, 0xc),
    wm(0x032c, 0xc000_0000, 0x1),
    wm(0x12b8, 1 << 30, 0x0),
];

/// `rtw89_dack_info` (path A), RCK and LCK values retained by one RTL8851B
/// `rfk_init`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Results {
    /// `msbk_d[RF_PATH_A][index][16]`.
    pub msbk: [[u8; 16]; 2],
    /// `biask_d[RF_PATH_A][index]`.
    pub biask: [u16; 2],
    /// `dadck_d[RF_PATH_A][index]` after `_new_dadck` (u8 truncation as
    /// Linux).
    pub dadck: [u8; 2],
    /// `addck_d[RF_PATH_A][index]`.
    pub addck: [u16; 2],
    /// RR_RCKC `RR_RCKC_CA` result.
    pub rck: u32,
    /// Last `rtw8851b_aack` IB values (`ib[0..4]`) and retry count.
    pub aack_ib: [u32; 4],
    pub aack_rek: u8,
    /// `rtw8851b_lck_init` `lck->thermal[RF_PATH_A]`: the fresh EWMA reads 0
    /// before any track sample.
    pub lck_thermal: u8,
}

/// One retained RTL8851B `rfk_init` attempt.
#[derive(Default)]
pub(in super::super) struct Init {
    state: State,
    results: Results,
}

/// One retained RTL8851B `rtw8851b_rx_dck(PHY_0)` of `rtw8851b_rfk_channel`.
#[derive(Default)]
pub(in super::super) struct ChannelRxDck {
    state: State,
}

impl<I: Interface> Access<'_, I> {
    /// `rtw8851b_by_rate_dpd`: MAC write32_mask.
    fn n51_by_rate_dpd(&mut self) -> Result<(), Error> {
        self.0.admit()?;
        let old = self.0.read32(R_AX_PWR_SWING_OTHER_CTRL0)?;
        if old == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        self.0.admit()?;
        self.0.write32(
            R_AX_PWR_SWING_OTHER_CTRL0,
            (old & !B_AX_CFIR_BY_RATE_OFF_MASK) | 0x21861,
        )?;
        self.0.admit()?;
        if self.0.read32(R_AX_PWR_SWING_OTHER_CTRL0)? & B_AX_CFIR_BY_RATE_OFF_MASK != 0x21861 {
            return Err(power::Error::Access.into());
        }
        Ok(())
    }
    async fn n51_rf_poll(
        &mut self,
        address: u32,
        mask: u32,
        step: u64,
        budget: u64,
    ) -> Result<(), Error> {
        let start = self.0.now_us();
        loop {
            if self.rr(0, address, mask).await? != 0 {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= budget {
                return Err(power::Error::Timeout.into());
            }
            self.delay(step).await?;
        }
    }
    /// `rtw8851b_aack`.
    async fn n51_aack(&mut self, results: &mut Results) -> Result<(), Error> {
        let tmp05 = self.rr(0, RR_RSV1, RFREG_MASK).await?;
        let tmpd3 = self.rr(0, RR_LCK_TRG, RFREG_MASK).await?;
        self.wr(0, RR_MOD, RR_MOD_MASK, 0x3).await?;
        self.wr(0, RR_RSV1, RFREG_MASK, 0x0).await?;
        self.wr(0, RR_LCK_TRG, RR_LCK_ST, 0x0).await?;
        let mut rek = 0u8;
        while rek < 4 {
            self.wr(0, RR_AACK, RFREG_MASK, 0x8201e).await?;
            self.wr(0, RR_AACK, RFREG_MASK, 0x8201f).await?;
            self.delay(100).await?;
            // read_poll_timeout_atomic(rtw89_read_rf, 1, 1000, A, 0xd0, BIT(16)).
            self.n51_rf_poll(0xd0, 1 << 16, 1, 1000).await?;
            self.wr(0, RR_VCI, RR_VCI_ON, 0x1).await?;
            for i in 0..4u32 {
                self.wr(0, RR_VCO, RR_VCO_SEL, i).await?;
                results.aack_ib[i as usize] = self.rr(0, RR_IBD, RR_IBD_VAL).await?;
            }
            self.wr(0, RR_VCI, RR_VCI_ON, 0x0).await?;
            if results.aack_ib.iter().all(|&ib| ib != 0) {
                break;
            }
            rek += 1;
        }
        results.aack_rek = rek;
        self.wr(0, RR_RSV1, RFREG_MASK, tmp05).await?;
        self.wr(0, RR_LCK_TRG, RFREG_MASK, tmpd3).await
    }
    /// `_rck(RF_PATH_A)`: RCK trigger polled 2us/30us.
    async fn n51_rck(&mut self) -> Result<u32, Error> {
        let saved = self.rr(0, RR_RSV1, RFREG_MASK).await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(0, RR_MOD, RR_MOD_MASK, RF_RX).await?;
        self.wr(0, RR_RCKC, RFREG_MASK, 0x240).await?;
        self.n51_rf_poll(RR_RCKS, 1 << 3, 2, 30).await?;
        let value = self.rr(0, RR_RCKC, RR_RCKC_CA).await?;
        self.wr(0, RR_RCKC, RFREG_MASK, value).await?;
        self.wr(0, RR_RSV1, RFREG_MASK, saved).await?;
        Ok(value)
    }
    /// `_drck`.
    async fn n51_drck(&mut self) -> Result<(), Error> {
        self.wm(R_DRCK, B_DRCK_IDLE, 1)?;
        self.wm(R_DRCK, B_DRCK_EN, 1)?;
        self.poll(R_DRCK_RES, B_DRCK_POL, 1, 10_000).await?;
        self.wm(R_DRCK, B_DRCK_EN, 0)?;
        self.wm(R_DRCK_FH, B_DRCK_LAT, 1)?;
        self.delay(1).await?;
        self.wm(R_DRCK_FH, B_DRCK_LAT, 0)?;
        let rck_d = self.bb(R_DRCK_RES, 0x7c00)?;
        self.wm(R_DRCK, B_DRCK_IDLE, 0)?;
        self.wm(R_DRCK, B_DRCK_VAL, rck_d)
    }
    /// `_addck`, `_addck_backup`, `_addck_reload` (S0 only).
    async fn n51_addck(&mut self, results: &mut Results) -> Result<(), Error> {
        self.wm(R_ADDCK0, B_ADDCK0_RST, 1)?;
        self.wm(R_ADDCK0, B_ADDCK0_EN, 1)?;
        self.wm(R_ADDCK0, B_ADDCK0_EN, 0)?;
        self.delay(1).await?;
        self.wm(R_ADDCK0, B_ADDCK0, 1)?;
        self.poll(R_ADDCKR0, 1, 1, 10_000).await?;
        self.wm(R_ADDCK0, B_ADDCK0_RST, 0)?;
        self.wm(R_ADDCK0, B_ADDCK0, 0)?;
        results.addck = [
            self.bb(R_ADDCKR0, B_ADDCKR0_A0)? as u16,
            self.bb(R_ADDCKR0, B_ADDCKR0_A1)? as u16,
        ];
        self.wm(R_ADDCK0_RL, B_ADDCK0_RL1, u32::from(results.addck[0]))?;
        self.wm(R_ADDCK0_RL, B_ADDCK0_RL0, u32::from(results.addck[1]))?;
        self.wm(R_ADDCK0_RL, B_ADDCK0_RLS, 3)
    }
    /// `_dack_s0_poll`: all four OK bits, in Linux short-circuit order.
    fn n51_dack_done(&mut self) -> Result<bool, Error> {
        for (address, mask) in [
            (R_DACK_S0P0, 1 << 31),
            (R_DACK_S0P1, 1 << 31),
            (R_DACK_S0P2, 1 << 2),
            (R_DACK_S0P3, 1 << 2),
        ] {
            if self.bb(address, mask)? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// `_dack_s0` incl. `_dack_backup_s0` and `_dack_reload(RF_PATH_A)`.
    async fn n51_dack_s0(&mut self, results: &mut Results) -> Result<(), Error> {
        self.table(&DACK_S0_1).await?;
        // `_dack_reset`.
        self.wm(R_DCOF0, B_DCOF0_RST, 0)?;
        self.wm(R_DCOF0, B_DCOF0_RST, 1)?;
        self.wm(R_DCOF1, B_DCOF1_S, 1)?;
        let start = self.0.now_us();
        while !self.n51_dack_done()? {
            if self.0.now_us().saturating_sub(start) >= 10_000 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(1).await?;
        }
        self.table(&DACK_S0_2).await?;
        // `_dack_backup_s0`.
        self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 1)?;
        for i in 0..16u32 {
            self.wm(R_DCOF0, B_DCOF0_V, i)?;
            results.msbk[0][i as usize] = self.bb(R_DACK_S0P2, B_DACK_S0M)? as u8;
            self.wm(R_DCOF8, B_DCOF8_V, i)?;
            results.msbk[1][i as usize] = self.bb(R_DACK_S0P3, B_DACK_S0M)? as u8;
        }
        results.biask = [
            self.bb(R_DACK_BIAS00, B_DACK_BIAS)? as u16,
            self.bb(R_DACK_BIAS01, B_DACK_BIAS)? as u16,
        ];
        results.dadck = [
            (self.bb(R_DACK_DADCK00, B_DACK_DADCK)? as u8).wrapping_add(24),
            (self.bb(R_DACK_DADCK01, B_DACK_DADCK)? as u8).wrapping_add(24),
        ];
        // `_dack_reload` = `_dack_reload_by_path(A, 0..2)`.
        for index in 0..2usize {
            let offset = if index == 0 { 0 } else { 0x14 };
            self.wm(R_DCOF1, B_DCOF1_RST, 1)?;
            self.wm(R_DCOF9, B_DCOF9_RST, 1)?;
            let msbk = &results.msbk[index];
            for (slot, first) in [12usize, 8, 4, 0].into_iter().enumerate() {
                let value = u32::from_le_bytes([
                    msbk[first],
                    msbk[first + 1],
                    msbk[first + 2],
                    msbk[first + 3],
                ]);
                self.0.admit()?;
                self.0
                    .write32(0x10000 + 0xc200 + offset + 4 * slot as u32, value)?;
            }
            let value =
                (u32::from(results.biask[index]) << 22) | (u32::from(results.dadck[index]) << 14);
            self.0.admit()?;
            self.0.write32(0x10000 + 0xc210 + offset, value)?;
            self.wm(R_DACKN0_CTL + offset, B_DACKN0_EN, 1)?;
        }
        self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 0)
    }
    /// `_new_dadck`.
    async fn n51_new_dadck(&mut self, results: &mut Results) -> Result<(), Error> {
        self.table(&DADCK_SETUP).await?;
        self.poll(R_ADDCKR0, 1, 1, 10_000).await?;
        self.wm(R_ADDCK0, B_ADDCK0_IQ, 0)?;
        let i_dc = self.bb(R_ADDCKR0, B_ADDCKR0_DC)?;
        self.wm(R_ADDCK0, B_ADDCK0_IQ, 1)?;
        let q_dc = self.bb(R_ADDCKR0, B_ADDCKR0_DC)?;
        // ic = 0x80 - sign_extend32(dc, 11) * 6, stored in u8 dadck_d.
        let correct = |dc: u32| (0x80i32 - (((dc << 20) as i32) >> 20) * 6) as u8;
        results.dadck = [correct(i_dc), correct(q_dc)];
        self.wm(R_DACKN0_CTL, B_DACKN0_V, u32::from(results.dadck[0]))?;
        self.wm(R_DACKN1_CTL, B_DACKN1_V, u32::from(results.dadck[1]))?;
        self.table(&DADCK_POST).await
    }
    /// `_dac_cal(force = false)`.
    async fn n51_dac(&mut self, results: &mut Results) -> Result<(), Error> {
        // rf0_0 is read (Linux logs it).
        self.rr(0, RR_MOD, RFREG_MASK).await?;
        self.n51_drck().await?;
        self.table(&DACK_MANUAL_OFF).await?;
        self.wr(0, RR_MOD, RFREG_MASK, 0x337e1).await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.n51_addck(results).await?;
        self.wr(0, RR_MOD, RFREG_MASK, 0x40001).await?;
        self.n51_dack_s0(results).await?;
        self.n51_new_dadck(results).await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 1).await
    }
    /// `_set_rx_dck(A, RF_RX)` with `_rxbb_ofst_swap`.
    async fn n51_set_rx_dck(&mut self) -> Result<(), Error> {
        self.wr(0, RR_DCK, RR_DCK_LV, 0).await?;
        self.wr(0, RR_DCK, RR_DCK_LV, 1).await?;
        self.n51_rf_poll(RR_DCK, 1 << 8, 2, 2000).await?;
        self.wr(0, RR_DCK, RR_DCK_LV, 0).await?;
        let val_i = self.rr(0, RR_DCK, RR_DCK_S1).await?;
        let val_q = self.rr(0, RR_DCK1, RR_DCK1_S1).await?;
        self.wr(0, RR_LUTWE2, RR_LUTWE2_DIS, 1).await?;
        self.wr(0, RR_LUTWA, RFREG_MASK, RF_RX).await?;
        self.wr(0, RR_LUTWD0, RFREG_MASK, (val_q << 4) | val_i)
            .await?;
        self.wr(0, RR_LUTWE2, RR_LUTWE2_DIS, 0).await
    }
    /// `rtw8851b_rx_dck(PHY_0)`: BTC RXDCK START, `stop_sch_tx`,
    /// `_wait_rx_mode(RF_A)` (2us/5000us), `_rx_dck`, resume, STOP.
    /// `tssi_mode` is `rtwdev->is_tssi_mode[RF_PATH_A]`.
    async fn n51_rx_dck(&mut self, tssi_mode: bool) -> Result<(), Error> {
        self.0.admit()?;
        self.0.begin(Kind::Rxdck).await?;
        let saved = self.0.pause().await?;
        let start = self.0.now_us();
        while self.rr(0, RR_MOD, RR_MOD_MASK).await? == 2 {
            if self.0.now_us().saturating_sub(start) >= 5000 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(2).await?;
        }
        let rf_reg5 = self.rr(0, RR_RSV1, RFREG_MASK).await?;
        if tssi_mode {
            self.wm(R_P0_TSSI_TRK, B_P0_TSSI_TRK_EN, 1)?;
        }
        self.wr(0, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(0, RR_MOD, RR_MOD_MASK, RF_RX).await?;
        self.n51_set_rx_dck().await?;
        self.wr(0, RR_RSV1, RFREG_MASK, rf_reg5).await?;
        if tssi_mode {
            self.wm(R_P0_TSSI_TRK, B_P0_TSSI_TRK_EN, 0)?;
        }
        self.0.resume(saved).await?;
        self.0.end(Kind::Rxdck).await
    }
}

impl Init {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn results(&self) -> Option<&Results> {
        (self.state == State::BasicCalibrated).then_some(&self.results)
    }
    /// rtw8851b.c `rtw8851b_rfk_init`: `is_tssi_mode[A/B] = false`, the LCK
    /// thermal baseline, `rtw8851b_dpk_init`, `rtw8851b_aack`,
    /// `rtw8851b_rck`, `rtw8851b_dack`, then `rtw8851b_rx_dck(PHY_0)`.
    ///
    /// # Safety
    /// Actual RTL8851B PHY_0 with completed RTL8851B factory/BB/RF/NCTL
    /// tables and `controls_51`; current admission is enforced by Interface
    /// before every access. No concurrent reset/PHY/PM/packet owner; the
    /// outer attempt closes and retains DMA on cancellation or failure.
    pub async unsafe fn prepare(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Calibrating;
        io.admit()?;
        self.results.lck_thermal = 0;
        let mut access = Access(io);
        access.n51_by_rate_dpd()?;
        access.n51_aack(&mut self.results).await?;
        self.results.rck = access.n51_rck().await?;
        access.n51_dac(&mut self.results).await?;
        access.n51_rx_dck(false).await?;
        self.state = State::BasicCalibrated;
        Ok(())
    }
}

impl ChannelRxDck {
    pub fn state(&self) -> State {
        self.state
    }
    /// The `rtw8851b_rx_dck(phy_idx)` of `rtw8851b_rfk_channel`, after
    /// `rtw89_btc_ntfy_conn_rfk(true)`.
    ///
    /// # Safety
    /// Same retained RTL8851B owner after a completed [`Init`] and
    /// channel program; `tssi_mode` must be the actual retained TSSI state.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        tssi_mode: bool,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Calibrating;
        Access(io).n51_rx_dck(tssi_mode).await?;
        self.state = State::BasicCalibrated;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "n51_tests.rs"]
mod tests;
