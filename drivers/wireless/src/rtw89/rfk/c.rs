// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C `rtw8852c_rfk_init` (rtw8852c.c): `rtw8852c_lck_init`,
//! `rtw8852c_dpk_init`, `rtw8852c_rck`, `rtw8852c_dack` and
//! `rtw8852c_rx_dck(PHY_0, is_afe = false)` from rtw8852c_rfk.c, for the
//! non-DBCC PHY_0 (`_kpath` = RF_AB). Linux only logs RCK/ADDCK/DACK/RXDCK
//! poll timeouts; NARF fails the attempt closed instead.
use super::{power, Access, Error, Interface, Kind, State};

// RF registers/fields (reg.h) not already shared with the B core.
const RFREG_MASK: u32 = 0xfffff;
const RR_MOD: u32 = 0x00;
const RR_MOD_MASK: u32 = 0xf0000;
const RR_MOD_V_RX: u32 = 0x3;
const RR_MOD_LO_SEL: u32 = 1 << 1;
const RR_MOD_DCK: u32 = 0x7c00;
const RR_MODOPT: u32 = 0x01;
const RR_RSV1: u32 = 0x05;
const RR_RSV1_RST: u32 = 1;
const RR_RCKC: u32 = 0x1b;
const RR_RCKC_CA: u32 = 0x7c00;
const RR_RCKS: u32 = 0x1c;
const RR_DCK: u32 = 0x92;
const RR_DCK_LV: u32 = 1;
const RR_DCK_FINE: u32 = 1 << 1;
const RR_DCK_DONE: u32 = 0xe0;
const RR_DCK_TIA: u32 = 0xfe00;
const RR_DCK1: u32 = 0x93;
const RR_DCK1_CLR: u32 = 0xf;
const RR_DCK1_DONE: u32 = 1 << 5;
const RR_DCK1_TIA: u32 = 0xfe00;
const RR_DCKC: u32 = 0x95;
const RR_DCKC_CHK: u32 = 1 << 3;
const RR_RXBB2: u32 = 0x8f;
const RR_RXBB2_IDAC: u32 = 0xe00;
const RR_LUTPLL: u32 = 0xec;
const RR_CAL_RW: u32 = 1 << 19;
const RR_RFC: u32 = 0xf0;
const RR_WCAL: u32 = 1 << 16;
const RR_LUTWA: u32 = 0x33;
const RR_LUTWD0: u32 = 0x3f;
const RR_LUTWD0_MB: u32 = 0xfc0;
const RR_LUTWD0_LB: u32 = 0x3f;

// BB registers (reg.h), PHY-relative.
const R_ADDCK0: u32 = 0xc0f4;
const R_ADDCK1: u32 = 0xc1f4;
const B_ADDCK_RST: u32 = 1 << 2;
const B_ADDCK_EN: u32 = 1 << 4;
const B_ADDCK: u32 = 0x300;
const R_ADDCKR0: u32 = 0xc0fc;
const R_ADDCKR1: u32 = 0xc1fc;
const B_ADDCKR_A0: u32 = 0xffc00;
const B_ADDCKR_A1: u32 = 0x3ff;
const R_ADDCK0_RL: u32 = 0xc0f8;
const R_ADDCK1_RL: u32 = 0xc1f8;
const B_ADDCK_RL1: u32 = 0x0ffc_0000;
const B_ADDCK_RL0: u32 = 0x0003_ff00;
const B_ADDCK_RLS: u32 = 0x3000_0000;
const R_P0_NRBW: u32 = 0x12b8;
const R_P1_DBGMOD: u32 = 0x32b8;
const B_DBG_ON: u32 = 1 << 30;
const R_P0_RXCK: u32 = 0x12a0;
const B_P0_TXCK_ON: u32 = 1 << 15;
const B_P0_TXCK_VAL: u32 = 0x7000;
const R_DCOF1: u32 = 0xc004;
const R_DACK1_K: u32 = 0xc104;
const R_DRCK: u32 = 0xc0c4;
const B_DRCK_EN: u32 = 1 << 6;
const B_DRCK_IDLE: u32 = 1 << 9;
const B_DRCK_VAL: u32 = 0x1f;
const R_DRCK_RES: u32 = 0xc0c8;
const B_DRCK_RES: u32 = 0x000f_8000;
const R_P0_TSSI_TRK: u32 = 0x5818;
const B_P0_TSSI_TRK_EN: u32 = 1 << 30;
const DAC_160M: u32 = 3;

/// `_dck_addr_bs` / `_dck_addr` (RF_PATH_NUM_8852C entries).
const DCK_ADDR_BS: [u8; 2] = [0x0, 0x10];
const DCK_ADDR: [u8; 2] = [0xc, 0x1c];

/// `rtw89_dack_info` / RCK values retained by one C `rfk_init`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Results {
    /// `msbk_d[path][index][16]`.
    pub msbk: [[[u8; 16]; 2]; 2],
    /// `biask_d[path][index]`.
    pub biask: [[u16; 2]; 2],
    /// `dadck_d[path][index]`.
    pub dadck: [[u8; 2]; 2],
    /// `addck_d[path][index]`.
    pub addck: [[u16; 2]; 2],
    /// RR_RCKC `RR_RCKC_CA` result per path.
    pub rck: [u32; 2],
    /// `rtw8852c_dpk_init`: `is_dpk_enable = true`, reload disabled.
    pub dpk_enable: bool,
}

/// One retained RTL8852C `rfk_init` attempt.
#[derive(Default)]
pub(in super::super) struct Init {
    state: State,
    results: Results,
}

impl<I: Interface> Access<'_, I> {
    async fn c_rck(&mut self, path: u8) -> Result<u32, Error> {
        let saved = self.rr(path, RR_RSV1, RFREG_MASK).await?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
        self.wr(path, RR_RCKC, RFREG_MASK, 0x240).await?;
        // read_poll_timeout_atomic(rtw89_read_rf, ..., 2, 20, path, 0x1c, BIT(3)).
        let start = self.0.now_us();
        loop {
            if self.rr(path, RR_RCKS, 1 << 3).await? != 0 {
                break;
            }
            if self.0.now_us().saturating_sub(start) >= 20 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(2).await?;
        }
        let value = self.rr(path, RR_RCKC, RR_RCKC_CA).await?;
        self.wr(path, RR_RCKC, RFREG_MASK, value).await?;
        self.wr(path, RR_RSV1, RFREG_MASK, saved).await?;
        Ok(value)
    }
    /// `_drck` + `rtw8852c_drck_defs`.
    async fn c_drck(&mut self) -> Result<(), Error> {
        self.wm(R_DRCK, B_DRCK_EN, 1)?;
        self.poll(R_DRCK_RES, 1 << 3, 1, 10_000).await?;
        self.wm(R_DRCK, B_DRCK_EN, 0)?;
        self.wm(0xc094, 1 << 9, 1)?;
        self.delay(1).await?;
        self.wm(0xc094, 1 << 9, 0)?;
        let value = self.bb(R_DRCK_RES, B_DRCK_RES)?;
        self.wm(R_DRCK, B_DRCK_IDLE, 0)?;
        self.wm(R_DRCK, B_DRCK_VAL, value)
    }
    /// `_addck`, `_addck_backup`, `_addck_reload`.
    async fn c_addck(&mut self, results: &mut Results) -> Result<(), Error> {
        for (addck, report) in [(R_ADDCK0, R_ADDCKR0), (R_ADDCK1, R_ADDCKR1)] {
            self.wm(addck, B_ADDCK_RST, 1)?;
            self.wm(addck, B_ADDCK_EN, 1)?;
            self.wm(addck, B_ADDCK_EN, 0)?;
            self.delay(1).await?;
            self.wm(addck, B_ADDCK, 1)?;
            self.poll(report, 1, 1, 10_000).await?;
            self.wm(addck, B_ADDCK_RST, 0)?;
        }
        for (path, (addck, report)) in [(R_ADDCK0, R_ADDCKR0), (R_ADDCK1, R_ADDCKR1)]
            .into_iter()
            .enumerate()
        {
            self.wm(addck, B_ADDCK, 0)?;
            results.addck[path] = [
                self.bb(report, B_ADDCKR_A0)? as u16,
                self.bb(report, B_ADDCKR_A1)? as u16,
            ];
        }
        for (path, reload) in [R_ADDCK0_RL, R_ADDCK1_RL].into_iter().enumerate() {
            self.wm(reload, B_ADDCK_RL1, u32::from(results.addck[path][0]))?;
            self.wm(reload, B_ADDCK_RL0, u32::from(results.addck[path][1]))?;
            self.wm(reload, B_ADDCK_RLS, 3)?;
        }
        Ok(())
    }
    /// `_check_dack_done`: all four OK bits, in Linux short-circuit order.
    fn c_dack_done(&mut self, s0: bool) -> Result<bool, Error> {
        let checks: [(u32, u32); 4] = if s0 {
            [
                (0xc040, 1 << 31),
                (0xc064, 1 << 31),
                (0xc05c, 1 << 2),
                (0xc080, 1 << 2),
            ]
        } else {
            [
                (0xc140, 1 << 31),
                (0xc164, 1 << 31),
                (0xc15c, 1 << 2),
                (0xc180, 1 << 2),
            ]
        };
        for (address, mask) in checks {
            if self.bb(address, mask)? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// `rtw8852c_txck_force(path, force, DAC_160M)`.
    fn c_txck(&mut self, path: u8, force: bool) -> Result<(), Error> {
        let address = R_P0_RXCK | (u32::from(path) << 13);
        self.wm(address, B_P0_TXCK_ON, 0)?;
        if force {
            self.wm(address, B_P0_TXCK_VAL, DAC_160M)?;
            self.wm(address, B_P0_TXCK_ON, 1)?;
        }
        Ok(())
    }
    /// `_dack_s0` / `_dack_s1` incl. backup and `_dack_reload`.
    async fn c_dack_path(&mut self, path: u8, results: &mut Results) -> Result<(), Error> {
        let p = usize::from(path);
        let base = u32::from(path) << 8;
        let nrbw = if path == 0 { R_P0_NRBW } else { R_P1_DBGMOD };
        self.c_txck(path, true)?;
        // rtw8852c_dack_defs_s0 / _s1.
        self.wm(nrbw, 1 << 30, 1)?;
        self.wm(0x030c, 1 << 28, 1)?;
        self.wm(0x032c, 0x8000_0000, 0)?;
        self.wm(0xc004 + base, 0xfff0_0000, 0x30)?;
        self.wm(0xc024 + base, 0xfff0_0000, 0x30)?;
        // `_dack_reset`: rtw8852c_dack_reset_defs_a / _b.
        self.wm(0xc000 + base, 1 << 17, 0)?;
        self.wm(0xc000 + base, 1 << 17, 1)?;
        let trigger = if path == 0 { R_DCOF1 } else { R_DACK1_K };
        self.wm(trigger, 1, 1)?;
        let start = self.0.now_us();
        while !self.c_dack_done(path == 0)? {
            if self.0.now_us().saturating_sub(start) >= 10_000 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(1).await?;
        }
        self.wm(trigger, 1, 0)?;
        self.c_txck(path, false)?;
        // `_dack_backup_s0` / `_dack_backup_s1`.
        self.wm(nrbw, B_DBG_ON, 1)?;
        for i in 0..16u32 {
            self.wm(0xc000 + base, 0x1e, i)?;
            results.msbk[p][0][i as usize] = self.bb(0xc05c + base, 0xff00_0000)? as u8;
            self.wm(0xc020 + base, 0x1e, i)?;
            results.msbk[p][1][i as usize] = self.bb(0xc080 + base, 0xff00_0000)? as u8;
        }
        results.biask[p] = [
            self.bb(0xc048 + base, 0xffc)? as u16,
            self.bb(0xc06c + base, 0xffc)? as u16,
        ];
        results.dadck[p] = [
            self.bb(0xc060 + base, 0xff00_0000)? as u8,
            self.bb(0xc084 + base, 0xff00_0000)? as u8,
        ];
        // `_dack_reload(path)` = `_dack_reload_by_path(path, 0..2)`.
        for index in 0..2usize {
            let offset = if index == 0 { 0 } else { 0x14 } + if path == 0 { 0 } else { 0x28 };
            // rtw8852c_dack_reload_defs.
            for address in [0xc004, 0xc024, 0xc104, 0xc124] {
                self.wm(address, 1 << 17, 1)?;
            }
            let msbk = &results.msbk[p][index];
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
            let value = (u32::from(results.biask[p][index]) << 22)
                | (u32::from(results.dadck[p][index]) << 14);
            self.0.admit()?;
            self.0.write32(0x10000 + 0xc210 + offset, value)?;
            let old = self.bb(0xc210 + offset, u32::MAX)?;
            self.0.admit()?;
            self.0.write32(0x10000 + 0xc210 + offset, old | 1)?;
        }
        self.wm(nrbw, B_DBG_ON, 0)
    }
    /// `_dac_cal(force = false)`. The ONESHOT coexistence notifications
    /// around ADDCK/DACK return without I/O for DACK (coex.c
    /// `rtw89_btc_ntfy_wl_rfk`), so only the outer START/STOP are emitted.
    async fn c_dac(&mut self, results: &mut Results) -> Result<(), Error> {
        let saved = [
            self.rr(0, RR_MOD, RFREG_MASK).await?,
            self.rr(1, RR_MOD, RFREG_MASK).await?,
        ];
        self.c_drck().await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(1, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(0, RR_MOD, RFREG_MASK, 0x337e1).await?;
        self.wr(1, RR_MOD, RFREG_MASK, 0x337e1).await?;
        self.c_addck(results).await?;
        self.wr(0, RR_MODOPT, RFREG_MASK, 0).await?;
        self.wr(1, RR_MODOPT, RFREG_MASK, 0).await?;
        self.c_dack_path(0, results).await?;
        self.c_dack_path(1, results).await?;
        self.wr(0, RR_MOD, RFREG_MASK, saved[0]).await?;
        self.wr(1, RR_MOD, RFREG_MASK, saved[1]).await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 1).await?;
        self.wr(1, RR_RSV1, RR_RSV1_RST, 1).await
    }
    /// `_rx_dck_toggle`.
    async fn c_rx_dck_toggle(&mut self, path: u8) -> Result<(), Error> {
        self.wr(path, RR_DCK, RR_DCK_LV, 0).await?;
        self.wr(path, RR_DCK, RR_DCK_LV, 1).await?;
        let start = self.0.now_us();
        loop {
            if self.rr(path, RR_DCK1, RR_DCK1_DONE).await? != 0 {
                break;
            }
            if self.0.now_us().saturating_sub(start) >= 2000 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(2).await?;
        }
        self.wr(path, RR_DCK, RR_DCK_LV, 0).await
    }
    /// `_set_rx_dck`.
    pub(super) async fn c_set_rx_dck(&mut self, path: u8) -> Result<(), Error> {
        self.wr(path, RR_DCK1, RR_DCK1_CLR, 0).await?;
        self.c_rx_dck_toggle(path).await?;
        if self.rr(path, RR_DCKC, RR_DCKC_CHK).await? == 0 {
            return Ok(());
        }
        let res = self.rr(path, RR_DCK, RR_DCK_DONE).await?;
        if res > 1 {
            self.wr(path, RR_RXBB2, RR_RXBB2_IDAC, res).await?;
            self.c_rx_dck_toggle(path).await?;
            self.wr(path, RR_RXBB2, RR_RXBB2_IDAC, 1).await?;
        }
        Ok(())
    }
    async fn c_dck_sample(&mut self, path: u8, address: u8) -> Result<(i32, i32), Error> {
        self.wr(path, RR_MOD, RR_MOD_DCK, u32::from(address))
            .await?;
        let i = self.rr(path, RR_DCK, RR_DCK_TIA).await? as u8;
        let q = self.rr(path, RR_DCK1, RR_DCK1_TIA).await? as u8;
        Ok((i32::from(i), i32::from(q)))
    }
    /// `_rx_dck_fix_if_need` + `_rx_dck_value_rewrite` (asymmetric
    /// `< th` / `<= th` PASS test kept as Linux has it).
    async fn c_fix(
        &mut self,
        path: u8,
        address: u8,
        bs: (i32, i32),
        value: (i32, i32),
    ) -> Result<(), Error> {
        const TH: i32 = 10;
        let (mut i, mut q) = value;
        if (bs.0 - i).abs() < TH && (bs.1 - q).abs() <= TH {
            return Ok(());
        }
        if (bs.0 - i).abs() > TH {
            i = bs.0;
        }
        if (bs.1 - q).abs() > TH {
            q = bs.1;
        }
        let ofst = (((q as u32) >> 1) << RR_LUTWD0_MB.trailing_zeros()) & RR_LUTWD0_MB
            | (((i as u32) >> 1) & RR_LUTWD0_LB);
        self.wr(path, RR_LUTPLL, RR_CAL_RW, 1).await?;
        self.wr(path, RR_RFC, RR_WCAL, 1).await?;
        self.wr(path, RR_DCK, RR_DCK_FINE, 1).await?;
        self.wr(path, RR_LUTWA, 0xff, u32::from(address)).await?;
        self.wr(path, RR_LUTWD0, RFREG_MASK, ofst).await?;
        self.wr(path, RR_LUTWD0, RFREG_MASK, ofst).await?;
        self.wr(path, RR_DCK, RR_DCK_FINE, 0).await?;
        self.wr(path, RR_RFC, RR_WCAL, 0).await?;
        self.wr(path, RR_LUTPLL, RR_CAL_RW, 0).await
    }
    /// `_rx_dck_recover`.
    async fn c_rx_dck_recover(&mut self, path: u8) -> Result<(), Error> {
        for i in 0..2 {
            let even_bs = self.c_dck_sample(path, DCK_ADDR_BS[i]).await?;
            let odd_bs = self.c_dck_sample(path, DCK_ADDR_BS[i] + 1).await?;
            let even = self.c_dck_sample(path, DCK_ADDR[i]).await?;
            self.c_fix(path, DCK_ADDR[i], even_bs, even).await?;
            let odd = self.c_dck_sample(path, DCK_ADDR[i] + 1).await?;
            self.c_fix(path, DCK_ADDR[i] + 1, odd_bs, odd).await?;
        }
        Ok(())
    }
    /// `_rx_dck(PHY_0, is_afe, retry_limit = 1)`: with one try the
    /// `rek_cnt == retry_limit - 1` branch always runs `_rx_dck_recover`
    /// and `_rx_dck_rek_check` is never reached. `dbcc_en` = 0 for LO_SEL.
    pub(super) async fn c_rx_dck(&mut self, tssi_mode: [bool; 2]) -> Result<(), Error> {
        for path in 0..2u8 {
            let saved = self.rr(path, RR_RSV1, RFREG_MASK).await?;
            let trk = R_P0_TSSI_TRK + (u32::from(path) << 13);
            if tssi_mode[usize::from(path)] {
                self.wm(trk, B_P0_TSSI_TRK_EN, 1)?;
            }
            self.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
            self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
            self.wr(path, RR_MOD, RR_MOD_LO_SEL, 0).await?;
            self.c_set_rx_dck(path).await?;
            self.c_rx_dck_recover(path).await?;
            self.wr(path, RR_RSV1, RFREG_MASK, saved).await?;
            if tssi_mode[usize::from(path)] {
                self.wm(trk, B_P0_TSSI_TRK_EN, 0)?;
            }
        }
        Ok(())
    }
}

impl Init {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn results(&self) -> Option<&Results> {
        (self.state == State::BasicCalibrated).then_some(&self.results)
    }
    /// rtw8852c.c `rtw8852c_rfk_init`: `is_tssi_mode[A/B] = false`, MCC
    /// RFK state cleared, LCK thermal baseline (a fresh EWMA before any
    /// track sample), `rtw8852c_dpk_init`, RCK A then B, DACK bracketed by
    /// `BTC_WRFKT_DACK` START/STOP, then the un-notified initial RX DCK.
    ///
    /// # Safety
    /// Actual RTL8852C PHY0 (non-DBCC), completed C factory/BB/RF/NCTL
    /// tables and `controls_c`; current admission is enforced by Interface
    /// before every access. No concurrent reset/PHY/PM/packet owner; the
    /// outer attempt closes and retains DMA on cancellation or failure.
    pub async unsafe fn prepare(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Calibrating;
        io.admit()?;
        self.results.dpk_enable = true;
        let mut access = Access(io);
        for path in 0..2 {
            self.results.rck[usize::from(path)] = access.c_rck(path).await?;
        }
        access.0.admit()?;
        access.0.begin(Kind::Dack).await?;
        access.c_dac(&mut self.results).await?;
        access.0.end(Kind::Dack).await?;
        access.c_rx_dck([false; 2]).await?;
        self.state = State::BasicCalibrated;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "c_tests.rs"]
mod tests;
