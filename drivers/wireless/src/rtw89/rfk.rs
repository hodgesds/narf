// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! B initial RCK/DACK/RXDCK core. Native emission stays behind a measured
//! board/current-policy/coexistence adapter; this is not a station receipt.
use super::{
    power::{self, Io},
    rfk_regs::*,
    rfk_tables as tables,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Entry(pub u8, pub u8, pub u32, pub u32, pub u32);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Register(power::Error),
    Policy,
    Table,
    Terminal,
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Register(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Dack,
    Rxdck,
}
pub(super) trait Interface: Io {
    /// Recheck current signed board envelope and host channel policy. The
    /// native adapter must also retain actual factory/NCTL/coexistence state.
    fn admit(&mut self) -> Result<(), Error>;
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error>;
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error>;
    async fn begin(&mut self, kind: Kind) -> Result<(), Error>;
    async fn end(&mut self, kind: Kind) -> Result<(), Error>;
    async fn pause(&mut self) -> Result<u32, Error>;
    async fn resume(&mut self, saved: u32) -> Result<(), Error>;
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Results {
    pub msbk: [[[u8; 16]; 2]; 2],
    pub dadck: [[u8; 2]; 2],
    pub addck: [[u16; 2]; 2],
    pub bias: [[u16; 2]; 2],
    pub dpd_gain: u8,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Calibrating,
    BasicCalibrated,
}
#[derive(Default)]
pub(super) struct Rfk {
    state: State,
    results: Results,
}
struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    fn bb(&mut self, address: u32, mask: u32) -> Result<u32, Error> {
        self.0.admit()?;
        let v = self.0.read32(0x10000 + address)?;
        if v == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        Ok((v & mask) >> mask.trailing_zeros())
    }
    fn wm(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        if address > 0xffff || address & 3 != 0 || mask == 0 {
            return Err(Error::Table);
        }
        let old = self.bb(address, u32::MAX)?;
        self.0.admit()?;
        self.0.write32(
            0x10000 + address,
            (old & !mask) | ((value << mask.trailing_zeros()) & mask),
        )?;
        Ok(())
    }
    async fn rr(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        self.0.admit()?;
        self.0.rf_read(path, address, mask).await
    }
    async fn wr(&mut self, path: u8, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.0.admit()?;
        self.0.rf_write(path, address, mask, value).await
    }
    async fn delay(&mut self, us: u64) -> Result<(), Error> {
        self.0.admit()?;
        self.0.delay_us(us).await;
        self.0.admit()
    }
    async fn poll(&mut self, address: u32, mask: u32, step: u64, budget: u64) -> Result<(), Error> {
        let start = self.0.now_us();
        loop {
            if self.bb(address, mask)? != 0 {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= budget {
                return Err(power::Error::Timeout.into());
            }
            self.delay(step).await?;
        }
    }
    async fn table(&mut self, program: &[Entry]) -> Result<(), Error> {
        for &Entry(kind, path, address, mask, value) in program {
            match kind {
                0 => self.wr(path, address, mask, value).await?,
                1 => self.wm(address, mask, value)?,
                2 => {
                    let old = self.bb(address, u32::MAX)?;
                    self.0.admit()?;
                    self.0.write32(0x10000 + address, old | mask)?;
                }
                3 => {
                    let old = self.bb(address, u32::MAX)?;
                    self.0.admit()?;
                    self.0.write32(0x10000 + address, old & !mask)?;
                }
                4 => self.delay(u64::from(value)).await?,
                _ => return Err(Error::Table),
            }
        }
        Ok(())
    }
    async fn check_addc(&mut self, path: u8) -> Result<(), Error> {
        self.table(if path == 0 {
            tables::CHECK_ADDC_DEFS_A
        } else {
            tables::CHECK_ADDC_DEFS_B
        })
        .await?;
        // Original diagnostic acquisition is finite, not a completion spin.
        // Preserve every volatile sample even though only RFK diagnostics use
        // the averaged signed I/Q values and no readiness comes from them.
        for _ in 0..100 {
            self.bb(R_DBG32_D, u32::MAX)?;
        }
        Ok(())
    }
    async fn rck(&mut self, path: u8) -> Result<(), Error> {
        let saved = self.rr(path, RR_RSV1, RFREG_MASK).await?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
        self.wr(path, RR_RCKC, RFREG_MASK, 0x240).await?;
        let start = self.0.now_us();
        loop {
            if self.rr(path, RR_RCKS, 8).await? != 0 {
                break;
            }
            if self.0.now_us().saturating_sub(start) >= 30 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(2).await?;
        }
        let value = self.rr(path, RR_RCKC, RR_RCKC_CA).await?;
        self.wr(path, RR_RCKC, RFREG_MASK, value).await?;
        self.wr(path, RR_RSV1, RFREG_MASK, saved).await
    }
    async fn drck(&mut self) -> Result<(), Error> {
        self.wm(R_DRCK_V1, B_DRCK_V1_KICK, 1)?;
        self.poll(R_DRCK_RS, B_DRCK_RS_DONE, 1, 10_000).await?;
        self.wm(R_DRCK_V1, B_DRCK_V1_KICK, 0)?;
        self.wm(R_DRCK_FH, B_DRCK_LAT, 1)?;
        self.delay(1).await?;
        self.wm(R_DRCK_FH, B_DRCK_LAT, 0)?;
        let result = self.bb(R_DRCK_RS, B_DRCK_RS_LPS)?;
        self.wm(R_DRCK_V1, B_DRCK_V1_SEL, 0)?;
        self.wm(R_DRCK_V1, B_DRCK_V1_CV, result)
    }
    async fn addck(&mut self, result: &mut Results) -> Result<(), Error> {
        self.wm(R_ADDCK0, B_ADDCK0_MAN, 0)?;
        self.wm(R_PATH1_SAMPL_DLY_T_V1, 0x30, 0)?;
        for path in 0..2 {
            let (debug, debug_mask, delay, addck, trigger, select, report) = if path == 0 {
                (
                    R_P0_NRBW,
                    B_P0_NRBW_DBG,
                    R_PATH0_SAMPL_DLY_T_V1,
                    R_ADDCK0,
                    B_ADDCK0_TRG,
                    B_ADDCK0,
                    R_ADDCKR0,
                )
            } else {
                (
                    R_P1_DBGMOD,
                    B_P1_DBGMOD_ON,
                    R_PATH1_SAMPL_DLY_T_V1,
                    R_ADDCK1,
                    B_ADDCK1_TRG,
                    B_ADDCK1,
                    R_ADDCKR1,
                )
            };
            self.wm(debug, debug_mask, 1)?;
            self.wm(R_ANAPAR, B_ANAPAR_ADCCLK, 0)?;
            self.wm(R_ANAPAR, B_ANAPAR_FLTRST, 0)?;
            self.wm(R_ANAPAR, B_ANAPAR_FLTRST, 1)?;
            self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 15)?;
            self.wm(R_ANAPAR, B_ANAPAR_EN, 0)?;
            self.wm(delay, 2, 1)?;
            self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 3)?;
            self.check_addc(path).await?;
            self.wm(addck, trigger, 1)?;
            self.wm(addck, trigger, 0)?;
            self.delay(1).await?;
            self.wm(addck, select, 1)?;
            self.poll(report, 1, 1, 10_000).await?;
            self.check_addc(path).await?;
            self.wm(delay, 2, 0)?;
            self.wm(R_ANAPAR, B_ANAPAR_EN, 1)?;
            self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 12)?;
            self.wm(R_ANAPAR, B_ANAPAR_ADCCLK, 1)?;
            self.wm(debug, debug_mask, 0)?;
        }
        self.wm(R_ADDCK0, B_ADDCK0, 0)?;
        result.addck[0][0] = self.bb(R_ADDCKR0, B_ADDCKR0_A0)? as u16;
        result.addck[0][1] = self.bb(R_ADDCKR0, B_ADDCKR0_A1)? as u16;
        self.wm(R_ADDCK1, B_ADDCK1, 0)?;
        result.addck[1][0] = self.bb(R_ADDCKR1, B_ADDCKR1_A0)? as u16;
        result.addck[1][1] = self.bb(R_ADDCKR1, B_ADDCKR1_A1)? as u16;
        self.wm(R_ADDCK0D, B_ADDCK0D_VAL, u32::from(result.addck[0][0]))?;
        self.wm(R_ADDCK0, B_ADDCK0_VAL, u32::from(result.addck[0][1] >> 6))?;
        self.wm(
            R_ADDCK0D,
            B_ADDCK0D_VAL2,
            u32::from(result.addck[0][1] & 63),
        )?;
        self.wm(R_ADDCK0, B_ADDCK0_MAN, 3)?;
        self.wm(R_ADDCK1D, B_ADDCK1D_VAL, u32::from(result.addck[1][0]))?;
        self.wm(R_ADDCK1, B_ADDCK0_VAL, u32::from(result.addck[1][1] >> 6))?;
        self.wm(
            R_ADDCK1D,
            B_ADDCK1D_VAL2,
            u32::from(result.addck[1][1] & 63),
        )?;
        self.wm(R_ADDCK1, B_ADDCK1_MAN, 3)
    }
    async fn dack_part(&mut self, path: u8, part: bool) -> Result<(), Error> {
        let (first, first_mask, second, second_mask) = match (path, part) {
            (0, true) => (R_DACK_S0P0, B_DACK_S0P0_OK, R_DACK_S0P1, B_DACK_S0P1_OK),
            (0, false) => (R_DACK_S0P2, B_DACK_S0P2_OK, R_DACK_S0P3, B_DACK_S0P3_OK),
            (1, true) => (R_DACK_S1P0, B_DACK_S1P0_OK, R_DACK_S1P1, B_DACK_S1P1_OK),
            _ => (R_DACK10S, B_DACK_S1P2_OK, R_DACK11S, B_DACK_S1P3_OK),
        };
        let start = self.0.now_us();
        loop {
            let first_done = self.bb(first, first_mask)? != 0;
            // Preserve Linux's asymmetric S1 redundant-done check, including
            // short-circuit read order: S0 needs both, S1 accepts either.
            let done = if path == 0 {
                first_done && self.bb(second, second_mask)? != 0
            } else {
                first_done || self.bb(second, second_mask)? != 0
            };
            if done {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= 10_000 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(1).await?;
        }
    }
    async fn backup_dack(&mut self, path: u8, result: &mut Results) -> Result<(), Error> {
        let p = path as usize;
        if path == 0 {
            self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 1)?;
            for i in 0..16 {
                self.wm(R_DCOF0, B_DCOF0_V, i)?;
                result.msbk[p][0][i as usize] = self.bb(R_DACK_S0P2, B_DACK_S0M0)? as u8;
                self.wm(R_DCOF8, B_DCOF8_V, i)?;
                result.msbk[p][1][i as usize] = self.bb(R_DACK_S0P3, B_DACK_S0M1)? as u8;
            }
            result.bias[p] = [
                self.bb(R_DACK_BIAS00, B_DACK_BIAS00)? as u16,
                self.bb(R_DACK_BIAS01, B_DACK_BIAS01)? as u16,
            ];
            result.dadck[p] = [
                self.bb(R_DACK_DADCK00, B_DACK_DADCK00)? as u8,
                self.bb(R_DACK_DADCK01, B_DACK_DADCK01)? as u8,
            ];
            self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 0)?;
        } else {
            self.table(tables::CHECK_DADC_EN_DEFS_B).await?;
            self.check_addc(path).await?;
            self.table(tables::CHECK_DADC_DIS_DEFS_B).await?;
            self.wm(R_P1_DBGMOD, B_P1_DBGMOD_ON, 1)?;
            for i in 0..16 {
                self.wm(R_DACK10, B_DACK10, i)?;
                result.msbk[p][0][i as usize] = self.bb(R_DACK10S, B_DACK10S)? as u8;
                self.wm(R_DACK11, B_DACK11, i)?;
                result.msbk[p][1][i as usize] = self.bb(R_DACK11S, B_DACK11S)? as u8;
            }
            result.bias[p] = [
                self.bb(R_DACK_BIAS10, B_DACK_BIAS10)? as u16,
                self.bb(R_DACK_BIAS11, B_DACK_BIAS11)? as u16,
            ];
            result.dadck[p] = [
                self.bb(R_DACK_DADCK10, B_DACK_DADCK10)? as u8,
                self.bb(R_DACK_DADCK11, B_DACK_DADCK11)? as u8,
            ];
            self.wm(R_P1_DBGMOD, B_P1_DBGMOD_ON, 0)?;
        }
        Ok(())
    }
    async fn dac(&mut self, result: &mut Results) -> Result<(), Error> {
        let saved = [
            self.rr(0, RR_MOD, RFREG_MASK).await?,
            self.rr(1, RR_MOD, RFREG_MASK).await?,
        ];
        self.0.admit()?;
        self.0.write32(R_AX_PHYREG_SET, 15)?;
        self.table(tables::AFE_INIT_DEFS).await?;
        self.drck().await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(1, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(0, RR_MOD, RFREG_MASK, 0x337e1).await?;
        self.wr(1, RR_MOD, RFREG_MASK, 0x337e1).await?;
        self.addck(result).await?;
        self.wr(0, RR_MODOPT, RFREG_MASK, 0).await?;
        self.wr(1, RR_MODOPT, RFREG_MASK, 0).await?;
        for path in 0..2 {
            let programs = if path == 0 {
                [
                    tables::DACK_S0_1_DEFS,
                    tables::DACK_S0_2_DEFS,
                    tables::DACK_S0_3_DEFS,
                ]
            } else {
                [
                    tables::DACK_S1_1_DEFS,
                    tables::DACK_S1_2_DEFS,
                    tables::DACK_S1_3_DEFS,
                ]
            };
            self.table(programs[0]).await?;
            self.dack_part(path, true).await?;
            self.table(programs[1]).await?;
            self.dack_part(path, false).await?;
            self.table(programs[2]).await?;
            self.backup_dack(path, result).await?;
        }
        self.wr(0, RR_MOD, RFREG_MASK, saved[0]).await?;
        self.wr(1, RR_MOD, RFREG_MASK, saved[1]).await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 1).await?;
        self.wr(1, RR_RSV1, RR_RSV1_RST, 1).await
    }
    async fn rx_dck(&mut self) -> Result<(), Error> {
        for path in 0..2 {
            let saved = self.rr(path, RR_RSV1, RFREG_MASK).await?;
            let tune = self.rr(path, RR_DCK, RR_DCK_FINE).await?;
            self.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
            self.wr(path, RR_DCK, RR_DCK_FINE, 0).await?;
            self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
            self.wr(path, RR_DCK1, RR_DCK1_CLR, 0).await?;
            self.wr(path, RR_DCK, RR_DCK_LV, 0).await?;
            self.wr(path, RR_DCK, RR_DCK_LV, 1).await?;
            self.delay(1000).await?;
            self.wr(path, RR_DCK, RR_DCK_FINE, tune).await?;
            self.wr(path, RR_RSV1, RFREG_MASK, saved).await?;
        }
        Ok(())
    }
}
impl Rfk {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn results(&self) -> Option<&Results> {
        (self.state == State::BasicCalibrated).then_some(&self.results)
    }
    /// # Safety
    /// Actual initial B PHY0/SCC, full completed factory/BB/RF/NCTL path and
    /// initial TSSI-disabled state; signed current measured board/channel and
    /// real coexistence admission is enforced by Interface before transitions.
    /// No concurrent reset/PHY/PM/packet owner; outer Native attempt closes and
    /// retains DMA on cancellation/failure. This does not complete channel RFK.
    pub async unsafe fn prepare(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Calibrating;
        io.admit()?;
        let mut access = Access(io);
        let backoff = access.bb(R_DPD_BF, B_DPD_BF_OFDM)? + access.bb(R_DPD_BF, B_DPD_BF_SCA)?;
        self.results.dpd_gain = if backoff >= 44 {
            for path in 0..2 {
                access.wm(R_DPD_CH0A + (path << 8), B_DPD_CFG, 0x7f7f7f)?;
            }
            0x7f
        } else {
            0x5b
        };
        access.rck(0).await?;
        access.rck(1).await?;
        access.0.admit()?;
        access.0.begin(Kind::Dack).await?;
        access.dac(&mut self.results).await?;
        access.0.end(Kind::Dack).await?;
        access.0.admit()?;
        access.0.begin(Kind::Rxdck).await?;
        let saved = access.0.pause().await?;
        for path in 0..2 {
            let start = access.0.now_us();
            loop {
                if access.rr(path, RR_MOD, RR_MOD_MASK).await? != 2 {
                    break;
                }
                if access.0.now_us().saturating_sub(start) >= 5000 {
                    return Err(power::Error::Timeout.into());
                }
                access.delay(2).await?;
            }
        }
        access.rx_dck().await?;
        access.0.resume(saved).await?;
        access.0.end(Kind::Rxdck).await?;
        self.state = State::BasicCalibrated;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "rfk/tests.rs"]
mod tests;
