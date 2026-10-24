// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact initial B channel1/20MHz RF synth core. This is not the complete BB,
//! IQK/TSSI/DPK channel continuation and has no native startup caller yet.
use super::{
    power,
    rfk::{self, Interface},
};
#[path = "channel_rf/regs.rs"]
mod regs;
use regs::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Rfk(rfk::Error),
    Register(power::Error),
    Terminal,
}
impl From<rfk::Error> for Error {
    fn from(e: rfk::Error) -> Self {
        Self::Rfk(e)
    }
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Register(e)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    SynthConfigured,
}
#[derive(Default)]
pub(super) struct Channel {
    state: State,
}
struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    async fn read(&mut self, p: u8, a: u32, m: u32) -> Result<u32, Error> {
        self.0.admit()?;
        let v = self.0.rf_read(p, a, m).await?;
        if v == INV_RF_DATA {
            return Err(power::Error::Gone.into());
        }
        Ok(v)
    }
    async fn write(&mut self, p: u8, a: u32, m: u32, v: u32) -> Result<(), Error> {
        self.0.admit()?;
        self.0.rf_write(p, a, m, v).await?;
        Ok(())
    }
    async fn delay(&mut self, us: u64) -> Result<(), Error> {
        self.0.admit()?;
        self.0.delay_us(us).await;
        self.0.admit()?;
        Ok(())
    }
    async fn s0(&mut self, v: u32) -> Result<(), Error> {
        let saved = self.read(0, RR_LDO, RFREG_MASK).await?;
        self.write(0, RR_LDO, RR_LDO_SEL, 1).await?;
        self.write(0, RR_CFGCH, RFREG_MASK, v).await?;
        let result = async {
            let start = self.0.now_us();
            loop {
                if self.read(0, RR_LPF, RR_LPF_BUSY).await? == 0 {
                    return Ok(());
                }
                if self.0.now_us().saturating_sub(start) >= 1000 {
                    return Err(Error::Register(power::Error::Timeout));
                }
                self.delay(1).await?;
            }
        }
        .await;
        let restored = self.write(0, RR_LDO, RFREG_MASK, saved).await;
        result?;
        restored
    }
    async fn lock(&mut self) -> Result<(), Error> {
        if self.read(0, RR_SYNFB, RR_SYNFB_LK).await? == 0 {
            for (m, v) in [
                (RR_MMD_RST_EN, 1),
                (RR_MMD_RST_SYN, 0),
                (RR_MMD_RST_SYN, 1),
                (RR_MMD_RST_EN, 0),
            ] {
                self.write(0, RR_MMD, m, v).await?;
            }
        }
        self.delay(10).await?;
        if self.read(0, RR_SYNFB, RR_SYNFB_LK).await? == 0 {
            self.write(0, RR_LCK_TRG, RR_LCK_TRGSEL, 1).await?;
            let v = self.read(0, RR_CFGCH, RFREG_MASK).await?;
            self.s0(v).await?;
            self.write(0, RR_LCK_TRG, RR_LCK_TRGSEL, 0).await?;
        }
        if self.read(0, RR_SYNFB, RR_SYNFB_LK).await? == 0 {
            for a in [RR_POW, RR_SX] {
                let v = self.read(0, a, RFREG_MASK).await?;
                self.write(0, a, RFREG_MASK, v).await?;
            }
            self.write(0, RR_SYNLUT, RR_SYNLUT_MOD, 1).await?;
            self.write(0, RR_POW, RR_POW_SYN, 0).await?;
            self.write(0, RR_POW, RR_POW_SYN, 3).await?;
            self.write(0, RR_SYNLUT, RR_SYNLUT_MOD, 0).await?;
            self.write(0, RR_LCK_TRG, RR_LCK_TRGSEL, 1).await?;
            let v = self.read(0, RR_CFGCH, RFREG_MASK).await?;
            self.s0(v).await?;
            self.write(0, RR_LCK_TRG, RR_LCK_TRGSEL, 0).await?;
        }
        // Linux logs final synth failure; this one-shot owner requires actual lock.
        if self.read(0, RR_SYNFB, RR_SYNFB_LK).await? == 0 {
            return Err(power::Error::Timeout.into());
        }
        Ok(())
    }
    async fn channel(&mut self, p: u8, direct: bool) -> Result<(), Error> {
        let a = if direct { RR_CFGCH_V1 } else { RR_CFGCH };
        let mut v = self.read(p, a, RFREG_MASK).await?;
        v &= !(RR_CFGCH_BAND1
            | RR_CFGCH_POW_LCK
            | RR_CFGCH_TRX_AH
            | RR_CFGCH_BCN
            | RR_CFGCH_BAND0
            | RR_CFGCH_CH);
        v |= 1 << RR_CFGCH_CH.trailing_zeros();
        v &= !(RR_CFGCH_POW_LCK | RR_CFGCH_TRX_AH | RR_CFGCH_BCN | RR_CFGCH_BW2) & RFREG_MASK;
        v |= RR_CFGCH_BW2;
        if p == 0 && !direct {
            self.s0(v).await?;
            self.lock().await?;
        } else {
            self.write(p, a, RFREG_MASK, v).await?;
        }
        self.write(p, RR_LCKST, RR_LCKST_BIN, 0).await?;
        self.write(p, RR_LCKST, RR_LCKST_BIN, 1).await
    }
    async fn bandwidth(&mut self, p: u8, direct: bool) -> Result<(), Error> {
        let a = if direct { RR_CFGCH_V1 } else { RR_CFGCH };
        let mut v = self.read(p, a, RFREG_MASK).await?;
        v = (v & !RR_CFGCH_BW) | ((CFGCH_BW_20M << RR_CFGCH_BW.trailing_zeros()) & RR_CFGCH_BW);
        v &= !(RR_CFGCH_POW_LCK | RR_CFGCH_TRX_AH | RR_CFGCH_BCN | RR_CFGCH_BW2) & RFREG_MASK;
        v |= RR_CFGCH_BW2;
        self.write(p, a, RFREG_MASK, v).await
    }
}
impl Channel {
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Complete B basic RFK, source coexistence and a current measured envelope
    /// explicitly covering this source LCK/synth recipe; same retained exclusive
    /// PHY0/SCC owner with packet and autonomous-response TX disabled. Caller
    /// terminalizes/retains uncertain native ownership if this future is dropped.
    /// The current basic-calibration artifact alone does not authorize this step.
    pub async unsafe fn prepare(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        let mut a = Access(io);
        for direct in [false, true] {
            for p in 0..2 {
                a.channel(p, direct).await?;
            }
        }
        for direct in [false, true] {
            for p in 0..2 {
                a.bandwidth(p, direct).await?;
            }
        }
        for p in 0..2 {
            a.write(p, RR_LUTWE2, RR_LUTWE2_RTXBW, 1).await?;
            a.write(p, RR_LUTWA, RR_LUTWA_M2, 0x12).await?;
            a.write(p, RR_LUTWD0, RR_LUTWD0_LB, 0x1b).await?;
            a.write(p, RR_LUTWE2, RR_LUTWE2_RTXBW, 0).await?;
        }
        let mask = RR_CFGCH_CH
            | RR_CFGCH_BAND0
            | RR_CFGCH_BAND1
            | RR_CFGCH_BW
            | RR_CFGCH_BW2
            | RR_CFGCH_POW_LCK
            | RR_CFGCH_TRX_AH
            | RR_CFGCH_BCN;
        let expected = (1 << RR_CFGCH_CH.trailing_zeros())
            | ((CFGCH_BW_20M << RR_CFGCH_BW.trailing_zeros()) & RR_CFGCH_BW)
            | RR_CFGCH_BW2;
        for direct in [false, true] {
            for p in 0..2 {
                if a.read(p, if direct { RR_CFGCH_V1 } else { RR_CFGCH }, RFREG_MASK)
                    .await?
                    & mask
                    != expected
                {
                    return Err(power::Error::Access.into());
                }
            }
        }
        self.state = State::SynthConfigured;
        Ok(())
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_rf/tests.rs"]
mod tests;
