// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact B 2.4/5GHz 20MHz RF synth core (Linux rtw8852b_rfk.c
//! rtw8852b_set_channel_rf: _ctrl_ch, _ctrl_bw, _rxbb_bw). Initial channel1 and
//! typed noninitial primaries share this one source order. This is not the
//! complete BB, IQK/TSSI/DPK channel continuation.
use super::{
    operating_channel::{Profile, Width},
    power,
    rfk::{self, Interface},
};
#[path = "channel_rf/regs.rs"]
mod regs;
use regs::*;
#[path = "channel_rf/recipe.rs"]
mod recipe;
pub(super) const RECIPE: [u8; 32] = recipe::RECIPE;
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
/// Linux `_ch_setting`: 5GHz centers set `CFGCH_BAND1_5G`/`CFGCH_BAND0_5G`.
fn band_bits(channel: Profile) -> u32 {
    if channel.is_5ghz() {
        ((CFGCH_BAND1_5G << RR_CFGCH_BAND1.trailing_zeros()) & RR_CFGCH_BAND1)
            | ((CFGCH_BAND0_5G << RR_CFGCH_BAND0.trailing_zeros()) & RR_CFGCH_BAND0)
    } else {
        0
    }
}
/// rtw8852b_rfk.c `_bw_setting` RR_CFGCH_BW field per width (`None` for
/// 160MHz: rtw8852b.c `support_bandwidths` has none, `_bw_setting` fails).
fn bw_bits(channel: Profile) -> Option<u32> {
    let bw = match channel.width() {
        Width::Mhz20 => CFGCH_BW_20M,
        Width::Mhz40 => CFGCH_BW_40M,
        Width::Mhz80 => CFGCH_BW_80M,
        Width::Mhz160 => return None,
    };
    Some((bw << RR_CFGCH_BW.trailing_zeros()) & RR_CFGCH_BW)
}
/// rtw8852b_rfk.c `_set_rxbb_bw` RR_LUTWD0 LB value per width.
const fn rxbb_lb(channel: Profile) -> Option<u32> {
    match channel.width() {
        Width::Mhz20 => Some(0x1b),
        Width::Mhz40 => Some(0x13),
        Width::Mhz80 => Some(0xb),
        Width::Mhz160 => None,
    }
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
    /// Linux `_ch_setting`: `direct=false` is the DAV RR_CFGCH word.
    async fn channel(&mut self, p: u8, direct: bool, channel: Profile) -> Result<(), Error> {
        let primary = channel.center();
        let a = if direct { RR_CFGCH_V1 } else { RR_CFGCH };
        let mut v = self.read(p, a, RFREG_MASK).await?;
        v &= !(RR_CFGCH_BAND1
            | RR_CFGCH_POW_LCK
            | RR_CFGCH_TRX_AH
            | RR_CFGCH_BCN
            | RR_CFGCH_BAND0
            | RR_CFGCH_CH);
        v |= (u32::from(primary) << RR_CFGCH_CH.trailing_zeros()) & RR_CFGCH_CH;
        v |= band_bits(channel);
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
    async fn bandwidth(&mut self, p: u8, direct: bool, channel: Profile) -> Result<(), Error> {
        let a = if direct { RR_CFGCH_V1 } else { RR_CFGCH };
        let mut v = self.read(p, a, RFREG_MASK).await?;
        v = (v & !RR_CFGCH_BW) | bw_bits(channel).ok_or(Error::Terminal)?;
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
        // SAFETY: same contract; fixed original channel1 profile.
        unsafe { self.prepare_for_channel(io, Profile::INITIAL).await }
    }
    /// # Safety
    /// Same as [`Self::prepare`], and the current signed envelope plus host
    /// permission cover THIS actual typed primary's synth/LCK emissions.
    pub async unsafe fn prepare_for_channel(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
    ) -> Result<(), Error> {
        // SAFETY: same contract; RTL8852B programs RF paths A and B.
        unsafe { self.prepare_paths(io, channel, 2).await }
    }
    /// rtw8851b_rfk.c `rtw8851b_set_channel_rf`: the same `_ctrl_ch`
    /// (`_set_s0_arfc18` + `_lck_check` on the path-A RR_CFGCH word),
    /// `_ctrl_bw` and `_rxbb_bw` source order on RF path A only
    /// (`RF_PATH_NUM_8851B` = 1, `_kpath` = RF_A).
    ///
    /// # Safety
    /// Same as [`Self::prepare_for_channel`] on an actual RTL8851B with
    /// completed RTL8851B RFK init.
    pub async unsafe fn prepare_for_channel_51(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
    ) -> Result<(), Error> {
        // SAFETY: forwarded; one RF path.
        unsafe { self.prepare_paths(io, channel, 1).await }
    }
    async unsafe fn prepare_paths(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        paths: u8,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        // rtw8852b.c `support_bandwidths` has no 160MHz: refused before any
        // RF write.
        let (Some(bw), Some(lb)) = (bw_bits(channel), rxbb_lb(channel)) else {
            return Err(Error::Terminal);
        };
        self.state = State::Preparing;
        let mut a = Access(io);
        for direct in [false, true] {
            for p in 0..paths {
                a.channel(p, direct, channel).await?;
            }
        }
        for direct in [false, true] {
            for p in 0..paths {
                a.bandwidth(p, direct, channel).await?;
            }
        }
        for p in 0..paths {
            a.write(p, RR_LUTWE2, RR_LUTWE2_RTXBW, 1).await?;
            a.write(p, RR_LUTWA, RR_LUTWA_M2, 0x12).await?;
            a.write(p, RR_LUTWD0, RR_LUTWD0_LB, lb).await?;
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
        let expected = ((u32::from(channel.center()) << RR_CFGCH_CH.trailing_zeros())
            & RR_CFGCH_CH)
            | band_bits(channel)
            | bw
            | RR_CFGCH_BW2;
        for direct in [false, true] {
            for p in 0..paths {
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
