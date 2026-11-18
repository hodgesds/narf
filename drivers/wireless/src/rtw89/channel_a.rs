// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A MAC_0/PHY_0, non-DBCC channel control and TX-power composition.
//! Linux rtw8852a.c `rtw8852a_set_channel{,_mac,_bb,_help}` and their
//! channel/BW, SCO, spur and reset subroutines. This owner establishes
//! Programmed, never Calibrated: channel RFK needs separate live inputs.
use super::{
    operating_channel::{Profile, Width},
    power,
    radio_power_c::Plan,
    rfk::{Error, Interface},
};

/// Added to the signed A board identity when native channel control is
/// composed. Old records cannot silently authorize this new RF program.
pub(super) const RECIPE: &[u8] = b"RTL8852A native MAC0 PHY0 non-DBCC channel control v1: source set_channel_help, set_channel_mac, ctrl_sco_cck, ctrl_ch RF18 A/B, ctrl_bw RF18 A/B, set_channel_bb CCA/reset/spur/raw primary, Plan::visit_a_channel byrate/offset/limit/RU only, help exit/coex band notify; readback and current admission per access; Programmed only, no channel-RFK completion or ordinary station/AP admission";

const PHY: u32 = 0x10000;
const RF_MASK: u32 = 0xf_ffff;
const BARKER: [u32; 14] = [
    0x1cfea, 0x1d0e1, 0x1d1d7, 0x1d2cd, 0x1d3c3, 0x1d4b9, 0x1d5b0, 0x1d6a6, 0x1d79c, 0x1d892,
    0x1d988, 0x1da7f, 0x1db75, 0x1ddc4,
];
const CCK: [u32; 14] = [
    0x27de3, 0x27f35, 0x28088, 0x281da, 0x2832d, 0x2847f, 0x285d2, 0x28724, 0x28877, 0x289c9,
    0x28b1c, 0x28c6e, 0x28dc1, 0x290ed,
];
const FIR: [u32; 8] = [
    0x3d23ff, 0x29b354, 0xfc1c8, 0xfdb053, 0xf86f9a, 0xfaef92, 0xfe5fcc, 0xffdff5,
];
const FIR14: [u32; 8] = [
    0x3b13ff, 0x1c42de, 0xfdb0ad, 0xf60f6e, 0xfd8f92, 0x2d011, 0x1c02c, 0xfff00a,
];

/// `rtw8852a_ctrl_sco_cck`: the source's HT40 primary-channel-1
/// special case selects center+2; all other HT40 profiles select center-2.
fn sco(profile: Profile) -> Option<[u32; 2]> {
    if profile.is_5ghz() {
        return None;
    }
    let channel = match profile.width() {
        Width::Mhz20 => profile.center(),
        Width::Mhz40 if profile.primary() == 1 => profile.center() + 2,
        Width::Mhz40 => profile.center() - 2,
        _ => return None,
    };
    let i = usize::from(channel.checked_sub(1)?);
    Some([*BARKER.get(i)?, *CCK.get(i)?])
}

struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    fn step(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        let expected = if mask == u32::MAX {
            value
        } else {
            self.0.admit()?;
            let old = self.0.read32(address)?;
            if old == u32::MAX {
                return Err(power::Error::Gone.into());
            }
            (old & !mask) | ((value << mask.trailing_zeros()) & mask)
        };
        self.0.admit()?;
        self.0.write32(address, expected)?;
        self.0.admit()?;
        let actual = self.0.read32(address)?;
        if actual == u32::MAX || actual & mask != expected & mask {
            return Err(power::Error::Access.into());
        }
        Ok(())
    }
    fn bb(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.step(PHY + address, mask, value)
    }
    fn byte(&mut self, address: u32, mask: u8, value: u8) -> Result<(), Error> {
        self.0.admit()?;
        let old = self.0.read8(address)?;
        if old == u8::MAX {
            return Err(power::Error::Gone.into());
        }
        let expected = (old & !mask) | (value & mask);
        self.0.admit()?;
        self.0.write8(address, expected)?;
        self.0.admit()?;
        if self.0.read8(address)? != expected {
            return Err(power::Error::Access.into());
        }
        Ok(())
    }
    async fn rf_read(&mut self, path: u8) -> Result<u32, Error> {
        self.0.admit()?;
        let value = self.0.rf_read(path, 0x18, RF_MASK).await?;
        if value == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        Ok(value)
    }
    async fn rf_write(&mut self, path: u8, value: u32) -> Result<(), Error> {
        self.0.admit()?;
        self.0.rf_write(path, 0x18, RF_MASK, value).await?;
        if self.rf_read(path).await? != value & RF_MASK {
            return Err(power::Error::Access.into());
        }
        Ok(())
    }
    async fn delay(&mut self, us: u64) -> Result<(), Error> {
        self.0.admit()?;
        self.0.delay_us(us).await;
        self.0.admit()
    }
    fn reset(&mut self) -> Result<(), Error> {
        for value in [1, 0, 1] {
            self.bb(0x0704, 1 << 1, value)?;
        }
        Ok(())
    }
    fn tssi_continue(&mut self, enabled: bool) -> Result<(), Error> {
        for path in 0..2u32 {
            self.bb(0x58dc + (path << 13), 1 << 30, u32::from(!enabled))?;
            self.bb(0x5818 + (path << 13), 1 << 30, u32::from(!enabled))?;
        }
        Ok(())
    }
    async fn enter(&mut self) -> Result<u32, Error> {
        self.0.admit()?;
        let saved = self.0.pause().await?;
        self.step(0xce40, 1, 0)?;
        self.bb(0, 1 << 31, 0)?;
        self.tssi_continue(false)?;
        self.bb(0x20fc, 0xff00_0000, 0xf)?;
        self.delay(40).await?;
        self.bb(0x0704, 1 << 1, 0)?;
        Ok(saved)
    }
    async fn leave(&mut self, saved: u32) -> Result<(), Error> {
        self.step(0xce40, u32::MAX, 0x2b)?;
        self.step(0x9c18, 3, 2)?;
        self.bb(0x20fc, 0xff00_0000, 0)?;
        self.bb(0, 1 << 31, 1)?;
        self.tssi_continue(true)?;
        self.bb(0x0704, 1 << 1, 1)?;
        self.0.admit()?;
        self.0.resume(saved).await?;
        self.0.admit()
    }
    fn mac(&mut self, profile: Profile) -> Result<(), Error> {
        let (mode, subcarrier) = match profile.width() {
            Width::Mhz20 => (0, 0),
            Width::Mhz40 => (1, u32::from(profile.txsc(Width::Mhz20))),
            Width::Mhz80 => (
                2,
                u32::from(profile.txsc(Width::Mhz20))
                    | (u32::from(profile.txsc(Width::Mhz40)) << 4),
            ),
            Width::Mhz160 => return Err(Error::Policy),
        };
        self.byte(0xc010, 3, mode)?;
        self.step(0xc088, u32::MAX, subcarrier)?;
        // A changes only CHECK_CCK_EN/RTS_LIMIT_IN_OFDM6, preserving
        // BAND_MODE (unlike rtw8852c_set_channel_mac).
        self.byte(0xc628, 3, if profile.is_5ghz() { 3 } else { 0 })
    }
    async fn channel(&mut self, profile: Profile) -> Result<(), Error> {
        let g2 = u32::from(!profile.is_5ghz());
        for (path, mode) in [(0, 0x4644), (1, 0x4718)] {
            let old = self.rf_read(path).await?;
            let value = (old & !0x3_03ff)
                | u32::from(profile.center())
                | if profile.is_5ghz() { 0x1_0100 } else { 0 };
            self.rf_write(path, value).await?;
            self.bb(mode, 0xc000_0000, g2)?;
        }
        // A and B have byte-identical rtw8852{a,b}_sco_mapping tables.
        self.bb(0x4974, 0x7f, profile.sco_compensation())?;
        self.bb(0x4498, 1 << 30, g2)?;
        let fir = if profile.center() == 14 { FIR14 } else { FIR };
        for (i, value) in fir.into_iter().enumerate() {
            self.bb(0x2300 + 4 * i as u32, 0xff_ffff, value)?;
        }
        Ok(())
    }
    async fn bandwidth(&mut self, profile: Profile) -> Result<(), Error> {
        let (mode, rf_bw) = match profile.width() {
            Width::Mhz20 => (0, 0xc00),
            Width::Mhz40 => (1, 0x800),
            Width::Mhz80 => (2, 0x400),
            Width::Mhz160 => return Err(Error::Policy),
        };
        self.bb(0x4974, 0xc000_0000, mode)?;
        self.bb(0x4978, 0x3000, 0)?;
        self.bb(0x4978, 0xf00, u32::from(profile.pri_ch_idx()))?;
        if profile.width() == Width::Mhz40 {
            self.bb(0x237c, 1, u32::from(profile.pri_ch_idx() == 1))?;
        }
        for path in 0..2 {
            let old = self.rf_read(path).await?;
            self.bb(0x12d0 + (u32::from(path) << 13), 0x6000, 0)?;
            self.bb(0x12ec + (u32::from(path) << 13), 0x30, 2)?;
            self.rf_write(path, (old & !0xc00) | rf_bw).await?;
        }
        Ok(())
    }
    fn spur(&mut self, center: u8) -> Result<(), Error> {
        let terms = match center {
            153 => Some((0x210, 0x7c0)),
            151 => Some((0x210, 0x40)),
            155 => Some((0x2d0, 0x740)),
            _ => None,
        };
        if let Some((notch, csi)) = terms {
            self.bb(0x469c, 0xfff, notch)?;
            self.bb(0x4770, 0xfff, notch)?;
            self.bb(0x42ac, 0x7ff, csi)?;
        }
        let enabled = u32::from(terms.is_some());
        self.bb(0x469c, 1 << 12, enabled)?;
        self.bb(0x4770, 1 << 12, enabled)?;
        self.bb(0x42c4, 1 << 23, enabled)
    }
    async fn bb_channel(&mut self, profile: Profile) -> Result<(), Error> {
        if let Some([barker, cck]) = sco(profile) {
            self.bb(0x23b0, 0x7ffff, barker)?;
            self.bb(0x23b4, 0x7ffff, cck)?;
        }
        self.channel(profile).await?;
        self.bandwidth(profile).await?;
        self.bb(0x2344, 1 << 31, u32::from(profile.is_5ghz()))?;
        if profile.is_5ghz() {
            self.bb(0x5818, 1 << 30, 1)?;
            self.bb(0x7818, 1 << 30, 1)?;
            self.reset()?;
            self.bb(0x5818, 1 << 30, 0)?;
            self.bb(0x7818, 1 << 30, 0)?;
            self.delay(1).await?;
        }
        self.spur(profile.center())?;
        // A records the primary channel directly, not C's encoded index.
        self.bb(0x0734, 0xff_0000, u32::from(profile.primary()))?;
        self.reset()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Busy,
    Programmed,
}

#[derive(Default)]
pub(super) struct Channel {
    state: State,
    programmed: Option<Profile>,
}
impl Channel {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn programmed(&self) -> Option<Profile> {
        (self.state == State::Programmed)
            .then_some(self.programmed)
            .flatten()
    }
    /// core.c `__rtw89_set_channel`: scheduler/help enter, A MAC/BB/RF
    /// program, `rtw8852a_set_txpwr`, then help exit. This grants no
    /// channel-RFK completion or ordinary station readiness.
    ///
    /// # Safety
    /// Actual A MAC0/PHY0, non-DBCC after A tables/DM/RFK init. Exclusive
    /// WLAN-only coexistence and exclusive radio/reset/PM ownership,
    /// ordinary TX and autonomous responses
    /// closed. Current signed A records and host policy cover this exact
    /// profile and `Plan::from_elements_a` plan. Every access rechecks
    /// through Interface; caller terminalizes/retains uncertain ownership
    /// on failure/cancellation and never treats Programmed as Calibrated.
    pub async unsafe fn set_channel(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        power: &Plan,
    ) -> Result<(), Error> {
        if profile.width() == Width::Mhz160
            || power.channel().primary() != profile.primary()
            || power.channel().primary_mhz() != profile.mhz()
            || power.channel().center() != profile.center()
            || power.channel().width().mhz() != profile.width().mhz()
        {
            return Err(Error::Policy);
        }
        if !matches!(self.state, State::New | State::Programmed) {
            return Err(Error::Terminal);
        }
        let band_changed = self.programmed.map(|p| p.is_5ghz()) != Some(profile.is_5ghz());
        self.state = State::Busy;
        self.programmed = None;
        let mut access = Access(io);
        let saved = access.enter().await?;
        access.mac(profile)?;
        access.bb_channel(profile).await?;
        power.visit_a_channel(|a, m, v| access.step(a, m, v))?;
        access.leave(saved).await?;
        if band_changed {
            access.0.admit()?;
            access.0.coex_switch_band().await?;
            access.0.admit()?;
            // TSSI scan is inactive until the separate A channel RFK
            // enables both paths; no thermal values are fabricated here.
        }
        self.programmed = Some(profile);
        self.state = State::Programmed;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_a/tests.rs"]
pub(super) mod tests;
