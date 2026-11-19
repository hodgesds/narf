// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! rtw8852a_rfk.c::_tssi_high_power/_tssi_pre_tx and rtw8852a.c PMAC helpers.
use super::*;
use crate::rtw89::{
    mac::ChipId,
    power,
    radio_assets::Assets,
    radio_power_c::{Rules, RS_MCS, RS_OFDM},
};
#[path = "a_pmac_table.rs"]
mod plcp;

pub(in crate::rtw89) const RECIPE: &[u8] = b"RTL8852A complete TSSI high_power/pre_tx v1; exact WW/noDAG/noSAR MCS currentBW1TX nonBF lower20 + OFDM20 lower20; high_power qdbm>1800 on2G else source tracking table; source HT20MCS7 fullword PLCP, MAC_SEL PHY1 aliases PHY0 in SCC, AB path3 NSS4 and pathB reset1/3; source pre_tx s16 power (power*100>>1)>1800?68:power*2; DPK START, scheduler stop/RXidle, counter16, PMAC20 count/5000 period,15ms, exact source stop/TMAC, actual counter and optional offsets retained; source closure on drop, no invented measurement";

/// Pure exact source queries from this retained A firmware container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Inputs {
    profile: Profile,
    mcs: i8,
    ofdm: i8,
}
impl Inputs {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtw89) fn fixture(profile: Profile, mcs: i8, ofdm: i8) -> Self {
        Self { profile, mcs, ofdm }
    }
    pub fn profile(self) -> Profile {
        self.profile
    }
    pub fn matches(self, profile: Profile) -> bool {
        self.profile == profile
    }
    pub fn from_assets(assets: &Assets, rfe: u8, profile: Profile) -> Result<Self, Error> {
        if assets.chip() != ChipId::Rtl8852A || profile.band() == Band::Ghz6 {
            return Err(Error::Table);
        }
        let lower = profile
            .center()
            .checked_sub(match profile.width() {
                crate::rtw89::operating_channel_c::Width::Mhz20 => 0,
                crate::rtw89::operating_channel_c::Width::Mhz40 => 2,
                crate::rtw89::operating_channel_c::Width::Mhz80 => 6,
                _ => return Err(Error::Policy),
            })
            .ok_or(Error::Policy)?;
        let rules = Rules::for_channel(assets.elements(), rfe, profile.band(), None)?;
        Ok(Self {
            profile,
            mcs: rules.limit(profile.width() as u8, 0, RS_MCS, 0, lower),
            ofdm: rules.limit(0, 0, RS_OFDM, 0, lower),
        })
    }
    pub fn bind(&self, h: &mut narf_crypto::sha256::Sha256) {
        h.update(RECIPE);
        h.update(&[
            self.profile.band() as u8,
            self.profile.primary(),
            self.profile.center(),
            self.profile.width() as u8,
            self.mcs as u8,
            self.ofdm as u8,
        ]);
        for &(a, v) in plcp::PLCP {
            h.update(&a.to_le_bytes());
            h.update(&v.to_le_bytes());
        }
    }
    fn power(self) -> i16 {
        if (i32::from(self.ofdm) * 100) >> 1 > 1800 {
            68
        } else {
            i16::from(self.ofdm) * 2
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Report {
    pub before: u16,
    pub after: u16,
    pub count: u32,
    pub power: i16,
    pub default_txagc: [Option<u8>; 2],
    pub retained_default_txagc: [Option<u8>; 2],
}
fn set(
    a: &mut Access<'_, impl Interface>,
    address: u32,
    mask: u32,
    value: u32,
) -> Result<(), Error> {
    a.wm(address, mask, value)?;
    if a.bb(address, mask)? != value & (mask >> mask.trailing_zeros()) {
        return Err(power::Error::Access.into());
    }
    Ok(())
}
fn hw_tx(a: &mut Access<'_, impl Interface>, input: Inputs, enable: bool) -> Result<(), Error> {
    // Source replays PLCP/path/power even on disable. Keep this order.
    for &(address, value) in plcp::PLCP {
        set(a, address, u32::MAX, value)?;
    }
    set(a, 0x09a4, 0x1c, 7)?;
    set(a, 0x09a4, 0x1c, 7)?; // PHY1 maps to PHY0 unless DBCC.
    set(a, 0x458c, 0xf0000000, 3)?;
    set(a, 0x45b4, 0x1e0000, 4)?;
    set(a, 0x78dc, 0xc0000000, 1)?; // AB takes source's non-A branch.
    set(a, 0x78dc, 0xc0000000, 3)?;
    set(a, 0x09a4, 0x10000, 1)?;
    set(a, 0x4594, 0x7fc00000, input.power() as u32)?;
    if enable {
        set(a, 0x0980, 1, 1)?;
        set(a, 0x0980, 0x10000, 1)?;
        set(a, 0x0988, 0xfff, 0x3f)?;
        set(a, 0x0704, 2, 0)?;
        set(a, 0x0c3c, 0x200, 1)?;
        set(a, 0x2344, 0x80000000, 1)?;
        set(a, 0x0704, 2, 1)?;
        set(a, 0x09c4, 0x10, 1)?;
        set(a, 0x09c4, 0xffffff00, 5000)?;
        set(a, 0x09c8, u32::MAX, 20)?;
        set(a, 0x09c0, 1, 1)?;
        set(a, 0x09c0, 1, 0)?;
    } else {
        set(a, 0x09c4, 0x10, 0)?;
        set(a, 0x0c3c, 0x200, 0)?;
        if input.profile.band() == Band::Ghz2 {
            set(a, 0x2344, 0x80000000, 0)?;
        }
    }
    Ok(())
}
fn tmac(a: &mut Access<'_, impl Interface>) -> Result<(), Error> {
    for (address, mask) in [
        (0x0980, 1),
        (0x0980, 0x10000),
        (0x0988, 0xfff),
        (0x0994, 0xf0),
        (0x09a4, 0x400),
        (0x09a4, 0x1c),
        (0x09a4, 0x10000),
    ] {
        set(a, address, mask, 0)?;
    }
    Ok(())
}
impl Tssi {
    /// # Safety
    /// Same exclusive current A owner after the actual TSSI prefix on this
    /// channel. The new signed full recipe covers source PMAC emissions,
    /// exact firmware limits and the original native terminal closure.
    pub async unsafe fn finish_tail(
        &mut self,
        io: &mut impl Interface,
        input: Inputs,
    ) -> Result<(), Error> {
        if !self.programmed || self.complete.is_some() || self.profile != Some(input.profile) {
            return Err(Error::Terminal);
        }
        self.programmed = false; // failure/drop cannot publish prefix as complete.
        let mut a = Access(io);
        if i32::from(input.mcs) * 100 / 4 > 1800 && input.profile.band() == Band::Ghz2 {
            self.results.tracking_check = [true; 2];
        } else {
            a.table(TSSI_TRACKING_DEFS).await?;
            self.results.extra_ofst = [0; 2];
            self.results.tracking_check = [false; 2];
        }
        a.0.begin(Kind::Dpk).await?;
        let saved = a.0.pause().await?;
        a.a_wait_rx_mode().await?;
        let before = a.bb(0x1a40, 0xffff)? as u16;
        hw_tx(&mut a, input, true)?;
        a.delay(15_000).await?;
        hw_tx(&mut a, input, false)?;
        let after = a.bb(0x1a40, 0xffff)? as u16;
        // Source subtraction promotes u16 values to int then stores u32.
        let count = (i32::from(after) - i32::from(before)) as u32;
        let mut default_txagc = [None; 2];
        for (path, address) in [0x1c60, 0x3c60].into_iter().enumerate() {
            if a.bb(address, 0xffff0000)? != 0xc000 && a.bb(address, 0xffff0000)? != 0 {
                for _ in 0..6 {
                    let actual = a.bb(address, 0xff000000)? as u8;
                    default_txagc[path] = Some(actual);
                    if actual != 0 {
                        break;
                    }
                }
            }
            if let Some(actual) = default_txagc[path] {
                self.default_txagc[path] = Some(actual);
            }
        }
        tmac(&mut a)?;
        a.0.resume(saved).await?;
        a.0.end(Kind::Dpk).await?;
        a.0.admit()?;
        self.complete = Some(Report {
            before,
            after,
            count,
            power: input.power(),
            default_txagc,
            retained_default_txagc: self.default_txagc,
        });
        self.programmed = true;
        Ok(())
    }
}
