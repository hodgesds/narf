// SPDX-License-Identifier: ISC
//! D11AC channel geometry from Linux brcmfmac/cfg80211.c and brcmutil/d11.c.
//! Firmware valid-channel discovery and host policy remain separate gates.

/// Exact brcmfmac __wl_5ghz_channels set. No 6 GHz/4.9 GHz alias inference.
pub(super) const CHANNELS_5GHZ: [u8; 29] = [
    34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132,
    136, 140, 144, 149, 153, 157, 161, 165,
];

pub(super) fn frequency(channel: u8) -> Option<u32> {
    match channel {
        1..=13 => Some(2407 + 5 * u32::from(channel)),
        14 => Some(2484),
        ch if CHANNELS_5GHZ.contains(&ch) => Some(5000 + 5 * u32::from(ch)),
        _ => None,
    }
}

pub(super) fn from_frequency(mhz: u32) -> Option<u8> {
    let channel = match mhz {
        2484 => 14,
        2412..=2472 if (mhz - 2407) % 5 == 0 => (mhz - 2407) / 5,
        5170..=5825 if mhz % 5 == 0 => (mhz - 5000) / 5,
        _ => return None,
    };
    let channel = u8::try_from(channel).ok()?;
    (frequency(channel) == Some(mhz)).then_some(channel)
}

/// Initial operating channel is 20 MHz with no sideband.
pub(super) fn encode20(channel: u8) -> Option<u16> {
    frequency(channel)?;
    Some(if channel <= 14 { 0x1000 } else { 0xd000 } | u16::from(channel))
}

/// One retained occupied channel. A40MHz geometry is usable only when the
/// firmware's native chanspec inventory also contains this exact encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Operating {
    pub(super) primary: u8,
    pub(super) secondary: Option<u8>,
    center80: Option<u8>,
}
impl Operating {
    pub(super) fn twenty(primary: u8) -> Option<Self> {
        encode20(primary)?;
        Some(Self {
            primary,
            secondary: None,
            center80: None,
        })
    }
    pub(super) fn forty(primary: u8, secondary: u8) -> Option<Self> {
        let a = frequency(primary)?;
        let b = frequency(secondary)?;
        if primary == 14
            || secondary == 14
            || a.abs_diff(b) != 20
            || (primary <= 14) != (secondary <= 14)
        {
            return None;
        }
        Some(Self {
            primary,
            secondary: Some(secondary),
            center80: None,
        })
    }
    pub(super) fn eighty(primary: u8, center: u8) -> Option<Self> {
        if ![42, 58, 106, 122, 138, 155, 171].contains(&center) {
            return None;
        }
        let channels = [center - 6, center - 2, center + 2, center + 6];
        if channels
            .iter()
            .any(|ch| *ch <= 14 || frequency(*ch).is_none())
        {
            return None;
        }
        let index = channels.iter().position(|ch| *ch == primary)?;
        let mut value = Self::forty(primary, channels[index ^ 1])?;
        value.center80 = Some(center);
        Some(value)
    }
    pub(super) fn constituents(self) -> [Option<u8>; 4] {
        if let Some(c) = self.center80 {
            [Some(c - 6), Some(c - 2), Some(c + 2), Some(c + 6)]
        } else {
            [Some(self.primary), self.secondary, None, None]
        }
    }
    pub(super) fn width(self) -> u32 {
        if self.center80.is_some() {
            80
        } else if self.secondary.is_some() {
            40
        } else {
            20
        }
    }
    pub(super) fn chanspec(self) -> u16 {
        if let Some(center) = self.center80 {
            let side = (u16::from(self.primary) + 6 - u16::from(center)) / 4;
            return 0xe000 | (side << 8) | u16::from(center);
        }
        if let Some(secondary) = self.secondary {
            let center = (u16::from(self.primary) + u16::from(secondary)) / 2;
            let side = if self.primary > secondary { 0x100 } else { 0 };
            (if self.primary <= 14 { 0x1800 } else { 0xd800 }) | side | center
        } else {
            encode20(self.primary).expect("validated operating channel")
        }
    }
    pub(super) fn span(self) -> (u32, u32) {
        if let Some(center) = self.center80 {
            let center = 5000 + u32::from(center) * 5;
            return (center - 40, center + 40);
        }
        let a = frequency(self.primary).expect("validated primary channel");
        let b = self
            .secondary
            .map_or(a, |ch| frequency(ch).expect("validated secondary channel"));
        (a.min(b) - 10, a.max(b) + 10)
    }
    pub(super) fn decode40(chanspec: u16) -> Option<Self> {
        if chanspec & 0x3800 != 0x1800 {
            return None;
        }
        let primary = primary(chanspec, 0)?;
        let secondary = if chanspec & 0x700 == 0 {
            primary.checked_add(4)?
        } else {
            primary.checked_sub(4)?
        };
        let value = Self::forty(primary, secondary)?;
        (value.chanspec() == chanspec).then_some(value)
    }
    pub(super) fn decode80(chanspec: u16) -> Option<Self> {
        if chanspec & 0xf800 != 0xe000 {
            return None;
        }
        let value = Self::eighty(primary(chanspec, 0)?, (chanspec & 255) as u8)?;
        (value.chanspec() == chanspec).then_some(value)
    }
}

/// Decode the advertised primary channel, including a wider AP's center and
/// sideband. Never reinterpret a center channel as its primary. A supplied
/// BSS-info ctl_ch must agree with the independently decoded chanspec.
pub(super) fn primary(chanspec: u16, ctl_ch: u8) -> Option<u8> {
    let center = i16::from((chanspec & 255) as u8);
    if center == 0 {
        return None;
    }
    let side = ((chanspec >> 8) & 7) as i16;
    let offset = match chanspec & 0x3800 {
        0x1000 if side == 0 => 0,
        0x1800 if side < 2 => side * 4 - 2,
        0x2000 if side < 4 => side * 4 - 6,
        0x2800 => side * 4 - 14,
        _ => return None,
    };
    let channel = u8::try_from(center + offset).ok()?;
    frequency(channel)?;
    let band = if channel <= 14 { 0 } else { 0xc000 };
    if chanspec & 0xc000 != band
        || ctl_ch != 0 && ctl_ch != channel
        || band == 0 && chanspec & 0x3800 > 0x1800
        || channel == 14 && chanspec & 0x3800 != 0x1000
    {
        return None;
    }
    Some(channel)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_tests.rs"]
mod tests;
