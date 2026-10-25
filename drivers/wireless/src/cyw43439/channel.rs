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
