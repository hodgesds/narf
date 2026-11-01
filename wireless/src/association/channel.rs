//! Shared legacy 20MHz channel geometry from Linux mt76/mac80211.c.
//! Full-rate2.4GHz channels1–13 have regular5MHz spacing; channel14 is absent.
//! Channel numbers with the CONNAC2 6 GHz flag never enter this profile.
use alloc::vec::Vec;

pub const CHANNELS_5GHZ: [u8; 28] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    Ghz2,
    Ghz5,
    /// 6 GHz (IEEE802.11ax-2021 27.3.23.2). Its channel numbers collide with
    /// 2.4/5 GHz ones, so `band(u8)` never returns it; callers carry it.
    Ghz6,
}

pub fn band(channel: u8) -> Option<Band> {
    if (1..=13).contains(&channel) {
        Some(Band::Ghz2)
    } else if CHANNELS_5GHZ.contains(&channel) {
        Some(Band::Ghz5)
    } else {
        None
    }
}

pub fn frequency(channel: u8) -> Option<u32> {
    frequency_in(band(channel)?, channel)
}

/// cfg80211 `ieee80211_channel_to_freq_khz` (in MHz) for `band`. The 2.4/5
/// GHz results are limited to this profile's channels (`band(channel)`);
/// 6 GHz includes the source-supported UNII-9 tail through253 and channel2
/// (5935MHz). This geometry grants no device/regulatory permission.
pub fn frequency_in(band_id: Band, channel: u8) -> Option<u32> {
    match band_id {
        Band::Ghz2 | Band::Ghz5 if band(channel) != Some(band_id) => None,
        Band::Ghz2 => Some(2407 + 5 * u32::from(channel)),
        Band::Ghz5 => Some(5000 + 5 * u32::from(channel)),
        Band::Ghz6 if channel == 2 => Some(5935),
        Band::Ghz6 if valid_6ghz(channel) => Some(5950 + 5 * u32::from(channel)),
        Band::Ghz6 => None,
    }
}

/// A 6 GHz channel number of any width: 20 MHz channels1+4k through253
/// and the 40/80/160/320 MHz centre numbers (3 + 8k, 7 + 16k, 15 + 32k,
/// 31+32k), matching `ieee80211_channel_to_freq_khz`'s explicit253 bound.
pub fn valid_6ghz(channel: u8) -> bool {
    (1..=253).contains(&channel) && channel % 2 == 1
}

/// `ieee80211_freq_khz_to_channel` plus the band: 2.4/5 GHz in this profile
/// (`from_frequency`) and 6 GHz5935MHz /5955..=7215MHz.
pub fn from_frequency_band(mhz: u32) -> Option<(Band, u8)> {
    if let Some(channel) = from_frequency(mhz) {
        return band(channel).map(|band| (band, channel));
    }
    if mhz == 5935 {
        return Some((Band::Ghz6, 2));
    }
    let channel = u8::try_from(mhz.checked_sub(5950)? / 5).ok()?;
    (mhz % 5 == 0 && frequency_in(Band::Ghz6, channel) == Some(mhz))
        .then_some((Band::Ghz6, channel))
}

pub fn from_frequency(mhz: u32) -> Option<u8> {
    let channel = match mhz {
        2412..=2472 if (mhz - 2407) % 5 == 0 => u8::try_from((mhz - 2407) / 5).ok()?,
        5180..=5885 if mhz % 5 == 0 => u8::try_from((mhz - 5000) / 5).ok()?,
        _ => return None,
    };
    frequency(channel)
        .filter(|value| *value == mhz)
        .map(|_| channel)
}

pub fn channels(bands: u8) -> Vec<u8> {
    let mut channels = Vec::new();
    if bands & 1 != 0 {
        channels.extend(1..=13);
    }
    if bands & 2 != 0 {
        channels.extend(CHANNELS_5GHZ);
    }
    channels
}
