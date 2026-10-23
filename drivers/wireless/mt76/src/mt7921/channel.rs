//! Legacy 20 MHz channel geometry from Linux mt76/mac80211.c.
//! Channel numbers with the CONNAC2 6 GHz flag never enter this profile.
use alloc::vec::Vec;

pub(crate) const CHANNELS_5GHZ: [u8; 28] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Band {
    Ghz2,
    Ghz5,
}

impl Band {
    pub(crate) fn capability(self) -> u8 {
        self.scan_tag()
    }
    pub(crate) fn scan_tag(self) -> u8 {
        match self {
            Self::Ghz2 => 1,
            Self::Ghz5 => 2,
        }
    }
    pub(crate) fn switch_tag(self) -> u8 {
        self.scan_tag() - 1
    }
}

pub(crate) fn band(channel: u8) -> Option<Band> {
    if (1..=11).contains(&channel) {
        Some(Band::Ghz2)
    } else if CHANNELS_5GHZ.contains(&channel) {
        Some(Band::Ghz5)
    } else {
        None
    }
}

pub(crate) fn frequency(channel: u8) -> Option<u32> {
    Some(match band(channel)? {
        Band::Ghz2 => 2407 + 5 * u32::from(channel),
        Band::Ghz5 => 5000 + 5 * u32::from(channel),
    })
}

pub(crate) fn from_frequency(mhz: u32) -> Option<u8> {
    let channel = match mhz {
        2412..=2462 if (mhz - 2407) % 5 == 0 => u8::try_from((mhz - 2407) / 5).ok()?,
        5180..=5885 if mhz % 5 == 0 => u8::try_from((mhz - 5000) / 5).ok()?,
        _ => return None,
    };
    frequency(channel)
        .filter(|value| *value == mhz)
        .map(|_| channel)
}

pub(crate) fn channels(bands: u8) -> Vec<u8> {
    let mut channels = Vec::new();
    if bands & 1 != 0 {
        channels.extend(1..=11);
    }
    if bands & 2 != 0 {
        channels.extend(CHANNELS_5GHZ);
    }
    channels
}
