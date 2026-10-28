//! Legacy 20 MHz channel geometry from Linux mt76/mac80211.c.
//! 6 GHz channel numbers overlap the 2.4/5 GHz numbering, so they never enter
//! [`band`]; a 6 GHz channel is always carried with an explicit
//! [`Band::Ghz6`] (see [`rx_channel`] / [`from_rx_channel`] for the RXD
//! encoding).
use alloc::vec::Vec;

pub(crate) const CHANNELS_5GHZ: [u8; 28] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Band {
    Ghz2,
    Ghz5,
    /// Linux v7.2 `NL80211_BAND_6GHZ`. Never derived from a bare channel
    /// number; gated on the NIC `MT_NIC_CAP_6G` TLV, not on `phy.bands`.
    Ghz6,
}

impl Band {
    /// The `MT_NIC_CAP_PHY` band bit. 6 GHz has none (its capability is the
    /// separate `has_6ghz` TLV), so its bit never matches `phy.bands & 3`.
    pub(crate) fn capability(self) -> u8 {
        self.scan_tag()
    }
    /// mt76_connac_mcu_hw_scan / tx_power_limit_tlv / config_sniffer band:
    /// 2.4 GHz 1, 5 GHz 2, 6 GHz 3 (mt7921/mcu.c:1167).
    pub(crate) fn scan_tag(self) -> u8 {
        match self {
            Self::Ghz2 => 1,
            Self::Ghz5 => 2,
            Self::Ghz6 => 3,
        }
    }
    /// mt7921_mcu_set_chan_info `channel_band`: the nl80211 band, except
    /// that 6 GHz is 2 (mt7921/mcu.c:892).
    pub(crate) fn switch_tag(self) -> u8 {
        self.scan_tag() - 1
    }
    /// UNI_BSS_INFO_RLM `band`: the raw nl80211 band
    /// (mt76_connac_mcu_uni_set_chctx), `NL80211_BAND_6GHZ` = 3.
    pub(crate) fn nl80211(self) -> u8 {
        match self {
            Self::Ghz2 => 0,
            Self::Ghz5 => 1,
            Self::Ghz6 => 3,
        }
    }
}

/// 6 GHz 20 MHz channel numbers 1, 5, ..., 233 (cfg80211
/// `ieee80211_channel_to_freq_khz`: 5950 + 5n MHz).
pub(crate) fn channels_6ghz() -> impl Iterator<Item = u8> {
    (1..=233u8).step_by(4)
}

/// The CONNAC2 RXD3 `CH_FREQ` value for a channel, as decoded by Linux
/// `mt792x_get_status_freq_info`: 6 GHz channel n is `181 + (n - 1) / 4`.
pub(crate) fn rx_channel(band: Band, channel: u8) -> Option<u8> {
    match band {
        Band::Ghz6 => (narf_wireless::association::channel::valid_6ghz(channel)
            && channel % 4 == 1)
            .then(|| 181 + (channel - 1) / 4),
        _ => (self::band(channel) == Some(band)).then_some(channel),
    }
}

/// Inverse of [`rx_channel`] (`mt792x_get_status_freq_info`): values above
/// 180 are 6 GHz, above 14 are 5 GHz, the rest 2.4 GHz.
pub(crate) fn from_rx_channel(value: u8) -> Option<(Band, u8)> {
    if value > 180 {
        let channel = (value - 181).checked_mul(4)?.checked_add(1)?;
        narf_wireless::association::channel::valid_6ghz(channel).then_some((Band::Ghz6, channel))
    } else {
        band(value).map(|band| (band, value))
    }
}

/// The centre frequency of a channel in an explicit band.
pub(crate) fn frequency_in(band: Band, channel: u8) -> Option<u32> {
    match band {
        Band::Ghz6 => narf_wireless::association::channel::frequency_in(
            narf_wireless::association::channel::Band::Ghz6,
            channel,
        ),
        _ => frequency(channel).filter(|_| self::band(channel) == Some(band)),
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
        Band::Ghz6 => return None,
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

/// Contiguous 5-GHz80-MHz centers and four20-MHz constituents. Keep the
/// UNII discontinuity between144/149 explicit; array adjacency is not RF
/// geometry. cfg80211_chandef_valid/primary and IEEE VHT operation channel.
pub(crate) fn block80(primary: u8, center: u8) -> Option<[u8; 4]> {
    if ![42, 58, 106, 122, 138, 155, 171].contains(&center) {
        return None;
    }
    let first = center.checked_sub(6)?;
    let channels = [first, first + 4, first + 8, first + 12];
    (channels.contains(&primary) && channels.iter().all(|ch| band(*ch) == Some(Band::Ghz5)))
        .then_some(channels)
}
/// Contiguous160 blocks, each containing eight real20MHz channels. Do not
/// join the128/132 or144/149 discontinuities into an invented wide channel.
pub(crate) fn block160(primary: u8, center: u8) -> Option<[u8; 8]> {
    if ![50, 114, 163].contains(&center) {
        return None;
    }
    let first = center.checked_sub(14)?;
    let channels = core::array::from_fn(|index| first + index as u8 * 4);
    (channels.contains(&primary) && channels.iter().all(|ch| band(*ch) == Some(Band::Ghz5)))
        .then_some(channels)
}
