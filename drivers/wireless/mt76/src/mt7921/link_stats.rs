//! What the station keeps about its AP for NL80211_CMD_GET_STATION: the
//! last and averaged receive signal and the last receive rate (mac80211
//! `sta_set_sinfo` from `ieee80211_rx_status`, mt7921 `mt7921_mac_fill_rx` +
//! `mt76_connac2_mac_fill_rx_rate`), and the CONNAC2 rate-word decoder that
//! P-RXV and TXS share. Only frames from the associated BSSID count.
use narf_wireless::RateInfo;

/// `enum mt76_phy_type` (mt76.h).
const PHY_CCK: u8 = 0;
const PHY_OFDM: u8 = 1;
const PHY_HT: u8 = 2;
const PHY_HT_GF: u8 = 3;
const PHY_VHT: u8 = 4;
const PHY_HE_SU: u8 = 8;
const PHY_HE_MU: u8 = 11;

/// mac80211 `DECLARE_EWMA(signal, 10, 8)`: precision 10, weight 1/8, over
/// the negated dBm value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Ewma(u64);
impl Ewma {
    fn add(&mut self, value: u64) {
        self.0 = if self.0 == 0 {
            value << 10
        } else {
            ((self.0 << 3) - self.0 + (value << 10)) >> 3
        };
    }
    fn read(self) -> Option<u64> {
        (self.0 != 0).then_some(self.0 >> 10)
    }
}

/// The receive-side facts mac80211 keeps per station.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LinkStats {
    /// `NL80211_STA_INFO_SIGNAL`: the strongest chain of the last frame.
    pub signal_dbm: Option<i8>,
    /// Per receive chain of the last frame (`CHAIN_SIGNAL`).
    pub chain_signal_dbm: [Option<i8>; 2],
    avg: Ewma,
    /// `NL80211_STA_INFO_RX_BITRATE`: the last data frame's rate.
    pub rx_rate: Option<RateInfo>,
    /// Beacons from the AP with a signal sample, and the last one's signal:
    /// the input of mac80211's software CQM (`ieee80211_rx_bss_info`).
    pub beacons: u32,
    pub beacon_signal_dbm: Option<i8>,
}

impl LinkStats {
    /// One received frame from the AP: its RCPI word (group 3 or group 5)
    /// and, for a data frame, its P-RXV DW0.
    pub fn observe(&mut self, rcpi: Option<u32>, rxv: Option<u32>, data: bool, beacon: bool) {
        if let Some(rcpi) = rcpi {
            let mut chains = [None; 2];
            for (chain, slot) in chains.iter_mut().enumerate() {
                // mt7921 `to_rssi`: (RCPI - 220) / 2; 0 and >= 220 are no
                // sample.
                let value = ((rcpi >> (chain * 8)) & 255) as i16;
                if (1..220).contains(&value) {
                    *slot = Some((value / 2 - 110) as i8);
                }
            }
            if let Some(strongest) = chains.iter().flatten().max().copied() {
                self.chain_signal_dbm = chains;
                self.signal_dbm = Some(strongest);
                self.avg.add(u64::from(strongest.unsigned_abs()));
                if beacon {
                    self.beacons = self.beacons.wrapping_add(1);
                    self.beacon_signal_dbm = Some(strongest);
                }
            }
        }
        if data {
            if let Some(rate) = rxv.and_then(rx_rate) {
                self.rx_rate = Some(rate);
            }
        }
    }
    /// `NL80211_STA_INFO_SIGNAL_AVG`.
    pub fn signal_avg_dbm(&self) -> Option<i8> {
        self.avg
            .read()
            .and_then(|negated| i8::try_from(-(negated as i64)).ok())
    }
}

/// `mt76_connac2_mac_fill_rx_rate` over P-RXV DW0.
pub(crate) fn rx_rate(v0: u32) -> Option<RateInfo> {
    let idx = (v0 & 0x7f) as u8;
    let nss = ((v0 >> 7) & 7) as u8 + 1;
    let bw = ((v0 >> 12) & 7) as u8;
    let gi = ((v0 >> 15) & 3) as u8;
    let mode = ((v0 >> 24) & 15) as u8;
    // CONNAC2 carries HE DCM in the rate index (`idx & MT_PRXV_TX_DCM`).
    let dcm = idx & (1 << 4) != 0;
    rate(mode, idx, nss, bw, gi, dcm)
}

/// The CONNAC2 rate word (`MT_TX_RATE_*` / `MT_PRXV_*`) as `rate_info`.
/// `bw` is `enum ieee80211_sta_rx_bandwidth` (0..=3); `gi` the HT/VHT
/// short-GI flag or the HE GI (0/1/2).
pub(crate) fn rate(mode: u8, idx: u8, nss: u8, bw: u8, gi: u8, dcm: bool) -> Option<RateInfo> {
    let width_mhz = match bw {
        0 => 20,
        1 => 40,
        2 => 80,
        3 => 160,
        _ => return None,
    };
    let mut info = RateInfo {
        width_mhz,
        ..RateInfo::default()
    };
    match mode {
        PHY_CCK => {
            // mt76_rates: CCK hw_value 0..3, short preamble adds 4.
            info.bitrate_100kbps = *[10u32, 20, 55, 110].get(usize::from(idx & !4))?;
            info.width_mhz = 20;
        }
        PHY_OFDM => {
            info.bitrate_100kbps = match idx {
                11 => 60,
                15 => 90,
                10 => 120,
                14 => 180,
                9 => 240,
                13 => 360,
                8 => 480,
                12 => 540,
                _ => return None,
            };
            info.width_mhz = 20;
        }
        PHY_HT | PHY_HT_GF => {
            if idx > 31 {
                return None;
            }
            info.ht_mcs = Some(idx);
            info.short_gi = gi != 0;
            info.bitrate_100kbps = narf_wireless::rate::ht_bitrate_100kbps(
                idx % 8,
                idx / 8 + 1,
                width_mhz,
                info.short_gi,
            )?;
        }
        PHY_VHT => {
            if idx > 9 {
                return None;
            }
            info.vht_mcs = Some((idx, nss));
            info.short_gi = gi != 0;
            info.bitrate_100kbps =
                narf_wireless::rate::vht_bitrate_100kbps(idx, nss, width_mhz, info.short_gi)?;
        }
        PHY_HE_SU..=PHY_HE_MU => {
            let mcs = idx & 15;
            if mcs > 11 || gi > 2 {
                return None;
            }
            info.he_mcs = Some((mcs, nss, gi));
            info.he_dcm = dcm;
            let rate = narf_wireless::rate::he_bitrate_100kbps(mcs, nss, gi, width_mhz, None)?;
            // cfg80211_calculate_bitrate_he: DCM halves the rate.
            info.bitrate_100kbps = if dcm { rate / 2 } else { rate };
        }
        _ => return None,
    }
    Some(info)
}

#[path = "link_stats_tests.rs"]
mod tests;
