// SPDX-License-Identifier: GPL-2.0-or-later
//! 802.1d priority, WMM access category and AX queue selection.
//!
//! Host-side equivalents of the mac80211/cfg80211 steps rtw89 relies on:
//! - `net/wireless/util.c::cfg80211_classify8021d` (RFC 8325 DSCP mapping),
//! - `net/mac80211/wme.c::{ieee802_1d_to_ac,wme_downgrade_ac,
//!   ieee80211_downgrade_queue}` (ACM downgrade),
//! - `rtw89/txrx.h::{rtw89_core_get_qsel,rtw89_core_get_tid_indicate}` and
//!   `rtw89/core.c::rtw89_core_get_ch_dma` (TID -> QSEL -> ACH0..3).

/// WMM access categories in mac80211 `IEEE80211_AC_*` order (VO first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Ac {
    Voice = 0,
    Video = 1,
    BestEffort = 2,
    Background = 3,
}
impl Ac {
    /// `ieee802_1d_to_ac`.
    pub(super) fn of(tid: u8) -> Self {
        match tid & 7 {
            1 | 2 => Self::Background,
            0 | 3 => Self::BestEffort,
            4 | 5 => Self::Video,
            _ => Self::Voice,
        }
    }
    /// Canonical WMM parameter row index (BE, BK, VI, VO) used by
    /// `narf_wireless::wmm::Parameters::ac`.
    pub(super) fn wmm_index(self) -> usize {
        match self {
            Self::BestEffort => 0,
            Self::Background => 1,
            Self::Video => 2,
            Self::Voice => 3,
        }
    }
    /// Strict host service order, highest priority first.
    pub(super) const ORDER: [Self; 4] =
        [Self::Voice, Self::Video, Self::BestEffort, Self::Background];
}

/// `cfg80211_classify8021d` without a QoS map or VLAN tag (both rejected
/// by this station's Ethernet admission). `frame` is an Ethernet II frame.
pub(super) fn classify(frame: &[u8]) -> u8 {
    let Some(ethertype) = frame.get(12..14) else {
        return 0;
    };
    let dscp = match u16::from_be_bytes([ethertype[0], ethertype[1]]) {
        0x0800 => match frame.get(14..16) {
            Some(ip) if ip[0] >> 4 == 4 => ip[1] & 0xfc,
            _ => return 0,
        },
        0x86dd => match frame.get(14..16) {
            Some(ip) if ip[0] >> 4 == 6 => ((ip[0] & 0x0f) << 4 | ip[1] >> 4) & 0xfc,
            _ => return 0,
        },
        0x8847 | 0x8848 => {
            // MPLS label stack entry: TC is bits 11..9.
            return match frame.get(14..18) {
                Some(entry) => (entry[2] >> 1) & 7,
                None => 0,
            };
        }
        // IEEE 802.21 is always network control traffic.
        0x8917 => return 7,
        _ => return 0,
    };
    // RFC 8325 section 2.3 default, then the section 4 exceptions.
    match dscp >> 2 {
        10 | 12 | 14 | 16 => 0,
        18 | 20 | 22 => 3,
        24 | 26 | 28 | 30 => 4,
        44 | 46 => 6,
        48 => 7,
        _ => dscp >> 5,
    }
}

/// `wme_downgrade_ac`: move to the next lower AC, or None at BK.
fn downgrade_once(tid: u8) -> Option<u8> {
    match tid {
        6 | 7 => Some(5),
        4 | 5 => Some(0),
        0 | 3 => Some(2),
        _ => None,
    }
}

/// `ieee80211_downgrade_queue` for a client without admitted TSPECs:
/// `acm[i]` is the AP's ACM bit for WMM row `i` (BE, BK, VI, VO).
pub(super) fn downgrade(mut tid: u8, acm: [bool; 4]) -> u8 {
    tid &= 7;
    while acm[Ac::of(tid).wmm_index()] {
        match downgrade_once(tid) {
            Some(next) => tid = next,
            // All lower ACs require admission: mac80211 sends on BK.
            None => break,
        }
    }
    tid
}

/// TID for an outgoing Ethernet frame on an admitted WMM link.
pub(super) fn tid_for(frame: &[u8], acm: [bool; 4]) -> u8 {
    downgrade(classify(frame), acm)
}

/// `rtw89_core_get_tid_indicate`: odd-numbered member of each AC pair.
pub(super) fn tid_indicate(tid: u8) -> bool {
    matches!(tid & 7, 2 | 3 | 5 | 7)
}

#[cfg(feature = "kernel-test")]
#[path = "qos/tests.rs"]
mod tests;
