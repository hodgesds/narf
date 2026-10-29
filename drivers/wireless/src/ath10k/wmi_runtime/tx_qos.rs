// SPDX-License-Identifier: GPL-2.0-or-later
//! Station QoS-data TID selection for the RAW HTT owner.
//!
//! Linux v6.10 `net/mac80211/wme.c::ieee80211_select_queue` (control-port
//! EAPOL at priority 7, otherwise `net/wireless/util.c::
//! cfg80211_classify8021d`) and `ieee80211_downgrade_queue` /
//! `wme_downgrade_ac`: while the AP marks the frame's AC with ACM and no
//! TSPEC is admitted, VO -> VI (UP 5), VI -> BE (UP 3), BE -> BK (UP 2);
//! BK is used even when it also requires admission. ath10k firmware owns
//! TX aggregation (`mac.c::ath10k_ampdu_action` rejects mac80211 TX BA,
//! `TX_AMPDU_SETUP_IN_HW`), so the host only supplies the TID in the QoS
//! Control field and the HTT descriptor (`htt_tx.c::ath10k_htt_tx`
//! `HTT_DATA_TX_DESC_FLAGS1_EXT_TID`).
use narf_wireless::wmm::Parameters;

/// `ieee802_1d_to_ac` in canonical WMM ACI order (BE=0, BK=1, VI=2, VO=3).
pub(super) const UP_TO_ACI: [usize; 8] = [0, 1, 1, 0, 2, 2, 3, 3];

/// `sdata->wmm_acm` as a per-ACI admission-required mask.
pub(super) fn admission(parameters: &Parameters) -> [bool; 4] {
    [0, 1, 2, 3].map(|aci| parameters.ac[aci].admission_control)
}

/// `wme_downgrade_ac`; `None` at BK (the lowest AC).
fn downgrade(up: u8) -> Option<u8> {
    match up {
        6 | 7 => Some(5),
        4 | 5 => Some(3),
        0 | 3 => Some(2),
        _ => None,
    }
}

/// User priority (= TID) for one host Ethernet frame on a WMM association.
pub(super) fn priority(ethernet: &[u8], acm: [bool; 4]) -> u8 {
    let mut up = if ethernet.len() >= 14 && ethernet[12..14] == [0x88, 0x8e] {
        7
    } else {
        crate::ath11k::tx_hdr::classify8021d(ethernet) & 7
    };
    // No TSPEC is ever admitted by this owner (`tspec` row).
    while acm[UP_TO_ACI[usize::from(up)]] {
        match downgrade(up) {
            Some(lower) => up = lower,
            None => break,
        }
    }
    up
}

/// HTT descriptor TID for an outgoing 802.11 data frame: the QoS Control
/// TID for QoS data, else the non-QoS sentinel 16.
pub(super) fn descriptor_tid(frame: &[u8]) -> u8 {
    if frame.first() == Some(&0x88) && frame.len() >= 26 {
        frame[24] & 15
    } else {
        16
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "tx_qos_tests.rs"]
mod tests;
