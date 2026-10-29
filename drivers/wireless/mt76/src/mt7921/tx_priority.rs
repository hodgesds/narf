//! Station transmit priority and WMM access-category selection.
//!
//! Linux references (7.3-rc7): `net/wireless/util.c::cfg80211_classify8021d`
//! (RFC 8325 DSCP mapping, MPLS TC, 802.21), `net/mac80211/wme.c`
//! (`ieee802_1d_to_ac`, `ieee80211_downgrade_queue`, `wme_downgrade_ac`) and
//! `net/mac80211/mlme.c::_ieee80211_sta_wmm_params` (`wmm_acm` per-UP bits).
//! No QoS Map is configured natively and the native TX path carries no
//! out-of-band VLAN tag, so those two cfg80211 inputs are absent.

/// `ieee802_1d_to_ac`: user priority -> mac80211 AC (VO=0, VI=1, BE=2, BK=3).
pub(crate) const UP_TO_AC: [u8; 8] = [2, 3, 3, 2, 1, 1, 0, 0];

/// `cfg80211_classify8021d` for an 802.3 frame (destination, source,
/// EtherType, payload).
pub(crate) fn classify8021d(ethernet: &[u8]) -> u8 {
    let Some(ethertype) = ethernet.get(12..14) else {
        return 0;
    };
    let payload = &ethernet[14..];
    let dscp = match u16::from_be_bytes([ethertype[0], ethertype[1]]) {
        // IPv4 DS field is the TOS octet.
        0x0800 => match payload.get(1) {
            Some(tos) => tos & 0xfc,
            None => return 0,
        },
        // IPv6 traffic class straddles the first two octets.
        0x86dd => match payload.get(..2) {
            Some(head) => ((head[0] << 4) | (head[1] >> 4)) & 0xfc,
            None => return 0,
        },
        // MPLS unicast/multicast: label-stack TC (bits 11..9).
        0x8847 | 0x8848 => match payload.get(..4) {
            Some(label) => {
                let entry = u32::from_be_bytes([label[0], label[1], label[2], label[3]]);
                return ((entry >> 9) & 7) as u8;
            }
            None => return 0,
        },
        // 802.21 is always network control traffic.
        0x8917 => return 7,
        _ => return 0,
    };
    match dscp >> 2 {
        // AF11/AF12/AF13 high-throughput data, CS2 OAM.
        10 | 12 | 14 | 16 => 0,
        // AF21/AF22/AF23 low-latency data.
        18 | 20 | 22 => 3,
        // CS3 broadcast video, AF31/AF32/AF33 multimedia streaming.
        24 | 26 | 28 | 30 => 4,
        // VA voice admit, EF telephony.
        44 | 46 => 6,
        // CS6 network control.
        48 => 7,
        _ => dscp >> 5,
    }
}

/// `wmm_acm` from the WMM Parameter element's ACM bits in ACI order
/// (BE, BK, VI, VO): each AC marks both of its user priorities.
pub(crate) fn acm_mask(acm_by_aci: [bool; 4]) -> u8 {
    const UPS: [u8; 4] = [(1 << 0) | (1 << 3), (1 << 1) | (1 << 2), 0x30, 0xc0];
    acm_by_aci
        .iter()
        .zip(UPS)
        .filter(|(acm, _)| **acm)
        .fold(0, |mask, (_, ups)| mask | ups)
}

/// `ieee80211_downgrade_queue` without an admitted TSPEC: step VO->VI->BE->BK
/// while the AP requires admission control; an AP that marks every lower AC
/// leaves the frame on the last reachable priority (the Linux BK workaround).
pub(crate) fn downgrade(mut up: u8, acm: u8) -> u8 {
    while acm & (1 << up) != 0 {
        up = match up {
            6 | 7 => 5,
            4 | 5 => 3,
            0 | 3 => 2,
            _ => break,
        };
    }
    up
}

/// The station's transmit user priority for one Ethernet frame.
pub(crate) fn select(ethernet: &[u8], acm: u8) -> u8 {
    downgrade(classify8021d(ethernet), acm)
}
