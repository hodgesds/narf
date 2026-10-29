// SPDX-License-Identifier: GPL-2.0-or-later
//! Separately qualified all-TID WMM routing (`N2xQ`) across BE/BK/VI/VO.
//!
//! Host-side equivalents of the steps Linux rtw88 relies on:
//! - `net/wireless/util.c::cfg80211_classify8021d`: RFC 8325 DSCP mapping;
//! - `net/mac80211/wme.c::{ieee802_1d_to_ac,wme_downgrade_ac,
//!   ieee80211_downgrade_queue}`: ACM downgrade with no admitted TSPEC;
//! - `rtw88/tx.c::rtw_tx_ac_to_hwq` (VO/VI/BE/BK rings) and
//!   `rtw_tx_pkt_info_update` (`qsel = skb->priority`, the TID);
//! - `rtw88/pci.h` `RTK_PCI_TXBD_IDX_{BK,BE,VI,VO}Q` 0x3ac/0x3a8/0x3a4/0x3a0.
//!
//! The base N2xL WMM grant admits one BE/TID0 producer. Driving the other
//! three EDCA queues changes the over-air contention behaviour, so it needs
//! a separate continuation over the exact base. Payload byte0 is the set of
//! extra ACs (bit0 BK, bit1 VI, bit2 VO); every other byte is zero.
use super::packet_format::{DataProfile, ACS_BK, ACS_VI, ACS_VO};
use super::qualification::{Kind, PAYLOAD};

pub(super) static KIND: Kind = Kind {
    tag: b'Q',
    stem: "qos",
    source: b"source cfg80211_classify8021d RFC8325 no QoS map; mac80211 ieee802_1d_to_ac wme_downgrade_ac ieee80211_downgrade_queue no TSPEC; rtw88 tx.c rtw_tx_ac_to_hwq VO/VI/BE/BK, rtw_tx_pkt_info_update qsel=TID; pci.h TXBD_IDX BK 0x3ac BE 0x3a8 VI 0x3a4 VO 0x3a0; EDCA 0x508/0x50c/0x504/0x500 from bound AP WMM parameters; normal ack, no EOSP/A-MSDU bit; payload byte0 bit0 BK bit1 VI bit2 VO, others zero",
    admit,
};

fn admit(did: u16, p: &[u8; PAYLOAD]) -> bool {
    matches!(did, 0xc821 | 0xc822) && bounds(p).is_some()
}

/// Qualified extra-AC set, or `None` if the payload is inadmissible.
pub(super) fn bounds(p: &[u8; PAYLOAD]) -> Option<u8> {
    let acs = p[0];
    (acs != 0 && acs & !(ACS_BK | ACS_VI | ACS_VO) == 0 && p[1..].iter().all(|b| *b == 0))
        .then_some(acs)
}

/// `cfg80211_classify8021d` without a QoS map or VLAN tag (both refused by
/// this station's Ethernet admission). `frame` is an Ethernet II frame.
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
            return match frame.get(14..18) {
                Some(entry) => (entry[2] >> 1) & 7,
                None => 0,
            };
        }
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

/// `wme_downgrade_ac`: the next lower AC, or `None` at BK.
fn downgrade_once(tid: u8) -> Option<u8> {
    match tid {
        6 | 7 => Some(5),
        4 | 5 => Some(0),
        0 | 3 => Some(2),
        _ => None,
    }
}

/// Canonical WMM row (BE, BK, VI, VO) of `tid`.
fn row(tid: u8) -> usize {
    match tid & 7 {
        0 | 3 => 0,
        1 | 2 => 1,
        4 | 5 => 2,
        _ => 3,
    }
}

/// TID for an outgoing Ethernet frame: classify, apply the AP's ACM bits
/// (`ieee80211_downgrade_queue`, sending on BK when every lower AC needs
/// admission), then step down past ACs the qualified profile lacks. BK
/// without its qualification falls back to BE/TID0.
pub(super) fn tid_for(frame: &[u8], acm: [bool; 4], profile: DataProfile) -> u8 {
    if profile.acs == 0 || !profile.qos {
        return 0;
    }
    let mut tid = classify(frame) & 7;
    while acm[row(tid)] {
        match downgrade_once(tid) {
            Some(next) => tid = next,
            None => break,
        }
    }
    loop {
        if profile.tid_queue(tid).is_some() {
            return tid;
        }
        match downgrade_once(tid) {
            Some(next) => tid = next,
            None => return 0,
        }
    }
}
