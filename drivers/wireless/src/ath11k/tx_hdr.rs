//! Ethernet → 802.11 data frames for a station vif — what mac80211 does
//! between `ieee80211_subif_start_xmit` and `ath11k_mac_op_tx` when the
//! vdev's TX encapsulation is NATIVE_WIFI (Linux's default
//! `ath11k_frame_mode`, which `mac.rs` programs as `TX_ENCAP_TYPE` /
//! `RX_DECAP_TYPE`).
//!
//! | NARF | Linux |
//! |---|---|
//! | [`classify8021d`] | `net/wireless/util.c::cfg80211_classify8021d` (no QoS map, no VLAN offload) |
//! | [`select_queue`] | `net/mac80211/wme.c::ieee80211_select_queue` (+ `ieee80211_downgrade_queue` without ACM / TSPEC / reserved TID) |
//! | [`build_sta_data`] | `net/mac80211/tx.c::ieee80211_build_hdr` (`NL80211_IFTYPE_STATION`, no TDLS / 4-addr), `ieee80211_set_qos_hdr`, the sequence number of `ieee80211_xmit_fast_finish` / `ieee80211_tx_h_sequence`, `ieee80211_tx_set_protected` (CCMP with a hardware key) |
//!
//! The result is the 802.11 frame mac80211 hands to `ath11k_dp_tx`;
//! [`super::dp_ring::Dp::tx`] then applies `ath11k_dp_tx_encap_nwifi`
//! (QoS control stripped, QoS subtype cleared) and takes the TID from
//! `skb->priority` ([`Built::tid`]). With a hardware key and no
//! `IEEE80211_KEY_FLAG_GENERATE_IV` (ath11k sets only
//! `GENERATE_IV_MGMT` for CCMP) mac80211 adds neither CCMP header nor
//! MIC space — only the Protected bit; the firmware encrypts with the
//! key installed through `WMI_VDEV_INSTALL_KEY_CMDID`.

extern crate alloc;

use alloc::vec::Vec;

use super::dp_ring::{BRIDGE_TUNNEL_HEADER, ETH_HLEN, ETH_P_PAE, RFC1042_HEADER};

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_P_MPLS_UC: u16 = 0x8847;
pub const ETH_P_MPLS_MC: u16 = 0x8848;
pub const ETH_P_80221: u16 = 0x8917;
pub const ETH_P_AARP: u16 = 0x80f3;
pub const ETH_P_IPX: u16 = 0x8137;
pub const ETH_P_802_3_MIN: u16 = 0x0600;

pub const IEEE80211_FTYPE_DATA: u16 = 0x0008;
pub const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;
pub const IEEE80211_FCTL_TODS: u16 = 0x0100;
pub const IEEE80211_FCTL_PROTECTED: u16 = 0x4000;
pub const IEEE80211_QOS_CTL_ACK_POLICY_NOACK: u8 = 0x20;
/// `IEEE80211_SCTL_SEQ`.
pub const IEEE80211_SCTL_SEQ: u16 = 0xfff0;

/// `enum ieee80211_ac_numbers`.
pub mod ac {
    pub const VO: u16 = 0;
    pub const VI: u16 = 1;
    pub const BE: u16 = 2;
    pub const BK: u16 = 3;
}

/// `ieee802_1d_to_ac[]` (net/mac80211/util.c).
pub const IEEE802_1D_TO_AC: [u16; 8] = [
    ac::BE,
    ac::BK,
    ac::BK,
    ac::BE,
    ac::VI,
    ac::VI,
    ac::VO,
    ac::VO,
];

const EPERM: i32 = 1;
const EINVAL: i32 = 22;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn is_multicast(a: &[u8]) -> bool {
    a[0] & 1 != 0
}

/// `cfg80211_classify8021d(skb, NULL)` for a frame from the stack:
/// `skb->protocol` is the Ethernet type, `skb->priority` is 0 (so not
/// the 256..263 override) and no VLAN tag is offloaded. Returns the
/// 802.1D user priority (= TID).
pub fn classify8021d(eth: &[u8]) -> u8 {
    if eth.len() < ETH_HLEN {
        return 0;
    }
    let dscp: u32 = match be16(eth, 12) {
        // ipv4_get_dsfield: the TOS byte.
        ETH_P_IP => match eth.get(ETH_HLEN + 1) {
            Some(&tos) => tos as u32 & 0xfc,
            None => return 0,
        },
        // ipv6_get_dsfield: traffic class = bits 11:4 of the first word.
        ETH_P_IPV6 => match eth.get(ETH_HLEN..ETH_HLEN + 2) {
            Some(b) => (be16(b, 0) >> 4) as u32 & 0xfc,
            None => return 0,
        },
        ETH_P_MPLS_UC | ETH_P_MPLS_MC => {
            // skb_header_pointer → NULL ⇒ 0; TC = bits 11:9 of the entry.
            return match eth.get(ETH_HLEN..ETH_HLEN + 4) {
                Some(b) => {
                    ((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x0000_0e00) >> 9) as u8
                }
                None => 0,
            };
        }
        // "802.21 is always network control traffic"
        ETH_P_80221 => return 7,
        _ => return 0,
    };
    // RFC 8325 §2.3: the three MSBs of the DSCP, with §4's exceptions.
    let mut ret = dscp >> 5;
    match dscp >> 2 {
        10 | 12 | 14 => ret = 0, // AF11..AF13
        16 => ret = 0,           // CS2
        18 | 20 | 22 => ret = 3, // AF21..AF23
        24 => ret = 4,           // CS3
        26 | 28 | 30 => ret = 4, // AF31..AF33
        44 => ret = 6,           // VA
        46 => ret = 6,           // EF
        48 => ret = 7,           // CS6
        _ => {}
    }
    (ret & 7) as u8
}

/// `ieee80211_select_queue` for the AP station: `(skb->priority, AC)`.
/// Without WMM (`sta->sta.wme` false) the priority is forced to 0 and
/// the queue is BE; the control-port protocol (EAPOL) gets priority 7.
/// NARF has no admission control (`wmm_acm`), TSPECs or reserved TID,
/// so `ieee80211_downgrade_queue` is the plain table lookup.
pub fn select_queue(eth: &[u8], wme: bool) -> (u8, u16) {
    if !wme {
        return (0, ac::BE);
    }
    let prio = if eth.len() >= ETH_HLEN && be16(eth, 12) == ETH_P_PAE {
        7
    } else {
        classify8021d(eth)
    };
    (prio, IEEE802_1D_TO_AC[prio as usize & 7])
}

/// What [`build_sta_data`] needs from the station's state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StaTx {
    /// `sdata->vif.addr`.
    pub own: [u8; 6],
    /// `sdata->vif.cfg.ap_addr`.
    pub bssid: [u8; 6],
    /// `sta->sta.wme` (the AP's association response carried WMM).
    pub wme: bool,
    /// `WLAN_STA_AUTHORIZED` (802.1X port open).
    pub authorized: bool,
    /// A pairwise key is installed in hardware (`sta->ptk[]`): the frame
    /// is marked Protected.
    pub protected: bool,
}

/// mac80211 sequence counters: `sdata->sequence_number` (non-QoS) and
/// `sta->tid_seq[]` (QoS data).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SeqState {
    pub global: u16,
    pub tid: [u16; 16],
}

/// A built frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Built {
    /// The 802.11 data frame (QoS control present for a WMM AP).
    pub frame: Vec<u8>,
    /// `skb->priority` (802.1D UP; the TCL TID for QoS data).
    pub tid: u8,
    /// `skb_get_queue_mapping` (the AC; the TCL descriptor's pool id).
    pub ac: u16,
}

/// `ieee80211_build_hdr` for `NL80211_IFTYPE_STATION` (ToDS: addr1 =
/// BSSID, addr2 = the Ethernet SA, addr3 = the Ethernet DA), then the
/// QoS control (`ieee80211_set_qos_hdr`: TID, NoAck for a group
/// receiver), the sequence number and the Protected bit.
///
/// `Err(EPERM)` = "dropped frame to %pM (unauthorized port)": unicast
/// before authorization unless it is our own EAPOL. `Err(EINVAL)` = not
/// an Ethernet frame.
pub fn build_sta_data(eth: &[u8], sta: &StaTx, seq: &mut SeqState) -> Result<Built, i32> {
    if eth.len() < ETH_HLEN {
        return Err(EINVAL);
    }
    let ethertype = be16(eth, 12);
    let (tid, queue) = select_queue(eth, sta.wme);
    let addr1 = sta.bssid;
    let multicast = is_multicast(&addr1);
    if !multicast && !sta.authorized && (ethertype != ETH_P_PAE || eth[6..12] != sta.own) {
        return Err(EPERM);
    }
    let mut fc = IEEE80211_FTYPE_DATA | IEEE80211_FCTL_TODS;
    let mut hdrlen = 24;
    if sta.wme {
        fc |= IEEE80211_STYPE_QOS_DATA;
        hdrlen += 2;
    }
    // ieee80211_tx_h_select_key → the PTK → ieee80211_tx_set_protected.
    if sta.protected {
        fc |= IEEE80211_FCTL_PROTECTED;
    }
    // ieee80211_xmit_fast_finish / ieee80211_tx_h_sequence.
    let seq_ctrl = if sta.wme && !multicast {
        let s = &mut seq.tid[tid as usize & 0xf];
        let v = *s;
        *s = (v + 0x10) & IEEE80211_SCTL_SEQ;
        v
    } else {
        let v = seq.global;
        seq.global = seq.global.wrapping_add(0x10);
        v
    };

    let (encaps, skip): (&[u8], usize) = if ethertype == ETH_P_AARP || ethertype == ETH_P_IPX {
        (&BRIDGE_TUNNEL_HEADER, ETH_HLEN - 2)
    } else if ethertype >= ETH_P_802_3_MIN {
        (&RFC1042_HEADER, ETH_HLEN - 2)
    } else {
        (&[], ETH_HLEN)
    };

    let mut f = Vec::with_capacity(hdrlen + encaps.len() + eth.len() - skip);
    f.extend_from_slice(&fc.to_le_bytes());
    f.extend_from_slice(&[0, 0]); // duration_id
    f.extend_from_slice(&addr1);
    f.extend_from_slice(&eth[6..12]);
    f.extend_from_slice(&eth[0..6]);
    f.extend_from_slice(&seq_ctrl.to_le_bytes());
    if sta.wme {
        let mut q0 = tid & 0x0f;
        if multicast {
            q0 |= IEEE80211_QOS_CTL_ACK_POLICY_NOACK;
        }
        f.extend_from_slice(&[q0, 0]);
    }
    f.extend_from_slice(encaps);
    f.extend_from_slice(&eth[skip..]);
    Ok(Built {
        frame: f,
        tid,
        ac: queue,
    })
}
