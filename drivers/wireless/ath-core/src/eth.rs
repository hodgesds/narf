// SPDX-License-Identifier: GPL-2.0-or-later
//! Ethernet-frame QoS classification shared by the ath drivers.
//!
//! `classify8021d` lived in the ath11k driver's `tx_hdr` module; promoted here
//! so ath10k can classify without depending on an Atheros driver crate. The
//! driver keeps its own copies of these universal protocol constants for its
//! encapsulation paths; the small `be16` helper and the handful of EtherType
//! values below make this function self-contained.

/// Ethernet header length.
const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_MPLS_UC: u16 = 0x8847;
const ETH_P_MPLS_MC: u16 = 0x8848;
const ETH_P_80221: u16 = 0x8917;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

/// `cfg80211_classify8021d`: map an Ethernet frame's IP/MPLS/802.21 markings
/// to an 802.1d user priority (0..=7).
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
