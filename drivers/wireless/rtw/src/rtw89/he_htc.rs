// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! HE A-Control insertion and the AX firmware rate-report fallback fence.
//! Linux rtw89 core.c::__rtw89_core_tx_check_he_qos_htc/_adjust_he_qos_htc,
//! phy.c::rtw89_phy_c2h_ra_rpt_iter and fw.h::rtw89_c2h_ra_rpt.

/// HE variant (3), CAS control ID (6), zero CAS payload. The retained
/// 20MHz profile does not need the 2.4GHz/40MHz no-UL-OFDMA OM override.
pub(super) const CONTROL: [u8; 4] = [0x1b, 0, 0, 0];

/// An AX OUTSRC/RA/STS report for this station's MACID0. `None` is an
/// unrelated event; a malformed matching report closes insertion until a
/// valid higher-MCS report arrives. No report grants HE or RF authority.
pub(super) fn rate_allows(bytes: &[u8]) -> Option<bool> {
    let header = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    if header & 0xffff != 6 {
        return None;
    }
    let Some(body) = bytes.get(8..12) else {
        return Some(false);
    };
    let station = u32::from_le_bytes(body.try_into().ok()?);
    if station & 0xffff != 0 {
        return None;
    }
    if bytes.len() != 16 || u32::from_le_bytes(bytes[4..8].try_into().ok()?) & 0x3fff != 16 {
        return Some(false);
    }
    let rate = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    let mcs_nss = (rate & 0x7f) as u8;
    let mcs = mcs_nss & 15;
    // This live profile transmits one stream at 20MHz. BE report extensions
    // and undefined GI/LTF values cannot enable AX header insertion.
    if rate & 0x1e000 != 0 || (rate >> 10) & 7 > 5 {
        return Some(false);
    }
    Some(match (rate >> 8) & 3 {
        1 => mcs_nss <= 7 && mcs_nss > 2,
        2 => mcs_nss >> 4 == 0 && (3..=9).contains(&mcs),
        3 => mcs_nss >> 4 == 0 && (3..=11).contains(&mcs),
        _ => false,
    })
}

/// Keep interoperability-sensitive EAPOL, ARP, DHCP and ICMP in their
/// ordinary header form, as rtw89_core_tx_btc_spec_pkt_notify does. Malformed
/// IPv4 cannot establish a safe packet classification either.
pub(super) fn packet_allows(ethernet: &[u8]) -> bool {
    let Some(protocol) = ethernet.get(12..14) else {
        return false;
    };
    match protocol {
        [0x88, 0x8e] | [0x08, 0x06] => false,
        [0x08, 0x00] => {
            let ip = &ethernet[14..];
            if ip.len() < 20 || ip[0] >> 4 != 4 {
                return false;
            }
            let length = usize::from(ip[0] & 15) * 4;
            if length < 20 || length > ip.len() || ip[9] == 1 {
                return false;
            }
            if ip[9] != 17 {
                return true;
            }
            // A noninitial IPv4 fragment has no UDP header to classify.
            if u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0 {
                return false;
            }
            let Some(udp) = ip.get(length..length + 8) else {
                return false;
            };
            !matches!(&udp[..4], [0, 67, 0, 68] | [0, 68, 0, 67])
        }
        _ => true,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "he_htc/tests.rs"]
mod tests;
