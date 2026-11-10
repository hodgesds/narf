// SPDX-License-Identifier: GPL-2.0-or-later
//! Directional RTW8852B TX A-MSDU facts; no RX capability or RF authority.
pub(super) const MAX_BODY: usize = 5000; // rtw8852b_chip_info.max_amsdu_limit
/// RTL8852A A-MSDU ceiling (`rtw8852a_chip_info.max_amsdu_limit`): A
/// admits A-MSDU bodies only to 3500 bytes, not B's 5000.
pub(super) const MAX_BODY_A: usize = 3500;
pub(super) const PREFIX: usize = 8;

/// Native AX OUTSRC/RA/STS for MACID0. Linux phy.c::get_max_amsdu_len
/// and cfg80211_calculate_bitrate bound current RC-sized A-MSDU. Invalid
/// matching reports deny; another MACID/event cannot change this peer.
pub(super) fn rate_limit(bytes: &[u8], he: bool) -> Option<usize> {
    let header = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    if header & 0xffff != 6 {
        return None;
    }
    let Some(station) = bytes
        .get(8..12)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
    else {
        return Some(1);
    };
    if station & 0xffff != 0 {
        return None;
    }
    if bytes.len() != 16
        || u32::from_le_bytes(bytes[4..8].try_into().ok()?) & 0x3fff != 16
        || station & 0x80000000 != 0
    {
        return Some(1);
    }
    let rate = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    let mcs_nss = (rate & 0x7f) as usize;
    let gi = (rate >> 10) & 7;
    if rate & 0x1e000 != 0 || gi > 5 {
        return Some(1);
    } // no wider/B0/BW2/BE extension
    let (mcs, bitrate) = match (rate >> 8) & 3 {
        1 if mcs_nss <= 7 => {
            let rates = if gi == 0 {
                [65, 130, 195, 260, 390, 520, 585, 650]
            } else {
                [72, 144, 217, 289, 433, 578, 650, 722]
            };
            (mcs_nss, rates[mcs_nss])
        }
        3 if he && mcs_nss <= 11 => {
            // Source rates242, 1SS, no DCM. HE GI0.8 for codes3/5,
            // GI1.6 for2/4 and GI3.2 for0/1, as the AX native RA report.
            let base: u64 = match gi {
                3 | 5 => 114711111,
                2 | 4 => 108333333,
                _ => 97500000,
            };
            let divisors = [
                102399u64, 51201, 34134, 25599, 17067, 12801, 11377, 10239, 8532, 7680, 6828, 6144,
            ];
            (
                mcs_nss,
                (base * 6144 / divisors[mcs_nss] / 8 / 10000) as u32,
            )
        }
        _ => return Some(1),
    };
    Some(if bitrate < 550 || mcs <= 2 {
        1
    } else if bitrate < 1800 {
        1200
    } else if bitrate < 4000 {
        2600
    } else if bitrate < 7000 {
        3500
    } else {
        MAX_BODY
    })
}
