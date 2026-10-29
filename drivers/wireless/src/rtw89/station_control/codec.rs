// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact AX-v0 MAC0/MACID0 fields. No firmware/radio or key authority.
fn word(bytes: &mut [u8], index: usize, value: u32) {
    bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn role(remove: bool) -> [u8; 4] {
    ((1u32 << 13) | (u32::from(remove) << 10)).to_le_bytes()
}
pub(super) fn join(connected: bool) -> [u8; 4] {
    ((1u32 << 26) | if connected { 2 << 24 } else { 1 << 8 }).to_le_bytes()
}
pub(super) fn pause(paused: bool) -> [u8; 32] {
    let mut bytes = [0; 32];
    word(&mut bytes, 0, u32::from(paused));
    word(&mut bytes, 4, 1);
    bytes
}
pub(super) fn cam(
    own: [u8; 6],
    peer: [u8; 6],
    aid: u16,
    associated: bool,
    valid: bool,
) -> [u8; 60] {
    let mut bytes = [0; 60];
    let own_hash = own.into_iter().fold(0u8, |a, b| a ^ b);
    let peer_hash = peer.into_iter().fold(0u8, |a, b| a ^ b);
    word(&mut bytes, 1, 0x40 << 16);
    word(
        &mut bytes,
        2,
        u32::from(valid)
            | ((u32::from(associated) * 2) << 1)
            | u32::from(own_hash) << 16
            | u32::from(peer_hash) << 24,
    );
    word(
        &mut bytes,
        4,
        u32::from_le_bytes(own[..4].try_into().unwrap()),
    );
    word(
        &mut bytes,
        5,
        u32::from_le_bytes([own[4], own[5], peer[0], peer[1]]),
    );
    word(
        &mut bytes,
        6,
        u32::from_le_bytes(peer[2..].try_into().unwrap()),
    );
    // Source SEC_NORMAL mode, with every security-entry valid bit/key index0.
    word(
        &mut bytes,
        9,
        2 << 16 | if associated { u32::from(aid) } else { 0 },
    );
    word(&mut bytes, 12, 8 << 16);
    word(
        &mut bytes,
        13,
        u32::from(valid) | (0x3f << 2) | u32::from(peer[0]) << 16 | u32::from(peer[1]) << 24,
    );
    word(
        &mut bytes,
        14,
        u32::from_le_bytes(peer[2..].try_into().unwrap()),
    );
    bytes
}
fn field(bytes: &mut [u8; 68], index: usize, mask: u32, value: u32) {
    let p = index * 4;
    let old = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
    word(
        bytes,
        index,
        old & !mask | (value << mask.trailing_zeros()) & mask,
    );
    let mp = (index + 8) * 4;
    let old = u32::from_le_bytes(bytes[mp..mp + 4].try_into().unwrap());
    word(bytes, index + 8, old | mask);
}
pub(super) fn default_cctl() -> [u8; 68] {
    let mut bytes = [0; 68];
    word(&mut bytes, 0, 1 << 7); // operation1, MACID0
    field(&mut bytes, 5, 0x0000_0e00, 0); // source TX power mode
    field(&mut bytes, 6, 0x000f_0000, 1); // source explicit TX-A
    for mask in [
        0x0030_0000,
        0x00c0_0000,
        0x0300_0000,
        0x0c00_0000,
        1 << 28,
        1 << 29,
        1 << 30,
        1 << 31,
    ] {
        field(&mut bytes, 6, mask, 0);
    }
    field(&mut bytes, 1, 1 << 21, 0); // no optional firmware MGQ report
    field(&mut bytes, 7, 0x000c_0000, 0);
    field(&mut bytes, 7, 0x0f00_0000, 0);
    bytes
}
pub(super) fn fixed_cctl() -> [u8; 68] {
    let mut bytes = [0; 68];
    word(&mut bytes, 0, 1 << 7);
    field(&mut bytes, 1, 1 << 25, 1); // source disable RTS fallback
    field(&mut bytes, 1, 1 << 26, 1); // source disable data fallback
    field(&mut bytes, 2, 0xf000_0000, 0); // source RTS retry lowest CCK1
    field(&mut bytes, 2, 1 << 11, 0); // source retry-limit select
    field(&mut bytes, 3, 1 << 6, 0);
    field(&mut bytes, 7, 1 << 17, 1); // source STA ULDL
    field(&mut bytes, 5, 7, 0); // source port0
    for mask in [3 << 20, 3 << 22, 3 << 30] {
        field(&mut bytes, 7, mask, 0);
    }
    field(&mut bytes, 8, 3 << 28, 0); // source non-HE160 padding
                                      // Explicit source setters for the fixed legacy/raw software-crypto path.
    field(&mut bytes, 1, 0x1ff, 0); // CCK1
    field(&mut bytes, 1, 3 << 10, 0); //20MHz
    field(&mut bytes, 1, 1 << 27, 0); // no trial rate
    field(&mut bytes, 4, 0xf000_0000, 0); // no hardware security type
    bytes
}
pub(super) fn edca(ac: u8, short: bool) -> [u8; 12] {
    let mut bytes = [0; 12];
    word(&mut bytes, 0, u32::from(ac) << 5);
    // Non-QoS legacy-b CWmin31/CWmax1023/AIFSN2/TXOP0, 2.4GHz SIFS10.
    word(
        &mut bytes,
        1,
        (10 << 12) | (5 << 8) | if short { 28 } else { 50 },
    );
    bytes
}
/// `rtw89_phy_ra_sta_update` + `rtw89_fw_h2c_ra` (AX, no CSI) for a
/// legacy 2.4GHz station: `rates` is the response-bound supported-rate
/// bitmap in hardware order (CCK1,2,5.5,11, OFDM6..54). No calibrated RSSI
/// exists, so the RSSI floor keeps every rate and `init_rate_lv` is 0, as
/// Linux does for an RSSI of 0/1.
/// `rtw89_fw_h2c_ba_cam` (BA CAM v0, RTL8852B): W0 VALID, INIT_REQ (hardware
/// takes the SSN), ENTRY_IDX[3:2], TID[7:4], MACID[15:8], BMAP_SIZE[19:16]
/// (0 for <=64), SSN[31:20]; W1 unused. An invalidation carries only MACID
/// and ENTRY_IDX.
pub(super) fn ba_cam(valid: bool, entry: u8, tid: u8, buf: u16, ssn: u16) -> [u8; 8] {
    let mut bytes = [0; 8];
    let mut w0 = u32::from(entry & 3) << 2; // MACID0
    if valid {
        w0 |= 1
            | 1 << 1
            | u32::from(tid & 0xf) << 4
            | if buf > 64 { 4 << 16 } else { 0 }
            | u32::from(ssn & 0xfff) << 20;
    }
    word(&mut bytes, 0, w0);
    bytes
}
/// Negotiated HT facts consumed by `rtw89_phy_ra_sta_update`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct HtRa {
    /// Peer RX MCS bitmap bytes 0..3 (`ht_cap.mcs.rx_mask`).
    pub(in crate::rtw89) peer_rx_mcs: [u8; 4],
    /// Peer RX SGI20 intersected with local TX SGI20.
    pub(in crate::rtw89) sgi20: bool,
    /// Peer RX LDPC intersected with local TX LDPC.
    pub(in crate::rtw89) ldpc: bool,
}
/// Negotiated HE facts consumed by `rtw89_phy_ra_sta_update`'s HE branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct HeRa {
    /// Peer RX HE-MCS map at the operating width, intersected with the
    /// local TX map (mac80211 `ieee80211_he_mcs_intersection`).
    pub(in crate::rtw89) peer_rx_mcs: u16,
    /// Peer HE PHY LDPC in payload (`IEEE80211_HE_PHY_CAP1_LDPC_...`).
    pub(in crate::rtw89) ldpc: bool,
    /// Peer DCM RX constellation nonzero (`DCM_MAX_CONST_RX_16_QAM` mask).
    pub(in crate::rtw89) dcm: bool,
}
pub(super) fn ra(rates: u16) -> Option<[u8; 16]> {
    ra_ht(rates, None)
}
/// `get_mcs_ra_mask(mcs_map, 11, 2)` (phy.c `get_he_ra_mask`): per NSS,
/// MCS0..11/0..9/0..7 at bit 12 + 12 * nss.
pub(super) fn he_mcs_mask(map: u16) -> u64 {
    (0..4).fold(0u64, |mask, i| {
        let top = match (map >> (2 * i)) & 3 {
            2 => 11,
            1 => 9,
            0 => 7,
            _ => return mask,
        };
        mask | ((1u64 << (top + 1)) - 1) << (12 + 12 * i)
    })
}
/// HE branch of `rtw89_phy_ra_sta_update`: `mode = HE|CCK|OFDM` (no HT
/// bit), HE mask from the intersected peer RX map, masked to this profile's
/// one TX stream (`rtw89_ra_mask_he_rates[0]`) plus SUBOFDM/SUBCCK, SGI from
/// the HT SGI20 negotiation (Linux reads `ht_cap` for 20MHz), LDPC and DCM
/// from the peer HE PHY capabilities. `fix_giltf_en` stays clear, so firmware
/// selects GI/LTF. ER is zero: Linux sets `er_cap` only after
/// `rtw89_phy_ra_assoc`.
pub(super) fn ra_he(rates: u16, ht: HtRa, he: HeRa) -> Option<[u8; 16]> {
    const CCK: u64 = 0xf;
    const OFDM: u64 = 0xff0;
    const SUBCCK: u64 = 0x5;
    let legacy = u64::from(rates) & (CCK | OFDM);
    if legacy == 0 {
        return None;
    }
    let mut mode = 0x10u32; // RTW89_RA_MODE_HE
    if legacy & CCK != 0 {
        mode |= 1;
    }
    if legacy & OFDM != 0 {
        mode |= 2;
    }
    let backup = legacy | he_mcs_mask(he.peer_rx_mcs);
    let mut allowed = 0xfff000; // RA_MASK_HE_1SS_RATES
    if mode & 2 != 0 {
        allowed |= 0x10; // RA_MASK_SUBOFDM_RATES
    }
    if mode & 1 != 0 {
        allowed |= SUBCCK;
    }
    let mut mask = backup & allowed;
    if mask & !(CCK | OFDM) == 0 {
        mask |= backup & !(CCK | OFDM);
    }
    if mask == 0 {
        mask |= backup & (CCK | OFDM);
    }
    let mut bytes = [0; 16];
    word(
        &mut bytes,
        0,
        mode << 1
            | u32::from(he.dcm) << 16
            | 1 << 20
            | u32::from(ht.sgi20) << 21
            | u32::from(he.ldpc) << 22,
    );
    word(&mut bytes, 1, mask as u32);
    word(&mut bytes, 2, (mask >> 32) as u32 & 0x7fff_ffff);
    Some(bytes)
}
/// HT branch: `mode |= HT`, MCS mask from the peer RX bitmap, then masked
/// to this profile's one TX stream (`rtw89_ra_mask_ht_rates[0]`) plus
/// `RA_MASK_SUBOFDM_RATES`/`RA_MASK_SUBCCK_RATES`.
pub(super) fn ra_ht(rates: u16, ht: Option<HtRa>) -> Option<[u8; 16]> {
    const CCK: u64 = 0xf;
    const OFDM: u64 = 0xff0;
    const SUBCCK: u64 = 0x5;
    let supported = u64::from(rates) & (CCK | OFDM);
    if supported == 0 {
        return None;
    }
    let mut mode = 0u32;
    if supported & CCK != 0 {
        mode |= 1; // RTW89_RA_MODE_CCK
    }
    if supported & OFDM != 0 {
        mode |= 2; // RTW89_RA_MODE_OFDM
    }
    let mut supported = supported;
    if let Some(ht) = ht {
        mode |= 4; // RTW89_RA_MODE_HT
        let m = ht.peer_rx_mcs;
        supported |= u64::from(m[3]) << 48
            | u64::from(m[2]) << 36
            | u64::from(m[1]) << 24
            | u64::from(m[0]) << 12;
    }
    let backup = supported;
    let mut mask = supported;
    if mode >= 4 {
        let mut allowed = 0xff000; // RA_MASK_HT_1SS_RATES
        if mode & 2 != 0 {
            allowed |= 0x10; // RA_MASK_SUBOFDM_RATES
        }
        if mode & 1 != 0 {
            allowed |= SUBCCK;
        }
        mask &= allowed;
    } else if mode & 2 != 0 {
        mask &= OFDM | SUBCCK;
    }
    // rtw89_phy_ra_mask_recover
    if mask & !(CCK | OFDM) == 0 {
        mask |= backup & !(CCK | OFDM);
    }
    if mask == 0 {
        mask |= backup & (CCK | OFDM);
    }
    let mut bytes = [0; 16];
    // MODE[5:1], BW_CAP 20MHz, MACID0, INIT_RATE_LV0, UPD_ALL, SS_NUM0.
    let (sgi, ldpc) = ht.map_or((false, false), |ht| (ht.sgi20, ht.ldpc));
    word(
        &mut bytes,
        0,
        mode << 1 | 1 << 20 | u32::from(sgi) << 21 | u32::from(ldpc) << 22,
    );
    word(&mut bytes, 1, mask as u32);
    word(&mut bytes, 2, (mask >> 32) as u32 & 0x7fff_ffff);
    Some(bytes)
}
pub(super) fn wmm_edca(p: narf_wireless::wmm::Parameters, short: bool) -> Option<[[u8; 12]; 4]> {
    if p.ac[0].admission_control
        || p.ac.iter().any(|a| {
            a.ecw_min == 0
                || a.ecw_min > 15
                || a.ecw_max > 15
                || a.ecw_min > a.ecw_max
                || a.aifsn < 2
                || a.aifsn > 15
        })
    {
        return None;
    }
    let mut commands = [[0; 12]; 4];
    for (i, a) in p.ac.iter().enumerate() {
        let aifs = u32::from(if i == 0 { a.aifsn.max(3) } else { a.aifsn })
            * if short { 9 } else { 20 }
            + 10;
        if aifs > 255 {
            return None;
        }
        word(&mut commands[i], 0, (i as u32) << 5);
        word(
            &mut commands[i],
            1,
            u32::from(if i == 0 { 0 } else { a.txop }) << 16
                | u32::from(if i == 0 { a.ecw_max.max(10) } else { a.ecw_max }) << 12
                | u32::from(if i == 0 { a.ecw_min.max(5) } else { a.ecw_min }) << 8
                | aifs,
        );
    }
    Some(commands)
}
