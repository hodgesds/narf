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
pub(super) fn ra(rates: u16) -> Option<[u8; 16]> {
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
    let backup = supported;
    let mut mask = supported;
    if mode & 2 != 0 {
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
    word(&mut bytes, 0, mode << 1 | 1 << 20);
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
