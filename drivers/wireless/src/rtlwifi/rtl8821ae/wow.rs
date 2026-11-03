// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE WoWLAN pieces (Linux `rtl8821ae/sw.c`, `fw.c`, `hw.c`,
//! `core.c`, `base.c`).
//!
//! - Capability (`base.c::_rtl_init_mac80211` with `sw.c` `wo_wlan_mode =
//!   WAKE_ON_MAGIC_PACKET | WAKE_ON_PATTERN_MATCH`): `WIPHY_WOWLAN_MAGIC_PKT`,
//!   16 patterns (`MAX_SUPPORT_WOL_PATTERN_NUM`), 13..=128 bytes
//!   (`MIN_WOL_PATTERN_SIZE` / `MAX_WOL_PATTERN_SIZE`), no packet offset.
//!   Linux advertises neither disconnect nor GTK rekey: `ppsc->
//!   gtk_offload_enable` / `arp_offload_enable` are never set for this chip,
//!   so the remote-wake-control H2C carries both offloads off and no GTK
//!   rekey offload exists to port. The firmware still wakes on disconnect
//!   (`DISCONNECT_WAKE_UP` 1) and always arms magic-packet and pattern
//!   matching (`wo_wlan_mode` is static), exactly as Linux.
//! - H2C payloads: `rtl8821ae_set_fw_wowlan_mode`,
//!   `_remote_wake_ctrl_cmd`, `_keep_alive_cmd`,
//!   `_disconnect_decision_ctrl_cmd`, `_global_info_cmd` and the
//!   `H2C_8821AE_AOAC_RSVDPAGE` locations of
//!   `rtl8821ae_set_fw_rsvdpagepkt(.., dl_whole_packets = true)`.
//! - Patterns: `core.c::_rtl_add_wowlan_patterns` (type, 6-bit mask shift,
//!   content after DA/SA, `_calculate_wol_pattern_crc`) and
//!   `hw.c::rtl8821ae_add_wowlan_pattern` (WKFM CAM through the RX packet
//!   buffer debug window), then `REG_WKFMCAM_NUM` (`0x698`).
//! - Wake reason: `hw.c::_rtl8821ae_get_wakeup_reason` (`REG_MCUTST_WOWLAN`).
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;
use alloc::vec::Vec;
use narf_wireless::{WowlanConfig, WowlanPattern, WowlanSupport};

/// `H2C_8821AE_*` WoWLAN command ids (`fw.h`).
pub const H2C_KEEP_ALIVE_CTRL: u8 = 0x03;
pub const H2C_DISCONNECT_DECISION: u8 = 0x04;
pub const H2C_WO_WLAN: u8 = 0x80;
pub const H2C_REMOTE_WAKE_CTRL: u8 = 0x81;
pub const H2C_AOAC_GLOBAL_INFO: u8 = 0x82;
pub const H2C_AOAC_RSVDPAGE: u8 = 0x83;

/// `rtl8821ae/reg.h`.
pub const REG_PKT_BUFF_ACCESS_CTRL: u16 = 0x0106;
pub const RXPKT_BUF_SELECT: u8 = 0xa5;
pub const DISABLE_TRXPKT_BUF_ACCESS: u8 = 0x00;
pub const REG_PKTBUF_DBG_CTRL: u16 = 0x0140;
pub const REG_PKTBUF_DBG_DATA_L: u16 = 0x0144;
pub const REG_PKTBUF_DBG_DATA_H: u16 = 0x0148;
pub const REG_RXPKTBUF_CTRL: u16 = REG_PKTBUF_DBG_CTRL + 2;
pub const REG_MCUTST_WOWLAN: u16 = 0x01c7;
pub const REG_WKFMCAM_NUM: u16 = 0x0698;

/// `wifi.h`.
pub const MAX_PATTERNS: usize = 16;
pub const MIN_PATTERN_LEN: usize = 13;
pub const MAX_PATTERN_LEN: usize = 128;
pub const MAX_MASK_SIZE: usize = 16;
pub const WKFMCAM_ADDR_NUM: u8 = 6;
pub const WKFMCAM_SIZE: u16 = 24;
/// `MAX_RX_DMA_BUFFER_SIZE_8812` (`def.h`): the WKFM CAM starts at the
/// 128-byte RX page boundary after it.
pub const MAX_RX_DMA_BUFFER_SIZE: u16 = 0x3e80;

/// Reserved-page locations (`fw.c` `ARPRESP_PG`, `REMOTE_PG`, `GTKEXT_PG`).
pub const ARPRESP_PG: u8 = 5;
pub const REMOTE_PG: u8 = 6;
pub const GTKEXT_PG: u8 = 7;
/// `TOTAL_RESERVED_PKT_LEN_8821 - 40`: the whole-packet upload length.
pub const WHOLE_RSVD_PAGE_LEN: usize = 2048 - 40;

/// `base.c::_rtl_init_mac80211` WoWLAN capability (see the module note).
pub fn support() -> WowlanSupport {
    WowlanSupport {
        disconnect: false,
        magic_packet: true,
        gtk_rekey: false,
        gtk_rekey_failure: false,
        max_patterns: MAX_PATTERNS as u8,
        min_pattern_len: MIN_PATTERN_LEN as u8,
        max_pattern_len: MAX_PATTERN_LEN as u16,
        max_packet_offset: 0,
        net_detect_max_match_sets: 0,
        net_detect_random_mac: false,
    }
}

/// Re-check a retained configuration against [`support`] (nl80211 has
/// already validated it; `set_wowlan` does not trust its caller).
pub fn validate(config: &WowlanConfig) -> Result<(), Error> {
    if config.disconnect || config.gtk_rekey_failure || config.net_detect.is_some() {
        return Err(Error::State);
    }
    if config.patterns.len() > MAX_PATTERNS || (!config.magic_packet && config.patterns.is_empty())
    {
        return Err(Error::State);
    }
    for p in &config.patterns {
        let len = p.pattern.len();
        if !(MIN_PATTERN_LEN..=MAX_PATTERN_LEN).contains(&len)
            || p.offset != 0
            || p.mask.len() != len.div_ceil(8)
        {
            return Err(Error::State);
        }
    }
    Ok(())
}

/// `rtl8821ae_set_fw_wowlan_mode`: FUNC_ENABLE, PATTERN_MATCH and
/// MAGIC_PKT from the static `wo_wlan_mode`, DISCONNECT_WAKE_UP 1, GPIO 0.
pub fn wowlan_mode(enable: bool) -> [u8; 3] {
    [u8::from(enable) | 1 << 1 | 1 << 2 | 1 << 7, 0, 0]
}
/// `rtl8821ae_set_fw_remote_wake_ctrl_cmd` (`H2C_8821AE_REMOTE_WAKE_CTRL_LEN`
/// 1): ARP/GTK offload and RealWoW v2 off (never enabled for this chip).
pub fn remote_wake_ctrl(enable: bool) -> [u8; 1] {
    [u8::from(enable)]
}
/// `rtl8821ae_set_fw_keep_alive_cmd`: driver-defined 10 s period.
pub fn keep_alive(enable: bool) -> [u8; 3] {
    [u8::from(enable) | 1 << 1, 10, 0]
}
/// `rtl8821ae_set_fw_disconnect_decision_ctrl_cmd`: user setting, 30 s
/// check period, 3 try packets.
pub fn disconnect_decision(enable: bool) -> [u8; 3] {
    [u8::from(enable) | 1 << 1, 30, 3]
}
/// `enum rt_enc_alg` values this owner can hold.
pub const NO_ENCRYPTION: u8 = 0;
pub const AESCCMP_ENCRYPTION: u8 = 4;
/// `rtl8821ae_set_fw_global_info_cmd`: pairwise and group algorithms.
pub fn global_info(pairwise: u8, group: u8) -> [u8; 2] {
    [pairwise, group]
}
/// `u1rsvdpageloc2` of the whole-packet upload: REMOTE_WAKE_CTRL_INFO,
/// ARP_RSP, (NEIGHBOR_ADV 0), (GTK_RSP 0), (GTK_INFO 0), GTK_EXT_MEM.
pub fn aoac_rsvdpage() -> [u8; 7] {
    [REMOTE_PG, ARPRESP_PG, 0, 0, 0, GTKEXT_PG, 0]
}

/// `rtl8821ae_set_fw_rsvdpagepkt(hw, false, true)`: the normal pages
/// ([`super::station::reserved_pages`]) plus the ARP-response A1/A2/A3 of
/// page 5; pages 6/7 stay zero. The ARP payload keeps Linux's template
/// addresses (ARP offload is off, `remote_wake_ctrl`).
pub fn whole_reserved_pages(own: [u8; 6], bssid: [u8; 6], aid: u16) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::with_capacity(WHOLE_RSVD_PAGE_LEN);
    bytes.extend_from_slice(&super::rsvd_page::TEMPLATE);
    bytes.extend_from_slice(&super::rsvd_page::WOWLAN_TEMPLATE);
    let normal = super::station::reserved_pages(own, bssid, aid)?;
    bytes[..normal.len()].copy_from_slice(&normal);
    let at = usize::from(ARPRESP_PG) * 256;
    bytes[at + 4..at + 10].copy_from_slice(&bssid);
    bytes[at + 10..at + 16].copy_from_slice(&own);
    bytes[at + 16..at + 22].copy_from_slice(&bssid);
    bytes.truncate(WHOLE_RSVD_PAGE_LEN);
    Ok(bytes)
}

/// `enum rtl_wow_pattern_type` (`wifi.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternType {
    Unicast,
    Multicast,
    Broadcast,
    Unknown,
}

/// `struct rtl_wow_pattern`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pattern {
    pub kind: PatternType,
    pub crc: u16,
    pub mask: [u32; 4],
}

/// `core.c::crc16_ccitt` (bit-serial, LSB-first data, poly 0x1021).
fn crc16_ccitt(data: u8, mut crc: u16) -> u16 {
    for i in 0..8 {
        let shift_in = ((crc >> 15) as u8 ^ (data >> i)) & 1;
        let mut result = crc << 1;
        result = (result & !1) | u16::from(shift_in);
        let bit11 = ((crc >> 11) as u8 & 1) ^ shift_in;
        result = (result & !(1 << 12)) | (u16::from(bit11) << 12);
        let bit4 = ((crc >> 4) as u8 & 1) ^ shift_in;
        result = (result & !(1 << 5)) | (u16::from(bit4) << 5);
        crc = result;
    }
    crc
}

/// `core.c::_calculate_wol_pattern_crc`.
pub fn pattern_crc(content: &[u8]) -> u16 {
    !content.iter().fold(0xffff, |crc, &b| crc16_ccitt(b, crc))
}

/// `core.c::_rtl_add_wowlan_patterns` for one validated pattern.
pub fn translate(p: &WowlanPattern, own: [u8; 6]) -> Pattern {
    let os = &p.pattern;
    let kind = if os[..6] == [0xff; 6] {
        PatternType::Broadcast
    } else if os[..2] == [0x33, 0x33] || os[..3] == [0x01, 0x00, 0x5e] {
        PatternType::Multicast
    } else if os[..6] == own {
        PatternType::Unicast
    } else {
        PatternType::Unknown
    };
    let mask_os = &p.mask;
    let mask_len = os.len().div_ceil(8);
    let mut mask = [0u8; MAX_MASK_SIZE];
    // 802.3 → 802.11-LLC: shift by six bits, then clear bits 0..5.
    for j in 0..mask_len - 1 {
        mask[j] = mask_os[j] >> 6 | (mask_os[j + 1] & 0x3f) << 2;
    }
    mask[mask_len - 1] = (mask_os[mask_len - 1] >> 6) & 0x3f;
    mask[0] &= 0xc0;
    let mut words = [0u32; 4];
    for (j, w) in words.iter_mut().enumerate() {
        *w = u32::from_le_bytes([
            mask[j * 4],
            mask[j * 4 + 1],
            mask[j * 4 + 2],
            mask[j * 4 + 3],
        ]);
    }
    // The CRC covers the masked bytes after DA/SA (the first 12).
    let content: Vec<u8> = (12..os.len())
        .filter(|&j| (mask_os[j / 8] >> (j % 8)) & 1 != 0)
        .map(|j| os[j])
        .collect();
    Pattern {
        kind,
        crc: pattern_crc(&content),
        mask: words,
    }
}

/// `rtl8821ae_add_wowlan_pattern` CAM entry `addr` (0, 2..=5) as
/// (data register, value, `REG_RXPKTBUF_CTRL` command); `None` for the
/// entry Linux leaves unwritten (1).
pub fn cam_entry(p: &Pattern, addr: u8) -> Option<(u16, u32, u16)> {
    match addr {
        0 => {
            let kind = match p.kind {
                PatternType::Unicast => 1 << 24,
                PatternType::Multicast => 1 << 25,
                PatternType::Broadcast => 1 << 26,
                PatternType::Unknown => 0,
            };
            Some((
                REG_PKTBUF_DBG_DATA_L,
                1 << 31 | kind | u32::from(p.crc),
                0x0f01,
            ))
        }
        2 | 4 => Some((REG_PKTBUF_DBG_DATA_L, p.mask[usize::from(addr - 2)], 0x0f01)),
        3 | 5 => Some((REG_PKTBUF_DBG_DATA_H, p.mask[usize::from(addr - 2)], 0xf001)),
        _ => None,
    }
}

/// `rtl8821ae_add_wowlan_pattern` RX-buffer pointer of CAM entry `addr`
/// of pattern `index` (8-byte units from the WKFM CAM start).
pub fn cam_address(index: u8, addr: u8) -> u16 {
    let cam_start = (MAX_RX_DMA_BUFFER_SIZE / 128) * 128;
    (cam_start + u16::from(index) * WKFMCAM_SIZE + u16::from(addr) * 4) >> 3
}

/// `rtl8821ae_add_wowlan_pattern` for pattern `index`. Linux only warns on
/// a write that never completes; here it is an error (the pattern would
/// not be armed).
pub async fn program_pattern(io: &impl Io, index: u8, p: &Pattern) -> Result<(), Error> {
    io.write8(REG_PKT_BUFF_ACCESS_CTRL, RXPKT_BUF_SELECT)?;
    let result = async {
        for addr in 0..WKFMCAM_ADDR_NUM {
            io.write16(REG_PKTBUF_DBG_CTRL, cam_address(index, addr))?;
            if let Some((reg, value, command)) = cam_entry(p, addr) {
                io.write32(reg, value)?;
                io.write16(REG_RXPKTBUF_CTRL, command)?;
            }
            let mut done = false;
            for _ in 0..100 {
                let busy = io.read8(REG_RXPKTBUF_CTRL)?;
                io.delay_us(2).await;
                if busy == 0 {
                    done = true;
                    break;
                }
            }
            if !done {
                return Err(Error::CommandTimeout);
            }
        }
        Ok(())
    }
    .await;
    io.write8(REG_PKT_BUFF_ACCESS_CTRL, DISABLE_TRXPKT_BUF_ACCESS)?;
    result
}

/// `rtl_op_suspend` → `_rtl_add_wowlan_patterns` over `config`, then
/// `REG_WKFMCAM_NUM`.
pub async fn program_patterns(
    io: &impl Io,
    config: &WowlanConfig,
    own: [u8; 6],
) -> Result<(), Error> {
    for (index, p) in config.patterns.iter().enumerate() {
        program_pattern(io, index as u8, &translate(p, own)).await?;
    }
    io.write8(REG_WKFMCAM_NUM, config.patterns.len() as u8)?;
    Ok(())
}

/// `_rtl8821ae_get_wakeup_reason`: `FW_WOW_V2_*` → `WOL_REASON_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeReason {
    PtkUpdate,
    GtkUpdate,
    Disassoc,
    Deauth,
    ApLost,
    MagicPacket,
    UnicastPacket,
    PatternPacket,
    Rtd3SsidMatch,
    RealWowWakePacket,
    RealWowAckLost,
    /// Any other `REG_MCUTST_WOWLAN` value (Linux: `wakeup_reason` 0).
    Unknown(u8),
}
pub fn wake_reason(fw_reason: u8) -> WakeReason {
    match fw_reason {
        0x01 => WakeReason::PtkUpdate,
        0x02 => WakeReason::GtkUpdate,
        0x04 => WakeReason::Disassoc,
        0x08 => WakeReason::Deauth,
        0x10 => WakeReason::ApLost,
        0x21 => WakeReason::MagicPacket,
        0x22 => WakeReason::UnicastPacket,
        0x23 => WakeReason::PatternPacket,
        0x24 => WakeReason::Rtd3SsidMatch,
        0x30 => WakeReason::RealWowWakePacket,
        0x31 => WakeReason::RealWowAckLost,
        other => WakeReason::Unknown(other),
    }
}
