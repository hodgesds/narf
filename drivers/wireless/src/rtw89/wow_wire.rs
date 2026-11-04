// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B Wake-on-WLAN source codecs only: wowlan stub, pattern CAM
//! entries, the MAC/WOW H2C bodies, the security-CAM key body, the wake
//! reason register and the AOAC C2H report. Nothing here owns MMIO, H2C
//! transport or firmware; a native owner must sequence them
//! (`wow.c::rtw89_wow_suspend`/`rtw89_wow_resume`).
//! Linux 7.3-rc4 `wow.c`, `wow.h`, `fw.c`/`fw.h` (WOW H2C), `cam.c`
//! (`rtw89_cam_get_sec_key_cmd`), `mac.c` (`wow_ctrl`, AOAC C2H) and
//! `rtw8852b.c` (`rtw_wowlan_stub_8852b`, `rtw8852b_wow_wakeup_regs`).
use alloc::vec::Vec;
use narf_wireless::{WowlanConfig, WowlanPattern, WowlanSupport};

/// `RTW89_MAX_PATTERN_NUM`.
pub(super) const MAX_PATTERNS: usize = 18;
/// `RTW89_MAX_PATTERN_SIZE`.
pub(super) const MAX_PATTERN_LEN: usize = 128;
/// `RTW89_MAX_PATTERN_MASK_SIZE` words (16 mask bytes, 128 bits).
const MASK_WORDS: usize = 4;

/// `H2C_CL_MAC_WOW` (`fw.h`).
pub(super) const H2C_CL_MAC_WOW: u8 = 0x1;
/// `H2C_CL_MAC_WOW` functions (`enum rtw89_wow_h2c_func`).
pub(super) const H2C_FUNC_KEEP_ALIVE: u8 = 0x0;
pub(super) const H2C_FUNC_DISCONNECT_DETECT: u8 = 0x1;
pub(super) const H2C_FUNC_WOW_GLOBAL: u8 = 0x2;
pub(super) const H2C_FUNC_GTK_OFLD: u8 = 0x3;
pub(super) const H2C_FUNC_WAKEUP_CTRL: u8 = 0x8;
pub(super) const H2C_FUNC_WOW_CAM_UPD: u8 = 0xc;
pub(super) const H2C_FUNC_AOAC_REPORT_REQ: u8 = 0xd;
/// `H2C_CL_MAC_SEC_CAM` / `H2C_FUNC_MAC_SEC_UPD` (`cam.c`).
pub(super) const H2C_CL_MAC_SEC_CAM: u8 = 0xa;
pub(super) const H2C_FUNC_MAC_SEC_UPD: u8 = 0x1;
/// `RTW89_MAC_C2H_CLASS_WOW` / `RTW89_MAC_C2H_FUNC_AOAC_REPORT`.
pub(super) const C2H_CLASS_WOW: u8 = 0x3;
pub(super) const C2H_FUNC_AOAC_REPORT: u8 = 0x0;

/// `mac.c` AX `wow_ctrl`: `R_AX_WOW_CTRL` / `B_AX_WOW_WOWEN`, polled by
/// `rtw89_wow_check_fw_status` every 50us for at most 50ms.
pub(super) const R_AX_WOW_CTRL: u32 = 0x9c50;
pub(super) const B_AX_WOW_WOWEN: u8 = 1 << 1;
pub(super) const WOW_STATUS_POLL_US: u64 = 50;
pub(super) const WOW_STATUS_TIMEOUT_US: u64 = 50_000;
/// `rtw8852b_wow_wakeup_regs`: `R_AX_C2HREG_DATA3 + 3` for both reason
/// register versions.
pub(super) const WAKE_REASON_REG: u32 = 0x815c + 3;

/// `rtw_wowlan_stub_8852b`: magic packet, disconnect and 18 patterns of
/// 1..=128 bytes. Linux declares neither GTK-rekey nor net-detect for B.
pub(super) fn support() -> WowlanSupport {
    WowlanSupport {
        disconnect: true,
        magic_packet: true,
        gtk_rekey: false,
        gtk_rekey_failure: false,
        max_patterns: MAX_PATTERNS as u8,
        min_pattern_len: 1,
        max_pattern_len: MAX_PATTERN_LEN as u16,
        max_packet_offset: 0,
        net_detect_max_match_sets: 0,
        net_detect_random_mac: false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// Outside [`support`] (net-detect, GTK-rekey wake).
    Unsupported,
    /// Malformed configuration or a pattern whose DA mask
    /// `rtw89_wow_pattern_get_type` rejects (`-EPERM`).
    Invalid,
}

/// Re-validate a retained configuration against [`support`] and generate
/// every pattern against the station address, as `rtw89_wow_set_wakeups`
/// does before any hardware is touched.
pub(super) fn validate(config: &WowlanConfig, own: [u8; 6]) -> Result<Vec<Pattern>, Error> {
    if config.net_detect.is_some() || config.gtk_rekey_failure {
        return Err(Error::Unsupported);
    }
    if config.patterns.len() > MAX_PATTERNS {
        return Err(Error::Invalid);
    }
    if !config.disconnect && !config.magic_packet && config.patterns.is_empty() {
        return Err(Error::Invalid);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(config.patterns.len())
        .map_err(|_| Error::Invalid)?;
    for p in &config.patterns {
        let len = p.pattern.len();
        if !(1..=MAX_PATTERN_LEN).contains(&len) || p.offset != 0 || p.mask.len() != len.div_ceil(8)
        {
            return Err(Error::Invalid);
        }
        out.push(generate(p, own)?);
    }
    Ok(out)
}

/// `struct rtw89_wow_cam_info` minus index/r_w/valid, which the H2C
/// encoder supplies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pattern {
    pub mask: [u32; MASK_WORDS],
    pub crc: u16,
    pub uc: bool,
    pub mc: bool,
    pub bc: bool,
}

/// `__rtw89_cal_crc16` + `rtw89_calc_crc`: Realtek CRC16 (seed 0xffff,
/// LSB-first input, taps at bits 12 and 5), one's complement.
pub(super) fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &byte in data {
        for bit in 0..8 {
            let shift_in = ((crc >> 15) ^ u16::from(byte >> bit)) & 1;
            let mut next = (crc << 1) & !1 | shift_in;
            next = next & !(1 << 12) | (((crc >> 11) & 1) ^ shift_in) << 12;
            next = next & !(1 << 5) | (((crc >> 4) & 1) ^ shift_in) << 5;
            crc = next;
        }
    }
    !crc
}

/// `rtw89_wow_pattern_get_type` + `rtw89_wow_pattern_generate`. The DA is
/// the masked first six bytes: broadcast, multicast, the station's own
/// address under a full DA mask, or fully unmasked (wildcard, no type bit);
/// anything else is rejected. The hardware matches from the LLC header, so
/// the mask shifts by six bits with bits 0..5 cleared, and the CRC covers
/// masked bytes from offset 12.
pub(super) fn generate(p: &WowlanPattern, own: [u8; 6]) -> Result<Pattern, Error> {
    let pattern = &p.pattern;
    let mask = &p.mask;
    let mask_len = pattern.len().div_ceil(8);
    if pattern.is_empty() || mask.len() < mask_len || mask_len > MASK_WORDS * 4 {
        return Err(Error::Invalid);
    }
    let da_mask = mask[0] & 0x3f;
    let mut da = [0u8; 6];
    for (i, slot) in da.iter_mut().enumerate() {
        if da_mask & (1 << i) != 0 {
            *slot = pattern.get(i).copied().unwrap_or(0);
        }
    }
    let (mut uc, mut mc, mut bc) = (false, false, false);
    if da == [0xff; 6] {
        bc = true;
    } else if da[0] & 1 != 0 {
        mc = true;
    } else if da == own && da_mask == 0x3f {
        uc = true;
    } else if da_mask != 0 {
        return Err(Error::Invalid);
    }
    let mut hw = [0u8; MASK_WORDS * 4];
    for (i, slot) in hw.iter_mut().enumerate().take(mask_len - 1) {
        *slot = (mask[i] >> 6) | (mask[i + 1] & 0x3f) << 2;
    }
    hw[mask_len - 1] = mask[mask_len - 1] >> 6;
    hw[0] &= !0x3f;
    let mut words = [0u32; MASK_WORDS];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u32::from_le_bytes([hw[i * 4], hw[i * 4 + 1], hw[i * 4 + 2], hw[i * 4 + 3]]);
    }
    let mut content = Vec::new();
    content
        .try_reserve_exact(pattern.len())
        .map_err(|_| Error::Invalid)?;
    for (i, &b) in pattern.iter().enumerate().skip(12) {
        if (mask[i / 8] >> (i % 8)) & 1 != 0 {
            content.push(b);
        }
    }
    Ok(Pattern {
        mask: words,
        crc: crc16(&content),
        uc,
        mc,
        bc,
    })
}

/// `rtw89_fw_h2c_wow_cam_update` (AX v0, RTL8852B `h2c_wow_cam_update`).
/// `Some` writes entry `idx` as `rtw89_wow_parse_patterns` fills it
/// (`r_w`, `skip_mac_hdr`, `valid`, positive match); `None` is
/// `rtw89_wow_pattern_clear_cam` (only `r_w`/`idx` and a clear valid bit).
pub(super) fn cam_update(idx: u8, pattern: Option<&Pattern>) -> Option<[u8; 24]> {
    if usize::from(idx) >= MAX_PATTERNS {
        return None;
    }
    let mut out = [0u8; 24];
    out[0..4].copy_from_slice(&(1 | u32::from(idx) << 1).to_le_bytes());
    if let Some(p) = pattern {
        for (i, word) in p.mask.iter().enumerate() {
            out[4 + i * 4..8 + i * 4].copy_from_slice(&word.to_le_bytes());
        }
        let w5 = u32::from(p.crc)
            | 1 << 23
            | u32::from(p.uc) << 24
            | u32::from(p.mc) << 25
            | u32::from(p.bc) << 26
            | 1 << 31;
        out[20..24].copy_from_slice(&w5.to_le_bytes());
    }
    Some(out)
}

/// `rtw89_fw_h2c_keep_alive` (`H2C_KEEP_ALIVE_LEN` 4): enable, the
/// offloaded packet id, period 5 and the MAC id. Disabling sends id 0.
pub(super) fn keep_alive(enable: bool, packet: u8, mac_id: u8) -> [u8; 4] {
    let id = if enable { packet } else { 0 };
    (u32::from(enable) | u32::from(id) << 8 | 5 << 16 | u32::from(mac_id) << 24).to_le_bytes()
}

/// `rtw89_fw_h2c_disconnect_detect` (`H2C_DISCONNECT_DETECT_LEN` 8). The
/// fields are filled only when disconnect wake is requested
/// (`RTW89_WOW_FLAG_EN_DISCONNECT`): enable, `!enable` disconnect, MAC id,
/// check period 100, try count 5.
pub(super) fn disconnect_detect(enable: bool, requested: bool, mac_id: u8) -> [u8; 8] {
    let mut out = [0u8; 8];
    if requested {
        let w0 = u32::from(enable)
            | u32::from(!enable) << 2
            | u32::from(mac_id) << 8
            | 100 << 16
            | 5 << 24;
        out[0..4].copy_from_slice(&w0.to_le_bytes());
    }
    out
}

/// `rtw89_fw_h2c_wow_wakeup_ctrl`: pattern match (when any pattern is
/// installed), magic packet, deauth (disconnect) and the MAC id. Non-MLD.
pub(super) fn wakeup_ctrl(
    enable: bool,
    patterns: bool,
    magic: bool,
    disconnect: bool,
    mac_id: u8,
) -> [u8; 4] {
    let e = u32::from(enable);
    let w0 = if patterns { e } else { 0 }
        | if magic { e << 1 } else { 0 }
        | if disconnect { e << 4 } else { 0 }
        | u32::from(mac_id) << 24;
    w0.to_le_bytes()
}

/// `enum rtw89_fw_alg` values this profile can hand to the WoW firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Alg {
    /// Open BSS (`ptk_alg`/`gtk_alg` zero).
    None = 0,
    /// `RTW89_WOW_FW_ALG_CCMP`.
    Ccmp = 6,
}

/// `struct rtw89_wow_key_info` (56 bytes, packed).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct KeyInfo {
    pub ptk_tx_iv: [u8; 8],
    pub valid_check: u8,
    pub symbol_check_en: u8,
    pub gtk_keyidx: u8,
    pub ptk_rx_iv: [u8; 8],
    pub gtk_rx_iv: [[u8; 8]; 4],
}
/// `RTW89_WOW_VALID_CHECK` and `RTW89_WOW_SYMBOL_CHK_{PTK,GTK}`.
pub(super) const VALID_CHECK: u8 = 0xdd;
pub(super) const SYMBOL_CHECK_PTK_GTK: u8 = 0b11;

/// `_pn_to_iv` for CCMP-128: PN0, PN1, 0, ExtIV | key id << 6, PN2..PN5.
pub(super) fn ccmp_iv(pn: u64, key_id: u8) -> [u8; 8] {
    let b = pn.to_le_bytes();
    [
        b[0],
        b[1],
        0,
        0x20 | (key_id & 3) << 6,
        b[2],
        b[3],
        b[4],
        b[5],
    ]
}
/// `_iv_to_pn` for CCMP-128 (the AOAC report's IVs back to a 48-bit PN).
pub(super) fn ccmp_pn(iv: &[u8; 8]) -> u64 {
    u64::from_le_bytes([iv[0], iv[1], iv[4], iv[5], iv[6], iv[7], 0, 0])
}

impl KeyInfo {
    fn encode(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        out[0..8].copy_from_slice(&self.ptk_tx_iv);
        out[8] = self.valid_check;
        out[9] = self.symbol_check_en;
        out[10] = self.gtk_keyidx;
        out[16..24].copy_from_slice(&self.ptk_rx_iv);
        for (i, iv) in self.gtk_rx_iv.iter().enumerate() {
            out[24 + i * 8..32 + i * 8].copy_from_slice(iv);
        }
        out
    }
}

/// `rtw89_fw_h2c_wow_global` (`struct rtw89_h2c_wow_global`, 60 bytes):
/// enable, MAC id, pairwise/group algorithm and the key info.
pub(super) fn wow_global(
    enable: bool,
    mac_id: u8,
    pairwise: Alg,
    group: Alg,
    keys: &KeyInfo,
) -> [u8; 60] {
    let mut out = [0u8; 60];
    let w0 =
        u32::from(enable) | u32::from(mac_id) << 8 | (pairwise as u32) << 16 | (group as u32) << 24;
    out[0..4].copy_from_slice(&w0.to_le_bytes());
    out[4..60].copy_from_slice(&keys.encode());
    out
}

/// `rtw89_fw_h2c_wow_request_aoac` (`struct rtw89_h2c_wow_aoac`): no
/// parameters; RECV ack only, the C2H report answers it.
pub(super) fn aoac_request() -> [u8; 4] {
    [0; 4]
}

/// `rtw89_cam_get_sec_key_cmd` (`H2C_SEC_CAM_LEN` 24) for one
/// non-extended entry: index, offset 0, `RTW89_SEC_CAM_LEN` 20,
/// `RTW89_SEC_KEY_TYPE_CCMP128` 6, no SPP, then the 16 key bytes as four
/// little-endian words.
pub(super) fn sec_cam_ccmp(index: u8, key: &[u8; 16]) -> zeroize::Zeroizing<[u8; 24]> {
    let mut out = zeroize::Zeroizing::new([0u8; 24]);
    out[0..4].copy_from_slice(&(u32::from(index) | 20 << 16).to_le_bytes());
    out[4..8].copy_from_slice(&6u32.to_le_bytes());
    out[8..24].copy_from_slice(key);
    out
}

/// Driver-accessor wake report (`rtw89_wow_show_wakeup_reason`). As for
/// iwlwifi (iwlwifi.md section 3.80) and rtw88, the shared contract has no
/// `ieee80211_report_wowlan_wakeup` event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakeReport {
    pub disconnect: bool,
    pub magic_packet: bool,
    pub gtk_rekey_failure: bool,
    pub pattern_index: Option<u8>,
    pub net_detect: bool,
    /// A reason byte that maps to no trigger (Linux reports a NULL wakeup).
    pub unknown: Option<u8>,
}

/// `enum rtw89_wake_reason` -> report, exactly as
/// `rtw89_wow_show_wakeup_reason`. A pattern match takes its index from
/// the AOAC report (`aoac_rpt->pattern_idx`).
pub(super) fn decode_reason(reason: u8, aoac: Option<&AoacReport>) -> WakeReport {
    let mut r = WakeReport::default();
    match reason {
        0x04 | 0x08 | 0x10 => r.disconnect = true,
        0x21 => r.magic_packet = true,
        0x02 => r.gtk_rekey_failure = true,
        0x23 => r.pattern_index = Some(aoac.map_or(0, |a| a.pattern_idx)),
        0x55 => r.net_detect = true,
        other => r.unknown = Some(other),
    }
    r
}
/// Linux keeps the association after every reason; like rtw88, NARF drops
/// it when the AP is gone or the reason is unknown, so the SME rejoins.
pub(super) fn keeps_link(report: &WakeReport) -> bool {
    !report.disconnect && report.unknown.is_none()
}

/// `struct rtw89_c2h_wow_aoac_report` after the eight-byte C2H header
/// (`rtw89_mac_c2h_wow_aoac_rpt`). GTK/IGTK material is deliberately not
/// retained: this profile installs no GTK offload, so a rekey report is
/// refused by the caller instead of consumed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct AoacReport {
    pub rpt_ver: u8,
    pub sec_type: u8,
    pub key_idx: u8,
    pub pattern_idx: u8,
    pub rekey_ok: u8,
    pub ptk_tx_iv: [u8; 8],
    pub ptk_rx_iv: [u8; 8],
    pub gtk_rx_iv: [[u8; 8]; 4],
}
const AOAC_BODY_LEN: usize = 148;
pub(super) fn decode_aoac(body: &[u8]) -> Option<AoacReport> {
    if body.len() < AOAC_BODY_LEN {
        return None;
    }
    let iv = |at: usize| -> [u8; 8] {
        let mut v = [0u8; 8];
        v.copy_from_slice(&body[at..at + 8]);
        v
    };
    Some(AoacReport {
        rpt_ver: body[0],
        sec_type: body[1],
        key_idx: body[2],
        pattern_idx: body[3],
        rekey_ok: body[4],
        ptk_tx_iv: iv(8),
        ptk_rx_iv: iv(56),
        gtk_rx_iv: [iv(64), iv(72), iv(80), iv(88)],
    })
}

#[cfg(feature = "kernel-test")]
#[path = "wow_wire_tests.rs"]
mod tests;
