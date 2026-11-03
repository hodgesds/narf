// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822CE Wake-on-WLAN, Linux 7.3-rc4 `rtw88/wow.c` + `fw.c` WoW H2Cs.
//!
//! Only `rtw8822c.c` declares `wow_fw_name`/`wowlan_stub`; RTL8821C/8822B
//! declare neither, so every entry point here is C22-only. This module owns
//! the source sequence (`rtw_wow_suspend`/`rtw_wow_resume`), the pattern CAM
//! encoding, the WoW H2C layouts and the wake-reason decode. The hardware
//! side is the narrow [`Io`] trait; the WoW image is the separately
//! registered, authenticated `rtw88/rtw8822c_wow_fw.bin` and the restore is
//! the registered normal image (`firmware_transport::registered_*`), never a
//! cached or unverified copy. Any error is terminal for the WoW attempt: the
//! caller must run the cold full restart (`system_pm_native` resume) rather
//! than trusting the station that was armed.
use super::firmware_transport::{Error as NativeError, PreparedImage};
use alloc::{boxed::Box, vec::Vec};
use narf_wireless::{WowlanConfig, WowlanPattern, WowlanSupport};

/// `main.h` `RTW_MAX_PATTERN_NUM`, `RTW_MAX_PATTERN_MASK_SIZE`,
/// `RTW_MAX_PATTERN_SIZE`.
pub(super) const MAX_PATTERNS: usize = 12;
pub(super) const MASK_SIZE: usize = 16;
pub(super) const MAX_PATTERN_LEN: usize = 128;
/// `rtw8822c_hw_spec.wow_fw_name`.
pub(super) const WOW_FIRMWARE: &str = "rtw88/rtw8822c_wow_fw.bin";

// reg.h
const REG_SYS_FUNC_EN: u16 = 0x0002;
const BIT_FEN_BB_RSTB: u8 = 1 << 0;
const REG_RSV_CTRL: u16 = 0x001c;
const BIT_WLOCK_1C_B6: u8 = 1 << 5;
const BIT_R_DIS_PRST: u8 = 1 << 6;
const REG_FE1IMR: u16 = 0x0120;
const BIT_FS_RXDONE: u32 = 1 << 16;
pub(super) const REG_WOWLAN_WAKE_REASON: u16 = 0x01c7;
const REG_RXPKT_NUM: u16 = 0x0284;
const BIT_RW_RELEASE: u32 = 1 << 18;
const BIT_RXDMA_IDLE: u32 = 1 << 17;
const REG_BCNQ_INFO: u16 = 0x0418;
const BIT_MGQ_CPU_EMPTY: u32 = 1 << 24;
const REG_TXPAUSE: u16 = 0x0522;
pub(super) const REG_WKFMCAM_CMD: u16 = 0x0698;
pub(super) const REG_WKFMCAM_RWD: u16 = 0x069c;
pub(super) const BIT_WKFCAM_POLLING_V1: u32 = 1 << 31;
pub(super) const BIT_WKFCAM_CLR_V1: u32 = 1 << 30;
pub(super) const BIT_WKFCAM_WE: u32 = 1 << 16;
pub(super) const BIT_WKFMCAM_VALID: u32 = 1 << 31;
pub(super) const BIT_WKFMCAM_BC: u32 = 1 << 26;
pub(super) const BIT_WKFMCAM_MC: u32 = 1 << 25;
pub(super) const BIT_WKFMCAM_UC: u32 = 1 << 24;

// fw.h H2C class ids.
const H2C_CMD_RSVD_PAGE: u8 = 0x00;
const H2C_CMD_MEDIA_STATUS_RPT: u8 = 0x01;
const H2C_CMD_KEEP_ALIVE: u8 = 0x03;
const H2C_CMD_DISCONNECT_DECISION: u8 = 0x04;
const H2C_CMD_WOWLAN: u8 = 0x80;
const H2C_CMD_REMOTE_WAKE_CTRL: u8 = 0x81;
const H2C_CMD_AOAC_GLOBAL_INFO: u8 = 0x82;

/// `main.h` `enum rtw_security_type` values the AOAC H2C carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyType {
    None = 0,
    Wep40 = 1,
    Tkip = 2,
    Aes = 4,
    Wep104 = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// Not RTL8822CE, not an associated station or an unadvertised trigger.
    Unsupported,
    /// Configuration outside the advertised `wowlan_stub` bounds.
    Invalid,
    /// `rtw_wow_check_fw_status` / CAM / RX DMA poll expired.
    Timeout,
    Native(NativeError),
}
impl From<NativeError> for Error {
    fn from(e: NativeError) -> Self {
        Self::Native(e)
    }
}

/// `rtw_wowlan_stub_8822c`, minus what NARF does not port. Linux also sets
/// `WIPHY_WOWLAN_SUPPORTS_GTK_REKEY` and `WIPHY_WOWLAN_NET_DETECT`; rtw88
/// has no `set_rekey_data` op (the flag only lets the firmware wake on a
/// rekey frame, reported here as `gtk_rekey_failure`), and net-detect needs
/// the PNO reserved pages/NLO/channel-switch H2Cs that are not ported, so
/// neither is advertised. `pattern_min_len` 1, no packet offset.
pub(super) fn support(did: u16) -> Option<WowlanSupport> {
    (did == 0xc822).then_some(WowlanSupport {
        disconnect: true,
        magic_packet: true,
        gtk_rekey: false,
        gtk_rekey_failure: true,
        max_patterns: MAX_PATTERNS as u8,
        min_pattern_len: 1,
        max_pattern_len: MAX_PATTERN_LEN as u16,
        max_packet_offset: 0,
        net_detect_max_match_sets: 0,
        net_detect_random_mac: false,
    })
}

/// Re-validate a retained configuration against [`support`]; nl80211 has
/// already done so but `set_wowlan` must not trust its caller.
pub(super) fn validate(did: u16, config: &WowlanConfig) -> Result<(), Error> {
    support(did).ok_or(Error::Unsupported)?;
    if config.net_detect.is_some() {
        return Err(Error::Unsupported);
    }
    if config.patterns.len() > MAX_PATTERNS {
        return Err(Error::Invalid);
    }
    for p in &config.patterns {
        let len = p.pattern.len();
        if !(1..=MAX_PATTERN_LEN).contains(&len) || p.offset != 0 || p.mask.len() != len.div_ceil(8)
        {
            return Err(Error::Invalid);
        }
    }
    if !config.disconnect
        && !config.magic_packet
        && !config.gtk_rekey_failure
        && config.patterns.is_empty()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// `enum rtw_wow_pattern_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PatternType {
    Broadcast,
    Multicast,
    Unicast,
    Invalid,
}
/// `struct rtw_wow_pattern`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pattern {
    pub kind: PatternType,
    pub mask: [u8; MASK_SIZE],
    pub crc: u16,
}

/// `__rtw_cal_crc16` + `rtw_calc_crc`: Realtek CRC16 (poly 0x1021, LSB
/// first input, seed 0xffff), one's complement.
pub(super) fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &byte in data {
        for bit in 0..8 {
            let shift_in = ((crc >> 15) ^ u16::from(byte >> bit)) & 1;
            let mut next = crc << 1;
            next = next & !1 | shift_in;
            let b11 = ((crc >> 11) & 1) ^ shift_in;
            next = next & !(1 << 12) | b11 << 12;
            let b4 = ((crc >> 4) & 1) ^ shift_in;
            next = next & !(1 << 5) | b4 << 5;
            crc = next;
        }
    }
    !crc
}

/// `rtw_wow_pattern_generate`: the OS pattern is an 802.3 frame, hardware
/// matches from the LLC header, so the mask shifts by 6 bytes (bits) and
/// the CRC covers masked bytes from offset 12.
pub(super) fn generate(p: &WowlanPattern, own: [u8; 6]) -> Pattern {
    let pattern = &p.pattern;
    let mask = &p.mask;
    let kind = if pattern.len() >= 6 && pattern[..6] == [0xff; 6] {
        PatternType::Broadcast
    } else if pattern.first().is_some_and(|b| b & 1 != 0) {
        PatternType::Multicast
    } else if pattern.len() >= 6 && pattern[..6] == own {
        PatternType::Unicast
    } else {
        PatternType::Invalid
    };
    let mask_len = pattern.len().div_ceil(8).min(mask.len());
    let mut hw = [0u8; MASK_SIZE];
    if mask_len != 0 {
        let mut i = 0;
        while i + 1 < mask_len && i < MASK_SIZE {
            hw[i] = (mask[i] >> 6) | (mask[i + 1] & 0x3f) << 2;
            i += 1;
        }
        if i < MASK_SIZE {
            hw[i] = mask[i] >> 6;
        }
        hw[0] &= !0x3f;
    }
    let mut content = Vec::with_capacity(pattern.len());
    for (i, &b) in pattern.iter().enumerate().skip(12) {
        if mask.get(i / 8).is_some_and(|m| (m >> (i % 8)) & 1 != 0) {
            content.push(b);
        }
    }
    Pattern {
        kind,
        mask: hw,
        crc: crc16(&content),
    }
}

/// `rtw_wow_pattern_write_cam_ent`: four mask words at `(id << 3) + 0..3`
/// then the CRC/type/valid word at `(id << 3) + 4`. Returns
/// `(address, data)`.
pub(super) fn cam_entry(id: u8, p: &Pattern) -> [(u8, u32); 5] {
    let mut out = [(0u8, 0u32); 5];
    for (i, slot) in out.iter_mut().take(MASK_SIZE / 4).enumerate() {
        let m = &p.mask[i * 4..i * 4 + 4];
        *slot = (
            (id << 3) + i as u8,
            u32::from_le_bytes([m[0], m[1], m[2], m[3]]),
        );
    }
    let flags = match p.kind {
        PatternType::Broadcast => BIT_WKFMCAM_BC | BIT_WKFMCAM_VALID,
        PatternType::Multicast => BIT_WKFMCAM_MC | BIT_WKFMCAM_VALID,
        PatternType::Unicast => BIT_WKFMCAM_UC | BIT_WKFMCAM_VALID,
        PatternType::Invalid => 0,
    };
    out[4] = ((id << 3) + (MASK_SIZE / 4) as u8, u32::from(p.crc) | flags);
    out
}

/// `rtw_wow_param.flags` + pattern count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Flags {
    pub disconnect: bool,
    pub magic_packet: bool,
    pub rekey: bool,
    pub patterns: u8,
}
impl Flags {
    pub(super) fn from_config(config: &WowlanConfig) -> Self {
        Self {
            disconnect: config.disconnect,
            magic_packet: config.magic_packet,
            rekey: config.gtk_rekey_failure,
            patterns: config.patterns.len().min(MAX_PATTERNS) as u8,
        }
    }
}

/// fw.c WoW H2C builders. All are 8-byte HMEBOX commands, class in byte 0.
pub(super) mod h2c {
    use super::*;
    fn cmd(class: u8, word: u32) -> [u8; 8] {
        let mut out = [0; 8];
        out[..4].copy_from_slice(&(word | u32::from(class)).to_le_bytes());
        out
    }
    /// `rtw_fw_set_wowlan_ctrl_cmd` (managed-linked vif).
    pub(in super::super) fn wowlan(flags: Flags, enable: bool) -> [u8; 8] {
        let mut w = 0;
        if enable {
            w |= 1 << 8;
            if flags.magic_packet {
                w |= 1 << 10;
            }
            if flags.disconnect {
                w |= 1 << 15;
            }
            if flags.rekey {
                w |= 1 << 14;
            }
            if flags.patterns != 0 {
                w |= 1 << 9;
            }
        }
        cmd(H2C_CMD_WOWLAN, w)
    }
    /// `rtw_fw_set_remote_wake_ctrl_cmd`; NLO offload bit only without link.
    pub(in super::super) fn remote_wake(enable: bool) -> [u8; 8] {
        cmd(H2C_CMD_REMOTE_WAKE_CTRL, u32::from(enable) << 8)
    }
    /// `rtw_fw_set_aoac_global_info_cmd`.
    pub(in super::super) fn aoac(pairwise: KeyType, group: KeyType) -> [u8; 8] {
        cmd(
            H2C_CMD_AOAC_GLOBAL_INFO,
            (pairwise as u32) << 8 | (group as u32) << 16,
        )
    }
    /// `rtw_fw_set_keep_alive_cmd`: adopt, NULL packet, period 5.
    pub(in super::super) fn keep_alive(enable: bool) -> [u8; 8] {
        cmd(
            H2C_CMD_KEEP_ALIVE,
            u32::from(enable) << 8 | 1 << 9 | 5 << 16,
        )
    }
    /// `rtw_fw_set_disconnect_decision_cmd`: adopt, period 30, 5 retries,
    /// only when the disconnect trigger is armed (else class only).
    pub(in super::super) fn disconnect_decision(flags: Flags, enable: bool) -> [u8; 8] {
        let w = if flags.disconnect {
            u32::from(enable) << 8 | 1 << 9 | 30 << 16 | 5 << 24
        } else {
            0
        };
        cmd(H2C_CMD_DISCONNECT_DECISION, w)
    }
    /// `rtw_fw_media_status_report`.
    pub(in super::super) fn media_status(mac_id: u8, connect: bool) -> [u8; 8] {
        cmd(
            H2C_CMD_MEDIA_STATUS_RPT,
            u32::from(connect) << 8 | u32::from(mac_id) << 16,
        )
    }
    /// `rtw_send_rsvd_page_h2c`: probe-resp, PS-Poll, NULL, QoS-NULL page
    /// locations in bytes 1..=4 (`runtime_ps_wire::Pages::locations`).
    pub(in super::super) fn rsvd_page(locations: [u8; 8]) -> [u8; 8] {
        let mut out = [0; 8];
        out[0] = H2C_CMD_RSVD_PAGE;
        out[1..5].copy_from_slice(&locations[1..5]);
        out
    }
}

/// cfg80211 `struct cfg80211_wowlan_wakeup` subset rtw88 reports
/// (`rtw_wow_show_wakeup_reason`). Like iwlwifi (§3.80), the shared
/// contract has no `ieee80211_report_wowlan_wakeup` event, so this is a
/// driver accessor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakeReport {
    pub disconnect: bool,
    pub magic_packet: bool,
    pub gtk_rekey_failure: bool,
    /// Firmware reports no index; Linux reports 0.
    pub pattern_index: Option<u8>,
    pub net_detect: bool,
    /// `REG_WOWLAN_WAKE_REASON` value that maps to no trigger (Linux
    /// reports a NULL wakeup).
    pub unknown: Option<u8>,
}

/// `enum rtw_wake_reason` → report, exactly as `rtw_wow_show_wakeup_reason`.
pub(super) fn decode(reason: u8) -> WakeReport {
    let mut r = WakeReport::default();
    match reason {
        0x08 | 0x10 => r.disconnect = true,
        0x21 => r.magic_packet = true,
        0x02 => r.gtk_rekey_failure = true,
        0x23 => r.pattern_index = Some(0),
        0x55 => r.net_detect = true,
        other => r.unknown = Some(other),
    }
    r
}
/// Linux keeps the association after every reason; NARF additionally
/// drops it when the AP is gone, so the SME rejoins explicitly.
pub(super) fn keeps_link(report: &WakeReport) -> bool {
    !report.disconnect && report.unknown.is_none()
}

/// Everything `rtw_wow_suspend` reads from the managed-linked station.
pub(super) struct Plan {
    pub own: [u8; 6],
    pub mac_id: u8,
    pub flags: Flags,
    pub patterns: Vec<Pattern>,
    pub pairwise: KeyType,
    pub group: KeyType,
    /// PTK/GTK security-CAM entries for AOAC (`sec.c`); empty on an open BSS.
    pub cam: Vec<super::security_cam::Entry>,
    /// STA reserved pages (`rtw_add_rsvd_page_sta`), built by
    /// `runtime_ps_wire::Pages::station`.
    pub pages: Vec<u8>,
    pub locations: [u8; 8],
}
impl Plan {
    pub(super) fn new(
        did: u16,
        config: &WowlanConfig,
        own: [u8; 6],
        peer: [u8; 6],
        aid: u16,
        wmm: bool,
        keys: Option<&narf_wireless::station_security::SuspendKeys>,
    ) -> Result<Self, Error> {
        validate(did, config)?;
        // wow.c::rtw_wow_fw_security_type_iter: CCMP maps to RTW_CAM_AES for
        // both the pairwise and the group slot; an open BSS reports none.
        let (cam, pairwise, group) = match keys {
            Some(keys) => (
                super::security_cam::entries(keys, peer)?,
                KeyType::Aes,
                KeyType::Aes,
            ),
            None => (Vec::new(), KeyType::None, KeyType::None),
        };
        let pages =
            super::runtime_ps_wire::Pages::station(own, peer, aid, wmm).ok_or(Error::Invalid)?;
        Ok(Self {
            own,
            mac_id: 0,
            flags: Flags::from_config(config),
            patterns: config.patterns.iter().map(|p| generate(p, own)).collect(),
            pairwise,
            group,
            cam,
            pages: pages.bytes,
            locations: pages.locations,
        })
    }
}

/// Hardware side of the WoW sequence. `download` must run the same
/// authenticated section download as bring-up (`firmware_transport`
/// `Owner::run`) followed by `rtw_fw_send_general_info`/`phydm_info`;
/// `reserved_page` the same reserved-page DMA. The caller must hold the
/// original station quiesced (no host TX/RX publication) for the whole
/// sequence.
#[async_trait::async_trait]
pub(super) trait Io: Send {
    fn read8(&mut self, reg: u16) -> Result<u8, NativeError>;
    fn read32(&mut self, reg: u16) -> Result<u32, NativeError>;
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), NativeError>;
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), NativeError>;
    async fn delay_us(&mut self, us: u64);
    async fn download(&mut self, image: &PreparedImage) -> Result<(), NativeError>;
    async fn reserved_page(&mut self, pages: &[u8]) -> Result<(), NativeError>;
    async fn h2c(&mut self, command: [u8; 8]) -> Result<(), NativeError>;
    /// `rtw_hci_stop` (PCI: stop TX/RX rings and IRQ).
    fn hci_stop(&mut self) -> Result<(), NativeError>;
    /// `rtw_hci_setup` + `rtw_hci_start`.
    async fn hci_restart(&mut self) -> Result<(), NativeError>;
    /// After `rtw_wow_resume_trx`: close the firmware-swap window and
    /// readmit host packet producers on the restored normal image.
    fn end_swap(&mut self) -> Result<(), NativeError>;
}

async fn poll32<I: Io>(
    io: &mut I,
    reg: u16,
    mask: u32,
    want: u32,
    tries: u32,
) -> Result<(), Error> {
    for _ in 0..tries {
        let v = io.read32(reg)?;
        if v == u32::MAX {
            return Err(Error::Native(NativeError::Gone));
        }
        if v & mask == want {
            return Ok(());
        }
        io.delay_us(1000).await;
    }
    Err(Error::Timeout)
}
fn update8<I: Io>(io: &mut I, reg: u16, clear: u8, set: u8) -> Result<(), Error> {
    let v = io.read8(reg)?;
    io.write8(reg, v & !clear | set)?;
    Ok(())
}
fn update32<I: Io>(io: &mut I, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let v = io.read32(reg)?;
    io.write32(reg, v & !clear | set)?;
    Ok(())
}

/// `rtw_wow_bb_stop`. Returns the saved `REG_TXPAUSE`.
async fn bb_stop<I: Io>(io: &mut I) -> Result<u8, Error> {
    io.delay_us(100_000).await;
    // Linux only warns on a non-empty MGQ; the read is kept for parity.
    let _mgq_empty = io.read32(REG_BCNQ_INFO)? & BIT_MGQ_CPU_EMPTY != 0;
    let txpause = io.read8(REG_TXPAUSE)?;
    io.write8(REG_TXPAUSE, 0xff)?;
    update8(io, REG_SYS_FUNC_EN, BIT_FEN_BB_RSTB, 0)?;
    Ok(txpause)
}
/// `rtw_wow_bb_start`.
fn bb_start<I: Io>(io: &mut I, txpause: u8) -> Result<(), Error> {
    update8(io, REG_SYS_FUNC_EN, 0, BIT_FEN_BB_RSTB)?;
    io.write8(REG_TXPAUSE, txpause)?;
    Ok(())
}
/// `rtw_wow_rx_dma_stop`. Linux logs a non-idle RX DMA and proceeds; NARF
/// refuses to swap firmware under an active RX DMA engine.
async fn rx_dma_stop<I: Io>(io: &mut I) -> Result<(), Error> {
    io.delay_us(100_000).await;
    update32(io, REG_RXPKT_NUM, 0, BIT_RW_RELEASE)?;
    poll32(io, REG_RXPKT_NUM, BIT_RXDMA_IDLE, BIT_RXDMA_IDLE, 100).await
}
/// `rtw_wow_pattern_write_cam`: one word, then poll the busy bit.
async fn cam_write<I: Io>(io: &mut I, addr: u8, data: u32) -> Result<(), Error> {
    io.write32(REG_WKFMCAM_RWD, data)?;
    io.write32(
        REG_WKFMCAM_CMD,
        BIT_WKFCAM_POLLING_V1 | BIT_WKFCAM_WE | u32::from(addr) << 8,
    )?;
    poll32(io, REG_WKFMCAM_CMD, BIT_WKFCAM_POLLING_V1, 0, 100).await
}
/// `rtw_wow_pattern_clear_cam`.
async fn cam_clear<I: Io>(io: &mut I) -> Result<(), Error> {
    io.write32(REG_WKFMCAM_CMD, BIT_WKFCAM_POLLING_V1 | BIT_WKFCAM_CLR_V1)?;
    poll32(io, REG_WKFMCAM_CMD, BIT_WKFCAM_POLLING_V1, 0, 100).await
}
/// `rtw_wow_check_fw_status`: 1 ms step, 100 ms budget.
async fn check_fw_status<I: Io>(io: &mut I, enable: bool) -> Result<(), Error> {
    if enable {
        for _ in 0..100 {
            if io.read8(REG_WOWLAN_WAKE_REASON)? == 0 {
                return Ok(());
            }
            io.delay_us(1000).await;
        }
        return Err(Error::Timeout);
    }
    poll32(io, REG_FE1IMR, BIT_FS_RXDONE, 0, 100).await?;
    poll32(io, REG_RXPKT_NUM, BIT_RW_RELEASE, 0, 100).await
}

/// Proof that the WoW firmware is running with the host transport stopped.
/// Only [`resume`] consumes it; dropping it means the caller must restart.
#[must_use]
pub(super) struct Armed {
    flags: Flags,
    mac_id: u8,
    pages: Vec<u8>,
    cam: super::security_cam::Installed,
}

/// `rtw_wow_suspend` for a managed-linked station (`rtw_wow_enable` +
/// `rtw_wow_start`). LPS entry (`rtw_wow_enter_ps`) is not performed: the
/// WoW firmware stays awake under the station's existing power program.
pub(super) async fn suspend<I: Io>(
    io: &mut I,
    plan: &Plan,
    wow_image: &PreparedImage,
) -> Result<Armed, Error> {
    // rtw_wow_stop_trx
    let txpause = bb_stop(io).await?;
    rx_dma_stop(io).await?;
    // rtw_wow_swap_fw(RTW_WOWLAN_FW)
    io.download(wow_image).await?;
    io.h2c(h2c::media_status(plan.mac_id, true)).await?;
    // rtw_ops_set_key(SET_KEY) + rtw_sec_enable_sec_engine: Linux keeps the
    // keys in the CAM all along; NARF installs them only now, with host RX
    // DMA stopped, so the awake path never saw device-decrypted frames.
    let cam = super::security_cam::install(io, &plan.cam).await?;
    // rtw_wow_config_wow_fw_rsvd_page
    io.reserved_page(&plan.pages).await?;
    // rtw_wow_fw_start (mgd linked)
    io.h2c(h2c::rsvd_page(plan.locations)).await?;
    for (id, p) in plan.patterns.iter().enumerate() {
        for (addr, data) in cam_entry(id as u8, p) {
            cam_write(io, addr, data).await?;
        }
    }
    io.h2c(h2c::aoac(plan.pairwise, plan.group)).await?;
    io.h2c(h2c::disconnect_decision(plan.flags, true)).await?;
    io.h2c(h2c::keep_alive(true)).await?;
    io.h2c(h2c::wowlan(plan.flags, true)).await?;
    io.h2c(h2c::remote_wake(true)).await?;
    check_fw_status(io, true).await?;
    // rtw_wow_start tail
    io.hci_stop()?;
    bb_start(io, txpause)?;
    // rtw_wow_avoid_reset_mac (PCIe)
    io.write8(REG_RSV_CTRL, BIT_WLOCK_1C_B6)?;
    io.write8(REG_RSV_CTRL, BIT_WLOCK_1C_B6 | BIT_R_DIS_PRST)?;
    Ok(Armed {
        flags: plan.flags,
        mac_id: plan.mac_id,
        pages: plan.pages.clone(),
        cam,
    })
}

/// `rtw_wow_resume`: read the wake reason, stop WoW firmware, restore the
/// authenticated normal image and its reserved pages, restart TRX. Any
/// error is returned after the reason is captured; the caller restarts.
pub(super) async fn resume<I: Io>(
    io: &mut I,
    armed: Armed,
    normal_image: &PreparedImage,
) -> (Option<WakeReport>, Result<(), Error>) {
    let report = match io.read8(REG_WOWLAN_WAKE_REASON) {
        Ok(reason) => decode(reason),
        Err(e) => return (None, Err(e.into())),
    };
    let result = resume_inner(io, armed, normal_image).await;
    (Some(report), result)
}
async fn resume_inner<I: Io>(
    io: &mut I,
    armed: Armed,
    normal_image: &PreparedImage,
) -> Result<(), Error> {
    // Return to software CCMP before any host ring restarts, so no
    // device-decrypted frame reaches the host's CCMP/replay path. Linux
    // keeps hardware keys (rtw_ops_set_key) and has nothing to undo.
    super::security_cam::clear(io, armed.cam).await?;
    // rtw_wow_stop
    io.hci_restart().await?;
    io.h2c(h2c::disconnect_decision(armed.flags, false)).await?;
    io.h2c(h2c::keep_alive(false)).await?;
    cam_clear(io).await?;
    io.h2c(h2c::wowlan(armed.flags, false)).await?;
    io.h2c(h2c::remote_wake(false)).await?;
    check_fw_status(io, false).await?;
    // The suspend tail restored TXPAUSE, so this re-read is the original.
    let txpause = bb_stop(io).await?;
    // rtw_wow_swap_fw(RTW_NORMAL_FW)
    io.download(normal_image).await?;
    io.h2c(h2c::media_status(armed.mac_id, true)).await?;
    // rtw_wow_config_normal_fw_rsvd_page (linked)
    io.reserved_page(&armed.pages).await?;
    // rtw_wow_resume_trx
    update32(io, REG_RXPKT_NUM, BIT_RW_RELEASE, 0)?;
    bb_start(io, txpause)?;
    io.end_swap()?;
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "wow_tests.rs"]
mod tests;
