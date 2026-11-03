// SPDX-License-Identifier: GPL-2.0-or-later
//! Station WoWLAN over the TLV WMI dialect (Linux `wow.c`, `wmi-tlv.c`).
//!
//! Only `wmi-tlv.c` implements the `gen_wow_*` ops; MAIN/10.x/10.4 images
//! never get `wiphy->wowlan`. Advertisement additionally needs firmware
//! feature `ATH10K_FW_FEATURE_WOWLAN_SUPPORT` (bit 6) and TLV service
//! `WMI_TLV_SERVICE_WOW` (13), exactly as `ath10k_wow_init`.
//!
//! Suspend (`ath10k_wow_op_suspend`): clear every wake event and every
//! pattern slot on the station vdev, program the requested patterns and
//! events, wait for TX completion, send `WOW_ENABLE` and wait for the HTC
//! endpoint-0 SEND_SUSPEND_COMPLETE. Resume (`ath10k_wow_op_resume`): send
//! `WOW_HOSTWAKEUP_FROM_SLEEP` and wait for `WOW_WAKEUP_HOST`, whose wake
//! reason and raw packet buffer are retained as a [`WakeReport`].
//!
//! Keys stay in the firmware key cache and host PN/replay counters stay in
//! the retained station owner; neither is reset by this sequence.
use super::*;
use narf_wireless::{WowlanConfig, WowlanSupport};

/// `ATH10K_FW_FEATURE_WOWLAN_SUPPORT`.
const FEATURE_WOWLAN: u64 = 1 << 6;
/// `WMI_TLV_SERVICE_WOW` / `WMI_TLV_SERVICE_NLO`.
const SERVICE_WOW: usize = 13;
// `wmi-tlv.h` WMI_TLV_GRP_WOW (0x13) command and event identities.
const ADD_PATTERN: u32 = 0x13001;
const DEL_PATTERN: u32 = 0x13002;
const ADD_DEL_EVENT: u32 = 0x13003;
const ENABLE: u32 = 0x13004;
const HOST_WAKEUP: u32 = 0x13005;
pub(in crate::ath10k) const WAKEUP_EVENT: u32 = 0x13001;
// `enum wmi_tlv_tag`.
const TAG_ARRAY_UINT32: u32 = 16;
const TAG_ARRAY_BYTE: u16 = 17;
const TAG_ARRAY_STRUCT: u32 = 18;
const TAG_EVENT_INFO: u16 = 49;
const TAG_ENABLE: u32 = 119;
const TAG_HOST_WAKEUP: u32 = 120;
const TAG_DEL_PATTERN: u32 = 136;
const TAG_ADD_DEL_EVENT: u32 = 137;
const TAG_ADD_PATTERN: u32 = 179;
const TAG_BITMAP_PATTERN: u32 = 180;
/// `WOW_EVENT_MAX` (`enum wmi_wow_wakeup_event`).
pub(in crate::ath10k) const EVENT_MAX: u32 = 24;
/// `TARGET_TLV_NUM_WOW_PATTERNS`, also INIT's `num_wow_filters`.
pub(in crate::ath10k) const PATTERNS: u32 = 22;
/// `WOW_MAX_PATTERN_SIZE` / `WOW_DEFAULT_BITMAP_PATTERN_SIZE`.
const PATTERN_SIZE: usize = 148;
/// `WOW_MAX_PKT_OFFSET`.
const MAX_OFFSET: usize = 128;
/// `WOW_HDR_LEN`: `ieee80211_hdr_3addr` + `rfc1042_hdr`.
const HDR_LEN: usize = 32;
const ETH_HLEN: usize = 14;
/// `WOW_MAX_REDUCE` = WOW_HDR_LEN - ETH_HLEN - offsetof(addr1).
const MAX_REDUCE: usize = HDR_LEN - ETH_HLEN - 4;
// `enum wmi_wow_wakeup_event`.
const BMISS: u32 = 0;
const DEAUTH: u32 = 2;
const MAGIC: u32 = 3;
const DISASSOC: u32 = 8;
const PATTERN: u32 = 9;
const CSA_IE: u32 = 10;
/// Linux `ath10k_mac_wait_tx_complete` (`ATH10K_FLUSH_TIMEOUT_HZ`).
const FLUSH_MS: u64 = 5000;
/// `ath10k_wow_enable` / `ath10k_wow_wakeup`: 3 s completions.
const WOW_MS: u64 = 3000;

/// `ar->wmi.rx_decap_mode` for the station owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath10k) enum Decap {
    /// `ATH10K_HW_TXRX_RAW` (every NARF station owner).
    Raw,
    /// `ATH10K_HW_TXRX_NATIVE_WIFI`.
    NativeWifi,
}

/// `ath10k_wowlan_support` after `ath10k_wow_init`. Under RAW decap
/// `ath10k_vif_wow_set_wakeups` never copies the cfg80211 pattern into the
/// zero-initialised `new_pattern` and so programs zero-length patterns;
/// NARF therefore advertises no patterns for RAW instead of that no-op.
/// NET_DETECT (`WMI_SERVICE_NLO`) is not implemented and not advertised.
pub(in crate::ath10k) fn support(decap: Decap) -> WowlanSupport {
    let (max_patterns, min, max, offset) = match decap {
        Decap::Raw => (0, 0, 0, 0),
        Decap::NativeWifi => (
            PATTERNS as u8,
            1,
            (PATTERN_SIZE - MAX_REDUCE) as u16,
            (MAX_OFFSET - MAX_REDUCE) as u16,
        ),
    };
    WowlanSupport {
        disconnect: true,
        magic_packet: true,
        gtk_rekey: false,
        gtk_rekey_failure: false,
        max_patterns,
        min_pattern_len: min,
        max_pattern_len: max,
        max_packet_offset: offset,
        net_detect_max_match_sets: 0,
        net_detect_random_mac: false,
    }
}

/// One firmware bitmap pattern after `ath10k_vif_wow_set_wakeups`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::ath10k) struct Pattern {
    pub bytes: Vec<u8>,
    /// One 0x00/0xff byte per pattern byte.
    pub mask: Vec<u8>,
    pub offset: u32,
}

/// The validated station wake program (`ath10k_vif_wow_set_wakeups`, STA).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::ath10k) struct Program {
    /// Bit `n` enables `enum wmi_wow_wakeup_event` value `n`.
    pub events: u32,
    pub patterns: Vec<Pattern>,
}

impl Program {
    /// Re-validate a retained cfg80211 configuration against `support`.
    pub(in crate::ath10k) fn new(config: &WowlanConfig, decap: Decap) -> Result<Self, Error> {
        let limits = support(decap);
        if config.gtk_rekey_failure
            || config.net_detect.is_some()
            || config.patterns.len() > usize::from(limits.max_patterns)
        {
            return Err(Error::Unsupported);
        }
        let mut events = 0;
        if config.disconnect {
            events |= (1 << DEAUTH) | (1 << DISASSOC) | (1 << BMISS) | (1 << CSA_IE);
        }
        if config.magic_packet {
            events |= 1 << MAGIC;
        }
        let mut patterns = Vec::new();
        patterns
            .try_reserve_exact(config.patterns.len())
            .map_err(|_| Error::NoMemory)?;
        for pattern in &config.patterns {
            let length = pattern.pattern.len();
            let offset = usize::try_from(pattern.offset).map_err(|_| Error::Unsupported)?;
            if length < usize::from(limits.min_pattern_len)
                || length > usize::from(limits.max_pattern_len)
                || offset > usize::from(limits.max_packet_offset)
                || pattern.mask.len() != length.div_ceil(8)
            {
                return Err(Error::Unsupported);
            }
            // Bytemask (one bit per byte, LSB first) to firmware bitmask.
            let mut mask = Vec::new();
            mask.try_reserve_exact(length)
                .map_err(|_| Error::NoMemory)?;
            mask.extend((0..length).map(|j| {
                if pattern.mask[j / 8] & (1 << (j % 8)) != 0 {
                    0xff
                } else {
                    0
                }
            }));
            let converted = convert_8023(&pattern.pattern, &mask, offset)?;
            if converted.bytes.len() > PATTERN_SIZE {
                return Err(Error::Unsupported);
            }
            patterns.push(converted);
            events |= 1 << PATTERN;
        }
        Ok(Self { events, patterns })
    }
}

/// `ath10k_wow_convert_8023_to_80211` for offsets inside the Ethernet header,
/// else `pkt_offset += WOW_HDR_LEN - ETH_HLEN` (native-WiFi decap only).
fn convert_8023(pattern: &[u8], mask: &[u8], offset: usize) -> Result<Pattern, Error> {
    let owned = |bytes: &[u8]| wire::owned(bytes);
    if offset >= ETH_HLEN {
        return Ok(Pattern {
            bytes: owned(pattern)?,
            mask: owned(mask)?,
            offset: (offset + HDR_LEN - ETH_HLEN) as u32,
        });
    }
    let total = offset + pattern.len();
    let head = (ETH_HLEN - offset).min(pattern.len());
    let mut eth = [[0u8; ETH_HLEN]; 2];
    eth[0][offset..offset + head].copy_from_slice(&pattern[..head]);
    eth[1][offset..offset + head].copy_from_slice(&mask[..head]);
    let mut wifi = [[0u8; HDR_LEN]; 2];
    for (wifi, eth) in wifi.iter_mut().zip(eth.iter()) {
        wifi[4..10].copy_from_slice(&eth[0..6]); // addr1 <- h_dest
        wifi[16..22].copy_from_slice(&eth[6..12]); // addr3 <- h_source
        wifi[30..32].copy_from_slice(&eth[12..14]); // snap_type <- h_proto
    }
    let start = if offset < 6 {
        offset + 4
    } else if offset < 12 {
        offset + 16 - 6
    } else {
        offset + HDR_LEN - ETH_HLEN
    };
    let end = if total > ETH_HLEN {
        HDR_LEN
    } else if total > 12 {
        HDR_LEN + total - ETH_HLEN
    } else if total > 6 {
        total - 6 + 16
    } else {
        total + 4
    };
    let mut bytes = owned(&wifi[0][start..end])?;
    let mut bits = owned(&wifi[1][start..end])?;
    if total > ETH_HLEN {
        let body = ETH_HLEN - offset;
        bytes
            .try_reserve_exact(pattern.len() - body)
            .map_err(|_| Error::NoMemory)?;
        bits.try_reserve_exact(pattern.len() - body)
            .map_err(|_| Error::NoMemory)?;
        bytes.extend_from_slice(&pattern[body..]);
        bits.extend_from_slice(&mask[body..]);
    }
    Ok(Pattern {
        bytes,
        mask: bits,
        offset: start as u32,
    })
}

fn tlv(v: &mut [u8], at: usize, tag: u32, len: usize) {
    wire::put(v, at, (tag << 16) | len as u32);
}
/// `ath10k_wmi_tlv_op_gen_wow_enable` (PCI `link_can_suspend`: pause 0).
pub(in crate::ath10k) fn enable() -> Result<Vec<u8>, Error> {
    let mut out = wire::packet(ENABLE, 16)?;
    tlv(&mut out, 4, TAG_ENABLE, 12);
    wire::put(&mut out, 8, 1);
    Ok(out)
}
/// `ath10k_wmi_tlv_op_gen_wow_add_wakeup_event`.
pub(in crate::ath10k) fn wakeup_event(vdev: u32, event: u32, add: bool) -> Result<Vec<u8>, Error> {
    if event >= EVENT_MAX {
        return Err(Error::Unsupported);
    }
    let mut out = wire::packet(ADD_DEL_EVENT, 16)?;
    tlv(&mut out, 4, TAG_ADD_DEL_EVENT, 12);
    wire::put(&mut out, 8, vdev);
    wire::put(&mut out, 12, u32::from(add));
    wire::put(&mut out, 16, 1 << event);
    Ok(out)
}
/// `ath10k_wmi_tlv_gen_wow_host_wakeup_ind`.
pub(in crate::ath10k) fn host_wakeup() -> Result<Vec<u8>, Error> {
    let mut out = wire::packet(HOST_WAKEUP, 8)?;
    tlv(&mut out, 4, TAG_HOST_WAKEUP, 4);
    Ok(out)
}
/// `ath10k_wmi_tlv_op_gen_wow_del_pattern` (`WOW_BITMAP_PATTERN`).
pub(in crate::ath10k) fn del_pattern(vdev: u32, id: u32) -> Result<Vec<u8>, Error> {
    let mut out = wire::packet(DEL_PATTERN, 16)?;
    tlv(&mut out, 4, TAG_DEL_PATTERN, 12);
    wire::put(&mut out, 8, vdev);
    wire::put(&mut out, 12, id);
    Ok(out)
}
/// `ath10k_wmi_tlv_op_gen_wow_add_pattern`: the bitmap pattern followed by
/// empty IPv4/IPv6-sync, magic and info-timeout arrays and one zero
/// ratelimit word.
pub(in crate::ath10k) fn add_pattern(
    vdev: u32,
    id: u32,
    pattern: &Pattern,
) -> Result<Vec<u8>, Error> {
    let length = pattern.bytes.len();
    if length > PATTERN_SIZE || pattern.mask.len() != length {
        return Err(Error::Unsupported);
    }
    const BITMAP: usize = 2 * PATTERN_SIZE + 16;
    let mut out = wire::packet(ADD_PATTERN, 16 + 4 + 4 + BITMAP + 4 * 4 + 8)?;
    tlv(&mut out, 4, TAG_ADD_PATTERN, 12);
    wire::put(&mut out, 8, vdev);
    wire::put(&mut out, 12, id);
    // pattern_type WOW_BITMAP_PATTERN = 0.
    tlv(&mut out, 20, TAG_ARRAY_STRUCT, 4 + BITMAP);
    tlv(&mut out, 24, TAG_BITMAP_PATTERN, BITMAP);
    out[28..28 + length].copy_from_slice(&pattern.bytes);
    out[28 + PATTERN_SIZE..28 + PATTERN_SIZE + length].copy_from_slice(&pattern.mask);
    let at = 28 + 2 * PATTERN_SIZE;
    wire::put(&mut out, at, pattern.offset);
    wire::put(&mut out, at + 4, length as u32);
    wire::put(&mut out, at + 8, length as u32);
    wire::put(&mut out, at + 12, id);
    let mut at = 24 + 4 + BITMAP;
    for tag in [
        TAG_ARRAY_STRUCT,
        TAG_ARRAY_STRUCT,
        TAG_ARRAY_STRUCT,
        TAG_ARRAY_UINT32,
    ] {
        tlv(&mut out, at, tag, 0);
        at += 4;
    }
    tlv(&mut out, at, TAG_ARRAY_UINT32, 4);
    Ok(out)
}

/// `struct wmi_wow_ev_arg` plus the event's raw `wow_packet_buffer` (the
/// shared contract has no `ieee80211_report_wowlan_wakeup`; Linux ath10k
/// only logs the reason and never decodes the buffer, so neither does NARF).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WakeReport {
    pub vdev: u32,
    pub flag: u32,
    /// `enum wmi_wow_wake_reason` (0xffffffff = UNSPECIFIED).
    pub reason: u32,
    /// The first `data_len` bytes of the optional ARRAY_BYTE buffer.
    pub packet: Vec<u8>,
}
impl WakeReport {
    pub const NLOD: u32 = 0;
    pub const AP_ASSOC_LOST: u32 = 1;
    pub const DEAUTH_RECVD: u32 = 3;
    pub const DISASSOC_RECVD: u32 = 4;
    pub const GTK_HS_ERR: u32 = 5;
    pub const EAP_REQ: u32 = 6;
    pub const FOURWAY_HS_RECV: u32 = 7;
    pub const PATTERN_MATCH_FOUND: u32 = 9;
    pub const RECV_MAGIC_PATTERN: u32 = 10;
    pub const CSA_EVENT: u32 = 13;
    pub fn magic_packet(&self) -> bool {
        self.reason == Self::RECV_MAGIC_PATTERN
    }
    pub fn pattern(&self) -> bool {
        self.reason == Self::PATTERN_MATCH_FOUND
    }
    /// Beacon loss, deauthentication, disassociation or a channel switch:
    /// cfg80211's `disconnect` wake (Linux maps BMISS/CSA there too).
    pub fn disconnect(&self) -> bool {
        matches!(
            self.reason,
            Self::AP_ASSOC_LOST | Self::DEAUTH_RECVD | Self::DISASSOC_RECVD | Self::CSA_EVENT
        )
    }
    /// The host association cannot be assumed current: a disconnect-class
    /// wake or a firmware-observed key handshake NARF does not offload.
    pub fn connection_lost(&self) -> bool {
        self.disconnect()
            || matches!(
                self.reason,
                Self::GTK_HS_ERR | Self::EAP_REQ | Self::FOURWAY_HS_RECV
            )
    }
}

/// `ath10k_wmi_tlv_op_pull_wow_ev` over the body after the WMI header.
pub(in crate::ath10k) fn wake_event(body: &[u8]) -> Result<WakeReport, Error> {
    let info = wire::tag(body, TAG_EVENT_INFO)?;
    if info.len() < 16 {
        return Err(Error::Malformed);
    }
    let data_len = wire::word(info, 12)? as usize;
    let packet = match wire::tag(body, TAG_ARRAY_BYTE) {
        Ok(buffer) => wire::owned(&buffer[..data_len.min(buffer.len())])?,
        Err(_) => Vec::new(),
    };
    Ok(WakeReport {
        vdev: wire::word(info, 0)?,
        flag: wire::word(info, 4)?,
        reason: wire::word(info, 8)?,
        packet,
    })
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn wow_decap(&self) -> Decap {
        if self.htt.wmi.raw_mode() {
            Decap::Raw
        } else {
            Decap::NativeWifi
        }
    }
    /// `ath10k_wow_init`: TLV dialect, firmware WOWLAN feature and service.
    /// The station data owner (RAW, or native WiFi with hardware keys on
    /// TLV firmware without `RAW_MODE_SUPPORT`) is also required before
    /// anything is advertised.
    pub(in crate::ath10k) fn wowlan_support(&self) -> Option<WowlanSupport> {
        let caps = self.htt.wmi.caps.as_ref()?;
        (self.wire.dialect == Dialect::Tlv
            && self.features & FEATURE_WOWLAN != 0
            && caps.service(Dialect::Tlv, SERVICE_WOW)
            && self.data_supported())
        .then(|| support(self.wow_decap()))
    }
    pub(in crate::ath10k) fn wow_armed(&self) -> bool {
        self.wow_armed
    }
    async fn send_all(&mut self, commands: &[Vec<u8>]) -> Result<(), Error> {
        for command in commands {
            self.htt
                .wmi
                .htc
                .send_wmi(command)
                .await
                .map_err(htt::Error::from)?;
        }
        Ok(())
    }
    /// `ath10k_wow_op_suspend` for the associated station vdev0. Any error
    /// leaves this owner failed; the caller falls back to the ordinary
    /// non-WoWLAN suspend exactly as Linux returns 1 to mac80211.
    pub(in crate::ath10k) async fn wow_suspend(
        &mut self,
        program: &Program,
        current: impl Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error>,
    ) -> Result<(), Error> {
        if self.failed || self.wow_armed || self.wowlan_support().is_none() {
            return Err(Error::Failed);
        }
        if self.station_link().is_none() {
            return Err(Error::Failed);
        }
        // All commands are encoded before the first publication.
        let mut commands = Vec::new();
        let count = (EVENT_MAX + PATTERNS) as usize + program.patterns.len() + EVENT_MAX as usize;
        commands
            .try_reserve_exact(count)
            .map_err(|_| Error::NoMemory)?;
        // ath10k_wow_vif_cleanup: disable every event, delete every slot.
        for event in 0..EVENT_MAX {
            commands.push(wakeup_event(0, event, false)?);
        }
        for id in 0..PATTERNS {
            commands.push(del_pattern(0, id)?);
        }
        for (id, pattern) in program.patterns.iter().enumerate() {
            commands.push(add_pattern(0, id as u32, pattern)?);
        }
        for event in (0..EVENT_MAX).filter(|e| program.events & (1 << e) != 0) {
            commands.push(wakeup_event(0, event, true)?);
        }
        let enable = enable()?;
        self.failed = true;
        self.send_all(&commands).await?;
        self.failed = false;
        // ath10k_mac_wait_tx_complete: a timeout is only a Linux warning.
        let deadline = narf_time::Deadline::after_ms(FLUSH_MS);
        while self.tx_in_flight() != 0 && !deadline.expired() {
            narf_scheduler::yield_now().await;
            // The host stack is quiescing for system sleep; frames received
            // during this flush are not delivered.
            let _ = self.poll_ethernet(&current()?).await?;
        }
        // ath10k_wow_enable: reinit target_suspend, send, wait 3 s.
        self.failed = true;
        let _ = self.htt.wmi.htc.take_suspend_complete();
        self.send_all(core::slice::from_ref(&enable)).await?;
        let deadline = narf_time::Deadline::after_ms(WOW_MS);
        loop {
            if self.htt.wmi.htc.take_suspend_complete() {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_scheduler::yield_now().await;
            let event = self.station_progress().await?;
            match event {
                htt::Event::Idle | htt::Event::Progress => {}
                other => self.queue(other)?,
            }
        }
        self.wow_armed = true;
        self.failed = false;
        Ok(())
    }
    /// `ath10k_wow_op_resume` after `ath10k_hif_resume`: HOSTWAKEUP, then the
    /// firmware's WOW_WAKEUP_HOST within 3 s. Errors leave the owner failed;
    /// Linux then marks the device RESTARTING for a full reconfiguration.
    pub(in crate::ath10k) async fn wow_resume(&mut self) -> Result<WakeReport, Error> {
        if self.failed || !self.wow_armed {
            return Err(Error::Failed);
        }
        let command = host_wakeup()?;
        self.failed = true;
        self.wow_armed = false;
        self.send_all(core::slice::from_ref(&command)).await?;
        let deadline = narf_time::Deadline::after_ms(WOW_MS);
        loop {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_scheduler::yield_now().await;
            let event = self.station_progress().await?;
            match event {
                htt::Event::Idle | htt::Event::Progress => {}
                htt::Event::Wmi(bytes) if wire::word(&bytes, 0)? & 0xffffff == WAKEUP_EVENT => {
                    let report = wake_event(&bytes[4..])?;
                    self.failed = false;
                    return Ok(report);
                }
                other => self.queue(other)?,
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "wow_tests.rs"]
mod tests;
