// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! API77 MVM WoWLAN/D3 wire contract.
//!
//! Mirrors Linux `mvm/d3.c` (`__iwl_mvm_suspend`, `iwl_mvm_get_wowlan_config`,
//! `iwl_mvm_wowlan_config`, `iwl_mvm_wowlan_config_rsc_tsc`,
//! `iwl_mvm_send_patterns`, `iwl_mvm_wait_d3_notif`,
//! `iwl_mvm_parse_wowlan_info_notif_v1`, `iwl_mvm_query_wakeup_reasons`),
//! `mvm/offloading.c::iwl_mvm_send_proto_offload`, `fw/api/d3.h` and
//! `fw/api/offload.h`. Only the exact command/notification versions that the
//! installed 22000/API77 images advertise are admitted; every other version
//! is refused instead of guessed.
//!
//! Those images set `IWL_UCODE_TLV_CAPA_CNSLDTD_D3_D0_IMG` (capability 17):
//! the runtime image is also the D3 image, so Linux never loads a separate
//! `IWL_UCODE_WOWLAN` image (`iwl_mvm_switch_to_d3` only runs for
//! non-unified images) and neither does NARF. A firmware without that bit
//! is refused.
use super::boot_context::{put16, put32};
use super::firmware_api::FirmwareApi;
use alloc::vec::Vec;
use narf_wireless::{WowlanConfig, WowlanSupport};
use zeroize::Zeroizing;

/// Narrow LONG_GROUP opcodes (`fw/api/commands.h`).
pub(super) const D3_CONFIG_CMD: u8 = 0xd3;
pub(super) const PROT_OFFLOAD_CONFIG_CMD: u8 = 0xd4;
pub(super) const WOWLAN_PATTERNS: u8 = 0xe0;
pub(super) const WOWLAN_CONFIGURATION: u8 = 0xe1;
pub(super) const WOWLAN_TSC_RSC_PARAM: u8 = 0xe2;
pub(super) const D0I3_END_CMD: u8 = 0xed;
/// `PROT_OFFLOAD_GROUP` notifications (`fw/api/offload.h`).
pub(super) const PROT_OFFLOAD_GROUP: u8 = 0xb;
pub(super) const WOWLAN_WAKE_PKT_NOTIFICATION: u8 = 0xfc;
pub(super) const WOWLAN_INFO_NOTIFICATION: u8 = 0xfd;
pub(super) const D3_END_NOTIFICATION: u8 = 0xfe;

const CAPA_CNSLDTD_D3_D0_IMG: usize = 17;
const CAPA_D0I3_END_FIRST: usize = 41;
const CAPA_OFFLOAD_BTM_SUPPORT: usize = 113;
const API_WOWLAN_TCP_SYN_WAKE: usize = 53;
const FLAGS_NEW_NSOFFL_SMALL: u32 = 1 << 15;
const FLAGS_NEW_NSOFFL_LARGE: u32 = 1 << 16;

/// `IWL_WOWLAN_MAX_PATTERNS` / `IWL_WOWLAN_{MIN,MAX}_PATTERN_LEN`.
pub(super) const MAX_PATTERNS: usize = 20;
pub(super) const MIN_PATTERN_LEN: usize = 16;
pub(super) const MAX_PATTERN_LEN: usize = 128;

/// `enum iwl_wowlan_wakeup_filters`.
pub(super) mod filter {
    pub const MAGIC_PACKET: u32 = 1 << 0;
    pub const PATTERN_MATCH: u32 = 1 << 1;
    pub const BEACON_MISS: u32 = 1 << 2;
    pub const LINK_CHANGE: u32 = 1 << 3;
}
/// `enum iwl_wowlan_flags`.
mod flags {
    pub const IS_11W_ASSOC: u8 = 1 << 0;
    pub const ENABLE_L3_FILTERING: u8 = 1 << 1;
    pub const ENABLE_NBNS_FILTERING: u8 = 1 << 2;
    pub const ENABLE_DHCP_FILTERING: u8 = 1 << 3;
}
/// `enum iwl_wowlan_wakeup_reason`.
pub(super) mod reason {
    pub const MAGIC_PACKET: u32 = 1 << 0;
    pub const PATTERN: u32 = 1 << 1;
    pub const MISSED_BEACON: u32 = 1 << 2;
    pub const DEAUTH: u32 = 1 << 3;
    pub const GTK_REKEY_FAILURE: u32 = 1 << 4;
    pub const RFKILL_DEASSERTED: u32 = 1 << 5;
    pub const UCODE_ERROR: u32 = 1 << 6;
    pub const EAPOL_REQUEST: u32 = 1 << 7;
    pub const FOUR_WAY_HANDSHAKE: u32 = 1 << 8;
    pub const UNPROTECTED_DEAUTH: u32 = 1 << 17;
    pub const TCP_SYN: u32 = 0xf << 18;
    /// `IWL_WOWLAN_WAKEUP_REASON_HAS_WAKEUP_PKT`.
    pub const HAS_WAKE_PACKET: u32 = MAGIC_PACKET | PATTERN | TCP_SYN;
}
/// `IWL_D0I3_RESET_REQUIRE`.
const D0I3_RESET_REQUIRE: u32 = 1 << 0;
/// `IWL_MCAST_KEY_MAP_INVALID`.
const MCAST_KEY_MAP_INVALID: u8 = 0xff;

/// Exact admitted D3 command surface of one parsed firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct D3Api {
    /// `IWL_UCODE_TLV_CAPA_OFFLOAD_BTM_SUPPORT`: Linux sets
    /// `IWL_D3_PROTO_OFFLOAD_BTM` whenever firmware advertises it.
    pub btm: bool,
}

impl D3Api {
    /// Admit only the 22000/API77 unified-image notification-based flow:
    /// WOWLAN_CONFIGURATION v6, WOWLAN_PATTERNS v3 (TCP-SYN-wake layout),
    /// WOWLAN_TSC_RSC_PARAM v5, PROT_OFFLOAD_CONFIG v4 (large NS layout),
    /// D3_CONFIG v4, D0I3_END_FIRST and WOWLAN_INFO v1 / WAKE_PKT v1 /
    /// D3_END v1. Linux would
    /// fall back to WOWLAN_GET_STATUSES or older layouts for other images;
    /// those are not implemented and fail closed here.
    pub(super) fn admit(api: &FirmwareApi<'_>) -> Result<Self, &'static str> {
        if !api.has_capability(CAPA_CNSLDTD_D3_D0_IMG) {
            return Err("MVM WoWLAN requires the consolidated D3/D0 image");
        }
        // Every installed API77 image sets D0I3_END_FIRST; the 22000 resume
        // then starts with D0I3_END_CMD (`iwl_mvm_resume_firmware`). The
        // doorbell/late-D0I3_END variants are not implemented.
        if !api.has_capability(CAPA_D0I3_END_FIRST) {
            return Err("MVM WoWLAN requires D0I3_END_FIRST resume");
        }
        let exact = |command, version| api.command_version(0, command) == Some(version);
        if !exact(WOWLAN_CONFIGURATION, 6) {
            return Err("MVM WoWLAN configuration version not admitted");
        }
        if !exact(WOWLAN_PATTERNS, 3)
            || api.api_changes[API_WOWLAN_TCP_SYN_WAKE / 32] & (1 << (API_WOWLAN_TCP_SYN_WAKE % 32))
                == 0
        {
            return Err("MVM WoWLAN pattern version not admitted");
        }
        if !exact(WOWLAN_TSC_RSC_PARAM, 5) {
            return Err("MVM WoWLAN RSC/TSC version not admitted");
        }
        if !exact(PROT_OFFLOAD_CONFIG_CMD, 4)
            || api.flags & FLAGS_NEW_NSOFFL_LARGE == 0
            || api.flags & FLAGS_NEW_NSOFFL_SMALL != 0
        {
            return Err("MVM WoWLAN protocol offload version not admitted");
        }
        if !exact(D3_CONFIG_CMD, 4) {
            return Err("MVM D3 configuration version not admitted");
        }
        // `iwl_mvm_d3_resume_notif_based`: all three notifications present.
        let notif = |command| api.versions(PROT_OFFLOAD_GROUP, command).map(|v| v.1);
        if notif(WOWLAN_INFO_NOTIFICATION) != Some(1)
            || notif(WOWLAN_WAKE_PKT_NOTIFICATION) != Some(1)
            || notif(D3_END_NOTIFICATION) != Some(1)
        {
            return Err("MVM WoWLAN resume notification versions not admitted");
        }
        Ok(Self {
            btm: api.has_capability(CAPA_OFFLOAD_BTM_SUPPORT),
        })
    }
}

/// `mvm/mac80211.c::iwl_mvm_mac_setup_register` limits, narrowed to the
/// triggers whose complete NARF path exists: disconnect, magic packet and
/// bitmask patterns. Linux's `max_pkt_offset` stays zero. GTK rekey offload
/// (`WOWLAN_KEK_KCK_MATERIAL`), EAP/4-way/RF-kill triggers and NET_DETECT are
/// not advertised.
pub(super) const fn support() -> WowlanSupport {
    WowlanSupport {
        disconnect: true,
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

/// One firmware bitmask pattern (`struct iwl_wowlan_pattern_v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Pattern {
    pub mask: Vec<u8>,
    pub bytes: Vec<u8>,
}

/// The validated cfg80211 request this firmware programs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Wake {
    pub disconnect: bool,
    pub magic_packet: bool,
    pub patterns: Vec<Pattern>,
}

impl Wake {
    /// Re-validate a shared configuration against [`support`]; nl80211
    /// already applied the same limits, but the driver never trusts them.
    pub(super) fn from_config(config: &WowlanConfig) -> Result<Self, &'static str> {
        if config.gtk_rekey_failure || config.net_detect.is_some() {
            return Err("MVM WoWLAN trigger not advertised");
        }
        if config.patterns.len() > MAX_PATTERNS {
            return Err("MVM WoWLAN pattern count exceeds firmware limit");
        }
        let mut patterns = Vec::with_capacity(config.patterns.len());
        for pattern in &config.patterns {
            let len = pattern.pattern.len();
            if !(MIN_PATTERN_LEN..=MAX_PATTERN_LEN).contains(&len)
                || pattern.mask.len() != len.div_ceil(8)
                || pattern.offset != 0
            {
                return Err("MVM WoWLAN pattern outside firmware limits");
            }
            patterns.push(Pattern {
                mask: pattern.mask.clone(),
                bytes: pattern.pattern.clone(),
            });
        }
        if !config.disconnect && !config.magic_packet && patterns.is_empty() {
            return Err("MVM WoWLAN configuration has no trigger");
        }
        Ok(Self {
            disconnect: config.disconnect,
            magic_packet: config.magic_packet,
            patterns,
        })
    }

    /// `iwl_mvm_get_wowlan_config` wakeup filter.
    pub(super) fn filter(&self) -> u32 {
        let mut value = 0;
        if self.disconnect {
            value |= filter::BEACON_MISS | filter::LINK_CHANGE;
        }
        if self.magic_packet {
            value |= filter::MAGIC_PACKET;
        }
        if !self.patterns.is_empty() {
            value |= filter::PATTERN_MATCH;
        }
        value
    }
}

/// Facts of the associated station that WOWLAN_CONFIGURATION carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Station {
    pub sta_id: u8,
    pub ht: bool,
    pub mfp: bool,
    /// Next QoS sequence number per TID (mac80211 `tid_data[].seq_number`).
    pub next_qos_seq: [u16; 8],
}

/// `struct iwl_wowlan_config_cmd_v6` (WOWLAN_CONFIG_API_S_VER_6). Version 6
/// leaves `non_qos_seq` reserved; version < 7 carries `qos_seq` as the last
/// used value (`iwl_mvm_set_wowlan_qos_seq`). TID 0 is the offload TID.
pub(super) fn configuration_v6(wake: &Wake, station: &Station) -> [u8; 28] {
    let mut bytes = [0; 28];
    put32(&mut bytes, 0, wake.filter());
    for (tid, next) in station.next_qos_seq.iter().enumerate() {
        put16(&mut bytes, 6 + 2 * tid, next.wrapping_sub(0x10));
    }
    bytes[22] = 0; // wowlan_ba_teardown_tids (Linux TODO)
    bytes[23] = station.ht as u8;
    bytes[24] = 0; // offloading_tid
    bytes[25] = flags::ENABLE_L3_FILTERING
        | flags::ENABLE_NBNS_FILTERING
        | flags::ENABLE_DHCP_FILTERING
        | if station.mfp { flags::IS_11W_ASSOC } else { 0 };
    bytes[26] = station.sta_id;
    bytes
}

/// `struct iwl_wowlan_pattern_v2` size: type + 3 reserved + union (148).
const PATTERN_V2: usize = 152;

/// `iwl_mvm_send_patterns` with `struct iwl_wowlan_patterns_cmd` v3. `None`
/// means no command is sent, exactly as Linux returns early.
pub(super) fn patterns_v3(sta_id: u8, patterns: &[Pattern]) -> Option<Vec<u8>> {
    if patterns.is_empty() {
        return None;
    }
    let mut bytes = alloc::vec![0; 4 + patterns.len() * PATTERN_V2];
    bytes[0] = patterns.len() as u8;
    bytes[1] = sta_id;
    for (index, pattern) in patterns.iter().enumerate() {
        let base = 4 + index * PATTERN_V2;
        bytes[base] = 0; // WOWLAN_PATTERN_TYPE_BITMASK
        let body = base + 4;
        bytes[body..body + pattern.mask.len()].copy_from_slice(&pattern.mask);
        bytes[body + 16..body + 16 + pattern.bytes.len()].copy_from_slice(&pattern.bytes);
        bytes[body + 144] = pattern.mask.len() as u8;
        bytes[body + 145] = pattern.bytes.len() as u8;
    }
    Some(bytes)
}

/// Host RX replay state handed to firmware for D3.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Counters {
    /// Highest accepted PTK PN per TID (`ucast_rsc`).
    pub ptk: Option<[u64; 8]>,
    /// Up to two installed GTKs: key index and highest accepted PN per TID.
    pub gtks: Vec<(u8, [u64; 8])>,
}

/// `struct iwl_wowlan_rsc_tsc_params_cmd` (ALL_TSC_RSC_API_S_VER_5), filled
/// like `iwl_mvm_wowlan_get_rsc_v5_data`. `None` mirrors Linux skipping the
/// command when no PTK/GTK has an RSC (`have_rsc`).
pub(super) fn rsc_tsc_v5(
    sta_id: u8,
    counters: &Counters,
) -> Result<Option<[u8; 200]>, &'static str> {
    if counters.ptk.is_none() && counters.gtks.is_empty() {
        return Ok(None);
    }
    if counters.gtks.len() > 2 {
        return Err("MVM WoWLAN more than two GTKs");
    }
    let mut bytes = [0; 200];
    if let Some(ptk) = counters.ptk {
        for (tid, pn) in ptk.iter().enumerate() {
            put64(&mut bytes, tid * 8, *pn);
        }
    }
    bytes[196..200].fill(MCAST_KEY_MAP_INVALID);
    for (slot, (id, pns)) in counters.gtks.iter().enumerate() {
        if *id > 3 || counters.gtks[..slot].iter().any(|(other, _)| other == id) {
            return Err("MVM WoWLAN GTK index invalid");
        }
        for (tid, pn) in pns.iter().enumerate() {
            put64(&mut bytes, 64 + slot * 64 + tid * 8, *pn);
        }
        bytes[196 + usize::from(*id)] = slot as u8;
    }
    put32(&mut bytes, 192, u32::from(sta_id));
    Ok(Some(bytes))
}

/// `struct iwl_proto_offload_cmd_v4` (PROT_OFFLOAD_CONFIG_CMD_DB_S_VER_4):
/// sta_id, common (20), num_valid_ipv6_addrs, 12 target addresses (20
/// each) and 4 NS configurations (40 each). NARF publishes no ARP/IPv6
/// address list to the driver, so like Linux with `arp_addr_cnt == 0` and no
/// IPv6 targets only the BTM bit can be enabled.
pub(super) fn proto_offload_v4(sta_id: u8, api: &D3Api) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 4 + 20 + 4 + 12 * 20 + 4 * 40];
    put32(&mut bytes, 0, u32::from(sta_id));
    // IWL_D3_PROTO_OFFLOAD_BTM
    put32(&mut bytes, 4, if api.btm { 1 << 4 } else { 0 });
    bytes
}

/// `struct iwl_d3_manager_config` (D3_MANAGER_CONFIG_CMD_S_VER_4): Linux's
/// ten-second minimum sleep, no debug wake flags, no host timer.
pub(super) fn d3_config() -> [u8; 12] {
    let mut bytes = [0; 12];
    put32(&mut bytes, 0, 10 * 1000 * 1000);
    bytes
}

/// One GTK reported back by firmware (`iwl_mvm_convert_gtk_v3`).
pub(super) struct ReportedGtk {
    pub id: u8,
    pub len: u8,
    pub flags: u8,
    pub key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for ReportedGtk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReportedGtk")
            .field("id", &self.id)
            .field("len", &self.len)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Converted `struct iwl_wowlan_info_notif_v1` (`iwl_wowlan_status_data`).
#[derive(Debug, Default)]
pub(super) struct WakeStatus {
    pub reasons: u32,
    pub pattern_number: u16,
    /// Last QoS sequence number firmware used per TID.
    pub qos_seq: [u16; 8],
    pub gtk_rekeys: u32,
    pub replay_counter: u64,
    pub received_beacons: u32,
    pub wake_packet_length: u32,
    pub tid_tear_down: u8,
    pub station_id: u8,
    /// PTK RX PN per TID from `gtk[0].sc.ucast_rsc`.
    pub ptk_rx: [u64; 8],
    /// GTK RX PN per TID, keyed by AP key index (`mcast_key_id_map`).
    pub gtk_rx: Vec<(u8, [u64; 8])>,
    pub gtks: Vec<ReportedGtk>,
}

/// `sizeof(struct iwl_wowlan_info_notif_v1)`.
pub(super) const INFO_V1_LEN: usize = 624;
const GTK_STATUS_V3: usize = 244;

/// `iwl_mvm_parse_wowlan_info_notif_v1`: a short notification is invalid.
pub(super) fn parse_info_v1(bytes: &[u8]) -> Result<WakeStatus, &'static str> {
    if bytes.len() < INFO_V1_LEN {
        return Err("MVM WoWLAN info notification truncated");
    }
    let mut status = WakeStatus::default();
    // iwl_mvm_convert_key_counters_v5 uses gtk[0].sc for every counter.
    let sc = &bytes[44..44 + 200]; // key32 len flags res2 mic8
    for (tid, pn) in status.ptk_rx.iter_mut().enumerate() {
        *pn = get64(sc, tid * 8);
    }
    for (id, &entry) in sc[196..200].iter().enumerate() {
        if usize::from(entry) < 2 {
            let mut pns = [0; 8];
            for (tid, pn) in pns.iter_mut().enumerate() {
                *pn = get64(sc, 64 + usize::from(entry) * 64 + tid * 8);
            }
            status.gtk_rx.push((id as u8, pns));
        }
    }
    for index in 0..2 {
        let gtk = &bytes[index * GTK_STATUS_V3..(index + 1) * GTK_STATUS_V3];
        let len = gtk[32];
        if len == 0 {
            continue;
        }
        if usize::from(len) > 32 {
            return Err("MVM WoWLAN reported GTK length invalid");
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&gtk[..32]);
        status.gtks.push(ReportedGtk {
            id: gtk[33] & 3,
            len,
            flags: gtk[33],
            key,
        });
    }
    status.replay_counter = get64(bytes, 568);
    status.pattern_number = get16(bytes, 576);
    for (tid, seq) in status.qos_seq.iter_mut().enumerate() {
        *seq = get16(bytes, 580 + 2 * tid);
    }
    status.reasons = get32(bytes, 596);
    status.gtk_rekeys = get32(bytes, 600);
    status.received_beacons = get32(bytes, 608);
    status.wake_packet_length = get32(bytes, 612);
    status.tid_tear_down = bytes[620];
    status.station_id = bytes[621];
    Ok(status)
}

/// `struct iwl_wowlan_wake_pkt_notif`: the captured frame, bounded by both
/// the reported length and the received payload.
pub(super) fn parse_wake_packet(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    if bytes.len() < 8 {
        return Err("MVM WoWLAN wake packet notification truncated");
    }
    let length = get32(bytes, 0) as usize;
    let body = &bytes[8..];
    Ok(body[..length.min(body.len())].to_vec())
}

/// `struct iwl_d3_end_notif`: `IWL_D0I3_RESET_REQUIRE`.
pub(super) fn parse_d3_end(bytes: &[u8]) -> Result<bool, &'static str> {
    if bytes.len() < 4 {
        return Err("Invalid D3 end notification size");
    }
    Ok(get32(bytes, 0) & D0I3_RESET_REQUIRE != 0)
}

/// `iwl_mvm_setup_connection_keep`: a disconnection wake ends the session.
/// NARF does not offload GTK rekeying, so a reported rekey is also a reason
/// to drop the connection instead of installing unseen material.
pub(super) fn keeps_connection(status: &WakeStatus) -> bool {
    status.reasons & (reason::MISSED_BEACON | reason::DEAUTH | reason::UCODE_ERROR) == 0
        && status.gtk_rekeys == 0
}

/// cfg80211 `struct cfg80211_wowlan_wakeup` subset this driver reports
/// (`iwl_mvm_report_wakeup_reasons`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WakeReport {
    pub non_wireless: bool,
    pub magic_packet: bool,
    pub pattern_index: Option<u16>,
    pub disconnect: bool,
    pub gtk_rekey_failure: bool,
    pub rfkill_release: bool,
    pub eap_identity_request: bool,
    pub four_way_handshake: bool,
    pub unprotected_deauth_disassoc: bool,
    pub packet: Vec<u8>,
}

/// `iwl_mvm_report_wakeup_reasons` mapping.
pub(super) fn report(status: &WakeStatus, packet: Vec<u8>) -> WakeReport {
    let reasons = status.reasons;
    if reasons == 0 {
        return WakeReport {
            non_wireless: true,
            ..WakeReport::default()
        };
    }
    WakeReport {
        non_wireless: false,
        magic_packet: reasons & reason::MAGIC_PACKET != 0,
        pattern_index: (reasons & reason::PATTERN != 0).then_some(status.pattern_number),
        disconnect: reasons & (reason::MISSED_BEACON | reason::DEAUTH) != 0,
        gtk_rekey_failure: reasons & reason::GTK_REKEY_FAILURE != 0,
        rfkill_release: reasons & reason::RFKILL_DEASSERTED != 0,
        eap_identity_request: reasons & reason::EAPOL_REQUEST != 0,
        four_way_handshake: reasons & reason::FOUR_WAY_HANDSHAKE != 0,
        unprotected_deauth_disassoc: reasons & reason::UNPROTECTED_DEAUTH != 0,
        packet: if reasons & reason::HAS_WAKE_PACKET != 0 {
            packet
        } else {
            Vec::new()
        },
    }
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_d3_tests.rs"]
mod tests;
