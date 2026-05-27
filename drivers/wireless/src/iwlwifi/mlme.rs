//! iwlwifi MLME scaffolding — Stage 3.
//!
//! Minimal 802.11 MLME layer for the MVM firmware path:
//! scan request encoding, beacon reception + parsing, and
//! association-request frame builder.
//!
//! ## What's here
//!
//! - `ScanRequest` / `scan_request_cmd` — encode the
//!   `SCAN_REQ_UMAC` host command body that MVM firmware understands.
//! - `BeaconInfo` — parse out the SSID + supported-rates IE from a
//!   raw beacon payload (11 bytes of fixed fields + IEs).
//! - `AssocRequestFrame` / `build_assoc_request` — build the
//!   complete 802.11 association-request frame payload (FC + addrs +
//!   body IEs: Capability, Listen Interval, SSID IE, Supported-Rates
//!   IE).
//!
//! ## What's not here (deferred notes)
//!
//! - Authentication state machine (SAE / FT / 802.1X): needs
//!   crypto module integration (`narf_crypto`).
//! - 4-way handshake key installation: needs station-table write to
//!   firmware.
//! - Data plane: needs QoS map, BA-session negotiation, AMSDU.
//! - Roaming / BSS transition: needs FT resource-request command.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `drivers/net/wireless/intel/iwlwifi/mvm/scan.c` —
//!   `iwl_mvm_scan_umac`, `iwl_scan_req_umac` layout.
//! - `drivers/net/wireless/intel/iwlwifi/mvm/mac80211.c` —
//!   `iwl_mvm_bss_info_changed`, `iwl_mvm_start_scan_on_idle`.
//! - `drivers/net/wireless/intel/iwlwifi/fw/api/scan.h` —
//!   `iwl_scan_req_umac_v{11,16}` layout, scan flags.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Scan request encoder ────────────────────────────────────────────

/// Maximum SSIDs per scan request.
pub const MAX_SCAN_SSIDS: usize = 20;
/// Maximum channels per scan request (2.4 GHz + 5 GHz = up to 36+).
pub const MAX_SCAN_CHANNELS: usize = 51;

/// Scan channel flags (from `iwl_scan_channel_flags_lmac` in
/// `fw/api/scan.h`).
pub mod scan_channel_flags {
    /// Send a probe request on this channel (active scan).
    pub const ACTIVE: u8 = 1 << 0;
    /// Do not send probe requests (passive scan, e.g. DFS channels).
    pub const PASSIVE: u8 = 1 << 1;
}

/// Scan type flags (from `IWL_MVM_LMAC_SCAN_FLAG_*`).
pub mod scan_flags {
    /// Schedule as a passive scan on all channels.
    pub const PASSIVE: u32 = 1 << 2;
    /// Use LMAC mode (AX200/AX201).
    pub const LMAC: u32 = 1 << 10;
    /// Use UMAC mode (AX210/AX211/BE200).
    pub const UMAC: u32 = 1 << 11;
    /// Enable scan completion notification.
    pub const COMPLETION_NOTIF: u32 = 1 << 16;
}

/// One channel entry in the UMAC scan request.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ScanChannel {
    /// 802.11 channel number (1-14 for 2.4 GHz; 36-177 for 5 GHz).
    pub channel_num: u8,
    /// Channel flags (`scan_channel_flags::*`).
    pub flags: u8,
    /// Minimum dwell time in milliseconds.
    pub dwell_time_ms_min: u16,
    /// Maximum dwell time in milliseconds.
    pub dwell_time_ms_max: u16,
}

/// One SSID entry in the probe-request IEs block.
#[derive(Clone, Debug)]
pub struct ScanSsid {
    pub ssid: [u8; 32],
    pub ssid_len: u8,
}

impl ScanSsid {
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut ssid = [0u8; 32];
        let len = b.len().min(32);
        ssid[..len].copy_from_slice(&b[..len]);
        Self { ssid, ssid_len: len as u8 }
    }
}

/// Host-side scan request parameters. Serialised into the MVM
/// `SCAN_REQ_UMAC` command body by `scan_request_cmd`.
#[derive(Clone, Debug)]
pub struct ScanRequest {
    /// Channels to scan.
    pub channels: Vec<ScanChannel>,
    /// SSIDs for directed probe requests (empty = wildcard/any).
    pub ssids: Vec<ScanSsid>,
    /// Passive or active.
    pub passive: bool,
    /// MAC address randomisation (set the local-bit in the probe SA).
    pub rand_mac: bool,
}

impl ScanRequest {
    /// Quick constructor: wildcard passive scan on the standard 2.4
    /// GHz channels (1-14) with max-dwell 110 ms.
    pub fn passive_2ghz() -> Self {
        let channels = (1u8..=13)
            .map(|n| ScanChannel {
                channel_num: n,
                flags: scan_channel_flags::PASSIVE,
                dwell_time_ms_min: 10,
                dwell_time_ms_max: 110,
            })
            .collect();
        Self { channels, ssids: Vec::new(), passive: true, rand_mac: false }
    }

    /// Quick constructor: active directed scan for a specific SSID.
    pub fn active_directed(ssid: &[u8], channels: Vec<ScanChannel>) -> Self {
        Self {
            channels,
            ssids: alloc::vec![ScanSsid::from_bytes(ssid)],
            passive: false,
            rand_mac: false,
        }
    }
}

/// Serialize a `ScanRequest` into the `SCAN_REQ_UMAC` command body.
///
/// The serialised layout is a simplified version of
/// `iwl_scan_req_umac_v11` sufficient for the bring-up arc. The
/// firmware validates the channel table and SSID IEs by byte offset,
/// so the encoding must match the firmware ABI.
///
/// Real-HW: this encoding targets MVM API ≥ 11 (AX200+). Earlier
/// firmware API is not in scope.
pub fn scan_request_cmd(req: &ScanRequest) -> Vec<u8> {
    let mut out = Vec::new();

    // Flags u32: COMPLETION_NOTIF always set; add PASSIVE if requested.
    let mut flags = scan_flags::COMPLETION_NOTIF;
    if req.passive {
        flags |= scan_flags::PASSIVE;
    }
    out.extend_from_slice(&flags.to_le_bytes());

    // Number of channels u8.
    out.push(req.channels.len().min(MAX_SCAN_CHANNELS) as u8);
    // Number of SSIDs u8.
    out.push(req.ssids.len().min(MAX_SCAN_SSIDS) as u8);
    // Random-MAC flag u8 + reserved u8.
    out.push(if req.rand_mac { 1 } else { 0 });
    out.push(0); // reserved

    // Channel table.
    for ch in req.channels.iter().take(MAX_SCAN_CHANNELS) {
        out.push(ch.channel_num);
        out.push(ch.flags);
        out.extend_from_slice(&ch.dwell_time_ms_min.to_le_bytes());
        out.extend_from_slice(&ch.dwell_time_ms_max.to_le_bytes());
    }

    // SSID IEs (TLV: tag=0x00, len, bytes).
    for ssid in req.ssids.iter().take(MAX_SCAN_SSIDS) {
        out.push(0x00); // SSID IE tag
        let len = ssid.ssid_len as usize;
        out.push(len as u8);
        out.extend_from_slice(&ssid.ssid[..len]);
    }

    out
}

// ── Beacon reception ────────────────────────────────────────────────

/// Parsed information from a received 802.11 beacon frame body
/// (the fixed + IE fields after the MAC header).
#[derive(Clone, Debug)]
pub struct BeaconInfo {
    /// BSSID extracted from the MAC header (caller fills this).
    pub bssid: [u8; 6],
    /// Beacon interval (in TU = 1024 µs). From fixed params offset 8.
    pub beacon_interval: u16,
    /// Capability information. From fixed params offset 10.
    pub capability_info: u16,
    /// SSID from the SSID IE (tag=0x00), if present. Up to 32 bytes.
    pub ssid: Vec<u8>,
    /// Supported rates from the Supported Rates IE (tag=0x01).
    pub supported_rates: Vec<u8>,
    /// RSSI in dBm (set by the RX metadata; caller fills from
    /// `iwl_rx_mpdu_desc`; we default to -100 here).
    pub rssi_dbm: i8,
}

impl BeaconInfo {
    fn default_with_bssid(bssid: [u8; 6]) -> Self {
        Self {
            bssid,
            beacon_interval: 0,
            capability_info: 0,
            ssid: Vec::new(),
            supported_rates: Vec::new(),
            rssi_dbm: -100,
        }
    }
}

/// Parse the body of a beacon frame. `body` is the slice starting
/// at the 802.11 fixed parameters (timestamp[8] + interval[2] +
/// capability[2] = 12 fixed bytes, followed by IEs).
///
/// Returns `None` if `body` is shorter than the 12 fixed-parameter
/// bytes.
pub fn parse_beacon(bssid: [u8; 6], body: &[u8]) -> Option<BeaconInfo> {
    if body.len() < 12 {
        return None;
    }
    let beacon_interval = u16::from_le_bytes([body[8], body[9]]);
    let capability_info = u16::from_le_bytes([body[10], body[11]]);

    let mut info = BeaconInfo::default_with_bssid(bssid);
    info.beacon_interval = beacon_interval;
    info.capability_info = capability_info;

    // Walk IEs starting at offset 12.
    let mut pos = 12usize;
    while pos + 2 <= body.len() {
        let tag = body[pos];
        let ie_len = body[pos + 1] as usize;
        pos += 2;
        if pos + ie_len > body.len() {
            break; // truncated IE
        }
        let ie_data = &body[pos..pos + ie_len];
        match tag {
            0x00 => {
                // SSID IE.
                info.ssid.extend_from_slice(ie_data);
            }
            0x01 => {
                // Supported Rates IE.
                info.supported_rates.extend_from_slice(ie_data);
            }
            _ => {} // skip unknown IEs
        }
        pos += ie_len;
    }

    Some(info)
}

// ── Association request encoder ─────────────────────────────────────

/// Parameters for building an association request frame.
#[derive(Clone, Debug)]
pub struct AssocParams {
    /// Station MAC address (addr2 / SA).
    pub sta_addr: [u8; 6],
    /// AP BSSID (addr1/DA + addr3).
    pub ap_bssid: [u8; 6],
    /// SSID to associate to.
    pub ssid: Vec<u8>,
    /// Rates to advertise (1 byte per rate, 802.11 encoding).
    pub supported_rates: Vec<u8>,
    /// 802.11 capability bitmap. Bit 0 = ESS. Typically 0x0431 for
    /// Infrastructure + Short-Preamble + PBCC.
    pub capability_info: u16,
    /// Listen interval in beacon intervals.
    pub listen_interval: u16,
    /// 12-bit sequence number for the frame's MAC header.
    pub seq_num: u16,
}

/// Build the complete 802.11 association request frame (MAC header
/// + body). Returns the raw bytes to feed into `TxPacket::management`.
///
/// Frame layout:
/// ```text
/// [24 bytes MAC header]
/// [2 bytes Capability Info]
/// [2 bytes Listen Interval]
/// [SSID IE: 0x00 | len | ssid...]
/// [Supported-Rates IE: 0x01 | len | rates...]
/// ```
pub fn build_assoc_request(params: &AssocParams) -> Vec<u8> {
    use super::tx::{MacHeader, fc};
    let mac_hdr = MacHeader::management(
        fc::SUBTYPE_ASSOC_REQ,
        params.ap_bssid,
        params.sta_addr,
        params.ap_bssid,
        params.seq_num,
    );

    let mut out = Vec::new();
    out.extend_from_slice(&mac_hdr.to_bytes());

    // Fixed parameters.
    out.extend_from_slice(&params.capability_info.to_le_bytes());
    out.extend_from_slice(&params.listen_interval.to_le_bytes());

    // SSID IE.
    let ssid_len = params.ssid.len().min(32);
    out.push(0x00); // SSID tag
    out.push(ssid_len as u8);
    out.extend_from_slice(&params.ssid[..ssid_len]);

    // Supported Rates IE.
    let rates_len = params.supported_rates.len().min(8);
    out.push(0x01); // Supported Rates tag
    out.push(rates_len as u8);
    out.extend_from_slice(&params.supported_rates[..rates_len]);

    out
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use super::super::tx::fc;

    // ── Smoke: scan request encode ─────────────────────────────────

    /// Encode a passive-2.4GHz scan and verify key byte-fields.
    fn smoke_iwlwifi_mlme_scan_request_encode() -> TestResult {
        let req = ScanRequest::passive_2ghz();
        let cmd = scan_request_cmd(&req);

        if cmd.len() < 8 {
            return TestResult::Fail("encoded scan cmd too short");
        }
        // Bytes 0-3: flags. COMPLETION_NOTIF | PASSIVE.
        let flags = u32::from_le_bytes(cmd[0..4].try_into().unwrap());
        if flags & scan_flags::COMPLETION_NOTIF == 0 {
            return TestResult::Fail("COMPLETION_NOTIF not set");
        }
        if flags & scan_flags::PASSIVE == 0 {
            return TestResult::Fail("PASSIVE not set for passive scan");
        }
        // Byte 4: channel count = 13 (channels 1-13).
        if cmd[4] != 13 {
            return TestResult::Fail("wrong channel count");
        }
        // Byte 5: SSID count = 0 (wildcard).
        if cmd[5] != 0 {
            return TestResult::Fail("ssid count should be 0 for wildcard");
        }
        TestResult::Pass
    }

    // ── Smoke: directed scan includes SSID IE ──────────────────────

    fn smoke_iwlwifi_mlme_scan_request_directed_has_ssid_ie() -> TestResult {
        let ch = ScanChannel {
            channel_num: 6,
            flags: scan_channel_flags::ACTIVE,
            dwell_time_ms_min: 10,
            dwell_time_ms_max: 60,
        };
        let req = ScanRequest::active_directed(b"narf-net", alloc::vec![ch]);
        let cmd = scan_request_cmd(&req);

        // Byte 5: SSID count = 1.
        if cmd[5] != 1 {
            return TestResult::Fail("ssid count should be 1");
        }
        // SSID IE should appear after the channel table.
        // Channel table = 1 channel × 6 bytes = 6 bytes.
        // IE starts at byte 8 + 6 = 14.
        if cmd.len() < 14 {
            return TestResult::Fail("cmd too short to contain SSID IE");
        }
        let ie_start = 8 + 6; // header + 1 channel
        if cmd[ie_start] != 0x00 {
            return TestResult::Fail("SSID IE tag not 0x00");
        }
        if cmd[ie_start + 1] != 8 {
            return TestResult::Fail("SSID IE len wrong");
        }
        if &cmd[ie_start + 2..ie_start + 10] != b"narf-net" {
            return TestResult::Fail("SSID bytes wrong");
        }
        TestResult::Pass
    }

    // ── Smoke: beacon parse ────────────────────────────────────────

    fn smoke_iwlwifi_mlme_beacon_parse() -> TestResult {
        let bssid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        // Minimal beacon body: 8-byte timestamp + 2-byte interval +
        // 2-byte capability + SSID IE (tag=0, len=5, "hello") +
        // Supported Rates IE (tag=1, len=2, 0x82 0x84).
        let body: &[u8] = &[
            // Timestamp (8 bytes)
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Beacon interval = 100 TU = 0x64
            0x64, 0x00,
            // Capability info = 0x0431
            0x31, 0x04,
            // SSID IE
            0x00, 0x05, b'h', b'e', b'l', b'l', b'o',
            // Supported Rates IE
            0x01, 0x02, 0x82, 0x84,
        ];

        let info = match parse_beacon(bssid, body) {
            Some(i) => i,
            None => return TestResult::Fail("parse_beacon returned None"),
        };

        if info.beacon_interval != 100 {
            return TestResult::Fail("beacon_interval wrong");
        }
        if info.capability_info != 0x0431 {
            return TestResult::Fail("capability_info wrong");
        }
        if info.ssid != b"hello" as &[u8] {
            return TestResult::Fail("SSID wrong");
        }
        if info.supported_rates.len() != 2 {
            return TestResult::Fail("supported_rates len wrong");
        }
        TestResult::Pass
    }

    // ── Smoke: assoc request encode ────────────────────────────────

    fn smoke_iwlwifi_mlme_assoc_request_encode() -> TestResult {
        let params = AssocParams {
            sta_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ap_bssid: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ssid: b"narf-net".to_vec(),
            supported_rates: alloc::vec![0x82, 0x84, 0x8B, 0x96],
            capability_info: 0x0411,
            listen_interval: 10,
            seq_num: 1,
        };
        let frame = build_assoc_request(&params);

        // Minimum size: 24 (MAC hdr) + 2 (cap) + 2 (LI) + 2+8 (SSID IE)
        //               + 2+4 (rates IE) = 44 bytes.
        if frame.len() < 44 {
            return TestResult::Fail("assoc request frame too short");
        }

        // MAC header frame_control at bytes 0-1: TYPE_MGMT (0x00) + SUBTYPE_ASSOC_REQ (0x00).
        let fc_val = u16::from_le_bytes([frame[0], frame[1]]);
        if fc_val != (fc::TYPE_MGMT | fc::SUBTYPE_ASSOC_REQ) {
            return TestResult::Fail("frame_control wrong in assoc req");
        }

        // addr1 (bytes 4-9) should be AP BSSID.
        if frame[4..10] != params.ap_bssid {
            return TestResult::Fail("addr1 (DA) wrong");
        }
        // addr2 (bytes 10-15) should be STA addr.
        if frame[10..16] != params.sta_addr {
            return TestResult::Fail("addr2 (SA) wrong");
        }

        // Fixed params start at byte 24.
        let cap = u16::from_le_bytes([frame[24], frame[25]]);
        if cap != 0x0411 {
            return TestResult::Fail("capability_info wrong in body");
        }
        let li = u16::from_le_bytes([frame[26], frame[27]]);
        if li != 10 {
            return TestResult::Fail("listen_interval wrong");
        }

        // SSID IE at byte 28.
        if frame[28] != 0x00 {
            return TestResult::Fail("SSID IE tag wrong");
        }
        if frame[29] != 8 {
            return TestResult::Fail("SSID IE len wrong");
        }
        if &frame[30..38] != b"narf-net" {
            return TestResult::Fail("SSID bytes wrong in assoc req");
        }

        // Supported Rates IE at byte 38.
        if frame[38] != 0x01 {
            return TestResult::Fail("Supported Rates IE tag wrong");
        }
        if frame[39] != 4 {
            return TestResult::Fail("Supported Rates IE len wrong");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_scan_request_encode
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_scan_request_directed_has_ssid_ie
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_beacon_parse
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_assoc_request_encode
    );
}
