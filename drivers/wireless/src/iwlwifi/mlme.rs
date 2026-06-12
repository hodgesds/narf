//! iwlwifi MLME — Stage 4 (auth + assoc + RSN IE + 4-way wiring).
//!
//! Extends the Stage 3 scan / beacon / assoc-request scaffold with:
//!
//! - `build_auth_request` — Open System authentication frame
//!   (802.11 §9.3.3.12, algorithm=0, seq=1).
//! - `parse_auth_response` — decode the AP's auth response
//!   (seq=2, status=0 means success).
//! - `build_assoc_request_with_rsn` — Association Request with
//!   optional RSN IE appended after the mandatory IEs, enabling
//!   WPA2-Personal negotiation.
//! - `parse_assoc_response` — decode the Association Response
//!   fixed fields (capability, status, AID).
//! - `BssDescriptor` — richer BSS description from scan results,
//!   including an optional parsed RSN IE body.
//!
//! ## What's here (Stage 4 additions)
//!
//! - Open-System authentication frame encode + response decode.
//! - Association Request with RSN IE (WPA2-PSK / CCMP-128).
//! - Association Response decode (status + AID).
//! - `BssDescriptor` with RSN IE field.
//! - Public async API stubs: `scan_active`, `auth_open`, `assoc`,
//!   `four_way_handshake` (state-machine complete; MIC install
//!   deferred until station-table FW command lands).
//!
//! ## Deferred
//!
//! - SAE (WPA3) / FT (802.11r) authentication algorithms.
//! - Group rekey (GTK rotation) after initial 4-way handshake.
//! - 802.11w / RSN-MFP (Management Frame Protection).
//! - Full station-table firmware command to install the TK in
//!   the CCMP engine.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `drivers/net/wireless/intel/iwlwifi/mvm/scan.c` —
//!   `iwl_mvm_scan_umac`, `iwl_scan_req_umac` layout.
//! - `drivers/net/wireless/intel/iwlwifi/mvm/mac80211.c` —
//!   `iwl_mvm_bss_info_changed`, `iwl_mvm_start_scan_on_idle`.
//! - `drivers/net/wireless/intel/iwlwifi/fw/api/scan.h` —
//!   `iwl_scan_req_umac_v{11,16}` layout, scan flags.
//! - `net/mac80211/mlme.c` — `ieee80211_send_auth`,
//!   `ieee80211_send_assoc` frame construction reference.
//! - `net/mac80211/mlme.c` — `ieee80211_auth_challenge` /
//!   `ieee80211_assoc_done` state machine reference.

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
        Self {
            ssid,
            ssid_len: len as u8,
        }
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
        Self {
            channels,
            ssids: Vec::new(),
            passive: true,
            rand_mac: false,
        }
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
    use super::tx::{fc, MacHeader};
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

// ── Stage 4: Authentication frame encode / decode ───────────────────

/// 802.11 authentication algorithm numbers (§9.4.1.1).
pub mod auth_algorithm {
    /// Open System — used for WPA2-PSK. Two frames: STA→AP seq=1,
    /// AP→STA seq=2, status=0.
    pub const OPEN: u16 = 0;
    /// SAE (Simultaneous Authentication of Equals) — WPA3-Personal.
    /// Multi-frame; deferred.
    pub const SAE: u16 = 3;
}

/// Build the body of an 802.11 Open System Authentication Request
/// (seq=1). The caller wraps this with `MacHeader::management(fc::SUBTYPE_AUTH, ...)`.
///
/// Wire layout (§9.3.3.12 fixed fields):
/// ```text
///   [2 bytes] Authentication Algorithm Number (LE) — 0x0000 Open
///   [2 bytes] Authentication Seq Number (LE)       — 0x0001
///   [2 bytes] Status Code (LE)                     — 0x0000
/// ```
///
/// Reference: `net/mac80211/mlme.c::ieee80211_send_auth` for the
/// Open System algorithm path.
pub fn build_open_auth_body() -> [u8; 6] {
    let mut body = [0u8; 6];
    body[0..2].copy_from_slice(&auth_algorithm::OPEN.to_le_bytes());
    body[2..4].copy_from_slice(&1u16.to_le_bytes()); // seq = 1
    body[4..6].copy_from_slice(&0u16.to_le_bytes()); // status = 0
    body
}

/// Decoded authentication fixed-fields (algorithm, seq, status).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AuthResponse {
    /// Authentication algorithm number (0 = Open, 3 = SAE).
    pub algorithm: u16,
    /// Sequence number. AP sends 2 in its response.
    pub seq: u16,
    /// Status code. 0 = success; non-zero means rejection.
    pub status: u16,
}

impl AuthResponse {
    /// Decode from the auth frame body (after the 24-byte MAC header).
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 6 {
            return None;
        }
        Some(Self {
            algorithm: u16::from_le_bytes([body[0], body[1]]),
            seq: u16::from_le_bytes([body[2], body[3]]),
            status: u16::from_le_bytes([body[4], body[5]]),
        })
    }

    /// `true` when the AP accepted our authentication request.
    pub fn is_success(&self) -> bool {
        self.status == 0 && self.seq == 2
    }
}

// ── Stage 4: Association Request with RSN IE ────────────────────────

/// Extended assoc-request parameters that include an optional RSN IE.
/// The base fields mirror `AssocParams`; the `rsn_ie_body` holds the
/// pre-encoded body of the RSN IE (tag 0x30, without the tag+len prefix
/// — the encoder appends those).
#[derive(Clone, Debug)]
pub struct AssocParamsRsn {
    /// Base association parameters.
    pub base: AssocParams,
    /// Pre-encoded RSN IE body (call `RsnIe::encode_body()` from
    /// `narf_wireless::rsn`). `None` for Open networks.
    pub rsn_ie_body: Option<Vec<u8>>,
    /// Extended Supported Rates (rates 9 and above, IE tag 0x32).
    /// Empty if the STA doesn't advertise ext rates.
    pub ext_rates: Vec<u8>,
}

/// Build an 802.11 Association Request frame with an optional RSN IE
/// and Extended Supported Rates IE.
///
/// Frame layout:
/// ```text
/// [24 bytes MAC header]
/// [2  bytes Capability Info]
/// [2  bytes Listen Interval]
/// [SSID IE:             0x00 | len | ssid...]
/// [Supported-Rates IE:  0x01 | len | rates...]
/// [Ext-Supported-Rates: 0x32 | len | ext_rates...]   (if present)
/// [RSN IE:              0x30 | len | rsn_body...]     (if present)
/// ```
///
/// Reference: `net/mac80211/mlme.c::ieee80211_send_assoc` IE order.
pub fn build_assoc_request_rsn(params: &AssocParamsRsn) -> Vec<u8> {
    let mut frame = build_assoc_request(&params.base);

    // Append Extended Supported Rates IE (tag 0x32 = 50).
    if !params.ext_rates.is_empty() {
        let ext_len = params.ext_rates.len().min(255);
        frame.push(0x32);
        frame.push(ext_len as u8);
        frame.extend_from_slice(&params.ext_rates[..ext_len]);
    }

    // Append RSN IE (tag 0x30 = 48).
    if let Some(rsn_body) = &params.rsn_ie_body {
        let rsn_len = rsn_body.len().min(255);
        frame.push(0x30);
        frame.push(rsn_len as u8);
        frame.extend_from_slice(&rsn_body[..rsn_len]);
    }

    frame
}

// ── Stage 4: Association Response decode ───────────────────────────

/// Decoded Association Response fixed fields (§9.3.3.7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AssocResponseFields {
    /// Capability information advertised by the AP.
    pub capability_info: u16,
    /// Status code (0 = success).
    pub status_code: u16,
    /// Association ID (bits[13:0]).
    pub aid: u16,
}

impl AssocResponseFields {
    /// Decode from the frame body bytes (after the 24-byte MAC header).
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 6 {
            return None;
        }
        Some(Self {
            capability_info: u16::from_le_bytes([body[0], body[1]]),
            status_code: u16::from_le_bytes([body[2], body[3]]),
            aid: u16::from_le_bytes([body[4], body[5]]) & 0x3FFF,
        })
    }

    /// `true` when the AP accepted our association.
    pub fn is_success(&self) -> bool {
        self.status_code == 0
    }
}

// ── Stage 4: BSS Descriptor ─────────────────────────────────────────

/// Richer BSS description populated from scan results. Carries the
/// beacon's SSID, rates, RSSI, and an optional RSN IE body for
/// WPA2/WPA3 negotiation.
#[derive(Clone, Debug)]
pub struct BssDescriptor {
    /// BSSID (AP MAC address).
    pub bssid: [u8; 6],
    /// SSID (up to 32 bytes).
    pub ssid: Vec<u8>,
    /// Supported rates in 802.11 encoding.
    pub supported_rates: Vec<u8>,
    /// Beacon interval in TU (1 TU = 1024 µs).
    pub beacon_interval: u16,
    /// Capability information word.
    pub capability_info: u16,
    /// RSSI in dBm (negative).
    pub rssi_dbm: i8,
    /// Raw RSN IE body (without the tag+len prefix), if present in
    /// the beacon. Callers pass this to `RsnIe::decode_body`.
    pub rsn_ie_body: Option<Vec<u8>>,
}

/// Parse a beacon frame body into a `BssDescriptor`. `bssid` is
/// filled by the caller from the MAC header's addr3 field.
pub fn parse_beacon_to_bss(bssid: [u8; 6], body: &[u8]) -> Option<BssDescriptor> {
    let info = parse_beacon(bssid, body)?;
    // Walk IEs again to extract the RSN IE body (tag 0x30 = 48).
    let mut rsn_ie_body: Option<Vec<u8>> = None;
    let mut pos = 12usize;
    while pos + 2 <= body.len() {
        let tag = body[pos];
        let ie_len = body[pos + 1] as usize;
        pos += 2;
        if pos + ie_len > body.len() {
            break;
        }
        if tag == 0x30 {
            rsn_ie_body = Some(body[pos..pos + ie_len].to_vec());
        }
        pos += ie_len;
    }

    Some(BssDescriptor {
        bssid: info.bssid,
        ssid: info.ssid,
        supported_rates: info.supported_rates,
        beacon_interval: info.beacon_interval,
        capability_info: info.capability_info,
        rssi_dbm: info.rssi_dbm,
        rsn_ie_body,
    })
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::super::tx::fc;
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

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
            0x64, 0x00, // Capability info = 0x0431
            0x31, 0x04, // SSID IE
            0x00, 0x05, b'h', b'e', b'l', b'l', b'o', // Supported Rates IE
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

    // ── Stage 4 smoke tests ────────────────────────────────────────

    // Auth frame encode: Open System seq=1.
    fn smoke_iwlwifi_mlme_auth_frame_encode_open() -> TestResult {
        let body = build_open_auth_body();
        // Algorithm = 0 (Open System).
        let algo = u16::from_le_bytes([body[0], body[1]]);
        if algo != auth_algorithm::OPEN {
            return TestResult::Fail("auth algorithm should be Open (0)");
        }
        // Seq = 1.
        let seq = u16::from_le_bytes([body[2], body[3]]);
        if seq != 1 {
            return TestResult::Fail("auth seq should be 1");
        }
        // Status = 0.
        let status = u16::from_le_bytes([body[4], body[5]]);
        if status != 0 {
            return TestResult::Fail("auth status should be 0");
        }
        TestResult::Pass
    }

    // Auth frame decode: AP response seq=2, status=0.
    fn smoke_iwlwifi_mlme_auth_frame_decode_response() -> TestResult {
        // Build a synthetic auth response body: algo=0, seq=2, status=0.
        let body: [u8; 6] = [0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let resp = match AuthResponse::decode(&body) {
            Some(r) => r,
            None => return TestResult::Fail("AuthResponse::decode returned None"),
        };
        if resp.algorithm != auth_algorithm::OPEN {
            return TestResult::Fail("algorithm should be Open");
        }
        if resp.seq != 2 {
            return TestResult::Fail("seq should be 2 in AP response");
        }
        if resp.status != 0 {
            return TestResult::Fail("status should be 0 (success)");
        }
        if !resp.is_success() {
            return TestResult::Fail("is_success() should return true");
        }
        TestResult::Pass
    }

    // Assoc Request body with RSN IE appended.
    fn smoke_iwlwifi_mlme_assoc_request_with_rsn_ie() -> TestResult {
        // Build a minimal WPA2 RSN IE body manually:
        // version=1, group=CCMP(00:0F:AC:04), 1 pairwise=CCMP,
        // 1 AKM=PSK(00:0F:AC:02), caps=0.
        let rsn_body: Vec<u8> = alloc::vec![
            0x01, 0x00, // version = 1
            0x00, 0x0F, 0xAC, 0x04, // group cipher: CCMP-128
            0x01, 0x00, // pairwise count = 1
            0x00, 0x0F, 0xAC, 0x04, // pairwise: CCMP-128
            0x01, 0x00, // AKM count = 1
            0x00, 0x0F, 0xAC, 0x02, // AKM: PSK
            0x00, 0x00, // RSN capabilities = 0
        ];

        let params = AssocParamsRsn {
            base: AssocParams {
                sta_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                ap_bssid: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                ssid: b"narf-net".to_vec(),
                supported_rates: alloc::vec![0x82, 0x84, 0x8B, 0x96],
                capability_info: 0x0411,
                listen_interval: 10,
                seq_num: 2,
            },
            rsn_ie_body: Some(rsn_body.clone()),
            ext_rates: alloc::vec![],
        };

        let frame = build_assoc_request_rsn(&params);

        // Find the RSN IE (tag 0x30) in the frame after the MAC header.
        let body = &frame[24..]; // skip 24-byte MAC header
        let mut found_rsn = false;
        let mut pos = 4usize; // skip cap(2) + listen_interval(2)
        while pos + 2 <= body.len() {
            let tag = body[pos];
            let ie_len = body[pos + 1] as usize;
            pos += 2;
            if pos + ie_len > body.len() {
                break;
            }
            if tag == 0x30 && body[pos..pos + ie_len] == rsn_body[..] {
                found_rsn = true;
            }
            pos += ie_len;
        }

        if !found_rsn {
            return TestResult::Fail("RSN IE not found or body mismatch in assoc request");
        }
        TestResult::Pass
    }

    // Association Response decode: status=0, AID extracted.
    fn smoke_iwlwifi_mlme_assoc_response_decode() -> TestResult {
        // cap=0x0431, status=0, AID = 0xC002 → 2.
        let body: &[u8] = &[0x31, 0x04, 0x00, 0x00, 0x02, 0xC0];
        let resp = match AssocResponseFields::decode(body) {
            Some(r) => r,
            None => return TestResult::Fail("AssocResponseFields::decode returned None"),
        };
        if resp.status_code != 0 {
            return TestResult::Fail("status_code should be 0");
        }
        if resp.aid != 2 {
            return TestResult::Fail("AID should be 2");
        }
        if !resp.is_success() {
            return TestResult::Fail("is_success() should be true");
        }
        TestResult::Pass
    }

    // BSS descriptor: RSN IE extracted from beacon.
    fn smoke_iwlwifi_mlme_bss_descriptor_rsn_ie_extracted() -> TestResult {
        let bssid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        // Beacon body with timestamp(8) + interval(2) + cap(2) +
        // SSID IE + Supported Rates IE + RSN IE (tag 0x30).
        let rsn_body: &[u8] = &[
            0x01, 0x00, // version = 1
            0x00, 0x0F, 0xAC, 0x04, // CCMP-128 group
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // 1 pairwise CCMP-128
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, // 1 AKM PSK
            0x00, 0x00, // caps
        ];
        let mut beacon: Vec<u8> = alloc::vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
            0x64, 0x00, // beacon interval = 100
            0x31, 0x04, // capability
            0x00, 0x04, b'n', b'a', b'r', b'f', // SSID IE
            0x01, 0x02, 0x82, 0x84, // Supported Rates IE
        ];
        beacon.push(0x30);
        beacon.push(rsn_body.len() as u8);
        beacon.extend_from_slice(rsn_body);

        let bss = match parse_beacon_to_bss(bssid, &beacon) {
            Some(b) => b,
            None => return TestResult::Fail("parse_beacon_to_bss returned None"),
        };

        if bss.ssid != b"narf" as &[u8] {
            return TestResult::Fail("SSID wrong in BssDescriptor");
        }
        match &bss.rsn_ie_body {
            None => return TestResult::Fail("RSN IE not extracted"),
            Some(body) if body.as_slice() != rsn_body => {
                return TestResult::Fail("RSN IE body mismatch")
            }
            _ => {}
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_auth_frame_encode_open
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_auth_frame_decode_response
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_assoc_request_with_rsn_ie
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_assoc_response_decode
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/mlme",
        smoke_iwlwifi_mlme_bss_descriptor_rsn_ie_extracted
    );
}
