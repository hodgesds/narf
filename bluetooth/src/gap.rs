//! Generic Access Profile — advertising-data records (clean-room).
//!
//! References (public-only):
//! - "Bluetooth Core Specification Supplement, Part A — Data Types
//!   Specification, Version 11" — Bluetooth SIG. Public adopted
//!   document. §1.3 (advertising data record format: 1-byte length
//!   covering type+payload, then 1-byte AD type, then payload).
//! - **Bluetooth Assigned Numbers — Generic Access Profile** —
//!   Bluetooth SIG. Public registry of AD type codes (Flags = 0x01,
//!   Incomplete / Complete 16-bit Service UUIDs = 0x02 / 0x03,
//!   16-bit Service Solicitation UUIDs = 0x14, Local Name (Shortened
//!   = 0x08, Complete = 0x09), Tx Power Level = 0x0A, Slave Connection
//!   Interval Range = 0x12, Service Data 16-bit UUID = 0x16, Public
//!   Target Address = 0x17, Appearance = 0x19, Manufacturer Specific
//!   Data = 0xFF).
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! No GPL Linux source consulted.
//!
//! ## Wire format (CSS Part A §1.3)
//!
//! ```text
//!   byte 0  length    (number of bytes that follow, ≥ 1, ≤ 30 in
//!                       a 31-byte legacy advertising packet)
//!   byte 1  AD type
//!   bytes 2..N+1  payload (length-1 bytes)
//! ```

use alloc::string::String;
use alloc::vec::Vec;

// ── AD type constants (Assigned Numbers) ───────────────────────────

pub const AD_FLAGS: u8 = 0x01;
pub const AD_INCOMPLETE_LIST_16: u8 = 0x02;
pub const AD_COMPLETE_LIST_16: u8 = 0x03;
pub const AD_INCOMPLETE_LIST_32: u8 = 0x04;
pub const AD_COMPLETE_LIST_32: u8 = 0x05;
pub const AD_INCOMPLETE_LIST_128: u8 = 0x06;
pub const AD_COMPLETE_LIST_128: u8 = 0x07;
pub const AD_SHORTENED_LOCAL_NAME: u8 = 0x08;
pub const AD_COMPLETE_LOCAL_NAME: u8 = 0x09;
pub const AD_TX_POWER_LEVEL: u8 = 0x0A;
pub const AD_CLASS_OF_DEVICE: u8 = 0x0D;
pub const AD_SLAVE_CONN_INTERVAL_RANGE: u8 = 0x12;
pub const AD_LIST_16_SOLICITATION: u8 = 0x14;
pub const AD_LIST_128_SOLICITATION: u8 = 0x15;
pub const AD_SERVICE_DATA_16: u8 = 0x16;
pub const AD_PUBLIC_TARGET_ADDRESS: u8 = 0x17;
pub const AD_RANDOM_TARGET_ADDRESS: u8 = 0x18;
pub const AD_APPEARANCE: u8 = 0x19;
pub const AD_ADVERTISING_INTERVAL: u8 = 0x1A;
pub const AD_LE_BLUETOOTH_DEVICE_ADDRESS: u8 = 0x1B;
pub const AD_LE_ROLE: u8 = 0x1C;
pub const AD_SERVICE_DATA_32: u8 = 0x20;
pub const AD_SERVICE_DATA_128: u8 = 0x21;
pub const AD_URI: u8 = 0x24;
pub const AD_LE_SUPPORTED_FEATURES: u8 = 0x27;
pub const AD_MANUFACTURER_SPECIFIC: u8 = 0xFF;

// ── Flags-byte bits (CSS Part A §1.3, table 1.1) ───────────────────

pub const FLAGS_LE_LIMITED_DISCOVERABLE: u8 = 1 << 0;
pub const FLAGS_LE_GENERAL_DISCOVERABLE: u8 = 1 << 1;
pub const FLAGS_BR_EDR_NOT_SUPPORTED: u8 = 1 << 2;
pub const FLAGS_LE_BR_EDR_CONTROLLER: u8 = 1 << 3;
pub const FLAGS_LE_BR_EDR_HOST: u8 = 1 << 4;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GapError {
    /// Buffer too short for the next record.
    Short,
    /// Record's `length` byte claims more bytes than the buffer carries.
    Truncated,
    /// Payload doesn't have enough bytes for its declared AD type
    /// (e.g. Tx Power Level needs 1 byte; 16-bit UUID list needs
    /// payload divisible by 2).
    BadPayload,
}

// ── TLV iterator ───────────────────────────────────────────────────

/// One advertising data record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdRecord<'a> {
    pub ad_type: u8,
    pub payload: &'a [u8],
}

/// Iterate AD records from the start of an advertising data packet
/// (or scan-response). Stops on `length == 0`, which the spec uses as
/// a terminator inside the 31-byte legacy advertisement payload.
#[derive(Debug)]
pub struct AdIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> AdIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for AdIter<'a> {
    type Item = Result<AdRecord<'a>, GapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let length = self.buf[self.pos] as usize;
        if length == 0 {
            // Terminator inside a legacy advertisement.
            return None;
        }
        if self.pos + 1 + length > self.buf.len() {
            self.pos = self.buf.len();
            return Some(Err(GapError::Truncated));
        }
        if length < 1 {
            return Some(Err(GapError::BadPayload));
        }
        let ad_type = self.buf[self.pos + 1];
        let payload = &self.buf[self.pos + 2..self.pos + 1 + length];
        self.pos += 1 + length;
        Some(Ok(AdRecord { ad_type, payload }))
    }
}

// ── Builder ────────────────────────────────────────────────────────

/// Append one AD record (length + type + payload) to `out`.
pub fn append_record(out: &mut Vec<u8>, ad_type: u8, payload: &[u8]) {
    out.push((1 + payload.len()) as u8);
    out.push(ad_type);
    out.extend_from_slice(payload);
}

/// Build a Flags record. `flags` is a bitmap of the `FLAGS_*` consts.
pub fn append_flags(out: &mut Vec<u8>, flags: u8) {
    append_record(out, AD_FLAGS, &[flags]);
}

/// Build a Complete Local Name record.
pub fn append_complete_local_name(out: &mut Vec<u8>, name: &str) {
    append_record(out, AD_COMPLETE_LOCAL_NAME, name.as_bytes());
}

/// Build a Tx Power Level record. `dbm` is signed (typically −127..+20).
pub fn append_tx_power(out: &mut Vec<u8>, dbm: i8) {
    append_record(out, AD_TX_POWER_LEVEL, &[dbm as u8]);
}

/// Build a Manufacturer Specific Data record. The 16-bit Company ID
/// goes first in little-endian, followed by vendor data.
pub fn append_manufacturer_data(out: &mut Vec<u8>, company_id: u16, data: &[u8]) {
    let mut payload = Vec::with_capacity(2 + data.len());
    payload.extend_from_slice(&company_id.to_le_bytes());
    payload.extend_from_slice(data);
    append_record(out, AD_MANUFACTURER_SPECIFIC, &payload);
}

/// Build an Incomplete or Complete 16-bit Service UUID list. UUIDs
/// are little-endian 16-bit values; `complete` selects the 0x02
/// / 0x03 variant.
pub fn append_service_uuid_list_16(out: &mut Vec<u8>, complete: bool, uuids: &[u16]) {
    let mut payload = Vec::with_capacity(uuids.len() * 2);
    for u in uuids {
        payload.extend_from_slice(&u.to_le_bytes());
    }
    let ad_type = if complete {
        AD_COMPLETE_LIST_16
    } else {
        AD_INCOMPLETE_LIST_16
    };
    append_record(out, ad_type, &payload);
}

/// Build a Service Data — 16-bit UUID record. `uuid` is the 2-byte
/// service UUID (LE on the wire), `data` is the service-defined
/// payload.
pub fn append_service_data_16(out: &mut Vec<u8>, uuid: u16, data: &[u8]) {
    let mut payload = Vec::with_capacity(2 + data.len());
    payload.extend_from_slice(&uuid.to_le_bytes());
    payload.extend_from_slice(data);
    append_record(out, AD_SERVICE_DATA_16, &payload);
}

// ── Convenience decoders ───────────────────────────────────────────

/// Find the first record of `ad_type` and return its payload.
pub fn find<'a>(buf: &'a [u8], ad_type: u8) -> Option<&'a [u8]> {
    for rec in AdIter::new(buf).flatten() {
        if rec.ad_type == ad_type {
            return Some(rec.payload);
        }
    }
    None
}

/// Decode a Local Name — looks up Complete first then Shortened.
pub fn local_name(buf: &[u8]) -> Option<String> {
    let payload = find(buf, AD_COMPLETE_LOCAL_NAME).or_else(|| find(buf, AD_SHORTENED_LOCAL_NAME))?;
    Some(String::from_utf8_lossy(payload).into_owned())
}

/// Decode the Flags byte, if present.
pub fn flags(buf: &[u8]) -> Option<u8> {
    find(buf, AD_FLAGS).and_then(|p| p.first().copied())
}

/// Decode the Tx Power Level (signed dBm) if present.
pub fn tx_power(buf: &[u8]) -> Option<i8> {
    find(buf, AD_TX_POWER_LEVEL).and_then(|p| p.first().copied().map(|b| b as i8))
}

/// Decode a 16-bit Manufacturer Specific Data record. Returns
/// (company id, vendor payload).
pub fn manufacturer_data<'a>(buf: &'a [u8]) -> Option<(u16, &'a [u8])> {
    let p = find(buf, AD_MANUFACTURER_SPECIFIC)?;
    if p.len() < 2 {
        return None;
    }
    Some((u16::from_le_bytes([p[0], p[1]]), &p[2..]))
}

/// Decode all 16-bit Service UUIDs in the buffer (covers both
/// Complete and Incomplete forms).
pub fn service_uuids_16(buf: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    for rec in AdIter::new(buf).flatten() {
        if rec.ad_type == AD_COMPLETE_LIST_16 || rec.ad_type == AD_INCOMPLETE_LIST_16 {
            for chunk in rec.payload.chunks_exact(2) {
                out.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
        }
    }
    out
}

// ── Central role — scan + connect HCI command builders ────────────
//
// Vol 4 Part E §7.8.10/11/12 define the LE Central scan + connect
// commands. The builders below produce the parameter-only bytes that
// go after the 2-byte opcode + 1-byte length in an HCI Command.

/// `Scan_Type` per §7.8.10 — 0x00 = Passive (RX only), 0x01 = Active
/// (RX + SCAN_REQ + RX SCAN_RSP).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScanType {
    Passive = 0x00,
    Active = 0x01,
}

/// `Own_Address_Type` per §7.8.10/12 — 0x00 = Public, 0x01 = Random,
/// 0x02 = Resolvable Private (fallback Public), 0x03 = Resolvable
/// Private (fallback Random).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OwnAddressType {
    Public = 0x00,
    Random = 0x01,
    ResolvablePublic = 0x02,
    ResolvableRandom = 0x03,
}

/// `Peer_Address_Type` per §7.8.12.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeerAddressType {
    Public = 0x00,
    Random = 0x01,
}

/// `Scanning_Filter_Policy` per §7.8.10. 0x00 = accept all,
/// 0x01 = accept only those in the filter accept list, plus the
/// extended variants 0x02 / 0x03 (RPA-aware).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScanFilterPolicy {
    AcceptAll = 0x00,
    AcceptListOnly = 0x01,
    AcceptAllRpa = 0x02,
    AcceptListOnlyRpa = 0x03,
}

/// `Initiator_Filter_Policy` per §7.8.12.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InitiatorFilterPolicy {
    /// Connect to the peer address in `peer_address`.
    PeerAddress = 0x00,
    /// Connect to any device in the filter accept list.
    AcceptList = 0x01,
}

/// LE Set Scan Parameters payload (§7.8.10).
///
/// `scan_interval` and `scan_window` are in units of 0.625 ms, range
/// 0x0004..=0x4000 (2.5 ms..=10240 ms).
#[derive(Copy, Clone, Debug)]
pub struct ScanParameters {
    pub scan_type: ScanType,
    pub scan_interval: u16,
    pub scan_window: u16,
    pub own_address_type: OwnAddressType,
    pub scanning_filter_policy: ScanFilterPolicy,
}

impl Default for ScanParameters {
    fn default() -> Self {
        // Sensible defaults for Central discovery: passive, 30 ms / 30 ms,
        // public address, accept-all. Matches the Linux default for
        // `hcitool lescan` minus the duplicate filter (that knob lives
        // in Set_Scan_Enable, not Set_Scan_Parameters).
        Self {
            scan_type: ScanType::Passive,
            // 0x0030 * 0.625 ms = 30 ms
            scan_interval: 0x0030,
            scan_window: 0x0030,
            own_address_type: OwnAddressType::Public,
            scanning_filter_policy: ScanFilterPolicy::AcceptAll,
        }
    }
}

impl ScanParameters {
    /// Build the 7-byte parameter block for HCI_LE_Set_Scan_Parameters.
    pub fn encode(&self) -> [u8; 7] {
        let si = self.scan_interval.to_le_bytes();
        let sw = self.scan_window.to_le_bytes();
        [
            self.scan_type as u8,
            si[0],
            si[1],
            sw[0],
            sw[1],
            self.own_address_type as u8,
            self.scanning_filter_policy as u8,
        ]
    }
}

/// LE Set Scan Enable payload (§7.8.11).
#[derive(Copy, Clone, Debug)]
pub struct ScanEnable {
    pub enable: bool,
    pub filter_duplicates: bool,
}

impl ScanEnable {
    pub fn encode(&self) -> [u8; 2] {
        [self.enable as u8, self.filter_duplicates as u8]
    }
}

/// LE Create Connection payload (§7.8.12). 25 bytes on the wire.
///
/// `min_interval` / `max_interval` are units of 1.25 ms (range
/// 0x0006..=0x0C80 ⇒ 7.5 ms..=4000 ms). `supervision_timeout` is
/// units of 10 ms.
#[derive(Copy, Clone, Debug)]
pub struct CreateConnection {
    pub scan_interval: u16,
    pub scan_window: u16,
    pub initiator_filter_policy: InitiatorFilterPolicy,
    pub peer_address_type: PeerAddressType,
    pub peer_address: [u8; 6],
    pub own_address_type: OwnAddressType,
    pub conn_interval_min: u16,
    pub conn_interval_max: u16,
    pub max_latency: u16,
    pub supervision_timeout: u16,
    pub min_ce_length: u16,
    pub max_ce_length: u16,
}

impl CreateConnection {
    /// Defaults for a typical Central connection to a known peer:
    /// 30 ms scan, public-address peer, 30..50 ms connection
    /// interval, 4 s supervision timeout.
    pub fn to_peer(peer_address_type: PeerAddressType, peer_address: [u8; 6]) -> Self {
        Self {
            scan_interval: 0x0030,
            scan_window: 0x0030,
            initiator_filter_policy: InitiatorFilterPolicy::PeerAddress,
            peer_address_type,
            peer_address,
            own_address_type: OwnAddressType::Public,
            // 0x0018 * 1.25ms = 30ms; 0x0028 * 1.25ms = 50ms.
            conn_interval_min: 0x0018,
            conn_interval_max: 0x0028,
            max_latency: 0x0000,
            // 0x0190 * 10ms = 4000ms.
            supervision_timeout: 0x0190,
            min_ce_length: 0,
            max_ce_length: 0,
        }
    }

    pub fn encode(&self) -> [u8; 25] {
        let mut out = [0u8; 25];
        out[0..2].copy_from_slice(&self.scan_interval.to_le_bytes());
        out[2..4].copy_from_slice(&self.scan_window.to_le_bytes());
        out[4] = self.initiator_filter_policy as u8;
        out[5] = self.peer_address_type as u8;
        out[6..12].copy_from_slice(&self.peer_address);
        out[12] = self.own_address_type as u8;
        out[13..15].copy_from_slice(&self.conn_interval_min.to_le_bytes());
        out[15..17].copy_from_slice(&self.conn_interval_max.to_le_bytes());
        out[17..19].copy_from_slice(&self.max_latency.to_le_bytes());
        out[19..21].copy_from_slice(&self.supervision_timeout.to_le_bytes());
        out[21..23].copy_from_slice(&self.min_ce_length.to_le_bytes());
        out[23..25].copy_from_slice(&self.max_ce_length.to_le_bytes());
        out
    }
}

/// HCI_Disconnect (§7.1.6) parameter block. 3 bytes:
/// `connection_handle` (2 LE) + `reason` (1).
///
/// The `reason` byte is one of the HCI error codes (§1.3). The host
/// only ever picks "Remote User Terminated Connection" (0x13) for a
/// clean teardown.
pub fn build_disconnect(connection_handle: u16, reason: u8) -> [u8; 3] {
    let h = (connection_handle & 0x0FFF).to_le_bytes();
    [h[0], h[1], reason]
}

/// Standard "Remote User Terminated Connection" reason code from
/// Vol 1 Part F §1.3 (HCI Error Code 0x13). The only value the host
/// is permitted to use for a host-initiated disconnect.
pub const DISCONNECT_REASON_REMOTE_USER: u8 = 0x13;

// ── Central state machine ─────────────────────────────────────────
//
// A Central tracks its scan state + known peers. Real bring-up wires
// this into a controller; the state machine itself is transport-free
// so it's straightforward to unit-test.

/// Phases the Central walks during discovery + connection setup.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CentralPhase {
    /// Initial state, no scan in progress.
    Idle,
    /// Set_Scan_Parameters issued, awaiting Command Complete.
    ParametersSent,
    /// Set_Scan_Enable(enable=1) issued, controller is scanning.
    Scanning,
    /// Set_Scan_Enable(enable=0) issued before LE_Create_Connection.
    ScanStopping,
    /// LE_Create_Connection issued, awaiting LE Connection Complete.
    Connecting,
    /// Connection complete; controller holds the link.
    Connected,
}

/// A discovered peer from the Central's scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub address_type: u8,
    pub address: [u8; 6],
    pub last_rssi: i8,
    pub event_type: u8,
    pub ad_data: Vec<u8>,
}

/// Lightweight Central state machine. Pass advertising reports in,
/// pull HCI command opcode + parameter pairs out for the controller
/// driver to send.
#[derive(Debug, Default)]
pub struct Central {
    pub phase: CentralPhase,
    pub peers: Vec<DiscoveredPeer>,
    pub connected_handle: Option<u16>,
}

impl Default for CentralPhase {
    fn default() -> Self {
        CentralPhase::Idle
    }
}

impl Central {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a discovered peer (or refresh its `last_rssi`).
    pub fn report_advertisement(
        &mut self,
        address_type: u8,
        address: [u8; 6],
        event_type: u8,
        ad_data: &[u8],
        rssi: i8,
    ) {
        if let Some(p) = self
            .peers
            .iter_mut()
            .find(|p| p.address == address && p.address_type == address_type)
        {
            p.last_rssi = rssi;
            p.event_type = event_type;
            // Refresh AD bytes if non-empty (scan responses carry
            // distinct AD records and should replace the latest).
            if !ad_data.is_empty() {
                p.ad_data = ad_data.to_vec();
            }
            return;
        }
        self.peers.push(DiscoveredPeer {
            address_type,
            address,
            last_rssi: rssi,
            event_type,
            ad_data: ad_data.to_vec(),
        });
    }

    /// Mark phase after the host has just emitted Set_Scan_Parameters.
    pub fn note_parameters_sent(&mut self) {
        self.phase = CentralPhase::ParametersSent;
    }

    /// Mark phase after the host has just emitted Set_Scan_Enable(1).
    pub fn note_scanning(&mut self) {
        self.phase = CentralPhase::Scanning;
    }

    /// Mark phase after the host has just emitted Set_Scan_Enable(0)
    /// to pre-empt a connect.
    pub fn note_scan_stopping(&mut self) {
        self.phase = CentralPhase::ScanStopping;
    }

    /// Mark phase after the host has just emitted LE_Create_Connection.
    pub fn note_connecting(&mut self) {
        self.phase = CentralPhase::Connecting;
    }

    /// Apply an LE Connection Complete subevent — clears any in-flight
    /// scan, records the connection handle, advances the state.
    pub fn note_connection_complete(&mut self, status: u8, handle: u16) {
        if status == 0x00 {
            self.connected_handle = Some(handle);
            self.phase = CentralPhase::Connected;
        } else {
            // Failed connect: drop back to Idle. The host can retry.
            self.connected_handle = None;
            self.phase = CentralPhase::Idle;
        }
    }

    /// Apply a Disconnection Complete event — clears connection state.
    pub fn note_disconnected(&mut self) {
        self.connected_handle = None;
        self.phase = CentralPhase::Idle;
    }
}
