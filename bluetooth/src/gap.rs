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
pub fn find(buf: &[u8], ad_type: u8) -> Option<&[u8]> {
    for rec in AdIter::new(buf).flatten() {
        if rec.ad_type == ad_type {
            return Some(rec.payload);
        }
    }
    None
}

/// Decode a Local Name — looks up Complete first then Shortened.
pub fn local_name(buf: &[u8]) -> Option<String> {
    let payload =
        find(buf, AD_COMPLETE_LOCAL_NAME).or_else(|| find(buf, AD_SHORTENED_LOCAL_NAME))?;
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
pub fn manufacturer_data(buf: &[u8]) -> Option<(u16, &[u8])> {
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

// ── LE Extended Create Connection (§7.8.66, v1 OCF 0x0043) ──────────
//
// The v1 command takes one 16-byte parameter block per initiating
// PHY, in ascending bit order (LE 1M first, then LE Coded). The v2
// form (OCF 0x0085, + Advertising_Handle/Subevent for a periodic
// advertising train) is out of scope — periodic advertising is
// tracked separately (#1560).

/// Initiating PHYs (§7.8.66): bit 0 = LE 1M, bit 2 = LE Coded —
/// the PHYs on which connectable advertisements are scanned and
/// for which connection parameters are provided. Bit 1 (LE 2M)
/// is deliberately NOT offered here: §7.8.66 assigns it connection
/// parameters only — no scanning PHY — and its scan interval/window
/// are ignored by the controller; a 2M link is reached via PHY
/// update after a 1M/Coded connect. At least one scanning PHY
/// (bit 0 or bit 2) must be set, or the controller rejects the
/// command with Invalid HCI Command Parameters (0x12).
pub const INITIATING_PHY_LE_1M: u8 = 0x01;
pub const INITIATING_PHY_LE_CODED: u8 = 0x04;
/// Valid initiating-PHY bits for this lane: 1M | Coded.
pub const INITIATING_PHY_MASK: u8 = INITIATING_PHY_LE_1M | INITIATING_PHY_LE_CODED;

/// Per-PHY initiation parameters for one bit of `Initiating_PHYs`
/// (§7.8.66). 16 bytes on the wire, in this field order.
/// `scan_interval` / `scan_window` are 0.625 ms units
/// (0x0004..=0xFFFF); `conn_interval_min/max` are 1.25 ms units
/// (0x0006..=0x0C80); `supervision_timeout` is 10 ms units
/// (0x000A..=0x0C80); `min_ce_length` / `max_ce_length` are
/// 0.625 ms units.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtConnPhyParams {
    pub scan_interval: u16,
    pub scan_window: u16,
    pub conn_interval_min: u16,
    pub conn_interval_max: u16,
    pub max_latency: u16,
    pub supervision_timeout: u16,
    pub min_ce_length: u16,
    pub max_ce_length: u16,
}

impl Default for ExtConnPhyParams {
    fn default() -> Self {
        // Same defaults as the legacy `CreateConnection::to_peer`:
        // 30 ms scan, 30..50 ms connection interval, 4 s
        // supervision timeout.
        Self {
            scan_interval: 0x0030,
            scan_window: 0x0030,
            conn_interval_min: 0x0018,
            conn_interval_max: 0x0028,
            max_latency: 0x0000,
            supervision_timeout: 0x0190,
            min_ce_length: 0,
            max_ce_length: 0,
        }
    }
}

/// LE Extended Create Connection payload (§7.8.66, v1). 10-byte
/// header + 16 bytes per initiating PHY: 26 bytes for one PHY,
/// 42 for both.
#[derive(Clone, Debug)]
pub struct ExtendedCreateConnection {
    pub initiator_filter_policy: InitiatorFilterPolicy,
    pub peer_address_type: PeerAddressType,
    pub peer_address: [u8; 6],
    pub own_address_type: OwnAddressType,
    /// Initiating PHYs bitmask: `INITIATING_PHY_LE_1M` (0x01)
    /// and/or `INITIATING_PHY_LE_CODED` (0x04).
    pub phys: u8,
    /// Parameters for the LE 1M PHY; required when bit 0 is set.
    pub phy_1m: Option<ExtConnPhyParams>,
    /// Parameters for the LE Coded PHY; required when bit 2 is set.
    pub phy_coded: Option<ExtConnPhyParams>,
}

impl ExtendedCreateConnection {
    /// Defaults for a typical Central connection to a known peer
    /// on the LE 1M PHY: 30 ms scan, public-address peer, 30..50 ms
    /// connection interval, 4 s supervision timeout.
    pub fn to_peer(peer_address_type: PeerAddressType, peer_address: [u8; 6]) -> Self {
        Self {
            initiator_filter_policy: InitiatorFilterPolicy::PeerAddress,
            peer_address_type,
            peer_address,
            own_address_type: OwnAddressType::Public,
            phys: INITIATING_PHY_LE_1M,
            phy_1m: Some(ExtConnPhyParams::default()),
            phy_coded: None,
        }
    }

    /// Same as [`Self::to_peer`] but initiating on the LE Coded
    /// PHY only (long-range connectable advertisements).
    pub fn to_peer_coded(peer_address_type: PeerAddressType, peer_address: [u8; 6]) -> Self {
        Self {
            initiator_filter_policy: InitiatorFilterPolicy::PeerAddress,
            peer_address_type,
            peer_address,
            own_address_type: OwnAddressType::Public,
            phys: INITIATING_PHY_LE_CODED,
            phy_1m: None,
            phy_coded: Some(ExtConnPhyParams::default()),
        }
    }

    /// Same as [`Self::to_peer`] but initiating on both the LE 1M
    /// and LE Coded PHYs: the controller scans both and the
    /// connection is created on whichever PHY hears the peer first
    /// (§7.8.66: scanning on any other PHY terminates once a
    /// connection request is sent on one PHY).
    pub fn to_peer_dual_phy(peer_address_type: PeerAddressType, peer_address: [u8; 6]) -> Self {
        Self {
            initiator_filter_policy: InitiatorFilterPolicy::PeerAddress,
            peer_address_type,
            peer_address,
            own_address_type: OwnAddressType::Public,
            phys: INITIATING_PHY_LE_1M | INITIATING_PHY_LE_CODED,
            phy_1m: Some(ExtConnPhyParams::default()),
            phy_coded: Some(ExtConnPhyParams::default()),
        }
    }

    /// Encode the parameter block, or `None` when the request is
    /// malformed: no scanning PHY set, a bit outside
    /// `INITIATING_PHY_MASK`, a missing per-PHY parameter block,
    /// or an inverted connection-interval / connection-event-length
    /// range (§7.8.66: min shall not exceed max).
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.phys == 0 || (self.phys & !INITIATING_PHY_MASK) != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(10 + 16 * 2);
        out.push(self.initiator_filter_policy as u8);
        out.push(self.own_address_type as u8);
        out.push(self.peer_address_type as u8);
        out.extend_from_slice(&self.peer_address);
        out.push(self.phys);
        // Per-PHY blocks in ascending bit order (§7.8.66: "The
        // array elements ... are ordered in the same order as the
        // set bits in the Initiating_PHYs parameter, starting
        // from bit 0").
        for (bit, params) in [
            (INITIATING_PHY_LE_1M, self.phy_1m),
            (INITIATING_PHY_LE_CODED, self.phy_coded),
        ] {
            if (self.phys & bit) == 0 {
                continue;
            }
            let p = params?;
            if p.conn_interval_min > p.conn_interval_max || p.min_ce_length > p.max_ce_length {
                return None;
            }
            out.extend_from_slice(&p.scan_interval.to_le_bytes());
            out.extend_from_slice(&p.scan_window.to_le_bytes());
            out.extend_from_slice(&p.conn_interval_min.to_le_bytes());
            out.extend_from_slice(&p.conn_interval_max.to_le_bytes());
            out.extend_from_slice(&p.max_latency.to_le_bytes());
            out.extend_from_slice(&p.supervision_timeout.to_le_bytes());
            out.extend_from_slice(&p.min_ce_length.to_le_bytes());
            out.extend_from_slice(&p.max_ce_length.to_le_bytes());
        }
        Some(out)
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum CentralPhase {
    /// Initial state, no scan in progress.
    #[default]
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

// ── LE Periodic Advertising — GAP encoders + state machines ────────
//
// Vol 4 Part E §7.8.61..63 (broadcaster: set parameters / data /
// enable), §7.8.67..69 (receiver: create sync / cancel / terminate),
// §7.7.65.14..16 (report / sync established / sync lost subevents).
// OCFs live in `crate::opcode`; the builders here produce only the
// parameter bytes that go after the 2-byte opcode + 1-byte length in
// an HCI Command.
//
// Two roles, two machines, mirroring `Central`:
// - `PeriodicAdvertiser` — the broadcaster side: which advertising
//   handle carries a periodic train and whether it is enabled.
// - `PeriodicSync` — the receiver side: creating / synced / lost.
// The pump drives both from `dispatch_event` (inbound subevents +
// command completions) and the `periodic_adv_*` API (outbound
// issuance). The state machines themselves are transport-free so
// they are straightforward to unit-test.

/// Periodic advertising interval bounds (§7.8.61): 0x0006..=0xFFFF
/// in units of 1.25 ms (7.5 ms..=81.91875 s).
pub const PER_ADV_INTERVAL_MIN: u16 = 0x0006;
pub const PER_ADV_INTERVAL_MAX: u16 = 0xFFFF;

/// `Periodic_Advertising_Properties` bits (§7.8.61).
pub const PER_ADV_PROP_INCLUDE_TX_POWER: u16 = 0x0001;
pub const PER_ADV_PROP_INCLUDE_ADI: u16 = 0x0040;

/// Maximum periodic advertising data length (§7.8.62):
/// `Advertising_Data_Length` is 0..=251.
pub const PER_ADV_DATA_MAX_LEN: usize = 251;

/// `Options` bits for LE Periodic Advertising Create Sync (§7.8.67).
pub const PA_SYNC_OPT_USE_PERIODIC_ADVERTISER_LIST: u8 = 0x01;
pub const PA_SYNC_OPT_REPORTING_ENABLED: u8 = 0x02;
pub const PA_SYNC_OPT_DUPLICATE_FILTERING: u8 = 0x04;

/// `Skip` bounds for Create Sync (§7.8.67): 0x0000..=0x01F3
/// periodic advertising events the controller may skip.
pub const PA_SYNC_SKIP_MAX: u16 = 0x01F3;

/// `Sync_Timeout` bounds for Create Sync (§7.8.67): 0x000A..=0x4000
/// in units of 10 ms (100 ms..=163.84 s).
pub const PA_SYNC_TIMEOUT_MIN: u16 = 0x000A;
pub const PA_SYNC_TIMEOUT_MAX: u16 = 0x4000;

/// `Sync_CTE_Type` values for Create Sync (§7.8.67).
pub const PA_SYNC_CTE_NONE: u8 = 0x00;
pub const PA_SYNC_CTE_AOA: u8 = 0x01;
pub const PA_SYNC_CTE_AOD_1US: u8 = 0x02;
pub const PA_SYNC_CTE_AOD_2US: u8 = 0x03;
pub const PA_SYNC_CTE_NO_SYNC_TO_CTE: u8 = 0xFF;

/// LE Set Periodic Advertising Parameters payload (§7.8.61).
/// 7 bytes on the wire.
#[derive(Copy, Clone, Debug)]
pub struct PeriodicAdvertisingParameters {
    pub advertising_handle: u8,
    pub interval_min: u16,
    pub interval_max: u16,
    pub include_tx_power: bool,
    pub include_adi: bool,
}

impl PeriodicAdvertisingParameters {
    /// 100 ms periodic interval (0x0050 * 1.25 ms), Tx Power
    /// included, ADI omitted — a typical broadcaster default.
    pub fn for_handle(advertising_handle: u8) -> Self {
        Self {
            advertising_handle,
            interval_min: 0x0050,
            interval_max: 0x0050,
            include_tx_power: true,
            include_adi: false,
        }
    }

    /// Spec range check (§7.8.61): both intervals in
    /// 0x0006..=0xFFFF and min <= max. The controller rejects
    /// out-of-range intervals with Invalid HCI Command Parameters
    /// (0x12); the pump refuses to send them at all.
    pub fn is_valid(&self) -> bool {
        self.interval_min >= PER_ADV_INTERVAL_MIN
            && self.interval_max >= PER_ADV_INTERVAL_MIN
            && self.interval_min <= self.interval_max
    }

    /// Build the 7-byte parameter block for
    /// HCI_LE_Set_Periodic_Advertising_Parameters.
    pub fn encode(&self) -> [u8; 7] {
        let mut properties: u16 = 0;
        if self.include_tx_power {
            properties |= PER_ADV_PROP_INCLUDE_TX_POWER;
        }
        if self.include_adi {
            properties |= PER_ADV_PROP_INCLUDE_ADI;
        }
        let min = self.interval_min.to_le_bytes();
        let max = self.interval_max.to_le_bytes();
        let props = properties.to_le_bytes();
        [
            self.advertising_handle,
            min[0],
            min[1],
            max[0],
            max[1],
            props[0],
            props[1],
        ]
    }
}

/// `Operation` for LE Set Periodic Advertising Data (§7.8.62).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeriodicAdvDataOperation {
    /// Intermediate fragment of the periodic advertising data.
    Intermediate = 0x00,
    /// First fragment.
    First = 0x01,
    /// Last fragment.
    Last = 0x02,
    /// Complete periodic advertising data (single fragment).
    Complete = 0x03,
    /// Unchanged data (controller re-uses the previous data;
    /// `Advertising_Data_Length` must be 0).
    Unchanged = 0x04,
}

/// Build the parameter block for HCI_LE_Set_Periodic_Advertising_Data
/// (§7.8.62): advertising_handle (1) + operation (1) +
/// advertising_data_length (1) + advertising_data (0..=251).
/// Callers must keep `data.len()` <= [`PER_ADV_DATA_MAX_LEN`] and
/// pass empty data for [`PeriodicAdvDataOperation::Unchanged`]; the
/// pump checks both before sending.
pub fn encode_periodic_adv_data(
    advertising_handle: u8,
    operation: PeriodicAdvDataOperation,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + data.len());
    out.push(advertising_handle);
    out.push(operation as u8);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

/// LE Set Periodic Advertising Enable payload (§7.8.63). 2 bytes.
#[derive(Copy, Clone, Debug)]
pub struct PeriodicAdvertisingEnable {
    pub enable: bool,
    pub advertising_handle: u8,
}

impl PeriodicAdvertisingEnable {
    pub fn encode(&self) -> [u8; 2] {
        [self.enable as u8, self.advertising_handle]
    }
}

/// LE Periodic Advertising Create Sync payload (§7.8.67). 14 bytes.
///
/// `options` is a bitmap of the `PA_SYNC_OPT_*` consts; use
/// [`PeriodicAdvertisingCreateSync::to_advertiser`] for the common
/// case (reporting on, duplicate filtering off, sync to a named
/// advertiser rather than the periodic advertiser list).
#[derive(Copy, Clone, Debug)]
pub struct PeriodicAdvertisingCreateSync {
    pub options: u8,
    pub advertising_sid: u8,
    pub advertiser_address_type: PeerAddressType,
    pub advertiser_address: [u8; 6],
    pub skip: u16,
    pub sync_timeout: u16,
    pub sync_cte_type: u8,
}

impl PeriodicAdvertisingCreateSync {
    /// Sync to a named advertiser: reporting initially enabled,
    /// no duplicate filtering, no periodic events skipped, 10 s
    /// sync timeout, no CTE sync (0xFF = do not sync to packets
    /// with a Constant Tone Extension — plain periodic trains
    /// carry none).
    pub fn to_advertiser(
        advertising_sid: u8,
        advertiser_address_type: PeerAddressType,
        advertiser_address: [u8; 6],
    ) -> Self {
        Self {
            options: PA_SYNC_OPT_REPORTING_ENABLED,
            advertising_sid,
            advertiser_address_type,
            advertiser_address,
            skip: 0x0000,
            // 0x03E8 * 10 ms = 10 s.
            sync_timeout: 0x03E8,
            sync_cte_type: PA_SYNC_CTE_NO_SYNC_TO_CTE,
        }
    }

    /// Spec range check (§7.8.67): skip <= 0x01F3, timeout in
    /// 0x000A..=0x4000, CTE type one of 0x00..=0x03 or 0xFF.
    pub fn is_valid(&self) -> bool {
        self.skip <= PA_SYNC_SKIP_MAX
            && self.sync_timeout >= PA_SYNC_TIMEOUT_MIN
            && self.sync_timeout <= PA_SYNC_TIMEOUT_MAX
            && (self.sync_cte_type <= PA_SYNC_CTE_AOD_2US
                || self.sync_cte_type == PA_SYNC_CTE_NO_SYNC_TO_CTE)
    }

    /// Build the 14-byte parameter block for
    /// HCI_LE_Periodic_Advertising_Create_Sync.
    pub fn encode(&self) -> [u8; 14] {
        let mut out = [0u8; 14];
        out[0] = self.options;
        out[1] = self.advertising_sid;
        out[2] = self.advertiser_address_type as u8;
        out[3..9].copy_from_slice(&self.advertiser_address);
        out[9..11].copy_from_slice(&self.skip.to_le_bytes());
        out[11..13].copy_from_slice(&self.sync_timeout.to_le_bytes());
        out[13] = self.sync_cte_type;
        out
    }
}

/// LE Periodic Advertising Terminate Sync parameter block (§7.8.69).
/// 2 bytes: sync_handle (2 LE).
pub fn build_periodic_adv_terminate_sync(sync_handle: u16) -> [u8; 2] {
    sync_handle.to_le_bytes()
}

// ── Broadcaster side ────────────────────────────────────────────────

/// Phases the periodic advertiser walks during train setup.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum PeriodicAdvertiserPhase {
    /// No periodic parameters configured for any handle.
    #[default]
    Idle,
    /// Parameters accepted for a handle; data may be set and the
    /// train may be enabled.
    Configured,
    /// Train enabled on the configured handle.
    Enabled,
}

/// Broadcaster-side periodic advertising state. The pump issues the
/// §7.8.61..63 commands; this machine records what the controller
/// has accepted, so the API can refuse enable-before-configure and
/// data-for-the-wrong-handle instead of sending a command the
/// controller must reject.
#[derive(Debug, Default)]
pub struct PeriodicAdvertiser {
    pub phase: PeriodicAdvertiserPhase,
    /// Handle the accepted parameters belong to, if any.
    pub advertising_handle: Option<u8>,
    /// Handle whose Set Parameters command is in flight (set at
    /// send time, consumed by the Command Complete).
    pending_handle: Option<u8>,
    /// (handle, enable) of an in-flight Set Enable command.
    pending_enable: Option<(u8, bool)>,
}

impl PeriodicAdvertiser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a Set Periodic Advertising Parameters command sent.
    pub fn note_parameters_sent(&mut self, advertising_handle: u8) {
        self.pending_handle = Some(advertising_handle);
    }

    /// Apply the Command Complete for Set Parameters: on success
    /// the handle is configured; on failure nothing changes and a
    /// retry from Idle/Configured is still possible. Re-setting
    /// parameters for the already-enabled handle keeps the train
    /// Enabled.
    pub fn note_parameters_set(&mut self, status: u8) {
        if let (0, Some(handle)) = (status, self.pending_handle.take()) {
            let was_enabled = self.phase == PeriodicAdvertiserPhase::Enabled
                && self.advertising_handle == Some(handle);
            self.advertising_handle = Some(handle);
            self.phase = if was_enabled {
                PeriodicAdvertiserPhase::Enabled
            } else {
                PeriodicAdvertiserPhase::Configured
            };
        }
    }

    /// Mark a Set Periodic Advertising Enable command sent.
    pub fn note_enable_sent(&mut self, advertising_handle: u8, enable: bool) {
        self.pending_enable = Some((advertising_handle, enable));
    }

    /// Apply the Command Complete for Set Enable: on success the
    /// phase follows the requested direction; on failure the phase
    /// is unchanged.
    pub fn note_enable_done(&mut self, status: u8) {
        match (status, self.pending_enable.take()) {
            (0, Some((handle, true))) => {
                self.advertising_handle = Some(handle);
                self.phase = PeriodicAdvertiserPhase::Enabled;
            }
            (0, Some((_, false))) => {
                // Disabling drops back to Configured (parameters
                // survive; the train can be re-enabled).
                if self.phase == PeriodicAdvertiserPhase::Enabled {
                    self.phase = PeriodicAdvertiserPhase::Configured;
                }
            }
            _ => {}
        }
    }
}

// ── Receiver side ───────────────────────────────────────────────────

/// Phases the periodic-sync receiver walks.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum PeriodicSyncPhase {
    /// No sync in progress or established.
    #[default]
    Idle,
    /// Create Sync issued, awaiting Sync Established (or a
    /// Command Status rejection).
    Creating,
    /// Sync established; reports are being received.
    Synced,
    /// Terminate Sync issued, awaiting its Command Complete.
    Terminating,
}

/// Receiver-side periodic advertising sync state. Transport-free:
/// the pump feeds it parsed subevents and command completions, and
/// it reassembles fragmented reports (Data_Status 0x01 fragments
/// accumulate until a 0x00 complete fragment lands; a 0x02
/// truncated fragment discards the partial reassembly, matching
/// the kernel's `iso_connect_ind` reassembly discipline).
///
/// A reassembled train payload is at most [`PER_ADV_DATA_MAX_LEN`]
/// bytes (§7.8.62); a fragment run that would exceed that is
/// discarded rather than grown without bound.
#[derive(Debug, Default)]
pub struct PeriodicSync {
    pub phase: PeriodicSyncPhase,
    /// Sync handle from the Sync Established subevent, while Synced
    /// (or Terminating).
    pub sync_handle: Option<u16>,
    pub advertising_sid: u8,
    pub advertiser_address_type: u8,
    pub advertiser_address: [u8; 6],
    pub advertiser_phy: u8,
    pub periodic_interval: u16,
    pub advertiser_clock_accuracy: u8,
    /// Complete (reassembled) reports delivered so far.
    pub reports_received: u32,
    /// Most recent complete report payload (AD records, verbatim).
    pub last_report: Vec<u8>,
    pub last_rssi: i8,
    pub last_tx_power: i8,
    /// Partial reassembly of an in-flight fragmented report.
    fragment: Vec<u8>,
}

impl PeriodicSync {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a Create Sync command sent.
    pub fn note_create_sync_sent(&mut self) {
        self.phase = PeriodicSyncPhase::Creating;
    }

    /// The controller rejected Create Sync outright (Command Status
    /// != 0): no sync will ever be established for this attempt.
    pub fn note_create_sync_rejected(&mut self) {
        if self.phase == PeriodicSyncPhase::Creating {
            self.phase = PeriodicSyncPhase::Idle;
        }
    }

    /// Apply the Command Complete for Create Sync Cancel: on
    /// success the pending attempt is gone.
    pub fn note_create_sync_cancelled(&mut self, status: u8) {
        if self.phase == PeriodicSyncPhase::Creating && status == 0 {
            self.phase = PeriodicSyncPhase::Idle;
        }
    }

    /// Apply a Sync Established subevent (§7.7.65.15). Only a
    /// pending attempt (Creating) can be established; a stale or
    /// duplicate subevent is ignored. A failed establishment
    /// (status != 0) returns to Idle.
    pub fn note_sync_established(&mut self, est: &crate::event::LePeriodicAdvSyncEstablished) {
        if self.phase != PeriodicSyncPhase::Creating {
            return;
        }
        if est.status != 0 {
            self.phase = PeriodicSyncPhase::Idle;
            return;
        }
        self.sync_handle = Some(est.sync_handle);
        self.advertising_sid = est.advertising_sid;
        self.advertiser_address_type = est.advertiser_address_type;
        self.advertiser_address = est.advertiser_address;
        self.advertiser_phy = est.advertiser_phy;
        self.periodic_interval = est.periodic_advertising_interval;
        self.advertiser_clock_accuracy = est.advertiser_clock_accuracy;
        self.fragment.clear();
        self.phase = PeriodicSyncPhase::Synced;
    }

    /// Apply one Periodic Advertising Report (§7.7.65.14). Reports
    /// for another sync handle, or while not Synced, are ignored —
    /// a residual report racing a Sync Lost / Terminate must not
    /// resurrect state. Complete fragments deliver the reassembled
    /// payload; More-To-Come fragments accumulate (bounded by
    /// [`PER_ADV_DATA_MAX_LEN`]); Truncated fragments drop the
    /// partial reassembly.
    pub fn note_report(&mut self, report: &crate::event::LePeriodicAdvReport) {
        if self.phase != PeriodicSyncPhase::Synced {
            return;
        }
        if self.sync_handle != Some(report.sync_handle) {
            return;
        }
        self.last_rssi = report.rssi;
        self.last_tx_power = report.tx_power;
        match report.data_status {
            crate::event::LE_PA_DATA_COMPLETE => {
                let mut assembled = core::mem::take(&mut self.fragment);
                assembled.extend_from_slice(&report.data);
                self.last_report = assembled;
                self.reports_received += 1;
            }
            crate::event::LE_PA_DATA_MORE_TO_COME => {
                if self.fragment.len() + report.data.len() <= PER_ADV_DATA_MAX_LEN {
                    self.fragment.extend_from_slice(&report.data);
                } else {
                    // Over-long fragment run: the train is
                    // misbehaving; drop the partial reassembly
                    // rather than grow without bound.
                    self.fragment.clear();
                }
            }
            crate::event::LE_PA_DATA_TRUNCATED => {
                self.fragment.clear();
            }
            _ => {}
        }
    }

    /// Apply a Sync Lost subevent (§7.7.65.16). Only the matching
    /// handle tears the sync down; a lost event for a stale handle
    /// is ignored.
    pub fn note_sync_lost(&mut self, lost: &crate::event::LePeriodicAdvSyncLost) {
        if self.sync_handle != Some(lost.sync_handle) {
            return;
        }
        self.clear_sync();
    }

    /// Mark a Terminate Sync command sent.
    pub fn note_terminate_sent(&mut self) {
        if self.phase == PeriodicSyncPhase::Synced {
            self.phase = PeriodicSyncPhase::Terminating;
        }
    }

    /// Apply the Command Complete for Terminate Sync: on success
    /// the sync is gone; on failure the sync is still up.
    pub fn note_terminated(&mut self, status: u8) {
        if self.phase != PeriodicSyncPhase::Terminating {
            return;
        }
        if status == 0 {
            self.clear_sync();
        } else {
            self.phase = PeriodicSyncPhase::Synced;
        }
    }

    fn clear_sync(&mut self) {
        self.phase = PeriodicSyncPhase::Idle;
        self.sync_handle = None;
        self.fragment.clear();
    }

    /// Snapshot of the receiver-visible sync state, for the pump
    /// API / fixtures. The in-flight fragment is intentionally not
    /// exposed: only complete reports are observable.
    pub fn snapshot(&self) -> PeriodicSyncSnapshot {
        PeriodicSyncSnapshot {
            phase: self.phase,
            sync_handle: self.sync_handle,
            advertising_sid: self.advertising_sid,
            advertiser_address_type: self.advertiser_address_type,
            advertiser_address: self.advertiser_address,
            advertiser_phy: self.advertiser_phy,
            periodic_interval: self.periodic_interval,
            reports_received: self.reports_received,
            last_report: self.last_report.clone(),
            last_rssi: self.last_rssi,
            last_tx_power: self.last_tx_power,
        }
    }
}

/// Receiver-visible periodic-sync state (see [`PeriodicSync::snapshot`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodicSyncSnapshot {
    pub phase: PeriodicSyncPhase,
    pub sync_handle: Option<u16>,
    pub advertising_sid: u8,
    pub advertiser_address_type: u8,
    pub advertiser_address: [u8; 6],
    pub advertiser_phy: u8,
    pub periodic_interval: u16,
    pub reports_received: u32,
    pub last_report: Vec<u8>,
    pub last_rssi: i8,
    pub last_tx_power: i8,
}
