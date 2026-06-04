// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/nfc/src/lib.rs — NCI 1.0 core types + NfcTransport trait
//
// NCI 1.0 specification:
//   NFC Controller Interface (NCI), Technical Specification, Version 1.0
//   NFC Forum, 2012.
//
// Packet format reference (NCI 1.0 §3.4):
//   Byte 0: [7:5] MT | [4] PBF | [3:0] GID   (control packets)
//            [7:5] MT | [4] PBF | [3:0] ConnID (data packets)
//   Byte 1: [7:2] RFU | [5:0] OID             (control packets)
//            0x00                               (data packets)
//   Byte 2: Payload Length (0–255)
//
// Linux cross-reference: include/net/nfc/nci.h, net/nfc/nci/core.c

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;

pub mod nxp_pn553;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

// ─── NCI Message Types (MT field, bits[7:5] of byte 0) ──────────────────────
// NCI 1.0 §3.4.1 Table 1

/// MT = 0b000 — Data packet
pub const NCI_MT_DATA: u8 = 0x00;
/// MT = 0b001 — Control Command (Host → NFCC)
pub const NCI_MT_CMD: u8 = 0x01;
/// MT = 0b010 — Control Response (NFCC → Host)
pub const NCI_MT_RSP: u8 = 0x02;
/// MT = 0b011 — Control Notification (NFCC → Host, unsolicited)
pub const NCI_MT_NTF: u8 = 0x03;

// ─── NCI Group IDs (GID, bits[3:0] of byte 0, control packets) ──────────────
// NCI 1.0 §4.1 Table 5

/// GID = 0x0 — NCI Core group (CORE_RESET, CORE_INIT, …)
pub const NCI_GID_CORE: u8 = 0x00;
/// GID = 0x1 — RF Management group (RF_DISCOVER_MAP, RF_DISCOVER, …)
pub const NCI_GID_RF_MGMT: u8 = 0x01;
/// GID = 0x2 — NFCEE Management group
pub const NCI_GID_NFCEE_MGMT: u8 = 0x02;
/// GID = 0xF — Vendor-specific
pub const NCI_GID_PROPRIETARY: u8 = 0x0F;

// ─── NCI Opcodes (OID) ───────────────────────────────────────────────────────

// CORE group (GID 0x0)
pub const NCI_OID_CORE_RESET: u8 = 0x00;
pub const NCI_OID_CORE_INIT: u8 = 0x01;

// RF Management group (GID 0x1)
pub const NCI_OID_RF_DISCOVER_MAP: u8 = 0x00;
pub const NCI_OID_RF_DISCOVER: u8 = 0x03;

// ─── NCI Status Codes ────────────────────────────────────────────────────────
// NCI 1.0 §4.2 Table 94

pub const NCI_STATUS_OK: u8 = 0x00;
pub const NCI_STATUS_REJECTED: u8 = 0x01;
pub const NCI_STATUS_FAILED: u8 = 0x03;

// ─── Reset Types ─────────────────────────────────────────────────────────────
pub const NCI_RESET_KEEP_CONFIG: u8 = 0x00;
pub const NCI_RESET_RESET_CONFIG: u8 = 0x01;

// ─── Discovery Map Mode Flags ─────────────────────────────────────────────────
pub const NCI_DISC_MAP_MODE_POLL: u8 = 0x01;
pub const NCI_DISC_MAP_MODE_LISTEN: u8 = 0x02;

// ─── RF Tech/Mode constants ───────────────────────────────────────────────────
pub const NCI_NFC_A_PASSIVE_POLL_MODE: u8 = 0x00;
pub const NCI_NFC_B_PASSIVE_POLL_MODE: u8 = 0x01;
pub const NCI_NFC_F_PASSIVE_POLL_MODE: u8 = 0x02;
pub const NCI_NFC_V_PASSIVE_POLL_MODE: u8 = 0x06;

// ─── NCI Error type ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NfcError {
    /// Transport I/O failure
    Io,
    /// Response status != STATUS_OK
    Status(u8),
    /// Response shorter than expected
    ShortResponse,
    /// Unrecognised MT/GID/OID combination
    UnknownOpcode,
    /// Payload length field doesn't match actual payload
    LengthMismatch,
}

// ─── NCI Packet Header ───────────────────────────────────────────────────────

/// Three-byte NCI 1.0 control-packet header.
///
/// Wire layout (NCI 1.0 §3.4):
///
/// ```text
/// byte 0: [ 7:5 MT ][ 4 PBF ][ 3:0 GID ]
/// byte 1: [ 7:2 RFU ][ 5:0 OID ]
/// byte 2: Payload Length
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NciHeader {
    /// Message Type (0=data, 1=cmd, 2=rsp, 3=ntf)
    pub mt: u8,
    /// Packet Boundary Flag — true means more fragments follow
    pub pbf: bool,
    /// Group ID (bits[3:0] of byte 0; undefined for data packets)
    pub gid: u8,
    /// Opcode ID (bits[5:0] of byte 1)
    pub oid: u8,
    /// Payload length (byte 2)
    pub length: u8,
}

impl NciHeader {
    /// Encode into the three-byte wire format.
    #[inline]
    pub fn encode(&self) -> [u8; 3] {
        let b0 = ((self.mt & 0x07) << 5) | (if self.pbf { 1 << 4 } else { 0 }) | (self.gid & 0x0F);
        let b1 = self.oid & 0x3F;
        [b0, b1, self.length]
    }

    /// Decode from a three-byte wire slice.
    ///
    /// Returns `Err(NfcError::ShortResponse)` if `bytes.len() < 3`.
    pub fn decode(bytes: &[u8]) -> Result<Self, NfcError> {
        if bytes.len() < 3 {
            return Err(NfcError::ShortResponse);
        }
        Ok(Self {
            mt: (bytes[0] >> 5) & 0x07,
            pbf: (bytes[0] & (1 << 4)) != 0,
            gid: bytes[0] & 0x0F,
            oid: bytes[1] & 0x3F,
            length: bytes[2],
        })
    }
}

// ─── NCI Message ─────────────────────────────────────────────────────────────

/// Full NCI control message with decoded header fields and owned payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NciMessage {
    pub mt: u8,
    pub pbf: bool,
    pub gid: u8,
    pub oid: u8,
    pub payload: Vec<u8>,
}

impl NciMessage {
    /// Serialize to the complete on-wire byte sequence (header + payload).
    pub fn encode(&self) -> Vec<u8> {
        let hdr = NciHeader {
            mt: self.mt,
            pbf: self.pbf,
            gid: self.gid,
            oid: self.oid,
            length: self.payload.len() as u8,
        };
        let raw = hdr.encode();
        let mut out = Vec::with_capacity(3 + self.payload.len());
        out.extend_from_slice(&raw);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode from a raw byte buffer (must include header + payload).
    pub fn decode(bytes: &[u8]) -> Result<Self, NfcError> {
        let hdr = NciHeader::decode(bytes)?;
        let expected_end = 3 + hdr.length as usize;
        if bytes.len() < expected_end {
            return Err(NfcError::LengthMismatch);
        }
        Ok(Self {
            mt: hdr.mt,
            pbf: hdr.pbf,
            gid: hdr.gid,
            oid: hdr.oid,
            payload: bytes[3..expected_end].to_vec(),
        })
    }
}

// ─── Control command constructors ────────────────────────────────────────────

/// CORE_RESET_CMD — NCI 1.0 §4.1.1
///
/// `reset_type`: `NCI_RESET_KEEP_CONFIG` (0x00) or `NCI_RESET_RESET_CONFIG` (0x01)
pub fn core_reset(reset_type: u8) -> NciMessage {
    NciMessage {
        mt: NCI_MT_CMD,
        pbf: false,
        gid: NCI_GID_CORE,
        oid: NCI_OID_CORE_RESET,
        payload: alloc::vec![reset_type],
    }
}

/// CORE_INIT_CMD — NCI 1.0 §4.1.3  (empty payload)
pub fn core_init() -> NciMessage {
    NciMessage {
        mt: NCI_MT_CMD,
        pbf: false,
        gid: NCI_GID_CORE,
        oid: NCI_OID_CORE_INIT,
        payload: Vec::new(),
    }
}

/// Single RF_DISCOVER_MAP entry.
///
/// Each entry maps an RF Protocol to an RF Interface + mode bitmask.
/// NCI 1.0 §7.1  Table 66.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfDiscoverMapEntry {
    /// RF Protocol (NCI_RF_PROTOCOL_*)
    pub rf_protocol: u8,
    /// Mode: NCI_DISC_MAP_MODE_POLL and/or NCI_DISC_MAP_MODE_LISTEN
    pub mode: u8,
    /// RF Interface (NCI_RF_INTERFACE_*)
    pub rf_interface: u8,
}

/// RF_DISCOVER_MAP_CMD — NCI 1.0 §7.1
pub fn rf_discover_map(entries: &[RfDiscoverMapEntry]) -> NciMessage {
    let mut payload = Vec::with_capacity(1 + entries.len() * 3);
    payload.push(entries.len() as u8);
    for e in entries {
        payload.push(e.rf_protocol);
        payload.push(e.mode);
        payload.push(e.rf_interface);
    }
    NciMessage {
        mt: NCI_MT_CMD,
        pbf: false,
        gid: NCI_GID_RF_MGMT,
        oid: NCI_OID_RF_DISCOVER_MAP,
        payload,
    }
}

/// Single RF_DISCOVER configuration entry.
///
/// NCI 1.0 §7.3  Table 68: (RF Tech+Mode, Frequency).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfDiscoverEntry {
    /// RF Technology and Mode (NCI_NFC_*_PASSIVE_POLL_MODE, etc.)
    pub rf_tech_mode: u8,
    /// Repetition frequency (0 = don't care / NFCC default)
    pub frequency: u8,
}

/// RF_DISCOVER_CMD — NCI 1.0 §7.3
pub fn rf_discover(entries: &[RfDiscoverEntry]) -> NciMessage {
    let mut payload = Vec::with_capacity(1 + entries.len() * 2);
    payload.push(entries.len() as u8);
    for e in entries {
        payload.push(e.rf_tech_mode);
        payload.push(e.frequency);
    }
    NciMessage {
        mt: NCI_MT_CMD,
        pbf: false,
        gid: NCI_GID_RF_MGMT,
        oid: NCI_OID_RF_DISCOVER,
        payload,
    }
}

// ─── CORE_INIT response decoder ──────────────────────────────────────────────

/// Decoded fields from a CORE_INIT_RSP payload.
///
/// NCI 1.0 §4.1.4:
///   Status (1B) | NFCC Features (4B) | Max Logical Connections (1B) |
///   Max Routing Table Size (2B) | Max Ctrl Pkt Payload Size (1B) |
///   Max Size for Large Parameters (2B) | Manufacturer ID (1B) |
///   Manufacturer Specific Info (variable)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreInitResponse {
    pub status: u8,
    pub nci_version: u8, // byte 4 of NFCC Features = NCI version
    pub manufacturer_id: u8,
    pub manufacturer_specific: Vec<u8>,
}

impl CoreInitResponse {
    /// Decode from a raw CORE_INIT_RSP `NciMessage`.
    ///
    /// Returns `Err(NfcError::ShortResponse)` if the payload is too short.
    /// Returns `Err(NfcError::Status(s))` if status != NCI_STATUS_OK.
    pub fn from_message(msg: &NciMessage) -> Result<Self, NfcError> {
        // Minimum layout: status(1) + nfcc_features(4) + max_log_conn(1) +
        //                 max_routing(2) + max_ctrl_payload(1) +
        //                 max_large_params(2) + manufacturer_id(1) = 12 bytes
        let p = &msg.payload;
        if p.len() < 12 {
            return Err(NfcError::ShortResponse);
        }
        let status = p[0];
        if status != NCI_STATUS_OK {
            return Err(NfcError::Status(status));
        }
        // NCI version is carried in NFCC Features byte 0 (bits[7:4] = major, [3:0] = minor)
        // stored at payload offset 1.
        let nci_version = p[1];
        // Manufacturer ID at offset 11.
        let manufacturer_id = p[11];
        // Remainder is Manufacturer Specific Info.
        let manufacturer_specific = p[12..].to_vec();
        Ok(Self {
            status,
            nci_version,
            manufacturer_id,
            manufacturer_specific,
        })
    }
}

// ─── NfcTransport trait ──────────────────────────────────────────────────────

/// Abstraction over the physical transport layer (I2C, SPI, USB).
///
/// Implementors are responsible for framing (e.g. the NXP PN553 I2C
/// transport reads a 3-byte header first, then the payload).
pub trait NfcTransport {
    /// Transmit `bytes` to the NFCC over the physical link.
    fn write(&self, bytes: &[u8]) -> Result<(), NfcError>;

    /// Receive up to `buf.len()` bytes from the NFCC.
    ///
    /// Returns the number of bytes actually read.
    fn read(&self, buf: &mut [u8]) -> Result<usize, NfcError>;

    /// Returns `true` when the controller's IRQ line is asserted (data ready).
    ///
    /// On NXP PN553 this is the active-high /IRQ GPIO.
    fn irq_high(&self) -> bool;
}
