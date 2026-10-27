//! Intel Integrated Sensor Hub (ISH) transport — ISHTP.
//!
//! Intel laptops expose their ambient-light / accelerometer / gyro /
//! lid-angle sensors through the Integrated Sensor Hub, a small
//! coprocessor on the PCH that speaks ISHTP (the Intel Sensor Hub
//! Transport Protocol, MEI's sibling) over a PCI functionBAR +
//! doorbell IPC channel. This module is the transport that was
//! missing from the input stack (issue #1030): it probes the ISH
//! PCI function, runs the ISHTP host-bus handshake, connects the
//! HID client, fetches the firmware's HID + report descriptors,
//! and feeds published input reports into the shared decode layer
//! in [`crate::hid_sensor`], which publishes `SensorEvent`s on the
//! sensor ring for consumers (issue #773 owns the userspace
//! surface on top of that ring). The publication shape and unit
//! contract deliberately mirror the AMD SFH transport
//! ([`crate::amd_sfh`]) so consumers see one sensor story across
//! vendors.
//!
//! ## Hardware contract
//!
//! Grounded in the ISH interface as implemented by Linux's
//! `drivers/hid/intel-ish-hid` (GPL-2.0; register layouts, message
//! encodings and GUIDs are Intel's published interface, restated
//! here).
//!
//! ### PCI identity
//!
//! The ISH function is vendor 8086 with a per-platform device ID
//! (see `PCI_IDS` — the full set Linux claims, CHV through NVL).
//! BAR0 holds the IPC register window; the defined registers end
//! at 0x400, so a BAR shorter than that is not an ISH window.
//! (Mehlow-server 8086:A309/A30A carry an ISH-shaped function that
//! must never be bound; they are not in the table.)
//!
//! ### IPC channel (BAR0)
//!
//! | Offset | Register | Meaning |
//! |--------|----------|---------|
//! | 0x34 | ISH_HOST_FWSTS | firmware status: ILUP bit 0, ISHTP_READY bit 1, FW state bits [15:12] |
//! | 0x38 | HOST_COMM | host status: ILUP bit 0, READY bit 7 |
//! | 0x44 | ISH_RST | firmware reset |
//! | 0x48 | HOST2ISH_DRBL | host→ISH doorbell (header below) |
//! | 0x54 | ISH2HOST_DRBL | ISH→host doorbell |
//! | 0x60 | ISH2HOST_MSG | ISH→host payload window, 128 bytes |
//! | 0xE0 | HOST2ISH_MSG | host→ISH payload window, 128 bytes |
//!
//! A doorbell word is a transfer header: length bits [9:0],
//! protocol bits [13:10] (1 = ISHTP, 3 = management), management
//! command bits [19:16], BUSY bit 31. One doorbell transfer
//! carries at most 128 bytes (`IPC_MSG_MAX_SIZE`); an ISHTP
//! message longer than that is fragmented across transfers — the
//! 4-byte ISHTP header rides only in the first fragment and the
//! receiver reassembles by the header's length field. The sender
//! polls the peer doorbell's BUSY bit before each fragment; the
//! receiver copies the payload window, then clears BUSY in the
//! doorbell to hand the window back (setting HOST_OWNS, bit 30,
//! while it reads, per the A0 erratum note in the register spec).
//!
//! Bring-up: wait for FWSTS.ILUP, set HOST_COMM ILUP+READY, wait
//! for FWSTS.ISHTP_READY, then run the HBM handshake. Interrupt
//! mask registers (PISR/PIMR) are deliberately untouched — this
//! transport polls the doorbell (see "Known gaps").
//!
//! ### ISHTP (protocol 1)
//!
//! Every message starts with a 4-byte header: fw_addr (byte 0),
//! host_addr (byte 1), payload length bits [24:16] (9 bits),
//! msg_complete bit 31. Address 0 on both sides is the Host Bus
//! Manager (HBM). HBM commands used here: HOST_START_REQ/RES
//! (0x01/0x81, version {minor 0, major 1}), HOST_ENUM_REQ/RES
//! (0x04/0x84, 32-byte valid-address bitmap),
//! HOST_CLIENT_PROPERTIES_REQ/RES (0x05/0x85, 28-byte client
//! properties incl. the protocol GUID and max message length),
//! CLIENT_CONNECT_REQ/RES (0x06/0x86, status 0 = success),
//! CLIENT_DISCONNECT_REQ/RES (0x07/0x87) and
//! ISHTP_FLOW_CONTROL (0x08). HOST_STOP_REQ (0x02) is sent
//! best-effort when bring-up fails midway.
//!
//! Flow control is per connection and credit-based, MEI-style:
//! the firmware grants the host one send credit with a
//! FLOW_CONTROL message after connect and after each consumed
//! client message; the host grants the firmware one credit at
//! connect and after each consumed firmware message. HBM-channel
//! messages are exempt. A client send with no credit waits
//! (bounded) for one — it never overruns the firmware.
//!
//! ### HID client
//!
//! The HID client is found by GUID
//! `33AECD58-B679-4E54-9BD9-A04D34F0C226` in the enumerated
//! properties. Its messages carry a 6-byte `hostif` header
//! {command (bit 7 = response), device_id, status, flags,
//! payload size u16}. Commands: GET_HID_DESCRIPTOR 0,
//! GET_REPORT_DESCRIPTOR 1, GET_FEATURE_REPORT 2,
//! SET_FEATURE_REPORT 3, GET_INPUT_REPORT 4,
//! PUBLISH_INPUT_REPORT 5, PUBLISH_INPUT_REPORT_LIST 6,
//! DM_ENUM_DEVICES 33. ENUM_DEVICES' response payload is a count
//! byte followed by packed 9-byte device records {dev_id u32,
//! dev_class u8, pid u16, vid u16}. Descriptor responses are the
//! raw descriptor bytes; published input reports are raw HID
//! reports *including* the report-ID prefix byte, exactly what
//! [`crate::hid_sensor::decode_report`] consumes. The aggregated
//! LIST form packs {total_size u16, count u8, flags u8} then
//! per-report records {size u16 (header+payload), hostif header,
//! payload}.
//!
//! Requests on the HID connection are serialised: one outstanding
//! request at a time (the firmware answers in order; Linux's
//! client effectively serialises its init the same way).
//!
//! ### System-state client (suspend / resume)
//!
//! Firmware client address 13 is the fixed system-state client.
//! The host connects (host_addr 2), subscribes to the
//! connected-standby + suspend state bits, and answers the
//! suspend path with a STATE_CHANGE_REQ (cmd 4) carrying
//! requested_states; the firmware acknowledges with the same
//! command and cmd_status set. The device_pm hooks use it to
//! notify the hub across system sleep (ISH is a wake source);
//! notification is best-effort and never vetoes suspend.
//!
//! ## Unit contract
//!
//! Unlike SFH (whose descriptors the transport itself
//! synthesises), ISH descriptors come from the firmware and
//! declare each data field's unit exponent. The conversion into
//! the decode layer's conventions is the shared
//! `hid_sensor::rescale_event`, driven by the profile's first data
//! field exponent `e` (raw × 10^e is the value in the HID Sensor
//! Usages base unit):
//!
//! - accel: base unit m/s² → milli-g: `raw × 10^(e+3) × 1000 / 9807`
//! - gyro: base unit deg/s → milli-deg/s: `raw × 10^(e+3)`
//! - mag: base unit milligauss → µT: `raw × 10^(e+3) / 10_000`
//! - ALS: base unit lux → lux: `raw × 10^e`
//! - inclinometer: base unit degrees → milli-deg: `raw × 10^(e+3)`
//! - proximity: passed through (distance already in mm /
//!   presence flag, per the usages spec).
//!
//! ## Composition
//!
//! Pre-flight (2026-10-26): no other in-tree driver or scaffold
//! claims any ISH PCI ID and no ISHTP code exists anywhere in
//! the tree, so — unlike SFH's MP2 function (#1046) — this
//! transport's probe has the field to itself.
//!
//! ## Known gaps (named, not hidden)
//!
//! - IRQ delivery: the ISH raises MSI/INTx, but input-class
//!   devices have no IRQ routing in this tree yet (same gap the
//!   SFH lane named for MP2 INTx), so the pump polls the doorbell
//!   at 5 ms. One MMIO read per idle tick; reports are not lost,
//!   only latency-quantised to the poll cadence.
//! - DMA client channels (HBM DMA_BUFFER_ALLOC_NOTIFY / DMA_XFER)
//!   are not implemented; no ISH HID firmware uses them for the
//!   HID client. If a future HID client advertises DMA-only
//!   operation, connect fails with `IshError::DmaOnlyClient`.
//! - Management-protocol traffic beyond reset notification
//!   (clock sync, RX-completion modes) is not implemented;
//!   RESET_NOTIFY is acknowledged and the session is rebuilt
//!   (see `IshHub::service`), other management commands are
//!   counted and dropped.
//! - HID devices whose descriptors yield no sensor profiles
//!   (e.g. an ISH-attached keyboard) are enumerated and logged
//!   but not presented: non-sensor HID belongs to the USB /
//!   I2C-HID paths in this stack (#773's surface is sensor-only).
//! - Full D0i3 / D3 platform power management of the PCI
//!   function belongs to platform PM; this module wires the
//!   ISHTP-level suspend/resume notification only.
//!
//! TCB: this module lives in `drivers/input`, outside the TCB
//! (frame/ + memory/ domain manager + capabilities/ core +
//! scheduler executor core + security-model/).

use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_lib::sync::IrqSafeSpinLock;

use crate::hid_sensor::{self, HidSensorKind, HidSensorProfile, SensorEvent};

// ── PCI identity ─────────────────────────────────────────────────

/// Intel vendor ID.
pub const INTEL_VENDOR: u16 = 0x8086;

/// All (vendor, device) pairs this transport claims — the ISH
/// function device IDs, CHV through NVL, matching the set Linux's
/// `ish_pci_tbl` claims.
pub const PCI_IDS: &[(u16, u16)] = &[
    (INTEL_VENDOR, 0x22D8), // CHV — Cherry Trail
    (INTEL_VENDOR, 0x0AA2), // BXT Ax — Broxton
    (INTEL_VENDOR, 0x1AA2), // BXT Bx — Broxton
    (INTEL_VENDOR, 0x5AA2), // APL Ax — Apollo Lake
    (INTEL_VENDOR, 0x9D35), // SPT Ax — Skylake-U/Y (Sunrise Point-LP)
    (INTEL_VENDOR, 0x9DFC), // CNL Ax — Cannon Lake
    (INTEL_VENDOR, 0x31A2), // GLK Ax — Gemini Lake
    (INTEL_VENDOR, 0xA37C), // CNL H — Cannon Lake-H
    (INTEL_VENDOR, 0x34FC), // ICL Mobile — Ice Lake
    (INTEL_VENDOR, 0xA135), // SPT H — Skylake-H (Sunrise Point-H)
    (INTEL_VENDOR, 0x02FC), // CML LP — Comet Lake-LP
    (INTEL_VENDOR, 0x06FC), // CMP H — Comet Lake-H
    (INTEL_VENDOR, 0x4BB3), // EHL Ax — Elkhart Lake
    (INTEL_VENDOR, 0xA0FC), // TGL LP — Tiger Lake-LP
    (INTEL_VENDOR, 0x43FC), // TGL H — Tiger Lake-H
    (INTEL_VENDOR, 0x7AF8), // ADL S — Alder Lake-S
    (INTEL_VENDOR, 0x51FC), // ADL P — Alder Lake-P
    (INTEL_VENDOR, 0x54FC), // ADL N — Alder Lake-N
    (INTEL_VENDOR, 0x7A78), // RPL S — Raptor Lake-S
    (INTEL_VENDOR, 0x7E45), // MTL P — Meteor Lake-P
    (INTEL_VENDOR, 0x7745), // ARL H — Arrow Lake-H
    (INTEL_VENDOR, 0x7F78), // ARL S — Arrow Lake-S
    (INTEL_VENDOR, 0xA845), // LNL M — Lunar Lake-M
    (INTEL_VENDOR, 0xE345), // PTL H — Panther Lake-H
    (INTEL_VENDOR, 0xE445), // PTL P — Panther Lake-P
    (INTEL_VENDOR, 0x4D45), // WCL — Wildcat Lake
    (INTEL_VENDOR, 0xD354), // NVL H — Nova Lake-H
    (INTEL_VENDOR, 0x6E78), // NVL S — Nova Lake-S
];

/// BAR holding the IPC register window.
const BAR_IPC: u8 = 0;
/// Minimum BAR0 length: the defined IPC registers end at
/// `IPC_REG_MAX` (0x400).
pub const ISH_BAR_MIN_LEN: usize = 0x400;

// ── IPC register map (BAR0) ──────────────────────────────────────

/// ISH firmware status register.
pub const REG_FWSTS: u64 = 0x34;
/// Host communication / status register.
pub const REG_HOST_COMM: u64 = 0x38;
/// Firmware reset register.
pub const REG_RST: u64 = 0x44;
/// Host→ISH doorbell.
pub const REG_HOST2ISH_DRBL: u64 = 0x48;
/// ISH→host doorbell.
pub const REG_ISH2HOST_DRBL: u64 = 0x54;
/// ISH→host payload window.
pub const REG_ISH2HOST_MSG: u64 = 0x60;
/// Host→ISH payload window.
pub const REG_HOST2ISH_MSG: u64 = 0xE0;

/// FWSTS / HOST_COMM ILUP bit ("interface link up").
pub const ILUP_BIT: u32 = 1 << 0;
/// FWSTS ISHTP_READY bit.
pub const ISHTP_READY_BIT: u32 = 1 << 1;
/// HOST_COMM host-ready bit.
pub const HOST_READY_BIT: u32 = 1 << 7;
/// FWSTS firmware-state field mask (bits [15:12]).
pub const FWSTS_STATE_MASK: u32 = 0xF << 12;

/// Doorbell BUSY bit.
pub const DRBL_BUSY: u32 = 1 << 31;
/// Doorbell HOST_OWNS bit (host is reading the payload window).
pub const DRBL_HOST_OWNS: u32 = 1 << 30;

/// IPC protocol numbers (doorbell bits [13:10]).
pub mod ipc_proto {
    /// ISHTP protocol.
    pub const ISHTP: u32 = 1;
    /// Management protocol.
    pub const MNG: u32 = 3;
}

/// Management commands (doorbell bits [19:16]).
pub mod mng_cmd {
    /// Firmware is about to reset; host must ack.
    pub const RESET_NOTIFY: u32 = 3;
    /// Host ack of RESET_NOTIFY.
    pub const RESET_NOTIFY_ACK: u32 = 4;
}

/// Maximum payload bytes in one doorbell transfer.
pub const IPC_MSG_MAX_SIZE: usize = 0x80;

/// Build a doorbell header word for an ISHTP transfer.
pub fn drbl_header_ishtp(len: usize) -> u32 {
    DRBL_BUSY | (ipc_proto::ISHTP << 10) | (len as u32 & 0x3FF)
}

/// Build a doorbell header word for a management transfer.
pub fn drbl_header_mng(cmd: u32, len: usize) -> u32 {
    DRBL_BUSY | (ipc_proto::MNG << 10) | ((cmd & 0xF) << 16) | (len as u32 & 0x3FF)
}

/// Payload length field of a doorbell word.
pub fn drbl_len(word: u32) -> usize {
    (word & 0x3FF) as usize
}

/// Protocol field of a doorbell word.
pub fn drbl_proto(word: u32) -> u32 {
    (word >> 10) & 0xF
}

/// Management-command field of a doorbell word.
pub fn drbl_mng_cmd(word: u32) -> u32 {
    (word >> 16) & 0xF
}

// ── ISHTP wire header ────────────────────────────────────────────

/// ISHTP message header length in bytes.
pub const ISHTP_HDR_LEN: usize = 4;

/// Pack an ISHTP header: fw_addr, host_addr, payload length
/// (9 bits), msg_complete.
pub fn ishtp_hdr(fw_addr: u8, host_addr: u8, payload_len: usize) -> [u8; ISHTP_HDR_LEN] {
    let word = (fw_addr as u32)
        | ((host_addr as u32) << 8)
        | (((payload_len as u32) & 0x1FF) << 16)
        | (1u32 << 31);
    word.to_le_bytes()
}

/// Unpack an ISHTP header into (fw_addr, host_addr, payload_len).
pub fn ishtp_parse_hdr(bytes: &[u8]) -> Option<(u8, u8, usize)> {
    if bytes.len() < ISHTP_HDR_LEN {
        return None;
    }
    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Some((
        (word & 0xFF) as u8,
        ((word >> 8) & 0xFF) as u8,
        ((word >> 16) & 0x1FF) as usize,
    ))
}

// ── HBM (host bus manager) ───────────────────────────────────────

/// HBM command opcodes (response = request | 0x80).
pub mod hbm {
    /// Host start handshake.
    pub const HOST_START_REQ: u8 = 0x01;
    /// Host stop.
    pub const HOST_STOP_REQ: u8 = 0x02;
    /// Firmware stop notification.
    pub const FW_STOP_REQ: u8 = 0x03;
    /// Enumerate firmware clients.
    pub const HOST_ENUM_REQ: u8 = 0x04;
    /// Query one client's properties.
    pub const HOST_CLIENT_PROPERTIES_REQ: u8 = 0x05;
    /// Connect a client.
    pub const CLIENT_CONNECT_REQ: u8 = 0x06;
    /// Disconnect a client.
    pub const CLIENT_DISCONNECT_REQ: u8 = 0x07;
    /// Flow-control credit grant.
    pub const ISHTP_FLOW_CONTROL: u8 = 0x08;
    /// Response bit.
    pub const RESP_BIT: u8 = 0x80;
}

/// HBM protocol version this host speaks.
pub const HBM_VERSION: (u8, u8) = (0, 1); // (minor, major)

/// Connect-response status: success.
pub const CONNECT_SUCCESS: u8 = 0;

/// Properties of one firmware client, from
/// HOST_CLIENT_PROPERTIES_RES.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientProperties {
    /// Protocol GUID, wire byte order (GUID fields little-endian,
    /// as in Linux's `guid_t` memory layout).
    pub protocol_name: [u8; 16],
    /// Protocol version.
    pub protocol_version: u8,
    /// Maximum simultaneous connections.
    pub max_connections: u8,
    /// Fixed firmware address (0 = dynamic).
    pub fixed_address: u8,
    /// Single receive buffer flag.
    pub single_recv_buf: u8,
    /// Maximum ISHTP payload for this client, bytes.
    pub max_msg_length: u32,
    /// DMA header length; bit 7 (0x80) = DMA enabled.
    pub dma_hdr_len: u8,
}

/// Client properties payload length (after the 4-byte response
/// preamble).
pub const CLIENT_PROPS_LEN: usize = 28;

/// Parse the 28-byte client-properties payload.
pub fn parse_client_properties(bytes: &[u8]) -> Option<ClientProperties> {
    if bytes.len() < CLIENT_PROPS_LEN {
        return None;
    }
    let mut protocol_name = [0u8; 16];
    protocol_name.copy_from_slice(&bytes[0..16]);
    Some(ClientProperties {
        protocol_name,
        protocol_version: bytes[16],
        max_connections: bytes[17],
        fixed_address: bytes[18],
        single_recv_buf: bytes[19],
        max_msg_length: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
        dma_hdr_len: bytes[24],
    })
}

/// The HID client's protocol GUID in wire byte order
/// (`33AECD58-B679-4E54-9BD9-A04D34F0C226`).
pub const HID_CLIENT_GUID: [u8; 16] = [
    0x58, 0xCD, 0xAE, 0x33, 0x79, 0xB6, 0x54, 0x4E, 0x9B, 0xD9, 0xA0, 0x4D, 0x34, 0xF0, 0xC2, 0x26,
];

/// Fixed firmware address of the system-state client.
pub const SYSSTATE_CLIENT_ADDR: u8 = 13;

/// Host-side connection addresses. Address 0 is HBM itself.
pub const HOST_ADDR_HID: u8 = 1;
/// Host address of the system-state connection.
pub const HOST_ADDR_SYSSTATE: u8 = 2;

// ── System-state client protocol ─────────────────────────────────

/// System-state message commands (first u32 of the payload).
pub mod sysstate_cmd {
    /// Subscribe to state changes.
    pub const SUBSCRIBE: u32 = 0x1;
    /// State status report.
    pub const STATUS: u32 = 0x2;
    /// Query subscribers.
    pub const QUERY_SUBSCRIBERS: u32 = 0x3;
    /// State change request / acknowledgement.
    pub const STATE_CHANGE_REQ: u32 = 0x4;
}

/// Connected-standby state bit.
pub const STATE_CONNECTED_STANDBY: u32 = 1 << 0;
/// Suspend state bit.
pub const STATE_SUSPEND: u32 = 1 << 1;

// ── HID client (hostif) protocol ────────────────────────────────

/// hostif command opcodes (response = request | 0x80).
pub mod hostif {
    /// Fetch the HID class descriptor.
    pub const GET_HID_DESCRIPTOR: u8 = 0;
    /// Fetch the report descriptor.
    pub const GET_REPORT_DESCRIPTOR: u8 = 1;
    /// Get a feature report.
    pub const GET_FEATURE_REPORT: u8 = 2;
    /// Set a feature report.
    pub const SET_FEATURE_REPORT: u8 = 3;
    /// Get (poll) an input report.
    pub const GET_INPUT_REPORT: u8 = 4;
    /// Firmware-published input report.
    pub const PUBLISH_INPUT_REPORT: u8 = 5;
    /// Firmware-published aggregated input reports.
    pub const PUBLISH_INPUT_REPORT_LIST: u8 = 6;
    /// Enumerate HID devices.
    pub const DM_ENUM_DEVICES: u8 = 33;
    /// A HID device was added (hot-plug notification).
    pub const DM_ADD_DEVICE: u8 = 34;
    /// Response bit.
    pub const RESP_BIT: u8 = 0x80;
    /// Command mask (strips the response bit).
    pub const CMD_MASK: u8 = 0x7F;
}

/// hostif header length: command, device_id, status, flags,
/// payload size u16.
pub const HOSTIF_HDR_LEN: usize = 6;

/// One HID device record from DM_ENUM_DEVICES (packed, 9 bytes):
/// dev_id u32, dev_class u8, pid u16, vid u16.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HidDeviceInfo {
    /// Firmware device ID (goes in the hostif header).
    pub dev_id: u32,
    /// Device class byte.
    pub dev_class: u8,
    /// USB-style product ID.
    pub pid: u16,
    /// USB-style vendor ID.
    pub vid: u16,
}

/// HID device record length in the enum response.
pub const HID_DEVICE_INFO_LEN: usize = 9;

/// Parse the ENUM_DEVICES response payload: count byte, then
/// packed device records.
pub fn parse_enum_devices(payload: &[u8]) -> Vec<HidDeviceInfo> {
    let mut out = Vec::new();
    if payload.is_empty() {
        return out;
    }
    let count = payload[0] as usize;
    for i in 0..count {
        let off = 1 + i * HID_DEVICE_INFO_LEN;
        if off + HID_DEVICE_INFO_LEN > payload.len() {
            break;
        }
        let b = &payload[off..off + HID_DEVICE_INFO_LEN];
        out.push(HidDeviceInfo {
            dev_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            dev_class: b[4],
            pid: u16::from_le_bytes([b[5], b[6]]),
            vid: u16::from_le_bytes([b[7], b[8]]),
        });
    }
    out
}

/// Fields of the standard 9-byte HID class descriptor this
/// transport reads out of a GET_HID_DESCRIPTOR response.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HidDescriptorInfo {
    /// bcdHID release number.
    pub bcd_hid: u16,
    /// Number of subordinate descriptors.
    pub num_descriptors: u8,
    /// Declared report-descriptor length.
    pub report_desc_len: u16,
}

/// Parse a HID class descriptor (type 0x21, report descriptor
/// type 0x22 first subordinate).
pub fn parse_hid_descriptor(bytes: &[u8]) -> Option<HidDescriptorInfo> {
    if bytes.len() < 9 || bytes[0] < 9 || bytes[1] != 0x21 || bytes[6] != 0x22 {
        return None;
    }
    Some(HidDescriptorInfo {
        bcd_hid: u16::from_le_bytes([bytes[2], bytes[3]]),
        num_descriptors: bytes[5],
        report_desc_len: u16::from_le_bytes([bytes[7], bytes[8]]),
    })
}

// ── Errors ───────────────────────────────────────────────────────

/// Transport-level failure modes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IshError {
    /// Firmware never raised ILUP / ISHTP_READY in the window.
    FirmwareNotReady,
    /// A doorbell stayed BUSY past the transfer timeout.
    DoorbellBusy,
    /// Firmware did not answer a request in time.
    ResponseTimeout,
    /// No flow-control credit arrived within the send timeout.
    CreditTimeout,
    /// HBM start handshake was rejected / version unsupported.
    StartRejected,
    /// Enumeration found no client with the wanted GUID.
    ClientNotFound,
    /// The HID client advertises DMA-only operation.
    DmaOnlyClient,
    /// Connect request answered with a non-success status.
    ConnectRefused(u8),
    /// The bus handshake has not run (or the session died).
    NotStarted,
    /// A HID request was answered with a non-zero status.
    HidStatus(u8),
    /// Device index out of range.
    NoSuchDevice,
    /// A response/descriptor payload was malformed.
    BadPayload,
    /// A message exceeds the client's max message length.
    MessageTooLarge,
}

// ── Hardware access trait ────────────────────────────────────────
//
// The protocol core is written against this trait so the fixture
// model can stand in for the silicon: `IshBus` is the BAR0 IPC
// register window. The production impl is below; the fixture
// impl lives in the tests module and models the firmware side of
// the conversation.

/// BAR0 IPC register-window access (32-bit MMIO).
pub trait IshBus {
    /// Read a 32-bit register at byte offset `off`.
    fn read32(&self, off: u64) -> u32;
    /// Write a 32-bit register at byte offset `off`.
    fn write32(&self, off: u64, val: u32);
}

// ── Production hardware access ───────────────────────────────────

/// Production `IshBus` over the mapped BAR0.
#[derive(Debug)]
pub struct MmioBus {
    regs: narf_driver_runtime::MmioRegion,
}

impl MmioBus {
    /// Wrap a mapped BAR0 region.
    pub fn new(regs: narf_driver_runtime::MmioRegion) -> Self {
        Self { regs }
    }
    /// BAR length in bytes.
    pub fn len(&self) -> usize {
        self.regs.len as usize
    }
    /// Whether the BAR is empty (never for a real mapping).
    pub fn is_empty(&self) -> bool {
        self.regs.len == 0
    }
}

impl IshBus for MmioBus {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: offsets used by the protocol core are within
        // the IPC window whose length probe validated
        // (≥ ISH_BAR_MIN_LEN); the bus probe contract gives this
        // driver exclusive ownership of the function.
        unsafe { self.regs.read32(off) }
    }
    fn write32(&self, off: u64, val: u32) {
        // SAFETY: same contract as read32.
        unsafe { self.regs.write32(off, val) }
    }
}

// ── Hub core ─────────────────────────────────────────────────────

/// Default bounded wait for the firmware to become ISHTP-ready.
pub const FW_READY_TIMEOUT_MS: u64 = 2_000;
/// Default bounded wait for an HBM / HID response.
pub const RESPONSE_TIMEOUT_MS: u64 = 3_000;
/// Default bounded wait for a doorbell to clear / a send credit.
pub const TRANSFER_TIMEOUT_MS: u64 = 1_000;
/// Bounded wait for the suspend/resume acknowledgement
/// (Linux waits 25 ms for the suspend ack).
pub const SYSSTATE_ACK_TIMEOUT_MS: u64 = 25;

/// Maximum HID devices tracked per hub (Linux allows 32; ISH
/// sensor hubs present a handful).
pub const MAX_HID_DEVICES: usize = 8;
/// Maximum decoded profiles kept per HID device.
pub const MAX_PROFILES_PER_DEVICE: usize = 8;
/// Reassembly ceiling for one ISHTP message (the HID client's
/// advertised max message length, clamped).
pub const MAX_MSG_LEN: usize = 8192;
/// Cap on complete messages drained per `service` call.
const MAX_DRAIN_PER_SERVICE: usize = 64;

/// One bound HID device: firmware identity, its descriptors, and
/// the decode profiles built from the report descriptor.
#[derive(Debug)]
pub struct IshHidDevice {
    /// Firmware device record.
    pub info: HidDeviceInfo,
    /// Parsed HID class descriptor facts.
    pub hid_descriptor: Option<HidDescriptorInfo>,
    /// Raw report descriptor bytes as fetched.
    pub report_descriptor: Vec<u8>,
    /// Decode profiles with their descriptor unit exponents.
    pub profiles: Vec<ProfileSlot>,
}

/// A decode profile plus the unit exponent its data fields
/// declared (the transport's unit contract is exponent-driven).
#[derive(Debug)]
pub struct ProfileSlot {
    /// The shared decode-layer profile.
    pub profile: HidSensorProfile,
    /// Unit exponent of the profile's first data field.
    pub unit_exp: i32,
}

/// State of one host connection (HID / system-state).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ConnState {
    /// Not connected.
    Down,
    /// Connect request sent, response pending.
    Connecting,
    /// Connected; `tx_credit` gates sends.
    Up,
}

/// A completed HBM response the waiter inspects.
#[derive(Clone, Debug)]
struct HbmResult {
    cmd: u8,
    payload: Vec<u8>,
}

/// A completed HID-client response for the outstanding request.
#[derive(Clone, Debug)]
struct HidResult {
    cmd: u8,
    status: u8,
    payload: Vec<u8>,
}

/// ISHTP transport hub: owns the IPC channel, the HBM session,
/// the HID + system-state connections, and the bound HID
/// devices, and drives published reports into the shared HID
/// sensor decode layer.
pub struct IshHub<B: IshBus> {
    bus: B,
    /// HBM handshake completed.
    started: bool,
    /// Firmware HBM version from the start response.
    fw_hbm_version: Option<(u8, u8)>,
    /// Firmware client address of the HID client.
    hid_fw_addr: Option<u8>,
    /// HID client properties (max message length governs RX/TX).
    hid_props: Option<ClientProperties>,
    /// HID connection state + send credit.
    hid_conn: ConnState,
    hid_tx_credit: u32,
    /// System-state connection state + send credit.
    sys_conn: ConnState,
    sys_tx_credit: u32,
    /// Bound HID devices.
    devices: Vec<IshHidDevice>,
    /// HID devices were enumerated + descriptors fetched.
    hid_ready: bool,
    /// Outstanding HBM request's response command (0 = none).
    hbm_wait_cmd: u8,
    /// Completed HBM response slot.
    hbm_result: Option<HbmResult>,
    /// Outstanding HID request command (0 = none).
    hid_wait_cmd: u8,
    /// Completed HID response slot.
    hid_result: Option<HidResult>,
    /// Outstanding system-state ack (requested_states echo).
    sys_wait: Option<u32>,
    /// System-state acknowledgement received for `sys_wait`.
    sys_acked: bool,
    /// Firmware signalled a reset (MNG RESET_NOTIFY / FW_STOP):
    /// the session is dead and must be rebuilt before use.
    session_dead: bool,
    /// Management commands seen but not handled (counted, dropped).
    mng_unhandled: u32,
    /// RX reassembly buffer (fragments of one ISHTP message).
    rx_asm: Vec<u8>,
    /// Timeout budgets; fixtures shrink them.
    fw_ready_timeout_ms: u64,
    response_timeout_ms: u64,
    transfer_timeout_ms: u64,
}

impl<B: IshBus> core::fmt::Debug for IshHub<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IshHub")
            .field("started", &self.started)
            .field("hid_fw_addr", &self.hid_fw_addr)
            .field("hid_conn", &self.hid_conn)
            .field("sys_conn", &self.sys_conn)
            .field("devices", &self.devices.len())
            .field("session_dead", &self.session_dead)
            .finish_non_exhaustive()
    }
}

impl<B: IshBus> IshHub<B> {
    /// New hub. `bring_up` must run before the transport serves.
    pub fn new(bus: B) -> Self {
        Self {
            bus,
            started: false,
            fw_hbm_version: None,
            hid_fw_addr: None,
            hid_props: None,
            hid_conn: ConnState::Down,
            hid_tx_credit: 0,
            sys_conn: ConnState::Down,
            sys_tx_credit: 0,
            devices: Vec::new(),
            hid_ready: false,
            hbm_wait_cmd: 0,
            hbm_result: None,
            hid_wait_cmd: 0,
            hid_result: None,
            sys_wait: None,
            sys_acked: false,
            session_dead: false,
            mng_unhandled: 0,
            rx_asm: Vec::new(),
            fw_ready_timeout_ms: FW_READY_TIMEOUT_MS,
            response_timeout_ms: RESPONSE_TIMEOUT_MS,
            transfer_timeout_ms: TRANSFER_TIMEOUT_MS,
        }
    }

    /// Whether the HBM session is up and the HID client is bound.
    pub fn is_up(&self) -> bool {
        self.started && !self.session_dead && self.hid_conn == ConnState::Up
    }

    /// Whether the firmware signalled a reset and the session
    /// needs rebuilding.
    pub fn session_dead(&self) -> bool {
        self.session_dead
    }

    /// Firmware HBM version (minor, major), once started.
    pub fn fw_hbm_version(&self) -> Option<(u8, u8)> {
        self.fw_hbm_version
    }

    /// Number of bound HID devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// The `i`-th bound HID device.
    pub fn device(&self, i: usize) -> Option<&IshHidDevice> {
        self.devices.get(i)
    }

    /// Management commands counted and dropped so far.
    pub fn mng_unhandled(&self) -> u32 {
        self.mng_unhandled
    }

    // -- bounded-wait plumbing -------------------------------------
    //
    // Every wait in this module follows the same shape: poll the
    // condition, drain the IPC channel (responses and publishes
    // can arrive at any time), run sleep pumps, and give up at a
    // cycle deadline. Never a bare spin on a hardware register.

    fn deadline_from_now(&self, timeout_ms: u64) -> u64 {
        narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(timeout_ms * 1_000_000))
    }

    fn wait_or_timeout(&mut self, deadline: u64) -> Result<(), IshError> {
        // One service pass per wait iteration: inbound messages
        // are what every waiter is ultimately waiting for.
        self.service(narf_time::monotonic_ns());
        if narf_time::now_cycles() >= deadline {
            return Err(IshError::ResponseTimeout);
        }
        narf_scheduler::sleep_pumps::run();
        core::hint::spin_loop();
        Ok(())
    }

    // -- IPC transfer layer -----------------------------------------

    /// Send one complete ISHTP message (header + payload),
    /// fragmenting across doorbell transfers. `fw_addr` /
    /// `host_addr` 0/0 is the HBM channel.
    fn send_ishtp(&mut self, fw_addr: u8, host_addr: u8, payload: &[u8]) -> Result<(), IshError> {
        let max_payload = if fw_addr == 0 {
            MAX_MSG_LEN
        } else {
            self.hid_props
                .as_ref()
                .map(|p| p.max_msg_length as usize)
                .unwrap_or(MAX_MSG_LEN)
        };
        if payload.len() > max_payload.min(MAX_MSG_LEN) {
            return Err(IshError::MessageTooLarge);
        }
        // Client channels are credit-gated (HBM is exempt).
        if fw_addr != 0 {
            self.wait_credit(host_addr)?;
            *self.credit_mut(host_addr) -= 1;
        }
        let mut stream = Vec::with_capacity(ISHTP_HDR_LEN + payload.len());
        stream.extend_from_slice(&ishtp_hdr(fw_addr, host_addr, payload.len()));
        stream.extend_from_slice(payload);
        for chunk in stream.chunks(IPC_MSG_MAX_SIZE) {
            self.write_fragment(chunk)?;
        }
        Ok(())
    }

    fn credit_mut(&mut self, host_addr: u8) -> &mut u32 {
        match host_addr {
            HOST_ADDR_SYSSTATE => &mut self.sys_tx_credit,
            _ => &mut self.hid_tx_credit,
        }
    }

    fn wait_credit(&mut self, host_addr: u8) -> Result<(), IshError> {
        let deadline = self.deadline_from_now(self.transfer_timeout_ms);
        loop {
            if *self.credit_mut(host_addr) > 0 {
                return Ok(());
            }
            self.wait_or_timeout(deadline)
                .map_err(|_| IshError::CreditTimeout)?;
        }
    }

    /// Write one doorbell fragment: wait for the host doorbell to
    /// clear, copy the payload window, ring the bell.
    fn write_fragment(&mut self, chunk: &[u8]) -> Result<(), IshError> {
        debug_assert!(chunk.len() <= IPC_MSG_MAX_SIZE);
        let deadline = self.deadline_from_now(self.transfer_timeout_ms);
        while self.bus.read32(REG_HOST2ISH_DRBL) & DRBL_BUSY != 0 {
            if narf_time::now_cycles() >= deadline {
                return Err(IshError::DoorbellBusy);
            }
            narf_scheduler::sleep_pumps::run();
            core::hint::spin_loop();
        }
        for (i, word) in chunk.chunks(4).enumerate() {
            let mut b = [0u8; 4];
            b[..word.len()].copy_from_slice(word);
            self.bus
                .write32(REG_HOST2ISH_MSG + 4 * i as u64, u32::from_le_bytes(b));
        }
        self.bus
            .write32(REG_HOST2ISH_DRBL, drbl_header_ishtp(chunk.len()));
        Ok(())
    }

    /// Send a management-protocol message (doorbell header only,
    /// no payload) — used for RESET_NOTIFY_ACK.
    fn send_mng(&mut self, cmd: u32) -> Result<(), IshError> {
        let deadline = self.deadline_from_now(self.transfer_timeout_ms);
        while self.bus.read32(REG_HOST2ISH_DRBL) & DRBL_BUSY != 0 {
            if narf_time::now_cycles() >= deadline {
                return Err(IshError::DoorbellBusy);
            }
            narf_scheduler::sleep_pumps::run();
            core::hint::spin_loop();
        }
        self.bus.write32(REG_HOST2ISH_DRBL, drbl_header_mng(cmd, 0));
        Ok(())
    }

    // -- receive path ------------------------------------------------

    /// Drain the IPC channel: reassemble and dispatch every
    /// complete inbound ISHTP message, handle management
    /// traffic. Called by the pump and inside every wait.
    /// `now_ns` timestamps decoded sensor events.
    pub fn service(&mut self, now_ns: u64) {
        for _ in 0..MAX_DRAIN_PER_SERVICE {
            let drbl = self.bus.read32(REG_ISH2HOST_DRBL);
            if drbl & DRBL_BUSY == 0 {
                return;
            }
            let len = drbl_len(drbl).min(IPC_MSG_MAX_SIZE);
            let proto = drbl_proto(drbl);
            // Claim the payload window while we read it (A0
            // erratum discipline), then hand it back.
            self.bus.write32(REG_ISH2HOST_DRBL, drbl | DRBL_HOST_OWNS);
            let mut frag = [0u8; IPC_MSG_MAX_SIZE];
            for i in 0..len.div_ceil(4) {
                let word = self.bus.read32(REG_ISH2HOST_MSG + 4 * i as u64);
                frag[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
            }
            self.bus.write32(REG_ISH2HOST_DRBL, 0);
            match proto {
                ipc_proto::ISHTP => self.rx_fragment(&frag[..len], now_ns),
                ipc_proto::MNG => self.rx_mng(drbl_mng_cmd(drbl), &frag[..len]),
                _ => {}
            }
        }
    }

    /// One ISHTP fragment: append to the reassembly buffer and
    /// dispatch when the header's length is satisfied.
    fn rx_fragment(&mut self, frag: &[u8], now_ns: u64) {
        if self.rx_asm.is_empty() && frag.len() < ISHTP_HDR_LEN {
            return; // runt fragment; cannot hold a header
        }
        self.rx_asm.extend_from_slice(frag);
        let Some((fw_addr, host_addr, payload_len)) = ishtp_parse_hdr(&self.rx_asm) else {
            self.rx_asm.clear();
            return;
        };
        if payload_len > MAX_MSG_LEN {
            self.rx_asm.clear();
            return;
        }
        if self.rx_asm.len() < ISHTP_HDR_LEN + payload_len {
            return; // more fragments coming
        }
        let payload: Vec<u8> = self.rx_asm[ISHTP_HDR_LEN..ISHTP_HDR_LEN + payload_len].to_vec();
        self.rx_asm.clear();
        self.dispatch(fw_addr, host_addr, &payload, now_ns);
    }

    /// Management-protocol receive: RESET_NOTIFY is acked and
    /// kills the session (the firmware is rebooting underneath
    /// us); anything else is counted and dropped.
    fn rx_mng(&mut self, cmd: u32, _payload: &[u8]) {
        if cmd == mng_cmd::RESET_NOTIFY {
            let _ = self.send_mng(mng_cmd::RESET_NOTIFY_ACK);
            self.mark_session_dead();
        } else {
            self.mng_unhandled += 1;
        }
    }

    /// The firmware went away (reset notify / FW_STOP_REQ):
    /// every connection and the HBM session are gone.
    fn mark_session_dead(&mut self) {
        self.session_dead = true;
        self.started = false;
        self.hid_conn = ConnState::Down;
        self.sys_conn = ConnState::Down;
        self.hid_tx_credit = 0;
        self.sys_tx_credit = 0;
        self.hid_ready = false;
        self.devices.clear();
        self.rx_asm.clear();
    }

    /// Dispatch one complete ISHTP message.
    fn dispatch(&mut self, fw_addr: u8, host_addr: u8, payload: &[u8], now_ns: u64) {
        if fw_addr == 0 && host_addr == 0 {
            self.dispatch_hbm(payload);
            return;
        }
        // A message from a client connection: after consuming it,
        // grant the firmware one more send credit for that
        // connection (MEI-style flow control).
        match host_addr {
            HOST_ADDR_HID if fw_addr == self.hid_fw_addr.unwrap_or(0) => {
                self.dispatch_hid(payload, now_ns);
            }
            HOST_ADDR_SYSSTATE if fw_addr == SYSSTATE_CLIENT_ADDR => {
                self.dispatch_sysstate(payload);
            }
            _ => {}
        }
        let _ = self.send_flow_control(fw_addr, host_addr);
    }

    /// HBM-channel dispatch: responses complete the outstanding
    /// request; flow control tops up a connection's send credit;
    /// FW_STOP_REQ kills the session.
    fn dispatch_hbm(&mut self, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let cmd = payload[0];
        match cmd {
            hbm::ISHTP_FLOW_CONTROL => {
                // payload: cmd, fw_addr, host_addr, reserved[5]
                if payload.len() >= 3 {
                    let host_addr = payload[2];
                    *self.credit_mut(host_addr) = self.credit_mut(host_addr).saturating_add(1);
                }
            }
            hbm::FW_STOP_REQ => self.mark_session_dead(),
            _ => {
                if cmd & hbm::RESP_BIT != 0 && cmd == self.hbm_wait_cmd {
                    self.hbm_result = Some(HbmResult {
                        cmd,
                        payload: payload.to_vec(),
                    });
                }
            }
        }
    }

    /// Grant the firmware one send credit on a connection.
    fn send_flow_control(&mut self, fw_addr: u8, host_addr: u8) -> Result<(), IshError> {
        let mut msg = [0u8; 8];
        msg[0] = hbm::ISHTP_FLOW_CONTROL;
        msg[1] = fw_addr;
        msg[2] = host_addr;
        self.send_ishtp(0, 0, &msg)
    }

    // -- HBM request/response ----------------------------------------

    /// Send an HBM request and wait (bounded) for its response.
    fn hbm_request(&mut self, req: &[u8], resp_cmd: u8) -> Result<Vec<u8>, IshError> {
        self.hbm_result = None;
        self.hbm_wait_cmd = resp_cmd;
        let sent = self.send_ishtp(0, 0, req);
        if let Err(e) = sent {
            self.hbm_wait_cmd = 0;
            return Err(e);
        }
        let deadline = self.deadline_from_now(self.response_timeout_ms);
        loop {
            if let Some(res) = self.hbm_result.take() {
                self.hbm_wait_cmd = 0;
                if res.cmd == resp_cmd {
                    return Ok(res.payload);
                }
                return Err(IshError::BadPayload);
            }
            if self.session_dead {
                self.hbm_wait_cmd = 0;
                return Err(IshError::NotStarted);
            }
            self.wait_or_timeout(deadline)?;
        }
    }

    /// HBM start handshake.
    fn hbm_start(&mut self) -> Result<(), IshError> {
        let req = [hbm::HOST_START_REQ, 0, HBM_VERSION.0, HBM_VERSION.1];
        let resp = self.hbm_request(&req, hbm::HOST_START_REQ | hbm::RESP_BIT)?;
        // {cmd, host_version_supported, fw_minor, fw_major}
        if resp.len() < 4 || resp[1] == 0 {
            return Err(IshError::StartRejected);
        }
        self.fw_hbm_version = Some((resp[2], resp[3]));
        self.started = true;
        Ok(())
    }

    /// Enumerate firmware clients: (address, properties) pairs.
    fn enumerate_clients(&mut self) -> Result<Vec<(u8, ClientProperties)>, IshError> {
        let resp = self.hbm_request(
            &[hbm::HOST_ENUM_REQ, 0, 0, 0],
            hbm::HOST_ENUM_REQ | hbm::RESP_BIT,
        )?;
        // {cmd, reserved[3], valid_addresses[32]}
        if resp.len() < 4 + 32 {
            return Err(IshError::BadPayload);
        }
        let bitmap = &resp[4..36];
        let mut out = Vec::new();
        for addr in 1..=255u8 {
            if bitmap[(addr / 8) as usize] & (1 << (addr % 8)) == 0 {
                continue;
            }
            let props_resp = self.hbm_request(
                &[hbm::HOST_CLIENT_PROPERTIES_REQ, addr, 0, 0],
                hbm::HOST_CLIENT_PROPERTIES_REQ | hbm::RESP_BIT,
            )?;
            // {cmd, address, status, reserved, properties[28]}
            if props_resp.len() < 4 + CLIENT_PROPS_LEN || props_resp[1] != addr {
                continue;
            }
            if let Some(props) = parse_client_properties(&props_resp[4..]) {
                out.push((addr, props));
            }
        }
        Ok(out)
    }

    /// Connect one client connection; on success the firmware's
    /// first flow-control grant is awaited so the first client
    /// send never races the credit.
    fn connect_client(&mut self, fw_addr: u8, host_addr: u8) -> Result<(), IshError> {
        let resp = self.hbm_request(
            &[hbm::CLIENT_CONNECT_REQ, fw_addr, host_addr, 0],
            hbm::CLIENT_CONNECT_REQ | hbm::RESP_BIT,
        )?;
        // {cmd, fw_addr, host_addr, status}
        if resp.len() < 4 || resp[1] != fw_addr || resp[2] != host_addr {
            return Err(IshError::BadPayload);
        }
        if resp[3] != CONNECT_SUCCESS {
            return Err(IshError::ConnectRefused(resp[3]));
        }
        // Prime the firmware's send credit, then await its grant
        // to us (both ride the HBM channel).
        self.send_flow_control(fw_addr, host_addr)?;
        let deadline = self.deadline_from_now(self.response_timeout_ms);
        while *self.credit_mut(host_addr) == 0 {
            self.wait_or_timeout(deadline)
                .map_err(|_| IshError::CreditTimeout)?;
        }
        Ok(())
    }

    /// Disconnect one client connection (best-effort response).
    /// Disconnect a client channel. Part of the HBM surface;
    /// no production teardown path exists yet (the device_pm
    /// registry has no unregister either — #1034), so nothing
    /// calls this today.
    #[allow(dead_code)]
    fn disconnect_client(&mut self, fw_addr: u8, host_addr: u8) {
        let _ = self.hbm_request(
            &[hbm::CLIENT_DISCONNECT_REQ, fw_addr, host_addr, 0],
            hbm::CLIENT_DISCONNECT_REQ | hbm::RESP_BIT,
        );
        match host_addr {
            HOST_ADDR_SYSSTATE => {
                self.sys_conn = ConnState::Down;
                self.sys_tx_credit = 0;
            }
            _ => {
                self.hid_conn = ConnState::Down;
                self.hid_tx_credit = 0;
            }
        }
    }

    // -- hardware + session bring-up --------------------------------

    /// Wait for FWSTS.ILUP, raise HOST_COMM ILUP+READY, then wait
    /// for FWSTS.ISHTP_READY.
    fn hw_ready(&mut self) -> Result<(), IshError> {
        let deadline = self.deadline_from_now(self.fw_ready_timeout_ms);
        while self.bus.read32(REG_FWSTS) & ILUP_BIT == 0 {
            if narf_time::now_cycles() >= deadline {
                return Err(IshError::FirmwareNotReady);
            }
            narf_scheduler::sleep_pumps::run();
            core::hint::spin_loop();
        }
        // Linux toggles READY first if it was already set (a warm
        // reboot leaves it raised); then raises ILUP + READY.
        let mut host_comm = self.bus.read32(REG_HOST_COMM);
        if host_comm & HOST_READY_BIT != 0 {
            host_comm &= !HOST_READY_BIT;
            self.bus.write32(REG_HOST_COMM, host_comm);
        }
        host_comm |= ILUP_BIT | HOST_READY_BIT;
        self.bus.write32(REG_HOST_COMM, host_comm);

        let deadline = self.deadline_from_now(self.fw_ready_timeout_ms);
        while self.bus.read32(REG_FWSTS) & ISHTP_READY_BIT == 0 {
            if narf_time::now_cycles() >= deadline {
                return Err(IshError::FirmwareNotReady);
            }
            narf_scheduler::sleep_pumps::run();
            core::hint::spin_loop();
        }
        Ok(())
    }

    /// Full bring-up: hardware ready → HBM start → enumerate →
    /// HID client connect + device/descriptor fetch → system-state
    /// connect + subscribe (best-effort). Safe to call again
    /// after `session_dead` (the pump's recovery path); state is
    /// reset first either way.
    pub fn bring_up(&mut self) -> Result<(), IshError> {
        self.mark_session_dead();
        self.session_dead = false;
        self.hbm_result = None;
        self.hid_result = None;

        self.hw_ready()?;
        let session = self.bring_up_session();
        if let Err(e) = session {
            // Best-effort HOST_STOP so the firmware doesn't keep a
            // half-open session; leave the session marked dead so
            // the pump retries recovery instead of going quiet.
            let _ = self.send_ishtp(0, 0, &[hbm::HOST_STOP_REQ, 0, 0, 0]);
            self.session_dead = true;
            return Err(e);
        }
        session
    }

    fn bring_up_session(&mut self) -> Result<(), IshError> {
        self.hbm_start()?;

        // Find the HID client by GUID.
        let clients = self.enumerate_clients()?;
        let (hid_addr, hid_props) = clients
            .into_iter()
            .find(|(_, p)| p.protocol_name == HID_CLIENT_GUID)
            .ok_or(IshError::ClientNotFound)?;
        if hid_props.dma_hdr_len & 0x80 != 0 {
            return Err(IshError::DmaOnlyClient);
        }
        self.hid_fw_addr = Some(hid_addr);
        self.hid_props = Some(hid_props);

        self.hid_conn = ConnState::Connecting;
        self.connect_client(hid_addr, HOST_ADDR_HID)?;
        self.hid_conn = ConnState::Up;
        self.hid_bring_up()?;

        // System-state client: fixed address, no properties
        // query. Failure here only costs suspend notification —
        // log it and continue (the sensors themselves work).
        self.sys_conn = ConnState::Connecting;
        match self.connect_client(SYSSTATE_CLIENT_ADDR, HOST_ADDR_SYSSTATE) {
            Ok(()) => {
                self.sys_conn = ConnState::Up;
                if let Err(e) = self.sysstate_subscribe() {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  intel-ish: system-state subscribe failed: {e:?}"
                    );
                }
            }
            Err(e) => {
                self.sys_conn = ConnState::Down;
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-ish: system-state client unavailable: {e:?} \
                     (suspend notification disabled)"
                );
            }
        }
        Ok(())
    }

    // -- HID client ---------------------------------------------------

    /// Route one HID-client message: a response completes the
    /// outstanding request; a publish is decoded and pushed.
    fn dispatch_hid(&mut self, payload: &[u8], now_ns: u64) {
        if payload.len() < HOSTIF_HDR_LEN {
            return;
        }
        let cmd = payload[0];
        let device_id = payload[1];
        let status = payload[2];
        let size = u16::from_le_bytes([payload[4], payload[5]]) as usize;
        let body_end = (HOSTIF_HDR_LEN + size).min(payload.len());
        let body = &payload[HOSTIF_HDR_LEN..body_end];
        if cmd & hostif::RESP_BIT != 0 {
            if (cmd & hostif::CMD_MASK) == self.hid_wait_cmd {
                self.hid_result = Some(HidResult {
                    cmd: cmd & hostif::CMD_MASK,
                    status,
                    payload: body.to_vec(),
                });
            }
            return;
        }
        match cmd {
            hostif::PUBLISH_INPUT_REPORT => {
                self.handle_publish(device_id, body, now_ns);
            }
            hostif::PUBLISH_INPUT_REPORT_LIST => {
                self.handle_publish_list(body, now_ns);
            }
            hostif::DM_ADD_DEVICE => {
                // Hot-added device: the pump re-runs enumeration
                // by rebuilding the session's device set lazily;
                // until then the device simply isn't presented.
                // (In practice ISH HID sets are static per boot.)
                self.hid_ready = false;
            }
            _ => {}
        }
    }

    /// Decode one published input report for `device_id` and
    /// publish the event through the shared publication path
    /// (`hid_sensor_pub` — sysfs/IIO surface + legacy sensor ring).
    fn handle_publish(&mut self, device_id: u8, report: &[u8], now_ns: u64) {
        let Some((kind, ev)) = self.decode_for_device(device_id, report, now_ns) else {
            return;
        };
        crate::hid_sensor_pub::publish(
            crate::hid_sensor_pub::SensorSource::IntelIsh,
            device_id as u32,
            kind,
            ev,
        );
    }

    /// Decode an aggregated publish list: {total_size u16,
    /// count u8, flags u8}, then per-report {size u16, hostif
    /// header, payload} records.
    fn handle_publish_list(&mut self, payload: &[u8], now_ns: u64) {
        if payload.len() < 4 {
            return;
        }
        let count = payload[2] as usize;
        let mut pos = 4usize;
        for _ in 0..count {
            if pos + 2 + HOSTIF_HDR_LEN > payload.len() {
                return;
            }
            let rec_size = u16::from_le_bytes([payload[pos], payload[pos + 1]]) as usize;
            if rec_size < HOSTIF_HDR_LEN || pos + 2 + rec_size > payload.len() {
                return;
            }
            let rec = &payload[pos + 2..pos + 2 + rec_size];
            let device_id = rec[1];
            let size = u16::from_le_bytes([rec[4], rec[5]]) as usize;
            let body_end = (HOSTIF_HDR_LEN + size).min(rec.len());
            self.handle_publish(device_id, &rec[HOSTIF_HDR_LEN..body_end], now_ns);
            pos += 2 + rec_size;
        }
    }

    /// Match a report to a profile on the named device and
    /// decode + rescale it. Returns the matched profile's kind
    /// alongside the event so publishers can attribute the reading.
    fn decode_for_device(
        &self,
        device_id: u8,
        report: &[u8],
        now_ns: u64,
    ) -> Option<(HidSensorKind, SensorEvent)> {
        if report.is_empty() {
            return None;
        }
        let dev = self
            .devices
            .iter()
            .find(|d| d.info.dev_id as u8 == device_id)?;
        let slot = dev
            .profiles
            .iter()
            .find(|s| s.profile.input_report_id == report[0])?;
        let ev = hid_sensor::decode_report(&slot.profile, report, now_ns).ok()?;
        Some((
            slot.profile.kind,
            hid_sensor::rescale_event(ev, slot.unit_exp),
        ))
    }

    /// Send a HID request and wait (bounded) for its response.
    /// Requests are serialised by construction — every caller
    /// waits for its own response before returning.
    fn hid_request(&mut self, cmd: u8, device_id: u8, extra: &[u8]) -> Result<Vec<u8>, IshError> {
        if self.hid_conn != ConnState::Up {
            return Err(IshError::NotStarted);
        }
        let fw_addr = self.hid_fw_addr.ok_or(IshError::NotStarted)?;
        let mut msg = Vec::with_capacity(HOSTIF_HDR_LEN + extra.len());
        msg.push(cmd);
        msg.push(device_id);
        msg.push(0); // status
        msg.push(0); // flags
        msg.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        msg.extend_from_slice(extra);
        self.hid_result = None;
        self.hid_wait_cmd = cmd;
        let sent = self.send_ishtp(fw_addr, HOST_ADDR_HID, &msg);
        if let Err(e) = sent {
            self.hid_wait_cmd = 0;
            return Err(e);
        }
        let deadline = self.deadline_from_now(self.response_timeout_ms);
        loop {
            if let Some(res) = self.hid_result.take() {
                self.hid_wait_cmd = 0;
                if res.cmd != cmd {
                    return Err(IshError::BadPayload);
                }
                if res.status != 0 {
                    return Err(IshError::HidStatus(res.status));
                }
                return Ok(res.payload);
            }
            if self.session_dead {
                self.hid_wait_cmd = 0;
                return Err(IshError::NotStarted);
            }
            self.wait_or_timeout(deadline)?;
        }
    }

    /// HID device enumeration + per-device descriptor fetch +
    /// profile construction. A device whose descriptors fail or
    /// yield no sensor profiles is logged and skipped — one bad
    /// device must not dark the hub.
    fn hid_bring_up(&mut self) -> Result<(), IshError> {
        let payload = self.hid_request(hostif::DM_ENUM_DEVICES, 0, &[])?;
        let infos = parse_enum_devices(&payload);
        self.devices.clear();
        for info in infos.into_iter().take(MAX_HID_DEVICES) {
            let dev_id = info.dev_id as u8;
            match self.fetch_device(info, dev_id) {
                Ok(dev) => {
                    if dev.profiles.is_empty() {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  intel-ish: HID device {} (vid {:04x} pid {:04x}) has no \
                             sensor collections; not presented",
                            info.dev_id,
                            info.vid,
                            info.pid
                        );
                    } else {
                        // Publish every sensor collection on this
                        // device through the shared surface
                        // (idempotent across session rebuilds).
                        for slot in &dev.profiles {
                            crate::hid_sensor_pub::register_sensor(
                                crate::hid_sensor_pub::SensorSource::IntelIsh,
                                dev_id as u32,
                                slot.profile.kind,
                            );
                        }
                        self.devices.push(dev);
                    }
                }
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  intel-ish: HID device {} descriptor fetch failed: {e:?}; skipped",
                        info.dev_id
                    );
                }
            }
        }
        self.hid_ready = true;
        Ok(())
    }

    fn fetch_device(&mut self, info: HidDeviceInfo, dev_id: u8) -> Result<IshHidDevice, IshError> {
        let hid_desc_bytes = self.hid_request(hostif::GET_HID_DESCRIPTOR, dev_id, &[])?;
        let hid_descriptor = parse_hid_descriptor(&hid_desc_bytes);
        let report_descriptor = self.hid_request(hostif::GET_REPORT_DESCRIPTOR, dev_id, &[])?;
        let rd =
            narf_hid::descriptor::parse(&report_descriptor).map_err(|_| IshError::BadPayload)?;
        let mut profiles = Vec::new();
        for profile in hid_sensor::enumerate_sensors(&rd) {
            if profiles.len() >= MAX_PROFILES_PER_DEVICE {
                break;
            }
            let unit_exp = profile.fields.first().map(|f| f.unit_exp).unwrap_or(0);
            profiles.push(ProfileSlot { profile, unit_exp });
        }
        Ok(IshHidDevice {
            info,
            hid_descriptor,
            report_descriptor,
            profiles,
        })
    }

    /// Poll one device's current input report for the profile
    /// with `report_id` (GET_INPUT_REPORT) and return the
    /// decoded, rescaled event. The response is consumed here,
    /// not published — callers wanting ring publication can push
    /// the returned event with `hid_sensor::push_sensor_event`.
    pub fn get_input_report(
        &mut self,
        device_index: usize,
        report_id: u8,
        now_ns: u64,
    ) -> Result<SensorEvent, IshError> {
        let dev_id = self
            .devices
            .get(device_index)
            .ok_or(IshError::NoSuchDevice)?
            .info
            .dev_id as u8;
        let payload = self.hid_request(hostif::GET_INPUT_REPORT, dev_id, &[report_id])?;
        self.decode_for_device(dev_id, &payload, now_ns)
            .map(|(_, ev)| ev)
            .ok_or(IshError::BadPayload)
    }

    /// Send a feature report (payload *including* the report-ID
    /// prefix byte) to a device and await the firmware's ack.
    pub fn set_feature_report(
        &mut self,
        device_index: usize,
        report: &[u8],
    ) -> Result<(), IshError> {
        let dev_id = self
            .devices
            .get(device_index)
            .ok_or(IshError::NoSuchDevice)?
            .info
            .dev_id as u8;
        self.hid_request(hostif::SET_FEATURE_REPORT, dev_id, report)?;
        Ok(())
    }

    /// Programme a profile's REPORT_INTERVAL property (ms)
    /// through the standard feature-report path — the in-kernel
    /// period control, mirroring the SFH transport's `set_period`.
    pub fn set_report_interval(
        &mut self,
        device_index: usize,
        profile_index: usize,
        interval_ms: u32,
    ) -> Result<(), IshError> {
        let (dev_id, report) = {
            let dev = self
                .devices
                .get(device_index)
                .ok_or(IshError::NoSuchDevice)?;
            let slot = dev
                .profiles
                .get(profile_index)
                .ok_or(IshError::NoSuchDevice)?;
            let mut body = [0u8; 16];
            let n =
                hid_sensor::build_interval_feature_report(&slot.profile, interval_ms, &mut body)
                    .map_err(|_| IshError::BadPayload)?;
            let mut report = Vec::with_capacity(1 + n);
            report.push(slot.profile.feature_report_id);
            report.extend_from_slice(&body[..n]);
            (dev.info.dev_id as u8, report)
        };
        self.hid_request(hostif::SET_FEATURE_REPORT, dev_id, &report)?;
        Ok(())
    }

    // -- system-state client ------------------------------------------

    /// Subscribe to suspend + connected-standby notifications.
    fn sysstate_subscribe(&mut self) -> Result<(), IshError> {
        let mut msg = [0u8; 8];
        msg[0..4].copy_from_slice(&sysstate_cmd::SUBSCRIBE.to_le_bytes());
        msg[4..8].copy_from_slice(&(STATE_SUSPEND | STATE_CONNECTED_STANDBY).to_le_bytes());
        self.send_ishtp(SYSSTATE_CLIENT_ADDR, HOST_ADDR_SYSSTATE, &msg)
    }

    /// Route one system-state message: a STATE_CHANGE_REQ with
    /// cmd_status set acknowledges our outstanding request.
    fn dispatch_sysstate(&mut self, payload: &[u8]) {
        if payload.len() < 8 {
            return;
        }
        let cmd = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let cmd_status = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if cmd == sysstate_cmd::STATE_CHANGE_REQ && cmd_status != 0 {
            self.sys_acked = true;
        }
    }

    /// Notify the firmware of a system-state change (suspend if
    /// `requested` carries STATE_SUSPEND, resume when 0) and wait
    /// briefly for the acknowledgement.
    fn sysstate_notify(&mut self, requested: u32) -> Result<(), IshError> {
        if self.sys_conn != ConnState::Up {
            return Err(IshError::NotStarted);
        }
        // Layout: hdr {cmd, cmd_status}, requested_states,
        // states_status. cmd_status and states_status stay 0 in
        // a request; the ack echoes the command with cmd_status
        // set.
        let mut msg = [0u8; 16];
        msg[0..4].copy_from_slice(&sysstate_cmd::STATE_CHANGE_REQ.to_le_bytes());
        msg[8..12].copy_from_slice(&requested.to_le_bytes());
        self.sys_acked = false;
        self.sys_wait = Some(requested);
        self.send_ishtp(SYSSTATE_CLIENT_ADDR, HOST_ADDR_SYSSTATE, &msg)?;
        let deadline = self.deadline_from_now(SYSSTATE_ACK_TIMEOUT_MS);
        loop {
            if self.sys_acked {
                self.sys_wait = None;
                return Ok(());
            }
            if self.session_dead {
                self.sys_wait = None;
                return Err(IshError::NotStarted);
            }
            self.wait_or_timeout(deadline)?;
        }
    }

    // -- power ---------------------------------------------------------

    /// Suspend: notify the hub firmware (it is a wake source and
    /// keeps sensing in connected standby). Best-effort by
    /// design — see the module header.
    pub fn suspend(&mut self) -> Result<(), IshError> {
        if self.sys_conn == ConnState::Up {
            self.sysstate_notify(STATE_SUSPEND)?;
        }
        Ok(())
    }

    /// Resume: notify the firmware the system is back; if the
    /// session died while asleep, rebuild it.
    pub fn resume(&mut self) -> Result<(), IshError> {
        if self.session_dead {
            return self.bring_up();
        }
        if self.sys_conn == ConnState::Up {
            self.sysstate_notify(0)?;
        }
        Ok(())
    }
}

// ── Production glue ──────────────────────────────────────────────

/// The bound hub (one ISH function per machine).
static HUB: IrqSafeSpinLock<Option<IshHub<MmioBus>>> = IrqSafeSpinLock::new(None);

/// Whether an ISH hub was probed and brought up.
pub fn is_probed() -> bool {
    HUB.lock().as_ref().map(|h| h.is_up()).unwrap_or(false)
}

/// device_pm suspend hook: notify the hub firmware so it can
/// gate its sensors and arm wake sources. Always `Ok` — the
/// notification is best-effort (see `IshHub::suspend`): a wedged
/// or absent hub must never veto system sleep. (A blanket Busy
/// here is what #1028 was filed against; this handler answers
/// from actual state, and its only failure mode is having
/// nothing to notify.)
fn pm_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if let Some(hub) = HUB.lock().as_mut() {
        if hub.is_up() {
            if let Err(e) = hub.suspend() {
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-ish: suspend notify failed: {e:?} (continuing)"
                );
            }
        }
    }
    Ok(())
}

/// device_pm resume hook: notify the firmware, or rebuild the
/// session if the hub reset while the system slept.
fn pm_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if let Some(hub) = HUB.lock().as_mut() {
        if let Err(e) = hub.resume() {
            let _ = writeln!(narf_console::Writer, "  intel-ish: resume failed: {e:?}");
        }
    }
    Ok(())
}

/// Report pump: drains the IPC doorbell at a 5 ms cadence (IRQ
/// routing for input-class devices is not wired yet — see the
/// module header) and rebuilds the session if the firmware
/// reset underneath us.
async fn pump_task() {
    let mut last_poll_ns: u64 = 0;
    loop {
        let now = narf_time::monotonic_ns();
        if now.saturating_sub(last_poll_ns) >= 5_000_000 {
            last_poll_ns = now;
            let mut guard = HUB.lock();
            if let Some(hub) = guard.as_mut() {
                if hub.session_dead() {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  intel-ish: firmware reset detected; rebuilding session"
                    );
                    if let Err(e) = hub.bring_up() {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  intel-ish: session rebuild failed: {e:?}"
                        );
                    }
                } else {
                    hub.service(now);
                }
            }
            drop(guard);
        }
        narf_scheduler::yield_now().await;
    }
}

/// PCI probe entry point.
///
/// # Safety
/// Exclusive BAR access held by the bus probe framework.
pub fn probe(
    device: narf_driver_runtime::BusDevice,
    cap: narf_driver_runtime::Cap<narf_driver_runtime::BusDeviceCap, narf_driver_runtime::Write>,
) -> Result<(), narf_bus::ProbeError> {
    if HUB.lock().is_some() {
        return Ok(()); // singleton: a second ISH function is not expected
    }
    if device.id.vendor != INTEL_VENDOR || !PCI_IDS.contains(&(device.id.vendor, device.id.device))
    {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }

    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: exclusive BAR ownership held by the bus probe contract.
    let regs = unsafe { narf_driver_runtime::map_bar(&device, BAR_IPC) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let bus = MmioBus::new(regs);
    if bus.len() < ISH_BAR_MIN_LEN {
        let _ = writeln!(
            narf_console::Writer,
            "  intel-ish: BAR0 too small ({} bytes, need {ISH_BAR_MIN_LEN}); not an ISH window",
            bus.len()
        );
        return Err(narf_bus::ProbeError::BadDevice);
    }

    let bound_domain = narf_drivers::BoundKind::Input.default_domain();
    let mut hub = IshHub::new(bus);
    match hub.bring_up() {
        Ok(()) => {}
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  intel-ish: bring-up failed: {e:?}; ISH present but not bound"
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    }
    let n_devices = hub.device_count();
    let n_profiles: usize = hub.devices.iter().map(|d| d.profiles.len()).sum();
    hid_sensor::init_sensor_ring();
    *HUB.lock() = Some(hub);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-ish"),
        kind: narf_drivers::BoundKind::Input,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: bound_domain,
    });
    narf_power::device_pm::register_device_pm("intel-ish", pm_suspend, pm_resume);
    narf_scheduler::spawn(pump_task());

    let _ = writeln!(
        narf_console::Writer,
        "  intel-ish: probed (0x{:04X}:0x{:04X}), {n_devices} HID device(s), \
         {n_profiles} sensor profile(s) streaming",
        device.id.vendor,
        device.id.device
    );
    Ok(())
}

/// Register the ISH PCI matches with the bus. Called from the
/// input crate's `register_initcalls` (composition in
/// `frame/src/bare_main.rs` calls that at Stage::Device).
pub fn register_initcalls() {
    for &(vendor, device) in PCI_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "intel-ish",
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}

// ── Tests ────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // -- Fake firmware -------------------------------------------
    //
    // The fake models the ISH firmware side of the conversation,
    // from the protocol contract — not from the driver's wishes:
    // it owns the IPC register file, consumes doorbell fragments
    // into an ISHTP stream, answers HBM + HID-client + system-
    // state messages the way firmware does, enforces flow-control
    // credits in both directions, and stages outbound fragments
    // into the ISH2HOST window one doorbell cycle at a time.

    const REG_WORDS: usize = 0x100; // 0x400 bytes of registers

    /// Firmware client addresses in the fake hub.
    const FW_HID_ADDR: u8 = 5;
    const FW_SYS_ADDR: u8 = SYSSTATE_CLIENT_ADDR;

    #[derive(Debug)]
    struct FakeFw {
        regs: Vec<u32>,
        /// FWSTS word (ILUP set; ISHTP_READY gated by `ready`).
        ready: bool,
        // Personality flags for refusal/timeout fixtures.
        never_start: bool,
        refuse_hid_connect: bool,
        refuse_sys_connect: bool,
        withhold_fc: bool,
        // Host→firmware ISHTP stream assembly.
        in_stream: Vec<u8>,
        host2ish_fragments: u32,
        // Firmware→host complete ISHTP streams awaiting posting.
        out_queue: VecDeque<Vec<u8>>,
        out_frag_sent: usize,
        // Credits the host granted the firmware.
        fw_send_credit: u32,
        pending_publish: VecDeque<(u8, Vec<u8>)>,
        // Observed conversation.
        start_count: u32,
        connect_count: u32,
        subscribed_states: Option<u32>,
        state_requests: Vec<u32>,
        last_feature: Vec<(u8, Vec<u8>)>,
        last_mng_ack: Option<u32>,
        raw_client_msgs: Vec<Vec<u8>>,
        samples: Vec<(u8, Vec<u8>)>,
    }

    impl FakeFw {
        fn new() -> Self {
            Self {
                regs: vec![0; REG_WORDS],
                ready: true,
                never_start: false,
                refuse_hid_connect: false,
                refuse_sys_connect: false,
                withhold_fc: false,
                in_stream: Vec::new(),
                host2ish_fragments: 0,
                out_queue: VecDeque::new(),
                out_frag_sent: 0,
                fw_send_credit: 0,
                pending_publish: VecDeque::new(),
                start_count: 0,
                connect_count: 0,
                subscribed_states: None,
                state_requests: Vec::new(),
                last_feature: Vec::new(),
                last_mng_ack: None,
                raw_client_msgs: Vec::new(),
                samples: Vec::new(),
            }
        }

        fn reg(&self, off: u64) -> u32 {
            if off == REG_FWSTS {
                let mut v = ILUP_BIT | (15 << 12); // ILUP + sensor app running
                if self.ready {
                    v |= ISHTP_READY_BIT;
                }
                return v;
            }
            self.regs[(off / 4) as usize]
        }

        fn set_reg(&mut self, off: u64, val: u32) {
            self.regs[(off / 4) as usize] = val;
        }

        fn write_reg(&mut self, off: u64, val: u32) {
            match off {
                REG_HOST2ISH_DRBL => self.on_host_doorbell(val),
                REG_ISH2HOST_DRBL => {
                    self.set_reg(off, val);
                    if val == 0 {
                        // Host handed the window back: post the
                        // next outbound fragment, if any.
                        self.post_fragment();
                    }
                }
                _ => self.set_reg(off, val),
            }
        }

        /// Firmware side of a host doorbell write.
        fn on_host_doorbell(&mut self, val: u32) {
            if val & DRBL_BUSY == 0 {
                return;
            }
            match drbl_proto(val) {
                ipc_proto::ISHTP => {
                    let len = drbl_len(val);
                    self.host2ish_fragments += 1;
                    for i in 0..len {
                        let word = self.reg(REG_HOST2ISH_MSG + 4 * (i / 4) as u64);
                        self.in_stream.push(word.to_le_bytes()[i % 4]);
                    }
                    // Firmware consumed the fragment.
                    self.set_reg(REG_HOST2ISH_DRBL, 0);
                    self.process_stream();
                }
                ipc_proto::MNG => {
                    self.last_mng_ack = Some(drbl_mng_cmd(val));
                    self.set_reg(REG_HOST2ISH_DRBL, 0);
                }
                _ => {}
            }
        }

        /// Stage the next outbound fragment into the ISH2HOST
        /// window and ring the doorbell.
        fn post_fragment(&mut self) {
            if self.reg(REG_ISH2HOST_DRBL) & DRBL_BUSY != 0 {
                return;
            }
            // Copy the fragment out and settle the queue
            // bookkeeping first — staging the fragment writes
            // registers, which cannot overlap the queue borrow.
            let (frag, finished) = {
                let Some(front) = self.out_queue.front() else {
                    return;
                };
                let remaining = front.len() - self.out_frag_sent;
                let n = remaining.min(IPC_MSG_MAX_SIZE);
                let frag: Vec<u8> = front[self.out_frag_sent..self.out_frag_sent + n].to_vec();
                self.out_frag_sent += n;
                let finished = self.out_frag_sent >= front.len();
                if finished {
                    self.out_frag_sent = 0;
                }
                (frag, finished)
            };
            if finished {
                self.out_queue.pop_front();
            }
            let n = frag.len();
            for (i, word) in frag.chunks(4).enumerate() {
                let mut b = [0u8; 4];
                b[..word.len()].copy_from_slice(word);
                self.set_reg(REG_ISH2HOST_MSG + 4 * i as u64, u32::from_le_bytes(b));
            }
            self.set_reg(REG_ISH2HOST_DRBL, drbl_header_ishtp(n));
        }

        /// Queue a complete ISHTP message for the host and start
        /// posting it if the window is free.
        fn queue_msg(&mut self, fw_addr: u8, host_addr: u8, payload: &[u8]) {
            let mut stream = Vec::with_capacity(ISHTP_HDR_LEN + payload.len());
            stream.extend_from_slice(&ishtp_hdr(fw_addr, host_addr, payload.len()));
            stream.extend_from_slice(payload);
            self.out_queue.push_back(stream);
            self.post_fragment();
        }

        fn queue_hbm(&mut self, payload: &[u8]) {
            self.queue_msg(0, 0, payload);
        }

        fn queue_fc(&mut self, fw_addr: u8, host_addr: u8) {
            if !self.withhold_fc {
                self.queue_hbm(&[hbm::ISHTP_FLOW_CONTROL, fw_addr, host_addr, 0, 0, 0, 0, 0]);
            }
        }

        /// Process every complete message in the inbound stream.
        fn process_stream(&mut self) {
            loop {
                if self.in_stream.len() < ISHTP_HDR_LEN {
                    return;
                }
                let Some((fw_addr, host_addr, payload_len)) = ishtp_parse_hdr(&self.in_stream)
                else {
                    self.in_stream.clear();
                    return;
                };
                if self.in_stream.len() < ISHTP_HDR_LEN + payload_len {
                    return;
                }
                let payload: Vec<u8> =
                    self.in_stream[ISHTP_HDR_LEN..ISHTP_HDR_LEN + payload_len].to_vec();
                self.in_stream.drain(..ISHTP_HDR_LEN + payload_len);
                self.process_msg(fw_addr, host_addr, &payload);
            }
        }

        fn process_msg(&mut self, fw_addr: u8, host_addr: u8, payload: &[u8]) {
            match (fw_addr, host_addr) {
                (0, 0) => self.process_hbm(payload),
                (FW_HID_ADDR, HOST_ADDR_HID) => {
                    self.raw_client_msgs.push(payload.to_vec());
                    self.process_hid(payload);
                    // Consumed: grant the host its next send credit.
                    self.queue_fc(FW_HID_ADDR, HOST_ADDR_HID);
                }
                (FW_SYS_ADDR, HOST_ADDR_SYSSTATE) => {
                    self.process_sysstate(payload);
                    // Consumed: grant the host its next send credit.
                    self.queue_fc(FW_SYS_ADDR, HOST_ADDR_SYSSTATE);
                }
                _ => {}
            }
        }

        fn process_hbm(&mut self, payload: &[u8]) {
            if payload.is_empty() {
                return;
            }
            match payload[0] {
                hbm::HOST_START_REQ => {
                    self.start_count += 1;
                    if !self.never_start {
                        self.queue_hbm(&[hbm::HOST_START_REQ | hbm::RESP_BIT, 1, 0, 1]);
                    }
                }
                hbm::HOST_ENUM_REQ => {
                    let mut resp = vec![hbm::HOST_ENUM_REQ | hbm::RESP_BIT, 0, 0, 0];
                    let mut bitmap = [0u8; 32];
                    bitmap[(FW_HID_ADDR / 8) as usize] |= 1 << (FW_HID_ADDR % 8);
                    bitmap[(FW_SYS_ADDR / 8) as usize] |= 1 << (FW_SYS_ADDR % 8);
                    resp.extend_from_slice(&bitmap);
                    self.queue_hbm(&resp);
                }
                hbm::HOST_CLIENT_PROPERTIES_REQ => {
                    let addr = payload[1];
                    let mut resp =
                        vec![hbm::HOST_CLIENT_PROPERTIES_REQ | hbm::RESP_BIT, addr, 0, 0];
                    let guid = if addr == FW_HID_ADDR {
                        HID_CLIENT_GUID
                    } else {
                        [0u8; 16]
                    };
                    let mut props = Vec::with_capacity(CLIENT_PROPS_LEN);
                    props.extend_from_slice(&guid);
                    props.push(1); // protocol_version
                    props.push(1); // max_connections
                    props.push(0); // fixed_address
                    props.push(0); // single_recv_buf
                    props.extend_from_slice(&4096u32.to_le_bytes()); // max_msg_length
                    props.push(0); // dma_hdr_len (DMA off)
                    props.extend_from_slice(&[0, 0, 0]);
                    resp.extend_from_slice(&props);
                    self.queue_hbm(&resp);
                }
                hbm::CLIENT_CONNECT_REQ => {
                    let (fw, host) = (payload[1], payload[2]);
                    self.connect_count += 1;
                    let status = if (fw == FW_HID_ADDR && self.refuse_hid_connect)
                        || (fw == FW_SYS_ADDR && self.refuse_sys_connect)
                    {
                        1
                    } else {
                        CONNECT_SUCCESS
                    };
                    self.queue_hbm(&[hbm::CLIENT_CONNECT_REQ | hbm::RESP_BIT, fw, host, status]);
                    if status == CONNECT_SUCCESS {
                        self.queue_fc(fw, host);
                    }
                }
                hbm::CLIENT_DISCONNECT_REQ => {
                    self.queue_hbm(&[
                        hbm::CLIENT_DISCONNECT_REQ | hbm::RESP_BIT,
                        payload[1],
                        payload[2],
                        0,
                    ]);
                }
                hbm::ISHTP_FLOW_CONTROL => {
                    // Host granted the firmware a send credit.
                    self.fw_send_credit += 1;
                    self.flush_pending_publish();
                }
                _ => {}
            }
        }

        fn process_hid(&mut self, payload: &[u8]) {
            if payload.len() < HOSTIF_HDR_LEN {
                return;
            }
            let cmd = payload[0] & hostif::CMD_MASK;
            let device_id = payload[1];
            let extra = &payload[HOSTIF_HDR_LEN..];
            let respond = |fw: &mut Self, cmd: u8, device_id: u8, body: &[u8]| {
                let mut resp = Vec::with_capacity(HOSTIF_HDR_LEN + body.len());
                resp.push(cmd | hostif::RESP_BIT);
                resp.push(device_id);
                resp.push(0); // status ok
                resp.push(0); // flags
                resp.extend_from_slice(&(body.len() as u16).to_le_bytes());
                resp.extend_from_slice(body);
                fw.queue_msg(FW_HID_ADDR, HOST_ADDR_HID, &resp);
            };
            match cmd {
                hostif::DM_ENUM_DEVICES => {
                    let mut body = vec![3u8];
                    for info in fake_device_infos() {
                        body.extend_from_slice(&info.dev_id.to_le_bytes());
                        body.push(info.dev_class);
                        body.extend_from_slice(&info.pid.to_le_bytes());
                        body.extend_from_slice(&info.vid.to_le_bytes());
                    }
                    respond(self, cmd, 0, &body);
                }
                hostif::GET_HID_DESCRIPTOR => {
                    let body = fake_hid_descriptor(device_id);
                    respond(self, cmd, device_id, &body);
                }
                hostif::GET_REPORT_DESCRIPTOR => {
                    let body = fake_report_descriptor(device_id);
                    respond(self, cmd, device_id, &body);
                }
                hostif::GET_INPUT_REPORT => {
                    let body = self
                        .samples
                        .iter()
                        .find(|(d, _)| *d == device_id)
                        .map(|(_, s)| s.clone())
                        .unwrap_or_else(|| default_sample(device_id));
                    respond(self, cmd, device_id, &body);
                }
                hostif::SET_FEATURE_REPORT => {
                    self.last_feature.push((device_id, extra.to_vec()));
                    respond(self, cmd, device_id, &[]);
                }
                _ => {}
            }
        }

        fn process_sysstate(&mut self, payload: &[u8]) {
            if payload.len() < 8 {
                return;
            }
            let cmd = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            match cmd {
                sysstate_cmd::SUBSCRIBE => {
                    self.subscribed_states = Some(u32::from_le_bytes([
                        payload[4], payload[5], payload[6], payload[7],
                    ]));
                }
                sysstate_cmd::STATE_CHANGE_REQ => {
                    let requested =
                        u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
                    self.state_requests.push(requested);
                    let mut resp = vec![0u8; 16];
                    resp[0..4].copy_from_slice(&sysstate_cmd::STATE_CHANGE_REQ.to_le_bytes());
                    resp[4..8].copy_from_slice(&1u32.to_le_bytes()); // cmd_status: ack
                    resp[8..12].copy_from_slice(&requested.to_le_bytes());
                    resp[12..16].copy_from_slice(&requested.to_le_bytes());
                    self.queue_msg(FW_SYS_ADDR, HOST_ADDR_SYSSTATE, &resp);
                }
                _ => {}
            }
        }

        /// Publish an input report for `device_id`, respecting
        /// firmware send credits exactly as silicon must.
        fn publish(&mut self, device_id: u8, report: &[u8]) {
            if self.fw_send_credit > 0 {
                self.fw_send_credit -= 1;
                self.send_publish(device_id, report);
            } else {
                self.pending_publish.push_back((device_id, report.to_vec()));
            }
        }

        fn send_publish(&mut self, device_id: u8, report: &[u8]) {
            let mut msg = Vec::with_capacity(HOSTIF_HDR_LEN + report.len());
            msg.push(hostif::PUBLISH_INPUT_REPORT);
            msg.push(device_id);
            msg.push(0);
            msg.push(0);
            msg.extend_from_slice(&(report.len() as u16).to_le_bytes());
            msg.extend_from_slice(report);
            self.queue_msg(FW_HID_ADDR, HOST_ADDR_HID, &msg);
        }

        /// Publish an aggregated report list.
        fn publish_list(&mut self, items: &[(u8, Vec<u8>)]) {
            if self.fw_send_credit == 0 {
                return;
            }
            self.fw_send_credit -= 1;
            let mut body = Vec::new();
            let mut total = 4usize;
            for (_, r) in items {
                total += 2 + HOSTIF_HDR_LEN + r.len();
            }
            body.extend_from_slice(&(total as u16).to_le_bytes());
            body.push(items.len() as u8);
            body.push(0);
            for (dev, report) in items {
                let rec_size = (HOSTIF_HDR_LEN + report.len()) as u16;
                body.extend_from_slice(&rec_size.to_le_bytes());
                body.push(hostif::PUBLISH_INPUT_REPORT);
                body.push(*dev);
                body.push(0);
                body.push(0);
                body.extend_from_slice(&(report.len() as u16).to_le_bytes());
                body.extend_from_slice(report);
            }
            let mut msg = Vec::with_capacity(HOSTIF_HDR_LEN + body.len());
            msg.push(hostif::PUBLISH_INPUT_REPORT_LIST);
            msg.push(0);
            msg.push(0);
            msg.push(0);
            msg.extend_from_slice(&(body.len() as u16).to_le_bytes());
            msg.extend_from_slice(&body);
            self.queue_msg(FW_HID_ADDR, HOST_ADDR_HID, &msg);
        }

        fn flush_pending_publish(&mut self) {
            while self.fw_send_credit > 0 {
                let Some((dev, report)) = self.pending_publish.pop_front() else {
                    break;
                };
                self.fw_send_credit -= 1;
                self.send_publish(dev, &report);
            }
        }

        /// Firmware reset notification (management protocol).
        fn send_reset_notify(&mut self) {
            for (i, word) in [1u32, 0].iter().enumerate() {
                self.set_reg(REG_ISH2HOST_MSG + 4 * i as u64, *word);
            }
            self.set_reg(REG_ISH2HOST_DRBL, drbl_header_mng(mng_cmd::RESET_NOTIFY, 4));
        }

        fn set_sample(&mut self, device_id: u8, report: Vec<u8>) {
            self.samples.retain(|(d, _)| *d != device_id);
            self.samples.push((device_id, report));
        }
    }

    #[derive(Clone, Debug)]
    struct FakeBus {
        fw: Rc<RefCell<FakeFw>>,
    }

    impl IshBus for FakeBus {
        fn read32(&self, off: u64) -> u32 {
            self.fw.borrow().reg(off)
        }
        fn write32(&self, off: u64, val: u32) {
            self.fw.borrow_mut().write_reg(off, val);
        }
    }

    type SharedFw = Rc<RefCell<FakeFw>>;
    type TestHub = IshHub<FakeBus>;

    fn make_hub() -> (TestHub, SharedFw) {
        let fw = Rc::new(RefCell::new(FakeFw::new()));
        let mut hub = IshHub::new(FakeBus { fw: fw.clone() });
        hub.fw_ready_timeout_ms = 50;
        hub.response_timeout_ms = 50;
        hub.transfer_timeout_ms = 50;
        (hub, fw)
    }

    fn reset_ring() {
        hid_sensor::init_sensor_ring();
        hid_sensor::__reset_sensor_ring_for_test();
    }

    // -- Fake device set -------------------------------------------
    //
    // Device 1: motion hub — accelerometer (report ID 1) + gyro
    // (report ID 2) in one report descriptor, 32-bit fields with
    // unit exponent −3. Device 2: ambient light (report ID 1,
    // 16-bit field, exponent 0). Device 3: a boot keyboard — no
    // sensor collections, must be enumerated then skipped.

    fn fake_device_infos() -> [HidDeviceInfo; 3] {
        [
            HidDeviceInfo {
                dev_id: 1,
                dev_class: 0,
                pid: 0x0001,
                vid: 0x8086,
            },
            HidDeviceInfo {
                dev_id: 2,
                dev_class: 0,
                pid: 0x0002,
                vid: 0x8086,
            },
            HidDeviceInfo {
                dev_id: 3,
                dev_class: 0,
                pid: 0x0003,
                vid: 0x8086,
            },
        ]
    }

    fn fake_hid_descriptor(device_id: u8) -> Vec<u8> {
        let len = fake_report_descriptor(device_id).len() as u16;
        let mut d = vec![9, 0x21, 0x01, 0x01, 0, 1, 0x22];
        d.extend_from_slice(&len.to_le_bytes());
        d
    }

    /// One 3-axis sensor collection: state + event bytes, three
    /// 32-bit data fields with unit exponent −3, and a
    /// REPORT_INTERVAL feature on the same report ID.
    fn axis_collection(sensor_usage: u16, data: [u16; 3], report_id: u8) -> Vec<u8> {
        let mut d = Vec::new();
        let mut item = |tag: u8, btype: u8, data: &[u8]| {
            let bsize = match data.len() {
                0 => 0u8,
                1 => 1,
                2 => 2,
                4 => 3,
                _ => panic!("bad item size"),
            };
            d.push((tag << 4) | (btype << 2) | bsize);
            d.extend_from_slice(data);
        };
        item(0x0, 1, &[0x20, 0x00]); // Usage Page (Sensor)
        item(0x0, 2, &sensor_usage.to_le_bytes()); // Usage (sensor type)
        item(0xA, 0, &[0x01]); // Collection (Application)
        item(0x8, 1, &[report_id]); // Report ID
                                    // Sensor state (0x0201)
        item(0x0, 2, &[0x01, 0x02]);
        item(0x1, 1, &[0x00]);
        item(0x2, 1, &[0x06]);
        item(0x7, 1, &[8]);
        item(0x9, 1, &[1]);
        item(0x8, 0, &[0x02]);
        // Sensor event (0x0202)
        item(0x0, 2, &[0x02, 0x02]);
        item(0x1, 1, &[0x00]);
        item(0x2, 1, &[0x05]);
        item(0x7, 1, &[8]);
        item(0x9, 1, &[1]);
        item(0x8, 0, &[0x02]);
        // Data fields
        for usage in data {
            item(0x0, 2, &usage.to_le_bytes());
            item(0x1, 1, &[0x00, 0x00, 0x00, 0x80]); // Logical Min (i32)
            item(0x2, 1, &[0xFF, 0xFF, 0xFF, 0x7F]); // Logical Max
            item(0x7, 1, &[32]); // Report Size 32
            item(0x9, 1, &[1]); // Report Count 1
            item(0x5, 1, &[0x0D]); // Unit Exponent −3
            item(0x8, 0, &[0x02]); // Input
        }
        // Feature: report interval (0x030E), u32
        item(0x8, 1, &[report_id]);
        item(0x0, 2, &[0x0E, 0x03]);
        item(0x1, 1, &[0x00]);
        item(0x2, 1, &[0xFF, 0xFF, 0xFF, 0xFF]);
        item(0x7, 1, &[32]);
        item(0x9, 1, &[1]);
        item(0xB, 0, &[0x02]); // Feature
        item(0xC, 0, &[]); // End Collection
        d
    }

    fn fake_report_descriptor(device_id: u8) -> Vec<u8> {
        match device_id {
            1 => {
                let mut d = axis_collection(0x0073, [0x0453, 0x0454, 0x0455], 1);
                d.extend_from_slice(&axis_collection(0x0076, [0x0457, 0x0458, 0x0459], 2));
                d
            }
            2 => hid_sensor::build_test_descriptor_with_feature(0x0041, &[0x04D1], 1, 1),
            _ => vec![
                // Boot keyboard descriptor (no sensor collections).
                0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00,
                0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xC0,
            ],
        }
    }

    /// Accel report for device 1: [id 1][state][event][x][y][z]
    /// with 32-bit axes in milli-m/s² (descriptor exponent −3).
    fn accel_report(x: i32, y: i32, z: i32) -> Vec<u8> {
        let mut r = vec![1u8, 2, 4];
        r.extend_from_slice(&x.to_le_bytes());
        r.extend_from_slice(&y.to_le_bytes());
        r.extend_from_slice(&z.to_le_bytes());
        r
    }

    /// Gyro report for device 1 (report ID 2), axes in
    /// milli-deg/s (exponent −3 over a deg/s base unit).
    fn gyro_report(x: i32, y: i32, z: i32) -> Vec<u8> {
        let mut r = vec![2u8, 2, 4];
        r.extend_from_slice(&x.to_le_bytes());
        r.extend_from_slice(&y.to_le_bytes());
        r.extend_from_slice(&z.to_le_bytes());
        r
    }

    fn default_sample(device_id: u8) -> Vec<u8> {
        match device_id {
            1 => accel_report(0, 0, 9810),
            2 => vec![1, 0xE8, 0x03], // 1000 lux
            _ => vec![device_id],
        }
    }

    // -- wire codecs ------------------------------------------------

    fn smoke_ish_pci_id_table() -> TestResult {
        // Every claimed ID is Intel + in the table; the table
        // matches the Linux-claimed set in size (28).
        if PCI_IDS.len() != 28 {
            return TestResult::Fail("PCI ID table size drifted from the reference set");
        }
        for &(vid, _) in PCI_IDS {
            if vid != INTEL_VENDOR {
                return TestResult::Fail("non-Intel vendor in ISH table");
            }
        }
        // Spot-check the laptop fleet + the Mehlow exclusion.
        for did in [0x9D35u16, 0xA0FC, 0x51FC, 0x7E45, 0xA845] {
            if !PCI_IDS.contains(&(INTEL_VENDOR, did)) {
                return TestResult::Fail("expected ISH DID missing");
            }
        }
        if PCI_IDS.contains(&(INTEL_VENDOR, 0xA309)) || PCI_IDS.contains(&(INTEL_VENDOR, 0xA30A)) {
            return TestResult::Fail("Mehlow invalid IDs must not be claimed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_ish_pci_id_table);

    fn smoke_ish_wire_codecs() -> TestResult {
        // Doorbell header: len 0x55, ISHTP protocol, busy.
        let w = drbl_header_ishtp(0x55);
        if w & DRBL_BUSY == 0 || drbl_len(w) != 0x55 || drbl_proto(w) != ipc_proto::ISHTP {
            return TestResult::Fail("doorbell header round-trip wrong");
        }
        let m = drbl_header_mng(mng_cmd::RESET_NOTIFY, 4);
        if drbl_proto(m) != ipc_proto::MNG || drbl_mng_cmd(m) != mng_cmd::RESET_NOTIFY {
            return TestResult::Fail("mng doorbell header wrong");
        }
        // ISHTP header round-trip.
        let h = ishtp_hdr(5, 1, 300);
        match ishtp_parse_hdr(&h) {
            Some((5, 1, 300)) => {}
            _ => return TestResult::Fail("ishtp header round-trip wrong"),
        }
        // Client properties parse.
        let mut p = Vec::new();
        p.extend_from_slice(&HID_CLIENT_GUID);
        p.extend_from_slice(&[1, 1, 0, 0]);
        p.extend_from_slice(&4096u32.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]);
        match parse_client_properties(&p) {
            Some(props)
                if props.protocol_name == HID_CLIENT_GUID
                    && props.max_msg_length == 4096
                    && props.dma_hdr_len & 0x80 == 0 => {}
            _ => return TestResult::Fail("client properties parse wrong"),
        }
        // Enum-devices parse.
        let mut payload = vec![2u8];
        for info in [
            HidDeviceInfo {
                dev_id: 7,
                dev_class: 1,
                pid: 0x1111,
                vid: 0x8086,
            },
            HidDeviceInfo {
                dev_id: 9,
                dev_class: 0,
                pid: 0x2222,
                vid: 0x8086,
            },
        ] {
            payload.extend_from_slice(&info.dev_id.to_le_bytes());
            payload.push(info.dev_class);
            payload.extend_from_slice(&info.pid.to_le_bytes());
            payload.extend_from_slice(&info.vid.to_le_bytes());
        }
        let infos = parse_enum_devices(&payload);
        if infos.len() != 2 || infos[0].dev_id != 7 || infos[1].pid != 0x2222 {
            return TestResult::Fail("enum devices parse wrong");
        }
        // HID descriptor parse.
        let d = fake_hid_descriptor(2);
        match parse_hid_descriptor(&d) {
            Some(info) if info.report_desc_len as usize == fake_report_descriptor(2).len() => {}
            _ => return TestResult::Fail("hid descriptor parse wrong"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_ish_wire_codecs);

    // -- bring-up ----------------------------------------------------

    fn smoke_ish_firmware_not_ready() -> TestResult {
        let (mut hub, fw) = make_hub();
        fw.borrow_mut().ready = false;
        match hub.bring_up() {
            Err(IshError::FirmwareNotReady) => TestResult::Pass,
            Err(_) => TestResult::Fail("wrong error for cold firmware"),
            Ok(()) => TestResult::Fail("bring_up succeeded with firmware down"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_firmware_not_ready);

    fn smoke_ish_start_timeout() -> TestResult {
        let (mut hub, fw) = make_hub();
        fw.borrow_mut().never_start = true;
        match hub.bring_up() {
            Err(IshError::ResponseTimeout) => TestResult::Pass,
            _ => TestResult::Fail("expected ResponseTimeout when firmware never answers start"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_start_timeout);

    fn smoke_ish_connect_refused() -> TestResult {
        let (mut hub, fw) = make_hub();
        fw.borrow_mut().refuse_hid_connect = true;
        match hub.bring_up() {
            Err(IshError::ConnectRefused(1)) => TestResult::Pass,
            _ => TestResult::Fail("expected ConnectRefused(1)"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_connect_refused);

    fn smoke_ish_credit_timeout() -> TestResult {
        let (mut hub, fw) = make_hub();
        fw.borrow_mut().withhold_fc = true;
        match hub.bring_up() {
            Err(IshError::CreditTimeout) => TestResult::Pass,
            _ => TestResult::Fail("expected CreditTimeout when no credit is ever granted"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_credit_timeout);

    fn smoke_ish_bring_up_end_to_end() -> TestResult {
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed against the fake hub");
        }
        if !hub.is_up() {
            return TestResult::Fail("hub not up after bring_up");
        }
        if hub.fw_hbm_version() != Some((0, 1)) {
            return TestResult::Fail("fw hbm version not recorded");
        }
        // Two sensor devices bound; the keyboard was skipped.
        if hub.device_count() != 2 {
            return TestResult::Fail("expected 2 bound HID devices");
        }
        let dev0 = hub.device(0).expect("device 0");
        if dev0.info.dev_id != 1 || dev0.profiles.len() != 2 {
            return TestResult::Fail("motion hub profiles wrong (want accel + gyro)");
        }
        let kinds: Vec<HidSensorKind> = dev0.profiles.iter().map(|p| p.profile.kind).collect();
        if !kinds.contains(&HidSensorKind::Accelerometer3D)
            || !kinds.contains(&HidSensorKind::Gyrometer3D)
        {
            return TestResult::Fail("motion hub kinds wrong");
        }
        // The unit exponents rode in from the descriptors.
        if dev0.profiles.iter().any(|p| p.unit_exp != -3) {
            return TestResult::Fail("descriptor unit exponents not captured");
        }
        let dev1 = hub.device(1).expect("device 1");
        if dev1.info.dev_id != 2
            || dev1.profiles.len() != 1
            || dev1.profiles[0].profile.kind != HidSensorKind::AmbientLight
        {
            return TestResult::Fail("ALS device binding wrong");
        }
        // HID descriptor metadata was parsed, not just fetched.
        match dev0.hid_descriptor {
            Some(info) if info.report_desc_len as usize == dev0.report_descriptor.len() => {}
            _ => return TestResult::Fail("hid descriptor info mismatch"),
        }
        // System-state client subscribed for suspend + standby.
        let fw = fw.borrow();
        if fw.start_count != 1 {
            return TestResult::Fail("expected exactly one HBM start");
        }
        if fw.subscribed_states != Some(STATE_SUSPEND | STATE_CONNECTED_STANDBY) {
            return TestResult::Fail("system-state subscription wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_ish_bring_up_end_to_end);

    // -- report path ---------------------------------------------------

    fn smoke_ish_publish_accel_gyro() -> TestResult {
        reset_ring();
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        // Firmware publishes accel: z = 9810 milli-m/s² → 1000 milli-g.
        fw.borrow_mut().publish(1, &accel_report(0, 0, 9810));
        hub.service(123);
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Accel3d {
                x_milli_g: 0,
                y_milli_g: 0,
                z_milli_g: 1000,
                timestamp_ns: 123,
            }) => {}
            _ => return TestResult::Fail("bad accel event from publish"),
        }
        // Gyro: raw is milli-deg/s at exponent −3 → passes at milli scale.
        fw.borrow_mut().publish(1, &gyro_report(0, 0, 45_000));
        hub.service(124);
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Gyro3d {
                z_milli_dps: 45_000,
                timestamp_ns: 124,
                ..
            }) => {}
            _ => return TestResult::Fail("bad gyro event from publish"),
        }
        if hid_sensor::pop_sensor_event().is_some() {
            return TestResult::Fail("unexpected extra event");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_ish_publish_accel_gyro);

    // Publication round trip (issue #773): bring-up registers the
    // hub's sensors, firmware-published reports land on the
    // IIO sysfs surface with the decode layer's values. The accel
    // pin is byte-exact at both ends: report z = 9810 milli-m/s²
    // (0x2652 LE in `accel_report`) → 1000 milli-g published, and
    // 1000 × in_accel_scale (0.00980665) = 9.80665 m/s² ≈ the
    // 9.810 m/s² the firmware sent (integer rescale rounds at the
    // milli-g step, as the unit contract documents).
    fn smoke_ish_publication_round_trip() -> TestResult {
        reset_ring();
        crate::hid_sensor_pub::__reset_for_test();
        narf_filesystem::sysfs::__reset_for_test();
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        let infos = crate::hid_sensor_pub::sensors();
        let find = |kind: hid_sensor::HidSensorKind| {
            infos
                .iter()
                .find(|i| {
                    i.kind == kind && i.source == crate::hid_sensor_pub::SensorSource::IntelIsh
                })
                .map(|i| i.id)
        };
        let (Some(accel), Some(gyro), Some(als)) = (
            find(hid_sensor::HidSensorKind::Accelerometer3D),
            find(hid_sensor::HidSensorKind::Gyrometer3D),
            find(hid_sensor::HidSensorKind::AmbientLight),
        ) else {
            return TestResult::Fail("bring_up did not register all ISH sensors");
        };
        let show = |id: crate::hid_sensor_pub::SensorId, attr: &str| {
            narf_filesystem::sysfs::class_register("iio")
                .get_child(&alloc::format!("iio:device{}", id.0))
                .and_then(|k| k.attr_show(attr))
        };
        if show(accel, "name").as_deref() != Some("accel_3d\n")
            || show(accel, "in_accel_scale").as_deref() != Some("0.00980665\n")
        {
            return TestResult::Fail("accel IIO identity/scale wrong");
        }
        fw.borrow_mut().publish(1, &accel_report(0, 0, 9810));
        hub.service(123);
        if show(accel, "in_accel_z_raw").as_deref() != Some("1000\n") {
            return TestResult::Fail("accel reading not published to sysfs");
        }
        if crate::hid_sensor_pub::latest(accel)
            != Some(SensorEvent::Accel3d {
                x_milli_g: 0,
                y_milli_g: 0,
                z_milli_g: 1000,
                timestamp_ns: 123,
            })
        {
            return TestResult::Fail("accel reading not in the published store");
        }
        // Gyro on the SAME hub device must not disturb the accel
        // device (masking-defeating).
        fw.borrow_mut().publish(1, &gyro_report(0, 0, 45_000));
        hub.service(124);
        if show(gyro, "in_anglvel_z_raw").as_deref() != Some("45000\n") {
            return TestResult::Fail("gyro reading not published to sysfs");
        }
        if show(accel, "in_accel_z_raw").as_deref() != Some("1000\n") {
            return TestResult::Fail("gyro publish aliased onto the accel device");
        }
        // ALS lives on hub device 2; report [1, 0xE8, 0x03] = 1000 lux.
        fw.borrow_mut().publish(2, &[1, 0xE8, 0x03]);
        hub.service(125);
        if show(als, "in_illuminance_raw").as_deref() != Some("1000\n") {
            return TestResult::Fail("ALS reading not published to sysfs");
        }
        if show(accel, "in_illuminance_raw").is_some() {
            return TestResult::Fail("ALS channel leaked onto the accel device");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_ish_publication_round_trip);

    fn smoke_ish_publish_list() -> TestResult {
        reset_ring();
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        fw.borrow_mut()
            .publish_list(&[(1, accel_report(9810, 0, 0)), (2, vec![1, 0xE8, 0x03])]);
        hub.service(55);
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Accel3d {
                x_milli_g: 1000, ..
            }) => {}
            _ => return TestResult::Fail("list accel event wrong"),
        }
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Lux {
                lux: 1000,
                timestamp_ns: 55,
            }) => {}
            _ => return TestResult::Fail("list lux event wrong"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_ish_publish_list);

    fn smoke_ish_get_input_report() -> TestResult {
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        fw.borrow_mut().set_sample(1, accel_report(-9810, 0, 0));
        match hub.get_input_report(0, 1, 42) {
            Ok(SensorEvent::Accel3d {
                x_milli_g: -1000,
                y_milli_g: 0,
                z_milli_g: 0,
                timestamp_ns: 42,
            }) => TestResult::Pass,
            _ => TestResult::Fail("get_input_report decode wrong"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_get_input_report);

    fn smoke_ish_set_report_interval() -> TestResult {
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        if hub.set_report_interval(0, 0, 50).is_err() {
            return TestResult::Fail("set_report_interval failed");
        }
        let fw = fw.borrow();
        // Firmware saw: device 1, payload = [report-id 1][interval u32 LE].
        match fw.last_feature.as_slice() {
            [(1, payload)] => {
                if payload.len() != 5 || payload[0] != 1 {
                    return TestResult::Fail("feature payload shape wrong");
                }
                let v = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                if v != 50 {
                    return TestResult::Fail("feature interval value wrong");
                }
                TestResult::Pass
            }
            _ => TestResult::Fail("firmware never received the feature report"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_set_report_interval);

    // -- fragmentation ---------------------------------------------------

    fn smoke_ish_tx_fragmentation() -> TestResult {
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        fw.borrow_mut().host2ish_fragments = 0;
        fw.borrow_mut().raw_client_msgs.clear();
        // A 300-byte client payload: unknown hostif command, so
        // the fake just records it. 304 stream bytes fragment
        // into 128 + 128 + 48 across three doorbell transfers.
        let payload = vec![0xABu8; 300];
        let fw_addr = hub.hid_fw_addr.expect("hid addr");
        if hub.send_ishtp(fw_addr, HOST_ADDR_HID, &payload).is_err() {
            return TestResult::Fail("fragmented send failed");
        }
        let fw = fw.borrow();
        if fw.host2ish_fragments != 3 {
            return TestResult::Fail("expected 3 doorbell fragments");
        }
        match fw.raw_client_msgs.last() {
            Some(msg) if *msg == payload => TestResult::Pass,
            _ => TestResult::Fail("firmware reassembly mismatch"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_tx_fragmentation);

    fn smoke_ish_descriptor_fetch_was_fragmented() -> TestResult {
        // The motion hub's report descriptor exceeds one IPC
        // transfer (two 3-axis collections), so its fetch during
        // bring-up necessarily exercised RX reassembly.
        if fake_report_descriptor(1).len() + HOSTIF_HDR_LEN + ISHTP_HDR_LEN <= IPC_MSG_MAX_SIZE {
            return TestResult::Fail("fixture descriptor too small to test fragmentation");
        }
        let (mut hub, _fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        match hub.device(0) {
            Some(dev) if dev.report_descriptor == fake_report_descriptor(1) => TestResult::Pass,
            _ => TestResult::Fail("reassembled descriptor bytes mismatch"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_descriptor_fetch_was_fragmented);

    // -- power ---------------------------------------------------------

    fn smoke_ish_suspend_resume_notify() -> TestResult {
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        if hub.suspend().is_err() {
            return TestResult::Fail("suspend notify failed");
        }
        if fw.borrow().state_requests.last() != Some(&STATE_SUSPEND) {
            return TestResult::Fail("firmware did not see the suspend request");
        }
        if hub.resume().is_err() {
            return TestResult::Fail("resume notify failed");
        }
        if fw.borrow().state_requests.last() != Some(&0) {
            return TestResult::Fail("firmware did not see the resume request");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_ish_suspend_resume_notify);

    fn smoke_ish_suspend_without_sysstate() -> TestResult {
        let (mut hub, fw) = make_hub();
        fw.borrow_mut().refuse_sys_connect = true;
        // Bring-up still succeeds; suspend degrades to a no-op.
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up must survive a missing system-state client");
        }
        match hub.suspend() {
            Ok(()) => TestResult::Pass,
            Err(_) => TestResult::Fail("suspend must be a no-op without the state client"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_suspend_without_sysstate);

    // -- firmware reset recovery ----------------------------------------

    fn smoke_ish_fw_reset_recovery() -> TestResult {
        reset_ring();
        let (mut hub, fw) = make_hub();
        if hub.bring_up().is_err() {
            return TestResult::Fail("bring_up failed");
        }
        fw.borrow_mut().send_reset_notify();
        hub.service(7);
        if !hub.session_dead() {
            return TestResult::Fail("reset notify did not kill the session");
        }
        if fw.borrow().last_mng_ack != Some(mng_cmd::RESET_NOTIFY_ACK) {
            return TestResult::Fail("reset notify was not acked");
        }
        // The pump's recovery path: rebuild and re-bind.
        if hub.bring_up().is_err() {
            return TestResult::Fail("session rebuild failed");
        }
        if fw.borrow().start_count != 2 {
            return TestResult::Fail("expected a second HBM start after reset");
        }
        if hub.device_count() != 2 || !hub.is_up() {
            return TestResult::Fail("devices not re-bound after reset");
        }
        // And the rebuilt session carries reports again.
        fw.borrow_mut().publish(2, &[1, 0x2A, 0x00]);
        hub.service(8);
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Lux { lux: 42, .. }) => TestResult::Pass,
            _ => TestResult::Fail("no reports after reset recovery"),
        }
    }
    kernel_test_in!("drivers/input", smoke_ish_fw_reset_recovery);
}
