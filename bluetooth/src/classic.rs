//! Classic BR/EDR command builders and helpers.
//!
//! Covers Inquiry, Create_Connection, Accept/Reject_Connection,
//! and the SSP (Secure Simple Pairing) IO-capability exchange needed
//! for classic bonding. SCO setup helpers also live here.
//!
//! ## Linux reference
//!
//! `net/bluetooth/hci_core.c` — `hci_inquiry`, `hci_connect_acl`,
//! `hci_conn_security`.
//! `net/bluetooth/hci_event.c` — `hci_io_capa_request_evt`,
//! `hci_user_confirm_request_evt`.
//! `drivers/bluetooth/btusb.c` — general USB HCI command flow.

use alloc::vec::Vec;

use crate::hci::Command;
use crate::opcode as op;

// ── Inquiry ────────────────────────────────────────────────────────

/// GIAC (General Inquiry Access Code) — the universal 24-bit LAP
/// 0x9E8B33.  Always safe for a host-initiated scan.
pub const GIAC: [u8; 3] = [0x33, 0x8B, 0x9E];

/// LIAC (Limited Inquiry Access Code) — 0x9E8B00.  Only used when
/// the device is in limited-discoverable mode.
pub const LIAC: [u8; 3] = [0x00, 0x8B, 0x9E];

/// Build an `HCI_Inquiry` command (§7.1.1).
///
/// - `lap`: 3-byte LAP (use [`GIAC`] or [`LIAC`]).
/// - `inquiry_length`: units of 1.28 s (1 = 1.28 s, max 0x30 = 61.44 s).
/// - `num_responses`: max devices to return (0 = unlimited).
pub fn build_inquiry(lap: [u8; 3], inquiry_length: u8, num_responses: u8) -> Command {
    Command::with_params(
        op::HCI_INQUIRY,
        &[lap[0], lap[1], lap[2], inquiry_length, num_responses],
    )
}

// ── Create Connection ──────────────────────────────────────────────

/// Default packet-type bitmap for `HCI_Create_Connection` (§7.1.5).
///
/// Enables DH1, DM1, DH3, DM3, DH5, DM5 (the six ACL packet types
/// a generic host wants). Expressed as the bitmask defined in Vol 2
/// Part B §6.19, Table 6.4.
pub const ACL_PACKET_TYPES_DEFAULT: u16 = 0xCC18;

/// Build an `HCI_Create_Connection` command (§7.1.5).
///
/// - `bd_addr`: remote device's 6-byte BD_ADDR (wire order, LSB first).
/// - `packet_type`: bitmask of ACL packet types; use [`ACL_PACKET_TYPES_DEFAULT`].
/// - `psrm`: Page_Scan_Repetition_Mode (from an Inquiry Result).
/// - `clock_offset`: 16-bit clock offset from an Inquiry Result.
/// - `allow_role_switch`: 1 = allow, 0 = prohibit.
pub fn build_create_connection(
    bd_addr: [u8; 6],
    packet_type: u16,
    psrm: u8,
    clock_offset: u16,
    allow_role_switch: u8,
) -> Command {
    let mut p = [0u8; 13];
    p[0..6].copy_from_slice(&bd_addr);
    p[6] = (packet_type & 0xFF) as u8;
    p[7] = (packet_type >> 8) as u8;
    p[8] = psrm;
    p[9] = 0; // Reserved (§7.1.5).
    p[10] = (clock_offset & 0xFF) as u8;
    p[11] = (clock_offset >> 8) as u8;
    p[12] = allow_role_switch;
    Command::with_params(op::HCI_CREATE_CONNECTION, &p)
}

/// Build an `HCI_Accept_Connection_Request` command (§7.1.8).
/// `role`: 0 = request to become central; 1 = remain peripheral.
pub fn build_accept_connection(bd_addr: [u8; 6], role: u8) -> Command {
    let mut p = [0u8; 7];
    p[0..6].copy_from_slice(&bd_addr);
    p[6] = role;
    Command::with_params(op::HCI_ACCEPT_CONNECTION_REQUEST, &p)
}

/// Build an `HCI_Reject_Connection_Request` command (§7.1.9).
pub fn build_reject_connection(bd_addr: [u8; 6], reason: u8) -> Command {
    let mut p = [0u8; 7];
    p[0..6].copy_from_slice(&bd_addr);
    p[6] = reason;
    Command::with_params(op::HCI_REJECT_CONNECTION_REQUEST, &p)
}

// ── SSP — Secure Simple Pairing (classic BR/EDR) ──────────────────

/// IO Capability values for SSP (§7.1.29, Vol 3 Part C §5.2.1).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClassicIoCap {
    DisplayOnly = 0x00,
    DisplayYesNo = 0x01,
    KeyboardOnly = 0x02,
    NoInputNoOutput = 0x03,
}

/// Authentication_Requirements values (§7.1.29, table 7.2).
/// Used in `HCI_IO_Capability_Request_Reply`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthRequirements {
    /// No bonding, no MITM.
    NoBondingNomitm = 0x00,
    /// No bonding, MITM required.
    NoBondingMitm = 0x01,
    /// Dedicated bonding, no MITM.
    DedicatedBondingNomitm = 0x02,
    /// Dedicated bonding, MITM.
    DedicatedBondingMitm = 0x03,
    /// General bonding, no MITM.
    GeneralBondingNomitm = 0x04,
    /// General bonding, MITM.
    GeneralBondingMitm = 0x05,
}

/// Build an `HCI_IO_Capability_Request_Reply` command (§7.1.29).
///
/// Issued in response to an `HCI_IO_Capability_Request` event when
/// the host wants to proceed with SSP (Secure Simple Pairing).
pub fn build_io_capability_reply(
    bd_addr: [u8; 6],
    io_cap: ClassicIoCap,
    oob_data_present: bool,
    auth_req: AuthRequirements,
) -> Command {
    let mut p = [0u8; 9];
    p[0..6].copy_from_slice(&bd_addr);
    p[6] = io_cap as u8;
    p[7] = if oob_data_present { 0x01 } else { 0x00 };
    p[8] = auth_req as u8;
    Command::with_params(op::HCI_IO_CAPABILITY_REQUEST_REPLY, &p)
}

/// Build an `HCI_User_Confirmation_Request_Reply` command (§7.1.30).
///
/// Sent when the user (or a "Just Works" policy) accepts the numeric
/// comparison / just-works confirmation.
pub fn build_user_confirmation_reply(bd_addr: [u8; 6]) -> Command {
    Command::with_params(op::HCI_USER_CONFIRMATION_REQUEST_REPLY, &bd_addr)
}

/// Build an `HCI_User_Confirmation_Request_Negative_Reply` (§7.1.31).
/// Sent when the user rejects the numeric comparison.
pub fn build_user_confirmation_negative_reply(bd_addr: [u8; 6]) -> Command {
    Command::with_params(op::HCI_USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY, &bd_addr)
}

// ── SCO / eSCO ────────────────────────────────────────────────────

/// Transmit / receive bandwidth for transparent eSCO (HFP narrow-band
/// 8 kHz, 16-bit PCM). Value is in bytes per second.
pub const SCO_BANDWIDTH_8KHZ: u32 = 8_000;
/// CVSD voice setting for HFP (Vol 3 Part B §4.3.2, vol2 part E §6.12).
/// 0x0060 = Linear PCM, 16-bit, 8 kHz.
pub const SCO_VOICE_SETTING_CVSD: u16 = 0x0060;

/// eSCO packet type bits for `HCI_Setup_Synchronous_Connection`.
/// 0x003F allows all SCO + eSCO packet types (EV3, EV4, EV5, 2-EV3,
/// 3-EV3, 2-EV5, 3-EV5). Mirrors Linux's `hci_setup_sync` defaults.
pub const ESCO_PACKET_TYPES_ALL: u16 = 0x003F;

/// Build an `HCI_Setup_Synchronous_Connection` command (§7.1.26).
///
/// Used to open a SCO/eSCO channel on an existing ACL `handle`.
///
/// `max_latency`: in ms. 7 ms is the minimum for narrow-band CVSD.
/// `retransmission_effort`: 0 = no effort, 1 = at least one attempt,
///   2 = minimise latency, 0xFF = don't care.
pub fn build_setup_synchronous_connection(
    handle: u16,
    transmit_bandwidth: u32,
    receive_bandwidth: u32,
    max_latency: u16,
    voice_setting: u16,
    retransmission_effort: u8,
    packet_type: u16,
) -> Command {
    let mut p = [0u8; 17];
    p[0] = (handle & 0xFF) as u8;
    p[1] = (handle >> 8) as u8;
    p[2] = (transmit_bandwidth & 0xFF) as u8;
    p[3] = ((transmit_bandwidth >> 8) & 0xFF) as u8;
    p[4] = ((transmit_bandwidth >> 16) & 0xFF) as u8;
    p[5] = ((transmit_bandwidth >> 24) & 0xFF) as u8;
    p[6] = (receive_bandwidth & 0xFF) as u8;
    p[7] = ((receive_bandwidth >> 8) & 0xFF) as u8;
    p[8] = ((receive_bandwidth >> 16) & 0xFF) as u8;
    p[9] = ((receive_bandwidth >> 24) & 0xFF) as u8;
    p[10] = (max_latency & 0xFF) as u8;
    p[11] = (max_latency >> 8) as u8;
    p[12] = (voice_setting & 0xFF) as u8;
    p[13] = (voice_setting >> 8) as u8;
    p[14] = retransmission_effort;
    p[15] = (packet_type & 0xFF) as u8;
    p[16] = (packet_type >> 8) as u8;
    Command::with_params(op::HCI_SETUP_SYNCHRONOUS_CONNECTION, &p)
}

/// Encode a USB bulk-IN ACL fragment into an `HciDispatch` payload.
/// The xHCI bulk-IN endpoint delivers raw HCI ACL packets without the
/// 0x02 indicator byte (the indicator is implicit in the endpoint
/// choice per Vol 4 Part B §2.2); we tag them here for `btusb`'s
/// event-dispatch path.
///
/// Returns the data unchanged — this is a thin wrapper to allow the
/// btusb dispatcher to call common decode helpers without touching
/// transport framing details.
pub fn acl_from_bulk_in(raw: &[u8]) -> &[u8] {
    raw
}

// ── Scan / host-configuration helpers ────────────────────────────

/// Build `HCI_Write_Simple_Pairing_Mode` to enable SSP (§7.3.59).
pub fn build_write_simple_pairing_mode(enable: bool) -> Command {
    Command::with_params(
        op::HCI_WRITE_SIMPLE_PAIRING_MODE,
        &[if enable { 0x01 } else { 0x00 }],
    )
}

/// Build `HCI_Write_Scan_Enable` (§7.3.18).
/// `mode`: 0 = off, 1 = inquiry, 2 = page, 3 = both.
pub fn build_write_scan_enable(mode: u8) -> Command {
    Command::with_params(op::HCI_WRITE_SCAN_ENABLE, &[mode])
}

/// Build `HCI_Write_Class_Of_Device` (§7.3.26).
pub fn build_write_class_of_device(cod: [u8; 3]) -> Command {
    Command::with_params(op::HCI_WRITE_CLASS_OF_DEVICE, &cod)
}

/// Build a `HCI_Write_Local_Name` command (§7.3.11).
/// The name is truncated / null-padded to 248 bytes as the spec requires.
pub fn build_write_local_name(name: &[u8]) -> Command {
    let mut p = [0u8; 248];
    let n = name.len().min(247); // leave room for NUL terminator.
    p[..n].copy_from_slice(&name[..n]);
    Command::with_params(op::HCI_WRITE_LOCAL_NAME, &p)
}

// ── Encoded inquiry command helpers ──────────────────────────────

/// Decode the parameters of a raw `HCI_Inquiry` command payload
/// (3 bytes of the 5-byte param block that follow the opcode byte in
/// an encoded Command packet). Used in tests to verify encoding.
///
/// Returns `(lap, inquiry_length, num_responses)` or `None`.
pub fn decode_inquiry_params(cmd: &crate::hci::Command) -> Option<([u8; 3], u8, u8)> {
    if cmd.opcode != op::HCI_INQUIRY {
        return None;
    }
    if cmd.params.len() < 5 {
        return None;
    }
    let lap = [cmd.params[0], cmd.params[1], cmd.params[2]];
    Some((lap, cmd.params[3], cmd.params[4]))
}

// ── Sync data packet helpers ──────────────────────────────────────

/// HCI Synchronous Data packet — used for SCO/eSCO audio frames.
///
/// Wire layout (Vol 4 Part E §5.4.3):
/// ```text
///   0..2: u16 LE handle (low 12) + flags (PS:2 RFU:2 in high 4)
///   2..4: u16 LE Data_Total_Length
///   4..N: data
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncData {
    pub handle: u16,
    /// Packet_Status_Flag bits[1:0] of the handle field high nibble.
    pub packet_status: u8,
    pub data: Vec<u8>,
}

impl SyncData {
    /// Encode to wire bytes (without the leading 0x03 indicator).
    pub fn encode(&self) -> Vec<u8> {
        let h = (self.handle & 0x0FFF) | (((self.packet_status & 0x3) as u16) << 12);
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push((h & 0xFF) as u8);
        out.push((h >> 8) as u8);
        let len = self.data.len() as u16;
        out.push((len & 0xFF) as u8);
        out.push((len >> 8) as u8);
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode from a buffer starting at the handle field (indicator
    /// already stripped).
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let h = u16::from_le_bytes([buf[0], buf[1]]);
        let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return None;
        }
        Some(Self {
            handle: h & 0x0FFF,
            packet_status: ((h >> 12) & 0x3) as u8,
            data: buf[4..4 + len].to_vec(),
        })
    }
}
