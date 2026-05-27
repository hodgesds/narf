//! HCI Event codes + decoders — Bluetooth Core Spec 5.3 Vol 4 Part E §7.7.

extern crate alloc;

use crate::hci::Event;

/// Common event codes (§7.7). Not exhaustive — extended as the
/// controller / data-plane work needs them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventCode {
    InquiryComplete = 0x01,
    InquiryResult = 0x02,
    ConnectionComplete = 0x03,
    DisconnectionComplete = 0x05,
    AuthenticationComplete = 0x06,
    EncryptionChange = 0x08,
    CommandComplete = 0x0E,
    CommandStatus = 0x0F,
    HardwareError = 0x10,
    NumberOfCompletedPackets = 0x13,
    SyncConnectionComplete = 0x2C,
    LeMeta = 0x3E,
    VendorSpecific = 0xFF,
}

impl EventCode {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::InquiryComplete),
            0x02 => Some(Self::InquiryResult),
            0x03 => Some(Self::ConnectionComplete),
            0x05 => Some(Self::DisconnectionComplete),
            0x06 => Some(Self::AuthenticationComplete),
            0x08 => Some(Self::EncryptionChange),
            0x0E => Some(Self::CommandComplete),
            0x0F => Some(Self::CommandStatus),
            0x10 => Some(Self::HardwareError),
            0x13 => Some(Self::NumberOfCompletedPackets),
            0x2C => Some(Self::SyncConnectionComplete),
            0x3E => Some(Self::LeMeta),
            0xFF => Some(Self::VendorSpecific),
            _ => None,
        }
    }
}

/// Decoded `HCI_Command_Complete` event payload (§7.7.14).
///
/// Layout:
/// ```text
///   0:    u8  Num_HCI_Command_Packets (controller's command credits)
///   1..3: u16 LE Command_Opcode
///   3..N: return parameters (opcode-specific)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandComplete<'a> {
    pub num_hci_command_packets: u8,
    pub opcode: u16,
    pub return_params: &'a [u8],
}

impl<'a> CommandComplete<'a> {
    pub fn parse(event: &'a Event) -> Option<Self> {
        if event.code != EventCode::CommandComplete as u8 {
            return None;
        }
        if event.params.len() < 3 {
            return None;
        }
        let p = &event.params;
        Some(Self {
            num_hci_command_packets: p[0],
            opcode: u16::from_le_bytes([p[1], p[2]]),
            return_params: &p[3..],
        })
    }

    /// `HCI_Status` is the first return parameter for almost every
    /// Command Complete; helper for the bring-up state machine which
    /// always wants it.
    pub fn status(&self) -> Option<u8> {
        self.return_params.first().copied()
    }
}

/// Decoded `HCI_Command_Status` event payload (§7.7.15).
///
/// Layout:
/// ```text
///   0:    u8  Status
///   1:    u8  Num_HCI_Command_Packets
///   2..4: u16 LE Command_Opcode
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandStatus {
    pub status: u8,
    pub num_hci_command_packets: u8,
    pub opcode: u16,
}

impl CommandStatus {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::CommandStatus as u8 {
            return None;
        }
        if event.params.len() < 4 {
            return None;
        }
        let p = &event.params;
        Some(Self {
            status: p[0],
            num_hci_command_packets: p[1],
            opcode: u16::from_le_bytes([p[2], p[3]]),
        })
    }
}

/// Decoded `HCI_Disconnection_Complete` event (§7.7.5).
///
/// Layout:
/// ```text
///   0:    u8  Status
///   1..3: u16 LE Connection_Handle (low 12 bits valid)
///   3:    u8  Reason
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DisconnectionComplete {
    pub status: u8,
    pub handle: u16,
    pub reason: u8,
}

impl DisconnectionComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::DisconnectionComplete as u8 {
            return None;
        }
        if event.params.len() < 4 {
            return None;
        }
        let p = &event.params;
        Some(Self {
            status: p[0],
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            reason: p[3],
        })
    }
}

/// Decoded `HCI_Number_Of_Completed_Packets` event (§7.7.19).
///
/// Layout:
/// ```text
///   0:    u8  Num_Handles
///   1..N: list of [Connection_Handle (2 LE), Num_Completed_Packets (2 LE)]
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumberOfCompletedPackets {
    /// Pairs of `(handle, completed_packet_count)`.
    pub entries: alloc::vec::Vec<(u16, u16)>,
}

impl NumberOfCompletedPackets {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::NumberOfCompletedPackets as u8 {
            return None;
        }
        if event.params.is_empty() {
            return None;
        }
        let n = event.params[0] as usize;
        if event.params.len() < 1 + n * 4 {
            return None;
        }
        let mut entries = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            let off = 1 + i * 4;
            let h = u16::from_le_bytes([event.params[off], event.params[off + 1]]) & 0x0FFF;
            let c = u16::from_le_bytes([event.params[off + 2], event.params[off + 3]]);
            entries.push((h, c));
        }
        Some(Self { entries })
    }
}

// ── LE Meta subevents (§7.7.65) ────────────────────────────────────
//
// Code 0x3E ("LE Meta") wraps every LE subevent. The first parameter
// byte is the subevent code; the rest are subevent-specific.

/// LE subevent codes (§7.7.65, table 7.4). Subset used here.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LeSubevent {
    ConnectionComplete = 0x01,
    AdvertisingReport = 0x02,
    ConnectionUpdateComplete = 0x03,
    EnhancedConnectionComplete = 0x0A,
}

impl LeSubevent {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ConnectionComplete),
            0x02 => Some(Self::AdvertisingReport),
            0x03 => Some(Self::ConnectionUpdateComplete),
            0x0A => Some(Self::EnhancedConnectionComplete),
            _ => None,
        }
    }
}

/// LE Connection Complete subevent (§7.7.65.1). Subevent 0x01.
///
/// Layout (after the 0x3E + subevent-code bytes):
/// ```text
///   0:     u8  Status
///   1..3:  u16 LE Connection_Handle
///   3:     u8  Role (0 = central / 1 = peripheral)
///   4:     u8  Peer_Address_Type (0 = public, 1 = random)
///   5..11: 6  Peer_Address (LE order)
///   11..13: u16 LE Connection_Interval (units of 1.25 ms)
///   13..15: u16 LE Peripheral_Latency
///   15..17: u16 LE Supervision_Timeout (units of 10 ms)
///   17:    u8  Central_Clock_Accuracy
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeConnectionComplete {
    pub status: u8,
    pub handle: u16,
    pub role: u8,
    pub peer_address_type: u8,
    pub peer_address: [u8; 6],
    pub connection_interval: u16,
    pub peripheral_latency: u16,
    pub supervision_timeout: u16,
    pub central_clock_accuracy: u8,
}

impl LeConnectionComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::ConnectionComplete as u8 {
            return None;
        }
        // 1-byte subevent + 18-byte payload = 19 bytes.
        if p.len() < 19 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[6..12]);
        Some(Self {
            status: p[1],
            handle: u16::from_le_bytes([p[2], p[3]]) & 0x0FFF,
            role: p[4],
            peer_address_type: p[5],
            peer_address: addr,
            connection_interval: u16::from_le_bytes([p[12], p[13]]),
            peripheral_latency: u16::from_le_bytes([p[14], p[15]]),
            supervision_timeout: u16::from_le_bytes([p[16], p[17]]),
            central_clock_accuracy: p[18],
        })
    }
}

/// One report inside an LE Advertising Report subevent (§7.7.65.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeAdvertisingReport {
    /// Event type (0 = ADV_IND, 1 = ADV_DIRECT_IND, 2 = ADV_SCAN_IND,
    /// 3 = ADV_NONCONN_IND, 4 = SCAN_RSP).
    pub event_type: u8,
    pub address_type: u8,
    pub address: [u8; 6],
    pub data: alloc::vec::Vec<u8>,
    pub rssi: i8,
}

/// Parse an LE Advertising Report subevent into the contained reports.
/// Returns `None` if the event isn't a well-formed LE Meta /
/// Advertising Report.
pub fn parse_le_advertising_reports(event: &Event) -> Option<alloc::vec::Vec<LeAdvertisingReport>> {
    if event.code != EventCode::LeMeta as u8 {
        return None;
    }
    let p = &event.params;
    if p.len() < 2 || p[0] != LeSubevent::AdvertisingReport as u8 {
        return None;
    }
    // Layout after subevent byte:
    //   1: Num_Reports
    //   ...for each report (parallel arrays in the spec, but in
    //   practice every Linux/BlueZ-compatible controller serialises
    //   one report at a time even with Num_Reports>1, so we walk
    //   per-report):
    //     Event_Type (1)
    //     Address_Type (1)
    //     Address (6)
    //     Length_Data (1)
    //     Data (Length_Data)
    //     RSSI (1, signed)
    let n = p[1] as usize;
    let mut out = alloc::vec::Vec::with_capacity(n);
    let mut i = 2;
    for _ in 0..n {
        if i + 9 > p.len() {
            return None;
        }
        let event_type = p[i];
        let address_type = p[i + 1];
        let mut address = [0u8; 6];
        address.copy_from_slice(&p[i + 2..i + 8]);
        let dlen = p[i + 8] as usize;
        i += 9;
        if i + dlen + 1 > p.len() {
            return None;
        }
        let data = p[i..i + dlen].to_vec();
        let rssi = p[i + dlen] as i8;
        i += dlen + 1;
        out.push(LeAdvertisingReport {
            event_type,
            address_type,
            address,
            data,
            rssi,
        });
    }
    Some(out)
}

// ── Stage 2: Classic BR/EDR event decoders ─────────────────────────
// Ref: net/bluetooth/hci_event.c — hci_inquiry_result_evt,
// hci_conn_complete_evt, hci_auth_complete_evt,
// hci_encrypt_change_evt, hci_sync_conn_complete_evt.

/// One device returned inside an `HCI_Inquiry_Result` event (§7.7.2).
/// Each entry is 14 bytes: BD_ADDR(6)+PSRM(1)+Rsvd(2)+CoD(3)+ClkOff(2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryResultEntry {
    pub bd_addr: [u8; 6],
    pub page_scan_repetition_mode: u8,
    pub class_of_device: [u8; 3],
    pub clock_offset: u16,
}

pub fn parse_inquiry_results(event: &Event) -> Option<alloc::vec::Vec<InquiryResultEntry>> {
    if event.code != EventCode::InquiryResult as u8 {
        return None;
    }
    let p = &event.params;
    if p.is_empty() { return None; }
    let n = p[0] as usize;
    if p.len() < 1 + n * 14 { return None; }
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let base = 1 + i * 14;
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[base..base + 6]);
        let psrm = p[base + 6];
        let mut cod = [0u8; 3];
        cod.copy_from_slice(&p[base + 9..base + 12]);
        let clk = u16::from_le_bytes([p[base + 12], p[base + 13]]);
        out.push(InquiryResultEntry { bd_addr: addr, page_scan_repetition_mode: psrm,
                                      class_of_device: cod, clock_offset: clk });
    }
    Some(out)
}

/// Decoded `HCI_Connection_Complete` event (§7.7.3) — classic BR/EDR.
/// Layout: Status(1) Handle_LE(2) BD_ADDR(6) Link_Type(1) Enc(1) = 11 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClassicConnectionComplete {
    pub status: u8,
    pub handle: u16,
    pub bd_addr: [u8; 6],
    pub link_type: u8,
    pub encryption_enabled: u8,
}
impl ClassicConnectionComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::ConnectionComplete as u8 { return None; }
        let p = &event.params;
        if p.len() < 11 { return None; }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[3..9]);
        Some(Self { status: p[0],
                    handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
                    bd_addr: addr, link_type: p[9], encryption_enabled: p[10] })
    }
}

/// Decoded `HCI_Authentication_Complete` event (§7.7.6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationComplete { pub status: u8, pub handle: u16 }
impl AuthenticationComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::AuthenticationComplete as u8 { return None; }
        let p = &event.params;
        if p.len() < 3 { return None; }
        Some(Self { status: p[0], handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF })
    }
}

/// Decoded `HCI_Encryption_Change` event v1 (§7.7.8).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EncryptionChangeV1 { pub status: u8, pub handle: u16, pub encryption_enabled: u8 }
impl EncryptionChangeV1 {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::EncryptionChange as u8 { return None; }
        let p = &event.params;
        if p.len() < 4 { return None; }
        Some(Self { status: p[0], handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
                    encryption_enabled: p[3] })
    }
}

/// Decoded `HCI_Synchronous_Connection_Complete` event (§7.7.35).
/// Layout: Status(1) Handle(2) BD_ADDR(6) Link_Type(1) TX_Interval(1)
///         ReTx_Window(1) Rx_Len(2) Tx_Len(2) Air_Mode(1) = 17 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SyncConnectionComplete {
    pub status: u8, pub handle: u16, pub bd_addr: [u8; 6],
    pub link_type: u8, pub transmission_interval: u8, pub retransmission_window: u8,
    pub rx_packet_length: u16, pub tx_packet_length: u16, pub air_mode: u8,
}
impl SyncConnectionComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::SyncConnectionComplete as u8 { return None; }
        let p = &event.params;
        if p.len() < 17 { return None; }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[3..9]);
        Some(Self { status: p[0], handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
                    bd_addr: addr, link_type: p[9], transmission_interval: p[10],
                    retransmission_window: p[11],
                    rx_packet_length: u16::from_le_bytes([p[12], p[13]]),
                    tx_packet_length: u16::from_le_bytes([p[14], p[15]]),
                    air_mode: p[16] })
    }
}
