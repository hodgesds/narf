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
    ConnectionRequest = 0x04,
    DisconnectionComplete = 0x05,
    AuthenticationComplete = 0x06,
    RemoteNameRequestComplete = 0x07,
    EncryptionChange = 0x08,
    ChangeConnectionLinkKeyComplete = 0x09,
    ReadRemoteSupportedFeaturesComplete = 0x0B,
    ReadRemoteVersionInformationComplete = 0x0C,
    CommandComplete = 0x0E,
    CommandStatus = 0x0F,
    HardwareError = 0x10,
    RoleChange = 0x12,
    NumberOfCompletedPackets = 0x13,
    ModeChange = 0x14,
    LinkKeyRequest = 0x17,
    LinkKeyNotification = 0x18,
    MaxSlotsChange = 0x1B,
    ReadClockOffsetComplete = 0x1D,
    QosSetupComplete = 0x1F,
    InquiryResultWithRssi = 0x22,
    SyncConnectionComplete = 0x2C,
    ExtendedInquiryResult = 0x2F,
    EncryptionKeyRefreshComplete = 0x30,
    IoCapabilityRequest = 0x31,
    IoCapabilityResponse = 0x32,
    UserConfirmationRequest = 0x33,
    UserPasskeyRequest = 0x34,
    SimplePairingComplete = 0x36,
    LeMeta = 0x3E,
    VendorSpecific = 0xFF,
}

impl EventCode {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::InquiryComplete),
            0x02 => Some(Self::InquiryResult),
            0x03 => Some(Self::ConnectionComplete),
            0x04 => Some(Self::ConnectionRequest),
            0x05 => Some(Self::DisconnectionComplete),
            0x06 => Some(Self::AuthenticationComplete),
            0x07 => Some(Self::RemoteNameRequestComplete),
            0x08 => Some(Self::EncryptionChange),
            0x09 => Some(Self::ChangeConnectionLinkKeyComplete),
            0x0B => Some(Self::ReadRemoteSupportedFeaturesComplete),
            0x0C => Some(Self::ReadRemoteVersionInformationComplete),
            0x0E => Some(Self::CommandComplete),
            0x0F => Some(Self::CommandStatus),
            0x10 => Some(Self::HardwareError),
            0x12 => Some(Self::RoleChange),
            0x13 => Some(Self::NumberOfCompletedPackets),
            0x14 => Some(Self::ModeChange),
            0x17 => Some(Self::LinkKeyRequest),
            0x18 => Some(Self::LinkKeyNotification),
            0x1B => Some(Self::MaxSlotsChange),
            0x1D => Some(Self::ReadClockOffsetComplete),
            0x1F => Some(Self::QosSetupComplete),
            0x22 => Some(Self::InquiryResultWithRssi),
            0x2C => Some(Self::SyncConnectionComplete),
            0x2F => Some(Self::ExtendedInquiryResult),
            0x30 => Some(Self::EncryptionKeyRefreshComplete),
            0x31 => Some(Self::IoCapabilityRequest),
            0x32 => Some(Self::IoCapabilityResponse),
            0x33 => Some(Self::UserConfirmationRequest),
            0x34 => Some(Self::UserPasskeyRequest),
            0x36 => Some(Self::SimplePairingComplete),
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
    ReadRemoteFeaturesComplete = 0x04,
    LongTermKeyRequest = 0x05,
    RemoteConnectionParameterRequest = 0x06,
    DataLengthChange = 0x07,
    EnhancedConnectionComplete = 0x0A,
    DirectedAdvertisingReport = 0x0B,
    PhyUpdateComplete = 0x0C,
    ExtendedAdvertisingReport = 0x0D,
    /// LE Periodic Advertising Sync Established (§7.7.65.15).
    PeriodicAdvertisingSyncEstablished = 0x0E,
    /// LE Periodic Advertising Report (§7.7.65.14).
    PeriodicAdvertisingReport = 0x0F,
    /// LE Periodic Advertising Sync Lost (§7.7.65.16).
    PeriodicAdvertisingSyncLost = 0x10,
    /// LE Scan Timeout (§7.7.65.17).
    ScanTimeout = 0x11,
    /// LE Advertising Set Terminated (§7.7.65.18).
    AdvertisingSetTerminated = 0x12,
    /// LE Scan Request Received (§7.7.65.19).
    ScanRequestReceived = 0x13,
    ChannelSelectionAlgorithm = 0x14,
    /// LE Periodic Advertising Sync Transfer Received [v1]
    /// (§7.7.65.21 in Core 5.x; §7.7.65.24 in Core 6.1).
    PeriodicAdvertisingSyncTransferReceived = 0x18,
}

impl LeSubevent {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ConnectionComplete),
            0x02 => Some(Self::AdvertisingReport),
            0x03 => Some(Self::ConnectionUpdateComplete),
            0x04 => Some(Self::ReadRemoteFeaturesComplete),
            0x05 => Some(Self::LongTermKeyRequest),
            0x06 => Some(Self::RemoteConnectionParameterRequest),
            0x07 => Some(Self::DataLengthChange),
            0x0A => Some(Self::EnhancedConnectionComplete),
            0x0B => Some(Self::DirectedAdvertisingReport),
            0x0C => Some(Self::PhyUpdateComplete),
            0x0D => Some(Self::ExtendedAdvertisingReport),
            0x0E => Some(Self::PeriodicAdvertisingSyncEstablished),
            0x0F => Some(Self::PeriodicAdvertisingReport),
            0x10 => Some(Self::PeriodicAdvertisingSyncLost),
            0x11 => Some(Self::ScanTimeout),
            0x12 => Some(Self::AdvertisingSetTerminated),
            0x13 => Some(Self::ScanRequestReceived),
            0x14 => Some(Self::ChannelSelectionAlgorithm),
            0x18 => Some(Self::PeriodicAdvertisingSyncTransferReceived),
            _ => None,
        }
    }
}

/// LE Long Term Key Request subevent (§7.7.65.5). Subevent 0x05.
/// Layout (after the 0x3E + subevent-code bytes):
///   0..2:  u16 LE Connection_Handle
///   2..10: u64 LE Random_Number (Rand)
///   10..12: u16 LE Encryption_Diversifier (EDIV)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LeLongTermKeyRequest {
    pub handle: u16,
    pub random_number: u64,
    pub ediv: u16,
}

impl LeLongTermKeyRequest {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::LongTermKeyRequest as u8 {
            return None;
        }
        if p.len() < 1 + 12 {
            return None;
        }
        Some(Self {
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            random_number: u64::from_le_bytes([p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10]]),
            ediv: u16::from_le_bytes([p[11], p[12]]),
        })
    }
}

/// LE Data Length Change subevent (§7.7.65.7). Subevent 0x07.
/// Layout: Handle(2) MaxTxOctets(2) MaxTxTime(2) MaxRxOctets(2) MaxRxTime(2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LeDataLengthChange {
    pub handle: u16,
    pub max_tx_octets: u16,
    pub max_tx_time: u16,
    pub max_rx_octets: u16,
    pub max_rx_time: u16,
}

impl LeDataLengthChange {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::DataLengthChange as u8 {
            return None;
        }
        if p.len() < 1 + 10 {
            return None;
        }
        Some(Self {
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            max_tx_octets: u16::from_le_bytes([p[3], p[4]]),
            max_tx_time: u16::from_le_bytes([p[5], p[6]]),
            max_rx_octets: u16::from_le_bytes([p[7], p[8]]),
            max_rx_time: u16::from_le_bytes([p[9], p[10]]),
        })
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

/// LE Enhanced Connection Complete subevent (§7.7.65.10, v1).
/// Subevent 0x0A. Generated (instead of the legacy 0x01 subevent)
/// when a connection is created by HCI_LE_Extended_Create_Connection
/// (§7.8.66) — and, when unmasked, in place of the legacy event for
/// HCI_LE_Create_Connection too.
///
/// Layout (after the 0x3E + subevent-code bytes):
/// ```text
///   0:     u8  Status
///   1..3:  u16 LE Connection_Handle
///   3:     u8  Role (0 = central / 1 = peripheral)
///   4:     u8  Peer_Address_Type (0 = public, 1 = random,
///              2 = public identity, 3 = random static identity)
///   5..11: 6  Peer_Address (LE order)
///   11..17: 6 Local_Resolvable_Private_Address
///   17..23: 6 Peer_Resolvable_Private_Address
///   23..25: u16 LE Connection_Interval (units of 1.25 ms)
///   25..27: u16 LE Peripheral_Latency
///   27..29: u16 LE Supervision_Timeout (units of 10 ms)
///   29:    u8  Central_Clock_Accuracy
/// ```
/// v2 (subevent 0x29, + Advertising_Handle/Sync_Handle) is only
/// generated for connections from periodic advertising with
/// responses, which the v1 command cannot create; it is not parsed
/// here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeEnhancedConnectionComplete {
    pub status: u8,
    pub handle: u16,
    pub role: u8,
    pub peer_address_type: u8,
    pub peer_address: [u8; 6],
    pub local_rpa: [u8; 6],
    pub peer_rpa: [u8; 6],
    pub connection_interval: u16,
    pub peripheral_latency: u16,
    pub supervision_timeout: u16,
    pub central_clock_accuracy: u8,
}

impl LeEnhancedConnectionComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::EnhancedConnectionComplete as u8 {
            return None;
        }
        // 1-byte subevent + 30-byte payload = 31 bytes.
        if p.len() < 31 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[6..12]);
        let mut local_rpa = [0u8; 6];
        local_rpa.copy_from_slice(&p[12..18]);
        let mut peer_rpa = [0u8; 6];
        peer_rpa.copy_from_slice(&p[18..24]);
        Some(Self {
            status: p[1],
            handle: u16::from_le_bytes([p[2], p[3]]) & 0x0FFF,
            role: p[4],
            peer_address_type: p[5],
            peer_address: addr,
            local_rpa,
            peer_rpa,
            connection_interval: u16::from_le_bytes([p[24], p[25]]),
            peripheral_latency: u16::from_le_bytes([p[26], p[27]]),
            supervision_timeout: u16::from_le_bytes([p[28], p[29]]),
            central_clock_accuracy: p[30],
        })
    }
}

/// LE Channel Selection Algorithm event (§7.7.65.20). Subevent 0x14.
/// Generated immediately after a successful LE Enhanced Connection
/// Complete (§7.8.66). Layout (after the 0x3E + subevent-code bytes):
/// ```text
///   0..2: u16 Connection_Handle
///   2:    u8  Channel_Selection_Algorithm (0x00 = #1, 0x01 = #2)
/// ```
/// Any other algorithm value is reserved for future use and is
/// rejected by the parser.
pub const CHANNEL_SELECTION_ALGORITHM_1: u8 = 0x00;
pub const CHANNEL_SELECTION_ALGORITHM_2: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeChannelSelectionAlgorithm {
    pub handle: u16,
    pub algorithm: u8,
}

impl LeChannelSelectionAlgorithm {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::ChannelSelectionAlgorithm as u8 {
            return None;
        }
        // 1-byte subevent + 3-byte payload = 4 bytes.
        if p.len() < 4 {
            return None;
        }
        if p[3] != CHANNEL_SELECTION_ALGORITHM_1 && p[3] != CHANNEL_SELECTION_ALGORITHM_2 {
            return None;
        }
        Some(Self {
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            algorithm: p[3],
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

// ── LE Extended Advertising Report (§7.7.65.13) ────────────────────
//
// Subevent 0x0D. One LE Meta event carries `Num_Reports` reports;
// each report is a fixed 24-byte header plus variable data:
//
// ```text
//   Event_Type (2 LE) — bits: 0 connectable, 1 scannable, 2 directed,
//       3 scan response, 4 legacy PDUs, 5..6 data status (00 complete,
//       01 incomplete-more-to-come, 10 incomplete-truncated), 7..15 RFU
//   Address_Type (1), Address (6)
//   Primary_PHY (1): 0x01 LE 1M, 0x03 LE Coded
//   Secondary_PHY (1): 0x00 no packets, 0x01 LE 1M, 0x02 LE 2M, 0x03 LE Coded
//   Advertising_SID (1): 0x00..0x0F, 0xFF = no ADI field
//   Tx_Power (1, signed dBm; 0x7F = unavailable)
//   RSSI (1, signed dBm; 0x7F = unavailable)
//   Periodic_Advertising_Interval (2 LE, 1.25 ms units; 0x0000 = none)
//   Direct_Address_Type (1), Direct_Address (6)
//   Data_Length (1), Data (Data_Length)
// ```
//
// Layout cross-checked against the Linux kernel header
// `include/net/bluetooth/hci.h` (`struct hci_ev_le_ext_adv_info`).

/// Data-status values in an extended report's `Event_Type` bits 5..6
/// (§7.7.65.13). The controller may split one advertisement across
/// several reports: every report but the last carries
/// `IncompleteMoreToCome`; the last carries `Complete`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtAdvDataStatus {
    Complete = 0x00,
    IncompleteMoreToCome = 0x01,
    IncompleteTruncated = 0x02,
}

impl ExtAdvDataStatus {
    pub fn from_event_type(event_type: u16) -> Option<Self> {
        match (event_type >> 5) & 0x03 {
            0x00 => Some(Self::Complete),
            0x01 => Some(Self::IncompleteMoreToCome),
            0x02 => Some(Self::IncompleteTruncated),
            _ => None,
        }
    }
}

/// One report inside an LE Extended Advertising Report subevent
/// (§7.7.65.13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeExtendedAdvertisingReport {
    pub event_type: u16,
    pub address_type: u8,
    pub address: [u8; 6],
    pub primary_phy: u8,
    pub secondary_phy: u8,
    pub sid: u8,
    pub tx_power: i8,
    pub rssi: i8,
    pub periodic_interval: u16,
    pub direct_address_type: u8,
    pub direct_address: [u8; 6],
    pub data: alloc::vec::Vec<u8>,
}

impl LeExtendedAdvertisingReport {
    /// Data status from `event_type` bits 5..6 (§7.7.65.13).
    pub fn data_status(&self) -> Option<ExtAdvDataStatus> {
        ExtAdvDataStatus::from_event_type(self.event_type)
    }

    /// Legacy-PDU bit (bit 4): the report came from a legacy
    /// advertising PDU, so primary/secondary PHY, SID, Tx power and
    /// periodic interval carry the spec's legacy sentinels.
    pub fn is_legacy(&self) -> bool {
        self.event_type & (1 << 4) != 0
    }
}

/// Parse an LE Extended Advertising Report subevent into the
/// contained reports. Returns `None` if the event isn't a well-formed
/// LE Meta / Extended Advertising Report — including a report whose
/// `Data_Length` runs past the end of the event, so a truncated
/// controller frame can never be mistaken for a short advertisement.
pub fn parse_le_extended_advertising_reports(
    event: &Event,
) -> Option<alloc::vec::Vec<LeExtendedAdvertisingReport>> {
    if event.code != EventCode::LeMeta as u8 {
        return None;
    }
    let p = &event.params;
    if p.len() < 2 || p[0] != LeSubevent::ExtendedAdvertisingReport as u8 {
        return None;
    }
    let n = p[1] as usize;
    let mut out = alloc::vec::Vec::with_capacity(n);
    let mut i = 2;
    for _ in 0..n {
        // Fixed 24-byte header per report.
        if i + 24 > p.len() {
            return None;
        }
        let event_type = u16::from_le_bytes([p[i], p[i + 1]]);
        let address_type = p[i + 2];
        let mut address = [0u8; 6];
        address.copy_from_slice(&p[i + 3..i + 9]);
        let primary_phy = p[i + 9];
        let secondary_phy = p[i + 10];
        let sid = p[i + 11];
        let tx_power = p[i + 12] as i8;
        let rssi = p[i + 13] as i8;
        let periodic_interval = u16::from_le_bytes([p[i + 14], p[i + 15]]);
        let direct_address_type = p[i + 16];
        let mut direct_address = [0u8; 6];
        direct_address.copy_from_slice(&p[i + 17..i + 23]);
        let dlen = p[i + 23] as usize;
        i += 24;
        if i + dlen > p.len() {
            return None;
        }
        let data = p[i..i + dlen].to_vec();
        i += dlen;
        out.push(LeExtendedAdvertisingReport {
            event_type,
            address_type,
            address,
            primary_phy,
            secondary_phy,
            sid,
            tx_power,
            rssi,
            periodic_interval,
            direct_address_type,
            direct_address,
            data,
        });
    }
    Some(out)
}

/// LE Scan Timeout subevent (§7.7.65.17). Subevent 0x11, no
/// parameters: the scan `Duration` from LE Set Extended Scan Enable
/// (§7.8.65) expired, so the controller stopped scanning on its own.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LeScanTimeout;

impl LeScanTimeout {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::ScanTimeout as u8 {
            return None;
        }
        Some(Self)
    }
}

/// LE Advertising Set Terminated subevent (§7.7.65.18). Subevent 0x12.
///
/// Layout (after the 0x3E + subevent-code bytes):
/// ```text
///   0:    u8  Status
///   1:    u8  Advertising_Handle
///   2..4: u16 LE Connection_Handle (0 if no connection was created)
///   4:    u8  Num_Completed_Extended_Advertising_Events
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LeAdvertisingSetTerminated {
    pub status: u8,
    pub handle: u8,
    pub connection_handle: u16,
    pub num_completed_events: u8,
}

impl LeAdvertisingSetTerminated {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::AdvertisingSetTerminated as u8 {
            return None;
        }
        if p.len() < 1 + 5 {
            return None;
        }
        Some(Self {
            status: p[1],
            handle: p[2],
            connection_handle: u16::from_le_bytes([p[3], p[4]]) & 0x0FFF,
            num_completed_events: p[5],
        })
    }
}

/// LE Scan Request Received subevent (§7.7.65.19). Subevent 0x13.
///
/// Layout (after the 0x3E + subevent-code bytes):
/// ```text
///   0:    u8  Advertising_Handle
///   1:    u8  Scanner_Address_Type
///   2..8: 6   Scanner_Address
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LeScanRequestReceived {
    pub handle: u8,
    pub scanner_address_type: u8,
    pub scanner_address: [u8; 6],
}

impl LeScanRequestReceived {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::ScanRequestReceived as u8 {
            return None;
        }
        if p.len() < 1 + 8 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[3..9]);
        Some(Self {
            handle: p[1],
            scanner_address_type: p[2],
            scanner_address: addr,
        })
    }
}

// ── Extended advertising / scan Command Complete return params ─────

/// LE Set Extended Advertising Parameters return params (§7.8.53):
/// Status (1) + Selected_Tx_Power (1, signed dBm) — the Tx power the
/// controller actually selected for the set. Returns `None` when the
/// Command Complete is too short to carry the power byte.
pub fn parse_ext_adv_selected_tx_power(cc: &CommandComplete) -> Option<i8> {
    if cc.return_params.len() < 2 {
        return None;
    }
    Some(cc.return_params[1] as i8)
}

/// LE Read Maximum Advertising Data Length return params (§7.8.57):
/// Status (1) + Maximum_Advertising_Data_Length (2 LE). The largest
/// advertising-data length the controller accepts in one Set Extended
/// Advertising Data command (at most 251, §7.8.54).
pub fn parse_max_adv_data_length(cc: &CommandComplete) -> Option<u16> {
    if cc.return_params.len() < 3 {
        return None;
    }
    Some(u16::from_le_bytes([
        cc.return_params[1],
        cc.return_params[2],
    ]))
}

/// LE Read Number of Supported Advertising Sets return params
/// (§7.8.58): Status (1) + Num_Supported_Advertising_Sets (1).
pub fn parse_num_supported_adv_sets(cc: &CommandComplete) -> Option<u8> {
    if cc.return_params.len() < 2 {
        return None;
    }
    Some(cc.return_params[1])
}

// ── LE Periodic Advertising subevents (§7.7.65.14..16, .21) ─────────
//
// Subevent 0x18 is decoded below (§7.7.65.21, issue #1575).
// Periodic advertising with responses (PAwR) — including the [v2]
// form of the transfer event (subevent 0x26) — is out of scope.

/// LE Periodic Advertising Sync Established subevent (§7.7.65.15).
/// Subevent 0x0E.
///
/// Layout (after the 0x3E + subevent-code bytes):
/// ```text
///   0:     u8  Status
///   1..3:  u16 LE Sync_Handle (0x0000..=0x0EFF; NOT a connection
///               handle — do not mask to 12 bits)
///   3:     u8  Advertising_SID
///   4:     u8  Advertiser_Address_Type (0 = public, 1 = random)
///   5..11: 6  Advertiser_Address (LE order)
///   11:    u8  Advertiser_PHY (0x01 = 1M, 0x02 = 2M, 0x03 = Coded)
///   12..14: u16 LE Periodic_Advertising_Interval (1.25 ms units)
///   14:    u8  Advertiser_Clock_Accuracy
/// ```
/// 15 payload bytes. The btmon trace of a real Create Sync shows
/// plen 16 for this subevent (1 subevent byte + 15), which pins the
/// length independently of the spec text.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LePeriodicAdvSyncEstablished {
    pub status: u8,
    pub sync_handle: u16,
    pub advertising_sid: u8,
    pub advertiser_address_type: u8,
    pub advertiser_address: [u8; 6],
    pub advertiser_phy: u8,
    pub periodic_advertising_interval: u16,
    pub advertiser_clock_accuracy: u8,
}

impl LePeriodicAdvSyncEstablished {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::PeriodicAdvertisingSyncEstablished as u8 {
            return None;
        }
        // 1-byte subevent + 15-byte payload = 16 bytes.
        if p.len() < 16 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[6..12]);
        Some(Self {
            status: p[1],
            sync_handle: u16::from_le_bytes([p[2], p[3]]),
            advertising_sid: p[4],
            advertiser_address_type: p[5],
            advertiser_address: addr,
            advertiser_phy: p[12],
            periodic_advertising_interval: u16::from_le_bytes([p[13], p[14]]),
            advertiser_clock_accuracy: p[15],
        })
    }
}

/// `Data_Status` values for an LE Periodic Advertising Report
/// (§7.7.65.14). Cross-checked against Linux
/// `include/net/bluetooth/hci.h` (`LE_PA_DATA_COMPLETE` 0x00,
/// `LE_PA_DATA_MORE_TO_COME` 0x01, `LE_PA_DATA_TRUNCATED` 0x02).
pub const LE_PA_DATA_COMPLETE: u8 = 0x00;
pub const LE_PA_DATA_MORE_TO_COME: u8 = 0x01;
pub const LE_PA_DATA_TRUNCATED: u8 = 0x02;

/// `CTE_Type` values for an LE Periodic Advertising Report
/// (§7.7.65.14): 0x00 = AoA, 0x01 = AoD 1 µs slots,
/// 0x02 = AoD 2 µs slots, 0xFF = no CTE.
pub const LE_PA_CTE_AOA: u8 = 0x00;
pub const LE_PA_CTE_AOD_1US: u8 = 0x01;
pub const LE_PA_CTE_AOD_2US: u8 = 0x02;
pub const LE_PA_CTE_NONE: u8 = 0xFF;

/// One LE Periodic Advertising Report subevent (§7.7.65.14).
/// Subevent 0x0F.
///
/// Layout (after the 0x3E + subevent-code bytes):
/// ```text
///   0..2:  u16 LE Sync_Handle
///   2:     i8  Tx_Power (dBm; 0x7F = unavailable)
///   3:     i8  RSSI (dBm; 0x7F = unavailable)
///   4:     u8  CTE_Type (0x00 AoA / 0x01 AoD 1µs / 0x02 AoD 2µs /
///               0xFF no CTE; other values reserved)
///   5:     u8  Data_Status (0x00 complete / 0x01 incomplete, more
///               to come / 0x02 incomplete, truncated)
///   6:     u8  Data_Length
///   7..:   Data (Data_Length bytes)
/// ```
/// Field order cross-checked against Linux
/// `struct hci_ev_le_per_adv_report` (`__le16 sync_handle; __u8
/// tx_power; __u8 rssi; __u8 cte_type; __u8 data_status; __u8
/// length; __u8 data[]`). A 2026 kernel fix for an out-of-bounds
/// read in the reassembly path (`hci_le_per_adv_report_evt`) is the
/// reason this parser validates `Data_Length` against the bytes the
/// event actually carries before slicing: a controller that reports
/// a length larger than the received event must yield `None`, never
/// a truncated read. Reserved `CTE_Type` / `Data_Status` values are
/// likewise rejected as malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LePeriodicAdvReport {
    pub sync_handle: u16,
    pub tx_power: i8,
    pub rssi: i8,
    pub cte_type: u8,
    pub data_status: u8,
    pub data: alloc::vec::Vec<u8>,
}

impl LePeriodicAdvReport {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::PeriodicAdvertisingReport as u8 {
            return None;
        }
        // 1-byte subevent + 7-byte fixed part.
        if p.len() < 8 {
            return None;
        }
        let cte_type = p[5];
        if cte_type != LE_PA_CTE_AOA
            && cte_type != LE_PA_CTE_AOD_1US
            && cte_type != LE_PA_CTE_AOD_2US
            && cte_type != LE_PA_CTE_NONE
        {
            return None;
        }
        let data_status = p[6];
        if data_status > LE_PA_DATA_TRUNCATED {
            return None;
        }
        let dlen = p[7] as usize;
        if p.len() < 8 + dlen {
            return None;
        }
        Some(Self {
            sync_handle: u16::from_le_bytes([p[1], p[2]]),
            tx_power: p[3] as i8,
            rssi: p[4] as i8,
            cte_type,
            data_status,
            data: p[8..8 + dlen].to_vec(),
        })
    }
}

/// LE Periodic Advertising Sync Lost subevent (§7.7.65.16).
/// Subevent 0x10. Layout (after the 0x3E + subevent-code bytes):
/// Sync_Handle (2 LE) only.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LePeriodicAdvSyncLost {
    pub sync_handle: u16,
}

impl LePeriodicAdvSyncLost {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::PeriodicAdvertisingSyncLost as u8 {
            return None;
        }
        if p.len() < 3 {
            return None;
        }
        Some(Self {
            sync_handle: u16::from_le_bytes([p[1], p[2]]),
        })
    }
}

/// LE Periodic Advertising Sync Transfer Received subevent [v1]
/// (§7.7.65.21 in Core 5.x; §7.7.65.24 in Core 6.1).
/// Subevent 0x18.
///
/// Layout (after the 0x3E + subevent-code bytes):
/// ```text
///   0:     u8  Status (0x00 = synchronised; 0x01..=0xFF =
///               synchronisation failed, Controller Error Code)
///   1..3:  u16 LE Connection_Handle (12 bits meaningful,
///               0x0000..=0x0EFF) — the ACL connection the sync
///               information arrived over
///   3..5:  u16 LE Service_Data (peer-provided value)
///   5..7:  u16 LE Sync_Handle (12 bits meaningful,
///               0x0000..=0x0EFF; the Host shall ignore it when
///               Status != 0)
///   7:     u8  Advertising_SID (0x00..=0x0F)
///   8:     u8  Advertiser_Address_Type (0x00 public,
///               0x01 random, 0x02 public identity,
///               0x03 random (static) identity)
///   9..15: 6  Advertiser_Address (LE order)
///   15:    u8  Advertiser_PHY (0x01 = 1M, 0x02 = 2M,
///               0x03 = Coded)
///   16..18: u16 LE Periodic_Advertising_Interval
///               (0x0006..=0xFFFF, 1.25 ms units)
///   18:    u8  Advertiser_Clock_Accuracy (0x00 = 500 ppm
///               ... 0x07 = 20 ppm)
/// ```
/// 19 payload bytes (1 subevent byte + 19 = 20 params bytes).
/// Grounded in the Core Specification text, not in the issue:
/// the issue's expected shape omits Connection_Handle, puts
/// Sync_Handle before Service_Data, and names a Sync_CTE_Type
/// field — none of which the spec has for this event (there is
/// no CTE type here; that field belongs to the Sync Established
/// [v2] / Report events). The [v2] form of this event (subevent
/// 0x26, Core 5.4+, four trailing PAwR bytes) is NOT decoded
/// here — PAwR is out of scope (#1575).
///
/// Strict: short events, reserved SID / address-type / PHY /
/// clock-accuracy values, an interval below 0x0006, and handles
/// above 0x0EFF are all malformed. A failed transfer (Status
/// != 0) still parses — the status is data for the state
/// machine, which ignores the Sync_Handle per the spec — it is
/// the layout that is validated here, not the outcome.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LePeriodicAdvSyncTransferReceived {
    pub status: u8,
    pub connection_handle: u16,
    pub service_data: u16,
    pub sync_handle: u16,
    pub advertising_sid: u8,
    pub advertiser_address_type: u8,
    pub advertiser_address: [u8; 6],
    pub advertiser_phy: u8,
    pub periodic_advertising_interval: u16,
    pub advertiser_clock_accuracy: u8,
}

impl LePeriodicAdvSyncTransferReceived {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::LeMeta as u8 {
            return None;
        }
        let p = &event.params;
        if p.is_empty() || p[0] != LeSubevent::PeriodicAdvertisingSyncTransferReceived as u8 {
            return None;
        }
        // 1-byte subevent + 19-byte payload = 20 bytes. The
        // payload fields start at p[1] (Status); every field
        // after it is offset by one from the subevent byte.
        if p.len() < 20 {
            return None;
        }
        let connection_handle = u16::from_le_bytes([p[2], p[3]]);
        let service_data = u16::from_le_bytes([p[4], p[5]]);
        let sync_handle = u16::from_le_bytes([p[6], p[7]]);
        let advertising_sid = p[8];
        let advertiser_address_type = p[9];
        let mut advertiser_address = [0u8; 6];
        advertiser_address.copy_from_slice(&p[10..16]);
        let advertiser_phy = p[16];
        let periodic_advertising_interval = u16::from_le_bytes([p[17], p[18]]);
        let advertiser_clock_accuracy = p[19];
        if connection_handle > 0x0EFF || sync_handle > 0x0EFF {
            return None;
        }
        if advertising_sid > 0x0F {
            return None;
        }
        if advertiser_address_type > 0x03 {
            return None;
        }
        if advertiser_phy != 0x01 && advertiser_phy != 0x02 && advertiser_phy != 0x03 {
            return None;
        }
        if periodic_advertising_interval < 0x0006 {
            return None;
        }
        if advertiser_clock_accuracy > 0x07 {
            return None;
        }
        Some(Self {
            status: p[1],
            connection_handle,
            service_data,
            sync_handle,
            advertising_sid,
            advertiser_address_type,
            advertiser_address,
            advertiser_phy,
            periodic_advertising_interval,
            advertiser_clock_accuracy,
        })
    }
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
    if p.is_empty() {
        return None;
    }
    let n = p[0] as usize;
    if p.len() < 1 + n * 14 {
        return None;
    }
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let base = 1 + i * 14;
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[base..base + 6]);
        let psrm = p[base + 6];
        let mut cod = [0u8; 3];
        cod.copy_from_slice(&p[base + 9..base + 12]);
        let clk = u16::from_le_bytes([p[base + 12], p[base + 13]]);
        out.push(InquiryResultEntry {
            bd_addr: addr,
            page_scan_repetition_mode: psrm,
            class_of_device: cod,
            clock_offset: clk,
        });
    }
    Some(out)
}

/// One device returned inside an `HCI_Inquiry_Result_with_RSSI`
/// event (§7.7.33, code 0x22). Each entry is 14 bytes: the
/// standard 14-byte entry (§7.7.2) with its second Reserved byte
/// dropped and a signed RSSI in dBm appended — BD_ADDR(6),
/// PSRM(1), Reserved(1), CoD(3), Clock_Offset(2), RSSI(1).
/// (Linux `struct inquiry_info_with_rssi`; a one-response event
/// carries plen 15 = Num_Responses(1) + 14.) The byte after PSRM
/// is the page-scan period mode / Reserved byte; it carries no
/// host-usable value and is skipped, exactly as the 2 reserved
/// bytes are skipped in the standard entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryResultWithRssiEntry {
    pub bd_addr: [u8; 6],
    pub page_scan_repetition_mode: u8,
    pub class_of_device: [u8; 3],
    pub clock_offset: u16,
    pub rssi: i8,
}

pub fn parse_inquiry_results_with_rssi(
    event: &Event,
) -> Option<alloc::vec::Vec<InquiryResultWithRssiEntry>> {
    if event.code != EventCode::InquiryResultWithRssi as u8 {
        return None;
    }
    let p = &event.params;
    if p.is_empty() {
        return None;
    }
    let n = p[0] as usize;
    if p.len() < 1 + n * 14 {
        return None;
    }
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let base = 1 + i * 14;
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[base..base + 6]);
        let psrm = p[base + 6];
        let mut cod = [0u8; 3];
        cod.copy_from_slice(&p[base + 8..base + 11]);
        let clk = u16::from_le_bytes([p[base + 11], p[base + 12]]);
        let rssi = p[base + 13] as i8;
        out.push(InquiryResultWithRssiEntry {
            bd_addr: addr,
            page_scan_repetition_mode: psrm,
            class_of_device: cod,
            clock_offset: clk,
            rssi,
        });
    }
    Some(out)
}

/// One device returned inside an `HCI_Extended_Inquiry_Result`
/// event (§7.7.38, code 0x2F). Each entry is 254 bytes — the
/// 14-byte RSSI entry (§7.7.33) plus the 240-byte Extended
/// Inquiry Response (EIR), an AD-format TLV block (Core Spec
/// Supplement Part A §1) whose Complete/Shortened Local Name
/// records carry the peer's name. (Linux `struct
/// extended_inquiry_info`; a one-response event carries plen 255
/// = Num_Responses(1) + 254.) The EIR bytes are kept raw; name
/// extraction lives with the peer table (`classic`), which reuses
/// the AD walker in `gap` instead of re-parsing TLV here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedInquiryResultEntry {
    pub bd_addr: [u8; 6],
    pub page_scan_repetition_mode: u8,
    pub class_of_device: [u8; 3],
    pub clock_offset: u16,
    pub rssi: i8,
    pub eir: [u8; 240],
}

pub fn parse_extended_inquiry_results(
    event: &Event,
) -> Option<alloc::vec::Vec<ExtendedInquiryResultEntry>> {
    if event.code != EventCode::ExtendedInquiryResult as u8 {
        return None;
    }
    let p = &event.params;
    if p.is_empty() {
        return None;
    }
    let n = p[0] as usize;
    if p.len() < 1 + n * 254 {
        return None;
    }
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let base = 1 + i * 254;
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[base..base + 6]);
        let psrm = p[base + 6];
        let mut cod = [0u8; 3];
        cod.copy_from_slice(&p[base + 8..base + 11]);
        let clk = u16::from_le_bytes([p[base + 11], p[base + 12]]);
        let rssi = p[base + 13] as i8;
        let mut eir = [0u8; 240];
        eir.copy_from_slice(&p[base + 14..base + 254]);
        out.push(ExtendedInquiryResultEntry {
            bd_addr: addr,
            page_scan_repetition_mode: psrm,
            class_of_device: cod,
            clock_offset: clk,
            rssi,
            eir,
        });
    }
    Some(out)
}

/// Decoded `HCI_Remote_Name_Request_Complete` event (§7.7.7,
/// code 0x07). Layout: Status(1) BD_ADDR(6) Remote_Name(248)
/// = 255 bytes. Remote_Name is the peer's user-friendly name,
/// NUL-terminated and NUL-padded when shorter than 248 bytes;
/// [`RemoteNameRequestComplete::name_bytes`] returns the bytes
/// up to the first NUL (empty when the name field is all NULs).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RemoteNameRequestComplete {
    pub status: u8,
    pub bd_addr: [u8; 6],
    pub remote_name: [u8; 248],
}

impl RemoteNameRequestComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::RemoteNameRequestComplete as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 255 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[1..7]);
        let mut remote_name = [0u8; 248];
        remote_name.copy_from_slice(&p[7..255]);
        Some(Self {
            status: p[0],
            bd_addr: addr,
            remote_name,
        })
    }

    /// Name bytes up to the first NUL terminator.
    pub fn name_bytes(&self) -> &[u8] {
        let end = self
            .remote_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.remote_name.len());
        &self.remote_name[..end]
    }
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
        if event.code != EventCode::ConnectionComplete as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 11 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[3..9]);
        Some(Self {
            status: p[0],
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            bd_addr: addr,
            link_type: p[9],
            encryption_enabled: p[10],
        })
    }
}

/// Decoded `HCI_Authentication_Complete` event (§7.7.6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationComplete {
    pub status: u8,
    pub handle: u16,
}
impl AuthenticationComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::AuthenticationComplete as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 3 {
            return None;
        }
        Some(Self {
            status: p[0],
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
        })
    }
}

/// Decoded `HCI_Encryption_Change` event v1 (§7.7.8).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EncryptionChangeV1 {
    pub status: u8,
    pub handle: u16,
    pub encryption_enabled: u8,
}
impl EncryptionChangeV1 {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::EncryptionChange as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 4 {
            return None;
        }
        Some(Self {
            status: p[0],
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            encryption_enabled: p[3],
        })
    }
}

/// Decoded `HCI_Synchronous_Connection_Complete` event (§7.7.35).
/// Layout: Status(1) Handle(2) BD_ADDR(6) Link_Type(1) TX_Interval(1)
///         ReTx_Window(1) Rx_Len(2) Tx_Len(2) Air_Mode(1) = 17 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SyncConnectionComplete {
    pub status: u8,
    pub handle: u16,
    pub bd_addr: [u8; 6],
    pub link_type: u8,
    pub transmission_interval: u8,
    pub retransmission_window: u8,
    pub rx_packet_length: u16,
    pub tx_packet_length: u16,
    pub air_mode: u8,
}
impl SyncConnectionComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::SyncConnectionComplete as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 17 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[3..9]);
        Some(Self {
            status: p[0],
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            bd_addr: addr,
            link_type: p[9],
            transmission_interval: p[10],
            retransmission_window: p[11],
            rx_packet_length: u16::from_le_bytes([p[12], p[13]]),
            tx_packet_length: u16::from_le_bytes([p[14], p[15]]),
            air_mode: p[16],
        })
    }
}

/// `HCI_Connection_Request` event (§7.7.4). Inbound BR/EDR connection
/// request; the host accepts or rejects via Accept/Reject_Connection.
/// Layout: BD_ADDR(6) ClassOfDevice(3) LinkType(1) = 10 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub bd_addr: [u8; 6],
    pub class_of_device: [u8; 3],
    pub link_type: u8,
}
impl ConnectionRequest {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::ConnectionRequest as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 10 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[0..6]);
        let mut cod = [0u8; 3];
        cod.copy_from_slice(&p[6..9]);
        Some(Self {
            bd_addr: addr,
            class_of_device: cod,
            link_type: p[9],
        })
    }
}

/// `HCI_IO_Capability_Request` event (§7.7.40). Controller asks the
/// host which IO capabilities to advertise for SSP. Layout: BD_ADDR(6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IoCapabilityRequest {
    pub bd_addr: [u8; 6],
}
impl IoCapabilityRequest {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::IoCapabilityRequest as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 6 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[0..6]);
        Some(Self { bd_addr: addr })
    }
}

/// `HCI_User_Confirmation_Request` event (§7.7.42). Numeric-comparison
/// SSP confirmation. Layout: BD_ADDR(6) NumericValue(4 LE) = 10 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UserConfirmationRequest {
    pub bd_addr: [u8; 6],
    pub numeric_value: u32,
}
impl UserConfirmationRequest {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::UserConfirmationRequest as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 10 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[0..6]);
        let val = u32::from_le_bytes([p[6], p[7], p[8], p[9]]);
        Some(Self {
            bd_addr: addr,
            numeric_value: val,
        })
    }
}

/// `HCI_Encryption_Key_Refresh_Complete` event (§7.7.39).
/// Layout: Status(1) Handle(2 LE) = 3 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKeyRefreshComplete {
    pub status: u8,
    pub handle: u16,
}
impl EncryptionKeyRefreshComplete {
    pub fn parse(event: &Event) -> Option<Self> {
        if event.code != EventCode::EncryptionKeyRefreshComplete as u8 {
            return None;
        }
        let p = &event.params;
        if p.len() < 3 {
            return None;
        }
        Some(Self {
            status: p[0],
            handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
        })
    }
}
