//! HCI Event codes + decoders — Bluetooth Core Spec 5.3 Vol 4 Part E §7.7.

use crate::hci::Event;

/// Common event codes (§7.7). Not exhaustive — extended as the
/// controller / data-plane work needs them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventCode {
    InquiryComplete = 0x01,
    ConnectionComplete = 0x03,
    DisconnectionComplete = 0x05,
    CommandComplete = 0x0E,
    CommandStatus = 0x0F,
    HardwareError = 0x10,
    NumberOfCompletedPackets = 0x13,
    LeMeta = 0x3E,
    VendorSpecific = 0xFF,
}

impl EventCode {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::InquiryComplete),
            0x03 => Some(Self::ConnectionComplete),
            0x05 => Some(Self::DisconnectionComplete),
            0x0E => Some(Self::CommandComplete),
            0x0F => Some(Self::CommandStatus),
            0x10 => Some(Self::HardwareError),
            0x13 => Some(Self::NumberOfCompletedPackets),
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
