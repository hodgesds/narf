//! HDMI CEC — Consumer Electronics Control (clean-room).
//!
//! References (public-only):
//! - HDMI Specification 1.4b, Supplement 1 — CEC. HDMI Forum.
//!   §CEC 6 (Signal Form / framing), §CEC 7 (Physical / Logical
//!   address allocation), §CEC 9 (Message Descriptions and Encodings),
//!   §CEC Tables 7..14 (opcode constants).
//!   <https://www.hdmi.org/spec/index>
//! - CEC v1.3a — public Annex (operand encodings, OSD name, vendor
//!   command, deck/play, system audio messages).
//!   <https://www.hdmi.org/spec/index>
//! - CTA-861-G §A — Source Physical Address mapping (the 4-nibble
//!   value carried in the HDMI VSDB; this module reads it from the
//!   `cta861::HdmiVsdb`).
//!   <https://standards.cta.tech/>
//!
//! No GPL Linux source consulted.
//!
//! ## Frame format (§CEC 6.2)
//!
//! Every CEC message is a sequence of *blocks*. Each block is one
//! byte preceded by a start bit and followed by an EOM (end-of-message)
//! bit and an ACK bit. The 0th block is the **header**:
//!
//! ```text
//!   header byte:
//!     bits[7..4] = Initiator logical address
//!     bits[3..0] = Destination logical address (0xF = broadcast)
//! ```
//!
//! If EOM was 1 on the header block the message is a "polling"
//! message (header only, used to claim a logical address). Otherwise
//! the second block is the **opcode** (one byte) and any subsequent
//! blocks are operands. Maximum CEC message length is 16 blocks
//! (header + opcode + ≤14 operand bytes), per §CEC 6.2.1.
//!
//! ## Logical addresses (§CEC 7.2)
//!
//! ```text
//!   0  TV
//!   1  Recording Device 1
//!   2  Recording Device 2
//!   3  Tuner 1
//!   4  Playback Device 1
//!   5  Audio System
//!   6  Tuner 2
//!   7  Tuner 3
//!   8  Playback Device 2
//!   9  Recording Device 3
//!   10 Tuner 4
//!   11 Playback Device 3
//!   12 Reserved
//!   13 Reserved
//!   14 Free Use
//!   15 Unregistered / Broadcast
//! ```

use alloc::vec::Vec;

/// Maximum CEC message length in bytes (§CEC 6.2.1).
pub const CEC_MAX_LEN: usize = 16;

/// Broadcast destination address (§CEC 7.2.4).
pub const CEC_BROADCAST: u8 = 0x0F;
/// Special "Unregistered" initiator address used during logical-
/// address allocation polling (§CEC 7.2.4.1).
pub const CEC_UNREGISTERED: u8 = 0x0F;

/// Logical addresses (§CEC 7.2.1, table 7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LogicalAddress {
    Tv = 0,
    RecordingDevice1 = 1,
    RecordingDevice2 = 2,
    Tuner1 = 3,
    PlaybackDevice1 = 4,
    AudioSystem = 5,
    Tuner2 = 6,
    Tuner3 = 7,
    PlaybackDevice2 = 8,
    RecordingDevice3 = 9,
    Tuner4 = 10,
    PlaybackDevice3 = 11,
    FreeUse = 14,
    Unregistered = 15,
}

impl LogicalAddress {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(b: u8) -> Option<Self> {
        match b & 0x0F {
            0 => Some(Self::Tv),
            1 => Some(Self::RecordingDevice1),
            2 => Some(Self::RecordingDevice2),
            3 => Some(Self::Tuner1),
            4 => Some(Self::PlaybackDevice1),
            5 => Some(Self::AudioSystem),
            6 => Some(Self::Tuner2),
            7 => Some(Self::Tuner3),
            8 => Some(Self::PlaybackDevice2),
            9 => Some(Self::RecordingDevice3),
            10 => Some(Self::Tuner4),
            11 => Some(Self::PlaybackDevice3),
            14 => Some(Self::FreeUse),
            15 => Some(Self::Unregistered),
            _ => None,
        }
    }
}

// ── Opcodes (CEC 1.3a Tables 8..14) ────────────────────────────────

pub const OPCODE_FEATURE_ABORT: u8 = 0x00;
pub const OPCODE_IMAGE_VIEW_ON: u8 = 0x04;
pub const OPCODE_TUNER_STEP_INCREMENT: u8 = 0x05;
pub const OPCODE_TUNER_STEP_DECREMENT: u8 = 0x06;
pub const OPCODE_TUNER_DEVICE_STATUS: u8 = 0x07;
pub const OPCODE_GIVE_TUNER_DEVICE_STATUS: u8 = 0x08;
pub const OPCODE_RECORD_ON: u8 = 0x09;
pub const OPCODE_RECORD_STATUS: u8 = 0x0A;
pub const OPCODE_RECORD_OFF: u8 = 0x0B;
pub const OPCODE_TEXT_VIEW_ON: u8 = 0x0D;
pub const OPCODE_RECORD_TV_SCREEN: u8 = 0x0F;
pub const OPCODE_GIVE_DECK_STATUS: u8 = 0x1A;
pub const OPCODE_DECK_STATUS: u8 = 0x1B;
pub const OPCODE_SET_MENU_LANGUAGE: u8 = 0x32;
pub const OPCODE_CLEAR_ANALOGUE_TIMER: u8 = 0x33;
pub const OPCODE_SET_ANALOGUE_TIMER: u8 = 0x34;
pub const OPCODE_TIMER_STATUS: u8 = 0x35;
pub const OPCODE_STANDBY: u8 = 0x36;
pub const OPCODE_PLAY: u8 = 0x41;
pub const OPCODE_DECK_CONTROL: u8 = 0x42;
pub const OPCODE_TIMER_CLEARED_STATUS: u8 = 0x43;
pub const OPCODE_USER_CONTROL_PRESSED: u8 = 0x44;
pub const OPCODE_USER_CONTROL_RELEASED: u8 = 0x45;
pub const OPCODE_GIVE_OSD_NAME: u8 = 0x46;
pub const OPCODE_SET_OSD_NAME: u8 = 0x47;
pub const OPCODE_SET_OSD_STRING: u8 = 0x64;
pub const OPCODE_SET_TIMER_PROGRAM_TITLE: u8 = 0x67;
pub const OPCODE_SYSTEM_AUDIO_MODE_REQUEST: u8 = 0x70;
pub const OPCODE_GIVE_AUDIO_STATUS: u8 = 0x71;
pub const OPCODE_SET_SYSTEM_AUDIO_MODE: u8 = 0x72;
pub const OPCODE_REPORT_AUDIO_STATUS: u8 = 0x7A;
pub const OPCODE_GIVE_SYSTEM_AUDIO_MODE_STATUS: u8 = 0x7D;
pub const OPCODE_SYSTEM_AUDIO_MODE_STATUS: u8 = 0x7E;
pub const OPCODE_ROUTING_CHANGE: u8 = 0x80;
pub const OPCODE_ROUTING_INFORMATION: u8 = 0x81;
pub const OPCODE_ACTIVE_SOURCE: u8 = 0x82;
pub const OPCODE_GIVE_PHYSICAL_ADDRESS: u8 = 0x83;
pub const OPCODE_REPORT_PHYSICAL_ADDRESS: u8 = 0x84;
pub const OPCODE_REQUEST_ACTIVE_SOURCE: u8 = 0x85;
pub const OPCODE_SET_STREAM_PATH: u8 = 0x86;
pub const OPCODE_DEVICE_VENDOR_ID: u8 = 0x87;
pub const OPCODE_VENDOR_COMMAND: u8 = 0x89;
pub const OPCODE_VENDOR_REMOTE_BUTTON_DOWN: u8 = 0x8A;
pub const OPCODE_VENDOR_REMOTE_BUTTON_UP: u8 = 0x8B;
pub const OPCODE_GIVE_DEVICE_VENDOR_ID: u8 = 0x8C;
pub const OPCODE_MENU_REQUEST: u8 = 0x8D;
pub const OPCODE_MENU_STATUS: u8 = 0x8E;
pub const OPCODE_GIVE_DEVICE_POWER_STATUS: u8 = 0x8F;
pub const OPCODE_REPORT_POWER_STATUS: u8 = 0x90;
pub const OPCODE_GET_MENU_LANGUAGE: u8 = 0x91;
pub const OPCODE_INACTIVE_SOURCE: u8 = 0x9D;
pub const OPCODE_CEC_VERSION: u8 = 0x9E;
pub const OPCODE_GET_CEC_VERSION: u8 = 0x9F;
pub const OPCODE_VENDOR_COMMAND_WITH_ID: u8 = 0xA0;
pub const OPCODE_REPORT_SHORT_AUDIO_DESCRIPTOR: u8 = 0xA3;
pub const OPCODE_REQUEST_SHORT_AUDIO_DESCRIPTOR: u8 = 0xA4;
pub const OPCODE_INITIATE_ARC: u8 = 0xC0;
pub const OPCODE_REPORT_ARC_INITIATED: u8 = 0xC1;
pub const OPCODE_REPORT_ARC_TERMINATED: u8 = 0xC2;
pub const OPCODE_REQUEST_ARC_INITIATION: u8 = 0xC3;
pub const OPCODE_REQUEST_ARC_TERMINATION: u8 = 0xC4;
pub const OPCODE_TERMINATE_ARC: u8 = 0xC5;
pub const OPCODE_ABORT: u8 = 0xFF;

/// Power-status operand values (§CEC 9.1.7, table 8a).
pub const POWER_STATUS_ON: u8 = 0x00;
pub const POWER_STATUS_STANDBY: u8 = 0x01;
pub const POWER_STATUS_TRANSITION_TO_ON: u8 = 0x02;
pub const POWER_STATUS_TRANSITION_TO_STANDBY: u8 = 0x03;

// ── Frame ─────────────────────────────────────────────────────────

/// Errors returned when decoding a CEC frame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CecError {
    /// Buffer was empty.
    Empty,
    /// Buffer exceeds the spec maximum (16 bytes).
    TooLong,
}

/// One CEC frame: header + optional opcode + 0..14 operand bytes.
/// Polling messages (allocation probes) have no opcode, only a header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub initiator: u8,
    pub destination: u8,
    /// `None` for polling (header-only) messages.
    pub opcode: Option<u8>,
    pub operands: Vec<u8>,
}

impl Frame {
    pub fn polling(initiator: u8) -> Self {
        Self {
            initiator: initiator & 0x0F,
            destination: initiator & 0x0F, // ping the address you want to claim
            opcode: None,
            operands: Vec::new(),
        }
    }

    pub fn new(initiator: u8, destination: u8, opcode: u8) -> Self {
        Self {
            initiator: initiator & 0x0F,
            destination: destination & 0x0F,
            opcode: Some(opcode),
            operands: Vec::new(),
        }
    }

    pub fn with_operand(mut self, b: u8) -> Self {
        self.operands.push(b);
        self
    }

    pub fn with_operands(mut self, operands: &[u8]) -> Self {
        self.operands.extend_from_slice(operands);
        self
    }

    /// Header byte: `(initiator << 4) | destination`.
    pub fn header(&self) -> u8 {
        ((self.initiator & 0x0F) << 4) | (self.destination & 0x0F)
    }

    /// Encode the frame to wire bytes. The result is the byte
    /// sequence the line driver clocks out. The start/EOM/ACK bits
    /// are line-encoded by hardware and are not part of this byte
    /// stream; this matches the convention every CEC controller MMIO
    /// register uses.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.operands.len());
        out.push(self.header());
        if let Some(op) = self.opcode {
            out.push(op);
            out.extend_from_slice(&self.operands);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, CecError> {
        if buf.is_empty() {
            return Err(CecError::Empty);
        }
        if buf.len() > CEC_MAX_LEN {
            return Err(CecError::TooLong);
        }
        let h = buf[0];
        let initiator = (h >> 4) & 0x0F;
        let destination = h & 0x0F;
        if buf.len() == 1 {
            return Ok(Self {
                initiator,
                destination,
                opcode: None,
                operands: Vec::new(),
            });
        }
        let opcode = Some(buf[1]);
        let operands = buf[2..].to_vec();
        Ok(Self {
            initiator,
            destination,
            opcode,
            operands,
        })
    }

    pub fn is_broadcast(&self) -> bool {
        self.destination == CEC_BROADCAST
    }

    pub fn is_polling(&self) -> bool {
        self.opcode.is_none()
    }
}

// ── Message builders (selected, common) ────────────────────────────

/// `<Image View On>` — wake the TV (§CEC 13.6, table 8b).
pub fn image_view_on(initiator: u8, tv: u8) -> Frame {
    Frame::new(initiator, tv, OPCODE_IMAGE_VIEW_ON)
}

/// `<Standby>` — broadcast or addressed power-off (§CEC 13.5).
pub fn standby(initiator: u8) -> Frame {
    Frame::new(initiator, CEC_BROADCAST, OPCODE_STANDBY)
}

/// `<Active Source>` — broadcast that this device's physical address
/// owns the active stream (§CEC 13.2). Phys addr is 4 nibbles packed
/// into 16 bits, high byte first on the wire.
pub fn active_source(initiator: u8, phys_addr: u16) -> Frame {
    let hi = (phys_addr >> 8) as u8;
    let lo = (phys_addr & 0xFF) as u8;
    Frame::new(initiator, CEC_BROADCAST, OPCODE_ACTIVE_SOURCE).with_operands(&[hi, lo])
}

/// `<Routing Change>` — broadcast: original phys addr → new phys addr.
pub fn routing_change(initiator: u8, original: u16, new: u16) -> Frame {
    Frame::new(initiator, CEC_BROADCAST, OPCODE_ROUTING_CHANGE).with_operands(&[
        (original >> 8) as u8,
        original as u8,
        (new >> 8) as u8,
        new as u8,
    ])
}

/// `<Report Physical Address>` — broadcast our phys addr + device type.
/// Device-type byte is the same enum CEC uses for logical-address
/// claim (0=TV, 1=Recording, 2=Reserved, 3=Tuner, 4=Playback,
/// 5=Audio System).
pub fn report_physical_address(initiator: u8, phys_addr: u16, device_type: u8) -> Frame {
    Frame::new(initiator, CEC_BROADCAST, OPCODE_REPORT_PHYSICAL_ADDRESS).with_operands(&[
        (phys_addr >> 8) as u8,
        phys_addr as u8,
        device_type,
    ])
}

/// `<Set OSD Name>` — reply to `<Give OSD Name>` with up to 14 bytes
/// of ASCII (§CEC 13.10, operand max length set by the 16-byte CEC
/// frame ceiling: header + opcode = 2, leaves 14 for name).
pub fn set_osd_name(initiator: u8, destination: u8, name: &str) -> Frame {
    let bytes = name.as_bytes();
    let take = bytes.len().min(14);
    Frame::new(initiator, destination, OPCODE_SET_OSD_NAME).with_operands(&bytes[..take])
}

/// `<Vendor Command With ID>` — payload prefixed by a 24-bit OUI.
pub fn vendor_command_with_id(initiator: u8, destination: u8, oui: u32, payload: &[u8]) -> Frame {
    let mut f = Frame::new(initiator, destination, OPCODE_VENDOR_COMMAND_WITH_ID).with_operands(&[
        ((oui >> 16) & 0xFF) as u8,
        ((oui >> 8) & 0xFF) as u8,
        (oui & 0xFF) as u8,
    ]);
    f.operands.extend_from_slice(payload);
    f
}

/// `<Report Power Status>` — operand is one of the `POWER_STATUS_*`.
pub fn report_power_status(initiator: u8, destination: u8, status: u8) -> Frame {
    Frame::new(initiator, destination, OPCODE_REPORT_POWER_STATUS).with_operand(status)
}

/// `<Feature Abort>` — operands: rejected opcode + reason byte
/// (§CEC 13.3, reason values: 0=Unrecognised, 1=Not in correct mode,
/// 2=Cannot provide source, 3=Invalid operand, 4=Refused).
pub fn feature_abort(initiator: u8, destination: u8, rejected_opcode: u8, reason: u8) -> Frame {
    Frame::new(initiator, destination, OPCODE_FEATURE_ABORT)
        .with_operands(&[rejected_opcode, reason])
}
