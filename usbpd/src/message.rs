//! PD message framing.
//!
//! USB-PD 3.1 §6.2.1 defines a 16-bit message header that prefixes
//! every Standard message and a 32-bit extended header that prefixes
//! Extended messages. Each message body carries 0..=7 Data Objects
//! (32-bit, little-endian on the wire).
//!   <https://www.usb.org/document-library/usb-power-delivery>
//!
//! Header layout (§6.2.1.1):
//!
//! | Bits   | Field                      |
//! | ------ | -------------------------- |
//! | 0..4   | Message Type               |
//! | 5      | Port Data Role (USB-PD r3) |
//! | 6..8   | Specification Revision     |
//! | 9      | Port Power Role            |
//! | 10..12 | Message ID                 |
//! | 13..15 | Number of Data Objects     |
//! | 15     | Extended (1 = extended)    |

use alloc::vec::Vec;

/// Specification Revision values (§6.2.1.1.5).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpecRev {
    R1_0 = 0b00,
    R2_0 = 0b01,
    R3_0 = 0b10,
}

/// Port Data Role (§6.2.1.1.6).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DataRole {
    Ufp = 0,
    Dfp = 1,
}

/// Port Power Role (§6.2.1.1.4).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerRole {
    Sink = 0,
    Source = 1,
}

/// Standard Control message types (§6.3.1, table 6-5). Only the
/// values the sink-role state machine actually consumes during a
/// power-contract negotiation; extended later.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CtrlMsg {
    GoodCrc = 0x01,
    GotoMin = 0x02,
    Accept = 0x03,
    Reject = 0x04,
    Ping = 0x05,
    PsRdy = 0x06,
    GetSourceCap = 0x07,
    GetSinkCap = 0x08,
    /// Power Role Swap request (§6.3.10).
    PrSwap = 0x0A,
    Wait = 0x0C,
    SoftReset = 0x0D,
}

impl CtrlMsg {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => CtrlMsg::GoodCrc,
            0x02 => CtrlMsg::GotoMin,
            0x03 => CtrlMsg::Accept,
            0x04 => CtrlMsg::Reject,
            0x05 => CtrlMsg::Ping,
            0x06 => CtrlMsg::PsRdy,
            0x07 => CtrlMsg::GetSourceCap,
            0x08 => CtrlMsg::GetSinkCap,
            0x0A => CtrlMsg::PrSwap,
            0x0C => CtrlMsg::Wait,
            0x0D => CtrlMsg::SoftReset,
            _ => return None,
        })
    }
}

/// Standard Data message types (§6.3, table 6-6).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DataMsg {
    SourceCapabilities = 0x01,
    Request = 0x02,
    Bist = 0x03,
    SinkCapabilities = 0x04,
    BatteryStatus = 0x05,
    Alert = 0x06,
    GetCountryInfo = 0x07,
    EnterUsb = 0x08,
    VendorDefined = 0x0F,
}

impl DataMsg {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => DataMsg::SourceCapabilities,
            0x02 => DataMsg::Request,
            0x04 => DataMsg::SinkCapabilities,
            0x06 => DataMsg::Alert,
            0x0F => DataMsg::VendorDefined,
            _ => return None,
        })
    }
}

/// Decoded PD message header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub msg_type: u8,
    pub data_role: DataRole,
    pub spec_rev: SpecRev,
    pub power_role: PowerRole,
    pub message_id: u8,
    pub num_data_objects: u8,
    pub extended: bool,
}

impl Header {
    /// Build a Control header (no Data Objects).
    pub fn control(
        msg: CtrlMsg,
        data_role: DataRole,
        power_role: PowerRole,
        spec_rev: SpecRev,
        message_id: u8,
    ) -> Self {
        Self {
            msg_type: msg as u8,
            data_role,
            spec_rev,
            power_role,
            message_id: message_id & 0x7,
            num_data_objects: 0,
            extended: false,
        }
    }

    /// Build a Data header.
    pub fn data(
        msg: DataMsg,
        data_role: DataRole,
        power_role: PowerRole,
        spec_rev: SpecRev,
        message_id: u8,
        num_objects: u8,
    ) -> Self {
        Self {
            msg_type: msg as u8,
            data_role,
            spec_rev,
            power_role,
            message_id: message_id & 0x7,
            num_data_objects: num_objects & 0x7,
            extended: false,
        }
    }

    pub fn encode(&self) -> u16 {
        (self.msg_type as u16 & 0x1F)
            | ((self.data_role as u16 & 0x1) << 5)
            | ((self.spec_rev as u16 & 0x3) << 6)
            | ((self.power_role as u16 & 0x1) << 8)
            | ((self.message_id as u16 & 0x7) << 9)
            | ((self.num_data_objects as u16 & 0x7) << 12)
            | ((self.extended as u16) << 15)
    }

    pub fn decode(raw: u16) -> Self {
        Self {
            msg_type: (raw & 0x1F) as u8,
            data_role: if (raw >> 5) & 0x1 != 0 {
                DataRole::Dfp
            } else {
                DataRole::Ufp
            },
            spec_rev: match (raw >> 6) & 0x3 {
                0b00 => SpecRev::R1_0,
                0b01 => SpecRev::R2_0,
                _ => SpecRev::R3_0,
            },
            power_role: if (raw >> 8) & 0x1 != 0 {
                PowerRole::Source
            } else {
                PowerRole::Sink
            },
            message_id: ((raw >> 9) & 0x7) as u8,
            num_data_objects: ((raw >> 12) & 0x7) as u8,
            extended: (raw >> 15) & 0x1 != 0,
        }
    }
}

// ── Power Data Objects (§6.4.1) ────────────────────────────────────

/// One PDO advertised by a Source. We model only the four Source
/// PDO variants the spec defines.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SourcePdo {
    /// Fixed Supply (§6.4.1.2.3). 5V / Vbus / max-current at 10mA units
    /// stored as 5V * 50mV-step is documented separately — we keep the
    /// raw values per §6.4.1.2.3 table 6-9: voltage in 50 mV units,
    /// current in 10 mA units.
    Fixed { voltage_mv: u32, max_current_ma: u32 },
    /// Variable Supply (Non-Battery). §6.4.1.2.4.
    Variable {
        max_voltage_mv: u32,
        min_voltage_mv: u32,
        max_current_ma: u32,
    },
    /// Battery (§6.4.1.2.5).
    Battery {
        max_voltage_mv: u32,
        min_voltage_mv: u32,
        max_power_mw: u32,
    },
    /// Augmented (Programmable Power Supply, §6.4.1.2.6).
    Augmented {
        max_voltage_mv: u32,
        min_voltage_mv: u32,
        max_current_ma: u32,
    },
}

impl SourcePdo {
    pub fn encode(&self) -> u32 {
        match *self {
            SourcePdo::Fixed {
                voltage_mv,
                max_current_ma,
            } => {
                // §6.4.1.2.3 table 6-9: type=0b00 (bits 30..31 = 00),
                // bits 10..19 = voltage / 50 mV, bits 0..9 = current / 10 mA.
                let v = (voltage_mv / 50) & 0x3FF;
                let i = (max_current_ma / 10) & 0x3FF;
                (0b00 << 30) | (v << 10) | i
            }
            SourcePdo::Battery {
                max_voltage_mv,
                min_voltage_mv,
                max_power_mw,
            } => {
                // type = 0b01.
                let mxv = (max_voltage_mv / 50) & 0x3FF;
                let mnv = (min_voltage_mv / 50) & 0x3FF;
                let mxp = (max_power_mw / 250) & 0x3FF;
                (0b01 << 30) | (mxv << 20) | (mnv << 10) | mxp
            }
            SourcePdo::Variable {
                max_voltage_mv,
                min_voltage_mv,
                max_current_ma,
            } => {
                // type = 0b10.
                let mxv = (max_voltage_mv / 50) & 0x3FF;
                let mnv = (min_voltage_mv / 50) & 0x3FF;
                let i = (max_current_ma / 10) & 0x3FF;
                (0b10 << 30) | (mxv << 20) | (mnv << 10) | i
            }
            SourcePdo::Augmented {
                max_voltage_mv,
                min_voltage_mv,
                max_current_ma,
            } => {
                // type = 0b11. SPR PPS sub-type = 0b00 (§6.4.1.2.6.1).
                // Voltage stored in 100 mV steps, current in 50 mA.
                let mxv = (max_voltage_mv / 100) & 0xFF;
                let mnv = (min_voltage_mv / 100) & 0xFF;
                let i = (max_current_ma / 50) & 0x7F;
                (0b11 << 30) | (mxv << 17) | (mnv << 8) | i
            }
        }
    }

    pub fn decode(raw: u32) -> Self {
        match (raw >> 30) & 0x3 {
            0b00 => SourcePdo::Fixed {
                voltage_mv: ((raw >> 10) & 0x3FF) * 50,
                max_current_ma: (raw & 0x3FF) * 10,
            },
            0b01 => SourcePdo::Battery {
                max_voltage_mv: ((raw >> 20) & 0x3FF) * 50,
                min_voltage_mv: ((raw >> 10) & 0x3FF) * 50,
                max_power_mw: (raw & 0x3FF) * 250,
            },
            0b10 => SourcePdo::Variable {
                max_voltage_mv: ((raw >> 20) & 0x3FF) * 50,
                min_voltage_mv: ((raw >> 10) & 0x3FF) * 50,
                max_current_ma: (raw & 0x3FF) * 10,
            },
            _ => SourcePdo::Augmented {
                max_voltage_mv: ((raw >> 17) & 0xFF) * 100,
                min_voltage_mv: ((raw >> 8) & 0xFF) * 100,
                max_current_ma: (raw & 0x7F) * 50,
            },
        }
    }
}

// ── Request Data Object (§6.4.2) ───────────────────────────────────

/// A Sink's Request Data Object (RDO) — picks one of the Source's
/// advertised PDOs by 1-based index and asks for current/power.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FixedRdo {
    /// 1-based PDO position from the most recently received
    /// Source_Capabilities (§6.4.2.1).
    pub object_position: u8,
    /// Operating current in 10 mA steps.
    pub op_current_ma: u32,
    /// Maximum operating current in 10 mA steps.
    pub max_op_current_ma: u32,
    /// "GiveBack" flag — sink supports Get_Sink_Cap during a contract
    /// (§6.4.2.4 Sink Operating-Position bits).
    pub give_back: bool,
    /// `USB_Communications_Capable` per §6.4.2.4 bit 25.
    pub usb_comms: bool,
    /// `No_USB_Suspend` per §6.4.2.4 bit 24.
    pub no_usb_suspend: bool,
    /// Capability mismatch flag (§6.4.2.4 bit 26).
    pub cap_mismatch: bool,
}

impl FixedRdo {
    pub fn encode(&self) -> u32 {
        ((self.object_position as u32 & 0x7) << 28)
            | ((self.give_back as u32) << 27)
            | ((self.cap_mismatch as u32) << 26)
            | ((self.usb_comms as u32) << 25)
            | ((self.no_usb_suspend as u32) << 24)
            | (((self.op_current_ma / 10) & 0x3FF) << 10)
            | ((self.max_op_current_ma / 10) & 0x3FF)
    }

    pub fn decode(raw: u32) -> Self {
        Self {
            object_position: ((raw >> 28) & 0x7) as u8,
            give_back: (raw >> 27) & 0x1 != 0,
            cap_mismatch: (raw >> 26) & 0x1 != 0,
            usb_comms: (raw >> 25) & 0x1 != 0,
            no_usb_suspend: (raw >> 24) & 0x1 != 0,
            op_current_ma: ((raw >> 10) & 0x3FF) * 10,
            max_op_current_ma: (raw & 0x3FF) * 10,
        }
    }
}

// ── Wire framing helpers ───────────────────────────────────────────

/// Encode `(header, data_objects)` to a contiguous byte buffer in the
/// little-endian-on-wire form a TCPC sees in its TX FIFO.
pub fn encode_message(h: Header, objects: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 4 * objects.len());
    let raw = h.encode();
    out.push((raw & 0xFF) as u8);
    out.push((raw >> 8) as u8);
    for o in objects {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out
}

/// Decode the inverse — pulls header + data objects out of a buffer.
pub fn decode_message(buf: &[u8]) -> Option<(Header, Vec<u32>)> {
    if buf.len() < 2 {
        return None;
    }
    let h = Header::decode(u16::from_le_bytes([buf[0], buf[1]]));
    let n = h.num_data_objects as usize;
    if buf.len() < 2 + 4 * n {
        return None;
    }
    let mut objs = Vec::with_capacity(n);
    for i in 0..n {
        let off = 2 + 4 * i;
        objs.push(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]));
    }
    Some((h, objs))
}
