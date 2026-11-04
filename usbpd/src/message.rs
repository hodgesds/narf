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
    /// Data Role Swap request (§6.3.9). Either port may initiate.
    DrSwap = 0x09,
    /// Power Role Swap request (§6.3.10).
    PrSwap = 0x0A,
    /// VConn Swap request (§6.3.11).
    VconnSwap = 0x0B,
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
            0x09 => CtrlMsg::DrSwap,
            0x0A => CtrlMsg::PrSwap,
            0x0B => CtrlMsg::VconnSwap,
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
    /// EPR_Request (§6.4.9): sink to source, SOP only, only in EPR
    /// Mode. Carries an RDO plus a copy of the PDO it targets.
    EprRequest = 0x09,
    /// EPR_Mode (§6.4.10): sink or source, SOP only. Carries one
    /// EPR Mode Data Object (EPRMDO, table 6.51).
    EprMode = 0x0A,
    VendorDefined = 0x0F,
}

impl DataMsg {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => DataMsg::SourceCapabilities,
            0x02 => DataMsg::Request,
            0x03 => DataMsg::Bist,
            0x04 => DataMsg::SinkCapabilities,
            0x06 => DataMsg::Alert,
            0x08 => DataMsg::EnterUsb,
            0x09 => DataMsg::EprRequest,
            0x0A => DataMsg::EprMode,
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
/// PDO variants the spec defines, plus the EPR AVS APDO.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SourcePdo {
    /// Fixed Supply (§6.4.1.2.3). 5V / Vbus / max-current at 10mA units
    /// stored as 5V * 50mV-step is documented separately — we keep the
    /// raw values per §6.4.1.2.3 table 6-9: voltage in 50 mV units,
    /// current in 10 mA units.
    ///
    /// `epr_mode_capable` is table 6-9 bit 23. Per §6.4.1.2.2.7 it is
    /// a static bit set when the source can supply more than 100 W
    /// and operate in EPR Mode. Bits 29…23 convey information only
    /// on the vSafe5V PDO (position 1); every other Fixed PDO sets
    /// them to zero — policy enforces that on advertisement, decode
    /// reads the bit wherever it appears.
    Fixed {
        voltage_mv: u32,
        max_current_ma: u32,
        epr_mode_capable: bool,
    },
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
    /// EPR Adjustable Voltage Supply APDO (§6.4.1.2.5.2, table
    /// 6.14 source / table 6.21 sink). APDO sub-type 01b, supplying
    /// 15 V up to 48 V. Voltages in 100 mV steps; `pdp_w` is the
    /// port's PDP in 1 W steps (the sink APDO's PDP is the power
    /// the device needs for full function). `peak_current` is the
    /// 2-bit table 6.15 overload capability on source APDOs; sink
    /// APDOs set bits 27…26 to zero, so sink-side construction
    /// passes 0 here.
    EprAvs {
        max_voltage_mv: u32,
        min_voltage_mv: u32,
        pdp_w: u32,
        peak_current: u8,
    },
}

impl SourcePdo {
    pub fn encode(&self) -> u32 {
        match *self {
            SourcePdo::Fixed {
                voltage_mv,
                max_current_ma,
                epr_mode_capable,
            } => {
                // §6.4.1.2.3 table 6-9: type=0b00 (bits 30..31 = 00),
                // bit 23 = EPR Mode Capable, bits 10..19 = voltage /
                // 50 mV, bits 0..9 = current / 10 mA.
                let v = (voltage_mv / 50) & 0x3FF;
                let i = (max_current_ma / 10) & 0x3FF;
                // type field (bits 30..31) is 0b00, contributing nothing.
                ((epr_mode_capable as u32) << 23) | (v << 10) | i
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
            SourcePdo::EprAvs {
                max_voltage_mv,
                min_voltage_mv,
                pdp_w,
                peak_current,
            } => {
                // EPR AVS APDO (§6.4.1.2.5.2, table 6.14): type =
                // 0b11, sub-type = 0b01 (bits 28..29), peak current
                // bits 26..27, max voltage in 100 mV steps over
                // NINE bits (17..25 — 48 V needs bit 25), reserved
                // bit 16 zero, min voltage in 100 mV steps bits
                // 8..15, PDP in 1 W steps bits 0..7.
                let mxv = (max_voltage_mv / 100) & 0x1FF;
                let mnv = (min_voltage_mv / 100) & 0xFF;
                let pdp = pdp_w & 0xFF;
                let pc = (peak_current as u32) & 0x3;
                (0b11 << 30) | (0b01 << 28) | (pc << 26) | (mxv << 17) | (mnv << 8) | pdp
            }
        }
    }

    pub fn decode(raw: u32) -> Self {
        match (raw >> 30) & 0x3 {
            0b00 => SourcePdo::Fixed {
                voltage_mv: ((raw >> 10) & 0x3FF) * 50,
                max_current_ma: (raw & 0x3FF) * 10,
                epr_mode_capable: (raw >> 23) & 0x1 != 0,
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
            _ => {
                // APDO: split on the sub-type in bits 28..29. 00b is
                // SPR PPS (§6.4.1.2.6.1); 01b is EPR AVS
                // (§6.4.1.2.5.2). The SPR AVS sub-type (10b, PD 3.2)
                // is not modelled in this crate, so it falls through
                // to the SPR PPS shape — the same mis-decode the old
                // code applied to every APDO — rather than inventing
                // a variant for it. EPR AVS must NOT land here: its
                // 9-bit max-voltage and PDP-in-watts fields would
                // decode as a truncated voltage and a bogus current.
                match (raw >> 28) & 0x3 {
                    0b01 => SourcePdo::EprAvs {
                        max_voltage_mv: ((raw >> 17) & 0x1FF) * 100,
                        min_voltage_mv: ((raw >> 8) & 0xFF) * 100,
                        pdp_w: raw & 0xFF,
                        peak_current: ((raw >> 26) & 0x3) as u8,
                    },
                    _ => SourcePdo::Augmented {
                        max_voltage_mv: ((raw >> 17) & 0xFF) * 100,
                        min_voltage_mv: ((raw >> 8) & 0xFF) * 100,
                        max_current_ma: (raw & 0x7F) * 50,
                    },
                }
            }
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
    /// `EPR_Mode_Capable` per §6.4.2.7 bit 22: the sink can operate
    /// in EPR Mode. EPR Mode entry (§6.4.10.1) requires this bit set
    /// in the sink's last Request RDO.
    pub epr_mode_capable: bool,
}

impl FixedRdo {
    pub fn encode(&self) -> u32 {
        // Object position is bits 31..28 (§6.4.2.1): SPR PDOs live
        // at 1..=7, EPR PDOs at 8..=11 — the full 4-bit field, not
        // the 3 bits the old code masked.
        ((self.object_position as u32 & 0xF) << 28)
            | ((self.give_back as u32) << 27)
            | ((self.cap_mismatch as u32) << 26)
            | ((self.usb_comms as u32) << 25)
            | ((self.no_usb_suspend as u32) << 24)
            | ((self.epr_mode_capable as u32) << 22)
            | (((self.op_current_ma / 10) & 0x3FF) << 10)
            | ((self.max_op_current_ma / 10) & 0x3FF)
    }

    pub fn decode(raw: u32) -> Self {
        Self {
            object_position: ((raw >> 28) & 0xF) as u8,
            give_back: (raw >> 27) & 0x1 != 0,
            cap_mismatch: (raw >> 26) & 0x1 != 0,
            usb_comms: (raw >> 25) & 0x1 != 0,
            no_usb_suspend: (raw >> 24) & 0x1 != 0,
            epr_mode_capable: (raw >> 22) & 0x1 != 0,
            op_current_ma: ((raw >> 10) & 0x3FF) * 10,
            max_op_current_ma: (raw & 0x3FF) * 10,
        }
    }
}

/// Programmable RDO (§6.4.2.5) — the sink's Request when picking a PPS
/// (Augmented) PDO. Voltage is asked for in 20 mV steps (bits 9..19,
/// 11 bits) and current in 50 mA steps (bits 0..6, 7 bits).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProgrammableRdo {
    /// 1-based PDO position from the most recently received
    /// Source_Capabilities (§6.4.2.1).
    pub object_position: u8,
    /// Requested output voltage in millivolts. Quantised to 20 mV.
    pub voltage_mv: u32,
    /// Requested operating current in milliamps. Quantised to 50 mA.
    pub op_current_ma: u32,
    /// `USB_Communications_Capable` per §6.4.2.4 bit 25.
    pub usb_comms: bool,
    /// `No_USB_Suspend` per §6.4.2.4 bit 24.
    pub no_usb_suspend: bool,
    /// Capability mismatch flag (§6.4.2.4 bit 26).
    pub cap_mismatch: bool,
    /// `EPR_Mode_Capable` per §6.4.2.7 bit 22, same rule as FixedRdo.
    pub epr_mode_capable: bool,
}

impl ProgrammableRdo {
    pub fn encode(&self) -> u32 {
        // Object position is bits 31..28 (§6.4.2.1), full 4-bit field.
        ((self.object_position as u32 & 0xF) << 28)
            | ((self.cap_mismatch as u32) << 26)
            | ((self.usb_comms as u32) << 25)
            | ((self.no_usb_suspend as u32) << 24)
            | ((self.epr_mode_capable as u32) << 22)
            | (((self.voltage_mv / 20) & 0x7FF) << 9)
            | ((self.op_current_ma / 50) & 0x7F)
    }

    pub fn decode(raw: u32) -> Self {
        Self {
            object_position: ((raw >> 28) & 0xF) as u8,
            cap_mismatch: (raw >> 26) & 0x1 != 0,
            usb_comms: (raw >> 25) & 0x1 != 0,
            no_usb_suspend: (raw >> 24) & 0x1 != 0,
            epr_mode_capable: (raw >> 22) & 0x1 != 0,
            voltage_mv: ((raw >> 9) & 0x7FF) * 20,
            op_current_ma: (raw & 0x7F) * 50,
        }
    }
}

/// AVS Request Data Object (§6.4.2, table 6.27) — the sink's Request
/// when picking an EPR AVS APDO, sent inside an EPR_Request Message.
/// Unlike PPS, an AVS source does NOT current-limit: the sink is
/// responsible for not taking more current than it requested, so
/// there is no max-current field, only the operating current.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AvsRdo {
    /// 1-based PDO position from the most recently received
    /// EPR_Source_Capabilities (§6.4.2.1). EPR PDOs live at 8..=11.
    pub object_position: u8,
    /// Requested output voltage in millivolts. Encoded in 25 mV
    /// units (bits 20..9) whose low two bits SHALL be zero, making
    /// the effective step 100 mV — encode floors to 100 mV.
    pub voltage_mv: u32,
    /// Requested operating current in milliamps. Quantised to 50 mA.
    pub op_current_ma: u32,
    /// `USB_Communications_Capable` per §6.4.2.4 bit 25.
    pub usb_comms: bool,
    /// `No_USB_Suspend` per §6.4.2.4 bit 24.
    pub no_usb_suspend: bool,
    /// Capability mismatch flag (§6.4.2.4 bit 26).
    pub cap_mismatch: bool,
    /// `EPR_Mode_Capable` per §6.4.2.7 bit 22, same rule as FixedRdo.
    pub epr_mode_capable: bool,
}

impl AvsRdo {
    pub fn encode(&self) -> u32 {
        // Voltage: 100 mV steps × 4 = 25 mV units with the low two
        // bits zero, per the table 6.27 note.
        let v_units = (self.voltage_mv / 100) * 4;
        ((self.object_position as u32 & 0xF) << 28)
            | ((self.cap_mismatch as u32) << 26)
            | ((self.usb_comms as u32) << 25)
            | ((self.no_usb_suspend as u32) << 24)
            | ((self.epr_mode_capable as u32) << 22)
            | ((v_units & 0x7FF) << 9)
            | ((self.op_current_ma / 50) & 0x7F)
    }

    pub fn decode(raw: u32) -> Self {
        Self {
            object_position: ((raw >> 28) & 0xF) as u8,
            cap_mismatch: (raw >> 26) & 0x1 != 0,
            usb_comms: (raw >> 25) & 0x1 != 0,
            no_usb_suspend: (raw >> 24) & 0x1 != 0,
            epr_mode_capable: (raw >> 22) & 0x1 != 0,
            voltage_mv: ((raw >> 9) & 0x7FF) * 25,
            op_current_ma: (raw & 0x7F) * 50,
        }
    }
}

/// EPR_Mode Action field values (§6.4.10, table 6.51). Sent by the
/// role in the "Sent By" column; anything else is reserved.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EprModeAction {
    Enter = 0x01,
    EnterAcknowledged = 0x02,
    EnterSucceeded = 0x03,
    EnterFailed = 0x04,
    Exit = 0x05,
}

impl EprModeAction {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => EprModeAction::Enter,
            0x02 => EprModeAction::EnterAcknowledged,
            0x03 => EprModeAction::EnterSucceeded,
            0x04 => EprModeAction::EnterFailed,
            0x05 => EprModeAction::Exit,
            _ => return None,
        })
    }
}

/// EPR_Mode Enter Failed Data values (§6.4.10, table 6.51).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EprEnterFailedReason {
    Unknown = 0x00,
    CableNotEprCapable = 0x01,
    NotVconnSource = 0x02,
    RdoBitNotSet = 0x03,
    UnableAtThisTime = 0x04,
    PdoBitNotSet = 0x05,
}

impl EprEnterFailedReason {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => EprEnterFailedReason::Unknown,
            0x01 => EprEnterFailedReason::CableNotEprCapable,
            0x02 => EprEnterFailedReason::NotVconnSource,
            0x03 => EprEnterFailedReason::RdoBitNotSet,
            0x04 => EprEnterFailedReason::UnableAtThisTime,
            0x05 => EprEnterFailedReason::PdoBitNotSet,
            _ => return None,
        })
    }
}

/// EPR Mode Data Object (§6.4.10, table 6.51) — the single data
/// object of an EPR_Mode Message. Bits 31..24 Action, bits 23..16
/// Data, bits 15..0 reserved zero.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EprModeDataObject {
    pub action: EprModeAction,
    /// Data byte. Its meaning depends on the action: Enter carries
    /// the sink's Operational PDP in watts; Enter Acknowledged,
    /// Enter Succeeded and Exit carry zero; Enter Failed carries an
    /// `EprEnterFailedReason` code.
    pub data: u8,
}

impl EprModeDataObject {
    /// Sink's Enter: Data = Operational PDP in watts.
    pub fn enter(operational_pdp_w: u8) -> Self {
        Self {
            action: EprModeAction::Enter,
            data: operational_pdp_w,
        }
    }

    pub fn enter_acknowledged() -> Self {
        Self {
            action: EprModeAction::EnterAcknowledged,
            data: 0,
        }
    }

    pub fn enter_succeeded() -> Self {
        Self {
            action: EprModeAction::EnterSucceeded,
            data: 0,
        }
    }

    pub fn enter_failed(reason: EprEnterFailedReason) -> Self {
        Self {
            action: EprModeAction::EnterFailed,
            data: reason as u8,
        }
    }

    pub fn exit() -> Self {
        Self {
            action: EprModeAction::Exit,
            data: 0,
        }
    }

    /// Operational PDP in watts; only meaningful on Enter.
    pub fn operational_pdp_w(&self) -> Option<u8> {
        if self.action == EprModeAction::Enter {
            Some(self.data)
        } else {
            None
        }
    }

    /// Failed reason; only meaningful on Enter Failed.
    pub fn failed_reason(&self) -> Option<EprEnterFailedReason> {
        if self.action == EprModeAction::EnterFailed {
            EprEnterFailedReason::from_u8(self.data)
        } else {
            None
        }
    }

    pub fn encode(&self) -> u32 {
        ((self.action as u32) << 24) | ((self.data as u32) << 16)
    }

    pub fn decode(raw: u32) -> Option<Self> {
        let action = EprModeAction::from_u8(((raw >> 24) & 0xFF) as u8)?;
        Some(Self {
            action,
            data: ((raw >> 16) & 0xFF) as u8,
        })
    }
}

/// BIST Mode (§6.4.3.1, table 6-31). Only the modes a normal port
/// driver actually emits / acknowledges; the others are
/// receiver-side-only or vendor-reserved.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BistMode {
    /// BIST Carrier Mode 2 (§6.4.3.1): the UUT emits a continuous
    /// carrier pattern on CC. Compliance testers use this to verify
    /// PHY signal quality.
    CarrierMode2 = 0x5,
    /// BIST Test Data Mode: the UUT receives test patterns and
    /// discards them. Compliance only.
    TestData = 0x8,
}

impl BistMode {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x5 => BistMode::CarrierMode2,
            0x8 => BistMode::TestData,
            _ => return None,
        })
    }
}

/// BIST Data Object (§6.4.3.1, table 6-32). Sent in the body of a
/// BIST data message to instruct the partner which BIST sub-mode to
/// enter. Reserved bits are zero.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BistDataObject {
    pub mode: BistMode,
}

impl BistDataObject {
    pub fn encode(&self) -> u32 {
        // BIST Mode lives in bits 28..31 (§6.4.3.1).
        (self.mode as u32 & 0xF) << 28
    }

    pub fn decode(raw: u32) -> Option<Self> {
        let mode = BistMode::from_u8(((raw >> 28) & 0xF) as u8)?;
        Some(Self { mode })
    }
}

// ── Enter_USB Data Object (EUDO, §6.4.9) ───────────────────────────

/// USB mode carried in an Enter_USB message (§6.4.9).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UsbMode {
    Usb2 = 0,
    Usb3 = 1,
    Usb4 = 2,
}

impl UsbMode {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => UsbMode::Usb2,
            1 => UsbMode::Usb3,
            2 => UsbMode::Usb4,
            _ => return None,
        })
    }
}

/// Cable speed carried in an Enter_USB message (§6.4.9).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CableSpeed {
    Usb2 = 0,
    Usb3Gen1 = 1,
    Usb4Gen2 = 2,
    Usb4Gen3 = 3,
}

/// Cable type carried in an Enter_USB message (§6.4.9).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CableType {
    Passive = 0,
    ReTimer = 1,
    ReDriver = 2,
    Optical = 3,
}

/// Cable current rating carried in an Enter_USB message (§6.4.9).
/// Value 1 is reserved by the spec and rejected on decode.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CableCurrent {
    NotSupported = 0,
    Current3A = 2,
    Current5A = 3,
}

impl CableCurrent {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => CableCurrent::NotSupported,
            2 => CableCurrent::Current3A,
            3 => CableCurrent::Current5A,
            _ => return None,
        })
    }
}

/// Enter_USB Data Object (EUDO, USB PD 3.1 §6.4.9): the single data
/// object of an EnterUsb message, carrying the USB4 entry parameters
/// (mode, DRD capability, cable speed/type/current, and the PCIe /
/// DisplayPort / TBT3 tunneling and host-present flags).
///
/// Bit layout (bit 31, bit 27, bit 24, and bits 12:0 are reserved):
/// - bits 30:28 — USB mode (0 = USB2, 1 = USB3, 2 = USB4; 3 reserved)
/// - bit 26 — USB4 DRD capable; bit 25 — USB3 DRD capable
/// - bits 23:21 — cable speed (0 = USB2, 1 = USB3 Gen1, 2 = USB4 Gen2,
///   3 = USB4 Gen3)
/// - bits 20:19 — cable type (0 = passive, 1 = re-timer, 2 = re-driver,
///   3 = optical)
/// - bits 18:17 — cable current (0 = not supported, 2 = 3 A, 3 = 5 A;
///   1 reserved)
/// - bit 16 — PCIe tunneling supported; bit 15 — DP supported;
///   bit 14 — TBT3 supported; bit 13 — host present.
///
/// Decode is strict on the two reserved field values (mode 3,
/// current 1) and ignores reserved bits, matching the repo's
/// `BistDataObject::decode` convention; encode zeroes reserved bits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EnterUsbDataObject {
    pub usb_mode: UsbMode,
    pub usb4_drd: bool,
    pub usb3_drd: bool,
    pub cable_speed: CableSpeed,
    pub cable_type: CableType,
    pub cable_current: CableCurrent,
    pub pcie_support: bool,
    pub dp_support: bool,
    pub tbt_support: bool,
    pub host_present: bool,
}

impl EnterUsbDataObject {
    pub fn encode(&self) -> u32 {
        ((self.usb_mode as u32) << 28)
            | ((self.usb4_drd as u32) << 26)
            | ((self.usb3_drd as u32) << 25)
            | ((self.cable_speed as u32) << 21)
            | ((self.cable_type as u32) << 19)
            | ((self.cable_current as u32) << 17)
            | ((self.pcie_support as u32) << 16)
            | ((self.dp_support as u32) << 15)
            | ((self.tbt_support as u32) << 14)
            | ((self.host_present as u32) << 13)
    }

    pub fn decode(raw: u32) -> Option<Self> {
        let usb_mode = UsbMode::from_u8(((raw >> 28) & 0x7) as u8)?;
        let cable_current = CableCurrent::from_u8(((raw >> 17) & 0x3) as u8)?;
        let cable_speed = match (raw >> 21) & 0x7 {
            0 => CableSpeed::Usb2,
            1 => CableSpeed::Usb3Gen1,
            2 => CableSpeed::Usb4Gen2,
            3 => CableSpeed::Usb4Gen3,
            _ => return None,
        };
        let cable_type = match (raw >> 19) & 0x3 {
            0 => CableType::Passive,
            1 => CableType::ReTimer,
            2 => CableType::ReDriver,
            3 => CableType::Optical,
            _ => return None,
        };
        Some(Self {
            usb_mode,
            usb4_drd: (raw >> 26) & 0x1 != 0,
            usb3_drd: (raw >> 25) & 0x1 != 0,
            cable_speed,
            cable_type,
            cable_current,
            pcie_support: (raw >> 16) & 0x1 != 0,
            dp_support: (raw >> 15) & 0x1 != 0,
            tbt_support: (raw >> 14) & 0x1 != 0,
            host_present: (raw >> 13) & 0x1 != 0,
        })
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
