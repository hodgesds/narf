//! Vendor Defined Messages + DisplayPort Alt Mode (clean-room).
//!
//! Specs:
//! - USB Power Delivery 3.1 §6.4.4 (Vendor Defined Message). Public
//!   USB-IF document.
//!   <https://www.usb.org/document-library/usb-power-delivery>
//! - VESA DisplayPort Alt Mode on USB Type-C Standard, Version 2.0.
//!   Public VESA document.
//!   <https://vesa.org/vesa-standards/>
//!
//! No GPL Linux `drivers/usb/typec/altmodes/` source consulted.
//!
//! ## VDM Header (USB-PD §6.4.4.1)
//!
//! 32-bit Data Object whose bit layout is:
//!
//! ```text
//!   31..16: SVID (16-bit Standard or Vendor ID)
//!   15:     VDM Type (0=Unstructured, 1=Structured)
//!   14..13: Structured VDM Version (00=1.0, 01=2.0)
//!   12..11: Reserved
//!   10..8:  Object Position (1..7, 0 reserved)
//!   7..6:   Command Type (00=REQ, 01=ACK, 10=NAK, 11=BUSY)
//!   5:      Reserved
//!   4..0:   Command (1=DiscIdentity, 2=DiscSVIDs, 3=DiscModes,
//!                    4=EnterMode, 5=ExitMode, 6=Attention)
//! ```
//!
//! ## DisplayPort Alt Mode (VESA DP Alt 2.0)
//!
//! DP uses SVID 0xFF01. After Enter Mode the partner exchanges:
//!
//! - DP_Status VDO (bit 0..2 = Port Connected, bit 3 = Power Low,
//!   bit 4 = Enabled, bit 5 = Multi-Function, bit 6 = USB Configured,
//!   bit 7 = Exit DP Mode, bit 8 = HPD State, bit 9 = HPD IRQ).
//! - DP_Configure VDO (bit 0..1 = DP Config: 0=USB, 1=DFP_D, 2=UFP_D,
//!   3=Reserved; bit 2..5 = DP Signaling Rate; bit 8..15 = Pin
//!   Assignment bitmap).

use alloc::vec::Vec;

// ── SVIDs ──────────────────────────────────────────────────────────

/// USB-IF Standard ID (used by Discover Identity).
pub const SVID_PD: u16 = 0xFF00;
/// VESA DisplayPort Alt Mode SVID.
pub const SVID_DISPLAYPORT: u16 = 0xFF01;

// ── VDM Type / Version ─────────────────────────────────────────────

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VdmType {
    Unstructured = 0,
    Structured = 1,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StructuredVdmVersion {
    V1_0 = 0b00,
    V2_0 = 0b01,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CommandType {
    Req = 0b00,
    Ack = 0b01,
    Nak = 0b10,
    Busy = 0b11,
}

impl CommandType {
    pub fn from_bits(b: u8) -> Self {
        match b & 0x3 {
            0b01 => CommandType::Ack,
            0b10 => CommandType::Nak,
            0b11 => CommandType::Busy,
            _ => CommandType::Req,
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VdmCommand {
    DiscoverIdentity = 1,
    DiscoverSvids = 2,
    DiscoverModes = 3,
    EnterMode = 4,
    ExitMode = 5,
    Attention = 6,
}

impl VdmCommand {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b & 0x1F {
            1 => Self::DiscoverIdentity,
            2 => Self::DiscoverSvids,
            3 => Self::DiscoverModes,
            4 => Self::EnterMode,
            5 => Self::ExitMode,
            6 => Self::Attention,
            _ => return None,
        })
    }
}

/// Decoded VDM header (one 32-bit Data Object).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VdmHeader {
    pub svid: u16,
    pub vdm_type: VdmType,
    pub version: StructuredVdmVersion,
    pub object_position: u8,
    pub command_type: CommandType,
    pub command: u8,
}

impl VdmHeader {
    pub fn structured(svid: u16, command: VdmCommand, command_type: CommandType) -> Self {
        Self {
            svid,
            vdm_type: VdmType::Structured,
            version: StructuredVdmVersion::V2_0,
            object_position: 0,
            command_type,
            command: command as u8,
        }
    }

    pub fn encode(&self) -> u32 {
        ((self.svid as u32) << 16)
            | ((self.vdm_type as u32 & 0x1) << 15)
            | ((self.version as u32 & 0x3) << 13)
            | ((self.object_position as u32 & 0x7) << 8)
            | ((self.command_type as u32 & 0x3) << 6)
            | (self.command as u32 & 0x1F)
    }

    pub fn decode(raw: u32) -> Self {
        Self {
            svid: ((raw >> 16) & 0xFFFF) as u16,
            vdm_type: if (raw >> 15) & 0x1 != 0 {
                VdmType::Structured
            } else {
                VdmType::Unstructured
            },
            version: match (raw >> 13) & 0x3 {
                0b01 => StructuredVdmVersion::V2_0,
                _ => StructuredVdmVersion::V1_0,
            },
            object_position: ((raw >> 8) & 0x7) as u8,
            command_type: CommandType::from_bits(((raw >> 6) & 0x3) as u8),
            command: (raw & 0x1F) as u8,
        }
    }
}

// ── DisplayPort Alt Mode VDOs (VESA DP Alt 2.0) ───────────────────

/// DP Capabilities VDO (sent in Discover Modes ACK by a UFP/DFP_D).
///
/// Bit layout:
///   0..1   Port Capability (1=UFP_D, 2=DFP_D, 3=both)
///   2..5   Signaling Rate (bitmap: 1=HBR3, 2=DP2.0 UHBR10/13.5/20)
///   6      Receptacle (0=plug, 1=receptacle)
///   7      USB 2.0 Not Used
///   8..15  DFP_D Pin Assignment bitmap (A..F)
///   16..23 UFP_D Pin Assignment bitmap (A..F)
///   24..31 Reserved
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpCapabilitiesVdo(pub u32);

impl DpCapabilitiesVdo {
    pub fn port_capability(self) -> u8 {
        (self.0 & 0x3) as u8
    }
    pub fn signaling(self) -> u8 {
        ((self.0 >> 2) & 0xF) as u8
    }
    pub fn receptacle(self) -> bool {
        (self.0 >> 6) & 0x1 != 0
    }
    pub fn dfp_d_pin_assignments(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }
    pub fn ufp_d_pin_assignments(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }
}

/// DP_Status VDO — sent by the UFP after Enter Mode and again on
/// Attention to surface HPD changes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DpStatusVdo {
    pub port_connected: u8, // bits 0..1: 0=neither, 1=DFP_D connected, 2=UFP_D connected, 3=both
    pub power_low: bool,    // bit 2 (Vbus low)
    pub enabled: bool,      // bit 3
    pub multi_function: bool, // bit 4
    pub usb_configured: bool, // bit 5
    pub exit_dp_mode: bool, // bit 6
    pub hpd_state: bool,    // bit 7
    pub hpd_irq: bool,      // bit 8
}

impl DpStatusVdo {
    pub fn encode(&self) -> u32 {
        (self.port_connected as u32 & 0x3)
            | ((self.power_low as u32) << 2)
            | ((self.enabled as u32) << 3)
            | ((self.multi_function as u32) << 4)
            | ((self.usb_configured as u32) << 5)
            | ((self.exit_dp_mode as u32) << 6)
            | ((self.hpd_state as u32) << 7)
            | ((self.hpd_irq as u32) << 8)
    }

    pub fn decode(raw: u32) -> Self {
        Self {
            port_connected: (raw & 0x3) as u8,
            power_low: (raw >> 2) & 0x1 != 0,
            enabled: (raw >> 3) & 0x1 != 0,
            multi_function: (raw >> 4) & 0x1 != 0,
            usb_configured: (raw >> 5) & 0x1 != 0,
            exit_dp_mode: (raw >> 6) & 0x1 != 0,
            hpd_state: (raw >> 7) & 0x1 != 0,
            hpd_irq: (raw >> 8) & 0x1 != 0,
        }
    }
}

/// DP Pin assignment values (VESA DP Alt 2.0 §6.5).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DpPinAssignment {
    A = 0x01,
    B = 0x02,
    C = 0x04,
    D = 0x08,
    E = 0x10,
    F = 0x20,
}

/// DP Configure VDO — sent by the DFP after evaluating Discover Modes.
/// Tells the UFP how to enter DP mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpConfigureVdo {
    /// 0=USB, 1=DFP_D, 2=UFP_D, 3=Reserved.
    pub dp_config: u8,
    /// Signalling rate bitmap (same encoding as Capabilities VDO).
    pub signaling: u8,
    /// DFP_D pin assignment bitmap (use one of `DpPinAssignment`).
    pub dfp_d_pin: u8,
    /// UFP_D pin assignment bitmap.
    pub ufp_d_pin: u8,
}

impl DpConfigureVdo {
    pub fn encode(&self) -> u32 {
        (self.dp_config as u32 & 0x3)
            | ((self.signaling as u32 & 0xF) << 2)
            | ((self.dfp_d_pin as u32) << 8)
            | ((self.ufp_d_pin as u32) << 16)
    }

    pub fn decode(raw: u32) -> Self {
        Self {
            dp_config: (raw & 0x3) as u8,
            signaling: ((raw >> 2) & 0xF) as u8,
            dfp_d_pin: ((raw >> 8) & 0xFF) as u8,
            ufp_d_pin: ((raw >> 16) & 0xFF) as u8,
        }
    }

    /// Build a "configure as DFP_D, pin assignment X, HBR3" VDO that
    /// covers the laptop-as-display-source case (the platform is the
    /// DFP and is driving an external monitor over USB-C).
    pub fn dfp_source(pin: DpPinAssignment) -> Self {
        Self {
            dp_config: 1, // DFP_D
            signaling: 0x1, // HBR3 (the most universally-supported mode)
            dfp_d_pin: pin as u8,
            ufp_d_pin: 0,
        }
    }
}

// ── Builders for whole VDM messages ───────────────────────────────

/// Build a Discover Identity REQ — VDM header with no extra VDOs.
/// Sent on SVID 0xFF00.
pub fn build_discover_identity_req() -> Vec<u32> {
    alloc::vec![VdmHeader::structured(
        SVID_PD,
        VdmCommand::DiscoverIdentity,
        CommandType::Req
    )
    .encode()]
}

/// Build a Discover SVIDs REQ.
pub fn build_discover_svids_req() -> Vec<u32> {
    alloc::vec![VdmHeader::structured(
        SVID_PD,
        VdmCommand::DiscoverSvids,
        CommandType::Req
    )
    .encode()]
}

/// Build a Discover Modes REQ for `svid`.
pub fn build_discover_modes_req(svid: u16) -> Vec<u32> {
    alloc::vec![VdmHeader::structured(
        svid,
        VdmCommand::DiscoverModes,
        CommandType::Req
    )
    .encode()]
}

/// Build an Enter Mode REQ for `svid` at `mode_position` (1..=6).
pub fn build_enter_mode_req(svid: u16, mode_position: u8) -> Vec<u32> {
    let mut h = VdmHeader::structured(svid, VdmCommand::EnterMode, CommandType::Req);
    h.object_position = mode_position & 0x7;
    alloc::vec![h.encode()]
}

/// Build a DP Configure REQ — VDM header on SVID 0xFF01 followed by
/// the Configure VDO.
pub fn build_dp_configure_req(mode_position: u8, cfg: DpConfigureVdo) -> Vec<u32> {
    let mut h = VdmHeader::structured(SVID_DISPLAYPORT, VdmCommand::Attention, CommandType::Req);
    h.object_position = mode_position & 0x7;
    alloc::vec![h.encode(), cfg.encode()]
}

// ── Discovery state machine (Alt-Mode entry) ──────────────────────

/// Phase of Alt-Mode discovery on a port.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AltModeState {
    Idle,
    DiscoveringIdentity,
    DiscoveringSvids,
    DiscoveringModes,
    EnteringMode,
    ConfiguringDp,
    Active,
    Failed,
}

/// Outcome of a single discovery step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AltStepOutcome {
    /// Caller should `transmit(frame)` and wait for reply.
    Transmit(Vec<u32>),
    /// State machine is idle — nothing to send; awaiting an event.
    Idle,
    /// Discovery completed with this DP configuration.
    Active(DpConfigureVdo),
    /// Discovery failed (NAK / unsupported / timeout).
    Failed,
}

/// Bare-bones DP Alt-Mode discovery driver. The TCPM passes received
/// VDOs in via [`feed_response`]; the state machine returns the next
/// VDM frame to transmit.
#[derive(Debug)]
pub struct DpAltModeDriver {
    pub state: AltModeState,
    /// Position of the DP mode in the partner's mode list (1..=6).
    /// Set when Discover Modes ACKs.
    pub dp_mode_position: u8,
    /// Caps reported by the UFP — used to pick a pin assignment.
    pub last_caps: Option<DpCapabilitiesVdo>,
    /// Active configuration once we reach `Active`.
    pub active_cfg: Option<DpConfigureVdo>,
}

impl Default for DpAltModeDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl DpAltModeDriver {
    pub const fn new() -> Self {
        Self {
            state: AltModeState::Idle,
            dp_mode_position: 0,
            last_caps: None,
            active_cfg: None,
        }
    }

    /// Kick off discovery from `Idle`.
    pub fn start(&mut self) -> AltStepOutcome {
        self.state = AltModeState::DiscoveringIdentity;
        AltStepOutcome::Transmit(build_discover_identity_req())
    }

    /// Feed a partner response (header + VDOs) into the state machine.
    /// Returns the next action.
    pub fn feed_response(&mut self, vdos: &[u32]) -> AltStepOutcome {
        if vdos.is_empty() {
            self.state = AltModeState::Failed;
            return AltStepOutcome::Failed;
        }
        let h = VdmHeader::decode(vdos[0]);
        if h.command_type != CommandType::Ack {
            self.state = AltModeState::Failed;
            return AltStepOutcome::Failed;
        }
        match (self.state, VdmCommand::from_u8(h.command)) {
            (AltModeState::DiscoveringIdentity, Some(VdmCommand::DiscoverIdentity)) => {
                self.state = AltModeState::DiscoveringSvids;
                AltStepOutcome::Transmit(build_discover_svids_req())
            }
            (AltModeState::DiscoveringSvids, Some(VdmCommand::DiscoverSvids)) => {
                // Walk the response VDOs for a VESA DisplayPort SVID.
                // Each VDO packs two 16-bit SVIDs (high then low,
                // §6.4.4.2.4).
                let mut found_dp = false;
                for v in &vdos[1..] {
                    let hi = (*v >> 16) as u16;
                    let lo = (*v & 0xFFFF) as u16;
                    if hi == SVID_DISPLAYPORT || lo == SVID_DISPLAYPORT {
                        found_dp = true;
                        break;
                    }
                }
                if !found_dp {
                    self.state = AltModeState::Failed;
                    return AltStepOutcome::Failed;
                }
                self.state = AltModeState::DiscoveringModes;
                AltStepOutcome::Transmit(build_discover_modes_req(SVID_DISPLAYPORT))
            }
            (AltModeState::DiscoveringModes, Some(VdmCommand::DiscoverModes)) => {
                // Use the first reported DP-mode VDO as the active mode.
                if vdos.len() < 2 {
                    self.state = AltModeState::Failed;
                    return AltStepOutcome::Failed;
                }
                self.last_caps = Some(DpCapabilitiesVdo(vdos[1]));
                self.dp_mode_position = 1;
                self.state = AltModeState::EnteringMode;
                AltStepOutcome::Transmit(build_enter_mode_req(
                    SVID_DISPLAYPORT,
                    self.dp_mode_position,
                ))
            }
            (AltModeState::EnteringMode, Some(VdmCommand::EnterMode)) => {
                // Pick a pin assignment from the UFP's DFP_D bitmap.
                // VESA recommends preferring D (4-lane DP, no USB) >
                // C (4-lane DP) > E (DP+USB sideband) for laptop use.
                let caps = self
                    .last_caps
                    .map(|c| c.dfp_d_pin_assignments())
                    .unwrap_or(DpPinAssignment::C as u8);
                let pin = if caps & (DpPinAssignment::D as u8) != 0 {
                    DpPinAssignment::D
                } else if caps & (DpPinAssignment::C as u8) != 0 {
                    DpPinAssignment::C
                } else if caps & (DpPinAssignment::E as u8) != 0 {
                    DpPinAssignment::E
                } else {
                    DpPinAssignment::C
                };
                let cfg = DpConfigureVdo::dfp_source(pin);
                self.state = AltModeState::ConfiguringDp;
                AltStepOutcome::Transmit(build_dp_configure_req(self.dp_mode_position, cfg))
            }
            (AltModeState::ConfiguringDp, Some(VdmCommand::Attention)) => {
                // Configure ACKs land as Attention because Configure is
                // sent on the DP SVID and the peer responds with the
                // current DP_Status.
                if vdos.len() < 2 {
                    self.state = AltModeState::Failed;
                    return AltStepOutcome::Failed;
                }
                let cfg = DpConfigureVdo::decode(vdos[1]);
                self.active_cfg = Some(cfg);
                self.state = AltModeState::Active;
                AltStepOutcome::Active(cfg)
            }
            _ => {
                self.state = AltModeState::Failed;
                AltStepOutcome::Failed
            }
        }
    }
}
