//! Alt Mode negotiation — DisplayPort and Thunderbolt.
//!
//! ## DisplayPort Alt Mode (SVID 0xFF01)
//!
//! Spec: VESA DisplayPort Alt Mode on USB Type-C Standard, Version
//! 2.0 (public VESA document).
//!
//! Negotiation sequence (mirroring `narf_usbpd::vdm::DpAltModeDriver`
//! but at the Type-C class level):
//!
//! 1. Discover Identity (SOP) — SVID list.
//! 2. Discover Modes (SVID 0xFF01) — capabilities VDO.
//! 3. Enter Mode (SOP, object position 1) — activate DP Alt Mode.
//! 4. DP Status Update — exchange `DpStatusVdo`.
//! 5. DP Configure — negotiate pin assignment, send `DpConfigureVdo`.
//!
//! The lower-layer encode/decode lives in `narf_usbpd::vdm`.  This
//! module re-exports the relevant VDM types and adds the extcon-class
//! view (pin assignment → `AltMode` variant, `Cable::Dp`).
//!
//! ## Thunderbolt 3/4 Alt Mode (SVID 0x8087)
//!
//! Intel Thunderbolt Alt Mode uses SVID 0x8087 (Intel USB-IF vendor
//! ID).  After `Enter Mode`, the TBT enumeration flow starts.  The
//! full TBT tunnel is handled by `drivers/thunderbolt`; this module
//! just records that TBT Alt Mode was entered so the extcon layer can
//! set `Cable::ThunderboltDock`.
//!
//! Linux refs:
//! - `drivers/usb/typec/altmodes/displayport.c`
//! - `drivers/usb/typec/altmodes/thunderbolt.c`
//! - `narf_usbpd::vdm` (encode/decode already shipped).

extern crate alloc;

use alloc::vec::Vec;

// Re-export VDM types so callers don't need to depend on narf-usbpd
// directly.
pub use narf_usbpd::vdm::{
    AltModeState, AltStepOutcome, DpAltModeDriver, DpCapabilitiesVdo, DpConfigureVdo,
    DpPinAssignment as DpPinAssign, DpStatusVdo, VdmCommand, VdmHeader, SVID_DISPLAYPORT,
};

/// Thunderbolt / USB4 Alt Mode SVID (Intel USB-IF vendor ID).
///
/// Linux ref: `drivers/thunderbolt/usb4.c` line 25 (`USB4_DATA_SVID`
/// / `TBT_PROTOCOL_SVID = 0x8087`).
pub const SVID_THUNDERBOLT: u16 = 0x8087;

// ── AltMode variant ────────────────────────────────────────────────

/// An Alt Mode that a Type-C connector has entered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AltMode {
    /// DisplayPort Alt Mode — pin assignment negotiated.
    ///
    /// Linux ref: `drivers/usb/typec/altmodes/displayport.c`,
    /// `dp_altmode_configure()`.
    DisplayPort(DpPinAssign),
    /// Thunderbolt 3/4 Alt Mode.
    ///
    /// `u8` carries the mode's Object Position from Discover Modes
    /// (typically 1).
    Thunderbolt(u8),
}

// ── DP Alt Mode message builders ──────────────────────────────────

/// Build a `DP Configure` VDM for the given pin assignment
/// (DFP source side).
///
/// Linux ref: `displayport.c::dp_altmode_configure_vdm()`.
/// VDM encode: `narf_usbpd::vdm::build_dp_configure_req` +
/// `DpConfigureVdo::dfp_source`.
pub fn encode_dp_configure(mode_pos: u8, pin: DpPinAssign) -> Vec<u32> {
    let cfg = DpConfigureVdo::dfp_source(pin);
    narf_usbpd::vdm::build_dp_configure_req(mode_pos, cfg)
}

/// Build an `Enter Mode` VDM for SVID 0xFF01 (DP Alt Mode),
/// object position `mode_pos` (usually 1).
///
/// Linux ref: `displayport.c::dp_altmode_enter()`.
pub fn encode_dp_enter_mode(mode_pos: u8) -> Vec<u32> {
    narf_usbpd::vdm::build_enter_mode_req(SVID_DISPLAYPORT, mode_pos)
}

/// Build an `Enter Mode` VDM for SVID 0x8087 (TBT Alt Mode).
pub fn encode_tbt_enter_mode(mode_pos: u8) -> Vec<u32> {
    narf_usbpd::vdm::build_enter_mode_req(SVID_THUNDERBOLT, mode_pos)
}

/// Pick the best-available `DpPinAssign` from the partner's
/// capabilities VDO.
///
/// `dfp_d_pins` is the raw byte from `DpCapabilitiesVdo::
/// dfp_d_pin_assignments()`, where each bit is a `DpPinAssignment`
/// bitmask value (A=0x01, B=0x02, C=0x04, D=0x08, E=0x10, F=0x20).
///
/// Priority order (most lanes preferred, matching cable type):
/// Pin C (4-lane, USB-C plug) > Pin E (4-lane, native DP cable) >
/// Pin D (2-lane, USB-C plug) > Pin F (2-lane, native DP cable) >
/// Pin A / B (legacy, deprecated in USB-C Spec 2.2 §6.2.1).
///
/// Linux ref: `drivers/usb/typec/altmodes/displayport.c::
/// dp_altmode_get_pin()`.
pub fn best_pin_assignment(dfp_d_pins: u8) -> Option<DpPinAssign> {
    const PRIORITY: &[DpPinAssign] = &[
        DpPinAssign::C,
        DpPinAssign::E,
        DpPinAssign::D,
        DpPinAssign::F,
        DpPinAssign::A,
        DpPinAssign::B,
    ];
    // `DpPinAssignment as u8` is the bitmask value (A=1, B=2, C=4, …).
    PRIORITY
        .iter()
        .copied()
        .find(|&pin| (dfp_d_pins & (pin as u8)) != 0)
}

/// Map `DpPinAssign` to the zero-based bit index used in the DP
/// capabilities VDO `dfp_d_pin_assignments` byte.
///
/// VESA DP Alt 2.0 Table 5-3: bit 0 = Pin A … bit 5 = Pin F.
/// (`DpPinAssignment` values are already bitmasks, so
/// `pin_bit(C) = 2` meaning bit-2 = 0x04 = Pin C.)
pub fn pin_bit(pin: DpPinAssign) -> u8 {
    match pin {
        DpPinAssign::A => 0,
        DpPinAssign::B => 1,
        DpPinAssign::C => 2,
        DpPinAssign::D => 3,
        DpPinAssign::E => 4,
        DpPinAssign::F => 5,
    }
}

/// Number of DP lanes activated by a pin assignment.
///
/// Pin C/E: 4 lanes (all DP, no USB SS).
/// Pin A:   4 lanes (deprecated, same lane count).
/// Pin B/D/F: 2 DP + 2 USB SS.
pub fn dp_lane_count(pin: DpPinAssign) -> u8 {
    match pin {
        DpPinAssign::A | DpPinAssign::C | DpPinAssign::E => 4,
        DpPinAssign::B | DpPinAssign::D | DpPinAssign::F => 2,
    }
}
