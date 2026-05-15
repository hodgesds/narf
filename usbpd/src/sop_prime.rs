//! USB Type-C SOP' / SOP'' cable VDM extensions — clean-room.
//!
//! References (public-only):
//! - "Universal Serial Bus Power Delivery Specification, Revision 3.1
//!   Version 1.8" — USB-IF. Public document. §6.2.1.1.6 (Message
//!   Target field — SOP* values), §6.4.4.3.1 (ID Header VDO layout
//!   for Cable Plug + Active/Passive Cable products), §6.4.4.3.1.4
//!   (Passive Cable VDO), §6.4.4.3.1.5 (Active Cable VDO),
//!   §6.4.4.3.1.6 (Active Cable VDO 2).
//! - "Universal Serial Bus Type-C Cable and Connector Specification,
//!   Revision 2.2" — USB-IF. Public. §3.7 (cable marker IC SOP'/SOP''
//!   addressing), §5.4 (cable VDO contents — VBUS current, latency,
//!   data rate).
//!
//! No GPL Linux source consulted.
//!
//! ## SOP* targeting (§6.2.1.1.6)
//!
//! The Message Target field of the SOP packet header tells the PHY
//! which device on the cable should answer:
//!
//! ```text
//!   0  SOP    — DFP / UFP port partner
//!   1  SOP'   — Cable Plug closer to source
//!   2  SOP''  — Cable Plug at the far end
//!   3  SOP_DBG' / SOP_DBG'' — debug
//! ```
//!
//! ## ID Header VDO (§6.4.4.3.1.1, table 6-29)
//!
//! 32-bit word returned in the Discover Identity response from any
//! SOP* target:
//!
//! ```text
//!   bit 31      USB Host Capable
//!   bit 30      USB Device Capable
//!   bits 29..27 Product Type (UFP / Cable Plug — 7-value enum)
//!   bit 26      Modal Operation Supported
//!   bits 25..23 Product Type (DFP)
//!   bits 22..21 Connector Type
//!   bits 20..16 Reserved
//!   bits 15..0  USB Vendor ID
//! ```

use alloc::vec::Vec;

// ── SOP* targets (§6.2.1.1.6) ──────────────────────────────────────

pub const SOP_TARGET_PORT_PARTNER: u8 = 0;
pub const SOP_TARGET_CABLE_PLUG_NEAR: u8 = 1;
pub const SOP_TARGET_CABLE_PLUG_FAR: u8 = 2;
pub const SOP_TARGET_DBG_NEAR: u8 = 3;
pub const SOP_TARGET_DBG_FAR: u8 = 4;

// ── Product Types — UFP / Cable Plug (§6.4.4.3.1.1, table 6-30) ────

pub const UFP_PRODUCT_TYPE_UNDEFINED: u8 = 0;
pub const UFP_PRODUCT_TYPE_HUB: u8 = 1;
pub const UFP_PRODUCT_TYPE_PERIPHERAL: u8 = 2;
pub const UFP_PRODUCT_TYPE_PSD: u8 = 3;

pub const CABLE_PLUG_TYPE_PASSIVE_CABLE: u8 = 3;
pub const CABLE_PLUG_TYPE_ACTIVE_CABLE: u8 = 4;
pub const CABLE_PLUG_TYPE_VPD: u8 = 6;

// ── Product Types — DFP (§6.4.4.3.1.1, table 6-31) ─────────────────

pub const DFP_PRODUCT_TYPE_UNDEFINED: u8 = 0;
pub const DFP_PRODUCT_TYPE_HUB: u8 = 1;
pub const DFP_PRODUCT_TYPE_HOST: u8 = 2;
pub const DFP_PRODUCT_TYPE_POWER_BRICK: u8 = 3;

// ── Connector Type (§6.4.4.3.1.1) ──────────────────────────────────

pub const CONNECTOR_RECEPTACLE: u8 = 2;
pub const CONNECTOR_PLUG: u8 = 3;

// ── ID Header VDO ──────────────────────────────────────────────────

/// Decoded ID Header VDO returned by any SOP* target.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IdHeaderVdo {
    pub usb_host_capable: bool,
    pub usb_device_capable: bool,
    pub ufp_product_type: u8,
    pub modal_operation: bool,
    pub dfp_product_type: u8,
    pub connector_type: u8,
    pub vendor_id: u16,
}

impl IdHeaderVdo {
    pub const fn encode(self) -> u32 {
        let mut v = (self.vendor_id as u32) & 0xFFFF;
        if self.usb_host_capable {
            v |= 1 << 31;
        }
        if self.usb_device_capable {
            v |= 1 << 30;
        }
        v |= ((self.ufp_product_type as u32) & 0x07) << 27;
        if self.modal_operation {
            v |= 1 << 26;
        }
        v |= ((self.dfp_product_type as u32) & 0x07) << 23;
        v |= ((self.connector_type as u32) & 0x03) << 21;
        v
    }

    pub const fn decode(v: u32) -> Self {
        Self {
            usb_host_capable: (v & (1 << 31)) != 0,
            usb_device_capable: (v & (1 << 30)) != 0,
            ufp_product_type: ((v >> 27) & 0x07) as u8,
            modal_operation: (v & (1 << 26)) != 0,
            dfp_product_type: ((v >> 23) & 0x07) as u8,
            connector_type: ((v >> 21) & 0x03) as u8,
            vendor_id: (v & 0xFFFF) as u16,
        }
    }
}

// ── Passive Cable VDO (§6.4.4.3.1.4, table 6-37) ───────────────────

/// VBus current handling values (table 6-37).
pub const VBUS_CURRENT_3A: u8 = 1;
pub const VBUS_CURRENT_5A: u8 = 2;

/// Cable termination types (table 6-37).
pub const CABLE_TERM_VCONN_NOT_REQUIRED: u8 = 0;
pub const CABLE_TERM_VCONN_REQUIRED: u8 = 1;

/// Latency encoding (table 6-37) — value × 10 ns.
pub const LATENCY_LT_10NS: u8 = 1;
pub const LATENCY_LT_20NS: u8 = 2;
pub const LATENCY_LT_30NS: u8 = 3;
pub const LATENCY_LT_40NS: u8 = 4;
pub const LATENCY_LT_50NS: u8 = 5;
pub const LATENCY_LT_60NS: u8 = 6;
pub const LATENCY_LT_70NS: u8 = 7;

/// USB SuperSpeed signalling (PD 3.1 §6.4.4.3.1.4).
pub const USB_SS_SIGNALING_USB2: u8 = 0;
pub const USB_SS_SIGNALING_GEN1: u8 = 1;
pub const USB_SS_SIGNALING_GEN2: u8 = 2;
pub const USB_SS_SIGNALING_GEN3: u8 = 3;

/// Decoded Passive Cable VDO.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PassiveCableVdo {
    pub hw_version: u8,
    pub firmware_version: u8,
    pub vdo_version: u8,
    pub plug_type: u8,
    pub epr_mode_capable: bool,
    pub cable_latency: u8,
    pub cable_termination: u8,
    pub max_vbus_voltage: u8,
    pub vbus_current: u8,
    pub usb_ss_signaling: u8,
}

impl PassiveCableVdo {
    pub fn encode(self) -> u32 {
        let mut v = 0u32;
        v |= ((self.hw_version as u32) & 0x0F) << 28;
        v |= ((self.firmware_version as u32) & 0x0F) << 24;
        v |= ((self.vdo_version as u32) & 0x07) << 21;
        v |= ((self.plug_type as u32) & 0x03) << 18;
        if self.epr_mode_capable {
            v |= 1 << 16;
        }
        // Cable Latency is 3 bits at [15:13] (USB-PD 3.1 §6.4.4.3.1.5
        // table 6-37). PD 3.0 had it as 4 bits at [16:13]; PD 3.1
        // reclaimed bit 16 for EPR Mode Capable so the field
        // narrowed to 3 bits with mask 0x07.
        v |= ((self.cable_latency as u32) & 0x07) << 13;
        v |= ((self.cable_termination as u32) & 0x03) << 11;
        v |= ((self.max_vbus_voltage as u32) & 0x03) << 9;
        v |= ((self.vbus_current as u32) & 0x03) << 5;
        v |= (self.usb_ss_signaling as u32) & 0x07;
        v
    }

    pub fn decode(v: u32) -> Self {
        Self {
            hw_version: ((v >> 28) & 0x0F) as u8,
            firmware_version: ((v >> 24) & 0x0F) as u8,
            vdo_version: ((v >> 21) & 0x07) as u8,
            plug_type: ((v >> 18) & 0x03) as u8,
            epr_mode_capable: (v & (1 << 16)) != 0,
            // 3-bit field — see encode comment above.
            cable_latency: ((v >> 13) & 0x07) as u8,
            cable_termination: ((v >> 11) & 0x03) as u8,
            max_vbus_voltage: ((v >> 9) & 0x03) as u8,
            vbus_current: ((v >> 5) & 0x03) as u8,
            usb_ss_signaling: (v & 0x07) as u8,
        }
    }
}

// ── Active Cable VDO 1 (§6.4.4.3.1.5, table 6-38) ──────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveCableVdo1 {
    pub hw_version: u8,
    pub firmware_version: u8,
    pub vdo_version: u8,
    pub plug_type: u8,
    pub epr_mode_capable: bool,
    pub cable_latency: u8,
    pub cable_termination: u8,
    pub max_vbus_voltage: u8,
    pub sbu_supported: bool,
    pub sbu_type: u8,
    pub vbus_current: u8,
    pub vbus_through_cable: bool,
    pub sop_double_prime_supported: bool,
    pub usb_ss_signaling: u8,
}

impl ActiveCableVdo1 {
    pub fn encode(self) -> u32 {
        let mut v = 0u32;
        v |= ((self.hw_version as u32) & 0x0F) << 28;
        v |= ((self.firmware_version as u32) & 0x0F) << 24;
        v |= ((self.vdo_version as u32) & 0x07) << 21;
        v |= ((self.plug_type as u32) & 0x03) << 18;
        if self.epr_mode_capable {
            v |= 1 << 16;
        }
        v |= ((self.cable_latency as u32) & 0x0F) << 13;
        v |= ((self.cable_termination as u32) & 0x03) << 11;
        v |= ((self.max_vbus_voltage as u32) & 0x03) << 9;
        if self.sbu_supported {
            v |= 1 << 8;
        }
        v |= ((self.sbu_type as u32) & 0x01) << 7;
        v |= ((self.vbus_current as u32) & 0x03) << 5;
        if self.vbus_through_cable {
            v |= 1 << 4;
        }
        if self.sop_double_prime_supported {
            v |= 1 << 3;
        }
        v |= (self.usb_ss_signaling as u32) & 0x07;
        v
    }

    pub fn decode(v: u32) -> Self {
        Self {
            hw_version: ((v >> 28) & 0x0F) as u8,
            firmware_version: ((v >> 24) & 0x0F) as u8,
            vdo_version: ((v >> 21) & 0x07) as u8,
            plug_type: ((v >> 18) & 0x03) as u8,
            epr_mode_capable: (v & (1 << 16)) != 0,
            cable_latency: ((v >> 13) & 0x0F) as u8,
            cable_termination: ((v >> 11) & 0x03) as u8,
            max_vbus_voltage: ((v >> 9) & 0x03) as u8,
            sbu_supported: (v & (1 << 8)) != 0,
            sbu_type: ((v >> 7) & 0x01) as u8,
            vbus_current: ((v >> 5) & 0x03) as u8,
            vbus_through_cable: (v & (1 << 4)) != 0,
            sop_double_prime_supported: (v & (1 << 3)) != 0,
            usb_ss_signaling: (v & 0x07) as u8,
        }
    }
}

// ── Discover Identity request frame ────────────────────────────────

/// Build a Discover Identity VDM body to send over an SOP*-targeted
/// header. Returns the raw 4-byte VDM header DWORD; concrete cable
/// drivers prepend the SOP target metadata when forming the SOP*
/// packet.
pub fn discover_identity_vdm_header() -> u32 {
    // VDM header format (PD §6.4.4.1):
    //   bits[31..16] = SVID (0xFF00 = USB-IF Standard)
    //   bit 15       = VDM Type = 1 (structured)
    //   bits[14..13] = Structured VDM Version = 1 (PD 3.1) → 01
    //   bits[12..11] = reserved
    //   bits[10..8]  = Object Position (0 for Discover Identity)
    //   bits[7..6]   = Command Type (0 = REQ)
    //   bit 5        = reserved
    //   bits[4..0]   = Command (1 = Discover Identity)
    let svid: u32 = 0xFF00;
    let vdm_type: u32 = 1 << 15;
    let svdm_version: u32 = 0x1 << 13;
    let cmd_type_req: u32 = 0;
    let cmd_discover_identity: u32 = 1;
    (svid << 16) | vdm_type | svdm_version | cmd_type_req | cmd_discover_identity
}

/// Build the full Discover Identity request as a sequence of 32-bit
/// data objects ready to ship — caller wraps them in the SOP*-tagged
/// PD message envelope produced by `crate::message`.
pub fn discover_identity_request_objects(target: u8) -> Vec<u32> {
    // The request only contains the VDM header (no VDOs).
    // `target` is informational only here — the SOP target is
    // encoded in the PD message header by the caller.
    let _ = target;
    alloc::vec![discover_identity_vdm_header()]
}
