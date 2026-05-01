//! USB HID — Human Interface Device — clean-room.
//!
//! ## Reference
//!
//! - "Device Class Definition for Human Interface Devices (HID)"
//!   Version 1.11, 27 June 2001. Public document, usb.org. Section
//!   numbers below (`§7.x`) refer to that spec.
//! - "Universal Serial Bus HID Usage Tables" 1.4 — for the keyboard
//!   usage page values (page 0x07).
//!
//! ## Scope
//!
//! Stage-5 cut: HID *boot keyboard* protocol only (§B.1 of the HID
//! spec). The boot keyboard report is a fixed 8-byte format that
//! every HID-class keyboard supports out-of-reset:
//!
//! ```text
//!   byte 0 : modifier mask (LCtrl/LShift/LAlt/LGUI/RCtrl/RShift/RAlt/RGUI)
//!   byte 1 : reserved
//!   byte 2..7 : up to 6 simultaneously-pressed scancodes (HID Usage IDs)
//! ```
//!
//! Setting boot protocol is one Set Protocol class request (§7.2.6);
//! after that the kernel can `bulk_in` (interrupt IN) every poll
//! interval and read 8-byte reports.

use crate::xhci::{self, Xhci, EndpointConfig, EndpointKind};

/// USB Interface Class for HID.
pub const HID_INTERFACE_CLASS: u8 = 0x03;
/// HID Subclass: 1 = Boot Interface (keyboard / mouse).
pub const HID_SUBCLASS_BOOT:   u8 = 0x01;
/// HID Boot Protocol: 1 = Keyboard, 2 = Mouse (§4.3).
pub const HID_PROTOCOL_KBD:    u8 = 0x01;

// Class-specific request codes from §7.2.
const HID_REQ_SET_PROTOCOL: u8 = 0x0B;
/// Boot protocol value (vs. 1 = Report Protocol).
const HID_BOOT_PROTOCOL:    u16 = 0;

/// Modifier mask bits in byte 0 of the boot keyboard report.
pub mod kbd_mod {
    pub const LCTRL:  u8 = 1 << 0;
    pub const LSHIFT: u8 = 1 << 1;
    pub const LALT:   u8 = 1 << 2;
    pub const LGUI:   u8 = 1 << 3;
    pub const RCTRL:  u8 = 1 << 4;
    pub const RSHIFT: u8 = 1 << 5;
    pub const RALT:   u8 = 1 << 6;
    pub const RGUI:   u8 = 1 << 7;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HidError {
    /// Device's interface descriptor didn't expose HID boot keyboard.
    NotBootKeyboard,
    /// Configuration descriptor didn't carry an Interrupt-IN endpoint.
    NoInterruptIn,
    /// `set_boot_protocol` failed (control transfer error).
    SetProtocolFailed,
    /// Underlying xHCI error.
    Xhci(xhci::XhciError),
}

impl From<xhci::XhciError> for HidError {
    fn from(e: xhci::XhciError) -> Self { HidError::Xhci(e) }
}

/// Decoded boot-keyboard report (§B.1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct KbdReport {
    pub modifiers: u8,
    pub keys:      [u8; 6],
}

impl KbdReport {
    /// Construct a report from the 8-byte wire format. Byte 1 is
    /// reserved per spec — we discard it.
    pub fn from_bytes(b: [u8; 8]) -> Self {
        Self {
            modifiers: b[0],
            keys: [b[2], b[3], b[4], b[5], b[6], b[7]],
        }
    }
    /// `true` if the given HID Usage ID appears in the key array.
    pub fn pressed(&self, usage: u8) -> bool {
        self.keys.iter().any(|&k| k == usage)
    }
}

/// Boot-keyboard binding. Holds the slot id + interrupt-IN DCI;
/// caller polls via `read_report`.
#[derive(Debug)]
pub struct BootKeyboard {
    pub slot_id:    u8,
    pub interrupt_in_ep: u8, // DCI of the interrupt-IN endpoint
    pub interface_num:   u8,
}

/// Walk a Configuration Descriptor (§9.6.3) tree looking for a HID
/// Boot Keyboard interface and its single interrupt-IN endpoint.
/// Returns `(interface_num, ep_config)` for the caller to feed into
/// `xhci::configure_endpoints`.
pub fn find_boot_keyboard(
    cfg: &[u8],
) -> Result<(u8, EndpointConfig), HidError> {
    let mut i = 0usize;
    let mut in_match = false;
    let mut iface_num: u8 = 0;
    let mut int_in: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() { break; }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Descriptor (§9.6.5).
            //   +2 bInterfaceNumber
            //   +5 bInterfaceClass
            //   +6 bInterfaceSubClass
            //   +7 bInterfaceProtocol
            4 if len >= 9 => {
                in_match =
                    cfg[i + 5] == HID_INTERFACE_CLASS
                    && cfg[i + 6] == HID_SUBCLASS_BOOT
                    && cfg[i + 7] == HID_PROTOCOL_KBD;
                if in_match { iface_num = cfg[i + 2]; }
            }
            // Endpoint Descriptor (§9.6.6).
            //   +2 bEndpointAddress (bit 7 = IN)
            //   +3 bmAttributes (bits[1:0] = transfer type; 3 = interrupt)
            //   +4..=5 wMaxPacketSize
            5 if len >= 7 && in_match && int_in.is_none() => {
                let ep_addr = cfg[i + 2];
                let attr    = cfg[i + 3];
                let mps     = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer_t  = attr & 0x03;
                let is_in   = ep_addr & 0x80 != 0;
                if xfer_t == 3 && is_in {
                    int_in = Some(EndpointConfig {
                        ep_addr,
                        max_packet: mps,
                        kind: EndpointKind::InterruptIn,
                    });
                }
            }
            _ => {}
        }
        i += len;
    }
    match int_in {
        Some(ep) => Ok((iface_num, ep)),
        None     => Err(HidError::NoInterruptIn),
    }
}

impl BootKeyboard {
    /// Bind a boot keyboard to an already-addressed + configured
    /// xHCI slot. Issues `Set Protocol(Boot)` so subsequent
    /// `read_report` calls return the fixed 8-byte format.
    pub fn attach(
        xhci_dev:        &Xhci,
        slot_id:         u8,
        interface_num:   u8,
        interrupt_in_ep: u8,
    ) -> Result<Self, HidError> {
        // Set Protocol class request (§7.2.6):
        //   bmRequestType: 0x21 (Class | Interface | Host-to-Device)
        //   bRequest: SET_PROTOCOL
        //   wValue: 0 (Boot protocol)
        //   wIndex: interface number
        //   wLength: 0
        let mut nothing = [0u8; 0];
        xhci_dev.control_in(
            slot_id,
            0x21,
            HID_REQ_SET_PROTOCOL,
            HID_BOOT_PROTOCOL,
            interface_num as u16,
            &mut nothing,
        ).map_err(|_| HidError::SetProtocolFailed)?;
        Ok(BootKeyboard { slot_id, interrupt_in_ep, interface_num })
    }

    /// Poll a single 8-byte boot-keyboard report off the interrupt-IN
    /// endpoint. Blocks until the device sends a report — typical
    /// keyboards send one every 8 ms while keys are held + on every
    /// state change.
    pub fn read_report(&self, xhci_dev: &Xhci) -> Result<KbdReport, HidError> {
        let mut buf = [0u8; 8];
        let n = xhci_dev.bulk_in(
            self.slot_id, self.interrupt_in_ep, &mut buf)?;
        if n < 8 {
            // Short report — pad zeroes (the device sends 8 even
            // when no keys are pressed; a short one means a bus
            // glitch, but we can still decode what arrived).
        }
        Ok(KbdReport::from_bytes(buf))
    }
}
