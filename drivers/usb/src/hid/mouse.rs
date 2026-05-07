//! USB HID — Boot Mouse (HID 1.11 §B.2) — clean-room.
//!
//! Spec: "Device Class Definition for Human Interface Devices (HID)"
//! Version 1.11, 27 June 2001, Appendix B.2 ("Mouse"). The Boot
//! Protocol mouse report is exactly 3 bytes:
//!
//! ```text
//!   byte 0 : button mask (bit 0 = button 1 / left,
//!                         bit 1 = button 2 / right,
//!                         bit 2 = button 3 / middle)
//!   byte 1 : signed X delta (i8)
//!   byte 2 : signed Y delta (i8, positive = down)
//! ```
//!
//! Some HID-class mice send a longer report (4–5 bytes with a
//! vertical-wheel byte and/or a horizontal-wheel byte) even in boot
//! mode; we accept anything ≥ 3 bytes and ignore the trailing data.
//! Wheel handling lands with the Report-Descriptor parser, where
//! we'll switch off boot protocol.
//!
//! Pipeline mirrors `hid::mod` (boot keyboard):
//!   1. `enumerate_and_attach_mice` — walk every connected port,
//!      address + configure each device, bind any HID Boot-Mouse
//!      interface. Runs as the `usb-hid-mouse` Stage::Device
//!      initcall.
//!   2. `pump_all` — poll each bound mouse, diff against the prior
//!      report, push `PointerEvent`s onto the global input ring.

use super::{
    HidError, HID_BOOT_PROTOCOL, HID_INTERFACE_CLASS, HID_REQ_SET_PROTOCOL, HID_SUBCLASS_BOOT,
};
use crate::xhci::{EndpointConfig, EndpointKind, Xhci};
use narf_input::{push_global, InputEvent, PointerButtons, PointerEvent};
use narf_lib::sync::IrqSafeSpinLock;

extern crate alloc;
use alloc::vec::Vec;

/// HID Boot Protocol code for a mouse (§4.3, table on page 9).
pub const HID_PROTOCOL_MOUSE: u8 = 0x02;

/// Button bits in byte 0 of the boot-mouse report.
pub mod btn {
    pub const LEFT: u8 = 1 << 0;
    pub const RIGHT: u8 = 1 << 1;
    pub const MIDDLE: u8 = 1 << 2;
}

/// Decoded boot-mouse report (§B.2).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MouseReport {
    pub buttons: u8,
    pub dx: i8,
    pub dy: i8,
}

impl MouseReport {
    /// Decode from the wire format. Accepts any slice of length ≥ 3;
    /// trailing bytes (wheel etc.) are ignored in boot mode.
    pub fn from_bytes(b: &[u8]) -> Self {
        if b.len() < 3 {
            return Self::default();
        }
        Self {
            buttons: b[0],
            dx: b[1] as i8,
            dy: b[2] as i8,
        }
    }
}

/// Boot-mouse binding. Holds the slot id + interrupt-IN DCI; caller
/// polls via `read_report` (raw 3-byte report) or `pump_once`
/// (decoded → global input ring).
#[derive(Debug)]
pub struct BootMouse {
    pub slot_id: u8,
    pub interrupt_in_ep: u8,
    pub interface_num: u8,
    /// Last button mask, used to diff press / release on `pump_once`.
    /// Movement deltas are accumulator-free — the device sends a
    /// fresh dx/dy every report, so each report is a self-contained
    /// pointer event.
    pub(crate) last_buttons: u8,
}

/// Walk a Configuration Descriptor (§9.6.3) tree looking for a HID
/// Boot Mouse interface and its single interrupt-IN endpoint.
/// Returns `(interface_num, ep_config)` for the caller to feed into
/// `xhci::configure_endpoints`.
pub fn find_boot_mouse(cfg: &[u8]) -> Result<(u8, EndpointConfig), HidError> {
    let mut i = 0usize;
    let mut in_match = false;
    let mut iface_num: u8 = 0;
    let mut int_in: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Descriptor (§9.6.5): bInterfaceClass=HID,
            // bInterfaceSubClass=Boot, bInterfaceProtocol=Mouse.
            4 if len >= 9 => {
                in_match = cfg[i + 5] == HID_INTERFACE_CLASS
                    && cfg[i + 6] == HID_SUBCLASS_BOOT
                    && cfg[i + 7] == HID_PROTOCOL_MOUSE;
                if in_match {
                    iface_num = cfg[i + 2];
                }
            }
            // Endpoint Descriptor (§9.6.6): interrupt-IN.
            5 if len >= 7 && in_match && int_in.is_none() => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer_t = attr & 0x03;
                let is_in = ep_addr & 0x80 != 0;
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
    int_in
        .map(|ep| (iface_num, ep))
        .ok_or(HidError::NoInterruptIn)
}

impl BootMouse {
    /// Bind a boot mouse to an already-addressed + configured xHCI
    /// slot. Issues `Set Protocol(Boot)` so subsequent `read_report`
    /// calls return the fixed 3-byte format.
    pub fn attach(
        xhci_dev: &Xhci,
        slot_id: u8,
        interface_num: u8,
        interrupt_in_ep: u8,
    ) -> Result<Self, HidError> {
        let mut nothing = [0u8; 0];
        xhci_dev
            .control_in(
                slot_id,
                0x21,
                HID_REQ_SET_PROTOCOL,
                HID_BOOT_PROTOCOL,
                interface_num as u16,
                &mut nothing,
            )
            .map_err(|_| HidError::SetProtocolFailed)?;
        Ok(BootMouse {
            slot_id,
            interrupt_in_ep,
            interface_num,
            last_buttons: 0,
        })
    }

    /// Poll one report off the interrupt-IN endpoint. Reads up to 8
    /// bytes (covers boot + any vendor wheel-padding) and feeds the
    /// first 3 to `MouseReport::from_bytes`.
    pub fn read_report(&self, xhci_dev: &Xhci) -> Result<MouseReport, HidError> {
        let mut buf = [0u8; 8];
        let n = xhci_dev.bulk_in(self.slot_id, self.interrupt_in_ep, &mut buf)?;
        if n < 3 {
            // Short — no movement data. Treat as idle report.
            return Ok(MouseReport::default());
        }
        Ok(MouseReport::from_bytes(&buf[..n]))
    }

    /// Poll one report and emit at most one `PointerEvent` to the
    /// global input ring. Returns the number of events emitted (0 or
    /// 1). A report with zero deltas and no button transitions is
    /// silent — userspace doesn't need a stream of "nothing changed"
    /// pings.
    pub fn pump_once(&mut self, xhci_dev: &Xhci) -> Result<usize, HidError> {
        let report = self.read_report(xhci_dev)?;
        Ok(self.translate_report(report))
    }

    /// Same translation as `pump_once`, but works from a caller-
    /// supplied report. Used by the in-tree smokes.
    pub fn translate_report(&mut self, report: MouseReport) -> usize {
        let buttons_changed = report.buttons != self.last_buttons;
        let moved = report.dx != 0 || report.dy != 0;
        self.last_buttons = report.buttons;
        if !buttons_changed && !moved {
            return 0;
        }
        push_global(InputEvent::Pointer(PointerEvent {
            dx: report.dx as i32,
            dy: report.dy as i32,
            buttons: button_byte_to_buttons(report.buttons),
        }));
        1
    }

    /// Reset the diff baseline — the next report is treated as if no
    /// buttons were previously held. Useful after re-attach.
    pub fn reset_diff(&mut self) {
        self.last_buttons = 0;
    }
}

/// Decode the HID button byte (boot report byte 0) into a
/// `narf_input::PointerButtons` set.
pub fn button_byte_to_buttons(byte: u8) -> PointerButtons {
    let mut b = PointerButtons::EMPTY;
    if byte & btn::LEFT != 0 {
        b.insert(PointerButtons::LEFT);
    }
    if byte & btn::RIGHT != 0 {
        b.insert(PointerButtons::RIGHT);
    }
    if byte & btn::MIDDLE != 0 {
        b.insert(PointerButtons::MIDDLE);
    }
    b
}

// ── Hot-plug enumeration ──────────────────────────────────────────

/// System-wide registry of attached HID boot mice. Populated by
/// `enumerate_and_attach_mice`; consumed by `pump_all`.
static MICE: IrqSafeSpinLock<Vec<BootMouse>> = IrqSafeSpinLock::new(Vec::new());

/// Walk every connected port and try to bring up a HID Boot Mouse
/// interface. Same flow as the keyboard counterpart in `hid::mod`.
pub fn enumerate_and_attach_mice(xhci_dev: &Xhci) -> usize {
    let mut attached = 0usize;
    for (port, _portsc) in xhci_dev.connected_ports() {
        if try_attach_port(xhci_dev, port).is_ok() {
            attached += 1;
        }
    }
    attached
}

fn try_attach_port(xhci_dev: &Xhci, port: u8) -> Result<(), HidError> {
    xhci_dev.port_reset(port).map_err(HidError::Xhci)?;
    let speed = xhci_dev.port_speed(port).ok_or(HidError::NoInterruptIn)?;
    let slot_id = xhci_dev.enable_slot().map_err(HidError::Xhci)?;
    xhci_dev
        .address_device(slot_id, port, speed)
        .map_err(HidError::Xhci)?;

    let mut head = [0u8; 9];
    let n = xhci_dev
        .get_config_descriptor(slot_id, 0, &mut head)
        .map_err(HidError::Xhci)?;
    if n < 9 {
        return Err(HidError::NoInterruptIn);
    }
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if total < 9 || total > 4096 {
        return Err(HidError::NoInterruptIn);
    }

    let mut full = alloc::vec![0u8; total];
    let n2 = xhci_dev
        .get_config_descriptor(slot_id, 0, &mut full)
        .map_err(HidError::Xhci)?;
    if n2 < total {
        full.truncate(n2);
    }

    let (iface, ep) = find_boot_mouse(&full)?;
    xhci_dev
        .configure_endpoints(slot_id, &[ep])
        .map_err(HidError::Xhci)?;

    let dci = ((ep.ep_addr & 0x0F) * 2) + 1;
    let m = BootMouse::attach(xhci_dev, slot_id, iface, dci)?;
    MICE.lock().push(m);
    Ok(())
}

/// Number of mice currently bound.
pub fn attached_mouse_count() -> usize {
    MICE.lock().len()
}

/// Drain one report from each attached mouse. Returns total events
/// emitted across all mice.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    let mut g = MICE.lock();
    let mut total = 0usize;
    for m in g.iter_mut() {
        if let Ok(n) = m.pump_once(xhci_dev) {
            total += n;
        }
    }
    total
}

#[doc(hidden)]
pub fn __reset_mice_for_test() {
    MICE.lock().clear();
}
