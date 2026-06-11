//! USB HID — Boot Mouse (HID 1.11 §B.2) — clean-room.
//!
//! Spec: "Device Class Definition for Human Interface Devices (HID)"
//! Version 1.11, 27 June 2001, Appendix B.2 ("Mouse").
//! <https://www.usb.org/document-library/device-class-definition-hid-111>
//! The Boot Protocol mouse report is exactly 3 bytes:
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
use narf_input::{
    evdev::{
        dispatch_key_to_node, dispatch_rel_to_node, key, rel, DeviceCaps, DeviceId, DeviceNode,
        ROUTER,
    },
    push_global, InputEvent, PointerButtons, PointerEvent,
};
use narf_lib::sync::IrqSafeSpinLock;

extern crate alloc;
use alloc::sync::Arc;
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
/// (decoded → global input ring + evdev ROUTER).
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
    /// evdev ROUTER device id — for unregister on detach.
    pub(crate) evdev_id: DeviceId,
    /// evdev DeviceNode — pointer events dispatched here for ROUTER.
    pub(crate) evdev_node: Arc<DeviceNode>,
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
            // Interface Descriptor (§9.6.5). Audit F-72: don't gate
            // on bInterfaceSubClass == Boot — many modern HID
            // pointing devices report Subclass=0 but still respond
            // to SET_PROTOCOL(Boot). Gate on Protocol == Mouse only;
            // the attach step issues SET_PROTOCOL and bails on STALL.
            4 if len >= 9 => {
                in_match = cfg[i + 5] == HID_INTERFACE_CLASS
                    && (cfg[i + 6] == HID_SUBCLASS_BOOT || cfg[i + 6] == 0)
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

/// Build the `DeviceCaps` for a USB boot-protocol mouse.
/// Registers REL_X/REL_Y axes and the three standard buttons.
/// Mirrors the PS/2 mouse capability setup in
/// `drivers/input/src/i8042_mouse.rs::init`.
pub fn boot_mouse_evdev_caps() -> DeviceCaps {
    let mut caps = DeviceCaps::new();
    caps.add_rel(rel::REL_X);
    caps.add_rel(rel::REL_Y);
    caps.add_key(key::BTN_LEFT);
    caps.add_key(key::BTN_RIGHT);
    caps.add_key(key::BTN_MIDDLE);
    caps
}

impl BootMouse {
    /// Bind a boot mouse to an already-addressed + configured xHCI
    /// slot. Issues `Set Protocol(Boot)` so subsequent `read_report`
    /// calls return the fixed 3-byte format. Also registers a
    /// DeviceNode with the evdev ROUTER so pointer events reach
    /// `/dev/input/event<N>`.
    ///
    /// Ref: `linux/drivers/hid/usbhid/usbmouse.c::usb_mouse_probe`
    /// (GPL-2.0-or-later).
    pub async fn attach(
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
            .await
            .map_err(|_| HidError::SetProtocolFailed)?;
        // Pre-arm the interrupt-IN endpoint so the controller starts
        // polling the device. Without this no Transfer Event ever
        // posts and the supervisor's IRQ-driven pump never wakes.
        xhci_dev
            .arm_interrupt_in(slot_id, interrupt_in_ep, 8)
            .map_err(HidError::Xhci)?;

        // Register with the evdev ROUTER. Mirrors i8042_mouse.rs::init().
        let (evdev_id, evdev_node) = ROUTER.register_device(boot_mouse_evdev_caps());

        Ok(BootMouse {
            slot_id,
            interrupt_in_ep,
            interface_num,
            last_buttons: 0,
            evdev_id,
            evdev_node,
        })
    }

    /// Unregister this mouse's DeviceNode from the evdev ROUTER.
    /// Call when the device is detached / unplugged so
    /// `/dev/input/event<N>` disappears.
    pub fn unregister_evdev(&self) {
        ROUTER.unregister_device(self.evdev_id);
    }

    /// Drain one pending interrupt-IN report off the endpoint without
    /// blocking. Returns `Ok(Some(report))` when the device produced
    /// a state-change report, `Ok(None)` when the controller is
    /// still waiting on the device.
    pub fn read_report(&self, xhci_dev: &Xhci) -> Result<Option<MouseReport>, HidError> {
        let mut buf = [0u8; 8];
        match xhci_dev
            .poll_interrupt_in(self.slot_id, self.interrupt_in_ep, &mut buf)
            .map_err(HidError::Xhci)?
        {
            Some(n) if n >= 3 => Ok(Some(MouseReport::from_bytes(&buf[..n]))),
            Some(_) => Ok(Some(MouseReport::default())),
            None => Ok(None),
        }
    }

    /// Drain all pending reports and push translated `PointerEvent`s
    /// to the global input ring. Returns the total number of events
    /// emitted across however many reports arrived since the last
    /// call. Non-blocking.
    pub fn pump_once(&mut self, xhci_dev: &Xhci) -> Result<usize, HidError> {
        let mut total = 0usize;
        while let Some(report) = self.read_report(xhci_dev)? {
            total += self.translate_report(report);
        }
        Ok(total)
    }

    /// Same translation as `pump_once`, but works from a caller-
    /// supplied report. Dispatches to both the legacy global ring and
    /// the evdev ROUTER DeviceNode.
    pub fn translate_report(&mut self, report: MouseReport) -> usize {
        let buttons_changed = report.buttons != self.last_buttons;
        let moved = report.dx != 0 || report.dy != 0;

        if !buttons_changed && !moved {
            return 0;
        }

        let dx = report.dx as i32;
        let dy = report.dy as i32;
        let btns = button_byte_to_buttons(report.buttons);

        // Legacy global ring (for cursor pump / FB status panel).
        push_global(InputEvent::Pointer(PointerEvent {
            dx,
            dy,
            buttons: btns,
        }));

        // evdev ROUTER — motion.
        if moved {
            dispatch_rel_to_node(&self.evdev_node, dx, dy);
        }

        // evdev ROUTER — button transitions (EV_KEY BTN_LEFT/RIGHT/MIDDLE).
        if buttons_changed {
            let prev = self.last_buttons;
            let cur = report.buttons;
            for &(mask, code) in &[
                (btn::LEFT, key::BTN_LEFT),
                (btn::RIGHT, key::BTN_RIGHT),
                (btn::MIDDLE, key::BTN_MIDDLE),
            ] {
                let was = prev & mask != 0;
                let now = cur & mask != 0;
                if was != now {
                    dispatch_key_to_node(&self.evdev_node, code, now);
                }
            }
        }

        self.last_buttons = report.buttons;
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
pub async fn enumerate_and_attach_mice(xhci_dev: &Xhci) -> usize {
    let mut attached = 0usize;
    for (port, _portsc) in xhci_dev.connected_ports() {
        if try_attach_port(xhci_dev, port).await.is_ok() {
            attached += 1;
        }
    }
    attached
}

/// Public per-port attach used by the supervisor's per-port
/// retry loop. Same shape as the keyboard variant.
pub async fn try_attach_mouse_on_port(xhci_dev: &Xhci, port: u8) -> Result<(), HidError> {
    let r = try_attach_port(xhci_dev, port).await;
    if r.is_ok() {
        use core::fmt::Write as _;
        use core::sync::atomic::{AtomicU64, Ordering};
        static ATTACHED_PORTS: AtomicU64 = AtomicU64::new(0);
        let bit = 1u64 << (port as u32 & 63);
        let prev = ATTACHED_PORTS.fetch_or(bit, Ordering::AcqRel);
        if prev & bit == 0 {
            let _ = writeln!(
                narf_console::Writer,
                "  usb-hid: mouse attached on port {}",
                port
            );
        }
    }
    r
}

/// Hub-downstream mouse attach: caller has already issued port_reset
/// (on the hub's downstream port), enable_slot, and
/// address_device_with(_with_topology). This entry point picks up
/// from there.
///
/// **Slot lifecycle**: does NOT call `disable_slot` on failure. The
/// dispatcher in `attach::dispatch_after_address` owns slot lifecycle
/// and frees the slot only when *every* class-probe fallback has run
/// and returned UnknownClass. Linux pattern: see
/// `drivers/usb/core/hub.c::usb_new_device`.
pub async fn try_bind_mouse_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    speed: crate::xhci::PortSpeed,
) -> Result<(), HidError> {
    bind_mouse_addressed_slot(xhci_dev, slot_id, speed).await
}

async fn try_attach_port(xhci_dev: &Xhci, port: u8) -> Result<(), HidError> {
    xhci_dev.port_reset(port).await.map_err(HidError::Xhci)?;
    let speed = xhci_dev.port_speed(port).ok_or(HidError::NoInterruptIn)?;
    let slot_id = xhci_dev.enable_slot().await.map_err(HidError::Xhci)?;
    let res = async {
        xhci_dev
            .address_device(slot_id, port, speed)
            .await
            .map_err(HidError::Xhci)?;
        bind_mouse_addressed_slot(xhci_dev, slot_id, speed).await
    }
    .await;
    if res.is_err() {
        let _ = xhci_dev.disable_slot(slot_id).await;
    }
    res
}

/// Post-address mouse bind: assumes caller has already addressed
/// the slot. Does GET_DESCRIPTOR + EP0-MPS refresh + interface
/// match + configure_endpoints + SET_CONFIGURATION + SET_PROTOCOL
/// + arm_interrupt_in + registry push.
///
/// No disable_slot — caller's guard handles that.
async fn bind_mouse_addressed_slot(
    xhci_dev: &Xhci,
    slot_id: u8,
    speed: crate::xhci::PortSpeed,
) -> Result<(), HidError> {
    // Refresh EP0 MPS via Evaluate Context once the device tells
    // us its real bMaxPacketSize0. Same logic as kbd path
    // (audit F-22 + F-23).
    if let Ok(desc) = xhci_dev.get_device_descriptor(slot_id).await {
        let mps0 = desc[7] as u16;
        let want = match speed {
            crate::xhci::PortSpeed::Low | crate::xhci::PortSpeed::Full
                if matches!(mps0, 8 | 16 | 32 | 64) =>
            {
                Some(mps0)
            }
            crate::xhci::PortSpeed::High if mps0 == 64 => Some(64),
            crate::xhci::PortSpeed::Super | crate::xhci::PortSpeed::SuperPlus if mps0 <= 13 => {
                Some(1u16 << mps0)
            }
            _ => None,
        };
        if let Some(real_mps) = want {
            let _ = xhci_dev.evaluate_context_ep0_mps(slot_id, real_mps).await;
        }
    }

    let mut head = [0u8; 9];
    let n = xhci_dev
        .get_config_descriptor(slot_id, 0, &mut head)
        .await
        .map_err(HidError::Xhci)?;
    if n < 9 {
        return Err(HidError::NoInterruptIn);
    }
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=4096).contains(&total) {
        return Err(HidError::NoInterruptIn);
    }
    // bConfigurationValue lives at cfg-descriptor offset +5
    // (USB 2.0 §9.6.3 table 9-10). Required by SET_CONFIGURATION
    // below (audit F-62).
    let cfg_value = head[5];

    let mut full = alloc::vec![0u8; total];
    let n2 = xhci_dev
        .get_config_descriptor(slot_id, 0, &mut full)
        .await
        .map_err(HidError::Xhci)?;
    if n2 < total {
        full.truncate(n2);
    }

    let (iface, ep) = find_boot_mouse(&full)?;

    // Configure xHC-side endpoint contexts first (xHCI §4.3.6
    // recommends this *before* SET_CONFIGURATION so the rings
    // are ready when the device starts producing reports).
    xhci_dev
        .configure_endpoints(slot_id, &[ep])
        .await
        .map_err(HidError::Xhci)?;

    // SET_CONFIGURATION (audit F-62): without this the device
    // stays in Address state and class requests STALL. Same fix
    // as the kbd path picked up earlier.
    // bmRequestType: Host-to-Device | Standard | Device = 0x00.
    let mut nothing = [0u8; 0];
    xhci_dev
        .control_in(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &mut nothing,
        )
        .await
        .map_err(HidError::Xhci)?;

    let dci = ((ep.ep_addr & 0x0F) * 2) + 1;
    let m = BootMouse::attach(xhci_dev, slot_id, iface, dci).await?;
    {
        let mut g = MICE.lock();
        g.push(m);
        ATTACHED_MOUSE_COUNT.store(g.len() as u32, core::sync::atomic::Ordering::Release);
    }
    Ok(())
}

/// Lock-free count of bound mice. Same rationale as
/// `hid::ATTACHED_KEYBOARD_COUNT` — pump_all holds MICE for the
/// duration of every interrupt-IN read; the diagnostic path
/// must not contend on it.
pub static ATTACHED_MOUSE_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Number of mice currently bound. Lock-free read of the snapshot.
pub fn attached_mouse_count() -> usize {
    ATTACHED_MOUSE_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize
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
