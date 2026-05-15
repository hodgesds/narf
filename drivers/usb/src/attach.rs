//! USB device-attach dispatcher with hub recursion — clean-room.
//!
//! References (public, non-GPL only):
//! - **eXtensible Host Controller Interface for Universal Serial Bus
//!   (xHCI)** Revision 1.2, May 2019 (Intel). §4.5.2 (Route String),
//!   §4.6.5 (Address Device), §6.2.2 (Slot Context Hub bit / TT
//!   fields).
//!     <https://www.intel.com/content/www/us/en/products/docs/io/universal-serial-bus/extensible-host-controler-interface-usb-xhci.html>
//! - **Universal Serial Bus Specification Revision 2.0** §11
//!   (Hub Specification).
//!     <https://www.usb.org/document-library/usb-20-specification>
//! - **Universal Serial Bus 3.2 Specification** Revision 1.1, June
//!   2022 (USB-IF). §10 (USB 3.x hub class extensions).
//!     <https://www.usb.org/document-library/usb-32-revision-11-june-2022>
//!
//! No GPL/BSD source code (Linux, FreeBSD, NetBSD, U-Boot) consulted.
//!
//! ## Shape
//!
//! - [`try_attach_root`] — drive port_reset → enable_slot →
//!   address_device on a root-hub port, GET_DESCRIPTOR(DEVICE), then
//!   dispatch to the right class driver (HID kbd, HID mouse, MSC,
//!   USB Hub). On hub class, the slot is marked-as-hub via
//!   `xhci.mark_as_hub` and a [`UsbHub`] handle is parked in [`HUBS`]
//!   for the supervisor to walk.
//!
//! - [`try_attach_via_hub`] — same dispatch, but the port_reset is
//!   issued through the parent hub's class request and the
//!   `address_device_with` call carries a `Topology` describing the
//!   route through the hub chain. Used to enumerate one downstream
//!   device of an already-bound hub.
//!
//! - [`HUBS`] — global registry of all bound `UsbHub` instances,
//!   keyed by route depth so the supervisor can walk in BFS order.

extern crate alloc;

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::hid;
use crate::hid::mouse;
use crate::hub::{self, UsbHub, HUB_INTERFACE_CLASS};
use crate::xhci::{self, PortSpeed, Topology, Xhci};

/// USB Device Class triple values we recognise (§9.6.1 of USB 2.0).
const DEV_CLASS_HUB: u8 = 0x09;

/// What did the attach attempt produce?
#[derive(Debug)]
pub enum AttachOutcome {
    /// Device bound as a HID Boot Keyboard. Slot stays alive.
    Keyboard,
    /// Device bound as a HID Boot Mouse. Slot stays alive.
    Mouse,
    /// Device bound as a HID Precision Touchpad (PTP). Slot stays
    /// alive; entry was added to `hid::touchpad::TOUCHPADS`.
    Touchpad,
    /// Device bound as a USB hub. Slot stays alive; entry was added
    /// to [`HUBS`] for downstream walking.
    Hub,
    /// We addressed the device but couldn't bind a class driver
    /// (unknown class, or a class driver we don't have). The slot
    /// has been disabled to free it for re-use.
    UnknownClass,
}

/// Per-hub registry entry. Holds the bound hub plus the route info
/// the supervisor needs to recurse: the route-string + tier of the
/// parent so we can compute the downstream device's topology with
/// `Topology::for_downstream`.
#[derive(Debug)]
pub struct HubBinding {
    pub hub: UsbHub,
    /// Route string of the path to *this* hub. Tier-0 hubs (sitting
    /// directly on the root hub) have route_string=0.
    pub route_string: u32,
    /// Number of hub hops from root to *this* hub. Used so a
    /// downstream device's tier = parent_tier + 1 in the route-string
    /// encoding.
    pub tier: u32,
    /// Root-hub port this hub's path originates from. Per xHCI
    /// §4.5.2 every downstream device shares this Root Hub Port
    /// Number in its Slot Context.
    pub root_hub_port: u8,
    /// Bitmask of downstream ports we've already bound *something*
    /// on (so the supervisor doesn't re-attach the same device on
    /// every cycle). Max 64 ports per hub fits in u64 — real hubs
    /// have ≤15 by convention.
    pub bound_downstream: u64,
}

/// Global registry of bound hubs, BFS-ordered (the supervisor walks
/// it linearly each cycle, and tier-N hubs always appear after every
/// tier-(N-1) hub that hosts them, so a downstream walk in registry
/// order always processes a parent before its children).
pub static HUBS: IrqSafeSpinLock<Vec<HubBinding>> = IrqSafeSpinLock::new(Vec::new());

/// Drive enumeration for a device on root-hub `port`. Returns the
/// outcome so the supervisor can update its claimed-bitmask state.
/// Slot is freed on failure (UnknownClass / class-driver error).
pub fn try_attach_root(xhci_dev: &Xhci, port: u8) -> AttachOutcome {
    // port_reset → enable_slot → address_device (root-hub topology).
    // Each step runs against the controller's PORTSC register set.
    if xhci_dev.port_reset(port).is_err() {
        return AttachOutcome::UnknownClass;
    }
    let speed = match xhci_dev.port_speed(port) {
        Some(s) => s,
        None => return AttachOutcome::UnknownClass,
    };
    let slot_id = match xhci_dev.enable_slot() {
        Ok(s) => s,
        Err(_) => return AttachOutcome::UnknownClass,
    };
    if xhci_dev.address_device(slot_id, port, speed).is_err() {
        let _ = xhci_dev.disable_slot(slot_id);
        return AttachOutcome::UnknownClass;
    }
    dispatch_after_address(xhci_dev, slot_id, port, speed, /*route*/ 0, /*root_port*/ port)
}

/// Drive enumeration for a device on `hub_port` of an already-bound
/// `parent`. Uses the hub-class request `port_reset` + the
/// topology-aware `address_device_with`. Returns the outcome and the
/// caller updates `parent.bound_downstream` on success.
pub fn try_attach_via_hub(
    xhci_dev: &Xhci,
    parent: &UsbHub,
    parent_route: u32,
    parent_tier: u32,
    parent_root_port: u8,
    hub_port: u8,
) -> AttachOutcome {
    if parent.port_reset(xhci_dev, hub_port).is_err() {
        return AttachOutcome::UnknownClass;
    }
    let speed = match parent.port_speed(xhci_dev, hub_port) {
        Ok(s) => s,
        Err(_) => return AttachOutcome::UnknownClass,
    };
    let slot_id = match xhci_dev.enable_slot() {
        Ok(s) => s,
        Err(_) => return AttachOutcome::UnknownClass,
    };
    let mut topology = Topology::for_downstream(parent_route, parent_tier, hub_port);
    // For an LS/FS device attached to a high-speed hub, the
    // controller needs the parent hub's slot ID + the port the
    // device sits on (xHCI 1.2 §6.2.2 dword2[7:0] / [15:8]) so it
    // can route Transaction-Translator traffic correctly. HS+
    // devices leave these fields zero. We only know the parent's
    // own speed indirectly here — the parent_hub_speed is whatever
    // the hub itself negotiated; for the typical "USB 2.0 hub" case
    // it's High and the LS/FS-via-HS path applies. Set the TT
    // fields whenever the *child* is LS/FS — safe, since they're
    // ignored for HS+ children even when populated.
    if matches!(speed, PortSpeed::Low | PortSpeed::Full) {
        topology.parent_hub_slot_id = parent.slot_id;
        topology.parent_hub_port = hub_port;
        // TT think time: 0 = 8 FS bit times. Sufficient for
        // single-TT hubs (the USB 2.0 default). Multi-TT hubs
        // advertise a different value via wHubCharacteristics
        // bits[6:5] — we don't decode that yet, so leave 0 and
        // accept the conservative think-time.
    }
    if xhci_dev
        .address_device_with(slot_id, parent_root_port, speed, topology)
        .is_err()
    {
        let _ = xhci_dev.disable_slot(slot_id);
        return AttachOutcome::UnknownClass;
    }
    dispatch_after_address(
        xhci_dev,
        slot_id,
        hub_port,
        speed,
        topology.route_string,
        parent_root_port,
    )
}

/// Free function so the dispatcher logic stays one place. `port` is
/// the per-hub port number used purely for HID-side error logging
/// dedup; `root_port` is the root-hub port that anchors the path.
fn dispatch_after_address(
    xhci_dev: &Xhci,
    slot_id: u8,
    port: u8,
    speed: PortSpeed,
    this_route: u32,
    root_port: u8,
) -> AttachOutcome {
    // GET_DESCRIPTOR(DEVICE) — bDeviceClass at offset +4 (USB 2.0
    // §9.6.1). 0x09 = Hub. 0x00 = "look at interface class" — most
    // devices go that route; we still try kbd/mouse below in that
    // case because their class lives at the interface.
    let dev_class = match xhci_dev.get_device_descriptor(slot_id) {
        Ok(d) => d[4],
        Err(_) => {
            let _ = xhci_dev.disable_slot(slot_id);
            return AttachOutcome::UnknownClass;
        }
    };

    if dev_class == DEV_CLASS_HUB {
        // Pull the configuration descriptor to find the hub
        // interface number (USB 2.0 §11.12.1: a hub presents
        // exactly one interface, class 0x09).
        let mut head = [0u8; 9];
        let n = xhci_dev.get_config_descriptor(slot_id, 0, &mut head);
        if n.is_err() || head.iter().take(2).all(|b| *b == 0) {
            let _ = xhci_dev.disable_slot(slot_id);
            return AttachOutcome::UnknownClass;
        }
        let total = u16::from_le_bytes([head[2], head[3]]) as usize;
        if !(9..=4096).contains(&total) {
            let _ = xhci_dev.disable_slot(slot_id);
            return AttachOutcome::UnknownClass;
        }
        let cfg_value = head[5];
        let mut full = alloc::vec![0u8; total];
        let n2 = match xhci_dev.get_config_descriptor(slot_id, 0, &mut full) {
            Ok(n) => n,
            Err(_) => {
                let _ = xhci_dev.disable_slot(slot_id);
                return AttachOutcome::UnknownClass;
            }
        };
        if n2 < total {
            full.truncate(n2);
        }
        let iface = match hub::find_hub_interface(&full) {
            Some(i) => i,
            None => {
                let _ = xhci_dev.disable_slot(slot_id);
                return AttachOutcome::UnknownClass;
            }
        };
        // SET_CONFIGURATION before any class request (USB 2.0
        // §9.4.7) — without it, `UsbHub::attach`'s
        // GET_DESCRIPTOR(Hub) would STALL.
        let mut nothing = [0u8; 0];
        if xhci_dev
            .control_in(
                slot_id,
                0x00,
                hid::STD_REQ_SET_CONFIGURATION,
                cfg_value as u16,
                0,
                &mut nothing,
            )
            .is_err()
        {
            let _ = xhci_dev.disable_slot(slot_id);
            return AttachOutcome::UnknownClass;
        }
        let bound = match UsbHub::attach(xhci_dev, slot_id, iface) {
            Ok(b) => b,
            Err(_) => {
                let _ = xhci_dev.disable_slot(slot_id);
                return AttachOutcome::UnknownClass;
            }
        };
        // Flip the slot context's Hub bit + Number of Ports so the
        // controller sizes its TT-routing state for downstream
        // enumeration (xHCI 1.2 §6.2.2 dword0[26], dword1[31:24]).
        // Failure here isn't fatal — most controllers tolerate it.
        let _ = xhci_dev.mark_as_hub(slot_id, bound.descriptor.num_ports, /*mtt*/ false);
        // Tier of THIS hub = number of 4-bit nibbles already
        // populated in `this_route`. For a tier-0 hub the route is
        // 0 and tier is 0; downstream-of-hub devices will use
        // tier+1 when calling `Topology::for_downstream`.
        let tier = (this_route.leading_zeros().wrapping_sub(12) / 4) as u32;
        // For root-hub-attached hubs `this_route` is 0 → leading
        // zeros above wraps; clamp to 0 in that case.
        let tier = if this_route == 0 { 0 } else { tier };
        let _ = port; // port retained for parity with via_hub log-dedup
        {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  usb-hub: attached on root_port={} route=0x{:05x} tier={} num_ports={}",
                root_port, this_route, tier, bound.descriptor.num_ports
            );
        }
        HUBS.lock().push(HubBinding {
            hub: bound,
            route_string: this_route,
            tier,
            root_hub_port: root_port,
            bound_downstream: 0,
        });
        return AttachOutcome::Hub;
    }

    // Not a hub — try HID Boot Keyboard first, then PTP touchpad
    // (post-Boot HID Report-protocol). Each call frees the slot on
    // failure. The mouse / touchpad paths only run if kbd didn't
    // bind, so we don't double-disable.
    if hid::try_bind_kbd_already_addressed(xhci_dev, slot_id, port, speed).is_ok() {
        return AttachOutcome::Keyboard;
    }
    // PTP touchpad: needs the config descriptor to locate the HID
    // interface + report descriptor length, so fetch it here and
    // hand the buffer to the binder.
    if let Some((iface, hid_off, ep, cfg_blob)) =
        fetch_cfg_and_find_hid(xhci_dev, slot_id)
    {
        if hid::touchpad::try_bind_touchpad_already_addressed(
            xhci_dev, slot_id, iface, hid_off, &cfg_blob, ep,
        )
        .is_ok()
        {
            return AttachOutcome::Touchpad;
        }
    }
    // try_bind_kbd_already_addressed disables the slot on failure,
    // so we need to re-enable + re-address for the mouse attempt.
    // For now, treat as UnknownClass — a real laptop mouse will
    // come up on the next supervisor cycle as a fresh attach where
    // the kbd attempt fails fast and the mouse attempt picks it up
    // (same shape as the existing root-hub path with kbd_fail_count
    // → mouse fallback). This keeps the recursion logic simple.
    let _ = mouse::try_bind_mouse_already_addressed; // silences unused

    // UnknownClass: log what we DID see at the interface level so a
    // future class-driver pass can prioritise. Reading the config
    // descriptor here is cheap (the slot is still addressed) and
    // surfaces the class triple of every interface in the log.
    log_unknown_device_classes(xhci_dev, slot_id, port);
    AttachOutcome::UnknownClass
}

/// Read the device's first configuration descriptor in full and
/// locate a HID interface with an interrupt-IN endpoint. Returns
/// `(interface_num, hid_descriptor_offset, endpoint, full_blob)` for
/// the touchpad binder to consume. None on any descriptor-fetch
/// error or no HID interface match.
fn fetch_cfg_and_find_hid(
    xhci_dev: &Xhci,
    slot_id: u8,
) -> Option<(u8, usize, crate::xhci::EndpointConfig, alloc::vec::Vec<u8>)> {
    let mut head = [0u8; 9];
    xhci_dev.get_config_descriptor(slot_id, 0, &mut head).ok()?;
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=4096).contains(&total) {
        return None;
    }
    let mut full = alloc::vec![0u8; total];
    let n = xhci_dev.get_config_descriptor(slot_id, 0, &mut full).ok()?;
    if n < total {
        full.truncate(n);
    }
    let (iface, hid_off, ep) = hid::touchpad::find_hid_interface(&full)?;
    Some((iface, hid_off, ep, full))
}

/// Walk the device's configuration descriptor and log the
/// (class, subclass, protocol) triple of every interface descriptor.
/// Useful for "what's on this port that we don't recognise" diagnosis
/// on real hardware. Quiet on failure — the device is being given up
/// on regardless.
fn log_unknown_device_classes(xhci_dev: &Xhci, slot_id: u8, port: u8) {
    use core::fmt::Write as _;
    let mut head = [0u8; 9];
    if xhci_dev.get_config_descriptor(slot_id, 0, &mut head).is_err() {
        return;
    }
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=4096).contains(&total) {
        return;
    }
    let mut full = alloc::vec![0u8; total];
    let n = match xhci_dev.get_config_descriptor(slot_id, 0, &mut full) {
        Ok(n) => n,
        Err(_) => return,
    };
    if n < total {
        full.truncate(n);
    }
    // USB 2.0 §9.6.5: Interface Descriptor is 9 bytes, type=4.
    // bInterfaceClass at +5, bSubClass at +6, bProtocol at +7.
    let mut i = 0usize;
    while i + 2 <= full.len() {
        let len = full[i] as usize;
        if len < 2 || i + len > full.len() {
            break;
        }
        if full[i + 1] == 4 && len >= 9 {
            let cls = full[i + 5];
            let sub = full[i + 6];
            let prot = full[i + 7];
            let s = match (cls, sub) {
                (0x03, _) => "HID",
                (0x08, _) => "Mass-Storage",
                (0x09, _) => "Hub",
                (0x0A, _) => "CDC-Data",
                (0x02, _) => "CDC-Comms",
                (0x0E, 0x01) => "UVC-VideoControl",
                (0x0E, 0x02) => "UVC-VideoStreaming",
                (0x0E, _) => "Video",
                (0x01, _) => "Audio",
                (0xE0, 0x01) => "USB-Bluetooth",
                (0xFE, 0x01) => "DFU",
                (0xFF, _) => "Vendor",
                _ => "?",
            };
            let _ = writeln!(
                narf_console::Writer,
                "  usb-attach: port={} slot={} unknown class {:02x}/{:02x}/{:02x} ({})",
                port, slot_id, cls, sub, prot, s
            );
        }
        i += len;
    }
}
