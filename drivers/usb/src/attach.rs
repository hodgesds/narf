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

use crate::fingerprint;
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
    /// Device bound as a HID Consumer Control interface (Usage Page
    /// 0x0C: volume, media transport, brightness, sleep). Slot stays
    /// alive; entry added to `hid::consumer::CONSUMER_DEVICES`.
    ConsumerControl,
    /// Device bound as a CDC-ACM serial adaptor (USB-to-serial
    /// dongle, Arduino-style virtual COM port). Slot stays alive;
    /// entry was added to `cdc_acm::ACM_DEVICES`.
    SerialAcm,
    /// Device bound as a USB Mass Storage (BBB BOT) device. Slot
    /// stays alive; entry was added to `msc::MSC_DEVICES` and the
    /// block-layer registration / partition scan runs from the
    /// caller's hot path.
    MassStorage,
    /// Device bound as a USB Audio Class device (headset / mic /
    /// USB-DAC). Slot stays alive; entry in `uac::UAC_DEVICES`.
    /// Iso streaming path is a follow-up.
    AudioClass,
    /// Device bound as a USB Video Class device (webcam). Slot
    /// stays alive; entry in `uvc::UVC_DEVICES`. Iso frame ring is
    /// a follow-up.
    VideoClass,
    /// Device bound as a CDC-NCM ethernet adapter (USB-Ethernet
    /// dongle, tethered phone). Slot stays alive; entry in
    /// `cdc_ncm::CDC_NCM_DEVICES`. NTB TX/RX rings are a follow-up.
    NetworkClass,
    /// Device bound as a USB Bluetooth HCI controller (class 0xE0 /
    /// 0x01 / 0x01). Slot stays alive; entry in
    /// `btusb::BTUSB_DEVICES`. ACL data plane is a follow-up.
    Bluetooth,
    /// Device bound as a USB hub. Slot stays alive; entry was added
    /// to [`HUBS`] for downstream walking.
    Hub,
    /// Device recognised as a Windows Biometric Device Interface
    /// (WBDI) fingerprint reader via MS OS 2.0 Compatible-ID
    /// descriptor (compatible_id="WINUSB", sub_compatible_id="WBDI").
    /// Slot stays alive; recogniser logs the match for a future
    /// userland driver. Vendor command codec is intentionally NOT
    /// implemented clean-room (Goodix / Synaptics-Validity / ELAN
    /// formats are libfprint-derived).
    WbdiFingerprint,
    /// Device matched the explicit USB VID/PID fingerprint table
    /// (Synaptics, Goodix, ELAN). Slot stays alive; endpoints
    /// configured. Vendor command protocol is userspace-only.
    Fingerprint,
    /// Device bound as a USB CCID smart-card reader (class 0x0B /
    /// subclass 0x00 / protocol 0x00). Slot stays alive; entry in
    /// `ccid::CCID_READERS`. PC/SC daemon attaches via /dev/ccid0.
    CcidReader,
    /// Device claimed by a driver registered in the USB class-driver
    /// registry (e.g. rtl8xxxu USB-WiFi). Slot stays alive; the
    /// registered driver owns the device.
    UsbClassDriver,
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
    /// Bitmask of downstream ports the host has put into Suspend
    /// (via `UsbHub::port_suspend`). Tracked separately from
    /// `bound_downstream` because a port can be both bound and
    /// suspended (the device is bound but idle long enough to
    /// be suspended for power-saving).
    pub suspended_downstream: u64,
    /// Per-port last-activity tick. The supervisor records the
    /// current `narf_time` tick whenever a port's bound device
    /// sees an interrupt-IN transfer; if (now - last) exceeds
    /// the idle threshold, the supervisor suspends the port.
    /// `u64::MAX` means "active right now, never let it be
    /// suspended on the next pass" (used as a sentinel after
    /// `port_resume`).
    pub last_activity_tick: [u64; 64],
}

/// Global registry of bound hubs, BFS-ordered (the supervisor walks
/// it linearly each cycle, and tier-N hubs always appear after every
/// tier-(N-1) hub that hosts them, so a downstream walk in registry
/// order always processes a parent before its children).
pub static HUBS: IrqSafeSpinLock<Vec<HubBinding>> = IrqSafeSpinLock::new(Vec::new());

/// Idle window before the supervisor suspends a downstream port,
/// in nanoseconds. 30 seconds matches Linux's
/// `usb.autosuspend_delay_ms` default of 2000 ms / 2 s — we pick
/// a longer default to avoid suspend churn during typing pauses;
/// real laptops override this via a tunable.
pub const IDLE_SUSPEND_NS: u64 = 30 * 1_000_000_000;

/// Mark a downstream port as having seen activity *now*. Called
/// from each class driver's pump path so the supervisor's idle
/// timer resets on each interrupt-IN / bulk transfer that
/// completes. `parent_hub_idx` is the index into [`HUBS`] of the
/// hub the device is attached to; `port` is the per-hub port number.
pub fn mark_port_activity(parent_hub_idx: usize, port: u8) {
    let now = narf_time::monotonic_ns();
    let mut g = HUBS.lock();
    if let Some(h) = g.get_mut(parent_hub_idx) {
        if let Some(slot) = h.last_activity_tick.get_mut(port as usize & 63) {
            *slot = now;
        }
    }
}

/// Walk every bound hub + suspend any downstream port whose last
/// activity is older than `IDLE_SUSPEND_NS`. Called once per
/// supervisor cycle. Suspended ports stay in `bound_downstream`
/// (the device is still bound, just gated); the supervisor's
/// next-resume hook (a class driver requesting a transfer) calls
/// [`resume_port`] which clears the suspend bit on the hub side.
pub async fn idle_suspend_pass(xhci_dev: &crate::xhci::Xhci) -> usize {
    let now = narf_time::monotonic_ns();
    // Snapshot under the lock, dispatch outside so control
    // transfers (which can sleep) don't hold the registry lock.
    let work: alloc::vec::Vec<(usize, u8)> = {
        let g = HUBS.lock();
        let mut out = alloc::vec::Vec::new();
        for (idx, h) in g.iter().enumerate() {
            let num_ports = h.hub.descriptor.num_ports.min(64);
            for p in 1..=num_ports {
                let bit = 1u64 << (p as u32 & 63);
                // Only consider bound + non-suspended ports.
                if h.bound_downstream & bit == 0 {
                    continue;
                }
                if h.suspended_downstream & bit != 0 {
                    continue;
                }
                let last = h.last_activity_tick[p as usize & 63];
                if last == u64::MAX {
                    continue;
                }
                if now.saturating_sub(last) >= IDLE_SUSPEND_NS {
                    out.push((idx, p));
                }
            }
        }
        out
    };
    let mut suspended = 0;
    for (idx, p) in &work {
        // Snapshot the bound hub out of the registry lock so we don't
        // hold the IrqSafeSpinLock across the .await.
        let hub_copy: Option<crate::hub::UsbHub> = {
            let g = HUBS.lock();
            g.get(*idx).map(|h| h.hub)
        };
        let h = match hub_copy {
            Some(h) => h,
            None => continue,
        };
        if h.port_suspend(xhci_dev, *p).await.is_ok() {
            let mut g = HUBS.lock();
            if let Some(h) = g.get_mut(*idx) {
                h.suspended_downstream |= 1u64 << (*p as u32 & 63);
            }
            suspended += 1;
        }
    }
    suspended
}

/// Resume a previously suspended downstream port — called by a
/// class driver before it issues the next transfer that would
/// otherwise return NAK on a gated D+/D- pair. Idempotent:
/// no-op if the port wasn't suspended.
pub async fn resume_port(xhci_dev: &crate::xhci::Xhci, parent_hub_idx: usize, port: u8) {
    let bit = 1u64 << (port as u32 & 63);
    let hub_copy: Option<crate::hub::UsbHub> = {
        let g = HUBS.lock();
        match g.get(parent_hub_idx) {
            Some(h) if h.suspended_downstream & bit != 0 => Some(h.hub),
            _ => None,
        }
    };
    let h = match hub_copy {
        Some(h) => h,
        None => return,
    };
    // Issue CLEAR_FEATURE(PORT_SUSPEND) + ack the change bit without
    // holding the registry lock across the .await.
    if h.port_resume(xhci_dev, port).await.is_ok() {
        let mut g = HUBS.lock();
        if let Some(h) = g.get_mut(parent_hub_idx) {
            h.suspended_downstream &= !bit;
            // Sentinel value: prevent re-suspend on the very next
            // pass — let class driver do real work first.
            h.last_activity_tick[port as usize & 63] = u64::MAX;
        }
    }
}

/// Drive enumeration for a device on root-hub `port`. Returns the
/// outcome so the supervisor can update its claimed-bitmask state.
/// Slot is freed on failure (UnknownClass / class-driver error).
pub async fn try_attach_root(xhci_dev: &Xhci, port: u8) -> AttachOutcome {
    // port_reset → enable_slot → address_device (root-hub topology).
    // Each step runs against the controller's PORTSC register set.
    if xhci_dev.port_reset(port).await.is_err() {
        return AttachOutcome::UnknownClass;
    }
    let speed = match xhci_dev.port_speed(port) {
        Some(s) => s,
        None => return AttachOutcome::UnknownClass,
    };
    let slot_id = match xhci_dev.enable_slot().await {
        Ok(s) => s,
        Err(_) => return AttachOutcome::UnknownClass,
    };
    if xhci_dev.address_device(slot_id, port, speed).await.is_err() {
        let _ = xhci_dev.disable_slot(slot_id).await;
        return AttachOutcome::UnknownClass;
    }
    dispatch_after_address(xhci_dev, slot_id, port, speed, /*route*/ 0, /*root_port*/ port).await
}

/// Drive enumeration for a device on `hub_port` of an already-bound
/// `parent`. Uses the hub-class request `port_reset` + the
/// topology-aware `address_device_with`. Returns the outcome and the
/// caller updates `parent.bound_downstream` on success.
pub async fn try_attach_via_hub(
    xhci_dev: &Xhci,
    parent: &UsbHub,
    parent_route: u32,
    parent_tier: u32,
    parent_root_port: u8,
    hub_port: u8,
) -> AttachOutcome {
    if parent.port_reset(xhci_dev, hub_port).await.is_err() {
        return AttachOutcome::UnknownClass;
    }
    let speed = match parent.port_speed(xhci_dev, hub_port).await {
        Ok(s) => s,
        Err(_) => return AttachOutcome::UnknownClass,
    };
    let slot_id = match xhci_dev.enable_slot().await {
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
        .await
        .is_err()
    {
        let _ = xhci_dev.disable_slot(slot_id).await;
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
    .await
}

/// Free function so the dispatcher logic stays one place. `port` is
/// the per-hub port number used purely for HID-side error logging
/// dedup; `root_port` is the root-hub port that anchors the path.
async fn dispatch_after_address(
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
    // Also capture idVendor (+8) and idProduct (+10) for explicit
    // VID/PID matches (fingerprint readers with vendor class 0xFF
    // that don't advertise MS OS 2.0 WBDI descriptors).
    let (dev_class, dev_vid, dev_pid) = match xhci_dev.get_device_descriptor(slot_id).await {
        Ok(d) => {
            let vid = u16::from_le_bytes([d[8], d[9]]);
            let pid = u16::from_le_bytes([d[10], d[11]]);
            (d[4], vid, pid)
        }
        Err(_) => {
            let _ = xhci_dev.disable_slot(slot_id).await;
            return AttachOutcome::UnknownClass;
        }
    };

    if dev_class == DEV_CLASS_HUB {
        // Pull the configuration descriptor to find the hub
        // interface number (USB 2.0 §11.12.1: a hub presents
        // exactly one interface, class 0x09).
        let mut head = [0u8; 9];
        let n = xhci_dev.get_config_descriptor(slot_id, 0, &mut head).await;
        if n.is_err() || head.iter().take(2).all(|b| *b == 0) {
            let _ = xhci_dev.disable_slot(slot_id).await;
            return AttachOutcome::UnknownClass;
        }
        let total = u16::from_le_bytes([head[2], head[3]]) as usize;
        if !(9..=4096).contains(&total) {
            let _ = xhci_dev.disable_slot(slot_id).await;
            return AttachOutcome::UnknownClass;
        }
        let cfg_value = head[5];
        let mut full = alloc::vec![0u8; total];
        let n2 = match xhci_dev.get_config_descriptor(slot_id, 0, &mut full).await {
            Ok(n) => n,
            Err(_) => {
                let _ = xhci_dev.disable_slot(slot_id).await;
                return AttachOutcome::UnknownClass;
            }
        };
        if n2 < total {
            full.truncate(n2);
        }
        let iface = match hub::find_hub_interface(&full) {
            Some(i) => i,
            None => {
                let _ = xhci_dev.disable_slot(slot_id).await;
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
            .await
            .is_err()
        {
            let _ = xhci_dev.disable_slot(slot_id).await;
            return AttachOutcome::UnknownClass;
        }
        let bound = match UsbHub::attach(xhci_dev, slot_id, iface).await {
            Ok(b) => b,
            Err(_) => {
                let _ = xhci_dev.disable_slot(slot_id).await;
                return AttachOutcome::UnknownClass;
            }
        };
        // Flip the slot context's Hub bit + Number of Ports so the
        // controller sizes its TT-routing state for downstream
        // enumeration (xHCI 1.2 §6.2.2 dword0[26], dword1[31:24]).
        // Failure here isn't fatal — most controllers tolerate it.
        let _ = xhci_dev.mark_as_hub(slot_id, bound.descriptor.num_ports, /*mtt*/ false).await;
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
            suspended_downstream: 0,
            last_activity_tick: [0u64; 64],
        });
        return AttachOutcome::Hub;
    }

    // Not a hub — run the class-probe cascade. The dispatcher owns
    // slot lifecycle: each class binder is called with the same
    // already-addressed `slot_id` and MUST NOT call `disable_slot`
    // internally on failure. Only after every fallback has returned
    // UnknownClass do we disable_slot here (the terminal-mismatch
    // path). Linux pattern: `drivers/usb/core/hub.c::usb_new_device`
    // → `usb_set_configuration` → per-driver probe; the device
    // remains addressed until the dispatcher gives up.
    //
    // Order: HID Boot Keyboard (fast device-descriptor-only path) →
    // PTP touchpad → HID Boot Mouse → CDC-ACM → MSC → UAC → UVC →
    // CDC-NCM → btusb → WBDI fingerprint. Keyboard and mouse use
    // class-at-interface match; the rest fingerprint via the config
    // descriptor blob.
    if hid::try_bind_kbd_already_addressed(xhci_dev, slot_id, port, speed).await.is_ok() {
        return AttachOutcome::Keyboard;
    }
    // PTP touchpad / CDC-ACM serial / MSC / UAC / UVC / CDC-NCM /
    // btusb / mouse: every binder downstream consumes the device's
    // full configuration descriptor. Fetch once + hand to each in
    // turn so we don't issue multiple GET_DESCRIPTOR(CONFIG) round-
    // trips.
    if let Some(cfg_blob) = fetch_full_config(xhci_dev, slot_id).await {
        // PTP touchpad first — HID class with Report descriptor
        // shape matching a precision-touchpad device.
        if let Some((iface, hid_off, ep)) =
            hid::touchpad::find_hid_interface(&cfg_blob)
        {
            if hid::touchpad::try_bind_touchpad_already_addressed(
                xhci_dev, slot_id, iface, hid_off, &cfg_blob, ep,
            )
            .await
            .is_ok()
            {
                return AttachOutcome::Touchpad;
            }
        }
        // HID Consumer Control — Usage Page 0x0C (volume / media /
        // brightness). Runs after touchpad (same HID class, different
        // report-descriptor shape) and before Boot Mouse (protocol 2)
        // because consumer interfaces present protocol=0 and would
        // look like a non-boot HID device to the mouse scanner.
        if hid::consumer::try_bind_consumer_already_addressed(
            xhci_dev, slot_id, 0, &cfg_blob,
        )
        .await
        .is_ok()
        {
            return AttachOutcome::ConsumerControl;
        }
        // HID Boot Mouse — class 0x03 / subclass 0x01 / protocol
        // 0x02. Runs after touchpad so a PTP-capable touchpad isn't
        // demoted to a boot mouse, but before CDC-ACM so a USB mouse
        // isn't misclassified as a serial dongle.
        if mouse::find_boot_mouse(&cfg_blob).is_ok() {
            if mouse::try_bind_mouse_already_addressed(
                xhci_dev, slot_id, speed,
            )
            .await
            .is_ok()
            {
                return AttachOutcome::Mouse;
            }
        }
        // CDC-ACM serial — Comm + Data interface pair (bare or
        // IAD-led composite).
        if crate::cdc_acm::find_acm_interfaces(&cfg_blob).is_some() {
            if crate::cdc_acm::try_bind_cdc_acm_already_addressed(
                xhci_dev, slot_id, &cfg_blob, speed,
            )
            .await
            .is_ok()
            {
                return AttachOutcome::SerialAcm;
            }
        }
        // USB Mass Storage (BBB BOT) — bInterfaceClass=0x08,
        // SubClass=0x06, Protocol=0x50. `find_bot_endpoints`
        // walks the config blob; if it doesn't find an MSC
        // interface it returns EndpointsMissing and we fall through.
        if let Ok(_idx) = crate::msc::try_bind_msc_already_addressed(
            xhci_dev, slot_id, &cfg_blob,
        ).await {
            return AttachOutcome::MassStorage;
        }
        // USB Audio Class — class 0x01, subclass 0x01 (AC).
        if let Ok(_idx) = crate::uac::try_bind_audio_already_addressed(
            xhci_dev, slot_id, &cfg_blob,
        ).await {
            return AttachOutcome::AudioClass;
        }
        // USB Video Class — class 0x0E, subclass 0x01 (VC).
        if let Ok(_idx) = crate::uvc::try_bind_video_already_addressed(
            xhci_dev, slot_id, &cfg_blob,
        ).await {
            return AttachOutcome::VideoClass;
        }
        // CDC-NCM ethernet — class 0x02 (Comm), subclass 0x0D.
        if let Ok(_idx) = crate::cdc_ncm::try_bind_ncm_already_addressed(
            xhci_dev, slot_id, &cfg_blob,
        ).await {
            return AttachOutcome::NetworkClass;
        }
        // USB Bluetooth HCI — class 0xE0 / subclass 0x01 / proto 0x01.
        // `find_bt_endpoints` walks the config blob; if no matching
        // interface is present it returns NotBluetooth and we fall
        // through to the unknown-class log.
        if crate::btusb::try_bind_btusb_already_addressed(
            xhci_dev, slot_id, &cfg_blob,
        ).await.is_ok() {
            return AttachOutcome::Bluetooth;
        }
        // Explicit USB-ID fingerprint match — Synaptics, Goodix, ELAN.
        // Runs before the WBDI cascade because many of these devices
        // expose vendor class 0xFF but omit the MS OS 2.0 descriptor,
        // so the WBDI recogniser would never fire for them. At most
        // ~10 lines per the scope spec.
        if fingerprint::classify_vid_pid(dev_vid, dev_pid).is_some() {
            if fingerprint::try_bind_fingerprint_already_addressed(
                xhci_dev, slot_id, dev_vid, dev_pid, &cfg_blob,
            ).await.is_ok() {
                return AttachOutcome::Fingerprint;
            }
        }
        // USB CCID smart-card reader — class 0x0B / subclass 0x00 /
        // protocol 0x00. `find_ccid_interface` walks the config blob;
        // returns NotCcid if not present.
        if crate::ccid::try_bind_ccid_already_addressed(
            xhci_dev, slot_id, &cfg_blob,
        ).await.is_ok() {
            return AttachOutcome::CcidReader;
        }
        // WBDI fingerprint reader — Microsoft Biometric Device
        // Interface, identified by an MS OS 2.0 Compatible-ID
        // descriptor of "WINBIO". Last in the cascade because the
        // wire-up here is intentionally non-fatal: a positive WBDI
        // sniff records the device for a future userland driver
        // but doesn't seize the slot beyond logging.
        if crate::wbdi::try_bind_wbdi_already_addressed(
            xhci_dev, slot_id, &cfg_blob,
        ).await.is_ok() {
            return AttachOutcome::WbdiFingerprint;
        }
    }

    // USB class-driver registry — VID/PID match for drivers that
    // registered at Stage::Subsys (e.g. rtl8xxxu USB-WiFi dongles).
    // Runs after every built-in class probe so a RTL8188EU dongle
    // that looks like a CDC-ACM or vendor-class device doesn't get
    // misclassified. Linux analogue: `usb_probe_device` walking the
    // bus's driver list in `drivers/usb/core/driver.c` (~L310).
    if let Some(c) = xhci::controller() {
        use alloc::sync::Arc;
        // Wrap the slot in a USBDevice with the VID/PID we already
        // fetched so dispatch_probe can read vendor/product IDs
        // without a second GET_DESCRIPTOR round-trip.
        let mut dev = crate::device::USBDevice::new(c, slot_id, port, speed);
        dev.set_ids(dev_vid, dev_pid);
        let dev = Arc::new(dev);
        if crate::class_registry::dispatch_probe(dev) {
            return AttachOutcome::UsbClassDriver;
        }
    }

    // Terminal mismatch: every class probe returned UnknownClass.
    // Free the slot here, in the dispatcher, so the next port-reset
    // / enable-slot pair on this port doesn't trip the controller's
    // "port already assigned" Slot Context conflict. Log what the
    // device's interface descriptors looked like so a future class-
    // driver pass has a starting point.
    log_unknown_device_classes(xhci_dev, slot_id, port).await;
    let _ = xhci_dev.disable_slot(slot_id).await;
    AttachOutcome::UnknownClass
}

/// Read the device's first configuration descriptor in full so the
/// per-class binders can search it for their interface signature
/// without re-issuing GET_DESCRIPTOR. Returns the full blob (header
/// + interface + endpoint descriptors), or None on any error.
async fn fetch_full_config(xhci_dev: &Xhci, slot_id: u8) -> Option<alloc::vec::Vec<u8>> {
    let mut head = [0u8; 9];
    xhci_dev.get_config_descriptor(slot_id, 0, &mut head).await.ok()?;
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=4096).contains(&total) {
        return None;
    }
    let mut full = alloc::vec![0u8; total];
    let n = xhci_dev.get_config_descriptor(slot_id, 0, &mut full).await.ok()?;
    if n < total {
        full.truncate(n);
    }
    Some(full)
}

/// Walk the device's configuration descriptor and log the
/// (class, subclass, protocol) triple of every interface descriptor.
/// Useful for "what's on this port that we don't recognise" diagnosis
/// on real hardware. Quiet on failure — the device is being given up
/// on regardless.
async fn log_unknown_device_classes(xhci_dev: &Xhci, slot_id: u8, port: u8) {
    use core::fmt::Write as _;
    let mut head = [0u8; 9];
    if xhci_dev.get_config_descriptor(slot_id, 0, &mut head).await.is_err() {
        return;
    }
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=4096).contains(&total) {
        return;
    }
    let mut full = alloc::vec![0u8; total];
    let n = match xhci_dev.get_config_descriptor(slot_id, 0, &mut full).await {
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
                (0x0B, _) => "CCID",
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
