//! USB device-attach dispatcher with hub recursion — clean-room.
//!
//! References (public, non-GPL only):
//! - **eXtensible Host Controller Interface for Universal Serial Bus
//!   (xHCI)** Revision 1.2, May 2019 (Intel). §4.5.2 (Route String),
//!   §4.6.5 (Address Device), §6.2.2 (Slot Context Hub bit / TT
//!   fields).
//!   <https://www.intel.com/content/www/us/en/products/docs/io/universal-serial-bus/extensible-host-controler-interface-usb-xhci.html>
//! - **Universal Serial Bus Specification Revision 2.0** §11
//!   (Hub Specification).
//!   <https://www.usb.org/document-library/usb-20-specification>
//! - **Universal Serial Bus 3.2 Specification** Revision 1.1, June
//!   2022 (USB-IF). §10 (USB 3.x hub class extensions).
//!   <https://www.usb.org/document-library/usb-32-revision-11-june-2022>
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
use crate::hub::{self, UsbHub};
use crate::xhci::{self, PortSpeed, Xhci};

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
    /// Device bound as a vendor USB-serial adapter (FTDI /
    /// CP210x / PL2303 / CH341, VID/PID-matched by
    /// `serial::identify`). Slot stays alive; entry was added to
    /// `serial::port::SERIAL_PORTS` and a `/dev/ttyUSB<N>` node
    /// published via `serial::devfs_bridge`.
    SerialVendor,
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
    /// stays alive; entry in `uvc::UVC_DEVICES` and a `/dev/video<N>`
    /// node are registered. Streaming starts after PROBE/COMMIT.
    VideoClass,
    /// Device bound as a CDC-NCM ethernet adapter (USB-Ethernet
    /// dongle, tethered phone). Slot stays alive; entry in
    /// `cdc_ncm::CDC_NCM_DEVICES`; NTB TX/RX run through the
    /// record's bulk endpoints (negotiated at bind).
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
    /// Device bound as a FIDO2 authenticator (CTAP2 over USB HID;
    /// the report descriptor carries the FIDO Alliance usage page
    /// 0xF1D0 with 64-byte in/out reports). Slot stays alive;
    /// entry in `ctap::CTAP_TOKENS`. The suspend service opens a
    /// `narf_ctap2::Client` over the token via `ctap::open_client`.
    CtapToken,
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
    /// Per-port last-activity tick. Stamped by
    /// [`mark_ports_bound`] when the port binds (bind is activity —
    /// a port's idle window runs from bind, not from the boot epoch
    /// the array initialises to), then refreshed by
    /// [`mark_port_activity`] whenever a port's bound device
    /// completes a transfer; if (now - last) exceeds the idle
    /// threshold, the supervisor suspends the port.
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

/// Number of populated 4-bit hops in an xHCI route string. A hub on a
/// root-hub port has route zero/tier zero; a hub reached through port N
/// of that hub has one populated nibble and tier one.
pub(crate) const fn route_tier(route_string: u32) -> u32 {
    let route = route_string & 0x000F_FFFF;
    if route == 0 {
        0
    } else {
        let significant_bits = 32 - route.leading_zeros();
        significant_bits.div_ceil(4)
    }
}

/// Idle window before the supervisor suspends a downstream port,
/// in nanoseconds. 30 seconds matches Linux's
/// `usb.autosuspend_delay_ms` default of 2000 ms / 2 s — we pick
/// a longer default to avoid suspend churn during typing pauses;
/// real laptops override this via a tunable.
pub const IDLE_SUSPEND_NS: u64 = 30 * 1_000_000_000;

/// Mark a downstream port as having seen activity *now*. Called
/// from each class driver's pump path so the supervisor's idle
/// timer resets on each interrupt-IN / bulk transfer that
/// completes. `parent_hub_slot` is the xHCI slot id of the hub
/// the device is attached to; `port` is the per-hub port number.
/// The hub is resolved by slot id under one lock hold, never by
/// a cached [`HUBS`] index: hub detach removes entries with
/// `retain`, which shifts every later index, so a cached index
/// can silently name the wrong hub after a detach (#892).
pub fn mark_port_activity(parent_hub_slot: u8, port: u8) {
    let now = narf_time::monotonic_ns();
    let mut g = HUBS.lock();
    let pos = g.iter().position(|h| h.hub.slot_id == parent_hub_slot);
    if let Some(h) = pos.and_then(|p| g.get_mut(p)) {
        if let Some(slot) = h.last_activity_tick.get_mut(port as usize & 63) {
            *slot = now;
        }
    }
}

/// Record that the downstream ports in `bits` of hub
/// `parent_hub_slot` have just been bound, stamping each newly
/// bound port's last-activity tick to *now*. Called by the
/// supervisor in place of a bare `bound_downstream |= bits`:
/// without the stamp the tick keeps its initial value of 0 (the
/// boot epoch), so a device bound after the machine has been up
/// for [`IDLE_SUSPEND_NS`] would be suspended on the very next
/// pass — it never got an idle window (#840). The hub is
/// resolved by slot id (see [`mark_port_activity`]).
pub fn mark_ports_bound(parent_hub_slot: u8, bits: u64) {
    let now = narf_time::monotonic_ns();
    let mut g = HUBS.lock();
    let pos = g.iter().position(|h| h.hub.slot_id == parent_hub_slot);
    if let Some(h) = pos.and_then(|p| g.get_mut(p)) {
        h.bound_downstream |= bits;
        let mut rest = bits;
        while rest != 0 {
            let p = rest.trailing_zeros() as usize;
            rest &= rest - 1;
            if let Some(slot) = h.last_activity_tick.get_mut(p & 63) {
                *slot = now;
            }
        }
    }
}

/// Find the [`HUBS`] index of the hub occupying xHCI slot
/// `slot_id`. Retained as the documented resolver for tests
/// and for callers that hold a slot id but need an index for a
/// single atomic snapshot; long-lived hub context is keyed by
/// slot id instead (see [`mark_port_activity`]), because
/// `retain` on hub detach shifts every later index.
///
/// First-match is unambiguous: at most one entry can carry a
/// given slot id at any time, even once slot ids recycle — the
/// composition this branch must stay correct under once slot
/// reclamation (queue 10) and hub detach (queue 11) land. The
/// invariant rests on four pillars, each verifiable in-tree:
///   1. Entries are created at exactly one site — the hub arm
///      of `dispatch_after_address` — one push per successful
///      hub bind of an addressed slot.
///   2. A slot id returns to the allocatable pool only via
///      `Xhci::reclaim_slot`, whose sole caller is
///      `detach_slot`; and `detach_slot` removes *every* HUBS
///      entry for the slot (`retain`) strictly before it
///      disables and reclaims the slot. Attach-failure paths
///      call `disable_slot` but never `reclaim_slot`, so a
///      failed bind's id stays retired rather than recycling
///      under a live entry.
///   3. Wholesale controller recovery clears HUBS entirely
///      (`detach_all_bindings`) in the same supervisor step
///      that observes the recovery-epoch change, before any
///      re-enumeration can push a fresh entry.
///   4. Attach and detach both run in the single supervisor
///      task, and this helper's only production caller is the
///      supervisor's attach walk — no interleaving can observe
///      a half-detached registry or bind a child under a hub
///      whose entry is being removed.
///      A stale live entry would have to survive its occupant's
///      detach, which pillar 2 makes impossible: removal strictly
///      precedes reuse.
pub fn hub_index_for_slot(slot_id: u8) -> Option<usize> {
    let g = HUBS.lock();
    g.iter().position(|h| h.hub.slot_id == slot_id)
}

/// Pure per-port suspend decision behind [`idle_suspend_pass`]:
/// a port is idle-expired when its last-activity tick is at least
/// [`IDLE_SUSPEND_NS`] old. The `u64::MAX` sentinel (stamped by
/// [`resume_port`]) never expires — the class driver that resumed
/// the port replaces it with a real tick on its next completed
/// transfer via [`mark_port_activity`].
pub(crate) fn port_idle_expired(last_activity_tick: u64, now: u64) -> bool {
    last_activity_tick != u64::MAX && now.saturating_sub(last_activity_tick) >= IDLE_SUSPEND_NS
}

/// Select the (parent hub slot id, port) pairs
/// [`idle_suspend_pass`] should suspend from a registry
/// snapshot: bound, not already suspended, and idle-expired.
/// Slot ids, not [`HUBS`] indices: the pass re-resolves each
/// pair after an await, and a detach between snapshot and
/// re-resolution would shift a cached index onto the wrong
/// hub (#892). Split out from the pass itself so the
/// selection policy is unit-testable without a controller.
pub(crate) fn idle_suspend_candidates(hubs: &[HubBinding], now: u64) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    for h in hubs.iter() {
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
            if port_idle_expired(h.last_activity_tick[p as usize & 63], now) {
                out.push((h.hub.slot_id, p));
            }
        }
    }
    out
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
    // Pairs are (parent hub slot id, port); each pair is
    // re-resolved by slot id after the await, so a detach that
    // shifts [`HUBS`] indices between snapshot and clear can
    // neither suspend the wrong hub nor set the wrong hub's
    // suspend bit (#892).
    let work: alloc::vec::Vec<(u8, u8)> = {
        let g = HUBS.lock();
        idle_suspend_candidates(&g[..], now)
    };
    let mut suspended = 0;
    for (slot, p) in &work {
        // Snapshot the bound hub out of the registry lock so we don't
        // hold the IrqSafeSpinLock across the .await.
        let hub_copy: Option<crate::hub::UsbHub> = {
            let g = HUBS.lock();
            g.iter().find(|h| h.hub.slot_id == *slot).map(|h| h.hub)
        };
        let h = match hub_copy {
            Some(h) => h,
            None => continue,
        };
        if h.port_suspend(xhci_dev, *p).await.is_ok() {
            let mut g = HUBS.lock();
            if let Some(h) = g.iter_mut().find(|h| h.hub.slot_id == *slot) {
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
/// no-op if the port wasn't suspended. The hub is resolved by
/// slot id both before and after the await (see
/// [`mark_port_activity`]): re-resolving by a cached index
/// after the await could clear the wrong hub's suspend bit
/// if a detach shifted [`HUBS`] in between (#892).
pub async fn resume_port(xhci_dev: &crate::xhci::Xhci, parent_hub_slot: u8, port: u8) {
    let bit = 1u64 << (port as u32 & 63);
    let hub_copy: Option<crate::hub::UsbHub> = {
        let g = HUBS.lock();
        match g.iter().find(|h| h.hub.slot_id == parent_hub_slot) {
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
        if let Some(h) = g.iter_mut().find(|h| h.hub.slot_id == parent_hub_slot) {
            h.suspended_downstream &= !bit;
            // Sentinel value: prevent re-suspend on the very next
            // pass — let class driver do real work first.
            h.last_activity_tick[port as usize & 63] = u64::MAX;
        }
    }
}

/// True iff `port` of hub `parent_hub_slot` is currently marked
/// suspended in the registry — the bookkeeping bit
/// [`idle_suspend_pass`] sets and [`resume_port`] clears. This
/// is a registry read, not a hardware probe (the hardware-side
/// equivalent is `UsbHub::port_is_suspended`). Resolved by
/// slot id (see [`mark_port_activity`]).
pub fn hub_port_is_suspended(parent_hub_slot: u8, port: u8) -> bool {
    let g = HUBS.lock();
    match g.iter().find(|h| h.hub.slot_id == parent_hub_slot) {
        Some(h) => h.suspended_downstream & (1u64 << (port as u32 & 63)) != 0,
        None => false,
    }
}

/// Pure selection behind the supervisor's HID wake step: the
/// subset of `ports` — hub contexts recorded by class-driver
/// bindings — that names a bound, currently-suspended port.
/// Split out from `hid::resume_suspended_hub_ports` so the
/// selection policy is unit-testable without a controller,
/// mirroring [`idle_suspend_candidates`]. Duplicate pairs in
/// `ports` (a composite device can bind two classes on one
/// port) collapse to one entry.
pub(crate) fn suspended_ports_among(hubs: &[HubBinding], ports: &[(u8, u8)]) -> Vec<(u8, u8)> {
    let mut out: Vec<(u8, u8)> = Vec::new();
    for &(slot, port) in ports {
        let bit = 1u64 << (port as u32 & 63);
        let selected = match hubs.iter().find(|h| h.hub.slot_id == slot) {
            Some(h) => h.bound_downstream & bit != 0 && h.suspended_downstream & bit != 0,
            None => false,
        };
        if selected && !out.contains(&(slot, port)) {
            out.push((slot, port));
        }
    }
    out
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
    dispatch_after_address(
        xhci_dev, slot_id, port, speed, /*route*/ 0, /*root_port*/ port,
        /*parent_hub_slot*/ None,
    )
    .await
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
    let topology = parent.child_topology(parent_route, parent_tier, hub_port, speed);
    // For an LS/FS device attached to a high-speed hub, the
    // controller needs the parent hub's slot ID + the port the
    // device sits on (xHCI 1.2 §6.2.2 dword2[7:0] / [15:8]) so it
    // can route Transaction-Translator traffic correctly. HS+
    // devices leave these fields zero. UsbHub retains its negotiated
    // upstream speed, so child_topology only supplies TT metadata
    // when the parent is High and the child is Low/Full.
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
        Some(parent.slot_id),
    )
    .await
}

/// Tear down whatever is bound to `slot_id` — the disconnect-side
/// counterpart of [`try_attach_root`] / [`try_attach_via_hub`],
/// driven by the supervisor when a claimed port's connection
/// disappears (or a bound hub port's does).
///
/// Order is load-bearing:
///   1. Class bindings first, while the slot is still addressed:
///      every supervisor-pumped class drops its binding for the
///      slot (evdev nodes unregister, so `/dev/input/event<N>`
///      disappears), and registered class drivers get their
///      `dispatch_unbind` hook — a hook that reports failure
///      does not abort the remaining hooks (#893). After this
///      step nothing polls the slot.
///   2. Hub subtree: if the slot is a hub, every bound downstream
///      device is detached recursively (their ports die with the
///      hub), then the hub's own [`HUBS`] entry is removed.
///   3. Controller teardown: Disable Slot (its completion is the
///      hardware-quiescence proof), then `reclaim_slot` releases
///      all of the slot's DMA and returns the id to the pool, so a
///      replug re-runs attach from scratch — possibly on the same
///      slot id, always under a fresh generation.
///
/// Errors from the controller steps are deliberately swallowed: on
/// a genuine unplug the device is gone either way, and a slot whose
/// reclaim refuses (Disable Slot failed) stays retired rather than
/// returning to the pool half-alive. Classes the supervisor does
/// not pump (MSC / UAC / btusb / CCID) have no
/// per-class binding removal yet — their slot is disabled and
/// reclaimed here, but their class-level registries are a
/// documented follow-up in #748. CDC-NCM + r8152 + CDC-ECM are
/// NOT in that set: their unbind hooks
/// (`cdc_ncm::detach_ncm_slot`, `r8152::detach_r8152_slot`,
/// `cdc_ecm::detach_ecm_slot`, registered in their
/// `register_initcalls` / `register`) run via `dispatch_unbind`
/// in step 1 above, tombstoning the slot's binding and
/// unregistering its net iface. UVC is not in that set either: its
/// unbind hook (`uvc::detach_uvc`, registered in
/// `uvc::register_initcalls`) runs via `dispatch_unbind` in step 1
/// above, dropping the slot's UVC binding and unregistering its
/// `/dev/video<N>` node.
pub async fn detach_slot(xhci_dev: &Xhci, slot_id: u8) {
    // 1. Class bindings.
    hid::detach_boot_keyboard(slot_id);
    hid::keyboard::unregister_keyboard_evdev(slot_id);
    mouse::detach_mouse(slot_id);
    hid::touchpad::unregister_touchpad_evdev(slot_id);
    hid::consumer::detach_consumer(slot_id);
    hid::generic::unregister_generic_evdev(slot_id);
    crate::cdc_acm::detach_acm(slot_id);
    crate::serial::port::detach_serial(slot_id);
    crate::xpad::detach_xpad(slot_id);
    crate::class_registry::dispatch_unbind(slot_id);

    // 2. Hub subtree, then the hub's own registry entry.
    let subtree: Vec<u8> = {
        let g = HUBS.lock();
        let mut out = Vec::new();
        if let Some(h) = g.iter().find(|h| h.hub.slot_id == slot_id) {
            for dp in 1..=h.hub.descriptor.num_ports.min(64) {
                let bit = 1u64 << (dp as u32 & 63);
                if h.bound_downstream & bit == 0 {
                    continue;
                }
                let child_route =
                    xhci::Topology::for_downstream(h.route_string, h.tier, dp).route_string;
                if let Some(child) = xhci_dev.slot_for_route(h.root_hub_port, child_route) {
                    out.push(child);
                }
            }
        }
        out
    };
    for child in subtree {
        alloc::boxed::Box::pin(detach_slot(xhci_dev, child)).await;
    }
    HUBS.lock().retain(|h| h.hub.slot_id != slot_id);

    // 3. Controller teardown + DMA reclamation (queue 10).
    let _ = xhci_dev.disable_slot(slot_id).await;
    let _ = xhci_dev.reclaim_slot(slot_id);
}

/// Drop every binding the supervisor owns, without touching the
/// controller. Called when the controller recovery epoch changes
/// (`Xhci::recover_controller` has already invalidated every
/// generation, dropped every `Device` and reset the slot table, so
/// all bindings reference dead slots by construction).
///
/// What this drops, exactly: the supervisor-pumped classes are
/// cleared from their own registries (boot + report keyboards,
/// mouse, touchpad, consumer, generic, ACM, xpad), every bound
/// MSC device is removed from `MSC_DEVICES` and unpublished via
/// `msc::unbind_all_msc`, and the hub registry is cleared.
/// Registered class drivers' per-slot unbind hooks are NOT called
/// on this path, and classes with neither a pumped clear nor a
/// wholesale unbind here (UAC / btusb / CCID)
/// keep their class-level registries across recovery — the
/// documented remainder of #748. CDC-NCM + r8152 + CDC-ECM are
/// NOT in that set: `cdc_ncm::detach_all_ncm`,
/// `r8152::detach_all_r8152` and `cdc_ecm::detach_all_ecm`
/// tombstone every binding and unregister every net iface, so
/// re-enumeration cannot append a second live iface for the
/// same adapter. UVC is not in that set either: `uvc::detach_all_uvc` drops every
/// UVC binding and unregisters every video node, so re-enumeration
/// cannot append a second live node for the same camera. The MSC
/// call is load-bearing, not symmetry: a surviving `MSC_DEVICES`
/// entry would make re-enumeration append a second live adapter for
/// the same BOT device (queue 16, Concern C).
pub fn detach_all_bindings() {
    hid::clear_boot_keyboards();
    hid::keyboard::unregister_all_keyboards();
    mouse::clear_mice();
    hid::touchpad::unregister_all_touchpads();
    hid::consumer::clear_consumers();
    hid::generic::unregister_all_generic();
    crate::cdc_acm::clear_acm();
    crate::serial::port::clear_serial();
    crate::xpad::clear_xpad();
    crate::msc::unbind_all_msc();
    crate::cdc_ncm::detach_all_ncm();
    crate::r8152::detach_all_r8152();
    crate::cdc_ecm::detach_all_ecm();
    crate::uvc::detach_all_uvc();
    HUBS.lock().clear();
}

/// Free function so the dispatcher logic stays one place. `port` is
/// the per-hub port number used purely for HID-side error logging
/// dedup; `root_port` is the root-hub port that anchors the path.
/// `parent_hub_slot` is the xHCI slot id of the parent hub when
/// the device sits behind one (`None` on a root port); class
/// drivers that participate in hub idle-suspend (MSC and the
/// pumped HID classes) record it with their port so they can
/// resume / feed their port. Slot id, not [`HUBS`] index: the
/// recorded context outlives the bind cycle, and hub detach
/// shifts every later index (#892).
async fn dispatch_after_address(
    xhci_dev: &Xhci,
    slot_id: u8,
    port: u8,
    speed: PortSpeed,
    this_route: u32,
    root_port: u8,
    parent_hub_slot: Option<u8>,
) -> AttachOutcome {
    // GET_DESCRIPTOR(DEVICE) — bDeviceClass at offset +4 (USB 2.0
    // §9.6.1). 0x09 = Hub. 0x00 = "look at interface class" — most
    // devices go that route; we still try kbd/mouse below in that
    // case because their class lives at the interface.
    // Also capture idVendor (+8) and idProduct (+10) for explicit
    // VID/PID matches (fingerprint readers with vendor class 0xFF
    // that don't advertise MS OS 2.0 WBDI descriptors).
    let (dev_class, dev_protocol, dev_vid, dev_pid) =
        match xhci_dev.get_device_descriptor(slot_id).await {
            Ok(d) => {
                let vid = u16::from_le_bytes([d[8], d[9]]);
                let pid = u16::from_le_bytes([d[10], d[11]]);
                (d[4], d[6], vid, pid)
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
        if xhci_dev
            .control_out(
                slot_id,
                0x00,
                hid::STD_REQ_SET_CONFIGURATION,
                cfg_value as u16,
                0,
                &[],
            )
            .await
            .is_err()
        {
            let _ = xhci_dev.disable_slot(slot_id).await;
            return AttachOutcome::UnknownClass;
        }
        let bound = match UsbHub::attach(xhci_dev, slot_id, iface, dev_protocol, speed).await {
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
        let _ = xhci_dev
            .mark_as_hub(slot_id, bound.descriptor.num_ports, bound.is_multi_tt())
            .await;
        // Tier of THIS hub = number of 4-bit nibbles already
        // populated in `this_route`. For a tier-0 hub the route is
        // 0 and tier is 0; downstream-of-hub devices will use
        // tier+1 when calling `Topology::for_downstream`.
        let tier = route_tier(this_route);
        let _ = port; // port retained for parity with via_hub log-dedup
        {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  usb-hub: attached on root_port={} route=0x{:05x} tier={} num_ports={} multi_tt={} tt={}",
                root_port,
                this_route,
                tier,
                bound.descriptor.num_ports,
                bound.is_multi_tt(),
                bound.descriptor.tt_think_time(),
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
    if hid::try_bind_kbd_already_addressed(
        xhci_dev,
        slot_id,
        port,
        speed,
        parent_hub_slot.map(|slot| (slot, port)),
    )
    .await
    .is_ok()
    {
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
        if let Some((iface, hid_off, ep)) = hid::touchpad::find_hid_interface(&cfg_blob) {
            if hid::touchpad::try_bind_touchpad_already_addressed(
                xhci_dev,
                slot_id,
                iface,
                hid_off,
                &cfg_blob,
                ep,
                hid::identity::BindTopology {
                    port,
                    hub_port: parent_hub_slot.map(|slot| (slot, port)),
                },
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
            xhci_dev,
            slot_id,
            0,
            &cfg_blob,
            parent_hub_slot.map(|slot| (slot, port)),
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
        if mouse::find_boot_mouse(&cfg_blob).is_ok()
            && mouse::try_bind_mouse_already_addressed(
                xhci_dev,
                slot_id,
                speed,
                port,
                parent_hub_slot.map(|slot| (slot, port)),
            )
            .await
            .is_ok()
        {
            return AttachOutcome::Mouse;
        }
        // CDC-ACM serial — Comm + Data interface pair (bare or
        // IAD-led composite).
        if crate::cdc_acm::find_acm_interfaces(&cfg_blob).is_some()
            && crate::cdc_acm::try_bind_cdc_acm_already_addressed(
                xhci_dev,
                slot_id,
                &cfg_blob,
                speed,
                parent_hub_slot.map(|slot| (slot, port)),
            )
            .await
            .is_ok()
        {
            return AttachOutcome::SerialAcm;
        }
        // USB Mass Storage (BBB BOT) — bInterfaceClass=0x08,
        // SubClass=0x06, Protocol=0x50. `find_bot_endpoints`
        // walks the config blob; if it doesn't find an MSC
        // interface it returns EndpointsMissing and we fall through.
        if let Ok(_idx) = crate::msc::try_bind_msc_already_addressed(
            xhci_dev,
            slot_id,
            &cfg_blob,
            parent_hub_slot.map(|slot| (slot, port)),
        )
        .await
        {
            return AttachOutcome::MassStorage;
        }
        // USB Audio Class — class 0x01, subclass 0x01 (AC).
        if let Ok(_idx) =
            crate::uac::try_bind_audio_already_addressed(xhci_dev, slot_id, &cfg_blob).await
        {
            return AttachOutcome::AudioClass;
        }
        // USB Video Class — class 0x0E, subclass 0x01 (VC).
        if let Ok(_idx) =
            crate::uvc::try_bind_video_already_addressed(xhci_dev, slot_id, &cfg_blob).await
        {
            return AttachOutcome::VideoClass;
        }
        // CDC-NCM ethernet — class 0x02 (Comm), subclass 0x0D.
        if let Ok(_idx) =
            crate::cdc_ncm::try_bind_ncm_already_addressed(xhci_dev, slot_id, &cfg_blob).await
        {
            return AttachOutcome::NetworkClass;
        }
        // CDC-ECM ethernet — class 0x02 (Comm), subclass 0x06.
        // Tried after NCM: the finders are subclass-gated, so an
        // ECM device falls through NCM's attempt (NotEcm) and an
        // NCM device falls through ECM's the same way. Same
        // outcome: one Ethernet iface either way.
        if let Ok(_idx) =
            crate::cdc_ecm::try_bind_ecm_already_addressed(xhci_dev, slot_id, &cfg_blob).await
        {
            return AttachOutcome::NetworkClass;
        }
        // USB Bluetooth HCI — class 0xE0 / subclass 0x01 / proto 0x01.
        // `find_bt_endpoints` walks the config blob; if no matching
        // interface is present it returns NotBluetooth and we fall
        // through to the unknown-class log.
        if crate::btusb::try_bind_btusb_already_addressed(
            xhci_dev, slot_id, dev_vid, dev_pid, &cfg_blob,
        )
        .await
        .is_ok()
        {
            return AttachOutcome::Bluetooth;
        }
        // Explicit USB-ID fingerprint match — Synaptics, Goodix,
        // ELAN, Validity (single authority table, issue #918).
        // Runs before the WBDI cascade because many of these devices
        // expose vendor class 0xFF but omit the MS OS 2.0 descriptor,
        // so the WBDI recogniser would never fire for them. At most
        // ~10 lines per the scope spec.
        if fingerprint::classify_vid_pid(dev_vid, dev_pid).is_some()
            && fingerprint::try_bind_fingerprint_already_addressed(
                xhci_dev, slot_id, dev_vid, dev_pid, &cfg_blob,
            )
            .await
            .is_ok()
        {
            return AttachOutcome::Fingerprint;
        }
        // USB CCID smart-card reader — class 0x0B / subclass 0x00 /
        // protocol 0x00. `find_ccid_interface` walks the config blob;
        // returns NotCcid if not present.
        if crate::ccid::try_bind_ccid_already_addressed(xhci_dev, slot_id, &cfg_blob)
            .await
            .is_ok()
        {
            return AttachOutcome::CcidReader;
        }
        // FIDO2 authenticator — CTAP2 over USB HID (issue #999).
        // Runs late in the cascade on purpose: the binder's own
        // discrimination is the report descriptor's FIDO usage
        // page (0xF1D0), fetched per HID interface, so dedicated
        // HID classes above keep their devices and only genuine
        // tokens (which nothing above claims) land here.
        if crate::ctap::try_bind_ctap_already_addressed(xhci_dev, slot_id, &cfg_blob)
            .await
            .is_ok()
        {
            return AttachOutcome::CtapToken;
        }
        // Vendor USB-serial adapter (FTDI / Silicon Labs CP210x /
        // Prolific PL2303 / WCH CH341) — exact VID/PID match via
        // `serial::identify`; the binder programs the default line
        // format from the family's vendor programming guide and
        // publishes /dev/ttyUSB<N>. Placed after the class-based
        // probes (a CDC-ACM device with a serial VID must still
        // bind as ACM above) and before the WBDI sniff.
        if crate::serial::identify(dev_vid, dev_pid).is_some()
            && crate::serial::port::try_bind_serial_already_addressed(
                xhci_dev,
                slot_id,
                dev_vid,
                dev_pid,
                &cfg_blob,
                parent_hub_slot.map(|slot| (slot, port)),
            )
            .await
            .is_ok()
        {
            return AttachOutcome::SerialVendor;
        }
        // WBDI fingerprint reader — Microsoft Biometric Device
        // Interface, identified by an MS OS 2.0 Compatible-ID
        // descriptor of "WINBIO". Last in the cascade because the
        // wire-up here is intentionally non-fatal: a positive WBDI
        // sniff records the device for a future userland driver
        // but doesn't seize the slot beyond logging.
        if crate::wbdi::try_bind_wbdi_already_addressed(xhci_dev, slot_id, &cfg_blob)
            .await
            .is_ok()
        {
            return AttachOutcome::WbdiFingerprint;
        }

        // USB class-driver registry — VID/PID or interface-class
        // match for drivers registered at Stage::Subsys (e.g.
        // rtl8xxxu USB-WiFi dongles). Run it after every built-in
        // class probe so a broad registered match cannot steal a
        // device that has a dedicated binder. Passing the full
        // configuration descriptor is load-bearing: class-only
        // matches must inspect interface triples, not treat an
        // unknown 0000:0000 VID/PID as a wildcard for every device.
        if let Some(c) = xhci::controller() {
            use alloc::sync::Arc;
            // Wrap the slot in a USBDevice with the VID/PID we already
            // fetched so dispatch_probe can read vendor/product IDs
            // without a second GET_DESCRIPTOR round-trip.
            let mut dev = crate::device::USBDevice::new(c, slot_id, port, speed);
            dev.set_ids(dev_vid, dev_pid);
            let dev = Arc::new(dev);
            if crate::class_registry::dispatch_probe(dev, &cfg_blob) {
                return AttachOutcome::UsbClassDriver;
            }
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
    xhci_dev
        .get_config_descriptor(slot_id, 0, &mut head)
        .await
        .ok()?;
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=4096).contains(&total) {
        return None;
    }
    let mut full = alloc::vec![0u8; total];
    let n = xhci_dev
        .get_config_descriptor(slot_id, 0, &mut full)
        .await
        .ok()?;
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
    if xhci_dev
        .get_config_descriptor(slot_id, 0, &mut head)
        .await
        .is_err()
    {
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
                port,
                slot_id,
                cls,
                sub,
                prot,
                s
            );
        }
        i += len;
    }
}
