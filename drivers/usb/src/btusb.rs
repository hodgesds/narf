//! USB Bluetooth HCI transport — Stage 0.
//!
//! ## References (public-only)
//!
//! - **Bluetooth Core Specification 5.3, Vol 4 Part B** — USB
//!   Transport Layer. Defines the four-endpoint split (default
//!   control / interrupt-IN events / bulk-IN ACL / bulk-OUT ACL,
//!   plus optional isoch SCO), the class-specific SETUP packet
//!   used to wrap HCI Commands, and the per-packet wire format.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//! - **Bluetooth Core Specification 5.3, Vol 4 Part E** — HCI
//!   Functional Specification (§7.3 Mandatory commands, §7.7
//!   Events, §7.4 Informational Parameters).
//! - **USB Class Definitions for Wireless Controllers v1.0**,
//!   USB-IF, 2007. Class triple `0xE0 / 0x01 / 0x01`.
//!   <https://www.usb.org/document-library/usb-class-definitions-wireless-controllers-10>
//! - **Linux `drivers/bluetooth/btusb.c`** — GPL-2.0; consulted
//!   per NARF 2026-05-20 relicense to GPL-2.0-or-later. We mirror
//!   the endpoint-discovery shape (bulk pair + interrupt-IN) and
//!   the post-attach Reset / Read_Local_Version probe sequence.
//! - **Linux `drivers/bluetooth/btusb.c` QCA USB setup** — GPL-2.0;
//!   WCN6855 version/status control requests and split control/bulk
//!   firmware download, including runtime firmware-name selection.
//!
//! ## Stage 0 scope
//!
//! 1. Recognise interface (class=0xE0, subclass=0x01, protocol=0x01).
//! 2. Walk the configuration descriptor for the bulk-IN/OUT ACL pair
//!    and the interrupt-IN event endpoint.
//! 3. Configure those endpoints + issue SET_CONFIGURATION.
//! 4. Apply required USB vendor firmware setup for recognised parts
//!    (Qualcomm WCN6855, Intel AX200/AX210-class, MediaTek
//!    MT7921/MT7922) before exposing the HCI transport.
//! 5. Drive mandatory HCI bring-up directly against the xHCI async
//!    transfer paths: Reset → version → BD_ADDR → buffer sizes → event mask.
//! 6. Log `bluetooth: $vendor adapter, HCI v$ver, Bluetooth $bt_ver`.
//! 7. Register an `HciTransport` against the slot for Stage-1+ users.
//! 8. SCO/eSCO isochronous transport (issue #817): record the SCO
//!    isoch endpoints of every alternate setting at bind, select
//!    the largest-budget alternate (see `BtEndpoints::best_sco_alt`),
//!    configure its isoch endpoints together with the base three,
//!    SET_INTERFACE to it after SET_CONFIGURATION, and carry SCO
//!    packets over isoch (`send_sco` / `recv_sco`). A device with
//!    no isoch endpoints still binds for ACL/events; its transport
//!    refuses SCO with `TransportError::Unsupported` instead of
//!    silently routing SCO to bulk-OUT.
//!
//! Out of scope for Stage 0: LE Advertising and BR/EDR Inquiry.
//! Those land as separate stages. (The ACL data plane is driven by
//! the `narf_bluetooth::pump` task registered at bring-up.)
//!
//! Why a per-driver async bring-up instead of routing through the
//! existing `narf_bluetooth::controller::Controller::bring_up`:
//! `Controller::bring_up` is synchronous and goes through the
//! `HciTransport` trait, which is also synchronous. Calling
//! `narf_scheduler::block_on` from inside the supervisor's executor
//! poll panics by design. So Stage-0 bring-up runs as an inline
//! async dance using `xhci.control_out` / `xhci.poll_interrupt_in`
//! directly, and the trait-based transport is registered afterwards.
//! Its sync methods bridge via `narf_scheduler::block_on_spin`
//! (not the halting `block_on`), which is safe from inside the
//! pump task's executor poll — see the `UsbHciTransport` docs.
//! The completed controller is adopted into the shared
//! ready registry without rerunning synchronous bring-up.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use narf_bluetooth::controller::ControllerInfo;
use narf_bluetooth::event::{CommandComplete, CommandStatus, EventCode};
use narf_bluetooth::hci::{Command, Event};
use narf_bluetooth::opcode as op;
use narf_bluetooth::transport::{HciTransport, TransportError};
use narf_lib::sync::IrqSafeSpinLock;

use crate::xhci::{EndpointConfig, EndpointKind, Xhci};

/// USB Class — Wireless Controller.
pub const USB_CLASS_WIRELESS: u8 = 0xE0;
/// USB Subclass — RF Controller.
pub const USB_SUBCLASS_RF: u8 = 0x01;
/// USB Protocol — Bluetooth Programming Interface.
pub const USB_PROTOCOL_BLUETOOTH: u8 = 0x01;

/// `bmRequestType` for an HCI Command transfer — Class | Interface |
/// Host-to-Device, per Vol 4 Part B §2.2.1.
const RT_HCI_COMMAND: u8 = 0x20;
/// `bRequest` for an HCI Command transfer — zero (Vol 4 Part B §2.2.1).
const REQ_HCI_COMMAND: u8 = 0x00;

/// Standard USB SET_CONFIGURATION request — USB 2.0 §9.4.7.
const STD_REQ_SET_CONFIGURATION: u8 = 0x09;

/// Standard USB SET_INTERFACE request — USB 2.0 §9.4.10.
/// `bmRequestType` 0x01 (Host-to-Device, Standard, Interface),
/// `wValue` = alternate setting, `wIndex` = interface number.
const STD_REQ_SET_INTERFACE: u8 = 0x0B;
/// `bmRequestType` for SET_INTERFACE (Host-to-Device | Standard |
/// Interface).
const RT_SET_INTERFACE: u8 = 0x01;

/// Length of an HCI SCO Data packet header (Vol 4 Part E §5.4.3:
/// 16-bit handle+flags, 8-bit length). The isoch endpoint's
/// `wMaxPacketSize` must cover header + payload.
pub const SCO_PACKET_HEADER_LEN: usize = 3;

/// Maximum number of SCO alternate settings recorded per device.
/// The Bluetooth USB layout is alt 0 (no isoch endpoints) plus
/// one isoch-carrying alternate per SCO packet size the device
/// offers; 8 slots cover that shape with a spare. A device
/// advertising more isoch alternates has its first 8 recorded and
/// the rest ignored — discovery never fails on a long alt table.
pub const MAX_SCO_ALT_SETTINGS: usize = 8;

/// One alternate setting of the HCI interface that carries SCO
/// isochronous endpoints (Vol 4 Part B §2.1: the isoch pair is
/// optional and appears only under non-zero alternate settings,
/// one setting per isoch packet budget).
///
/// A setting is *selectable* only when both directions are
/// present — SCO is bidirectional, and a half-populated setting
/// cannot carry a call. Discovery still records partial settings
/// so diagnostics can show what the device offered.
#[derive(Copy, Clone, Debug)]
pub struct ScoAltSetting {
    /// `bAlternateSetting` of the interface descriptor that owns
    /// these endpoints.
    pub alt_setting: u8,
    /// Isochronous-IN endpoint carrying SCO data device→host.
    pub sco_in: Option<EndpointConfig>,
    /// Isochronous-OUT endpoint carrying SCO data host→device.
    pub sco_out: Option<EndpointConfig>,
}

impl ScoAltSetting {
    /// Both isoch directions present.
    pub fn is_complete(self) -> bool {
        self.sco_in.is_some() && self.sco_out.is_some()
    }

    /// Smallest of the two directions' `wMaxPacketSize` values —
    /// the per-packet budget a SCO packet must fit in both
    /// directions. `None` when the setting is incomplete.
    pub fn packet_budget(self) -> Option<u16> {
        match (self.sco_in, self.sco_out) {
            (Some(i), Some(o)) => Some(i.max_packet.min(o.max_packet)),
            _ => None,
        }
    }
}

/// Endpoints required for a Stage-0 HCI USB transport.
#[derive(Copy, Clone, Debug)]
pub struct BtEndpoints {
    /// `bInterfaceNumber` of the HCI interface.
    pub interface: u8,
    /// Configuration value the device wants in SET_CONFIGURATION.
    pub config_value: u8,
    /// Interrupt-IN endpoint carrying HCI Events.
    pub event_in: EndpointConfig,
    /// Bulk-IN endpoint carrying ACL data device→host.
    pub acl_in: EndpointConfig,
    /// Bulk-OUT endpoint carrying ACL data host→device.
    pub acl_out: EndpointConfig,
    /// SCO isoch alternate settings, in descriptor order. `None`
    /// slots are unused. Alt 0 (no isoch endpoints) never appears
    /// here — only settings that carry at least one isoch endpoint.
    /// Empty when the device offers no SCO transport at all.
    pub sco_alts: [Option<ScoAltSetting>; MAX_SCO_ALT_SETTINGS],
}

impl BtEndpoints {
    /// Number of recorded SCO alternate settings.
    pub fn sco_alt_count(self) -> usize {
        self.sco_alts.iter().filter(|a| a.is_some()).count()
    }

    /// `true` when the device offers any SCO isoch transport.
    pub fn has_sco(self) -> bool {
        self.sco_alts.iter().flatten().any(|a| a.is_complete())
    }

    /// The complete SCO alternate with the largest per-packet
    /// budget (ties → lowest alternate number). This is the bind-time
    /// choice: the controller's SCO MTU is only known after
    /// HCI_Read_Buffer_Size, and the xHC endpoint contexts are
    /// configured exactly once at bind, so bind configures the
    /// largest budget — every SCO packet the device offers then
    /// fits, and `select_sco_alt_setting` can only switch down.
    pub fn best_sco_alt(self) -> Option<ScoAltSetting> {
        let mut best: Option<ScoAltSetting> = None;
        for alt in self.sco_alts.iter().flatten() {
            if !alt.is_complete() {
                continue;
            }
            let budget = alt.packet_budget().unwrap_or(0);
            let better = match best {
                None => true,
                Some(b) => {
                    budget > b.packet_budget().unwrap_or(0)
                        || (budget == b.packet_budget().unwrap_or(0)
                            && alt.alt_setting < b.alt_setting)
                }
            };
            if better {
                best = Some(*alt);
            }
        }
        best
    }

    /// The complete SCO alternate with the smallest budget that
    /// still fits a SCO packet carrying `payload_len` payload bytes
    /// (budget ≥ `payload_len + SCO_PACKET_HEADER_LEN`); ties →
    /// lowest alternate number. `None` when no recorded alternate
    /// fits — the caller must refuse the packet, never truncate it
    /// or route it to another endpoint.
    pub fn sco_alt_for_payload(self, payload_len: usize) -> Option<ScoAltSetting> {
        // Compared in `usize`: truncating `need` to `u16` would wrap
        // a huge payload to a small budget and select an alternate
        // that cannot carry it.
        let need = payload_len.saturating_add(SCO_PACKET_HEADER_LEN);
        self.sco_alts
            .iter()
            .flatten()
            .filter(|a| a.is_complete())
            .filter(|a| a.packet_budget().unwrap_or(0) as usize >= need)
            .min_by_key(|a| (a.packet_budget().unwrap_or(0), a.alt_setting))
            .copied()
    }
}

/// Errors returned from the bind path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BtUsbError {
    /// Configuration descriptor did not declare a 0xE0/0x01/0x01
    /// interface, or required endpoints were missing.
    NotBluetooth,
    /// `configure_endpoints` failed.
    EndpointConfig,
    /// SET_CONFIGURATION failed.
    SetConfiguration,
    /// HCI Command transfer failed at the USB layer.
    CommandTransfer,
    /// HCI Event poll did not produce a valid response within the
    /// 5-second per-command budget (Vol 4 Part E §6).
    EventTimeout,
    /// HCI Command Complete carried a non-zero Status byte.
    BadStatus(u8),
    /// HCI Command Complete carried an opcode we did not issue.
    OpcodeMismatch,
    /// HCI Command Complete return params were shorter than the spec
    /// requires for the issued opcode.
    ShortReturnParams,
    /// A recognised controller's vendor firmware setup failed.
    FirmwareSetup,
}

/// Walk a Configuration Descriptor for the *first* HCI interface and
/// resolve the three required endpoints. Returns `Err(NotBluetooth)`
/// if no matching interface exists, or one with the required endpoints
/// is missing.
///
/// Also records the SCO isochronous endpoints of every alternate
/// setting of that interface (`BtEndpoints::sco_alts`): alt 0
/// normally carries only the base three endpoints, and each
/// non-zero alternate adds an isoch IN/OUT pair with a larger
/// `wMaxPacketSize` (Vol 4 Part B §2.1). A device with no isoch
/// endpoint in any alternate still resolves — `sco_alts` is empty
/// and SCO is refused at the transport, not at discovery.
///
/// Wire layout per USB 2.0 §9.6.5 (Interface) / §9.6.6 (Endpoint).
/// `bmAttributes` low 2 bits = transfer type: 0 control, 1 isoch,
/// 2 bulk, 3 interrupt.
pub fn find_bt_endpoints(cfg: &[u8]) -> Result<BtEndpoints, BtUsbError> {
    if cfg.len() < 9 || cfg[1] != 0x02 {
        return Err(BtUsbError::NotBluetooth);
    }
    let config_value = cfg[5];

    let mut i = 0usize;
    let mut interface: Option<u8> = None;
    let mut event_in: Option<EndpointConfig> = None;
    let mut acl_in: Option<EndpointConfig> = None;
    let mut acl_out: Option<EndpointConfig> = None;
    let mut in_match = false;
    // `bAlternateSetting` of the interface descriptor most
    // recently seen while `in_match` is true.
    let mut alt_setting: u8 = 0;
    let mut sco_alts: [Option<ScoAltSetting>; MAX_SCO_ALT_SETTINGS] = [None; MAX_SCO_ALT_SETTINGS];

    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        match cfg[i + 1] {
            // Interface Descriptor (§9.6.5).
            4 if len >= 9 => {
                let class = cfg[i + 5];
                let sub = cfg[i + 6];
                let proto = cfg[i + 7];
                in_match = class == USB_CLASS_WIRELESS
                    && sub == USB_SUBCLASS_RF
                    && proto == USB_PROTOCOL_BLUETOOTH;
                if in_match {
                    if interface.is_none() {
                        interface = Some(cfg[i + 2]);
                    }
                    alt_setting = cfg[i + 3];
                }
            }
            // Endpoint Descriptor (§9.6.6).
            5 if len >= 7 && in_match => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer = attr & 0x03;
                let is_in = ep_addr & 0x80 != 0;
                match (xfer, is_in) {
                    // Interrupt-IN — HCI Events.
                    (3, true) if event_in.is_none() => {
                        event_in = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::InterruptIn,
                            interval: cfg[i + 6],
                        });
                    }
                    // Bulk-IN — ACL data.
                    (2, true) if acl_in.is_none() => {
                        acl_in = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::BulkIn,
                            interval: 0,
                        });
                    }
                    // Bulk-OUT — ACL data.
                    (2, false) if acl_out.is_none() => {
                        acl_out = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::BulkOut,
                            interval: 0,
                        });
                    }
                    // Isochronous — SCO data. Recorded per
                    // alternate setting, first endpoint per
                    // direction wins; the base three above are
                    // unaffected (alternates repeat them).
                    (1, true) | (1, false) => {
                        let kind = if is_in {
                            EndpointKind::IsochIn
                        } else {
                            EndpointKind::IsochOut
                        };
                        let ep = EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind,
                            interval: cfg[i + 6],
                        };
                        // Find the slot for this alternate, or
                        // the first free slot. A full table drops
                        // further alternates — discovery never
                        // fails on a long alt table.
                        let slot = sco_alts
                            .iter()
                            .position(|a| matches!(a, Some(s) if s.alt_setting == alt_setting))
                            .or_else(|| sco_alts.iter().position(|a| a.is_none()));
                        if let Some(slot) = slot {
                            let entry = sco_alts[slot].get_or_insert(ScoAltSetting {
                                alt_setting,
                                sco_in: None,
                                sco_out: None,
                            });
                            if is_in && entry.sco_in.is_none() {
                                entry.sco_in = Some(ep);
                            } else if !is_in && entry.sco_out.is_none() {
                                entry.sco_out = Some(ep);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        i += len;
    }

    Ok(BtEndpoints {
        interface: interface.ok_or(BtUsbError::NotBluetooth)?,
        config_value,
        event_in: event_in.ok_or(BtUsbError::NotBluetooth)?,
        acl_in: acl_in.ok_or(BtUsbError::NotBluetooth)?,
        acl_out: acl_out.ok_or(BtUsbError::NotBluetooth)?,
        sco_alts,
    })
}

/// Compute the xHCI Device Context Index for an endpoint per xHCI 1.2
/// §4.8.1: `(endpoint_number * 2) + (1 if IN else 0)`. Default-control
/// is DCI 1; first non-control endpoint is DCI 2+.
fn ep_dci(ep_addr: u8, is_in: bool) -> u8 {
    let num = ep_addr & 0x0F;
    let in_bit = if is_in { 1 } else { 0 };
    (num * 2) + in_bit
}

/// One bound USB Bluetooth controller. Kept in [`BTUSB_DEVICES`] so a
/// future ACL data-plane has somewhere to find the transport.
pub struct BtUsbDevice {
    /// xHCI controller id ([`crate::xhci::Xhci::id`]) the slot belongs
    /// to. Slot ids are unique per controller only, so the detach
    /// hook matches on (controller, slot) together.
    pub controller: u8,
    pub slot_id: u8,
    /// HCI ordinal assigned by
    /// `narf_bluetooth::controller::register_ready_transport` at bind
    /// time — what the detach hook hands to
    /// `narf_bluetooth::controller::unregister_controller`.
    pub hci_index: usize,
    /// Hub context for autosuspend: `Some((parent hub slot id,
    /// downstream port))` when the device sits behind a hub, `None`
    /// on a root port (root ports are never gated by the hub
    /// idle-suspend pass). Recorded at bind from the supervisor's
    /// attach context (MSC/NCM precedent) and used by the
    /// activity accounting, the class suspend hook, and the
    /// wake-watch. Slot id, never a `HUBS` index (see #892).
    pub hub_port: Option<(u8, u8)>,
    /// Whether the class suspend hook armed remote wakeup the last
    /// time it parked this device. Diagnostic only: a parked device
    /// with `wakeup_armed == false` cannot signal a device-side
    /// wake and relies on host TX demand to resume. Atomic because
    /// the hook mutates the record through the shared `Arc`
    /// (`BTUSB_DEVICES` holds `Arc<BtUsbDevice>`).
    pub wakeup_armed: AtomicBool,
    pub endpoints: BtEndpoints,
    /// Boxed transport handle. Same Arc is registered with
    /// `narf_bluetooth::transport::register`.
    pub transport: Arc<dyn HciTransport>,
    /// Captured controller info from the bring-up sequence.
    pub info: ControllerInfo,
}

impl fmt::Debug for BtUsbDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtUsbDevice")
            .field("controller", &self.controller)
            .field("slot_id", &self.slot_id)
            .field("hub_port", &self.hub_port)
            .field("hci_index", &self.hci_index)
            .field("wakeup_armed", &self.wakeup_armed)
            .field("endpoints", &self.endpoints)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// Registry of bound USB Bluetooth controllers. Entries are removed
/// by the detach hook ([`detach_btusb_slot`], issue #890); a slot
/// id reused by a replug gets a fresh entry.
static BTUSB_DEVICES: IrqSafeSpinLock<Vec<Arc<BtUsbDevice>>> = IrqSafeSpinLock::new(Vec::new());

/// Snapshot the registry. Used by tests + future data-plane.
pub fn devices() -> Vec<Arc<BtUsbDevice>> {
    BTUSB_DEVICES.lock().clone()
}

/// Number of bound USB Bluetooth controllers.
pub fn attached_count() -> usize {
    BTUSB_DEVICES.lock().len()
}

#[doc(hidden)]
pub fn __test_reset() {
    BTUSB_DEVICES.lock().clear();
    narf_bluetooth::transport::__test_reset();
    narf_bluetooth::controller::__test_reset_controllers();
}

/// Detach hook (issue #890): drop this slot's binding and tear its
/// controller down. Called by the supervisor's `dispatch_unbind`
/// from `detach_slot` step 1, while the slot is still addressed —
/// the class-level teardown runs before Disable Slot reclaims it.
///
/// The hook is infallible bookkeeping (registry removal +
/// [`narf_bluetooth::controller::unregister_controller`]), so it
/// reports `Ok(())` unconditionally (#893: a hook reports failure
/// with `Err(())`, never by panicking). It is idempotent: a slot
/// with no btusb binding is a no-op, and a second call for the
/// same slot finds nothing to remove because the first call took
/// the entry — detach never double-tears a controller down.
pub fn detach_btusb_slot(controller: u8, slot_id: u8) -> Result<(), ()> {
    let hci_index = {
        let mut devices = BTUSB_DEVICES.lock();
        let Some(pos) = devices
            .iter()
            .position(|d| d.controller == controller && d.slot_id == slot_id)
        else {
            return Ok(());
        };
        devices.remove(pos).hci_index
    };
    // BTUSB_DEVICES entry first, then the Bluetooth-side teardown:
    // even if the controller was already detached, the registry
    // must not keep the stale entry.
    let _ = narf_bluetooth::controller::unregister_controller(hci_index);
    Ok(())
}

/// Class-triple match for the registry entry: any VID/PID, USB-IF
/// Wireless Controller 0xE0/0x01/0x01 interface.
const BTUSB_CLASS_MATCH: [crate::class_registry::UsbClassMatch; 1] =
    [crate::class_registry::UsbClassMatch {
        vendor_id: 0,
        product_id: 0,
        class: Some(USB_CLASS_WIRELESS),
        subclass: Some(USB_SUBCLASS_RF),
        protocol: Some(USB_PROTOCOL_BLUETOOTH),
    }];

/// Registry probe for btusb. A device only reaches `dispatch_probe`
/// when the attach cascade's real (async) bind already declined or
/// failed — the registry probe is synchronous and cannot run the
/// Stage-0 bring-up — so it reports `BindFailed` and the dispatcher
/// falls through to the same terminal-mismatch handling the device
/// would have seen before this entry existed. (Same shape as MSC's
/// `msc_registry_probe`.)
fn btusb_registry_probe(
    _device: alloc::sync::Arc<crate::device::USBDevice>,
    _match_interface: Option<(u8, u8)>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    Err(crate::class_registry::UsbProbeError::BindFailed)
}

/// Register btusb's unbind hook with the class registry. Called from
/// the crate's Stage::Subsys initcalls (`lib.rs`). btusb binds
/// through the attach cascade, not the class registry; this
/// registration exists so the registry's unbind dispatch (detach
/// path) can reach [`detach_btusb_slot`].
pub fn register_initcalls() {
    let _ = crate::class_registry::register_class_driver_with_unbind(
        "usb-btusb",
        &BTUSB_CLASS_MATCH,
        btusb_registry_probe,
        detach_btusb_slot,
    );
}

/// `HciTransport` implementation backed by the xHCI control / bulk /
/// interrupt-IN transfer paths.
///
/// **Sync methods, `block_on_spin` bridge**: every method bridges
/// to async xHCI calls via `narf_scheduler::block_on_spin` — NOT
/// the halting `block_on`, which panics from inside an executor
/// poll (`CURRENT_TASK != 0`). The callers include the HCI pump
/// task (`spawn_stackful(async ... pump_once ...)` in
/// `narf_bluetooth::pump`) and the HCI socket send path, both of
/// which run inside executor polls, so the spinning bridge is the
/// only correct one here: it busy-polls the IRQ-driven xHCI
/// transfer itself instead of halting, and cannot deadlock the
/// executor. Stage-0 bring-up uses the async helpers below
/// directly; this transport exists so Stage-1+ callers (the pump
/// task, socket sends) can issue HCI commands once L2CAP / GATT
/// pumps are wired up.
pub struct UsbHciTransport {
    /// Controller index ([`crate::xhci::Xhci::id`]) the slot belongs to.
    controller: u8,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    acl_in_dci: u8,
    acl_out_dci: u8,
    event_max_packet: u16,
    /// Hub context for autosuspend accounting: `Some((parent hub
    /// slot id, downstream port))` when behind a hub, `None` on a
    /// root port. Every completed transfer feeds
    /// [`crate::attach::mark_port_activity`] through it, so the
    /// hub idle-suspend pass sees Bluetooth traffic (#820).
    hub_port: Option<(u8, u8)>,
    /// HCI ordinal assigned at bind, once
    /// `register_ready_transport` returns it. `usize::MAX` until
    /// then; the power-park checks below treat that as "unknown,
    /// do not refuse".
    hci_index: AtomicUsize,
    /// Re-arm flag: set the first time `recv_event` is called so the
    /// interrupt-IN endpoint is pre-armed before the first poll.
    armed: AtomicBool,
    /// Isochronous SCO endpoints of the bind-selected alternate
    /// setting. `None` when the device offers no SCO transport (or
    /// the alternate switch failed) — SCO is refused, never rerouted.
    sco_in_dci: Option<u8>,
    sco_out_dci: Option<u8>,
    /// All recorded SCO alternates, for `select_sco_alt_setting`.
    sco_alts: [Option<ScoAltSetting>; MAX_SCO_ALT_SETTINGS],
    /// Currently active SCO alternate setting (`0` = none / alt 0).
    sco_alt: AtomicU8,
}

impl fmt::Debug for UsbHciTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsbHciTransport")
            .field("slot_id", &self.slot_id)
            .field("interface", &self.interface)
            .field("event_dci", &self.event_dci)
            .field("acl_in_dci", &self.acl_in_dci)
            .field("acl_out_dci", &self.acl_out_dci)
            .field("event_max_packet", &self.event_max_packet)
            .field("hub_port", &self.hub_port)
            .field("sco_in_dci", &self.sco_in_dci)
            .field("sco_out_dci", &self.sco_out_dci)
            .field("sco_alt", &self.sco_alt.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Test-only transport with no SCO endpoints: exercises the
/// fail-closed SCO path without a live xHC.
#[doc(hidden)]
pub fn __test_transport_without_sco(controller: u8, slot_id: u8) -> UsbHciTransport {
    UsbHciTransport {
        controller,
        slot_id,
        interface: 0,
        event_dci: 3,
        acl_in_dci: 5,
        acl_out_dci: 4,
        event_max_packet: 16,
        hub_port: None,
        hci_index: AtomicUsize::new(usize::MAX),
        armed: AtomicBool::new(false),
        sco_in_dci: None,
        sco_out_dci: None,
        sco_alts: [None; MAX_SCO_ALT_SETTINGS],
        sco_alt: AtomicU8::new(0),
    }
}

impl UsbHciTransport {
    fn xhci(&self) -> Result<Arc<Xhci>, TransportError> {
        crate::xhci::controller_by_id(self.controller).ok_or(TransportError::Detached)
    }

    /// Record the HCI ordinal assigned at bind.
    fn set_hci_index(&self, index: usize) {
        self.hci_index.store(index, Ordering::Release);
    }

    /// HCI ordinal, or `usize::MAX` when not yet assigned at bind.
    fn hci_index(&self) -> usize {
        self.hci_index.load(Ordering::Acquire)
    }

    /// Feed one completed transfer into the hub idle-suspend
    /// accounting (#820): the supervisor's idle timer resets on
    /// every HCI packet in either direction, so an active
    /// controller never idles into a port suspend. No-op on a root
    /// port (no hub to account to) and when the hub is gone (the
    /// lookup finds nothing).
    fn mark_activity(&self) {
        if let Some((hub_slot, port)) = self.hub_port {
            crate::attach::mark_port_activity(self.controller, hub_slot, port);
        }
    }

    /// Refuse a transfer while the controller is parked for a power
    /// reason (mgmt power-off or system suspend, #820). A parked
    /// controller must not be driven: the pump is gated and the
    /// hardware may be powered down.
    fn refuse_when_power_parked(&self) -> Result<(), TransportError> {
        let index = self.hci_index();
        if index != usize::MAX && narf_bluetooth::pm::parked_for_power(index) {
            return Err(TransportError::Suspended);
        }
        Ok(())
    }

    /// TX-demand resume (#820): if the hub port is gated, resume
    /// it and clear the autosuspend park before the transfer
    /// proceeds (Linux `btusb_send_frame`'s
    /// `usb_autopm_get_interface`). No-op for root-port devices
    /// (`hub_port` is `None`) and when the port is already awake.
    ///
    /// Bridges via [`block_on_spin`], NOT the halting [`block_on`]:
    /// the sync [`HciTransport`] send methods are called from
    /// inside executor polls — the HCI pump task
    /// (`spawn_stackful(async ... pump_once ...)` in
    /// `narf_bluetooth::pump`) and the HCI socket send path — so
    /// `CURRENT_TASK != 0` and the halting bridge would panic
    /// (`narf_scheduler::block_on_inner`). The spinning bridge
    /// cannot deadlock the executor (it busy-polls the future
    /// itself instead of halting), and its documented callers may
    /// legitimately observe `CURRENT_TASK != 0`. The awaited
    /// [`resume_port`] is IRQ-driven xHCI control transfers, and
    /// no caller holds a lock the resume needs across this call
    /// (the pump core is taken out of its registry before
    /// transport I/O; `hci_sock::send` holds only a cloned
    /// controller `Vec`; the xHCI handle is a cloned `Arc`), so
    /// the spin lasts only the resume's control transfers.
    /// A failed resume is not reported (`resume_port` returns
    /// `()`); the transfer that follows fails on the still-gated
    /// port and the caller re-queues it, so nothing is lost.
    /// [`block_on_spin`]: narf_scheduler::block_on_spin
    /// [`block_on`]: narf_scheduler::block_on
    /// [`resume_port`]: crate::attach::resume_port
    fn ensure_port_awake(&self) {
        let Some((hub_slot, port)) = self.hub_port else {
            return;
        };
        if !crate::attach::hub_port_is_suspended(self.controller, hub_slot, port) {
            return;
        }
        let Ok(xhci) = self.xhci() else {
            return;
        };
        narf_scheduler::block_on_spin(crate::attach::resume_port(&xhci, hub_slot, port));
        let index = self.hci_index();
        if index != usize::MAX {
            narf_bluetooth::pm::unpark_autosuspend(index);
        }
    }

    fn arm_event_in(&self, xhci: &Xhci) -> Result<(), TransportError> {
        if self.armed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        xhci.arm_interrupt_in(
            self.slot_id,
            self.event_dci,
            self.event_max_packet.min(257) as u32,
        )
        .map(|_| ())
        .map_err(|_| TransportError::Transient)
    }

    /// `true` when this transport can carry SCO (isoch endpoints
    /// configured for an alternate setting).
    pub fn sco_available(&self) -> bool {
        self.sco_in_dci.is_some() && self.sco_out_dci.is_some()
    }

    /// Active SCO alternate setting, or `None` when the device
    /// offers no SCO transport.
    pub fn sco_alt_setting(&self) -> Option<u8> {
        self.sco_available()
            .then(|| self.sco_alt.load(Ordering::Acquire))
    }

    /// `(sco_in_max_packet, sco_out_max_packet)` of the currently
    /// active SCO alternate, looked up from the recorded table so a
    /// down-switch is reflected immediately. `None` when no SCO
    /// alternate is active (or the active alternate vanished from
    /// the table, which cannot happen — defensive fail-closed).
    fn sco_budgets(&self) -> Option<(u16, u16)> {
        if !self.sco_available() {
            return None;
        }
        let alt = self.sco_alt.load(Ordering::Acquire);
        self.sco_alts
            .iter()
            .flatten()
            .find(|a| a.alt_setting == alt)
            .and_then(|a| match (a.sco_in, a.sco_out) {
                (Some(i), Some(o)) => Some((i.max_packet, o.max_packet)),
                _ => None,
            })
    }

    /// Switch the HCI interface to the smallest complete SCO
    /// alternate whose isoch budget fits a SCO packet carrying
    /// `payload_len` payload bytes (budget ≥ payload + 3-byte SCO
    /// header), and return the alternate now active. A no-op when
    /// that alternate is already active.
    ///
    /// Only alternates that reuse the bind-configured isoch
    /// endpoint addresses can be selected: the xHC endpoint
    /// contexts were configured exactly once at bind, so an
    /// alternate that moves the isoch endpoints would leave the
    /// contexts pointing at dead addresses. Such a switch — and a
    /// packet no recorded alternate can fit — fails with
    /// `TransportError::Unsupported` and leaves the active
    /// alternate unchanged.
    ///
    /// Sync-context only (uses `block_on`, like `send_command`).
    pub fn select_sco_alt_setting(&self, payload_len: usize) -> Result<u8, TransportError> {
        // Compared in `usize` — see `sco_alt_for_payload`.
        let need = payload_len.saturating_add(SCO_PACKET_HEADER_LEN);
        let (Some(cur_in), Some(cur_out)) = (self.sco_in_dci, self.sco_out_dci) else {
            return Err(TransportError::Unsupported);
        };
        let mut target: Option<ScoAltSetting> = None;
        for alt in self.sco_alts.iter().flatten() {
            if !alt.is_complete() {
                continue;
            }
            let budget = alt.packet_budget().unwrap_or(0) as usize;
            if budget < need {
                continue;
            }
            let same_addrs = match (alt.sco_in, alt.sco_out) {
                (Some(i), Some(o)) => {
                    ep_dci(i.ep_addr, true) == cur_in && ep_dci(o.ep_addr, false) == cur_out
                }
                _ => false,
            };
            if !same_addrs {
                continue;
            }
            let better = match target {
                None => true,
                Some(t) => {
                    let t_budget = t.packet_budget().unwrap_or(0) as usize;
                    budget < t_budget || (budget == t_budget && alt.alt_setting < t.alt_setting)
                }
            };
            if better {
                target = Some(*alt);
            }
        }
        let target = target.ok_or(TransportError::Unsupported)?;
        let current = self.sco_alt.load(Ordering::Acquire);
        if target.alt_setting == current {
            return Ok(current);
        }
        let xhci = self.xhci()?;
        narf_scheduler::block_on(xhci.control_out(
            self.slot_id,
            RT_SET_INTERFACE,
            STD_REQ_SET_INTERFACE,
            target.alt_setting as u16,
            self.interface as u16,
            &[],
        ))
        .map_err(|_| TransportError::Transient)?;
        self.sco_alt.store(target.alt_setting, Ordering::Release);
        Ok(target.alt_setting)
    }
}

impl HciTransport for UsbHciTransport {
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
        self.refuse_when_power_parked()?;
        self.ensure_port_awake();
        let xhci = self.xhci()?;
        let payload = cmd.encode();
        let r = narf_scheduler::block_on_spin(xhci.control_out(
            self.slot_id,
            RT_HCI_COMMAND,
            REQ_HCI_COMMAND,
            0,
            self.interface as u16,
            &payload,
        ))
        .map_err(|_| TransportError::Transient);
        if r.is_ok() {
            self.mark_activity();
        }
        r?;
        Ok(())
    }

    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        let xhci = self.xhci()?;
        self.arm_event_in(&xhci)?;
        let mut buf = [0u8; 257];
        match xhci.poll_interrupt_in(self.slot_id, self.event_dci, &mut buf) {
            Ok(Some(n)) => {
                // Bytes arrived: activity even if the decode below
                // rejects them.
                self.mark_activity();
                let event = Event::decode(&buf[..n]).ok_or(TransportError::Transient)?;
                Ok(Some(event))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(TransportError::Transient),
        }
    }

    fn send_acl(&self, data: &[u8]) -> Result<(), TransportError> {
        self.refuse_when_power_parked()?;
        self.ensure_port_awake();
        let xhci = self.xhci()?;
        let r = narf_scheduler::block_on_spin(xhci.bulk_out(self.slot_id, self.acl_out_dci, data))
            .map_err(|_| TransportError::Transient);
        if r.is_ok() {
            self.mark_activity();
        }
        r?;
        Ok(())
    }

    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        // Stage 2: pull an ACL packet from the bulk-IN endpoint.
        // Bridges via block_on_spin, not the halting block_on:
        // this runs in the HCI pump task's executor poll, where
        // CURRENT_TASK != 0 would make the halting bridge panic.
        // See the `UsbHciTransport` docs. Ref: btusb_bulk_in()
        // in drivers/bluetooth/btusb.c.
        let xhci = self.xhci()?;
        let mut buf = [0u8; 1024];
        match narf_scheduler::block_on_spin(xhci.bulk_in(self.slot_id, self.acl_in_dci, &mut buf)) {
            Ok(0) => Ok(None),
            Ok(n) => {
                self.mark_activity();
                Ok(Some(buf[..n].to_vec()))
            }
            Err(_) => Ok(None),
        }
    }

    fn send_sco(&self, data: &[u8]) -> Result<(), TransportError> {
        // SCO/eSCO rides the isochronous endpoints (Vol 4 Part B
        // §2.1): one HCI SCO packet — 3-byte header + payload
        // (`ScoData::encode`, Vol 4 Part E §5.4.3) — per isoch
        // transfer. A device with no isoch endpoints refuses SCO
        // with `Unsupported`; the old bulk-OUT fallback misrouted
        // voice frames onto the ACL pipe, where the controller
        // cannot interpret them. A packet larger than the active
        // alternate's isoch budget is refused, never truncated.
        // (#820) Refuse while power-parked; a TX-demand resume
        // wakes the port first, as on Linux.
        self.refuse_when_power_parked()?;
        self.ensure_port_awake();
        let (sco_out_dci, budget) = match (self.sco_out_dci, self.sco_budgets()) {
            (Some(dci), Some((_, out))) => (dci, out),
            _ => return Err(TransportError::Unsupported),
        };
        if data.len() > budget as usize {
            return Err(TransportError::Unsupported);
        }
        let xhci = self.xhci()?;
        let r = narf_scheduler::block_on(xhci.isoch_out(self.slot_id, sco_out_dci, data))
            .map_err(|_| TransportError::Transient);
        if r.is_ok() {
            self.mark_activity();
        }
        r?;
        Ok(())
    }

    fn recv_sco(&self) -> Result<Option<Vec<u8>>, TransportError> {
        // Mirror `recv_acl`: one isoch-IN transfer per call; an
        // xHC error or an empty transfer means no SCO data is
        // ready. The receive buffer is one frame's isoch budget —
        // a legal SCO packet is at most 3 + 255 bytes (the SCO MTU
        // is a u8), so the 1024-byte cap never truncates one.
        // No isoch endpoints → `Unsupported`, not a silent `None`.
        let (sco_in_dci, budget) = match (self.sco_in_dci, self.sco_budgets()) {
            (Some(dci), Some((inp, _))) => (dci, inp),
            _ => return Err(TransportError::Unsupported),
        };
        let xhci = self.xhci()?;
        let buf_len = (budget as usize).clamp(1, 1024);
        let mut buf = [0u8; 1024];
        match narf_scheduler::block_on(xhci.isoch_in(self.slot_id, sco_in_dci, &mut buf[..buf_len]))
        {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(buf[..n].to_vec())),
            Err(_) => Ok(None),
        }
    }

    fn name(&self) -> &'static str {
        "usb"
    }
}

/// Issue one HCI Command on the control endpoint + wait for the
/// matching Command Complete event on the interrupt-IN endpoint.
/// Per Vol 4 Part E §6 the per-command budget is at least 5 s.
pub(crate) async fn send_command_and_await_complete(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    opcode: u16,
    params: &[u8],
) -> Result<Vec<u8>, BtUsbError> {
    let cmd = Command::with_params(opcode, params);
    let payload = cmd.encode();
    xhci.control_out(
        slot_id,
        RT_HCI_COMMAND,
        REQ_HCI_COMMAND,
        0,
        interface as u16,
        &payload,
    )
    .await
    .map_err(|_| BtUsbError::CommandTransfer)?;

    // The caller pre-arms interrupt-IN before the first command, and
    // `poll_interrupt_in` re-arms it after every completion. Keep exactly
    // one Event TRB outstanding; enqueueing another here would double-arm
    // the endpoint and make two TRBs share its persistent DMA buffer.
    let deadline = narf_time::Deadline::after_ms(5_500);
    let mut buf = [0u8; 257];
    loop {
        match xhci.poll_interrupt_in(slot_id, event_dci, &mut buf) {
            Ok(Some(n)) => {
                let event = Event::decode(&buf[..n]).ok_or(BtUsbError::EventTimeout)?;
                // Stage-0 only issues blocking commands → expect
                // CommandComplete; tolerate CommandStatus by treating
                // it as an early acknowledgement only when the status
                // is success and re-loop (some controllers emit a
                // dummy CommandStatus before CommandComplete).
                if event.code == EventCode::CommandStatus as u8 {
                    let status = CommandStatus::parse(&event).ok_or(BtUsbError::EventTimeout)?;
                    if status.opcode != opcode {
                        return Err(BtUsbError::OpcodeMismatch);
                    }
                    if status.status != 0 {
                        return Err(BtUsbError::BadStatus(status.status));
                    }
                    // `poll_interrupt_in` already re-armed the endpoint.
                    continue;
                }
                let cc = CommandComplete::parse(&event).ok_or(BtUsbError::EventTimeout)?;
                if cc.opcode != opcode {
                    return Err(BtUsbError::OpcodeMismatch);
                }
                let status = cc.status().unwrap_or(0xFF);
                if status != 0x00 {
                    return Err(BtUsbError::BadStatus(status));
                }
                return Ok(cc.return_params.to_vec());
            }
            Ok(None) => {
                if deadline.expired() {
                    return Err(BtUsbError::EventTimeout);
                }
                narf_scheduler::yield_now().await;
            }
            Err(_) => return Err(BtUsbError::CommandTransfer),
        }
    }
}

/// Issue one HCI Command + wait for a specific event code instead of
/// Command Complete. MediaTek WMT commands (opcode 0xFC6F) are
/// answered by a vendor WMT event (0xE4), not a Command Complete —
/// Linux uses `__hci_cmd_sync_ev` for the same reason.
///
/// Unrelated events are skipped: this runs only during pre-bring-up
/// vendor setup, when no host-stack traffic exists yet. A Command
/// Complete / Command Status for our opcode with a non-zero status
/// still fails the wait.
pub(crate) async fn send_command_and_await_event(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    opcode: u16,
    params: &[u8],
    want_code: u8,
) -> Result<Event, BtUsbError> {
    let cmd = Command::with_params(opcode, params);
    let payload = cmd.encode();
    xhci.control_out(
        slot_id,
        RT_HCI_COMMAND,
        REQ_HCI_COMMAND,
        0,
        interface as u16,
        &payload,
    )
    .await
    .map_err(|_| BtUsbError::CommandTransfer)?;

    let deadline = narf_time::Deadline::after_ms(5_500);
    let mut buf = [0u8; 257];
    loop {
        match xhci.poll_interrupt_in(slot_id, event_dci, &mut buf) {
            Ok(Some(n)) => {
                let event = Event::decode(&buf[..n]).ok_or(BtUsbError::EventTimeout)?;
                if event.code == want_code {
                    return Ok(event);
                }
                if event.code == EventCode::CommandStatus as u8 {
                    let status = CommandStatus::parse(&event).ok_or(BtUsbError::EventTimeout)?;
                    if status.opcode == opcode && status.status != 0 {
                        return Err(BtUsbError::BadStatus(status.status));
                    }
                }
                if event.code == EventCode::CommandComplete as u8 {
                    let cc = CommandComplete::parse(&event).ok_or(BtUsbError::EventTimeout)?;
                    if cc.opcode == opcode {
                        let status = cc.status().unwrap_or(0xFF);
                        if status != 0x00 {
                            return Err(BtUsbError::BadStatus(status));
                        }
                    }
                }
                // Any other event is not ours; keep waiting.
            }
            Ok(None) => {
                if deadline.expired() {
                    return Err(BtUsbError::EventTimeout);
                }
                narf_scheduler::yield_now().await;
            }
            Err(_) => return Err(BtUsbError::CommandTransfer),
        }
    }
}

/// Discard pending interrupt-IN events for up to `budget_ms`.
///
/// Vendor boot sequences leave asynchronous vendor events queued
/// (e.g. the Intel bootup event 0xFF/0x02 emitted after the Intel
/// Reset boots the operational image). The generic bring-up that
/// follows expects the next event to be its own Command Complete, so
/// vendor setup drains the queue first.
pub(crate) async fn drain_pending_events(xhci: &Xhci, slot_id: u8, event_dci: u8, budget_ms: u64) {
    let deadline = narf_time::Deadline::after_ms(budget_ms);
    let mut buf = [0u8; 257];
    loop {
        match xhci.poll_interrupt_in(slot_id, event_dci, &mut buf) {
            Ok(Some(_)) => {
                if deadline.expired() {
                    return;
                }
            }
            Ok(None) => {
                if deadline.expired() {
                    return;
                }
                narf_scheduler::yield_now().await;
            }
            Err(_) => return,
        }
    }
}

/// Open a firmware blob from the registry under the trusted-loader
/// authority — the same capability path `btusb_qca` uses. `None` when
/// the authority or the blob is unavailable; vendor setup treats
/// that as a hard failure for chips that cannot run without their
/// firmware.
pub(crate) fn firmware_cap(
    name: &str,
) -> Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>> {
    use narf_capabilities::Cap;
    let write = narf_firmware::trusted_loader_authority()?;
    let read: Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read> =
        write.derive().ok()?;
    narf_firmware::open(name, &read).ok()
}

/// Decode Read Local Version's Command Complete return parameters.
/// The first byte is HCI Status; the eight-byte version payload follows.
pub(crate) fn controller_info_from_version_return(
    ret: &[u8],
) -> Result<ControllerInfo, BtUsbError> {
    if ret.len() < 9 {
        return Err(BtUsbError::ShortReturnParams);
    }
    if ret[0] != 0 {
        return Err(BtUsbError::BadStatus(ret[0]));
    }
    Ok(ControllerInfo {
        bd_addr: [0; 6],
        hci_version: ret[1],
        hci_revision: u16::from_le_bytes([ret[2], ret[3]]),
        lmp_version: ret[4],
        manufacturer: u16::from_le_bytes([ret[5], ret[6]]),
        lmp_subversion: u16::from_le_bytes([ret[7], ret[8]]),
        ..Default::default()
    })
}

pub(crate) fn apply_bd_addr_return(
    info: &mut ControllerInfo,
    ret: &[u8],
) -> Result<(), BtUsbError> {
    if ret.len() < 7 {
        return Err(BtUsbError::ShortReturnParams);
    }
    if ret[0] != 0 {
        return Err(BtUsbError::BadStatus(ret[0]));
    }
    info.bd_addr.copy_from_slice(&ret[1..7]);
    Ok(())
}

pub(crate) fn apply_buffer_size_return(
    info: &mut ControllerInfo,
    ret: &[u8],
) -> Result<(), BtUsbError> {
    if ret.len() < 8 {
        return Err(BtUsbError::ShortReturnParams);
    }
    if ret[0] != 0 {
        return Err(BtUsbError::BadStatus(ret[0]));
    }
    info.acl_data_mtu = u16::from_le_bytes([ret[1], ret[2]]);
    info.sco_data_mtu = ret[3];
    info.acl_total_num = u16::from_le_bytes([ret[4], ret[5]]);
    info.sco_total_num = u16::from_le_bytes([ret[6], ret[7]]);
    Ok(())
}

/// Decode Read Local Name's Command Complete return parameters
/// (§7.4.14): Status (1) + Local_Name (248). The name mgmt
/// READ_INFO reports (issue #815).
pub(crate) fn apply_local_name_return(
    info: &mut ControllerInfo,
    ret: &[u8],
) -> Result<(), BtUsbError> {
    if ret.len() < 249 {
        return Err(BtUsbError::ShortReturnParams);
    }
    if ret[0] != 0 {
        return Err(BtUsbError::BadStatus(ret[0]));
    }
    info.local_name.copy_from_slice(&ret[1..249]);
    Ok(())
}

/// Decode Read Class Of Device's Command Complete return parameters
/// (§7.4.23): Status (1) + Class_Of_Device (3). The class mgmt
/// READ_INFO reports (issue #815).
pub(crate) fn apply_class_return(info: &mut ControllerInfo, ret: &[u8]) -> Result<(), BtUsbError> {
    if ret.len() < 4 {
        return Err(BtUsbError::ShortReturnParams);
    }
    if ret[0] != 0 {
        return Err(BtUsbError::BadStatus(ret[0]));
    }
    info.dev_class.copy_from_slice(&ret[1..4]);
    Ok(())
}

/// Post-address Bluetooth bind: caller has already issued port_reset +
/// enable_slot + address_device. We pull the config descriptor, match
/// the HCI interface + endpoints, configure them on the xHC, issue
/// SET_CONFIGURATION, then run the Stage-0 bring-up sequence and log
/// a single line summarising the controller.
///
/// `hub_port` is the device's hub context — `Some((parent hub slot
/// id, downstream port))` when it sits behind a hub, `None` on a
/// root port (MSC/NCM precedent) — recorded on the device record
/// and the transport so the hub idle-suspend pass sees Bluetooth
/// traffic and can park the datapath before gating the port (#820).
///
/// Returns `Ok(())` on success. On failure the caller frees the slot.
pub async fn try_bind_btusb_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    vendor_id: u16,
    product_id: u16,
    cfg: &[u8],
    hub_port: Option<(u8, u8)>,
) -> Result<(), BtUsbError> {
    let eps = find_bt_endpoints(cfg)?;

    // SCO alternate selection (issue #817): the xHC endpoint
    // contexts are configured exactly once, so bind configures the
    // largest-budget complete SCO alternate together with the base
    // three endpoints. The controller's SCO MTU is only known after
    // Read_Buffer_Size; configuring the largest budget keeps every
    // SCO packet the device offers usable, and the transport can
    // switch down to a smaller alternate later via SET_INTERFACE
    // (`UsbHciTransport::select_sco_alt_setting`).
    let sco_alt = eps.best_sco_alt();
    let mut all_eps: Vec<EndpointConfig> = Vec::with_capacity(5);
    all_eps.push(eps.event_in);
    all_eps.push(eps.acl_in);
    all_eps.push(eps.acl_out);
    if let Some(alt) = sco_alt {
        if let Some(sco_in) = alt.sco_in {
            all_eps.push(sco_in);
        }
        if let Some(sco_out) = alt.sco_out {
            all_eps.push(sco_out);
        }
    }

    // Configure the xHC-side endpoint contexts for the required
    // endpoints (+ the SCO isoch pair when offered). EP0 (default
    // control) is already provisioned by address_device.
    xhci_dev
        .configure_endpoints(slot_id, &all_eps)
        .await
        .map_err(|_| BtUsbError::EndpointConfig)?;

    // SET_CONFIGURATION before any class request (USB 2.0 §9.4.7) —
    // without it the controller's class-specific Setup transfer for
    // HCI_Reset would STALL.
    xhci_dev
        .control_out(
            slot_id,
            0x00, // bmRequestType: Host-to-Device, Standard, Device
            STD_REQ_SET_CONFIGURATION,
            eps.config_value as u16,
            0,
            &[],
        )
        .await
        .map_err(|_| BtUsbError::SetConfiguration)?;

    // Activate the SCO alternate setting (USB 2.0 §9.4.10).
    // SET_CONFIGURATION leaves alt 0 active, which carries no
    // isoch endpoints. A refused switch does not fail the bind —
    // SCO is optional per Vol 4 Part B §2.1 — but the transport is
    // left without SCO endpoints, so SCO is refused instead of
    // sent to endpoints the device never activated.
    let mut sco_active = false;
    if let Some(alt) = sco_alt {
        if alt.alt_setting > 0 {
            match xhci_dev
                .control_out(
                    slot_id,
                    RT_SET_INTERFACE,
                    STD_REQ_SET_INTERFACE,
                    alt.alt_setting as u16,
                    eps.interface as u16,
                    &[],
                )
                .await
            {
                Ok(_) => sco_active = true,
                Err(error) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "  btusb: slot={} SET_INTERFACE SCO alt {} failed: {:?}; SCO unavailable",
                        slot_id,
                        alt.alt_setting,
                        error
                    );
                }
            }
        } else {
            // Isoch endpoints already live under alt 0.
            sco_active = true;
        }
    }

    // ── Stage-0 bring-up dance ────────────────────────────────────
    // Vol 4 Part E §3 — Reset, Read_Local_Version, Read_BD_ADDR,
    // Read_Buffer_Size, Set_Event_Mask, Read_Local_Name,
    // Read_Class_Of_Device: the same sequence the sync bring-up
    // runs (see `narf_bluetooth::controller::Controller::bring_up`),
    // so the registered controller carries its real identity.
    let event_dci = ep_dci(eps.event_in.ep_addr, /*is_in*/ true);
    let acl_in_dci = ep_dci(eps.acl_in.ep_addr, /*is_in*/ true);
    let acl_out_dci = ep_dci(eps.acl_out.ep_addr, /*is_in*/ false);

    // Keep one interrupt-IN Event transfer outstanding across the
    // vendor setup and the whole mandatory command sequence. Every
    // successful poll re-arms it. (Arming happens before vendor
    // setup because the Intel / MediaTek sequences issue HCI
    // commands; the QCA DFU sequence does not use the event endpoint
    // and is unaffected.)
    if let Err(error) =
        xhci_dev.arm_interrupt_in(slot_id, event_dci, eps.event_in.max_packet.min(257) as u32)
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  btusb: slot={} cannot arm event DCI {}: {:?}",
            slot_id,
            event_dci,
            error
        );
        return Err(BtUsbError::CommandTransfer);
    }

    // Vendor firmware setup for recognised parts, before the generic
    // bring-up: controllers that need their firmware downloaded do
    // not answer normal HCI correctly until this has run. A failed
    // vendor setup fails the bind (Linux does the same — proceeding
    // to HCI Reset would register a controller that cannot work).
    match narf_bluetooth::btusb_quirks::identify(vendor_id, product_id) {
        Some(narf_bluetooth::btusb_quirks::Quirk::QualcommWcn6855) => {
            match crate::btusb_qca::setup_wcn6855(xhci_dev, slot_id, acl_out_dci).await {
                Ok(version) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "  btusb-qca: {:04x}:{:04x} ROM {:#010x}, patch {:#010x}",
                        vendor_id,
                        product_id,
                        version.rom_version,
                        version.patch_version,
                    );
                }
                Err(error) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "  btusb-qca: {:04x}:{:04x} setup failed: {:?}",
                        vendor_id,
                        product_id,
                        error,
                    );
                    return Err(BtUsbError::FirmwareSetup);
                }
            }
        }
        Some(narf_bluetooth::btusb_quirks::Quirk::Intel) => {
            if let Err(error) = crate::btusb_intel::setup_intel(
                xhci_dev,
                slot_id,
                eps.interface,
                event_dci,
                product_id,
            )
            .await
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  btusb-intel: {:04x}:{:04x} setup failed: {:?}",
                    vendor_id,
                    product_id,
                    error,
                );
                return Err(BtUsbError::FirmwareSetup);
            }
        }
        Some(narf_bluetooth::btusb_quirks::Quirk::MediaTek) => {
            if let Err(error) = crate::btusb_mtk::setup_mediatek(
                xhci_dev,
                slot_id,
                eps.interface,
                event_dci,
                product_id,
            )
            .await
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  btusb-mtk: {:04x}:{:04x} setup failed: {:?}",
                    vendor_id,
                    product_id,
                    error,
                );
                return Err(BtUsbError::FirmwareSetup);
            }
        }
        Some(narf_bluetooth::btusb_quirks::Quirk::Realtek) => {
            if let Err(error) = crate::btusb_rtl::setup_realtek(
                xhci_dev,
                slot_id,
                eps.interface,
                event_dci,
                vendor_id,
                product_id,
            )
            .await
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  btusb-rtl: {:04x}:{:04x} setup failed: {:?}",
                    vendor_id,
                    product_id,
                    error,
                );
                return Err(BtUsbError::FirmwareSetup);
            }
        }
        Some(narf_bluetooth::btusb_quirks::Quirk::Broadcom) => {
            if let Err(error) =
                crate::btusb_bcm::setup_broadcom(xhci_dev, slot_id, eps.interface, event_dci).await
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  btusb-bcm: {:04x}:{:04x} setup failed: {:?}",
                    vendor_id,
                    product_id,
                    error,
                );
                return Err(BtUsbError::FirmwareSetup);
            }
        }
        // CSR / Marvell and unrecognised parts proceed without a
        // vendor sequence for now, as before.
        _ => {}
    }

    // HCI_Reset (§7.3.2) — no parameters, no return params beyond
    // status. After this the controller is in a defined post-reset
    // state and discards any in-flight ACL / SCO traffic.
    if let Err(error) = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        op::HCI_RESET,
        &[],
    )
    .await
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  btusb: slot={} HCI Reset failed: {:?}",
            slot_id,
            error
        );
        return Err(error);
    }

    // HCI_Read_Local_Version_Information (§7.4.1) — returns
    // Status (1) + HCI_Version (1) + HCI_Revision (2) +
    // LMP_Version (1) + Manufacturer_Name (2) + LMP_Subversion (2).
    let ret = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        op::HCI_READ_LOCAL_VERSION,
        &[],
    )
    .await?;
    let mut info = controller_info_from_version_return(&ret)?;

    let ret = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        op::HCI_READ_BD_ADDR,
        &[],
    )
    .await?;
    apply_bd_addr_return(&mut info, &ret)?;

    let ret = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        op::HCI_READ_BUFFER_SIZE,
        &[],
    )
    .await?;
    apply_buffer_size_return(&mut info, &ret)?;

    // Default host event mask used by the shared controller bring-up.
    let _ = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        op::HCI_SET_EVENT_MASK,
        &narf_bluetooth::controller::DEFAULT_EVENT_MASK,
    )
    .await?;

    // Local name + Class of Device (§7.4.14/§7.4.23), mirroring the
    // sync bring-up: the identity mgmt READ_INFO reports (issue
    // #815). Read after the event mask, before registration, so no
    // mgmt socket ever sees a zeroed name/class for a controller
    // that knows its own.
    let ret = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        op::HCI_READ_LOCAL_NAME,
        &[],
    )
    .await?;
    apply_local_name_return(&mut info, &ret)?;

    let ret = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        op::HCI_READ_CLASS_OF_DEVICE,
        &[],
    )
    .await?;
    apply_class_return(&mut info, &ret)?;

    // Register a sync-context transport for Stage-1+ callers (L2CAP
    // pump, ACL data plane). Mandatory bring-up is done: every command
    // it issued used the async helper above. The SCO endpoints are
    // attached only when the alternate switch above succeeded.
    let (sco_in_dci, sco_out_dci, sco_alt_setting) = if sco_active {
        match sco_alt {
            Some(alt) => (
                alt.sco_in.map(|e| ep_dci(e.ep_addr, true)),
                alt.sco_out.map(|e| ep_dci(e.ep_addr, false)),
                alt.alt_setting,
            ),
            None => (None, None, 0),
        }
    } else {
        (None, None, 0)
    };
    let usb_transport = Arc::new(UsbHciTransport {
        controller: xhci_dev.id(),
        slot_id,
        interface: eps.interface,
        event_dci,
        acl_in_dci,
        acl_out_dci,
        event_max_packet: eps.event_in.max_packet,
        hub_port,
        hci_index: AtomicUsize::new(usize::MAX),
        armed: AtomicBool::new(true), // already armed by the bring-up
        sco_in_dci,
        sco_out_dci,
        sco_alts: eps.sco_alts,
        sco_alt: AtomicU8::new(sco_alt_setting),
    });
    let transport: Arc<dyn HciTransport> = usb_transport.clone();
    narf_bluetooth::transport::register(transport.clone());
    let hci_index = narf_bluetooth::controller::register_ready_transport(transport.clone(), info);
    // The transport needs its HCI ordinal for the power-park
    // checks (refuse-while-parked, TX-demand unpark).
    usb_transport.set_hci_index(hci_index);
    let _ = narf_bluetooth::sysfs_bridge::register_hci_controller(hci_index, info, &[]);

    // Device-PM registration (#820): system suspend parks the HCI
    // pump (no I/O, just the park flags — the handler runs with
    // interrupts gated); resume clears the park. The USB port power
    // state itself is owned by the hub/xHCI suspend path. The name
    // is per-controller: the registry is idempotent on name, so a
    // second dongle must not replace the first's entry.
    narf_power::device_pm::register_device_pm_ops(
        &alloc::format!("btusb-hci{}", hci_index),
        Arc::new(BtUsbPm { hci_index }),
    );

    {
        use core::fmt::Write as _;
        static ATTACHED: [AtomicU64; crate::xhci::MAX_CONTROLLERS] =
            [const { AtomicU64::new(0) }; crate::xhci::MAX_CONTROLLERS];
        let bit = 1u64 << (slot_id as u32 & 63);
        let controller = usize::from(xhci_dev.id()).min(crate::xhci::MAX_CONTROLLERS - 1);
        let prev = ATTACHED[controller].fetch_or(bit, Ordering::AcqRel);
        if prev & bit == 0 {
            let vendor = vendor_name(info.manufacturer);
            let bt_ver = bt_version_name(info.hci_version);
            let _ = writeln!(
                narf_console::Writer,
                "  bluetooth: {} adapter, HCI v0x{:02x}, Bluetooth {}",
                vendor,
                info.hci_version,
                bt_ver
            );
        }
    }

    if sco_active {
        use core::fmt::Write as _;
        if let Some(alt) = sco_alt {
            let _ = writeln!(
                narf_console::Writer,
                "  btusb: slot={} SCO isoch alt {} in=0x{:02x}/{} out=0x{:02x}/{}",
                slot_id,
                alt.alt_setting,
                alt.sco_in.map(|e| e.ep_addr).unwrap_or(0),
                alt.sco_in.map(|e| e.max_packet).unwrap_or(0),
                alt.sco_out.map(|e| e.ep_addr).unwrap_or(0),
                alt.sco_out.map(|e| e.max_packet).unwrap_or(0),
            );
        }
    }

    BTUSB_DEVICES.lock().push(Arc::new(BtUsbDevice {
        controller: xhci_dev.id(),
        slot_id,
        hub_port,
        hci_index,
        wakeup_armed: AtomicBool::new(false),
        endpoints: eps,
        transport,
        info,
    }));
    Ok(())
}

/// Device-PM ops for one bound USB Bluetooth controller (#820).
///
/// Suspend parks the HCI pump (flag stores only — the handler runs
/// on the boot CPU with interrupts gated, so no I/O, no scheduling);
/// resume clears the park. The USB port power state itself is owned
/// by the hub/xHCI suspend path.
#[derive(Debug)]
struct BtUsbPm {
    hci_index: usize,
}

impl narf_power::device_pm::DevicePmOps for BtUsbPm {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        narf_bluetooth::pm::suspend_controller(self.hci_index);
        Ok(())
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        narf_bluetooth::pm::resume_controller(self.hci_index);
        Ok(())
    }
}

/// Register the btusb class suspend hook (#820). Called from the
/// drivers/usb Stage::Subsys initcalls, alongside the NIC drivers'
/// registrations. The hook itself is per-port: it parks only a live
/// BT device whose recorded hub context matches the port the
/// supervisor's idle-suspend pass is about to gate.
pub fn register() {
    let _ = crate::class_registry::register_suspend_hook("btusb", |controller, slot, port| {
        alloc::boxed::Box::pin(suspend_btusb_port(controller, slot, port))
    });
}

/// Class suspend hook for one hub port (see
/// [`crate::class_registry::dispatch_suspend`]). Runs inside the
/// supervisor's idle-suspend pass, before the pass gates the port —
/// a driver with a live device on the port parks its datapath and
/// arms remote wakeup first, because a gated port blocks all
/// transfers including the arming control transfer (#1256).
///
/// Outcomes, mirroring the r8152/NCM hooks:
/// - No BT device on the port → `SuspendOutcome::NotMine`.
/// - The controller's idle timeout is 0 ("never autosuspend",
///   Linux semantics) → `SuspendOutcome::ParkFailed`: the pass
///   must not gate this cycle, and retries next cycle.
/// - Already parked → `SuspendOutcome::Parked` without re-arming
///   (idempotent).
/// - Remote-wakeup arming (standard `SET_FEATURE
///   (DEVICE_REMOTE_WAKEUP)`) fails → `SuspendOutcome::ParkFailed`:
///   fail closed. Without arming, a gated port has no
///   device-initiated resume path — an inbound connection attempt
///   while suspended would be missed until host-side TX demand —
///   so a device that cannot arm simply stays awake.
/// - Armed → park the HCI pump ([`narf_bluetooth::pm`]) and record
///   the arming, then `SuspendOutcome::Parked`.
async fn suspend_btusb_port(
    controller: u8,
    hub_slot: u8,
    port: u8,
) -> crate::class_registry::SuspendOutcome {
    use crate::class_registry::SuspendOutcome;
    // Read what arming needs, then release before any await.
    let target = {
        let g = BTUSB_DEVICES.lock();
        g.iter().find_map(|d| {
            if d.controller == controller && d.hub_port == Some((hub_slot, port)) {
                Some((d.slot_id, d.controller, d.hci_index))
            } else {
                None
            }
        })
    };
    let Some((slot_id, controller, hci_index)) = target else {
        return SuspendOutcome::NotMine;
    };
    if narf_bluetooth::pm::idle_timeout_ms(hci_index) == 0 {
        return SuspendOutcome::ParkFailed;
    }
    if narf_bluetooth::pm::is_runtime_suspended(hci_index) {
        return SuspendOutcome::Parked;
    }
    let Some(c) = crate::xhci::controller_by_id(controller) else {
        return SuspendOutcome::ParkFailed;
    };
    let setup = crate::control::set_feature_device_remote_wakeup();
    let armed = c
        .control_out(
            slot_id,
            setup.bm_request_type,
            setup.b_request,
            setup.w_value,
            setup.w_index,
            &[],
        )
        .await
        .is_ok();
    if !armed {
        return SuspendOutcome::ParkFailed;
    }
    // Park the pump, then record the arming only if the record is
    // still live (a detach in between wins; the pass's gating of a
    // device-less port is harmless).
    narf_bluetooth::pm::park_autosuspend(hci_index);
    let g = BTUSB_DEVICES.lock();
    match g.iter().find(|d| {
        d.controller == controller
            && d.hub_port == Some((hub_slot, port))
            && d.slot_id == slot_id
            && d.hci_index == hci_index
    }) {
        Some(rec) => {
            rec.wakeup_armed.store(true, Ordering::Release);
            SuspendOutcome::Parked
        }
        None => SuspendOutcome::NotMine,
    }
}

/// Resume one parked btusb port: re-open the hub port, then clear
/// the autosuspend park. Returns `true` iff the port is awake and
/// the park cleared. Idempotent in the sense that a non-parked
/// port returns `false` (nothing was resumed) — callers that need
/// "awake" semantics re-check the park flag. Never holds the
/// record lock across the resume await.
pub async fn resume_btusb_port(xhci_dev: &crate::xhci::Xhci, hub_slot: u8, port: u8) -> bool {
    let hci_index = {
        let g = BTUSB_DEVICES.lock();
        g.iter()
            .find(|d| {
                d.controller == xhci_dev.id()
                    && d.hub_port == Some((hub_slot, port))
                    && narf_bluetooth::pm::is_runtime_suspended(d.hci_index)
            })
            .map(|d| d.hci_index)
    };
    let Some(hci_index) = hci_index else {
        return false;
    };
    crate::attach::resume_port(xhci_dev, hub_slot, port).await;
    if crate::attach::hub_port_is_suspended(xhci_dev.id(), hub_slot, port) {
        return false;
    }
    narf_bluetooth::pm::unpark_autosuspend(hci_index);
    true
}

/// Hub ports holding a runtime-suspended btusb device. Mirrors
/// `hid::hub_ports`, filtered to parked devices: the wake-watch
/// step's candidate list.
pub fn suspended_hub_ports(controller: u8) -> Vec<(u8, u8)> {
    let g = BTUSB_DEVICES.lock();
    g.iter()
        .filter(|d| {
            d.controller == controller && narf_bluetooth::pm::is_runtime_suspended(d.hci_index)
        })
        .filter_map(|d| d.hub_port)
        .collect()
}

/// Wake-watch step: for each parked btusb port, read the hub port
/// status; on an observed remote-wakeup edge (the
/// `C_PORT_SUSPEND` change bit) resume the port. `port_resume`
/// acks the change bit, so no double-resume. Ports with no edge
/// stay suspended — unlike the HID/ACM unconditional wake, an
/// unconditional BT wake every cycle would defeat autosuspend.
/// Called from the supervisor's Phase 7, next to
/// `wake_suspended_nic_ports`.
pub async fn wake_suspended_ports(xhci_dev: &crate::xhci::Xhci) {
    for (hub_slot, port) in suspended_hub_ports(xhci_dev.id()) {
        if crate::attach::hub_port_suspend_change(xhci_dev, hub_slot, port).await == Some(true) {
            let _ = resume_btusb_port(xhci_dev, hub_slot, port).await;
        }
    }
}

/// Translate a small set of common Bluetooth SIG manufacturer IDs
/// (Vol 2 Part C §1, Assigned Numbers "Company Identifiers") to a
/// human-readable string. The full table is several hundred entries —
/// we cover only the chip vendors typically found in laptops + USB
/// dongles. Unknown IDs render as `unknown`.
fn vendor_name(manufacturer: u16) -> &'static str {
    // Picked from the SIG public list. Stable IDs — these are wire
    // identifiers and don't change.
    match manufacturer {
        0x0001 => "Nokia",
        0x0002 => "Intel",
        0x0003 => "IBM",
        0x0004 => "Toshiba",
        0x000F => "Broadcom",
        0x0010 => "Mitsubishi",
        0x001D => "Atheros",
        0x0025 => "MediaTek",
        0x002D => "Texas Instruments",
        0x004C => "Apple",
        0x0056 => "Sony",
        0x0075 => "Samsung",
        0x0087 => "Garmin",
        0x009E => "Bose",
        0x00D7 => "Qualcomm",
        0x010C => "Sennheiser",
        0x0131 => "Cypress Semiconductor",
        0x05F1 => "Linux Foundation",
        _ => "unknown",
    }
}

/// Map an HCI version byte (Vol 2 Part C "Assigned Numbers" §HCI
/// Version) to a short string. HCI version tracks LMP version on
/// every released BR/EDR/BLE-capable controller.
fn bt_version_name(hci_version: u8) -> &'static str {
    match hci_version {
        0x00 => "1.0b",
        0x01 => "1.1",
        0x02 => "1.2",
        0x03 => "2.0",
        0x04 => "2.1",
        0x05 => "3.0",
        0x06 => "4.0",
        0x07 => "4.1",
        0x08 => "4.2",
        0x09 => "5.0",
        0x0A => "5.1",
        0x0B => "5.2",
        0x0C => "5.3",
        0x0D => "5.4",
        _ => "?",
    }
}

// ── Fixtures ─────────────────────────────────────────────────────
//
// The suspend hook's pre-arm decisions (no live device, idle
// timeout veto, already-parked re-park) run against a modelled
// device record with no xHCI controller present, so they execute
// in the kernel-test binary. The arming control transfer itself
// and the TX-demand / wake-watch resume paths need a real hub
// port and are NOT covered here — they execute only on hardware
// (see the #820 PR body).

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_bluetooth::controller::ControllerInfo;
    use narf_bluetooth::transport::LoopbackTransport;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_power::device_pm::DevicePmOps;

    fn fake_endpoints() -> BtEndpoints {
        use crate::xhci::{EndpointConfig, EndpointKind};
        BtEndpoints {
            interface: 0,
            config_value: 1,
            event_in: EndpointConfig {
                ep_addr: 0x81,
                max_packet: 16,
                kind: EndpointKind::InterruptIn,
                interval: 1,
            },
            acl_in: EndpointConfig {
                ep_addr: 0x82,
                max_packet: 64,
                kind: EndpointKind::BulkIn,
                interval: 0,
            },
            acl_out: EndpointConfig {
                ep_addr: 0x02,
                max_packet: 64,
                kind: EndpointKind::BulkOut,
                interval: 0,
            },
            sco_alts: [None; MAX_SCO_ALT_SETTINGS],
        }
    }

    /// #890: the detach hook (`detach_btusb_slot`, as invoked by
    /// `dispatch_unbind` from `detach_slot`) drops the
    /// BTUSB_DEVICES entry and tears the controller down — pump
    /// slot gone, controller + transport unregistered, sysfs node
    /// gone, mgmt INDEX_REMOVED published. Slot ids are unique per
    /// controller only, so two devices sharing a slot id on
    /// different controllers detach independently; a second detach
    /// for the same slot and a detach for an unknown slot are
    /// no-ops.
    fn smoke_btusb_detach_slot_unregisters_controller() -> TestResult {
        use narf_bluetooth::transport::LoopbackTransport;
        use narf_filesystem::sysfs::__reset_for_test as sysfs_reset;

        // mgmt event opcode (mgmt.h MGMT_EV_INDEX_REMOVED).
        const EV_INDEX_REMOVED: u16 = 0x0005;

        static CAPTURED: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());
        fn capture_sink(event: &[u8]) {
            CAPTURED.lock().push(event.to_vec());
        }

        __test_reset();
        narf_bluetooth::pump::__test_reset();
        sysfs_reset();
        CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);
        let fail = |msg: &'static str| -> TestResult {
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            __test_reset();
            narf_bluetooth::pump::__test_reset();
            sysfs_reset();
            TestResult::Fail(msg)
        };

        // Two bound devices sharing slot id 3 on different xHCI
        // controllers (hci 0 and hci 1).
        let mk_device = |controller: u8, slot_id: u8, name: &'static str| {
            let transport: Arc<dyn HciTransport> = Arc::new(LoopbackTransport::new(name));
            narf_bluetooth::transport::register(transport.clone());
            let hci_index = narf_bluetooth::controller::register_ready_transport(
                transport.clone(),
                ControllerInfo::default(),
            );
            BTUSB_DEVICES.lock().push(Arc::new(BtUsbDevice {
                controller,
                slot_id,
                hub_port: None,
                hci_index,
                wakeup_armed: AtomicBool::new(false),
                endpoints: fake_endpoints(),
                transport,
                info: ControllerInfo::default(),
            }));
        };
        mk_device(0, 3, "btusb-detach-a");
        mk_device(1, 3, "btusb-detach-b");
        if attached_count() != 2 || narf_bluetooth::controller::controller_count() != 2 {
            return fail("setup did not bind two controllers");
        }
        if narf_bluetooth::sysfs_bridge::hci_kobject(1).is_none() {
            return fail("no sysfs node for hci1 after setup");
        }

        CAPTURED.lock().clear();
        if detach_btusb_slot(0, 3).is_err() {
            return fail("detach hook failed for a bound slot");
        }
        if attached_count() != 1 {
            return fail("BTUSB_DEVICES entry survived detach");
        }
        if narf_bluetooth::controller::controller_count() != 1
            || !narf_bluetooth::controller::is_live(1)
            || narf_bluetooth::controller::is_live(0)
        {
            return fail("wrong controller survived detach");
        }
        if narf_bluetooth::transport::transport_count() != 1 {
            return fail("detached transport survived detach");
        }
        if narf_bluetooth::pump::connection_count(0).is_some() {
            return fail("pump slot survived detach");
        }
        if narf_bluetooth::sysfs_bridge::hci_kobject(0).is_some()
            || narf_bluetooth::sysfs_bridge::hci_kobject(1).is_none()
        {
            return fail("sysfs nodes wrong after detach (hci0 must go, hci1 stay)");
        }
        let removed = CAPTURED
            .lock()
            .iter()
            .filter(|e| {
                e.len() >= 6
                    && u16::from_le_bytes([e[0], e[1]]) == EV_INDEX_REMOVED
                    && u16::from_le_bytes([e[2], e[3]]) == 0
            })
            .count();
        if removed != 1 {
            return fail("INDEX_REMOVED was not published exactly once for hci0");
        }

        // Second detach for the same slot: no-op.
        if detach_btusb_slot(0, 3).is_err() || attached_count() != 1 {
            return fail("second detach for the same slot was not a no-op");
        }
        // Unknown slot: no-op.
        if detach_btusb_slot(0, 7).is_err() || attached_count() != 1 {
            return fail("detach for an unknown slot was not a no-op");
        }
        // The other controller's slot detaches independently.
        if detach_btusb_slot(1, 3).is_err() {
            return fail("detach hook failed for the second controller");
        }
        if attached_count() != 0 || narf_bluetooth::controller::controller_count() != 0 {
            return fail("registries not empty after both detaches");
        }

        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        __test_reset();
        narf_bluetooth::pump::__test_reset();
        sysfs_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/btusb",
        smoke_btusb_detach_slot_unregisters_controller
    );

    fn fake_device(
        slot_id: u8,
        controller: u8,
        hub_port: Option<(u8, u8)>,
        hci_index: usize,
    ) -> Arc<BtUsbDevice> {
        Arc::new(BtUsbDevice {
            slot_id,
            controller,
            hub_port,
            hci_index,
            wakeup_armed: AtomicBool::new(false),
            endpoints: BtEndpoints {
                interface: 0,
                config_value: 1,
                event_in: EndpointConfig {
                    ep_addr: 0x81,
                    max_packet: 64,
                    kind: EndpointKind::InterruptIn,
                    interval: 1,
                },
                acl_in: EndpointConfig {
                    ep_addr: 0x82,
                    max_packet: 64,
                    kind: EndpointKind::BulkIn,
                    interval: 0,
                },
                acl_out: EndpointConfig {
                    ep_addr: 0x02,
                    max_packet: 64,
                    kind: EndpointKind::BulkOut,
                    interval: 0,
                },
                sco_alts: [None; MAX_SCO_ALT_SETTINGS],
            },
            transport: Arc::new(LoopbackTransport::new("test-btusb")),
            info: ControllerInfo::default(),
        })
    }

    fn reset_all() {
        __test_reset();
        narf_bluetooth::pm::__reset_for_test();
    }

    fn smoke_btusb_suspend_hook_not_mine() -> TestResult {
        use crate::class_registry::SuspendOutcome;
        reset_all();
        let out = narf_scheduler::block_on(suspend_btusb_port(0, 0xEE, 7));
        reset_all();
        if out != SuspendOutcome::NotMine {
            return TestResult::Fail("hook claimed a port with no BT device");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/btusb", smoke_btusb_suspend_hook_not_mine);

    fn smoke_btusb_suspend_hook_idle_timeout_zero_vetoes() -> TestResult {
        use crate::class_registry::SuspendOutcome;
        reset_all();
        BTUSB_DEVICES
            .lock()
            .push(fake_device(3, 0, Some((0xEE, 7)), 0));
        // Idle timeout 0 = "never autosuspend": the hook vetoes
        // gating instead of parking.
        narf_bluetooth::pm::set_idle_timeout_ms(0, 0);
        let out = narf_scheduler::block_on(suspend_btusb_port(0, 0xEE, 7));
        let still_unparked = !narf_bluetooth::pm::is_runtime_suspended(0);
        reset_all();
        if out != SuspendOutcome::ParkFailed {
            return TestResult::Fail("idle-timeout-0 device was not vetoed");
        }
        if !still_unparked {
            return TestResult::Fail("vetoed device was parked anyway");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/btusb",
        smoke_btusb_suspend_hook_idle_timeout_zero_vetoes
    );

    fn smoke_btusb_suspend_hook_already_parked() -> TestResult {
        use crate::class_registry::SuspendOutcome;
        reset_all();
        BTUSB_DEVICES
            .lock()
            .push(fake_device(3, 0, Some((0xEE, 7)), 0));
        // Default idle timeout (30 s) + already parked: idempotent
        // re-park with no arming attempt (no xHCI exists here).
        narf_bluetooth::pm::park_autosuspend(0);
        let out = narf_scheduler::block_on(suspend_btusb_port(0, 0xEE, 7));
        let still_parked = narf_bluetooth::pm::is_runtime_suspended(0);
        reset_all();
        if out != SuspendOutcome::Parked {
            return TestResult::Fail("already-parked device did not re-park");
        }
        if !still_parked {
            return TestResult::Fail("re-park cleared the park");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/btusb", smoke_btusb_suspend_hook_already_parked);

    fn smoke_btusb_suspended_hub_ports_lists_parked() -> TestResult {
        reset_all();
        BTUSB_DEVICES
            .lock()
            .push(fake_device(3, 0, Some((0xEE, 7)), 0));
        BTUSB_DEVICES
            .lock()
            .push(fake_device(4, 0, Some((0xEE, 8)), 1));
        let other = fake_device(3, 1, Some((0xEE, 7)), 2);
        BTUSB_DEVICES.lock().push(other);
        narf_bluetooth::pm::park_autosuspend(2);
        // hci0 and hci2 share hub/slot numbers on different controllers.
        narf_bluetooth::pm::park_autosuspend(0);
        let ports = suspended_hub_ports(0);
        let other_ports = suspended_hub_ports(1);
        let unrelated = narf_scheduler::block_on(suspend_btusb_port(2, 0xEE, 7));
        reset_all();
        if other_ports != alloc::vec![(0xEE, 7)]
            || unrelated != crate::class_registry::SuspendOutcome::NotMine
        {
            return TestResult::Fail("Bluetooth suspend selection crossed USB controllers");
        }
        if ports != alloc::vec![(0xEE, 7)] {
            return TestResult::Fail("wake-watch list missed the parked port or kept the live one");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/btusb",
        smoke_btusb_suspended_hub_ports_lists_parked
    );

    fn smoke_btusb_pm_ops_park_and_resume() -> TestResult {
        reset_all();
        let ops = BtUsbPm { hci_index: 0 };
        if ops.suspend().is_err() || !narf_bluetooth::pm::is_parked(0) {
            reset_all();
            return TestResult::Fail("device-PM suspend did not park the controller");
        }
        if !narf_bluetooth::pm::parked_for_power(0) {
            reset_all();
            return TestResult::Fail("device-PM suspend parked for the wrong reason");
        }
        if ops.resume().is_err() || narf_bluetooth::pm::is_parked(0) {
            reset_all();
            return TestResult::Fail("device-PM resume did not unpark the controller");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/btusb", smoke_btusb_pm_ops_park_and_resume);
}
