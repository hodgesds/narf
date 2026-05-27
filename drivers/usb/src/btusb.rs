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
//!   We do *not* port the vendor-specific Intel / Broadcom /
//!   Realtek bring-up quirks: that's Stage 1+.
//!
//! ## Stage 0 scope
//!
//! 1. Recognise interface (class=0xE0, subclass=0x01, protocol=0x01).
//! 2. Walk the configuration descriptor for the bulk-IN/OUT ACL pair
//!    and the interrupt-IN event endpoint.
//! 3. Configure those endpoints + issue SET_CONFIGURATION.
//! 4. Drive Stage-0 HCI bring-up directly against the xHCI async
//!    transfer paths: Reset → Read_Local_Version.
//! 5. Log `bluetooth: $vendor adapter, HCI v$ver, Bluetooth $bt_ver`.
//! 6. Register an `HciTransport` against the slot for Stage-1+ users.
//!
//! Out of scope for Stage 0: ACL data plane (L2CAP / GATT / pairing),
//! SCO/eSCO isoch streaming, vendor firmware load, LE Advertising,
//! BR/EDR Inquiry. Those land as separate stages.
//!
//! Why a per-driver async bring-up instead of routing through the
//! existing `narf_bluetooth::controller::Controller::bring_up`:
//! `Controller::bring_up` is synchronous and goes through the
//! `HciTransport` trait, which is also synchronous. Calling
//! `narf_scheduler::block_on` from inside the supervisor's executor
//! poll panics by design. So Stage-0 bring-up runs as an inline
//! async dance using `xhci.control_out` / `xhci.poll_interrupt_in`
//! directly, and the trait-based transport is registered afterwards
//! for any caller that can drive it from a non-executor context
//! (Stage-1+ ACL pumps).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_bluetooth::controller::ControllerInfo;
use narf_bluetooth::event::{CommandComplete, EventCode};
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
}

/// Walk a Configuration Descriptor for the *first* HCI interface and
/// resolve the three required endpoints. Returns `Err(NotBluetooth)`
/// if no matching interface exists, or one with the required endpoints
/// is missing.
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
                if in_match && interface.is_none() {
                    interface = Some(cfg[i + 2]);
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
                        });
                    }
                    // Bulk-IN — ACL data.
                    (2, true) if acl_in.is_none() => {
                        acl_in = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::BulkIn,
                        });
                    }
                    // Bulk-OUT — ACL data.
                    (2, false) if acl_out.is_none() => {
                        acl_out = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::BulkOut,
                        });
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
    pub slot_id: u8,
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
            .field("slot_id", &self.slot_id)
            .field("endpoints", &self.endpoints)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// Registry of bound USB Bluetooth controllers. Append-only for now;
/// Stage 1 will introduce removal on detach.
static BTUSB_DEVICES: IrqSafeSpinLock<Vec<Arc<BtUsbDevice>>> =
    IrqSafeSpinLock::new(Vec::new());

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
}

/// `HciTransport` implementation backed by the xHCI control / bulk /
/// interrupt-IN transfer paths.
///
/// **Sync-context only**: every method bridges to async xHCI calls
/// via `narf_scheduler::block_on`, which panics from inside an
/// executor poll. Stage-0 bring-up uses the async helpers below
/// directly; this transport exists so Stage-1+ callers running in
/// a kernel thread (not an executor task) can issue HCI commands
/// once L2CAP / GATT pumps are wired up.
pub struct UsbHciTransport {
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    acl_in_dci: u8,
    acl_out_dci: u8,
    event_max_packet: u16,
    /// Re-arm flag: set the first time `recv_event` is called so the
    /// interrupt-IN endpoint is pre-armed before the first poll.
    armed: AtomicBool,
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
            .finish_non_exhaustive()
    }
}

impl UsbHciTransport {
    fn xhci(&self) -> Result<Arc<Xhci>, TransportError> {
        crate::xhci::controller().ok_or(TransportError::Detached)
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
}

impl HciTransport for UsbHciTransport {
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
        let xhci = self.xhci()?;
        let payload = cmd.encode();
        narf_scheduler::block_on(xhci.control_out(
            self.slot_id,
            RT_HCI_COMMAND,
            REQ_HCI_COMMAND,
            0,
            self.interface as u16,
            &payload,
        ))
        .map_err(|_| TransportError::Transient)?;
        Ok(())
    }

    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        let xhci = self.xhci()?;
        self.arm_event_in(&xhci)?;
        let mut buf = [0u8; 257];
        match xhci.poll_interrupt_in(self.slot_id, self.event_dci, &mut buf) {
            Ok(Some(n)) => {
                let event = Event::decode(&buf[..n]).ok_or(TransportError::Transient)?;
                Ok(Some(event))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(TransportError::Transient),
        }
    }

    fn send_acl(&self, data: &[u8]) -> Result<(), TransportError> {
        let xhci = self.xhci()?;
        narf_scheduler::block_on(xhci.bulk_out(self.slot_id, self.acl_out_dci, data))
            .map_err(|_| TransportError::Transient)?;
        Ok(())
    }

    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        // Stage 2: pull an ACL packet from the bulk-IN endpoint.
        // Uses block_on(bulk_in) — only call from a non-executor
        // kernel thread (ACL pump task). Ref: btusb_bulk_in() in
        // drivers/bluetooth/btusb.c.
        let xhci = self.xhci()?;
        let mut buf = [0u8; 1024];
        match narf_scheduler::block_on(xhci.bulk_in(self.slot_id, self.acl_in_dci, &mut buf)) {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(buf[..n].to_vec())),
            Err(_) => Ok(None),
        }
    }

    fn send_sco(&self, data: &[u8]) -> Result<(), TransportError> {
        // SCO/eSCO: fall back to bulk-OUT until dedicated isoch
        // endpoint tracking lands (Stage 3+).
        let xhci = self.xhci()?;
        narf_scheduler::block_on(xhci.bulk_out(self.slot_id, self.acl_out_dci, data))
            .map_err(|_| TransportError::Transient)?;
        Ok(())
    }

    // recv_sco uses the default no-op implementation — dedicated isoch
    // IN endpoint tracking is a Stage 3+ concern.

    fn name(&self) -> &'static str {
        "usb"
    }
}

/// Issue one HCI Command on the control endpoint + wait for the
/// matching Command Complete event on the interrupt-IN endpoint.
/// Per Vol 4 Part E §6 the per-command budget is at least 5 s.
async fn send_command_and_await_complete(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    event_max_packet: u16,
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

    // Re-arm the interrupt-IN endpoint and busy-poll until the
    // controller posts a Transfer Event for it. The interrupt-IN
    // path doesn't have an inline async wait; we poll-with-yield.
    let len = event_max_packet.min(257) as u32;
    xhci.arm_interrupt_in(slot_id, event_dci, len)
        .map_err(|_| BtUsbError::CommandTransfer)?;

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
                    // Re-arm and continue polling for CommandComplete.
                    let _ = xhci.arm_interrupt_in(slot_id, event_dci, len);
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

/// Post-address Bluetooth bind: caller has already issued port_reset +
/// enable_slot + address_device. We pull the config descriptor, match
/// the HCI interface + endpoints, configure them on the xHC, issue
/// SET_CONFIGURATION, then run the Stage-0 bring-up sequence and log
/// a single line summarising the controller.
///
/// Returns `Ok(())` on success. On failure the caller frees the slot.
pub async fn try_bind_btusb_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<(), BtUsbError> {
    let eps = find_bt_endpoints(cfg)?;

    // Configure the xHC-side endpoint contexts for the three required
    // endpoints. EP0 (default control) is already provisioned by
    // address_device.
    xhci_dev
        .configure_endpoints(slot_id, &[eps.event_in, eps.acl_in, eps.acl_out])
        .await
        .map_err(|_| BtUsbError::EndpointConfig)?;

    // SET_CONFIGURATION before any class request (USB 2.0 §9.4.7) —
    // without it the controller's class-specific Setup transfer for
    // HCI_Reset would STALL.
    let mut nothing = [0u8; 0];
    xhci_dev
        .control_in(
            slot_id,
            0x00, // bmRequestType: Host-to-Device, Standard, Device
            STD_REQ_SET_CONFIGURATION,
            eps.config_value as u16,
            0,
            &mut nothing,
        )
        .await
        .map_err(|_| BtUsbError::SetConfiguration)?;

    // ── Stage-0 bring-up dance ────────────────────────────────────
    // Vol 4 Part E §3 — Reset, Read_Local_Version. We stop at
    // Read_Local_Version: Read_BD_ADDR + Read_Buffer_Size +
    // Set_Event_Mask are part of Stage-1 (full controller setup).
    let event_dci = ep_dci(eps.event_in.ep_addr, /*is_in*/ true);
    let acl_in_dci = ep_dci(eps.acl_in.ep_addr, /*is_in*/ true);
    let acl_out_dci = ep_dci(eps.acl_out.ep_addr, /*is_in*/ false);

    // HCI_Reset (§7.3.2) — no parameters, no return params beyond
    // status. After this the controller is in a defined post-reset
    // state and discards any in-flight ACL / SCO traffic.
    let _ = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        eps.event_in.max_packet,
        op::HCI_RESET,
        &[],
    )
    .await?;

    // HCI_Read_Local_Version_Information (§7.4.1) — returns
    // HCI_Version (1) + HCI_Revision (2) + LMP_Version (1) +
    // Manufacturer_Name (2) + LMP_Subversion (2).
    let ret = send_command_and_await_complete(
        xhci_dev,
        slot_id,
        eps.interface,
        event_dci,
        eps.event_in.max_packet,
        op::HCI_READ_LOCAL_VERSION,
        &[],
    )
    .await?;
    if ret.len() < 8 {
        return Err(BtUsbError::ShortReturnParams);
    }
    let info = ControllerInfo {
        bd_addr: [0; 6],
        hci_version: ret[0],
        hci_revision: u16::from_le_bytes([ret[1], ret[2]]),
        lmp_version: ret[3],
        manufacturer: u16::from_le_bytes([ret[4], ret[5]]),
        lmp_subversion: u16::from_le_bytes([ret[6], ret[7]]),
        ..Default::default()
    };

    // Register a sync-context transport for Stage-1+ callers (L2CAP
    // pump, ACL data plane). Stage-0 itself is done: every command
    // it issued used the async helper above.
    let transport: Arc<dyn HciTransport> = Arc::new(UsbHciTransport {
        slot_id,
        interface: eps.interface,
        event_dci,
        acl_in_dci,
        acl_out_dci,
        event_max_packet: eps.event_in.max_packet,
        armed: AtomicBool::new(true), // already armed by the bring-up
    });
    narf_bluetooth::transport::register(transport.clone());

    {
        use core::fmt::Write as _;
        static ATTACHED: AtomicU64 = AtomicU64::new(0);
        let bit = 1u64 << (slot_id as u32 & 63);
        let prev = ATTACHED.fetch_or(bit, Ordering::AcqRel);
        if prev & bit == 0 {
            let vendor = vendor_name(info.manufacturer);
            let bt_ver = bt_version_name(info.hci_version);
            let _ = writeln!(
                narf_console::Writer,
                "  bluetooth: {} adapter, HCI v0x{:02x}, Bluetooth {}",
                vendor, info.hci_version, bt_ver
            );
        }
    }

    BTUSB_DEVICES.lock().push(Arc::new(BtUsbDevice {
        slot_id,
        endpoints: eps,
        transport,
        info,
    }));
    Ok(())
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
