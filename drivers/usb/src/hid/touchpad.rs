//! USB-HID Precision Touchpad (PTP) driver — clean-room.
//!
//! Bridges the kernel's HID Report-protocol parser
//! (`narf_hid::descriptor` / `narf_hid::report` / `narf_hid::ptp`)
//! into the USB-HID supervisor pipeline so a non-Boot HID touchpad
//! attached over USB delivers PointerEvents to the global input
//! ring. Boot-only HID Mouse devices keep using `hid::mouse` (3-byte
//! Boot report); this module covers the modern PTP shape with
//! multi-finger contacts, mechanical button, and resolution metadata.
//!
//! References (public, non-GPL only):
//! - **HID Class Specification 1.11** (USB-IF, June 2001) §7.1.1
//!   GET_DESCRIPTOR(REPORT) class request encoding.
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//! - **HID Usage Tables 1.4** (USB-IF, March 2022) §16 Digitizers,
//!   in particular the Touchpad usage page subset (Tip Switch,
//!   Contact ID, X/Y, In Range, Confidence).
//!   <https://www.usb.org/document-library/hid-usage-tables-14>
//! - **Microsoft Precision Touchpad implementation guide** (public
//!   docs.microsoft.com), drives the device-mode (`Mode Feature
//!   Report`) byte layout this driver writes once at attach.
//!   <https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/touchpad-required-hid-top-level-collections>
//!
//! No GPL/BSD source code (Linux, FreeBSD, NetBSD, U-Boot) consulted.
//!
//! ## Wire model
//!
//! 1. Match the device's HID interface (class 0x03) — any subclass /
//!    protocol; we don't require Boot Mouse (proto=2) here.
//! 2. Parse the device's HID Descriptor (type 0x21) at the interface
//!    descriptor's tail to learn the Report Descriptor length.
//! 3. Issue `GET_DESCRIPTOR(0x22, length)` (class request, recipient
//!    Interface) to fetch the raw Report Descriptor.
//! 4. Parse it with `narf_hid::descriptor::parse` then look for a PTP
//!    profile via `narf_hid::ptp::detect`.
//! 5. If matched: write the Mode Feature Report (`SET_REPORT` for
//!    Feature, value=mode_report_id, mode byte = 3 → "Mouse and
//!    Touch" Microsoft mode) so the device emits PTP-format reports
//!    instead of falling back to Boot Mouse on attach.
//! 6. SET_CONFIGURATION + arm the interrupt-IN endpoint, same as the
//!    Boot HID path.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_hid::descriptor::{self, ReportDescriptor};
use narf_hid::ptp::{self, DecodedReport, PtpProfile};
use narf_input::{
    evdev::{dispatch_rel_to_node, rel, DeviceCaps, DeviceId, DeviceNode, ROUTER},
    push_global, InputEvent, PointerButtons, PointerEvent,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::hid::HidError;
use crate::xhci::{EndpointConfig, EndpointKind, Xhci};

/// HID class triple constants (USB 2.0 §9.6.5 + HID 1.11 §4).
pub const HID_INTERFACE_CLASS: u8 = 0x03;
/// HID Descriptor Type — appears INSIDE a HID interface block,
/// not at the top of the configuration tree (HID 1.11 §6.2.1).
pub const HID_DESC_TYPE_HID: u8 = 0x21;
/// Report Descriptor — fetched via GET_DESCRIPTOR with this in the
/// high byte of wValue (HID 1.11 §7.1.1).
pub const HID_DESC_TYPE_REPORT: u8 = 0x22;

/// Class-specific request codes (HID 1.11 §7.2).
pub const HID_REQ_SET_REPORT: u8 = 0x09;

/// Per-poll buffer size for an interrupt-IN read off a PTP touchpad.
/// PTP reports run 14..64 bytes for typical contact counts (5
/// fingers); cap at 128 to give room for vendor-extended reports
/// (digitizer pen pressure, hover, scan-time padding) without
/// burning extra DMA per device. Buffer is reused across polls.
pub const PTP_REPORT_BUF_BYTES: usize = 128;

/// `bmRequestType` values (USB 2.0 §9.3, table 9-2).
pub const RT_DEV_TO_HOST_STD_IFACE: u8 = 0x81;
pub const RT_HOST_TO_DEV_CLASS_IFACE: u8 = 0x21;

/// One bound PTP touchpad. Held in the global [`TOUCHPADS`]
/// registry; the supervisor's pump cycle drains reports off each.
#[derive(Debug)]
pub struct PtpTouchpad {
    pub slot_id: u8,
    /// DCI of the interrupt-IN endpoint that carries reports.
    pub interrupt_in_dci: u8,
    pub interface_num: u8,
    /// Cached profile — the report-byte → field mapping derived
    /// from the device's Report Descriptor.
    pub profile: PtpProfile,
    /// Last seen primary contact's absolute position. Used to emit
    /// relative motion. `None` until the first in-range contact.
    last_xy: IrqSafeSpinLock<Option<(i32, i32)>>,
    /// Last seen mechanical button state, for press/release diff.
    last_button: IrqSafeSpinLock<bool>,
    /// evdev ROUTER device id — for unregister on detach.
    pub(crate) evdev_id: DeviceId,
    /// evdev DeviceNode — pointer events dispatched here.
    pub(crate) evdev_node: Arc<DeviceNode>,
}

/// Global registry of bound touchpads. Populated by
/// [`try_bind_touchpad_already_addressed`]; consumed by [`pump_all`].
static TOUCHPADS: IrqSafeSpinLock<Vec<Arc<PtpTouchpad>>> = IrqSafeSpinLock::new(Vec::new());

/// Locate the HID interface in a configuration descriptor and return
/// `(interface_num, hid_descriptor_offset, interrupt_in_endpoint)`.
/// Returns the FIRST HID interface that has an interrupt-IN endpoint
/// — devices with multiple HID interfaces (e.g., touchpad +
/// keyboard combo) get re-attempted on the other interface in a
/// follow-up cycle (not yet implemented; today the first match
/// wins).
pub fn find_hid_interface(cfg: &[u8]) -> Option<(u8, usize, EndpointConfig)> {
    let mut i = 0usize;
    let mut iface_num: Option<u8> = None;
    let mut hid_desc_off: Option<usize> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Descriptor.
            4 if len >= 9 => {
                if cfg[i + 5] == HID_INTERFACE_CLASS {
                    iface_num = Some(cfg[i + 2]);
                    hid_desc_off = None;
                } else {
                    iface_num = None;
                }
            }
            HID_DESC_TYPE_HID if iface_num.is_some() => {
                hid_desc_off = Some(i);
            }
            // Endpoint Descriptor (USB 2.0 §9.6.6).
            5 if len >= 7 && iface_num.is_some() => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer_t = attr & 0x03;
                let is_in = ep_addr & 0x80 != 0;
                if xfer_t == 3 && is_in {
                    if let (Some(num), Some(off)) = (iface_num, hid_desc_off) {
                        return Some((
                            num,
                            off,
                            EndpointConfig {
                                ep_addr,
                                max_packet: mps,
                                kind: EndpointKind::InterruptIn,
                            },
                        ));
                    }
                }
            }
            _ => {}
        }
        i += len;
    }
    None
}

/// Decode the Report Descriptor length out of a HID Descriptor block
/// (HID 1.11 §6.2.1 table 6-2). The block layout is:
///   +0 bLength (≥9), +1 bDescriptorType (=0x21), +2..3 bcdHID,
///   +4 bCountryCode, +5 bNumDescriptors,
///   +6 bDescriptorType[0] (=0x22 for Report), +7..8 wDescriptorLength[0].
/// Returns `Some(report_len)` when a Report subordinate is present.
pub fn report_descriptor_length(cfg: &[u8], hid_desc_off: usize) -> Option<u16> {
    if hid_desc_off + 9 > cfg.len() {
        return None;
    }
    let block = &cfg[hid_desc_off..];
    if block[1] != HID_DESC_TYPE_HID || block[0] < 9 {
        return None;
    }
    if block[6] != HID_DESC_TYPE_REPORT {
        return None;
    }
    Some(u16::from_le_bytes([block[7], block[8]]))
}

/// Caller-side post-address PTP touchpad bind: GET_DESCRIPTOR(REPORT)
/// + parse + ptp::detect + interrupt-IN arm + registry push. Returns
///   `Err(HidError::NotBootKeyboard)` when the device's report
///   descriptor doesn't shape like a PTP touchpad — caller's
///   cleanup_guard handles disable_slot.
pub async fn try_bind_touchpad_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    interface_num: u8,
    hid_desc_off: usize,
    cfg: &[u8],
    ep: EndpointConfig,
) -> Result<(), HidError> {
    let report_len = report_descriptor_length(cfg, hid_desc_off).ok_or(HidError::NoInterruptIn)?;
    if report_len == 0 || report_len > 4096 {
        return Err(HidError::NoInterruptIn);
    }
    let mut blob = alloc::vec![0u8; report_len as usize];
    let _ = xhci_dev
        .control_in(
            slot_id,
            RT_DEV_TO_HOST_STD_IFACE,
            crate::xhci::USB_REQ_GET_DESCRIPTOR,
            (HID_DESC_TYPE_REPORT as u16) << 8,
            interface_num as u16,
            &mut blob,
        )
        .await
        .map_err(HidError::Xhci)?;

    let parsed: ReportDescriptor = descriptor::parse(&blob).map_err(|_| HidError::NoInterruptIn)?;
    let profile = ptp::detect(&parsed).ok_or(HidError::NoInterruptIn)?;

    // Configure xHC-side endpoint context.
    xhci_dev
        .configure_endpoints(slot_id, &[ep])
        .await
        .map_err(HidError::Xhci)?;

    // SET_CONFIGURATION before any class request (USB 2.0 §9.4.7) —
    // a HID touchpad held in Address state will STALL SET_REPORT.
    // Walk for the first Configuration Descriptor's bConfigurationValue
    // (offset +5 of the 9-byte cfg-descriptor header).
    if cfg.len() < 9 || cfg[1] != 2 {
        return Err(HidError::NoInterruptIn);
    }
    let cfg_value = cfg[5];
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

    // SET_PROTOCOL(Report) — HID §7.2.6.
    //
    // Synaptics / Elan / most Precision Touchpads advertise the Boot
    // interface (bInterfaceSubClass=1, bInterfaceProtocol=2) for BIOS
    // compat AND ship powered-up in Boot Mouse protocol. Without an
    // explicit SET_PROTOCOL(REPORT=1) the device keeps emitting 3-byte
    // boot-mouse reports — and `ptp::decode_input` rejects every report
    // because `report[0]` won't match the descriptor-walked input
    // report-id. The Feature SET_REPORT below would succeed but be
    // ignored: silent enumeration failure, no PTP events ever surface.
    // Linux usbhid does this implicitly at attach for non-boot ifaces;
    // we do it explicitly here. Reference: Linux `drivers/hid/usbhid/
    // usbhid.c:usbhid_start_interrupt_in_default`.
    xhci_dev
        .control_in(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            crate::hid::HID_REQ_SET_PROTOCOL,
            crate::hid::HID_REPORT_PROTOCOL,
            interface_num as u16,
            &mut nothing,
        )
        .await
        .map_err(HidError::Xhci)?;

    // SET_IDLE(0, 0) — "report on state change only". Some Synaptics
    // firmware silently suppresses reports until SET_IDLE has been
    // issued at least once. Failure is non-fatal (devices that don't
    // implement it STALL; SET_PROTOCOL above was the load-bearing
    // call). Mirrors `BootKeyboard::attach`.
    let _ = xhci_dev
        .control_in(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            crate::hid::HID_REQ_SET_IDLE,
            0,
            interface_num as u16,
            &mut nothing,
        )
        .await;

    // Enable Microsoft PTP "Mouse + Touch" mode via the Mode Feature
    // Report. The mode value is 3 per the MS PTP guide. Failure is
    // non-fatal (some devices STALL the request and fall back to
    // their default mode); the worst case is the device reverts to
    // Boot Mouse semantics.
    if let Some(mode_report) = ptp::build_mode_feature_report(&profile, 3) {
        let report_id = mode_report[0] as u16;
        let _ = xhci_dev
            .control_out(
                slot_id,
                RT_HOST_TO_DEV_CLASS_IFACE,
                HID_REQ_SET_REPORT,
                // wValue = (report-type << 8) | report-id. Feature = 3.
                (3u16 << 8) | report_id,
                interface_num as u16,
                &mode_report[1..], // strip leading report-id byte; xHCI sends it via wValue
            )
            .await;
    }

    let interrupt_in_ep = ep.ep_addr & 0x0F;
    let dci = (interrupt_in_ep * 2) + 1;
    // Arm one Normal TRB so the controller starts polling the device
    // — same pattern as `BootKeyboard::attach`. Buffer size is the
    // descriptor's max-input-report length (typical PTP report is
    // 14..64 bytes).
    let buf_len = PTP_REPORT_BUF_BYTES;
    xhci_dev
        .arm_interrupt_in(slot_id, dci, buf_len as u32)
        .map_err(HidError::Xhci)?;

    // Register with the evdev ROUTER as a relative-motion pointer device.
    // The PTP driver emits relative (dx, dy) via the first-contact diff,
    // so REL_X/REL_Y is the right evdev type. Mirrors i8042_mouse.rs::init().
    let mut caps = DeviceCaps::new();
    caps.add_rel(rel::REL_X);
    caps.add_rel(rel::REL_Y);
    let (evdev_id, evdev_node) = ROUTER.register_device(caps);

    let pad = Arc::new(PtpTouchpad {
        slot_id,
        interrupt_in_dci: dci,
        interface_num,
        profile,
        last_xy: IrqSafeSpinLock::new(None),
        last_button: IrqSafeSpinLock::new(false),
        evdev_id,
        evdev_node,
    });
    TOUCHPADS.lock().push(pad);
    Ok(())
}

/// Unregister a touchpad's evdev DeviceNode from the ROUTER.
/// Call when the device is detached / unplugged.
pub fn unregister_touchpad_evdev(slot_id: u8) {
    let mut g = TOUCHPADS.lock();
    if let Some(pos) = g.iter().position(|p| p.slot_id == slot_id) {
        let pad = g.remove(pos);
        ROUTER.unregister_device(pad.evdev_id);
    }
}

/// Drain reports from every bound touchpad. Each successful poll
/// drives `ptp::decode_input` over the report bytes and pushes a
/// `PointerEvent` (relative dx/dy + button state) onto the global
/// input ring for the FIRST in-range contact. Multi-finger gestures
/// (two-finger scroll, three-finger swipe) are a follow-up — the
/// first-contact translation here matches what a Boot Mouse would
/// produce, just sourced from the PTP report instead of a 3-byte
/// Boot blob.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    let pads: Vec<Arc<PtpTouchpad>> = {
        let g = TOUCHPADS.lock();
        g.clone()
    };
    let mut total = 0usize;
    for pad in &pads {
        let mut buf = alloc::vec![0u8; PTP_REPORT_BUF_BYTES];
        loop {
            match xhci_dev.poll_interrupt_in(pad.slot_id, pad.interrupt_in_dci, &mut buf) {
                Ok(Some(_)) => {
                    if let Ok(decoded) = ptp::decode_input(&pad.profile, &buf) {
                        total += emit_events(pad, decoded);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }
    total
}

/// Translate one decoded PTP report into PointerEvent(s). Returns
/// the number of events emitted. Logic:
/// - Track the FIRST in-range contact's (x, y); diff against the
///   cached last position to produce relative dx/dy.
/// - Track the mechanical button bit; flip → emit press/release with
///   the cached pointer position (dx=dy=0).
/// - All-fingers-up clears the cached position so the next contact
///   doesn't teleport.
fn emit_events(pad: &PtpTouchpad, r: DecodedReport) -> usize {
    let primary = r
        .contacts
        .iter()
        .take(r.contact_count as usize)
        .find(|c| c.in_range && c.confidence);
    let mut emitted = 0usize;

    let buttons = if r.button1 {
        PointerButtons::LEFT
    } else {
        PointerButtons::from_bits_truncate(0)
    };

    // Pointer motion based on first-contact xy diff.
    if let Some(c) = primary {
        let mut last = pad.last_xy.lock();
        let (dx, dy) = match *last {
            Some((px, py)) => (c.x - px, c.y - py),
            None => (0, 0),
        };
        *last = Some((c.x, c.y));
        if dx != 0 || dy != 0 {
            // Legacy ring.
            push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
            // evdev ROUTER — relative motion.
            dispatch_rel_to_node(&pad.evdev_node, dx, dy);
            emitted += 1;
        }
    } else {
        // No fingers down — clear the anchor so a fresh tap next
        // cycle doesn't synthesise a huge dx/dy from the old
        // position.
        *pad.last_xy.lock() = None;
    }

    // Button transition.
    {
        let mut last_btn = pad.last_button.lock();
        if *last_btn != r.button1 {
            *last_btn = r.button1;
            // Legacy ring.
            push_global(InputEvent::Pointer(PointerEvent {
                dx: 0,
                dy: 0,
                buttons,
            }));
            // evdev ROUTER — button click (dx=0 dy=0 still needs a SYN_REPORT
            // frame; dispatch_rel_to_node always appends one).
            dispatch_rel_to_node(&pad.evdev_node, 0, 0);
            emitted += 1;
        }
    }

    let _ = pad.profile.input_report_id; // silences if unused at any future cut
    let _ = r.scan_time;
    emitted
}

/// Number of bound touchpads. Test + diagnostics helper.
pub fn attached_touchpad_count() -> usize {
    TOUCHPADS.lock().len()
}
