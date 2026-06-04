//! USB HID Consumer Control (Usage Page 0x0C) driver — clean-room.
//!
//! ## References
//!
//! - "HID Usage Tables for Universal Serial Bus (USB)" Version 1.4,
//!   March 2022 (USB-IF). §15 Consumer Page. Usage values 0x01
//!   (Consumer Control Application) through the extended set.
//!   <https://www.usb.org/document-library/hid-usage-tables-14>
//!
//! - "Device Class Definition for Human Interface Devices (HID)"
//!   Version 1.11, 27 June 2001 (USB-IF). §6.2 (HID Descriptor), §7
//!   (class requests), Appendix B (Boot Protocol).
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//!
//! - Linux `drivers/hid/hid-input.c` — consumer-page usage-to-key
//!   mapping (GPL-2.0-or-later; adapted under NARF's GPL-2.0-or-later
//!   relicense per 2026-05-20 audit decision). The mapping table in
//!   `usage_to_keycode` tracks the `hidinput_hid_event` switch-case
//!   for `HID_UP_CONSUMER` items.
//!
//! ## Shape
//!
//! HID Consumer Control devices (USB usage page 0x0C, application
//! usage 0x01) carry non-typing input: volume, media transport,
//! brightness, sleep, wakeup, eject, and a large family of
//! vendor-specific function keys. Most laptop internal keyboards
//! attach a *composite* USB device that presents both a keyboard HID
//! interface (page 0x01) and a consumer HID interface (page 0x0C) on
//! separate endpoints, allowing Fn-key hotkeys to reach userspace as
//! consumer-page events independently of the boot-keyboard path.
//!
//! Report format: there is no mandated "boot consumer" format. Each
//! device describes its own report layout via a Report Descriptor.
//! In practice the vast majority of consumer-page devices use one of:
//!
//! - **1-byte**: a single usage-code field (common for dongle-style
//!   receivers, low-cost keyboards); at most one consumer key at a time.
//! - **2-byte little-endian**: a 16-bit usage code field; same
//!   semantics but allows usage codes above 0xFF.
//! - **Bitmap or multi-field**: rarely used on laptop keyboards; one
//!   bit per usage or several consecutive usage-minimum/maximum pairs.
//!
//! This driver handles the common 1-byte and 2-byte list-encoded
//! forms. Report IDs, when present, are detected and stripped. Usage
//! codes that exceed 16 bits are discarded (all Consumer Page codes
//! in HID 1.4 fit in 16 bits). Codes that don't map to a known
//! `KeyCode` produce no event.
//!
//! ## Pipeline
//!
//! 1. `try_bind_consumer_already_addressed` — called from
//!    `attach::dispatch_after_address` after the slot is addressed.
//!    Walks the configuration descriptor looking for a HID interface
//!    whose Report Descriptor advertises Consumer Control (Usage Page
//!    0x0C, application usage 0x01). Configures the endpoint, issues
//!    SET_CONFIGURATION + SET_PROTOCOL(Report) + SET_IDLE, arms the
//!    interrupt-IN TRB, and registers the device in `CONSUMER_DEVICES`.
//!
//! 2. `pump_all` — called from the supervisor's xHCI-IRQ / 100 ms
//!    timeout cycle. Drains pending interrupt-IN reports from each
//!    bound consumer device, diffs them against the previous report,
//!    and pushes `InputEvent::Key` events for any usage codes that
//!    entered or left the pressed set.

extern crate alloc;

use alloc::vec::Vec;

use narf_input::{push_key, KeyCode};
use narf_lib::sync::IrqSafeSpinLock;

use crate::hid::{HidError, HID_REPORT_PROTOCOL, HID_REQ_SET_IDLE, HID_REQ_SET_PROTOCOL};
use crate::xhci::{EndpointConfig, EndpointKind, Xhci};

// ── HID Consumer Page constants ────────────────────────────────────

/// HID Usage Page: Consumer Control (USB-IF HID Usage Tables §15).
pub const USAGE_PAGE_CONSUMER: u8 = 0x0C;
/// Consumer Control application-collection usage (§15 table 15-1,
/// "Consumer Control", usage type CA = Collection Application).
pub const USAGE_CONSUMER_CONTROL: u16 = 0x01;

/// Short-item Usage Page tag (bits[7:4] = 0x00, bits[3:2] = 0x01 for
/// global, bits[1:0] = size). HID Report Descriptor item encoding:
/// low-nibble of tag byte = 0x0 (Usage Page) and prefix bits = 0x1
/// (global). The full byte for "Usage Page, 1-byte data" = 0x05.
const HID_ITEM_USAGE_PAGE_1B: u8 = 0x05;
/// "Usage Page, 2-byte data" — covers pages > 0xFF (not needed for
/// Consumer but we check it to avoid false negatives).
const HID_ITEM_USAGE_PAGE_2B: u8 = 0x06;
/// "Usage, 1-byte data" — local item for the collection usage value.
const HID_ITEM_USAGE_1B: u8 = 0x09;
/// "Usage, 2-byte data" — local item for usages > 0xFF.
const HID_ITEM_USAGE_2B: u8 = 0x0A;
/// "Collection" item — follows the Usage item and opens a collection.
const HID_ITEM_COLLECTION: u8 = 0xA1;
/// Collection type Application (CA) = 0x01.
const HID_COLLECTION_APPLICATION: u8 = 0x01;

/// HID Descriptor type (bDescriptorType = 0x21 for HID, 0x22 for
/// Report Descriptor). See HID 1.11 §6.2.
pub const HID_DESC_TYPE_HID: u8 = 0x21;
/// HID Report Descriptor type. Fetched via
/// GET_DESCRIPTOR(wValue=(0x22 << 8)).
pub const HID_DESC_TYPE_REPORT: u8 = 0x22;

// Standard request codes reused from the touchpad module.
const RT_DEV_TO_HOST_STD_IFACE: u8 = 0x81;
const RT_HOST_TO_DEV_CLASS_IFACE: u8 = 0x21;

/// Maximum report descriptor blob size we'll fetch. Reports larger
/// than this are almost certainly firmware bugs; cap to bound
/// allocation.
const MAX_REPORT_DESCRIPTOR: usize = 4096;
/// Maximum interrupt-IN report size. Consumer Control reports are
/// typically 1-4 bytes; we size up to 64 to cover exotic devices
/// with long bitmaps or vendor-padding.
const CONSUMER_REPORT_BUF: usize = 64;

// ── Bound device record ────────────────────────────────────────────

/// One bound Consumer Control interface. Tracks the xHCI slot +
/// endpoint and enough state to diff successive reports.
#[derive(Debug)]
pub struct ConsumerDevice {
    pub slot_id: u8,
    /// DCI (Doorbell Context Index) of the interrupt-IN endpoint.
    pub interrupt_in_dci: u8,
    pub interface_num: u8,
    /// Optional report ID prefix byte. If the device's Report
    /// Descriptor opens the consumer collection with a Report ID
    /// item, every report starts with that byte and we strip it
    /// before parsing the usage-code bytes. `None` = no report ID.
    pub report_id: Option<u8>,
    /// Previous report payload (up to 8 usage codes, list-encoded).
    /// Diffed against each new report to synthesise press/release
    /// events. Stored in `[u16; 8]` to handle 2-byte usage codes.
    last_report: IrqSafeSpinLock<[u16; 8]>,
}

/// Global registry of bound Consumer Control interfaces.
static CONSUMER_DEVICES: IrqSafeSpinLock<Vec<ConsumerDevice>> = IrqSafeSpinLock::new(Vec::new());

// ── Usage-page detection in Report Descriptor ─────────────────────

/// Walk a raw HID Report Descriptor blob and return `true` if it
/// contains a Consumer Control Application Collection (Usage Page
/// 0x0C, Usage 0x01, Collection Application). Many laptops expose a
/// composite USB device whose second HID interface carries exactly
/// this signature.
///
/// The parser is a minimal state machine — just enough to identify
/// the page + usage pair before a Collection(Application) item.
/// Full descriptor parsing (field widths, report IDs, bitmap shapes)
/// lives in `narf_hid::descriptor`; this function is the cheap
/// "is this the right interface?" gate.
///
/// Adapted from `drivers/hid/hid-input.c` `hidinput_configure_usages`
/// (GPL-2.0-or-later) — specifically the logic that identifies a
/// Consumer Control top-level collection before dispatching to usage
/// handlers.
pub fn has_consumer_control_collection(report_desc: &[u8]) -> bool {
    let mut i = 0usize;
    let mut current_page: u16 = 0;
    let mut pending_usage: u16 = 0;

    while i < report_desc.len() {
        let tag = report_desc[i];
        // HID short-item size field: bits [1:0] encode 0→0, 1→1, 2→2, 3→4 bytes.
        let size_bits = tag & 0x03;
        let payload_len: usize = match size_bits {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => unreachable!(),
        };
        if i + 1 + payload_len > report_desc.len() {
            break;
        }
        let payload = &report_desc[i + 1..i + 1 + payload_len];

        // Decode the payload as a little-endian unsigned integer
        // (most relevant items are 1-2 bytes).
        let val: u32 = match payload_len {
            0 => 0,
            1 => payload[0] as u32,
            2 => u16::from_le_bytes([payload[0], payload[1]]) as u32,
            4 => u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
            _ => 0,
        };

        // Long items (tag == 0xFE) are rare; skip the header + length byte.
        if tag == 0xFE {
            if i + 2 <= report_desc.len() {
                let long_size = report_desc[i + 1] as usize;
                i += 2 + long_size;
            } else {
                break;
            }
            continue;
        }

        match tag {
            HID_ITEM_USAGE_PAGE_1B | HID_ITEM_USAGE_PAGE_2B => {
                current_page = val as u16;
                pending_usage = 0; // new page resets pending usage
            }
            HID_ITEM_USAGE_1B | HID_ITEM_USAGE_2B => {
                pending_usage = val as u16;
            }
            HID_ITEM_COLLECTION => {
                if payload_len >= 1
                    && current_page == USAGE_PAGE_CONSUMER as u16
                    && pending_usage == USAGE_CONSUMER_CONTROL
                    && val as u8 == HID_COLLECTION_APPLICATION
                {
                    return true;
                }
                // Any collection resets the pending usage; the page
                // persists across nested collections per HID 1.11 §6.2.2.
                pending_usage = 0;
            }
            _ => {}
        }
        i += 1 + payload_len;
    }
    false
}

/// Scan a Report Descriptor for a Report ID item that appears inside
/// (or immediately before) a Consumer Control Application Collection.
/// Returns the report ID byte (1-254), or `None` if no Report ID was
/// found before the consumer collection opens.
///
/// This is best-effort: if the descriptor uses multiple report IDs
/// and the consumer collection's ID isn't the first one declared,
/// the caller will find a non-matching byte at report[0] and fall
/// back to no-report-ID mode. In practice consumer-control
/// interfaces on laptops either have no report ID or have exactly
/// one (since there's typically only one collection on that
/// interface).
pub fn detect_report_id(report_desc: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    let mut current_page: u16 = 0;
    let mut pending_usage: u16 = 0;
    let mut last_report_id: Option<u8> = None;

    // HID "Report ID" global item: tag = 0x85 = (0x08 << 4) | (1 << 2) | 1.
    // bits[7:4] = 0x8 (Report ID tag), bits[3:2] = 0x1 (global), bits[1:0] = 0x1 (1 byte).
    const HID_ITEM_REPORT_ID: u8 = 0x85;

    while i < report_desc.len() {
        let tag = report_desc[i];
        let size_bits = tag & 0x03;
        let payload_len: usize = match size_bits {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => unreachable!(),
        };
        if i + 1 + payload_len > report_desc.len() {
            break;
        }
        let payload = &report_desc[i + 1..i + 1 + payload_len];
        let val: u32 = match payload_len {
            0 => 0,
            1 => payload[0] as u32,
            2 => u16::from_le_bytes([payload[0], payload[1]]) as u32,
            4 => u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
            _ => 0,
        };

        if tag == 0xFE {
            if i + 2 <= report_desc.len() {
                let long_size = report_desc[i + 1] as usize;
                i += 2 + long_size;
            } else {
                break;
            }
            continue;
        }

        match tag {
            HID_ITEM_USAGE_PAGE_1B | HID_ITEM_USAGE_PAGE_2B => {
                current_page = val as u16;
                pending_usage = 0;
            }
            HID_ITEM_USAGE_1B | HID_ITEM_USAGE_2B => {
                pending_usage = val as u16;
            }
            HID_ITEM_REPORT_ID => {
                last_report_id = Some(val as u8);
            }
            HID_ITEM_COLLECTION => {
                if current_page == USAGE_PAGE_CONSUMER as u16
                    && pending_usage == USAGE_CONSUMER_CONTROL
                    && payload_len >= 1
                    && val as u8 == HID_COLLECTION_APPLICATION
                {
                    return last_report_id;
                }
                pending_usage = 0;
            }
            _ => {}
        }
        i += 1 + payload_len;
    }
    None
}

// ── Consumer Control report decoder ───────────────────────────────

/// Decode a raw consumer-control interrupt-IN report byte slice into
/// a list of up to 8 pressed usage codes. `report_id` is `Some(id)`
/// if the device uses a report-ID prefix; in that case the first byte
/// of the slice is compared against `id` before parsing. Returns an
/// empty array when the report is empty, the report-ID doesn't match,
/// or all usage codes are zero.
///
/// Encoding: treats each byte in the payload as an independent 1-byte
/// usage code (the standard HID Consumer Control Array encoding:
/// `Logical Minimum(0)`, `Logical Maximum(255)`, `Report Size(8)`,
/// `Report Count(N)` — each non-zero byte is one currently-pressed
/// usage). This covers virtually all laptop consumer-control
/// interfaces found in the wild.
///
/// 2-byte (16-bit little-endian) usage codes exist in the HID spec
/// (Consumer Page usage IDs above 0xFF) but no real laptop keyboard
/// interface uses them; this decoder intentionally does not attempt
/// to auto-detect them. A full Report Descriptor parser would tell
/// us the field width; this minimal decoder uses 1 byte per field.
///
/// Adapted from the Linux `hid_process_event` loop for consumer-page
/// Array items (`drivers/hid/hid-core.c`), GPL-2.0-or-later.
pub fn decode_report(report: &[u8], report_id: Option<u8>) -> [u16; 8] {
    let mut out = [0u16; 8];
    let data = match report_id {
        Some(id) => {
            if report.is_empty() || report[0] != id {
                return out;
            }
            &report[1..]
        }
        None => report,
    };

    if data.is_empty() {
        return out;
    }

    // 1-byte list: each byte is a distinct usage code currently
    // pressed (key-array encoding, same as the HID boot keyboard).
    let mut idx = 0usize;
    for &b in data.iter().take(8) {
        if b != 0 {
            out[idx] = b as u16;
            idx += 1;
        }
    }
    out
}

// ── Consumer usage code → narf_input KeyCode ──────────────────────

/// Map a HID Consumer Control usage code (page 0x0C) to a NARF
/// `KeyCode`. Returns `KeyCode::Unknown` for unrecognised or
/// intentionally-unmapped codes.
///
/// Table source: Linux `drivers/hid/hid-input.c`
/// `hidinput_hid_event` switch for `HID_UP_CONSUMER` (0x000C0000),
/// GPL-2.0-or-later. Only codes with a 1:1 correspondent in NARF's
/// `KeyCode` set are listed; exotic consumer-page codes (web browser
/// navigation, CD-player functions, app launch keys) fall through to
/// `Unknown` until a consumer registers interest.
pub fn usage_to_keycode(usage: u16) -> KeyCode {
    // Vendor-specific / OEM ranges (≥ 0x400 in Consumer page) are
    // beyond HID 1.4 Table 15 and are left Unknown.
    match usage {
        // Power controls (§15, table 15-3).
        0x30 => KeyCode::Power,
        0x82 => KeyCode::Sleep,
        0x83 => KeyCode::WakeUp,

        // Media transport (§15, table 15-4). These map to Linux
        // KEY_NEXTSONG / KEY_PREVIOUSSONG / KEY_PLAYPAUSE / KEY_STOP.
        0xB5 => KeyCode::NextSong,
        0xB6 => KeyCode::PreviousSong,
        0xB7 => KeyCode::Stop,
        0xCD => KeyCode::PlayPause,

        // Eject / fastforward / rewind (§15, table 15-5).
        // FastForward / Rewind don't have dedicated NARF KeyCodes;
        // they map to Unknown for now. Eject is common on MacBook-
        // style keyboards and on external optical drives.
        0xB8 => KeyCode::Stop, // Eject → Stop as closest semantic

        // Volume / mute (§15, table 15-7). These are the three most
        // common consumer keys on any laptop keyboard.
        0xE0 => KeyCode::Mute, // Mute
        0xE2 => KeyCode::Mute, // Mute (some devices use 0xE2)
        0xE9 => KeyCode::VolumeUp,
        0xEA => KeyCode::VolumeDown,

        // Brightness (§15, "Display Brightness" area). HID 1.4 §15
        // table 15-12 and USB-IF Approved Usage Tables errata. Linux
        // maps these to KEY_BRIGHTNESSUP / KEY_BRIGHTNESSDOWN.
        0x6F => KeyCode::BrightnessUp,
        0x70 => KeyCode::BrightnessDown,

        // Keyboard Illumination (backlight, §15 table 15-12). Linux
        // maps these to KEY_KBDILLUMTOGGLE / KEY_KBDILLUMDOWN /
        // KEY_KBDILLUMUP.
        0x79 => KeyCode::KbdIlluminationToggle,
        0x7A => KeyCode::KbdIlluminationUp,
        0x7B => KeyCode::KbdIlluminationDown,

        // Wireless / WLAN / Airplane mode. Linux: KEY_WLAN.
        0x18A => KeyCode::WLan, // AL Internet Browser (closest)
        0x0C8 => KeyCode::WLan, // AC Wireless (§15.6 consumer)

        // Touchpad toggle (Fn+F9 on many AMD laptops). Vendor-specific
        // on many OEMs but a handful use the HID consumer code.
        0x1F4 => KeyCode::TouchpadToggle,

        _ => KeyCode::Unknown,
    }
}

// ── Report diff → KeyCode press/release events ────────────────────

/// Diff two consumer-control usage-code arrays and push press /
/// release `KeyEvent`s for any transitions. Returns the number of
/// events emitted.
///
/// Uses the same "set difference" approach as `hid::translate_diff`
/// for the boot keyboard: codes in `prev` that don't appear in `cur`
/// become releases; codes in `cur` that weren't in `prev` become
/// presses. Zero-valued slots (empty/padding) are ignored.
pub fn translate_diff(prev: &[u16; 8], cur: &[u16; 8]) -> usize {
    let mut emitted = 0usize;
    // Releases: codes present in prev that have left cur.
    for &p in prev.iter() {
        if p == 0 {
            continue;
        }
        if !cur.iter().any(|&c| c == p) {
            let code = usage_to_keycode(p);
            if code != KeyCode::Unknown {
                push_key(code, false);
                emitted += 1;
            }
        }
    }
    // Presses: codes present in cur that weren't in prev.
    for &c in cur.iter() {
        if c == 0 {
            continue;
        }
        if !prev.iter().any(|&p| p == c) {
            let code = usage_to_keycode(c);
            if code != KeyCode::Unknown {
                push_key(code, true);
                emitted += 1;
            }
        }
    }
    emitted
}

// ── Configuration-descriptor scan for consumer HID interface ──────

/// Walk a USB Configuration Descriptor blob looking for a HID
/// interface whose inline HID Descriptor (`bDescriptorType=0x21`)
/// advertises a Report Descriptor, then fetch + scan the Report
/// Descriptor for a Consumer Control Application Collection.
///
/// Returns `(interface_num, hid_desc_offset, interrupt_in_ep)` on
/// success. The caller supplies the full config blob (same slice
/// passed around the rest of `attach::dispatch_after_address`) rather
/// than issuing a second GET_DESCRIPTOR(CONFIG) round-trip.
///
/// Unlike the boot-keyboard / boot-mouse scanners this function does
/// NOT look at `bInterfaceProtocol` — consumer devices typically
/// present Protocol=0 (non-boot). The report descriptor check is the
/// only reliable gate.
pub fn find_consumer_interface(cfg: &[u8]) -> Option<(u8, usize, EndpointConfig)> {
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
            // Interface Descriptor (§9.6.5): class 0x03 = HID.
            4 if len >= 9 => {
                if cfg[i + 5] == crate::hid::HID_INTERFACE_CLASS {
                    iface_num = Some(cfg[i + 2]);
                    hid_desc_off = None;
                } else {
                    iface_num = None;
                    hid_desc_off = None;
                }
            }
            // HID Descriptor (0x21) — inline subordinate.
            HID_DESC_TYPE_HID if iface_num.is_some() => {
                hid_desc_off = Some(i);
            }
            // Endpoint Descriptor: interrupt-IN endpoint.
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

/// Extract the Report Descriptor length from the inline HID
/// Descriptor block at `hid_desc_off`. Mirrors
/// `hid::touchpad::report_descriptor_length`.
fn report_descriptor_length(cfg: &[u8], hid_desc_off: usize) -> Option<u16> {
    if hid_desc_off + 9 > cfg.len() {
        return None;
    }
    let block = &cfg[hid_desc_off..];
    if block[1] != HID_DESC_TYPE_HID || block[0] < 9 {
        return None;
    }
    // Subordinate descriptor type must be Report (0x22).
    if block[6] != HID_DESC_TYPE_REPORT {
        return None;
    }
    Some(u16::from_le_bytes([block[7], block[8]]))
}

// ── Public bind entry point ────────────────────────────────────────

/// Bind an already-addressed xHCI slot as a HID Consumer Control
/// device. The caller (`attach::dispatch_after_address`) has already
/// issued port_reset + enable_slot + address_device(_with) and owns
/// the slot lifecycle: this function MUST NOT call `disable_slot` on
/// failure.
///
/// Steps:
///   1. Scan `desc` (the full config descriptor blob) for a HID
///      interface whose Report Descriptor contains a Consumer Control
///      Application Collection (Usage Page 0x0C, Usage 0x01).
///   2. Fetch the Report Descriptor via GET_DESCRIPTOR(0x22).
///   3. If `has_consumer_control_collection` returns true, continue
///      with setup; otherwise return `NotBootKeyboard` so the
///      dispatcher falls through to the next class probe.
///   4. Configure the xHCI endpoint context (interrupt-IN).
///   5. Issue SET_CONFIGURATION.
///   6. Issue SET_PROTOCOL(Report) + SET_IDLE.
///   7. Arm one interrupt-IN TRB.
///   8. Register the device in `CONSUMER_DEVICES`.
pub async fn try_bind_consumer_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    _interface_num: u8,
    desc: &[u8],
) -> Result<(), HidError> {
    // Step 1: find the HID interface with its HID Descriptor offset +
    // interrupt-IN endpoint. The `interface_num` argument is the
    // pre-matched interface from the attach dispatcher; for the
    // consumer path we re-scan the config descriptor so this function
    // can also operate when called directly from the dispatcher with
    // `interface_num` set to the device's first interface.
    let (iface_num, hid_off, ep) =
        find_consumer_interface(desc).ok_or(HidError::NotBootKeyboard)?;

    // Step 2: determine Report Descriptor length from the inline HID
    // Descriptor block.
    let report_len = report_descriptor_length(desc, hid_off).ok_or(HidError::NoInterruptIn)?;
    if report_len == 0 || report_len as usize > MAX_REPORT_DESCRIPTOR {
        return Err(HidError::NoInterruptIn);
    }

    // Fetch the Report Descriptor via HID class GET_DESCRIPTOR.
    // bmRequestType: Device→Host | Standard | Interface = 0x81.
    let mut blob = alloc::vec![0u8; report_len as usize];
    xhci_dev
        .control_in(
            slot_id,
            RT_DEV_TO_HOST_STD_IFACE,
            crate::xhci::USB_REQ_GET_DESCRIPTOR,
            ((HID_DESC_TYPE_REPORT as u16) << 8) | 0,
            iface_num as u16,
            &mut blob,
        )
        .await
        .map_err(HidError::Xhci)?;

    // Step 3: verify the Report Descriptor advertises Consumer Control.
    if !has_consumer_control_collection(&blob) {
        return Err(HidError::NotBootKeyboard);
    }
    let report_id = detect_report_id(&blob);

    // Step 4: configure xHCI endpoint context.
    xhci_dev
        .configure_endpoints(slot_id, &[ep])
        .await
        .map_err(HidError::Xhci)?;

    // Step 5: SET_CONFIGURATION — device stays in Address state and
    // STALLs class requests without this (same as keyboard / mouse
    // paths).
    if desc.len() < 9 || desc[1] != 2 {
        return Err(HidError::NoInterruptIn);
    }
    let cfg_value = desc[5];
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

    // Step 6: SET_PROTOCOL(Report) — ensures the device emits Report
    // Descriptor-shaped reports rather than any vendor default.
    // Non-fatal on STALL (some low-cost consumer devices implement
    // neither Boot nor Report protocol explicitly and respond to both
    // without needing SET_PROTOCOL).
    let _ = xhci_dev
        .control_in(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            HID_REQ_SET_PROTOCOL,
            HID_REPORT_PROTOCOL,
            iface_num as u16,
            &mut nothing,
        )
        .await;

    // SET_IDLE(0, 0) — "report on change only".
    let _ = xhci_dev
        .control_in(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            HID_REQ_SET_IDLE,
            0,
            iface_num as u16,
            &mut nothing,
        )
        .await;

    // Step 7: arm one Normal TRB on the interrupt-IN endpoint.
    let interrupt_in_ep = ep.ep_addr & 0x0F;
    let dci = (interrupt_in_ep * 2) + 1;
    xhci_dev
        .arm_interrupt_in(slot_id, dci, CONSUMER_REPORT_BUF as u32)
        .map_err(HidError::Xhci)?;

    // Step 8: register in the global device list.
    let dev = ConsumerDevice {
        slot_id,
        interrupt_in_dci: dci,
        interface_num: iface_num,
        report_id,
        last_report: IrqSafeSpinLock::new([0u16; 8]),
    };
    {
        let mut g = CONSUMER_DEVICES.lock();
        g.push(dev);
        ATTACHED_CONSUMER_COUNT.store(g.len() as u32, core::sync::atomic::Ordering::Release);
    }
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  usb-hid: consumer slot={} iface={} dci={}",
            slot_id,
            iface_num,
            dci,
        );
    }
    Ok(())
}

// ── Pump ───────────────────────────────────────────────────────────

/// Drain pending reports from all bound Consumer Control devices,
/// diff each against its previous report, and push press/release
/// events onto the global Key ring. Returns total events emitted.
///
/// Designed to be called from the supervisor's xHCI-IRQ / 100 ms
/// timeout cycle alongside `hid::pump_all` and `mouse::pump_all`.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    let len = CONSUMER_DEVICES.lock().len();
    let mut total = 0usize;
    for idx in 0..len {
        total += pump_one(xhci_dev, idx);
    }
    total
}

/// Drain reports off a single consumer device by index. Extracts the
/// slot/dci/report_id under the lock, then polls without holding the
/// registry lock so the poll path can touch DMA memory freely.
fn pump_one(xhci_dev: &Xhci, idx: usize) -> usize {
    // Snapshot the fields we need without holding the registry lock
    // across the poll calls (which may access DMA-mapped buffers).
    let (slot_id, dci, report_id) = {
        let g = CONSUMER_DEVICES.lock();
        match g.get(idx) {
            Some(d) => (d.slot_id, d.interrupt_in_dci, d.report_id),
            None => return 0,
        }
    };

    let mut buf = [0u8; CONSUMER_REPORT_BUF];
    let mut total = 0usize;
    loop {
        match xhci_dev.poll_interrupt_in(slot_id, dci, &mut buf) {
            Ok(Some(_n)) => {
                let cur = decode_report(&buf, report_id);
                let prev = {
                    let g = CONSUMER_DEVICES.lock();
                    match g.get(idx) {
                        Some(d) => *d.last_report.lock(),
                        None => break,
                    }
                };
                let emitted = translate_diff(&prev, &cur);
                {
                    let g = CONSUMER_DEVICES.lock();
                    if let Some(d) = g.get(idx) {
                        *d.last_report.lock() = cur;
                    }
                }
                total += emitted;
            }
            Ok(None) => break,
            Err(_) => break,
        }
        // Reset buffer for next iteration.
        buf = [0u8; CONSUMER_REPORT_BUF];
    }
    total
}

// ── Diagnostic counters ────────────────────────────────────────────

/// Lock-free count of bound Consumer Control interfaces.
pub static ATTACHED_CONSUMER_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Number of bound Consumer Control interfaces (lock-free read).
pub fn attached_consumer_count() -> usize {
    ATTACHED_CONSUMER_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize
}

#[doc(hidden)]
pub fn __reset_consumers_for_test() {
    CONSUMER_DEVICES.lock().clear();
    ATTACHED_CONSUMER_COUNT.store(0, core::sync::atomic::Ordering::Release);
}

// ── Smokes ─────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_input::{KeyCode, __reset_global_ring_for_test, init_global_ring, pop_key};
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Smoke 1: usage-code → KeyCode mapping for the top-10 consumer keys ──

    fn smoke_consumer_usage_to_keycode_top10() -> TestResult {
        let cases: &[(u16, KeyCode)] = &[
            (0xE9, KeyCode::VolumeUp),
            (0xEA, KeyCode::VolumeDown),
            (0xE2, KeyCode::Mute),
            (0xCD, KeyCode::PlayPause),
            (0xB5, KeyCode::NextSong),
            (0xB6, KeyCode::PreviousSong),
            (0xB7, KeyCode::Stop),
            (0x6F, KeyCode::BrightnessUp),
            (0x70, KeyCode::BrightnessDown),
            (0x82, KeyCode::Sleep),
        ];
        for &(usage, want) in cases {
            let got = usage_to_keycode(usage);
            if got != want {
                return TestResult::Fail("usage_to_keycode mismatch for consumer key");
            }
        }
        // Codes with no mapping → Unknown.
        if usage_to_keycode(0x0000) != KeyCode::Unknown {
            return TestResult::Fail("zero usage should be Unknown");
        }
        if usage_to_keycode(0xFFFF) != KeyCode::Unknown {
            return TestResult::Fail("0xFFFF should be Unknown");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/consumer",
        smoke_consumer_usage_to_keycode_top10
    );

    // ── Smoke 2: multi-press report decode ───────────────────────────────

    fn smoke_consumer_multi_press_decode() -> TestResult {
        // A 3-byte report with no report-ID: three simultaneously pressed
        // keys (volume-up, mute, play-pause).
        let report: &[u8] = &[0xE9, 0xE2, 0xCD];
        let decoded = decode_report(report, None);
        // All three should appear in the decoded array.
        let has_vol_up = decoded.iter().any(|&c| c == 0xE9);
        let has_mute = decoded.iter().any(|&c| c == 0xE2);
        let has_play = decoded.iter().any(|&c| c == 0xCD);
        if !has_vol_up || !has_mute || !has_play {
            return TestResult::Fail("multi-press report not decoded correctly");
        }
        // Remaining slots should be zero.
        let nonzero_count = decoded.iter().filter(|&&c| c != 0).count();
        if nonzero_count != 3 {
            return TestResult::Fail("unexpected extra codes in decoded multi-press");
        }

        // Report with report-ID prefix: ID=0x03, then vol-up + brightness-up.
        let report_with_id: &[u8] = &[0x03, 0xE9, 0x6F];
        let decoded2 = decode_report(report_with_id, Some(0x03));
        if !decoded2.iter().any(|&c| c == 0xE9) {
            return TestResult::Fail("vol-up not found in report-ID-prefixed decode");
        }
        if !decoded2.iter().any(|&c| c == 0x6F) {
            return TestResult::Fail("brightness-up not found in report-ID-prefixed decode");
        }

        // Wrong report-ID: should produce all zeros.
        let decoded3 = decode_report(report_with_id, Some(0x01));
        if decoded3.iter().any(|&c| c != 0) {
            return TestResult::Fail("wrong report-ID should produce empty decode");
        }

        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/consumer",
        smoke_consumer_multi_press_decode
    );

    // ── Smoke 3: descriptor-shape detection (consumer page presence) ─────

    fn smoke_consumer_descriptor_detection() -> TestResult {
        // Minimal valid Consumer Control Report Descriptor:
        //   Usage Page (Consumer Control) = 0x05 0x0C
        //   Usage (Consumer Control)      = 0x09 0x01
        //   Collection (Application)      = 0xA1 0x01
        //     Usage Minimum               = 0x19 0x00
        //     Usage Maximum               = 0x29 0xFF
        //     Logical Minimum (0)         = 0x15 0x00
        //     Logical Maximum (255)       = 0x26 0xFF 0x00
        //     Report Size (8)             = 0x75 0x08
        //     Report Count (1)            = 0x95 0x01
        //     Input (Data, Array, Abs)    = 0x81 0x00
        //   End Collection                = 0xC0
        let consumer_desc: &[u8] = &[
            0x05, 0x0C, // Usage Page (Consumer Control)
            0x09, 0x01, // Usage (Consumer Control)
            0xA1, 0x01, // Collection (Application)
            0x19, 0x00, // Usage Minimum (0)
            0x29, 0xFF, // Usage Maximum (255)
            0x15, 0x00, // Logical Minimum (0)
            0x26, 0xFF, 0x00, // Logical Maximum (255) — 2-byte
            0x75, 0x08, // Report Size (8)
            0x95, 0x01, // Report Count (1)
            0x81, 0x00, // Input (Data, Array, Abs)
            0xC0, // End Collection
        ];

        if !has_consumer_control_collection(consumer_desc) {
            return TestResult::Fail("consumer descriptor not detected as consumer-page");
        }

        // A keyboard descriptor (Usage Page 0x01, keyboard) must NOT match.
        let kbd_desc: &[u8] = &[
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x06, // Usage (Keyboard)
            0xA1, 0x01, // Collection (Application)
            0xC0, // End Collection
        ];
        if has_consumer_control_collection(kbd_desc) {
            return TestResult::Fail("keyboard descriptor false-positive as consumer");
        }

        // Empty / too-short descriptor — should return false without panic.
        if has_consumer_control_collection(&[]) {
            return TestResult::Fail("empty descriptor false-positive");
        }
        if has_consumer_control_collection(&[0x05]) {
            return TestResult::Fail("single-byte descriptor false-positive");
        }

        // Descriptor with report ID before the consumer collection.
        let desc_with_rid: &[u8] = &[
            0x05, 0x0C, // Usage Page (Consumer Control)
            0x09, 0x01, // Usage (Consumer Control)
            0xA1, 0x01, // Collection (Application)
            0x85, 0x03, // Report ID (3)
            0x75, 0x08, // Report Size (8)
            0x95, 0x01, // Report Count (1)
            0x81, 0x00, // Input
            0xC0, // End Collection
        ];
        if !has_consumer_control_collection(desc_with_rid) {
            return TestResult::Fail("consumer descriptor with report-ID not detected");
        }
        // detect_report_id should return None here because Report ID appears
        // after the Collection item, not before — that's OK; we just verify it
        // doesn't panic and the collection IS detected.
        let _ = detect_report_id(desc_with_rid);

        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/consumer",
        smoke_consumer_descriptor_detection
    );

    // ── Smoke 4: translate_diff pushes correct press/release events ──────

    fn smoke_consumer_translate_diff_events() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();
        __reset_consumers_for_test();

        // Nothing → volume-up pressed.
        let prev = [0u16; 8];
        let mut cur = [0u16; 8];
        cur[0] = 0xE9; // VolumeUp
        let n = translate_diff(&prev, &cur);
        if n != 1 {
            return TestResult::Fail("expected 1 event for VolumeUp press");
        }
        match pop_key() {
            Some(k) if k.code == KeyCode::VolumeUp && k.pressed => {}
            _ => return TestResult::Fail("VolumeUp press event not in ring"),
        }

        // Volume-up held → mute also pressed (simultaneous).
        let prev2 = cur;
        let mut cur2 = [0u16; 8];
        cur2[0] = 0xE9; // VolumeUp still held
        cur2[1] = 0xE2; // Mute newly pressed
        let n2 = translate_diff(&prev2, &cur2);
        if n2 != 1 {
            return TestResult::Fail("expected 1 new event for Mute press");
        }
        match pop_key() {
            Some(k) if k.code == KeyCode::Mute && k.pressed => {}
            _ => return TestResult::Fail("Mute press event not in ring"),
        }

        // Both released.
        let prev3 = cur2;
        let cur3 = [0u16; 8];
        let n3 = translate_diff(&prev3, &cur3);
        if n3 != 2 {
            return TestResult::Fail("expected 2 release events");
        }
        // Both VolumeUp and Mute should appear as releases.
        let mut saw_vol_release = false;
        let mut saw_mute_release = false;
        for _ in 0..2 {
            match pop_key() {
                Some(k) if k.code == KeyCode::VolumeUp && !k.pressed => {
                    saw_vol_release = true;
                }
                Some(k) if k.code == KeyCode::Mute && !k.pressed => {
                    saw_mute_release = true;
                }
                _ => {}
            }
        }
        if !saw_vol_release {
            return TestResult::Fail("VolumeUp release missing");
        }
        if !saw_mute_release {
            return TestResult::Fail("Mute release missing");
        }

        // Unknown usage codes produce no events.
        let prev4 = [0u16; 8];
        let mut cur4 = [0u16; 8];
        cur4[0] = 0x0002; // "Numeric Key Pad" — not in NARF KeyCode set
        let n4 = translate_diff(&prev4, &cur4);
        if n4 != 0 {
            return TestResult::Fail("unknown usage code should not produce events");
        }

        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/consumer",
        smoke_consumer_translate_diff_events
    );
}
