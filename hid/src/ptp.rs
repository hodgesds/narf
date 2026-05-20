//! Microsoft Precision Touchpad (PTP) profile decoder — clean-room.
//!
//! ## Sources (public only)
//!
//! - **HID Usage Tables 1.4 §16** — Digitizer page (0x0D). Defines
//!   the usages this profile keys on: Touch Pad (0x05), Finger
//!   (0x22), Tip Switch (0x42), Contact ID (0x51), Contact Count
//!   (0x54), Scan Time (0x56), Device Mode (0x60).
//!   <https://usb.org/document-library/hid-usage-tables-14>
//! - **"Windows Precision Touchpad Implementation Guide"** —
//!   Microsoft public technical documentation. Defines the
//!   Required HID Top-Level Collections, Device Mode feature
//!   semantics (0 = Mouse mode legacy, 3 = Multi-touch reporting
//!   mode), and the per-contact field set every PTP must expose.
//!   <https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/windows-precision-touchpad-required-hid-top-level-collections>
//!   <https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/touchpad-windows-precision-touchpad-collection>
//! - **HID 1.11 §6.2.2** — descriptor parsing (already in
//!   [`crate::descriptor`]). Boot mouse / boot keyboard fixtures
//!   are not consulted here.
//!
//! No GPL / Linux source consulted.
//!
//! ## What this module is
//!
//! A *profile probe* + *report decoder* on top of
//! [`ReportDescriptor`]. Given a descriptor, [`detect`] returns
//! `Some(PtpProfile)` iff the descriptor declares a Touch Pad
//! Application Collection with the per-contact fields a Microsoft-
//! compliant PTP must include. The returned profile points at the
//! parsed [`Field`]s a transport layer needs to extract values
//! from runtime reports — no allocation per-report.
//!
//! [`decode_input`] applies the profile to one Input report and
//! produces a [`DecodedReport`] with the per-contact state plus
//! Contact Count, Scan Time, and the primary button.
//!
//! [`build_mode_feature_report`] builds the wire form of the
//! Device Mode Feature report — set `mode = 3` to put a touchpad
//! into multi-touch reporting mode.
//!
//! ## Contact disambiguation
//!
//! Two sibling Logical Collections of the same `(Digitizer, Finger)`
//! usage share an identical [`Field::collection_path`]; the only
//! thing that distinguishes finger N from finger N+1 in the parsed
//! output is *bit offset within the report*. The probe groups
//! per-contact fields by walking declaration order and treating each
//! `Tip Switch` field on `(0x0D, 0x42)` as a fresh contact boundary.
//! All other per-contact fields after a Tip Switch — up to the next
//! Tip Switch or the end of the report — bind to that contact.

extern crate alloc;
use alloc::vec::Vec;

use crate::descriptor::{Field, FieldKind, ReportDescriptor};
use crate::report::{extract, ReportError};
use crate::usage::{button, digitizer, generic_desktop};

/// PTP Device Mode values (Microsoft PTP spec §"Device Modes").
pub mod mode {
    /// Mouse-emulation legacy mode (boot-style 3-byte report).
    pub const MOUSE: u8 = 0x00;
    /// "Single Input" — relative mode with one contact.
    pub const SINGLE: u8 = 0x01;
    /// "Multiple Input" — multi-touch absolute mode. Setting this
    /// is the whole point of Configuration TLC support.
    pub const MULTI_TOUCH: u8 = 0x03;
}

/// Subset of fields on a single PTP contact (one Finger Logical
/// Collection within the Touch Pad Application Collection). Not
/// every field is mandatory; transports treat `None` as
/// "absent → caller picks a default".
#[derive(Clone, Debug)]
pub struct ContactFields {
    pub tip_switch: Field,
    pub contact_id: Option<Field>,
    pub x: Option<Field>,
    pub y: Option<Field>,
    pub pressure: Option<Field>,
    pub in_range: Option<Field>,
    pub confidence: Option<Field>,
}

/// Result of [`detect`]. Carries the parsed [`Field`]s a runtime
/// decoder needs — once a transport layer has the descriptor
/// parsed, it never re-parses for each report.
#[derive(Clone, Debug)]
pub struct PtpProfile {
    /// Report ID of the Input report carrying multi-touch data.
    /// `0` means the descriptor has no Report ID (rare for PTP).
    pub input_report_id: u8,
    pub contacts: Vec<ContactFields>,
    pub contact_count: Option<Field>,
    pub scan_time: Option<Field>,
    /// Button 1 (primary touchpad button), Usage Page Button (0x09)
    /// usage 0x01.
    pub button1: Option<Field>,
    /// Configuration TLC report id (Feature) — present iff the
    /// descriptor exposes a Device Mode Feature item.
    pub config_report_id: Option<u8>,
    /// Device Mode (Digitizer page, usage 0x60). [`build_mode_feature_report`]
    /// uses this to compose the byte payload.
    pub device_mode_feature: Option<Field>,
    /// Maximum simultaneous contacts the device claims to support.
    /// Sourced from the per-contact list length. Microsoft requires
    /// PTPs to support at least 3; modern devices do 5.
    pub contacts_max: usize,
}

/// Probe a parsed descriptor. Returns `Some` iff the descriptor
/// declares a Touch Pad Application Collection (Digitizer page,
/// usage 0x05) with at least one Tip Switch field and the
/// Contact Count field that PTP requires.
pub fn detect(d: &ReportDescriptor) -> Option<PtpProfile> {
    let has_touchpad = d
        .top_level_apps
        .iter()
        .any(|&(p, u)| p == digitizer::PAGE && u == digitizer::TOUCH_PAD);
    if !has_touchpad {
        return None;
    }

    // The Touch Pad input report is the report that carries the
    // first Tip Switch field. We bind to that report id.
    let tip_switch_field = d.fields.iter().find(|f| {
        f.kind == FieldKind::Input
            && f.usage_page == digitizer::PAGE
            && f.usages.iter().any(|u| u.1 == digitizer::TIP_SWITCH)
    })?;
    let input_report_id = tip_switch_field.report_id;

    // Walk the input fields in declaration order, grouping per
    // contact at every Tip Switch boundary.
    let mut contacts: Vec<ContactFields> = Vec::new();
    let mut current: Option<ContactFields> = None;
    let mut contact_count: Option<Field> = None;
    let mut scan_time: Option<Field> = None;
    let mut button1: Option<Field> = None;

    for f in d
        .fields
        .iter()
        .filter(|f| f.kind == FieldKind::Input && f.report_id == input_report_id)
    {
        if let Some(usage_id) = first_usage_on_page(f, digitizer::PAGE) {
            match usage_id {
                u if u == digitizer::TIP_SWITCH => {
                    if let Some(c) = current.take() {
                        contacts.push(c);
                    }
                    current = Some(ContactFields {
                        tip_switch: f.clone(),
                        contact_id: None,
                        x: None,
                        y: None,
                        pressure: None,
                        in_range: None,
                        confidence: None,
                    });
                    continue;
                }
                u if u == digitizer::CONTACT_ID => {
                    if let Some(c) = current.as_mut() {
                        c.contact_id = Some(f.clone());
                    }
                    continue;
                }
                u if u == digitizer::TIP_PRESSURE => {
                    if let Some(c) = current.as_mut() {
                        c.pressure = Some(f.clone());
                    }
                    continue;
                }
                u if u == digitizer::IN_RANGE => {
                    if let Some(c) = current.as_mut() {
                        c.in_range = Some(f.clone());
                    }
                    continue;
                }
                u if u == digitizer::TOUCH_VALID => {
                    if let Some(c) = current.as_mut() {
                        c.confidence = Some(f.clone());
                    }
                    continue;
                }
                u if u == digitizer::CONTACT_COUNT => {
                    contact_count = Some(f.clone());
                    continue;
                }
                u if u == digitizer::SCAN_TIME => {
                    scan_time = Some(f.clone());
                    continue;
                }
                _ => {}
            }
        }
        if let Some(usage_id) = first_usage_on_page(f, generic_desktop::PAGE) {
            match usage_id {
                u if u == generic_desktop::X => {
                    if let Some(c) = current.as_mut() {
                        c.x = Some(f.clone());
                    }
                }
                u if u == generic_desktop::Y => {
                    if let Some(c) = current.as_mut() {
                        c.y = Some(f.clone());
                    }
                }
                _ => {}
            }
            continue;
        }
        if let Some(usage_id) = first_usage_on_page(f, button::PAGE) {
            if usage_id == button::PRIMARY {
                button1 = Some(f.clone());
            }
        }
    }
    if let Some(c) = current.take() {
        contacts.push(c);
    }
    if contacts.is_empty() {
        return None;
    }
    if contact_count.is_none() {
        // Microsoft PTP spec mandates Contact Count. Without it we
        // can't tell how many of the per-contact slots in the report
        // are valid, so we refuse to bind.
        return None;
    }

    // Configuration TLC: locate Device Mode Feature (Digitizer page,
    // usage 0x60). Distinct report id from the input report — that's
    // how Configuration TLCs are spec'd.
    let mut config_report_id: Option<u8> = None;
    let mut device_mode_feature: Option<Field> = None;
    for f in d.fields.iter().filter(|f| f.kind == FieldKind::Feature) {
        if first_usage_on_page(f, digitizer::PAGE) == Some(digitizer::DEVICE_MODE) {
            config_report_id = Some(f.report_id);
            device_mode_feature = Some(f.clone());
            break;
        }
    }

    let contacts_max = contacts.len();
    Some(PtpProfile {
        input_report_id,
        contacts,
        contact_count,
        scan_time,
        button1,
        config_report_id,
        device_mode_feature,
        contacts_max,
    })
}

/// Decoded view of one PTP Input report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedReport {
    pub contacts: Vec<DecodedContact>,
    /// Number of valid entries in `contacts`. The wire report can
    /// carry more *slots* than are actually in use this scan; the
    /// caller iterates only `&contacts[..contact_count as usize]`.
    pub contact_count: u8,
    /// 100 µs ticks since some device-internal epoch (HID Usage
    /// Tables §16, Scan Time).
    pub scan_time: u32,
    /// State of the touchpad's primary mechanical button.
    pub button1: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DecodedContact {
    pub tip_switch: bool,
    pub contact_id: u8,
    pub x: i32,
    pub y: i32,
    pub pressure: Option<i32>,
    pub in_range: bool,
    pub confidence: bool,
}

/// Decode one Input report. `report` is the wire bytes including
/// the leading 1-byte Report ID; this function strips the prefix
/// itself.
pub fn decode_input(p: &PtpProfile, report: &[u8]) -> Result<DecodedReport, ReportError> {
    if report.is_empty() {
        return Err(ReportError::Short);
    }
    if report[0] != p.input_report_id {
        return Err(ReportError::Short);
    }
    let body = &report[1..];

    let mut contacts: Vec<DecodedContact> = Vec::with_capacity(p.contacts.len());
    for c in &p.contacts {
        let tip = first_value(&c.tip_switch, body)? != 0;
        let cid = match &c.contact_id {
            Some(f) => first_value(f, body)? as u8,
            None => 0,
        };
        let x = match &c.x {
            Some(f) => first_value(f, body)?,
            None => 0,
        };
        let y = match &c.y {
            Some(f) => first_value(f, body)?,
            None => 0,
        };
        let pressure = match &c.pressure {
            Some(f) => Some(first_value(f, body)?),
            None => None,
        };
        let in_range = match &c.in_range {
            Some(f) => first_value(f, body)? != 0,
            // Per Microsoft PTP: when In Range is absent, treat
            // Tip Switch == 1 as in-range. This matches what the
            // Windows PTP HID parser does for descriptors that
            // omit In Range.
            None => tip,
        };
        let confidence = match &c.confidence {
            Some(f) => first_value(f, body)? != 0,
            // No Confidence bit → Microsoft requires devices to
            // only report contacts they're confident about, so
            // assume true.
            None => true,
        };
        contacts.push(DecodedContact {
            tip_switch: tip,
            contact_id: cid,
            x,
            y,
            pressure,
            in_range,
            confidence,
        });
    }

    let contact_count = match &p.contact_count {
        Some(f) => first_value(f, body)? as u8,
        None => 0,
    };
    let scan_time = match &p.scan_time {
        Some(f) => first_value(f, body)? as u32,
        None => 0,
    };
    let button1 = match &p.button1 {
        Some(f) => first_value(f, body)? != 0,
        None => false,
    };

    Ok(DecodedReport {
        contacts,
        contact_count,
        scan_time,
        button1,
    })
}

/// Build the wire bytes for a Set Feature(Device Mode) request.
/// Returns `None` if the descriptor didn't expose a Device Mode
/// feature item; transport layers should treat that as "this device
/// is mouse-only and can't be put into multi-touch mode".
///
/// The output buffer is sized for the full Feature report, with
/// the Mode byte placed at the right bit offset and other field
/// bits left at zero.
pub fn build_mode_feature_report(p: &PtpProfile, mode: u8) -> Option<Vec<u8>> {
    let f = p.device_mode_feature.as_ref()?;
    let report_id = f.report_id;
    // Total body bits for *every* Feature field on this report id.
    let body_bits = body_bits_for(p, report_id, FieldKind::Feature);
    let body_bytes = (body_bits as usize + 7) / 8;
    let mut buf = alloc::vec![0u8; 1 + body_bytes];
    buf[0] = report_id;
    let _ = crate::report::pack(f, &mut buf[1..], &[mode as i32]);
    Some(buf)
}

/// Body length in bits for a (report_id, kind) pair. Same shape as
/// `ReportDescriptor::report_body_bits`; duplicated here so the
/// PTP profile doesn't depend on which report-id the caller
/// explicitly passed. Kept private — public API takes the kind
/// implicitly from the field-set.
fn body_bits_for(p: &PtpProfile, report_id: u8, _kind: FieldKind) -> u32 {
    // We only call this for Feature reports during build_mode_feature.
    let mut max_end = 0u32;
    for f in p
        .device_mode_feature
        .iter()
        .filter(|f| f.report_id == report_id)
    {
        let end = f.bit_offset.saturating_add(f.report_size.saturating_mul(f.report_count));
        if end > max_end {
            max_end = end;
        }
    }
    max_end
}

fn first_value(field: &Field, body: &[u8]) -> Result<i32, ReportError> {
    extract(field, body).map(|v| v.first().copied().unwrap_or(0))
}

fn first_usage_on_page(f: &Field, page: u16) -> Option<u16> {
    if f.usage_page == page {
        if let Some((p, id)) = f.usages.first() {
            if *p == page {
                return Some(*id);
            }
        }
        if let Some((p, id)) = f.usage_min {
            if p == page {
                return Some(id);
            }
        }
    }
    None
}

/// Test-only: a spec-shaped synthetic PTP Report Descriptor blob
/// (2 fingers + Contact Count + Scan Time + Button 1 + a
/// Configuration TLC with Device Mode Feature). Used by sibling
/// crates' smoke tests to exercise the PTP detect / decode /
/// mode-set chain end-to-end without re-pasting the blob.
#[doc(hidden)]
pub fn __ptp_descriptor_blob() -> &'static [u8] {
    PTP_DESCRIPTOR_BLOB
}

/// The blob; kept in a `static` rather than a module-level `const`
/// so the `__ptp_descriptor_blob` helper can return a `&'static`
/// slice. Same bytes as the in-crate test fixture.
static PTP_DESCRIPTOR_BLOB: &[u8] = &[
    // ── Touch Pad Application Collection (Input report ID 1) ────
    0x05, 0x0D,             // Usage Page (Digitizer)
    0x09, 0x05,             // Usage (Touch Pad)
    0xA1, 0x01,             //   Collection (Application)
    0x85, 0x01,             //     Report ID (1)
    // Finger 0
    0x09, 0x22,             //     Usage (Finger)
    0xA1, 0x02,             //     Collection (Logical)
    0x09, 0x42,             //       Usage (Tip Switch)
    0x15, 0x00,             //       Logical Min (0)
    0x25, 0x01,             //       Logical Max (1)
    0x75, 0x01,             //       Report Size (1)
    0x95, 0x01,             //       Report Count (1)
    0x81, 0x02,             //       Input (Data,Var,Abs)
    0x09, 0x51,             //       Usage (Contact ID)
    0x25, 0x07,             //       Logical Max (7)
    0x75, 0x03,             //       Report Size (3)
    0x81, 0x02,             //       Input
    0x75, 0x04,             //       Report Size (4) — padding
    0x95, 0x01,             //       Report Count (1)
    0x81, 0x03,             //       Input (Cnst,Var,Abs)
    0x05, 0x01,             //       Usage Page (Generic Desktop)
    0x09, 0x30,             //       Usage (X)
    0x26, 0xFF, 0x7F,       //       Logical Max (0x7FFF)
    0x75, 0x10,             //       Report Size (16)
    0x95, 0x01,             //       Report Count (1)
    0x81, 0x02,             //       Input
    0x09, 0x31,             //       Usage (Y)
    0x81, 0x02,             //       Input
    0xC0,                   //     End Collection
    // Finger 1 — same shape
    0x05, 0x0D,             //     Usage Page (Digitizer)
    0x09, 0x22,             //     Usage (Finger)
    0xA1, 0x02,             //     Collection (Logical)
    0x09, 0x42,             //       Usage (Tip Switch)
    0x15, 0x00,
    0x25, 0x01,
    0x75, 0x01,
    0x95, 0x01,
    0x81, 0x02,
    0x09, 0x51,
    0x25, 0x07,
    0x75, 0x03,
    0x81, 0x02,
    0x75, 0x04,
    0x95, 0x01,
    0x81, 0x03,
    0x05, 0x01,
    0x09, 0x30,
    0x26, 0xFF, 0x7F,
    0x75, 0x10,
    0x95, 0x01,
    0x81, 0x02,
    0x09, 0x31,
    0x81, 0x02,
    0xC0,                   //     End Collection
    // Contact Count + Scan Time + Button 1
    0x05, 0x0D,
    0x09, 0x54,             //     Usage (Contact Count)
    0x25, 0x02,             //     Logical Max (2)
    0x75, 0x08,             //     Report Size (8)
    0x95, 0x01,
    0x81, 0x02,
    0x09, 0x56,             //     Usage (Scan Time)
    0x27, 0xFF, 0xFF, 0x00, 0x00, // Logical Max (0xFFFF)
    0x75, 0x10,
    0x95, 0x01,
    0x81, 0x02,
    0x05, 0x09,             //     Usage Page (Button)
    0x09, 0x01,             //     Usage (Button 1)
    0x15, 0x00,
    0x25, 0x01,
    0x75, 0x01,
    0x95, 0x01,
    0x81, 0x02,
    0x75, 0x07,             //     padding
    0x81, 0x03,
    0xC0,                   //   End Collection
    // Configuration TLC (Feature report ID 3) — Device Mode
    0x05, 0x0D,
    0x09, 0x0E,             // Usage (Configuration)
    0xA1, 0x01,             // Collection (Application)
    0x85, 0x03,             //   Report ID (3)
    0x09, 0x22,             //   Usage (Finger)
    0xA1, 0x02,             //   Collection (Logical)
    0x09, 0x60,             //     Usage (Device Mode)
    0x15, 0x00,
    0x25, 0x0A,             //     Logical Max (10)
    0x75, 0x08,
    0x95, 0x01,
    0xB1, 0x02,             //     Feature
    0xC0,                   //   End Collection
    0xC0,                   // End Collection
];
