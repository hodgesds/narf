//! HID Digitizer touchscreen profile decoder — clean-room.
//!
//! ## Sources (public only)
//!
//! - **HID Usage Tables 1.4 §16** — Digitizer page (0x0D). Defines
//!   the usages this profile keys on: Touch Screen (0x04), Finger
//!   (0x22), Tip Switch (0x42), Contact ID (0x51), Contact Count
//!   (0x54), Tip Pressure (0x30), Width (0x48), Height (0x49).
//!   <https://usb.org/document-library/hid-usage-tables-14>
//! - **Microsoft "Digitizer Drivers — Touch Screen Sample Report
//!   Descriptor"** — public Windows Hardware Compatibility
//!   reference for the shape every i2c-HID touchscreen ships
//!   with: a Touch Screen Application Collection holding N
//!   Finger Logical Collections, each carrying Tip Switch +
//!   In Range + Contact Identifier + X + Y + (optional Tip
//!   Pressure) + (optional Width/Height), with a Contact Count
//!   field at the end of the report.
//!   <https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/touchscreen-sample-report-descriptors>
//!
//! ## What this module is
//!
//! A *profile probe* + *report decoder* on top of
//! [`ReportDescriptor`]. Given a parsed descriptor, [`detect`]
//! returns `Some(TouchscreenProfile)` iff the descriptor declares
//! a Touch Screen Application Collection (Digitizer page,
//! usage 0x04) with the per-contact fields a digitizer
//! touchscreen must include. The returned profile points at the
//! parsed [`Field`]s a transport layer extracts values from —
//! no allocation per-report.
//!
//! [`decode_input`] applies the profile to one Input report and
//! produces a [`DecodedTouchReport`] with the per-contact state
//! plus the Contact Count field.
//!
//! Stage-0 omits stylus / pen tilt / barrel pressure and the
//! contact bounding box (Width / Height): the
//! [`ContactFields`] schema records their presence so a later
//! stage can decode them without re-parsing the descriptor, but
//! [`decode_input`] doesn't populate them.

extern crate alloc;
use alloc::vec::Vec;

use crate::descriptor::{Field, FieldKind, ReportDescriptor};
use crate::report::{extract, ReportError};
use crate::usage::{digitizer, generic_desktop};

/// Subset of fields on a single touchscreen contact (one Finger
/// Logical Collection within the Touch Screen Application
/// Collection). Not every field is mandatory; transports treat
/// `None` as "absent → caller picks a default".
#[derive(Clone, Debug)]
pub struct ContactFields {
    pub tip_switch: Field,
    pub contact_id: Option<Field>,
    pub x: Option<Field>,
    pub y: Option<Field>,
    pub pressure: Option<Field>,
    pub in_range: Option<Field>,
    pub confidence: Option<Field>,
    /// Bounding-box width (HID Usage 0x0D/0x48). Stage-0
    /// decoder ignores this; presence noted so Stage-1 doesn't
    /// re-parse. `None` when the descriptor omits it.
    pub width: Option<Field>,
    /// Bounding-box height (HID Usage 0x0D/0x49). Stage-0
    /// decoder ignores this; presence noted so Stage-1 doesn't
    /// re-parse. `None` when the descriptor omits it.
    pub height: Option<Field>,
}

/// Result of [`detect`]. Carries the parsed [`Field`]s a runtime
/// decoder needs — once a transport layer has the descriptor
/// parsed, it never re-parses for each report.
#[derive(Clone, Debug)]
pub struct TouchscreenProfile {
    /// Report ID of the Input report carrying multi-touch data.
    /// `0` when the descriptor has no Report ID (very rare for
    /// modern touchscreens; most use ID 1 or higher).
    pub input_report_id: u8,
    pub contacts: Vec<ContactFields>,
    pub contact_count: Option<Field>,
    /// Maximum simultaneous contacts the device claims to
    /// support — taken from the per-contact list length.
    /// Microsoft requires touchscreens to support at least 2;
    /// modern panels do 5 or 10.
    pub contacts_max: usize,
    /// Logical-range bounds for the X axis (Generic Desktop
    /// 0x30) on the first contact. Touchscreens declare these
    /// in their report descriptors; transport layers feed them
    /// into `narf_input::TouchEvent::normalise_axis` to map raw
    /// device samples into the `0..=65535` shared space.
    /// `(0, 0)` when no X field is present.
    pub x_range: (i32, i32),
    /// Logical-range bounds for the Y axis (Generic Desktop
    /// 0x31), see `x_range`.
    pub y_range: (i32, i32),
}

/// Probe a parsed descriptor. Returns `Some` iff the descriptor
/// declares a Touch Screen Application Collection (Digitizer
/// page, usage 0x04) with at least one Tip Switch field — the
/// minimum for a usable touchscreen. Contact Count is checked
/// but not required (some single-contact touchscreens omit it;
/// the decoder falls back to "count the tip switches").
pub fn detect(d: &ReportDescriptor) -> Option<TouchscreenProfile> {
    let has_touchscreen = d
        .top_level_apps
        .iter()
        .any(|&(p, u)| p == digitizer::PAGE && u == digitizer::TOUCH_SCREEN);
    if !has_touchscreen {
        return None;
    }

    // The Touch Screen input report is the report that carries
    // the first Tip Switch field. We bind to that report id.
    let tip_switch_field = d.fields.iter().find(|f| {
        f.kind == FieldKind::Input
            && f.usage_page == digitizer::PAGE
            && f.usages.iter().any(|u| u.1 == digitizer::TIP_SWITCH)
    })?;
    let input_report_id = tip_switch_field.report_id;

    // Walk the input fields in declaration order, grouping per
    // contact at every Tip Switch boundary. Same shape as the
    // PTP probe in `ptp.rs` — touchpads and touchscreens use
    // the same wire pattern, differing only in the top-level
    // collection usage (0x05 vs 0x04).
    let mut contacts: Vec<ContactFields> = Vec::new();
    let mut current: Option<ContactFields> = None;
    let mut contact_count: Option<Field> = None;
    let mut x_range = (0i32, 0i32);
    let mut y_range = (0i32, 0i32);

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
                        width: None,
                        height: None,
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
                u if u == digitizer::WIDTH => {
                    if let Some(c) = current.as_mut() {
                        c.width = Some(f.clone());
                    }
                    continue;
                }
                u if u == digitizer::HEIGHT => {
                    if let Some(c) = current.as_mut() {
                        c.height = Some(f.clone());
                    }
                    continue;
                }
                _ => {}
            }
        }
        if let Some(usage_id) = first_usage_on_page(f, generic_desktop::PAGE) {
            match usage_id {
                u if u == generic_desktop::X => {
                    if let Some(c) = current.as_mut() {
                        // The first finger's X range carries the
                        // touchscreen's device-coordinate bounds.
                        // Per-finger Logical Min/Max are normally
                        // identical across fingers (Microsoft's
                        // sample descriptors all declare them once
                        // and the same), so latching from contact
                        // 0 is sound.
                        if contacts.is_empty() {
                            x_range = (f.logical_min, f.logical_max);
                        }
                        c.x = Some(f.clone());
                    }
                }
                u if u == generic_desktop::Y => {
                    if let Some(c) = current.as_mut() {
                        if contacts.is_empty() {
                            y_range = (f.logical_min, f.logical_max);
                        }
                        c.y = Some(f.clone());
                    }
                }
                _ => {}
            }
            continue;
        }
    }
    if let Some(c) = current.take() {
        contacts.push(c);
    }
    if contacts.is_empty() {
        return None;
    }

    let contacts_max = contacts.len();
    Some(TouchscreenProfile {
        input_report_id,
        contacts,
        contact_count,
        contacts_max,
        x_range,
        y_range,
    })
}

/// Decoded view of one touchscreen Input report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTouchReport {
    pub contacts: Vec<DecodedTouchContact>,
    /// Number of valid entries in `contacts` per the device's
    /// Contact Count field. When the descriptor omits Contact
    /// Count, the decoder falls back to the count of contacts
    /// whose Tip Switch is asserted in this report.
    pub contact_count: u8,
}

/// One contact's decoded state. Matches the Stage-0 surface —
/// stylus / pen / bounding-box fields are not decoded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DecodedTouchContact {
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
pub fn decode_input(
    p: &TouchscreenProfile,
    report: &[u8],
) -> Result<DecodedTouchReport, ReportError> {
    if report.is_empty() {
        return Err(ReportError::Short);
    }
    // When the descriptor uses Report IDs, the wire payload
    // begins with one; descriptors without report IDs deliver
    // bytes directly. Accept both shapes the same way the PTP
    // decoder does — fail mismatched IDs as a short report so
    // the bind layer's pump treats it as "not for me".
    if p.input_report_id != 0 && report[0] != p.input_report_id {
        return Err(ReportError::Short);
    }
    let body = if p.input_report_id != 0 {
        &report[1..]
    } else {
        report
    };

    let mut contacts: Vec<DecodedTouchContact> = Vec::with_capacity(p.contacts.len());
    let mut tip_asserted = 0u8;
    for c in &p.contacts {
        let tip = first_value(&c.tip_switch, body)? != 0;
        if tip {
            tip_asserted = tip_asserted.saturating_add(1);
        }
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
            // Without an explicit In Range bit, treat Tip Switch
            // == 1 as in-range — matches the Microsoft sample
            // descriptor behaviour.
            None => tip,
        };
        let confidence = match &c.confidence {
            Some(f) => first_value(f, body)? != 0,
            // No Confidence → assume the device only reports
            // contacts it's confident about.
            None => true,
        };
        contacts.push(DecodedTouchContact {
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
        None => tip_asserted,
    };

    Ok(DecodedTouchReport {
        contacts,
        contact_count,
    })
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

/// Test-only: synthetic touchscreen Report Descriptor blob with
/// two fingers + Contact Count. Used by sibling crates' smoke
/// tests to exercise the touchscreen detect / decode chain
/// end-to-end without re-pasting the blob. Modeled on the
/// Microsoft "Touch Screen Sample Report Descriptors" reference.
#[doc(hidden)]
pub fn __touchscreen_descriptor_blob() -> &'static [u8] {
    TOUCHSCREEN_DESCRIPTOR_BLOB
}

/// Two-finger touchscreen descriptor in the Microsoft sample
/// shape: Touch Screen Application → 2× Finger Logical Collections
/// (each with Tip Switch + In Range + Contact ID + X + Y) +
/// Contact Count. Logical range 0..=0x7FFF on X/Y mimics modern
/// 32k-step panels.
static TOUCHSCREEN_DESCRIPTOR_BLOB: &[u8] = &[
    0x05, 0x0D, // Usage Page (Digitizer)
    0x09, 0x04, // Usage (Touch Screen)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x01, //   Report ID (1)
    // Finger 0
    0x09, 0x22, //   Usage (Finger)
    0xA1, 0x02, //   Collection (Logical)
    0x09, 0x42, //     Usage (Tip Switch)
    0x15, 0x00, //     Logical Min (0)
    0x25, 0x01, //     Logical Max (1)
    0x75, 0x01, //     Report Size (1)
    0x95, 0x01, //     Report Count (1)
    0x81, 0x02, //     Input (Data,Var,Abs)
    0x09, 0x32, //     Usage (In Range)
    0x81, 0x02, //     Input
    0x75, 0x06, //     Report Size (6) — padding
    0x95, 0x01, 0x81, 0x03, //     Input (Cnst)
    0x09, 0x51, //     Usage (Contact ID)
    0x25, 0x7F, //     Logical Max (127)
    0x75, 0x08, //     Report Size (8)
    0x95, 0x01, 0x81, 0x02, //     Input
    0x05, 0x01, //     Usage Page (Generic Desktop)
    0x09, 0x30, //     Usage (X)
    0x26, 0xFF, 0x7F, //     Logical Max (0x7FFF)
    0x75, 0x10, //     Report Size (16)
    0x95, 0x01, 0x81, 0x02, //     Input
    0x09, 0x31, //     Usage (Y)
    0x81, 0x02, //     Input
    0xC0, //   End Collection (Finger 0)
    // Finger 1
    0x05, 0x0D, //   Usage Page (Digitizer)
    0x09, 0x22, //   Usage (Finger)
    0xA1, 0x02, //   Collection (Logical)
    0x09, 0x42, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02, 0x09, 0x32, 0x81, 0x02,
    0x75, 0x06, 0x95, 0x01, 0x81, 0x03, 0x09, 0x51, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x01, 0x81, 0x02,
    0x05, 0x01, 0x09, 0x30, 0x26, 0xFF, 0x7F, 0x75, 0x10, 0x95, 0x01, 0x81, 0x02, 0x09, 0x31, 0x81,
    0x02, 0xC0, //   End Collection (Finger 1)
    // Contact Count
    0x05, 0x0D, 0x09, 0x54, //   Usage (Contact Count)
    0x25, 0x02, //   Logical Max (2)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x01, 0x81, 0x02, 0xC0, // End Collection (Application)
];
