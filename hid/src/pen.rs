//! HID Pen / Digitizer profile decoder — clean-room.
//!
//! ## Sources (public only)
//!
//! - **HID Usage Tables 1.4 §16** — Digitizer page (0x0D). Defines
//!   every usage this profile keys on: Pen (0x02), Stylus (0x20),
//!   Tip Switch (0x42), In Range (0x32), Touch Valid (0x33),
//!   Eraser (0x45), Invert (0x3C), X-Tilt (0x3D), Y-Tilt (0x3E),
//!   Twist (0x41), Barrel Switch (0x44), Secondary Barrel
//!   Switch (0x5A), Tip Pressure (0x30).
//!   <https://usb.org/document-library/hid-usage-tables-14>
//! - **HID 1.11 §6.2.2** — descriptor parsing (already in
//!   [`crate::descriptor`]).
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//!
//! No GPL / Linux source consulted. Vendor-specific extensions
//! (Wacom Intuos / AES wire-protocol bytes, Microsoft Surface Pen
//! ID, N-trig) are NOT covered — those are documented only via
//! reverse-engineered material this project doesn't accept as a
//! clean-room source. The HID Pen profile this module decodes is
//! the *interoperable* baseline every modern active stylus
//! advertises (Wacom AES Pens, Microsoft Surface Slim Pen,
//! Samsung S Pen since Note 4, Apple Pencil-via-HID-stylus mode,
//! etc.).

extern crate alloc;
use alloc::vec::Vec;

use crate::descriptor::{Field, FieldKind, ReportDescriptor};
use crate::report::{extract, ReportError};
use crate::usage::{digitizer, generic_desktop};

/// One pen-profile field plus the index within its `usages` list.
/// HID descriptors commonly declare several button bits under one
/// Main Input with `Report Count = N` and `usages = [u1, u2, ...]`;
/// the decoder needs to know which index corresponds to which
/// pen usage to pick the right bit out of the extracted vector.
#[derive(Clone, Debug)]
pub struct UsagePick {
    pub field: Field,
    pub index: u32,
}

/// Subset of fields on a HID active stylus.
#[derive(Clone, Debug)]
pub struct PenFields {
    pub tip_switch: UsagePick,
    pub in_range: Option<UsagePick>,
    pub eraser: Option<UsagePick>,
    pub invert: Option<UsagePick>,
    pub barrel_switch: Option<UsagePick>,
    pub secondary_barrel_switch: Option<UsagePick>,
    pub x: UsagePick,
    pub y: UsagePick,
    pub tip_pressure: Option<UsagePick>,
    pub x_tilt: Option<UsagePick>,
    pub y_tilt: Option<UsagePick>,
    pub twist: Option<UsagePick>,
}

#[derive(Clone, Debug)]
pub struct PenProfile {
    pub input_report_id: u8,
    pub fields: PenFields,
}

/// Search every Input field for one that lists `(page, usage_id)`
/// in its usage vector. Returns the [`UsagePick`] capturing the
/// field plus the index of the matching usage.
fn pick(d: &ReportDescriptor, page: u16, usage_id: u16) -> Option<UsagePick> {
    for f in d.fields.iter().filter(|f| f.kind == FieldKind::Input) {
        if let Some(idx) = f.usages.iter().position(|u| u.0 == page && u.1 == usage_id) {
            return Some(UsagePick {
                field: f.clone(),
                index: idx as u32,
            });
        }
    }
    None
}

/// Probe a parsed descriptor for a Pen / Stylus Application
/// Collection. Returns `Some` iff the descriptor exposes the
/// minimum-required field set (Tip Switch + X + Y).
pub fn detect(d: &ReportDescriptor) -> Option<PenProfile> {
    let has_pen_root = d.top_level_apps.iter().any(|&(p, u)| {
        p == digitizer::PAGE && (u == digitizer::PEN || u == 0x20 /* Stylus */)
    });
    if !has_pen_root {
        return None;
    }
    let tip = pick(d, digitizer::PAGE, digitizer::TIP_SWITCH)?;
    let x = pick(d, generic_desktop::PAGE, generic_desktop::X)?;
    let y = pick(d, generic_desktop::PAGE, generic_desktop::Y)?;
    Some(PenProfile {
        input_report_id: tip.field.report_id,
        fields: PenFields {
            tip_switch: tip,
            in_range: pick(d, digitizer::PAGE, digitizer::IN_RANGE),
            eraser: pick(d, digitizer::PAGE, 0x45),
            invert: pick(d, digitizer::PAGE, 0x3C),
            barrel_switch: pick(d, digitizer::PAGE, 0x44),
            secondary_barrel_switch: pick(d, digitizer::PAGE, digitizer::SECONDARY_BARREL_SWITCH),
            x,
            y,
            tip_pressure: pick(d, digitizer::PAGE, digitizer::TIP_PRESSURE),
            x_tilt: pick(d, digitizer::PAGE, 0x3D),
            y_tilt: pick(d, digitizer::PAGE, 0x3E),
            twist: pick(d, digitizer::PAGE, 0x41),
        },
    })
}

/// Decoded view of one pen Input report.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DecodedPen {
    pub tip: bool,
    pub in_range: bool,
    pub eraser: bool,
    pub invert: bool,
    pub barrel_button: bool,
    pub secondary_barrel_button: bool,
    pub x: i32,
    pub y: i32,
    pub pressure: Option<i32>,
    pub x_tilt_deg: Option<i32>,
    pub y_tilt_deg: Option<i32>,
    pub twist: Option<i32>,
}

/// Pull the value at `slot.index` from a freshly-extracted field.
fn pick_at(field: &Field, body: &[u8], idx: u32) -> Result<i32, ReportError> {
    let v = extract(field, body)?;
    Ok(v.get(idx as usize).copied().unwrap_or(0))
}

fn pick_bool(slot: &UsagePick, body: &[u8]) -> Result<bool, ReportError> {
    Ok(pick_at(&slot.field, body, slot.index)? != 0)
}

fn pick_i32(slot: &UsagePick, body: &[u8]) -> Result<i32, ReportError> {
    pick_at(&slot.field, body, slot.index)
}

fn opt_bool(slot: &Option<UsagePick>, body: &[u8]) -> Result<bool, ReportError> {
    match slot {
        Some(s) => pick_bool(s, body),
        None => Ok(false),
    }
}

fn opt_i32(slot: &Option<UsagePick>, body: &[u8]) -> Result<Option<i32>, ReportError> {
    match slot {
        Some(s) => pick_i32(s, body).map(Some),
        None => Ok(None),
    }
}

/// Decode an Input report. Strips the report-id byte; returns
/// `Err(Short)` if the leading byte doesn't match the profile's
/// expected report id or the body is too short.
///
/// The descriptor layout typically has 5–8 separate fields; we
/// re-extract each on every call rather than caching, since the
/// cost is dwarfed by the surrounding USB / i2c-HID transfer.
pub fn decode_input(p: &PenProfile, report: &[u8]) -> Result<DecodedPen, ReportError> {
    if report.is_empty() || report[0] != p.input_report_id {
        return Err(ReportError::Short);
    }
    let body = &report[1..];
    let f = &p.fields;

    let tip = pick_bool(&f.tip_switch, body)?;
    let in_range = match &f.in_range {
        Some(s) => pick_bool(s, body)?,
        None => tip,
    };
    Ok(DecodedPen {
        tip,
        in_range,
        eraser: opt_bool(&f.eraser, body)?,
        invert: opt_bool(&f.invert, body)?,
        barrel_button: opt_bool(&f.barrel_switch, body)?,
        secondary_barrel_button: opt_bool(&f.secondary_barrel_switch, body)?,
        x: pick_i32(&f.x, body)?,
        y: pick_i32(&f.y, body)?,
        pressure: opt_i32(&f.tip_pressure, body)?,
        x_tilt_deg: opt_i32(&f.x_tilt, body)?,
        y_tilt_deg: opt_i32(&f.y_tilt, body)?,
        twist: opt_i32(&f.twist, body)?,
    })
}
