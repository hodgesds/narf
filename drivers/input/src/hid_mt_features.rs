//! Win8 Precision Touchpad (PTP) HID Feature reports — mode select +
//! max-contact discovery for the multi-touch class driver.
//!
//! ## Sources (public only)
//!
//! - **HID Usage Tables 1.4 §16** — Digitizer page (0x0D). Defines
//!   the Configuration TLC + Device Mode usage (0x60), Contact Count
//!   Maximum (0x55), Latency Mode (0x60 in some specs), Surface Switch
//!   (0x57), Button Switch (0x58).
//!   <https://usb.org/document-library/hid-usage-tables-14>
//! - **Microsoft Precision Touchpad implementation guide** — public
//!   technical documentation. Defines the Required HID Top-Level
//!   Collections, Device Mode feature semantics, and the
//!   Configuration TLC layout PTPs must expose:
//!     - `mode = 0x00` MOUSE (boot-style 3-byte report)
//!     - `mode = 0x01` SINGLE_INPUT
//!     - `mode = 0x03` MULTI_TOUCH / MULTIPLE_INPUT — "Mouse + Touch"
//!       Microsoft Precision-Touchpad reporting mode (sends both
//!       standard mouse + MT reports on the wire).
//!       <https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/touchpad-windows-precision-touchpad-collection>
//!
//! Linux reference (post-2026-05-20 GPL link policy permits citation):
//! `linux/drivers/hid/hid-multitouch.c`:
//!     - L82-83 `MT_INPUTMODE_TOUCHSCREEN=0x02 / _TOUCHPAD=0x03`
//!     - L538-580 `mt_feature_mapping()` — locates Contact Count
//!       Maximum + Button Type Feature fields.
//!     - L1643-1748 `mt_need_to_apply_feature()` / `mt_set_modes()`
//!       — drives the Device Mode + Latency / Surface / Button
//!       Switch Feature writes.
//!
//! ## What this module is
//!
//! A small helper layer on top of `narf_hid::ptp` (and the new
//! `hid_multitouch` driver) that exposes:
//!
//! 1. The two stable mode constants (`MODE_TOUCHPAD`,
//!    `MODE_TOUCHSCREEN`) the Win8 PTP spec asks the host to write.
//! 2. [`encode_mode_feature`] — builds the bytes a transport layer
//!    sends in `SET_FEATURE(Device Mode)`.
//! 3. [`decode_max_contact_count`] — reads back the value written
//!    by the device into a `GET_FEATURE(Contact Count Maximum)`
//!    response, with a sane fallback (5) for descriptors that omit
//!    the Maximum field.
//!
//! No transport (USB control / i2c / Bluetooth) — those layers feed
//! bytes in and read bytes out. This module is unit-testable in
//! isolation.

extern crate alloc;
use alloc::vec::Vec;

use narf_hid::descriptor::{Field, FieldKind, ReportDescriptor};
use narf_hid::ptp::{self, PtpProfile};
use narf_hid::report::{extract, pack, ReportError};
use narf_hid::usage::digitizer;

/// Microsoft PTP Device Mode values for the `Device Mode` Feature
/// item (HID Usage `0x0D / 0x60`). Mirrors `MT_INPUTMODE_*` in
/// `linux/drivers/hid/hid-multitouch.c:82-83`.
pub mod mode {
    /// Mouse-emulation legacy mode (boot-style 3-byte report).
    pub const MOUSE: u8 = 0x00;
    /// Single-Input — relative mode with one contact.
    pub const SINGLE_INPUT: u8 = 0x01;
    /// Touchscreen reporting mode — Linux `MT_INPUTMODE_TOUCHSCREEN`.
    pub const TOUCHSCREEN: u8 = 0x02;
    /// Touchpad / Multi-Touch reporting mode — Linux
    /// `MT_INPUTMODE_TOUCHPAD`. Microsoft "Mouse + Touch" mode that
    /// emits both standard mouse reports and MT reports on the wire.
    pub const TOUCHPAD: u8 = 0x03;
}

/// Default max-contact value when neither the descriptor nor a
/// `GET_FEATURE(Contact Count Maximum)` response provides one. The
/// Microsoft PTP spec mandates ≥3, but 5 is the universal Stage-1
/// landing zone — virtually every modern touchpad / touchscreen
/// supports 5 simultaneous contacts. Linux uses
/// `MT_DEFAULT_MAXCONTACT = 10` (`linux/drivers/hid/hid-multitouch.c:241`);
/// we choose the smaller value because over-allocating slot state
/// has higher cost in a no_std kernel than re-walking the table
/// when a device legitimately exposes >5.
pub const DEFAULT_MAX_CONTACTS: u8 = 5;

/// Microsoft PTP hard cap on `Contact Count Maximum` we'll honour
/// from the wire. Linux uses `MT_MAX_MAXCONTACT = 250`
/// (`linux/drivers/hid/hid-multitouch.c:242`); we cap lower because
/// per-slot tracking allocates fixed-size state — there's no
/// real-world device with more than ~10, but the bound keeps a
/// buggy firmware from wedging slot allocation.
pub const HARD_MAX_CONTACTS: u8 = 32;

/// Build the wire bytes for `SET_FEATURE(Device Mode)`.
///
/// Returns `None` when the parsed descriptor exposed no Device Mode
/// Feature field — caller treats that as "device is not a Win8 PTP;
/// fall back to whatever mode the firmware boots in".
///
/// Output layout matches [`narf_hid::ptp::build_mode_feature_report`]
/// — leading 1-byte report-id, then the Feature report body with the
/// Mode byte placed at the right bit offset and all other fields
/// zeroed. The caller strips the leading byte when its transport
/// puts the report-id in a separate field (e.g. USB control
/// `wValue`'s low byte).
pub fn encode_mode_feature(p: &PtpProfile, mode: u8) -> Option<Vec<u8>> {
    ptp::build_mode_feature_report(p, mode)
}

/// Default value used when a descriptor offers no `Contact Count
/// Maximum` Feature item AND the device hasn't been polled with
/// `GET_FEATURE`. Stays a const fn so callers can use it in `const`
/// contexts (e.g. boot panel default text).
pub const fn default_max_contacts() -> u8 {
    DEFAULT_MAX_CONTACTS
}

/// Locate the `Contact Count Maximum` (Digitizer page 0x0D, usage
/// 0x55) Feature item in a parsed descriptor. Used by the bind
/// layer to decide whether to issue `GET_FEATURE` to learn the
/// runtime max, vs trusting the descriptor's logical-max alone.
///
/// Mirrors Linux `mt_feature_mapping()` on `HID_DG_CONTACTMAX`
/// (`linux/drivers/hid/hid-multitouch.c:544-555`).
pub fn find_contact_count_max_feature(d: &ReportDescriptor) -> Option<&Field> {
    d.fields.iter().find(|f| {
        f.kind == FieldKind::Feature
            && f.usage_page == digitizer::PAGE
            && f.usages
                .iter()
                .any(|&(_, u)| u == digitizer::CONTACT_COUNT_MAX)
    })
}

/// Decode the `Contact Count Maximum` value from a raw
/// `GET_FEATURE` response. `body` is the report body *with the
/// report-id byte already stripped* — caller is responsible for
/// matching the report-id to the descriptor.
///
/// On any extraction error, or when the value is zero, returns
/// `field.logical_max` (capped at [`HARD_MAX_CONTACTS`]) as a
/// fallback — matches Linux's behaviour in `mt_feature_mapping()`
/// (`linux/drivers/hid/hid-multitouch.c:547-550`).
pub fn decode_max_contact_count(field: &Field, body: &[u8]) -> u8 {
    let from_wire = extract(field, body)
        .ok()
        .and_then(|v| v.first().copied())
        .unwrap_or(0);
    let raw = if from_wire > 0 {
        from_wire as u32
    } else {
        field.logical_max.max(0) as u32
    };
    // Clamp into [1, HARD_MAX_CONTACTS]. `0` is nonsensical (a
    // touchpad that supports zero contacts isn't a touchpad).
    let clamped = raw.clamp(1, HARD_MAX_CONTACTS as u32);
    clamped as u8
}

/// Compose a `SET_FEATURE(Contact Count Maximum)` request body. Used
/// by transports that want to write back a clamped max-contact value
/// to the device (Linux does this for some quirky firmwares, see
/// `mt_need_to_apply_feature()` on `HID_DG_CONTACTMAX`,
/// `linux/drivers/hid/hid-multitouch.c:1686-1695`).
///
/// Returns `None` when the descriptor has no `Contact Count Maximum`
/// Feature field. On success, returns the full report body (no
/// report-id prefix) ready to feed to the transport's `set_feature`
/// call.
pub fn encode_max_contact_count(d: &ReportDescriptor, max_contacts: u8) -> Option<Vec<u8>> {
    let f = find_contact_count_max_feature(d)?;
    let report_id = f.report_id;
    let body_bits = d.report_body_bits(report_id, FieldKind::Feature);
    let body_bytes = (body_bits as usize).div_ceil(8);
    let mut body = alloc::vec![0u8; body_bytes];
    let value = (max_contacts as i32).min(HARD_MAX_CONTACTS as i32);
    if pack(f, &mut body, &[value]).is_err() {
        return None;
    }
    Some(body)
}

/// Convert a `(profile, descriptor)` pair into the discovered max
/// contact count. Order of precedence (matches Linux
/// `mt_feature_mapping()` precedence):
///
/// 1. `class.max_contacts` if the caller's quirk table overrode it
///    (handled in the driver layer — passed in here).
/// 2. The Feature field's *logical maximum* — for descriptors that
///    declare a `Contact Count Maximum` field but where we haven't
///    issued `GET_FEATURE` yet.
/// 3. The per-contact slot list length (`profile.contacts_max`).
/// 4. [`DEFAULT_MAX_CONTACTS`].
pub fn resolve_max_contacts(p: &PtpProfile, d: &ReportDescriptor, class_max: Option<u8>) -> u8 {
    if let Some(m) = class_max.filter(|&m| m > 0) {
        return m.min(HARD_MAX_CONTACTS);
    }
    if let Some(f) = find_contact_count_max_feature(d) {
        let lm = f.logical_max;
        if lm > 0 {
            return (lm as u32).clamp(1, HARD_MAX_CONTACTS as u32) as u8;
        }
    }
    if p.contacts_max > 0 {
        return (p.contacts_max as u32).clamp(1, HARD_MAX_CONTACTS as u32) as u8;
    }
    DEFAULT_MAX_CONTACTS
}

/// Errors surfaceable from feature decode helpers. Kept distinct
/// from `narf_hid::report::ReportError` so the bind layer can log
/// "missing descriptor field" separately from "report body
/// truncated on the wire".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FeatureError {
    /// No Device Mode Feature field in the parsed descriptor.
    NoDeviceMode,
    /// No Contact Count Maximum Feature field in the parsed
    /// descriptor.
    NoContactMax,
    /// Underlying report codec error.
    Codec(ReportError),
}

impl From<ReportError> for FeatureError {
    fn from(e: ReportError) -> Self {
        FeatureError::Codec(e)
    }
}
