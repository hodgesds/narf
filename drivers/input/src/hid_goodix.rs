//! Goodix touchpads — GT7868Q (Linux `hid-multitouch`).
//!
//! There is no Goodix-specific I2C-HID touchpad driver in Linux:
//! ownership is the generic stack (`i2c-hid-acpi` → `i2c-hid-core`
//! → `hid-multitouch`), with the GT7868Q carried as explicit
//! entries in `hid-multitouch`'s device table plus a
//! report-descriptor fixup and one i2c-hid power quirk. This
//! module is NARF's copy of that explicit surface — device IDs,
//! the multitouch class, the fixup, and the resume quirk —
//! following the [`crate::hid_elan`] / [`crate::hid_rmi`] table +
//! `classify_device` shape. It does NOT touch the direct-I2C
//! Goodix touchscreen stub ([`crate::goodix`]) or the GT911 codec
//! (`narf_input::goodix`): those are touchscreen-only and
//! unrelated to this touchpad.
//!
//! Linux references (`torvalds/linux`, 7.4-rc2 @ 7475ea8b):
//!
//! - `drivers/hid/hid-multitouch.c:4599-4611` — GT7868Q entries:
//!   `HID_DEVICE(BUS_I2C, HID_GROUP_ANY, I2C_VENDOR_ID_GOODIX,
//!   I2C_DEVICE_ID_GOODIX_01E8/01E9)`, class
//!   `MT_CLS_WIN_8_FORCE_MULTI_INPUT_NSMU` (0x0018).
//! - `drivers/hid/hid-multitouch.c:592-608` — that class's quirk
//!   bundle (see [`crate::hid_multitouch::MtClass::Win8ForceMultiInputNsmu`]).
//! - `drivers/hid/hid-multitouch.c:3238-3303` — `mt_report_fixup`:
//!   for 27c6:01e8/01e9, descriptors under 608 bytes are left
//!   alone; otherwise `rdesc[607] == 0x15` (Logical Minimum) is
//!   patched to `0x25` (Logical Maximum), and any other byte is
//!   logged (`got: %x`) and left alone.
//! - `drivers/hid/i2c-hid/i2c-hid-core.c:291-293` — 27c6:0d42
//!   carries `I2C_HID_QUIRK_DELAY_WAKEUP_AFTER_RESUME`; `:1851-1861`
//!   — the resume path sleeps 1500 ms before the wakeup, "if we
//!   send wakeup too early, the device will never trigger input
//!   interrupts".
//! - `drivers/hid/i2c-hid/i2c-hid-core.c:843-845` — `i2c_hid_set_power`
//!   sleeps 60 ms after every successful PWR_ON ("According to
//!   Goodix Windows even waits 60 ms after (other?) PWR_ON
//!   requests"); that delay lives in NARF's
//!   [`crate::i2c_hid::I2cHidDriver::set_power`], not here.
//! - `drivers/hid/hid-ids.h:577-581` — vendor `0x27c6`,
//!   `01E8 0x01e8`, `01E9 0x01e9`, `01F0 0x01f0` (defined, **no
//!   user found** — deliberately NOT added here), `0D42 0x0d42`.
//! - ACPI enumeration is generic `PNP0C50`
//!   (`i2c-hid-acpi.c:95-99`); identity comes from the HID
//!   descriptor's VID:PID, not a `GDIX*` _HID.

use crate::hid_multitouch::MtClass;

// ── Device IDs (Linux `hid-ids.h:577-581`) ─────────────────────────

/// Goodix HID vendor ID (Linux `I2C_VENDOR_ID_GOODIX`).
pub const GOODIX_VENDOR_ID: u16 = 0x27c6;

/// Goodix GT7868Q touchpad (Linux `I2C_DEVICE_ID_GOODIX_01E8`).
pub const GOODIX_GT7868Q_01E8: u16 = 0x01e8;
/// Goodix GT7868Q touchpad (Linux `I2C_DEVICE_ID_GOODIX_01E9`).
pub const GOODIX_GT7868Q_01E9: u16 = 0x01e9;

/// Goodix 0d42 (Linux `I2C_DEVICE_ID_GOODIX_0D42`) — carries the
/// resume wakeup-delay quirk only; it is NOT a multitouch-table
/// device, so it has no row in [`GOODIX_DEVICE_TABLE`] and
/// [`classify_device`] returns `None` for it. Whether it is a
/// touchpad or a touchscreen is not stated in the Linux tree.
pub const GOODIX_0D42: u16 = 0x0d42;

// ── Device ID table (Linux `mt_devices[]` Goodix rows) ─────────────

/// One row of the Goodix touchpad device table: the HID VID:PID
/// plus the multitouch class Linux binds it to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GoodixDeviceMatch {
    pub vendor: u16,
    pub product: u16,
    pub class: MtClass,
}

/// The explicit Goodix touchpad list (Linux
/// `hid-multitouch.c:4599-4611`). Explicit rows only — there is
/// no VID or `GDIX` _HID fallback: a Goodix VID with an unlisted
/// PID (e.g. 0d42, or the defined-but-unused 01f0) must not be
/// claimed as a GT7868Q touchpad.
pub const GOODIX_DEVICE_TABLE: &[GoodixDeviceMatch] = &[
    GoodixDeviceMatch {
        vendor: GOODIX_VENDOR_ID,
        product: GOODIX_GT7868Q_01E8,
        class: MtClass::Win8ForceMultiInputNsmu,
    },
    GoodixDeviceMatch {
        vendor: GOODIX_VENDOR_ID,
        product: GOODIX_GT7868Q_01E9,
        class: MtClass::Win8ForceMultiInputNsmu,
    },
];

/// Look up a device in the table. Returns the matching entry or
/// `None` when no row matches.
pub fn match_device(vendor: u16, product: u16) -> Option<&'static GoodixDeviceMatch> {
    GOODIX_DEVICE_TABLE
        .iter()
        .find(|m| m.vendor == vendor && m.product == product)
}

/// Classify a HID device as a Goodix GT7868Q touchpad for the
/// bind layers. A table hit returns the multitouch class Linux
/// binds it to (`Win8ForceMultiInputNsmu`); anything else returns
/// `None`, so a non-matching device is rejected instead of being
/// claimed as Goodix.
///
/// `acpi_hid` is accepted for shape parity with
/// [`crate::hid_rmi::classify_device`] /
/// [`crate::hid_elan::classify_device`] and deliberately ignored:
/// Linux keys this classification purely on the HID descriptor
/// VID:PID, and ACPI enumeration is generic `PNP0C50` — a `GDIX*`
/// _HID does not identify a touchpad (GDIX1001 is a touchscreen).
pub fn classify_device(_acpi_hid: &str, vendor: u16, product: u16) -> Option<MtClass> {
    match_device(vendor, product).map(|m| m.class)
}

// ── Report-descriptor fixup (Linux `mt_report_fixup`) ───────────────

/// Minimum report-descriptor length the GT7868Q fixup reads.
/// Linux skips the fixup when `*size < 608`.
pub const GT7868Q_FIXUP_MIN_LEN: usize = 608;
/// Byte offset Linux patches (`rdesc[607]`).
pub const GT7868Q_FIXUP_OFFSET: usize = 607;
/// Byte Linux expects at the offset (Logical Minimum, 0x15).
pub const GT7868Q_FIXUP_EXPECTED: u8 = 0x15;
/// Byte Linux writes (Logical Maximum, 0x25).
pub const GT7868Q_FIXUP_PATCHED: u8 = 0x25;

/// Outcome of [`fixup_report_descriptor`], mirroring Linux's
/// `mt_report_fixup` branches (including the `dev_info` log
/// lines, which the caller emits).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReportDescriptorFixup {
    /// Not a GT7868Q — descriptor untouched.
    NotApplicable,
    /// GT7868Q, but the descriptor is shorter than
    /// [`GT7868Q_FIXUP_MIN_LEN`] — left alone.
    SkippedUndersize,
    /// `rdesc[607]` was `0x15` and is now `0x25`.
    Patched,
    /// GT7868Q with a long enough descriptor, but `rdesc[607]`
    /// held an unexpected byte (carried in the variant) — left
    /// alone, as Linux does ("the touchpad firmware is not
    /// suitable for applying the fix").
    UnexpectedByte(u8),
}

/// Apply the GT7868Q report-descriptor fixup in place. Call
/// between reading the descriptor and parsing it — Linux applies
/// its fixup before `hid_parse_report`, so the parsed descriptor
/// (and the blob the bind layer registers) carries the patched
/// byte.
pub fn fixup_report_descriptor(
    vendor: u16,
    product: u16,
    rdesc: &mut [u8],
) -> ReportDescriptorFixup {
    if match_device(vendor, product).is_none() {
        return ReportDescriptorFixup::NotApplicable;
    }
    if rdesc.len() < GT7868Q_FIXUP_MIN_LEN {
        return ReportDescriptorFixup::SkippedUndersize;
    }
    if rdesc[GT7868Q_FIXUP_OFFSET] == GT7868Q_FIXUP_EXPECTED {
        rdesc[GT7868Q_FIXUP_OFFSET] = GT7868Q_FIXUP_PATCHED;
        ReportDescriptorFixup::Patched
    } else {
        ReportDescriptorFixup::UnexpectedByte(rdesc[GT7868Q_FIXUP_OFFSET])
    }
}

// ── Resume quirk (Linux `I2C_HID_QUIRK_DELAY_WAKEUP_AFTER_RESUME`) ──

/// Milliseconds the resume path waits before waking a 27c6:0d42
/// device (Linux `i2c_hid_core_resume`: `msleep(1500)`).
pub const GOODIX_RESUME_WAKEUP_DELAY_MS: u64 = 1500;

/// Whether this VID:PID needs the delayed wakeup after resume.
/// Linux keys the quirk on 27c6:0d42 only
/// (`i2c-hid-core.c:291-293`).
pub fn needs_delayed_wakeup_after_resume(vendor: u16, product: u16) -> bool {
    vendor == GOODIX_VENDOR_ID && product == GOODIX_0D42
}

/// Banner + device-id table load, mirroring
/// [`crate::hid_elan::register_initcalls`].
pub fn register_initcalls() {
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  hid-goodix: loaded ({} device IDs)",
        GOODIX_DEVICE_TABLE.len(),
    );
}
