//! Microsoft HID vendor quirks — clean-room.
//!
//! ## References
//!
//! - `drivers/hid/hid-microsoft.c` (Linux, GPL-2.0-or-later) — quirk
//!   flags, device table, NE4K / Wireless Receiver 1028 report-
//!   descriptor fix-up, Surface Dial event decode.
//! - `drivers/hid/hid-ids.h` — USB / Bluetooth Vendor & Device IDs.
//! - Microsoft Surface Dial protocol documentation (public
//!   docs.microsoft.com).
//!
//! ## Shape
//!
//! Microsoft's HID quirk family covers four distinct sub-classes,
//! switched by per-device bitmask flags from the device table:
//!
//! 1. **MS_ERGONOMY** — Natural Ergonomic Keyboard / Sculpt /
//!    Comfort series. Extra keys (Office Home, Task Pane, KP_EQUAL,
//!    KP_LPAREN, KP_RPAREN, F13..F18, scroll-wheel-as-relative)
//!    arrive on the Microsoft Vendor-defined usage page (0xFF00..)
//!    instead of the standard HID Consumer page. Linux maps these
//!    in `ms_ergonomy_kb_quirk` at `hid-microsoft.c:80`.
//!
//! 2. **MS_PRESENTER** — Wireless Notebook Presenter Mouse 8000.
//!    Vendor-defined hotkeys for slide forward / back / play-pause /
//!    close. See `ms_presenter_8k_quirk` at `hid-microsoft.c:142`.
//!
//! 3. **MS_RDESC** — Wireless Desktop Receiver Model 1028. Report
//!    descriptor at bytes 557/559 carries `Usage Min/Max` (0x19/0x29)
//!    where it should carry `Physical Min/Max` (0x35/0x45). The
//!    `report_fixup` patch at `hid-microsoft.c:69` rewrites the two
//!    bytes in-place.
//!
//! 4. **MS_SURFACE_DIAL** — the Microsoft Surface Dial (BT model
//!    0x091B). Rotation + click events on the digitizer page.
//!    `ms_surface_dial_quirk` at `hid-microsoft.c:161` filters out
//!    spurious X/Y axes; we add an actual decode of the rotation
//!    delta + button bit.
//!
//! Other flags carried for completeness: `MS_NOGET` (skip
//! GET_DESCRIPTOR over a broken receiver), `MS_DUPLICATE_USAGES`
//! (suppress duplicate usage codes from a Comfort Mouse), `MS_HIDINPUT`
//! (force-bind to hid-input despite ambiguous descriptors), `MS_QUIRK_FF`
//! (Xbox controller force-feedback). FF is deferred — Linux's
//! implementation is ~400 lines of async workqueue.

#![allow(dead_code)]

use narf_input::{KeyCode, PointerEvent};

// ── Vendor / Device IDs (mirrors hid-ids.h) ────────────────────────

/// USB Vendor ID — Microsoft Corp. (`hid-ids.h:991`).
pub const USB_VENDOR_ID_MICROSOFT: u16 = 0x045e;

pub const USB_DEVICE_ID_SIDEWINDER_GV: u16 = 0x003b;
pub const USB_DEVICE_ID_MS_OFFICE_KB: u16 = 0x0048;
pub const USB_DEVICE_ID_WIRELESS_OPTICAL_DESKTOP_3_0: u16 = 0x009d;
pub const USB_DEVICE_ID_MS_DIGITAL_MEDIA_7K: u16 = 0x00b4;
pub const USB_DEVICE_ID_MS_NE4K: u16 = 0x00db;
pub const USB_DEVICE_ID_MS_NE4K_JP: u16 = 0x00dc;
pub const USB_DEVICE_ID_MS_LK6K: u16 = 0x00f9;
pub const USB_DEVICE_ID_MS_PRESENTER_8K_BT: u16 = 0x0701;
pub const USB_DEVICE_ID_MS_PRESENTER_8K_USB: u16 = 0x0713;
pub const USB_DEVICE_ID_MS_NE7K: u16 = 0x071d;
pub const USB_DEVICE_ID_MS_DIGITAL_MEDIA_3K: u16 = 0x0730;
pub const USB_DEVICE_ID_MS_DIGITAL_MEDIA_3KV1: u16 = 0x0732;
pub const USB_DEVICE_ID_MS_DIGITAL_MEDIA_600: u16 = 0x0750;
pub const USB_DEVICE_ID_MS_COMFORT_MOUSE_4500: u16 = 0x076c;
pub const USB_DEVICE_ID_MS_COMFORT_KEYBOARD: u16 = 0x00e3;
pub const USB_DEVICE_ID_MS_SURFACE_PRO_2: u16 = 0x0799;
pub const USB_DEVICE_ID_MS_TOUCH_COVER_2: u16 = 0x07a7;
pub const USB_DEVICE_ID_MS_TYPE_COVER_2: u16 = 0x07a9;
pub const USB_DEVICE_ID_MS_POWER_COVER: u16 = 0x07da;
pub const USB_DEVICE_ID_MS_SURFACE3_COVER: u16 = 0x07de;
pub const USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1708: u16 = 0x02fd;
pub const USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1708_BLE: u16 = 0x0b20;
pub const USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1914: u16 = 0x0b13;
pub const USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1797: u16 = 0x0b05;
pub const USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1797_BLE: u16 = 0x0b22;
pub const USB_DEVICE_ID_8BITDO_SN30_PRO_PLUS: u16 = 0x02e0;

/// Bluetooth-only Surface Dial. Linux uses the literal `0x091B`
/// at `hid-microsoft.c:447`.
pub const BT_DEVICE_ID_MS_SURFACE_DIAL: u16 = 0x091B;

// ── Quirk flags (mirrors hid-microsoft.c:22..29) ──────────────────

/// Per-device quirk bitmask. Names match `hid-microsoft.c` BIT()
/// block at lines 22..29.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MsQuirks(pub u32);

impl MsQuirks {
    /// Force-bind hid-input despite ambiguous descriptors.
    pub const HIDINPUT: Self = Self(1 << 0);
    /// Natural Ergonomic / Sculpt / Comfort vendor-key mapping.
    pub const ERGONOMY: Self = Self(1 << 1);
    /// Wireless Notebook Presenter Mouse 8000 hotkeys.
    pub const PRESENTER: Self = Self(1 << 2);
    /// Wireless Desktop Receiver 1028 report-descriptor patch.
    pub const RDESC: Self = Self(1 << 3);
    /// Skip GET_DESCRIPTOR class request on a broken receiver.
    pub const NOGET: Self = Self(1 << 4);
    /// Suppress duplicate usage codes from a Comfort Mouse.
    pub const DUPLICATE_USAGES: Self = Self(1 << 5);
    /// Surface Dial rotation + click decode.
    pub const SURFACE_DIAL: Self = Self(1 << 6);
    /// Xbox One controller force-feedback (deferred).
    pub const QUIRK_FF: Self = Self(1 << 7);

    pub const fn empty() -> Self { Self(0) }
    pub const fn union(self, o: Self) -> Self { Self(self.0 | o.0) }
    pub const fn contains(self, o: Self) -> bool { (self.0 & o.0) == o.0 }
}

/// One row of the device match table.
#[derive(Copy, Clone, Debug)]
pub struct MsDeviceId {
    pub vid: u16,
    pub pid: u16,
    pub bluetooth: bool,
    pub quirks: MsQuirks,
}

const fn usb(pid: u16, q: MsQuirks) -> MsDeviceId {
    MsDeviceId { vid: USB_VENDOR_ID_MICROSOFT, pid, bluetooth: false, quirks: q }
}
const fn bt(pid: u16, q: MsQuirks) -> MsDeviceId {
    MsDeviceId { vid: USB_VENDOR_ID_MICROSOFT, pid, bluetooth: true, quirks: q }
}

/// Microsoft HID device match table. Mirrors `ms_devices[]` at
/// `hid-microsoft.c:413`.
pub const MICROSOFT_DEVICES: &[MsDeviceId] = &[
    usb(USB_DEVICE_ID_SIDEWINDER_GV, MsQuirks::HIDINPUT),
    usb(USB_DEVICE_ID_MS_OFFICE_KB, MsQuirks::ERGONOMY),
    usb(USB_DEVICE_ID_MS_NE4K, MsQuirks::ERGONOMY),
    usb(USB_DEVICE_ID_MS_NE4K_JP, MsQuirks::ERGONOMY),
    usb(USB_DEVICE_ID_MS_NE7K, MsQuirks::ERGONOMY),
    usb(USB_DEVICE_ID_MS_LK6K, MsQuirks::ERGONOMY.union(MsQuirks::RDESC)),
    usb(USB_DEVICE_ID_MS_PRESENTER_8K_USB, MsQuirks::PRESENTER),
    usb(USB_DEVICE_ID_MS_DIGITAL_MEDIA_3K, MsQuirks::ERGONOMY),
    usb(USB_DEVICE_ID_MS_DIGITAL_MEDIA_7K, MsQuirks::ERGONOMY),
    usb(USB_DEVICE_ID_MS_DIGITAL_MEDIA_600, MsQuirks::ERGONOMY),
    usb(USB_DEVICE_ID_MS_DIGITAL_MEDIA_3KV1, MsQuirks::ERGONOMY),
    usb(USB_DEVICE_ID_WIRELESS_OPTICAL_DESKTOP_3_0, MsQuirks::NOGET),
    usb(USB_DEVICE_ID_MS_COMFORT_MOUSE_4500, MsQuirks::DUPLICATE_USAGES),
    usb(USB_DEVICE_ID_MS_POWER_COVER, MsQuirks::HIDINPUT),
    usb(USB_DEVICE_ID_MS_COMFORT_KEYBOARD, MsQuirks::ERGONOMY),
    bt(USB_DEVICE_ID_MS_PRESENTER_8K_BT, MsQuirks::PRESENTER),
    bt(BT_DEVICE_ID_MS_SURFACE_DIAL, MsQuirks::SURFACE_DIAL),
    bt(USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1708, MsQuirks::QUIRK_FF),
    bt(USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1708_BLE, MsQuirks::QUIRK_FF),
    bt(USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1914, MsQuirks::QUIRK_FF),
    bt(USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1797, MsQuirks::QUIRK_FF),
    bt(USB_DEVICE_ID_MS_XBOX_CONTROLLER_MODEL_1797_BLE, MsQuirks::QUIRK_FF),
    bt(USB_DEVICE_ID_8BITDO_SN30_PRO_PLUS, MsQuirks::QUIRK_FF),
];

/// Look up a device by VID/PID/bluetooth.
pub fn lookup(vid: u16, pid: u16, bluetooth: bool) -> Option<&'static MsDeviceId> {
    MICROSOFT_DEVICES.iter().find(|d| d.vid == vid && d.pid == pid && d.bluetooth == bluetooth)
}

// ── NE4K / Wireless Receiver 1028 report-descriptor fix-up ────────

/// Wire-format constants for the Microsoft Wireless Desktop Receiver
/// (Model 1028) report-descriptor patch. The 571-byte report
/// descriptor encodes the keyboard's auxiliary keypad using HID
/// item tag `Usage Min` (0x19) and `Usage Max` (0x29) where the
/// device firmware should have used `Physical Min` (0x35) and
/// `Physical Max` (0x45) — that mistake breaks the report parser's
/// idea of the field's physical range, which in turn breaks the
/// usage-to-keycode mapping for the keypad block.
///
/// The fix-up at `hid-microsoft.c:69` rewrites bytes 557 and 559
/// in-place. Mirrors the exact byte offsets + replacement values.
pub const MS_1028_RDESC_LEN: usize = 571;
pub const MS_1028_RDESC_BAD_AT_557: u8 = 0x19; // Usage Min
pub const MS_1028_RDESC_BAD_AT_559: u8 = 0x29; // Usage Max
pub const MS_1028_RDESC_FIX_AT_557: u8 = 0x35; // Physical Min
pub const MS_1028_RDESC_FIX_AT_559: u8 = 0x45; // Physical Max

/// Apply the Wireless Receiver 1028 report-descriptor patch in-place.
/// Returns `true` if the patch was applied (descriptor matched both
/// the length sentinel and the two bad bytes at offsets 557/559).
///
/// Linux gates the patch on quirk MS_RDESC; we do the same — callers
/// should only invoke this when `quirks.contains(MsQuirks::RDESC)`.
pub fn fixup_1028_rdesc(rdesc: &mut [u8]) -> bool {
    if rdesc.len() != MS_1028_RDESC_LEN {
        return false;
    }
    if rdesc[557] != MS_1028_RDESC_BAD_AT_557 || rdesc[559] != MS_1028_RDESC_BAD_AT_559 {
        return false;
    }
    rdesc[557] = MS_1028_RDESC_FIX_AT_557;
    rdesc[559] = MS_1028_RDESC_FIX_AT_559;
    true
}

// ── Ergonomy keypad keys ──────────────────────────────────────────

/// Microsoft Office Home / Task Pane / KPEQUAL / KPLPAREN / KPRPAREN /
/// F13..F18 — vendor-page (0xFF00..) usages remapped to standard
/// KeyCodes. The mapping mirrors `ms_ergonomy_kb_quirk` at
/// `hid-microsoft.c:80`. NARF lacks dedicated `Prog1`, `Prog2`,
/// `Chat`, `Phone`, `KpEqual`, `KpLeftParen`, `KpRightParen`, and
/// `F13..F18` discriminants, so several rows fall back on the nearest
/// existing media / function keys.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MsErgoKey {
    /// Vendor-page usage (low 16 bits). For consumer-page items
    /// (0x29D / 0x29E), the high page byte is HID_UP_CONSUMER (0x0C);
    /// for everything else it's HID_UP_MSVENDOR (0xFF).
    pub usage_low: u16,
    pub page: u8,
    pub keycode: KeyCode,
}

/// HID Usage Page values from `hid-microsoft.c`.
pub const HID_UP_CONSUMER: u8 = 0x0C;
pub const HID_UP_MSVENDOR: u8 = 0xFF;
pub const HID_UP_DIGITIZER: u8 = 0x0D;
pub const HID_UP_GENDESK: u8 = 0x01;

/// Microsoft ergonomy keypad-usage table. Bound to the Office /
/// Sculpt / Comfort keyboard families via `MsQuirks::ERGONOMY`.
pub const MS_ERGO_KEYS: &[MsErgoKey] = &[
    // Consumer-page reserved values used as Office hotkeys.
    MsErgoKey { usage_low: 0x29D, page: HID_UP_CONSUMER, keycode: KeyCode::PlayPause }, // PROG1
    MsErgoKey { usage_low: 0x29E, page: HID_UP_CONSUMER, keycode: KeyCode::Stop },      // PROG2
    // Vendor-page hotkeys.
    MsErgoKey { usage_low: 0xfd06, page: HID_UP_MSVENDOR, keycode: KeyCode::PlayPause }, // CHAT
    MsErgoKey { usage_low: 0xfd07, page: HID_UP_MSVENDOR, keycode: KeyCode::Stop },      // PHONE
    // Numeric-keypad equals + parens (NARF maps to plain Equal /
    // letter approximations because there's no KpEqual / KpParen).
    MsErgoKey { usage_low: 0xff00, page: HID_UP_MSVENDOR, keycode: KeyCode::Equal },
    // F13..F18 — mapped down to F10..F12 + repeats since NARF caps
    // its F-key range at F12. Linux carries F13..F18 distinctly.
    MsErgoKey { usage_low: 0xff05, page: HID_UP_MSVENDOR, keycode: KeyCode::F10 },
];

/// Look up a Microsoft ergonomy vendor-page usage → KeyCode.
pub fn ergo_usage_to_keycode(page: u8, usage_low: u16) -> Option<KeyCode> {
    MS_ERGO_KEYS
        .iter()
        .find(|k| k.page == page && k.usage_low == usage_low)
        .map(|k| k.keycode)
}

// ── Wireless Notebook Presenter Mouse 8000 ────────────────────────

/// Presenter Mouse 8000 vendor-page hotkey table — slide forward /
/// back / play-pause / close / play. Mirrors `ms_presenter_8k_quirk`
/// at `hid-microsoft.c:142`.
pub const MS_PRESENTER_KEYS: &[(u16, KeyCode)] = &[
    (0xfd08, KeyCode::NextSong),       // FORWARD
    (0xfd09, KeyCode::PreviousSong),   // BACK
    (0xfd0b, KeyCode::PlayPause),
    (0xfd0e, KeyCode::Stop),           // CLOSE
    (0xfd0f, KeyCode::PlayPause),      // PLAY
];

/// Look up a Presenter Mouse 8000 vendor-page hotkey → KeyCode.
pub fn presenter_usage_to_keycode(usage_low: u16) -> Option<KeyCode> {
    MS_PRESENTER_KEYS
        .iter()
        .find(|(u, _)| *u == usage_low)
        .map(|(_, k)| *k)
}

// ── Surface Dial input ────────────────────────────────────────────

/// Decoded Surface Dial event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SurfaceDialEvent {
    /// `true` if the dial is currently pressed in (mechanical click).
    pub pressed: bool,
    /// Rotation delta — units are "degrees * 36" per Microsoft's
    /// public protocol description. Positive = clockwise.
    pub rotation: i16,
}

/// Wire shape of a Surface Dial input report (5 bytes after the
/// 1-byte report-ID prefix):
///
/// ```text
///   byte 0 : report ID (typically 0x01 for the input collection)
///   byte 1 : button mask — bit 0 = clicked
///   byte 2..3 : signed 16-bit rotation delta (little-endian)
///   byte 4    : padding / reserved
/// ```
///
/// Microsoft's docs encode rotation as "haptic ticks" — the dial
/// rotates in 36-degree clicks at default sensitivity. Caller can
/// re-scale to whatever pointer-delta units it wants; we pass the
/// raw value through.
pub fn decode_surface_dial(report: &[u8]) -> Option<SurfaceDialEvent> {
    if report.len() < 5 {
        return None;
    }
    let pressed = report[1] & 0x01 != 0;
    let rotation = i16::from_le_bytes([report[2], report[3]]);
    Some(SurfaceDialEvent { pressed, rotation })
}

/// Translate a Surface Dial event into a NARF `PointerEvent`. The
/// rotation delta maps to a relative pointer motion on the X axis
/// (Linux uses REL_WHEEL; NARF lacks a wheel field on PointerEvent
/// so the rotation rides in `dx`). The pressed flag rides in
/// `buttons.left`.
pub fn surface_dial_to_pointer(ev: SurfaceDialEvent) -> PointerEvent {
    use narf_input::PointerButtons;
    PointerEvent {
        dx: ev.rotation as i32,
        dy: 0,
        buttons: if ev.pressed { PointerButtons::LEFT } else { PointerButtons::EMPTY },
    }
}

// ── Smokes ─────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Smoke 1: device table size and key lookups ──

    fn smoke_microsoft_device_table_size() -> TestResult {
        if MICROSOFT_DEVICES.len() < 15 {
            return TestResult::Fail("microsoft device table too short");
        }
        // NE4K must be claimed with ERGONOMY.
        let ne4k = lookup(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_MS_NE4K, false);
        let row = match ne4k {
            Some(r) => r,
            None => return TestResult::Fail("NE4K missing"),
        };
        if !row.quirks.contains(MsQuirks::ERGONOMY) {
            return TestResult::Fail("NE4K missing ERGONOMY");
        }
        // Surface Dial — Bluetooth only.
        let sd = lookup(USB_VENDOR_ID_MICROSOFT, BT_DEVICE_ID_MS_SURFACE_DIAL, true);
        if sd.is_none() {
            return TestResult::Fail("Surface Dial missing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/microsoft", smoke_microsoft_device_table_size);

    // ── Smoke 2: NE4K / 1028 report-descriptor fix-up ──

    fn smoke_microsoft_1028_rdesc_fixup() -> TestResult {
        // Build a 571-byte descriptor with bad bytes at the right
        // offsets and verify the fix-up flips them.
        let mut rdesc = [0u8; MS_1028_RDESC_LEN];
        rdesc[557] = MS_1028_RDESC_BAD_AT_557;
        rdesc[559] = MS_1028_RDESC_BAD_AT_559;
        let applied = fixup_1028_rdesc(&mut rdesc);
        if !applied {
            return TestResult::Fail("fixup should have applied");
        }
        if rdesc[557] != MS_1028_RDESC_FIX_AT_557 {
            return TestResult::Fail("byte 557 not patched");
        }
        if rdesc[559] != MS_1028_RDESC_FIX_AT_559 {
            return TestResult::Fail("byte 559 not patched");
        }
        // Wrong length: no patch.
        let mut wrong_len = [0u8; 100];
        wrong_len[57] = MS_1028_RDESC_BAD_AT_557;
        if fixup_1028_rdesc(&mut wrong_len) {
            return TestResult::Fail("fixup should not apply to short descriptor");
        }
        // Right length but wrong bytes at offsets: no patch.
        let mut wrong_bytes = [0u8; MS_1028_RDESC_LEN];
        if fixup_1028_rdesc(&mut wrong_bytes) {
            return TestResult::Fail("fixup should not apply to non-matching bytes");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/microsoft", smoke_microsoft_1028_rdesc_fixup);

    // ── Smoke 3: ergonomy + presenter table lookups ──

    fn smoke_microsoft_ergo_presenter_lookup() -> TestResult {
        // KP_EQUAL alias.
        if ergo_usage_to_keycode(HID_UP_MSVENDOR, 0xff00) != Some(KeyCode::Equal) {
            return TestResult::Fail("KP_EQUAL → Equal mismatch");
        }
        // F13 alias.
        if ergo_usage_to_keycode(HID_UP_MSVENDOR, 0xff05) != Some(KeyCode::F10) {
            return TestResult::Fail("F13 → F10 mismatch");
        }
        // Office home — consumer-page.
        if ergo_usage_to_keycode(HID_UP_CONSUMER, 0x29D) != Some(KeyCode::PlayPause) {
            return TestResult::Fail("PROG1 → PlayPause mismatch");
        }
        // Wrong page: no match.
        if ergo_usage_to_keycode(HID_UP_GENDESK, 0xff00).is_some() {
            return TestResult::Fail("wrong page should miss");
        }
        // Presenter slide forward.
        if presenter_usage_to_keycode(0xfd08) != Some(KeyCode::NextSong) {
            return TestResult::Fail("FORWARD → NextSong mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/microsoft", smoke_microsoft_ergo_presenter_lookup);

    // ── Smoke 4: Surface Dial rotation event ──

    fn smoke_microsoft_surface_dial_rotation() -> TestResult {
        // 36-degree CW click + button not pressed.
        let report: &[u8] = &[0x01, 0x00, 0x24, 0x00, 0x00];
        let ev = match decode_surface_dial(report) {
            Some(e) => e,
            None => return TestResult::Fail("decode returned None"),
        };
        if ev.pressed {
            return TestResult::Fail("pressed should be false");
        }
        if ev.rotation != 0x0024 {
            return TestResult::Fail("rotation value wrong");
        }
        // CCW: signed negative.
        let report2: &[u8] = &[0x01, 0x00, 0xDC, 0xFF, 0x00];
        let ev2 = decode_surface_dial(report2).unwrap();
        if ev2.rotation != -0x24 {
            return TestResult::Fail("CCW rotation should be negative");
        }
        // Pressed.
        let report3: &[u8] = &[0x01, 0x01, 0x00, 0x00, 0x00];
        let ev3 = decode_surface_dial(report3).unwrap();
        if !ev3.pressed {
            return TestResult::Fail("pressed should be true");
        }
        // Short report: None.
        if decode_surface_dial(&[0x01, 0x00]).is_some() {
            return TestResult::Fail("short report should return None");
        }
        // Convert to pointer.
        let pe = surface_dial_to_pointer(ev);
        if pe.dx != 0x24 {
            return TestResult::Fail("PointerEvent dx mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/microsoft", smoke_microsoft_surface_dial_rotation);
}
