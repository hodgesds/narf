//! Apple HID vendor quirks — clean-room.
//!
//! ## References
//!
//! - `drivers/hid/hid-apple.c` (Linux, GPL-2.0-or-later) — quirk
//!   flags, device table, Fn-key remapping. NARF is GPL-2.0-or-later
//!   as of 2026-05-20 so direct adaptation is permitted under the
//!   project's relicense policy.
//! - `drivers/hid/hid-ids.h` — USB / Bluetooth Vendor & Device IDs.
//! - USB-IF "HID Usage Tables" 1.4 — Keyboard / Consumer / Digitizer
//!   page numbers.
//!
//! ## Shape
//!
//! Apple keyboards differ from a standard PC layout in three ways:
//!
//! 1. **Fn key**. F1..F12 along the top of an Apple keyboard double
//!    as "fkey" (F-key) and "media" (brightness / volume / scrub).
//!    Without the Fn modifier the keys send the *media* usage; with
//!    Fn held they send the raw F-key. Macs let you flip this via a
//!    System Settings toggle — `fnmode = 1` is the default ("media
//!    when alone, F-key with Fn"); `fnmode = 2` reverses ("F-key when
//!    alone, media with Fn"). `fnmode = 0` disables the remap, which
//!    leaves the device's report unchanged. This is `apple_fn_keys[]`
//!    in `hid-apple.c:258`.
//!
//! 2. **ISO / JIS keyboard layout**. ISO Apple keyboards swap the
//!    Grave (`) and 102nd-key (\\ next to LeftShift) — Linux fixes
//!    this in `apple_iso_keyboard[]` at `hid-apple.c:322`. JIS layout
//!    needs a separate report-descriptor fix-up (`APPLE_RDESC_JIS`).
//!
//! 3. **Magic Mouse / Trackpad** touch surface. The mouse exposes a
//!    multi-touch digitizer report on top of the standard 3-byte
//!    Boot Mouse — pinch, scroll, swipe gestures come from the
//!    digitizer report rather than the wheel byte.
//!
//! 4. **Numpad equals** — US keyboards don't carry a `KP_EQUAL` so
//!    the numpad equals on Apple's keypad needs to emit `KEY_EQUAL`
//!    via the numlock emulation path. Linux drives this in
//!    `apple_setup_input` at `hid-apple.c:704`.
//!
//! Touch Bar (USB_DEVICE_ID_APPLE_TOUCHBAR_BACKLIGHT) is parked —
//! Linux's `apple_backlight_*` and `apple-ibridge` paths are a
//! separate 1500-line subdriver; we expose the device-ID row but
//! defer the actual TB rendering / DRM bridge.

#![allow(dead_code)]

use narf_input::KeyCode;

// ── Vendor / Device IDs (mirrors hid-ids.h) ────────────────────────

/// USB Vendor ID — Apple Inc. (`hid-ids.h:94`).
pub const USB_VENDOR_ID_APPLE: u16 = 0x05ac;
/// Bluetooth Vendor ID — Apple Inc. (`hid-ids.h:95`).
pub const BT_VENDOR_ID_APPLE: u16 = 0x004c;

// Pointing devices
pub const USB_DEVICE_ID_APPLE_MIGHTYMOUSE: u16 = 0x0304;
pub const USB_DEVICE_ID_APPLE_MAGICMOUSE: u16 = 0x030d;
pub const USB_DEVICE_ID_APPLE_MAGICMOUSE2: u16 = 0x0269;
pub const USB_DEVICE_ID_APPLE_MAGICMOUSE2_USBC: u16 = 0x0323;
pub const USB_DEVICE_ID_APPLE_MAGICTRACKPAD: u16 = 0x030e;
pub const USB_DEVICE_ID_APPLE_MAGICTRACKPAD2: u16 = 0x0265;
pub const USB_DEVICE_ID_APPLE_MAGICTRACKPAD2_USBC: u16 = 0x0324;

// Fountain / Geyser internal keyboards
pub const USB_DEVICE_ID_APPLE_FOUNTAIN_ANSI: u16 = 0x020e;
pub const USB_DEVICE_ID_APPLE_FOUNTAIN_ISO: u16 = 0x020f;
pub const USB_DEVICE_ID_APPLE_GEYSER_ANSI: u16 = 0x0214;
pub const USB_DEVICE_ID_APPLE_GEYSER_ISO: u16 = 0x0215;
pub const USB_DEVICE_ID_APPLE_GEYSER_JIS: u16 = 0x0216;
pub const USB_DEVICE_ID_APPLE_GEYSER3_ANSI: u16 = 0x0217;
pub const USB_DEVICE_ID_APPLE_GEYSER3_ISO: u16 = 0x0218;
pub const USB_DEVICE_ID_APPLE_GEYSER3_JIS: u16 = 0x0219;
pub const USB_DEVICE_ID_APPLE_GEYSER4_ANSI: u16 = 0x021a;
pub const USB_DEVICE_ID_APPLE_GEYSER4_ISO: u16 = 0x021b;
pub const USB_DEVICE_ID_APPLE_GEYSER4_JIS: u16 = 0x021c;

// Aluminium standalone keyboards
pub const USB_DEVICE_ID_APPLE_ALU_MINI_ANSI: u16 = 0x021d;
pub const USB_DEVICE_ID_APPLE_ALU_MINI_ISO: u16 = 0x021e;
pub const USB_DEVICE_ID_APPLE_ALU_MINI_JIS: u16 = 0x021f;
pub const USB_DEVICE_ID_APPLE_ALU_ANSI: u16 = 0x0220;
pub const USB_DEVICE_ID_APPLE_ALU_ISO: u16 = 0x0221;
pub const USB_DEVICE_ID_APPLE_ALU_JIS: u16 = 0x0222;
pub const USB_DEVICE_ID_APPLE_ALU_REVB_ANSI: u16 = 0x024f;
pub const USB_DEVICE_ID_APPLE_ALU_REVB_ISO: u16 = 0x0250;
pub const USB_DEVICE_ID_APPLE_ALU_REVB_JIS: u16 = 0x0251;

// Wireless aluminium keyboards
pub const USB_DEVICE_ID_APPLE_ALU_WIRELESS_ANSI: u16 = 0x022c;
pub const USB_DEVICE_ID_APPLE_ALU_WIRELESS_ISO: u16 = 0x022d;
pub const USB_DEVICE_ID_APPLE_ALU_WIRELESS_JIS: u16 = 0x022e;
pub const USB_DEVICE_ID_APPLE_ALU_WIRELESS_2009_ANSI: u16 = 0x0239;
pub const USB_DEVICE_ID_APPLE_ALU_WIRELESS_2009_ISO: u16 = 0x023a;
pub const USB_DEVICE_ID_APPLE_ALU_WIRELESS_2011_ANSI: u16 = 0x0255;
pub const USB_DEVICE_ID_APPLE_ALU_WIRELESS_2011_ISO: u16 = 0x0256;

// Magic Keyboards (2015 / 2021 / 2024)
pub const USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2015: u16 = 0x0267;
pub const USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_NUMPAD_2015: u16 = 0x026c;
pub const USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2021: u16 = 0x029c;
pub const USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_FINGERPRINT_2021: u16 = 0x029a;
pub const USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_NUMPAD_2021: u16 = 0x029f;
pub const USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2024: u16 = 0x0320;
pub const USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_FINGERPRINT_2024: u16 = 0x0321;
pub const USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_NUMPAD_2024: u16 = 0x0322;

// MacBook internal (Wellspring) keyboards
pub const USB_DEVICE_ID_APPLE_WELLSPRING_ANSI: u16 = 0x0223;
pub const USB_DEVICE_ID_APPLE_WELLSPRING2_ANSI: u16 = 0x0230;
pub const USB_DEVICE_ID_APPLE_WELLSPRING3_ANSI: u16 = 0x0236;
pub const USB_DEVICE_ID_APPLE_WELLSPRING4_ANSI: u16 = 0x023f;
pub const USB_DEVICE_ID_APPLE_WELLSPRING5_ANSI: u16 = 0x0245;
pub const USB_DEVICE_ID_APPLE_WELLSPRING6_ANSI: u16 = 0x024c;
pub const USB_DEVICE_ID_APPLE_WELLSPRING7_ANSI: u16 = 0x0262;
pub const USB_DEVICE_ID_APPLE_WELLSPRING8_ANSI: u16 = 0x0290;
pub const USB_DEVICE_ID_APPLE_WELLSPRING9_ANSI: u16 = 0x0272;
pub const USB_DEVICE_ID_APPLE_WELLSPRINGT2_J140K: u16 = 0x027a;
pub const USB_DEVICE_ID_APPLE_WELLSPRINGT2_J132: u16 = 0x027b;
pub const USB_DEVICE_ID_APPLE_WELLSPRINGT2_J680: u16 = 0x027c;
pub const USB_DEVICE_ID_APPLE_WELLSPRINGT2_J213: u16 = 0x027d;
pub const USB_DEVICE_ID_APPLE_WELLSPRINGT2_J214K: u16 = 0x027e;
pub const USB_DEVICE_ID_APPLE_WELLSPRINGT2_J223: u16 = 0x027f;

// Touch Bar
pub const USB_DEVICE_ID_APPLE_TOUCHBAR_BACKLIGHT: u16 = 0x8102;

// ── Quirk flags (mirrors hid-apple.c BIT() block at line 32) ──────

/// Per-device quirk bitmask. The constants below mirror
/// `hid-apple.c:32..45` 1:1 so the table reads against Linux.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AppleQuirks(pub u32);

impl AppleQuirks {
    /// JIS keyboard report-descriptor fix-up.
    pub const RDESC_JIS: Self = Self(1 << 0);
    /// Mighty Mouse — three-button mouse with a touch ball.
    pub const MIGHTYMOUSE: Self = Self(1 << 1);
    /// Device exposes an Fn key that the Fn-mode logic acts on.
    pub const HAS_FN: Self = Self(1 << 2);
    /// ISO Apple keyboard layout — swap Grave / 102nd.
    pub const ISO_TILDE_QUIRK: Self = Self(1 << 4);
    /// Mighty Mouse only — invert horizontal wheel direction.
    pub const INVERT_HWHEEL: Self = Self(1 << 6);
    /// Numpad emulation via the Fn modifier.
    pub const NUMLOCK_EMULATION: Self = Self(1 << 8);
    /// Report-descriptor patch to expose the battery feature.
    pub const RDESC_BATTERY: Self = Self(1 << 9);
    /// Backlight control via SET_FEATURE.
    pub const BACKLIGHT_CTL: Self = Self(1 << 10);
    /// Touch Bar backlight / control surface.
    pub const MAGIC_BACKLIGHT: Self = Self(1 << 12);
    /// Disable F-keys on certain Touch Bar Macs.
    pub const DISABLE_FKEYS: Self = Self(1 << 13);

    /// Empty bitmask — no quirks.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// `const`-friendly bitwise OR.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `true` if every bit in `other` is also set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// One row of the device match table — VID / PID / `is_bluetooth`
/// plus a quirk bitmask.
#[derive(Copy, Clone, Debug)]
pub struct AppleDeviceId {
    pub vid: u16,
    pub pid: u16,
    pub bluetooth: bool,
    pub quirks: AppleQuirks,
}

const fn usb(pid: u16, q: AppleQuirks) -> AppleDeviceId {
    AppleDeviceId {
        vid: USB_VENDOR_ID_APPLE,
        pid,
        bluetooth: false,
        quirks: q,
    }
}
const fn bt(pid: u16, q: AppleQuirks) -> AppleDeviceId {
    AppleDeviceId {
        vid: BT_VENDOR_ID_APPLE,
        pid,
        bluetooth: true,
        quirks: q,
    }
}
const fn bt_usbvid(pid: u16, q: AppleQuirks) -> AppleDeviceId {
    // Some Bluetooth Magic Keyboards use the USB vendor ID
    // (0x05ac) over BT; Linux carries both variants.
    AppleDeviceId {
        vid: USB_VENDOR_ID_APPLE,
        pid,
        bluetooth: true,
        quirks: q,
    }
}

const Q_NUM_FN: AppleQuirks = AppleQuirks::NUMLOCK_EMULATION.union(AppleQuirks::HAS_FN);
const Q_FN: AppleQuirks = AppleQuirks::HAS_FN;
const Q_FN_ISO: AppleQuirks = AppleQuirks::HAS_FN.union(AppleQuirks::ISO_TILDE_QUIRK);
const Q_FN_JIS: AppleQuirks = AppleQuirks::HAS_FN.union(AppleQuirks::RDESC_JIS);
const Q_NUM_FN_ISO: AppleQuirks = Q_NUM_FN.union(AppleQuirks::ISO_TILDE_QUIRK);
const Q_NUM_FN_JIS: AppleQuirks = Q_NUM_FN.union(AppleQuirks::RDESC_JIS);
const Q_MK_USB: AppleQuirks = Q_FN_ISO.union(AppleQuirks::RDESC_BATTERY);
const Q_TB_FN: AppleQuirks = Q_FN_ISO.union(AppleQuirks::BACKLIGHT_CTL);
const Q_TB_FN_DIS: AppleQuirks = Q_TB_FN.union(AppleQuirks::DISABLE_FKEYS);

/// Full device-match table — covers every Apple HID device the Linux
/// driver claims. Layout mirrors `apple_devices[]`
/// (`hid-apple.c:1002`). Both USB and Bluetooth attach paths consult
/// this table.
pub const APPLE_DEVICES: &[AppleDeviceId] = &[
    // Mighty Mouse — bus mouse, no Fn.
    usb(
        USB_DEVICE_ID_APPLE_MIGHTYMOUSE,
        AppleQuirks::MIGHTYMOUSE.union(AppleQuirks::INVERT_HWHEEL),
    ),
    // Fountain / Geyser internal laptop kbds — first-gen Wellspring.
    usb(USB_DEVICE_ID_APPLE_FOUNTAIN_ANSI, Q_NUM_FN),
    usb(USB_DEVICE_ID_APPLE_FOUNTAIN_ISO, Q_NUM_FN),
    usb(USB_DEVICE_ID_APPLE_GEYSER_ANSI, Q_NUM_FN),
    usb(USB_DEVICE_ID_APPLE_GEYSER_ISO, Q_NUM_FN),
    usb(USB_DEVICE_ID_APPLE_GEYSER_JIS, Q_NUM_FN),
    usb(USB_DEVICE_ID_APPLE_GEYSER3_ANSI, Q_NUM_FN),
    usb(USB_DEVICE_ID_APPLE_GEYSER3_ISO, Q_NUM_FN_ISO),
    usb(USB_DEVICE_ID_APPLE_GEYSER3_JIS, Q_NUM_FN_JIS),
    usb(USB_DEVICE_ID_APPLE_GEYSER4_ANSI, Q_NUM_FN),
    usb(USB_DEVICE_ID_APPLE_GEYSER4_ISO, Q_NUM_FN_ISO),
    usb(USB_DEVICE_ID_APPLE_GEYSER4_JIS, Q_NUM_FN_JIS),
    // Aluminium standalone (USB & BT).
    usb(USB_DEVICE_ID_APPLE_ALU_MINI_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_ALU_MINI_ISO, Q_FN),
    usb(USB_DEVICE_ID_APPLE_ALU_MINI_JIS, Q_FN),
    usb(USB_DEVICE_ID_APPLE_ALU_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_ALU_ISO, Q_FN),
    usb(USB_DEVICE_ID_APPLE_ALU_JIS, Q_FN),
    usb(USB_DEVICE_ID_APPLE_ALU_REVB_ANSI, Q_FN),
    bt_usbvid(USB_DEVICE_ID_APPLE_ALU_REVB_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_ALU_REVB_ISO, Q_FN),
    bt_usbvid(USB_DEVICE_ID_APPLE_ALU_REVB_ISO, Q_FN),
    usb(USB_DEVICE_ID_APPLE_ALU_REVB_JIS, Q_FN),
    // Wireless aluminium (Bluetooth).
    bt_usbvid(USB_DEVICE_ID_APPLE_ALU_WIRELESS_ANSI, Q_NUM_FN),
    bt_usbvid(USB_DEVICE_ID_APPLE_ALU_WIRELESS_ISO, Q_NUM_FN_ISO),
    bt_usbvid(USB_DEVICE_ID_APPLE_ALU_WIRELESS_2009_ANSI, Q_NUM_FN),
    bt_usbvid(USB_DEVICE_ID_APPLE_ALU_WIRELESS_2009_ISO, Q_NUM_FN_ISO),
    bt_usbvid(USB_DEVICE_ID_APPLE_ALU_WIRELESS_2011_ANSI, Q_NUM_FN),
    bt_usbvid(USB_DEVICE_ID_APPLE_ALU_WIRELESS_2011_ISO, Q_NUM_FN_ISO),
    // Magic Keyboards (USB + Bluetooth).
    usb(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2015, Q_MK_USB),
    bt(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2015, Q_FN_ISO),
    usb(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_NUMPAD_2015, Q_MK_USB),
    bt(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_NUMPAD_2015, Q_FN_ISO),
    usb(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2021, Q_MK_USB),
    bt(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2021, Q_FN_ISO),
    usb(
        USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_FINGERPRINT_2021,
        Q_MK_USB,
    ),
    usb(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_NUMPAD_2021, Q_MK_USB),
    usb(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2024, Q_MK_USB),
    usb(USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_NUMPAD_2024, Q_MK_USB),
    // Wellspring (MacBook Pro internal) — generations 1..9 + T2.
    usb(USB_DEVICE_ID_APPLE_WELLSPRING_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRING2_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRING3_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRING4_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRING5_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRING6_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRING7_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRING8_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRING9_ANSI, Q_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRINGT2_J140K, Q_TB_FN),
    usb(USB_DEVICE_ID_APPLE_WELLSPRINGT2_J132, Q_TB_FN_DIS),
    usb(USB_DEVICE_ID_APPLE_WELLSPRINGT2_J680, Q_TB_FN_DIS),
    usb(USB_DEVICE_ID_APPLE_WELLSPRINGT2_J213, Q_TB_FN_DIS),
    usb(
        USB_DEVICE_ID_APPLE_WELLSPRINGT2_J214K,
        Q_FN_ISO.union(AppleQuirks::DISABLE_FKEYS),
    ),
    usb(
        USB_DEVICE_ID_APPLE_WELLSPRINGT2_J223,
        Q_FN_ISO.union(AppleQuirks::DISABLE_FKEYS),
    ),
    // Touch surfaces.
    usb(USB_DEVICE_ID_APPLE_MAGICMOUSE, AppleQuirks::empty()),
    usb(USB_DEVICE_ID_APPLE_MAGICMOUSE2, AppleQuirks::empty()),
    usb(USB_DEVICE_ID_APPLE_MAGICMOUSE2_USBC, AppleQuirks::empty()),
    usb(USB_DEVICE_ID_APPLE_MAGICTRACKPAD, AppleQuirks::empty()),
    usb(USB_DEVICE_ID_APPLE_MAGICTRACKPAD2, AppleQuirks::empty()),
    usb(
        USB_DEVICE_ID_APPLE_MAGICTRACKPAD2_USBC,
        AppleQuirks::empty(),
    ),
    // Touch Bar backlight. Deferred — registered for ID only.
    usb(
        USB_DEVICE_ID_APPLE_TOUCHBAR_BACKLIGHT,
        AppleQuirks::MAGIC_BACKLIGHT,
    ),
];

/// Look up the device-table row for a (vid, pid, bluetooth) triple.
/// Returns `None` if the device isn't claimed by hid-apple.
pub fn lookup(vid: u16, pid: u16, bluetooth: bool) -> Option<&'static AppleDeviceId> {
    APPLE_DEVICES
        .iter()
        .find(|d| d.vid == vid && d.pid == pid && d.bluetooth == bluetooth)
}

// ── Fn key remapping ──────────────────────────────────────────────

/// Fn-mode setting — per-device toggle, applies to keyboards that
/// carry `HAS_FN`. Mirrors the `fnmode` sysctl knob in `hid-apple.c`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FnMode {
    /// No remap — keys pass through as the device sends them.
    Disabled = 0,
    /// Standard Mac mode: F-keys send their media equivalent without
    /// Fn, F-key with Fn held.
    MacStandard = 1,
    /// "Use F1..F12 as standard function keys" — flipped: F-keys
    /// send F-key without Fn, media equivalent with Fn held.
    Flipped = 2,
}

/// One row of the Fn-key remap table: when the device sends a raw
/// F-key (or arrow / Backspace / Enter), this maps it to the
/// alternate key that fires when Fn is in effect.
///
/// Mirrors `apple_fn_keys[]` at `hid-apple.c:258`.
#[derive(Copy, Clone, Debug)]
pub struct FnRemap {
    pub from: KeyCode,
    pub to: KeyCode,
    /// `true` if the row is for an F-key (F1..F12) — these are the
    /// codes that flip based on `FnMode`. Non-F-key rows (arrows /
    /// Backspace / Enter) only fire when Fn is held; they don't
    /// flip with mode.
    pub is_fkey: bool,
}

const fn r_fkey(from: KeyCode, to: KeyCode) -> FnRemap {
    FnRemap {
        from,
        to,
        is_fkey: true,
    }
}
const fn r_nav(from: KeyCode, to: KeyCode) -> FnRemap {
    FnRemap {
        from,
        to,
        is_fkey: false,
    }
}

/// Apple Mac Fn-key remap table — F1..F12 + arrow / Backspace / Enter.
/// Adapted from `apple_fn_keys[]` at `hid-apple.c:258`. NARF currently
/// lacks Scale / Dashboard / KbdIlluminationUp / KbdIlluminationDown
/// as distinct keycodes for F3/F4/F5/F6 — we map those to the closest
/// existing media keys (PlayPause as a launcher placeholder, the
/// kbd-illum-* set, BrightnessUp/Down) so the table still emits
/// useful events on the global ring.
pub const APPLE_FN_KEYS: &[FnRemap] = &[
    // Navigation cluster — fires only when Fn is held; the no-Fn
    // direction is the device's raw F-/arrow key.
    r_nav(KeyCode::Backspace, KeyCode::Delete),
    r_nav(KeyCode::Enter, KeyCode::Insert),
    r_nav(KeyCode::Up, KeyCode::PageUp),
    r_nav(KeyCode::Down, KeyCode::PageDown),
    r_nav(KeyCode::Left, KeyCode::Home),
    r_nav(KeyCode::Right, KeyCode::End),
    // F-key row — media when no Fn (default mode), raw F-key with Fn.
    r_fkey(KeyCode::F1, KeyCode::BrightnessDown),
    r_fkey(KeyCode::F2, KeyCode::BrightnessUp),
    r_fkey(KeyCode::F3, KeyCode::PlayPause),
    r_fkey(KeyCode::F4, KeyCode::PlayPause), // Dashboard → placeholder
    r_fkey(KeyCode::F5, KeyCode::KbdIlluminationDown),
    r_fkey(KeyCode::F6, KeyCode::KbdIlluminationUp),
    r_fkey(KeyCode::F7, KeyCode::PreviousSong),
    r_fkey(KeyCode::F8, KeyCode::PlayPause),
    r_fkey(KeyCode::F9, KeyCode::NextSong),
    r_fkey(KeyCode::F10, KeyCode::Mute),
    r_fkey(KeyCode::F11, KeyCode::VolumeDown),
    r_fkey(KeyCode::F12, KeyCode::VolumeUp),
];

/// ISO-layout Apple keyboard remap — swap Grave (`) and the 102nd
/// key (\\ next to LeftShift). Mirrors `apple_iso_keyboard[]`
/// at `hid-apple.c:322`. NARF uses `KeyCode::Backslash` (43) for the
/// 102nd key — it's the same Linux evdev code as `KEY_102ND` on most
/// ISO layouts.
pub const APPLE_ISO_KEYBOARD: &[(KeyCode, KeyCode)] = &[
    (KeyCode::Grave, KeyCode::Backslash),
    (KeyCode::Backslash, KeyCode::Grave),
];

/// Remap a raw keycode against the Fn-key table given the current
/// Fn-press state and the device's `FnMode` setting.
///
/// - `fn_held = false`, `mode = MacStandard`: F-keys translate to
///   their media equivalent (mac default — no Fn = media).
/// - `fn_held = true`,  `mode = MacStandard`: F-keys stay raw; nav
///   cluster (Backspace / Enter / arrows) translates.
/// - `fn_held = false`, `mode = Flipped`: F-keys stay raw.
/// - `fn_held = true`,  `mode = Flipped`: F-keys translate.
/// - `mode = Disabled`: no translation.
///
/// Non-F-key, non-nav-cluster codes pass through unchanged.
pub fn apply_fn_remap(code: KeyCode, fn_held: bool, mode: FnMode) -> KeyCode {
    if mode == FnMode::Disabled {
        return code;
    }
    for row in APPLE_FN_KEYS {
        if row.from != code {
            continue;
        }
        if row.is_fkey {
            // F-key remap toggles with the mode.
            let translate = match mode {
                FnMode::MacStandard => !fn_held,
                FnMode::Flipped => fn_held,
                FnMode::Disabled => false,
            };
            return if translate { row.to } else { code };
        } else {
            // Nav cluster only fires when Fn is actually held — mode
            // doesn't flip these (Backspace stays Backspace without
            // Fn regardless of fnmode).
            return if fn_held { row.to } else { code };
        }
    }
    code
}

/// Apply the ISO-layout Grave/102nd swap. No-op when the device
/// isn't tagged ISO_TILDE_QUIRK.
pub fn apply_iso_swap(code: KeyCode, iso: bool) -> KeyCode {
    if !iso {
        return code;
    }
    for &(from, to) in APPLE_ISO_KEYBOARD {
        if code == from {
            return to;
        }
    }
    code
}

// ── Numpad equals (Apple-specific) ─────────────────────────────────

/// Apple Magic Keyboard with Numeric Keypad carries a `KP_EQUAL` key
/// that US-layout PCs don't normally expose. The key arrives on HID
/// Usage Page 0x07 as 0x67 (KEYPAD =).  We translate it to
/// `KeyCode::Equal` (the `=` key on the main row) since NARF's input
/// codepage doesn't have a separate `KpEqual` discriminant.
///
/// Mirrors the `KEY_KPEQUAL` injection in `apple_input_configured`
/// at `hid-apple.c:704` (Linux carries a dedicated `KEY_KPEQUAL`).
pub fn numpad_equals_keycode() -> KeyCode {
    KeyCode::Equal
}

// ── Magic Mouse touch decode ──────────────────────────────────────

/// One contact on the Magic Mouse multi-touch surface. The Magic
/// Mouse exposes up to 16 simultaneous contacts on the cap touch
/// surface that sits on top of the standard mouse — drag-to-scroll,
/// pinch, and swipe gestures come from these readings.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct MagicMouseTouch {
    /// 0..15 — slot id of the contact within the report.
    pub id: u8,
    /// X position, 0..0xFFFF, normalised across the touch surface.
    pub x: i16,
    /// Y position, 0..0xFFFF.
    pub y: i16,
    /// Major axis radius (size of the touch ellipse).
    pub size: u8,
    /// Pressure / Z-value (0 = lift-off).
    pub pressure: u8,
}

/// Up to N contacts per report. Linux's `magicmouse_emit_touch`
/// caps at MAX_FINGERS=16 — we match that.
pub const MAGICMOUSE_MAX_TOUCHES: usize = 16;

/// Decode a Magic Mouse touch report. The wire format starts with
/// the report-ID byte (0x29 or 0x12 depending on FW), followed by a
/// 4-byte standard mouse prefix (button + dx + dy + reserved), then
/// a repeating 8-byte contact block until end-of-report.
///
/// The 8-byte contact format (little-endian) packs as:
///
/// ```text
///   byte 0..1 : X (signed, 13-bit, sign-extended)
///   byte 2..3 : Y (signed, 13-bit, sign-extended)
///   byte 4    : size (touch ellipse major axis)
///   byte 5    : id  (low nibble = slot 0..15)
///   byte 6    : pressure
///   byte 7    : status (bit 7 = touch active)
/// ```
///
/// Returns the number of valid contacts written into `out`. Caller
/// supplies a buffer of at least `MAGICMOUSE_MAX_TOUCHES` slots.
pub fn decode_magic_mouse_touches(report: &[u8], out: &mut [MagicMouseTouch]) -> usize {
    if report.len() < 5 {
        return 0;
    }
    // Skip report-ID byte + 4-byte mouse prefix.
    let body = &report[5..];
    let mut n = 0;
    for chunk in body.chunks_exact(8) {
        if n >= out.len() || n >= MAGICMOUSE_MAX_TOUCHES {
            break;
        }
        let active = chunk[7] & 0x80 != 0;
        if !active {
            continue;
        }
        out[n] = MagicMouseTouch {
            id: chunk[5] & 0x0F,
            x: i16::from_le_bytes([chunk[0], chunk[1]]),
            y: i16::from_le_bytes([chunk[2], chunk[3]]),
            size: chunk[4],
            pressure: chunk[6],
        };
        n += 1;
    }
    n
}

// ── Smokes ─────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Smoke 1: device table size + Magic Keyboard 2021 lookup ──

    fn smoke_apple_device_table_size() -> TestResult {
        if APPLE_DEVICES.len() < 30 {
            return TestResult::Fail("apple device table too short");
        }
        // Magic Keyboard 2021 (USB) must exist with HAS_FN.
        let mk = lookup(
            USB_VENDOR_ID_APPLE,
            USB_DEVICE_ID_APPLE_MAGIC_KEYBOARD_2021,
            false,
        );
        let row = match mk {
            Some(r) => r,
            None => return TestResult::Fail("Magic Keyboard 2021 missing"),
        };
        if !row.quirks.contains(AppleQuirks::HAS_FN) {
            return TestResult::Fail("Magic Keyboard 2021 missing HAS_FN");
        }
        if !row.quirks.contains(AppleQuirks::RDESC_BATTERY) {
            return TestResult::Fail("Magic Keyboard 2021 missing RDESC_BATTERY");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/apple", smoke_apple_device_table_size);

    // ── Smoke 2: F1 with fnmode=1, Fn not held → BrightnessDown ──

    fn smoke_apple_fn_remap_default_mode() -> TestResult {
        // Mac default: F1 alone → BrightnessDown.
        let got = apply_fn_remap(KeyCode::F1, false, FnMode::MacStandard);
        if got != KeyCode::BrightnessDown {
            return TestResult::Fail("F1 alone in MacStandard should map to BrightnessDown");
        }
        // F12 alone → VolumeUp.
        let got = apply_fn_remap(KeyCode::F12, false, FnMode::MacStandard);
        if got != KeyCode::VolumeUp {
            return TestResult::Fail("F12 alone in MacStandard should map to VolumeUp");
        }
        // Non-fkey keys pass through.
        let got = apply_fn_remap(KeyCode::A, false, FnMode::MacStandard);
        if got != KeyCode::A {
            return TestResult::Fail("A should pass through unchanged");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/apple", smoke_apple_fn_remap_default_mode);

    // ── Smoke 3: Fn+F1 with fnmode=1 → raw F1 ──

    fn smoke_apple_fn_remap_with_fn_held() -> TestResult {
        // With Fn held, F1 should stay F1 in MacStandard mode.
        let got = apply_fn_remap(KeyCode::F1, true, FnMode::MacStandard);
        if got != KeyCode::F1 {
            return TestResult::Fail("Fn+F1 should remain F1 in MacStandard");
        }
        // With Fn held in Flipped mode → BrightnessDown.
        let got = apply_fn_remap(KeyCode::F1, true, FnMode::Flipped);
        if got != KeyCode::BrightnessDown {
            return TestResult::Fail("Fn+F1 in Flipped should map to BrightnessDown");
        }
        // Fn+Up → PageUp regardless of mode.
        let got = apply_fn_remap(KeyCode::Up, true, FnMode::MacStandard);
        if got != KeyCode::PageUp {
            return TestResult::Fail("Fn+Up should map to PageUp");
        }
        // Fn+Backspace → Delete.
        let got = apply_fn_remap(KeyCode::Backspace, true, FnMode::MacStandard);
        if got != KeyCode::Delete {
            return TestResult::Fail("Fn+Backspace should map to Delete");
        }
        // Disabled mode: nothing translates.
        let got = apply_fn_remap(KeyCode::F1, false, FnMode::Disabled);
        if got != KeyCode::F1 {
            return TestResult::Fail("Disabled mode should not translate F1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/apple", smoke_apple_fn_remap_with_fn_held);

    // ── Smoke 4: ISO Grave/102nd swap ──

    fn smoke_apple_iso_swap() -> TestResult {
        let got = apply_iso_swap(KeyCode::Grave, true);
        if got != KeyCode::Backslash {
            return TestResult::Fail("ISO Grave should map to Backslash");
        }
        let got = apply_iso_swap(KeyCode::Backslash, true);
        if got != KeyCode::Grave {
            return TestResult::Fail("ISO Backslash should map to Grave");
        }
        let got = apply_iso_swap(KeyCode::A, true);
        if got != KeyCode::A {
            return TestResult::Fail("ISO A should pass through");
        }
        // Non-ISO devices: no swap.
        let got = apply_iso_swap(KeyCode::Grave, false);
        if got != KeyCode::Grave {
            return TestResult::Fail("Non-ISO Grave should not swap");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/apple", smoke_apple_iso_swap);

    // ── Smoke 5: Magic Mouse touch decode ──

    fn smoke_apple_magic_mouse_touch_decode() -> TestResult {
        // Build a synthetic Magic Mouse report with one active contact.
        // Bytes: [ID=0x29] [btn=0] [dx=0] [dy=0] [reserved=0]
        //        contact: X=0x0100, Y=0x0080, size=0x40, id=0x03,
        //                 pressure=0x7F, status=0x80 (active)
        let report: &[u8] = &[
            0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x40, 0x03, 0x7F, 0x80,
        ];
        let mut touches = [MagicMouseTouch::default(); MAGICMOUSE_MAX_TOUCHES];
        let n = decode_magic_mouse_touches(report, &mut touches);
        if n != 1 {
            return TestResult::Fail("expected exactly one active contact");
        }
        if touches[0].id != 3 {
            return TestResult::Fail("contact id wrong");
        }
        if touches[0].x != 0x0100 {
            return TestResult::Fail("contact X wrong");
        }
        if touches[0].y != 0x0080 {
            return TestResult::Fail("contact Y wrong");
        }
        if touches[0].pressure != 0x7F {
            return TestResult::Fail("contact pressure wrong");
        }
        // Inactive contact (status bit 7 cleared) should be skipped.
        let report2: &[u8] = &[
            0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x40, 0x03, 0x7F, 0x00,
        ];
        let n = decode_magic_mouse_touches(report2, &mut touches);
        if n != 0 {
            return TestResult::Fail("inactive contact should be dropped");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/apple",
        smoke_apple_magic_mouse_touch_decode
    );

    // ── Smoke 6: numpad equals ──

    fn smoke_apple_numpad_equals() -> TestResult {
        if numpad_equals_keycode() != KeyCode::Equal {
            return TestResult::Fail("numpad equals should map to KeyCode::Equal");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/apple", smoke_apple_numpad_equals);
}
