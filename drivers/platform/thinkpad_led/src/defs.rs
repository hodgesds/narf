//! Shared LED definitions for the ThinkPad LED driver (both builds).
//!
//! The seven LEDs, their Linux names, maxima, and default triggers,
//! plus the AML path literals and the HKEY HID table. No kernel
//! dependencies: both the builtin backend (AML direct) and the module
//! backend (AML through the KABI quad stream) read this file.
//!
//! DSDT-UNVERIFIED: every path literal below is copied verbatim from
//! lane 2's `drivers/platform/src/thinkpad_acpi.rs` and has NOT been
//! verified against the P14s DSDT yet — the HKEY device may sit
//! elsewhere than under the EC, and the EC path itself varies by
//! machine (`LPCB` vs `LPC`, `EC` vs `EC0`). Do not submit a PR with
//! these literals until the DSDT confirms them (tracker #2448,
//! mechanism record §5). The builtin copy lives here now (moved from
//! `thinkpad_acpi.rs` in lane 6 so the platform facade can depend on
//! this crate without a cycle); the module build cannot depend on
//! `drivers/platform`, so this is the single home for both builds.

/// HKEY device path — DSDT-UNVERIFIED (see above).
pub const HKEY_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY";

/// EC device path — DSDT-UNVERIFIED (see above).
pub const EC_PATH: &str = r"\_SB.PCI0.LPCB.EC";

/// HKEY `MLCS` (kbdlight set) — DSDT-UNVERIFIED.
pub const HKEY_MLCS_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY.MLCS";

/// HKEY `MLCG` (kbdlight get / support probe) — DSDT-UNVERIFIED.
pub const HKEY_MLCG_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY.MLCG";

/// HKEY `SSMS` (speaker-mute LED) — DSDT-UNVERIFIED.
pub const HKEY_SSMS_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY.SSMS";

/// HKEY `MMTS` (mic-mute LED) — DSDT-UNVERIFIED.
pub const HKEY_MMTS_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY.MMTS";

/// EC `LED` object (generic LEDs) — DSDT-UNVERIFIED.
pub const EC_LED_PATH: &str = r"\_SB.PCI0.LPCB.EC.LED";

/// HKEY HID table (`thinkpad_acpi.c::tpacpi_acpi_driver_init`):
/// `LEN0268` (newer, post-2010), `IBM0068` (older, pre-2010),
/// `LEN0018` (some ultrabooks).
pub const HID_TABLE: [&str; 3] = ["LEN0268", "IBM0068", "LEN0018"];

/// The HID table as one NUL-separated buffer, for the module
/// build's `narf_register_acpi_driver` call. A multi-string buffer,
/// not a single C string — the byte-string form is the correct one
/// here. Its contents must match [`HID_TABLE`] (checked by the
/// `hids_buffer_matches_table` test).
pub const HIDS: &[u8] = b"LEN0268\0IBM0068\0LEN0018\0";

/// EC HID (`PNP0C09`) — the module backend discovers the EC through
/// it (`narf_acpi_find_devices_by_hid`) to confirm the machine has
/// an EC before registering LEDs.
pub const EC_HID: &str = "PNP0C09";

/// HKEY mic-mute notify value (`HKEY_MIC_MUTE_LED`,
/// `thinkpad_acpi.c`): firmware says the mic-mute LED may be out of
/// sync — the driver re-asserts the last mic-mute state.
pub const MICMUTE_NOTIFY: u64 = 0x60C0;

/// Linux `TPACPI_SAFE_LEDS` (`thinkpad_acpi.c:5611`, 0x1481) —
/// bits {0, 7, 10, 12}. Every other generic-LED index is
/// restricted by default and needs the unsafe-LEDs policy decision
/// (audit Q6) before it is exposed.
pub const SAFE_GENERIC_LEDS: u16 = 0x1481;

/// Keyboard-backlight classdev max (`tpacpi_led_kbdlight`,
/// `thinkpad_acpi.c:5200`): levels 0-2. Whether the P14s 8840
/// uses 0-1 or 0-2 is DSDT-dependent (mechanism record §5.7).
pub const KBDLIGHT_MAX_LEVEL: u8 = 2;

/// Which of the three Linux mechanisms drives a LED (lane 1
/// re-derivation: the old `ThinkpadLed` mixed all three into one
/// index space — 5 of 6 wrong — and is deleted, not repaired).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LedKind {
    /// Keyboard backlight via `MLCS`/`MLCG`, level `u8` 0-2.
    Kbdlight,
    /// Speaker-mute LED via `SSMS(1)`/`SSMS(0)`, `bool`.
    Mute,
    /// Mic-mute LED via `MMTS(2)`/`MMTS(0)`, `bool`.
    MicMute,
    /// A Linux-safe generic LED under the EC `LED` object, by
    /// index (only the four `TPACPI_SAFE_LEDS` indices).
    Generic(u8),
}

/// One LED the driver registers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LedDef {
    /// Linux sysfs name (`tpacpi_led_names[16]`, `platform::mute`,
    /// `platform::micmute`).
    pub name: &'static str,
    /// Classdev max brightness.
    pub max_brightness: u32,
    /// Trigger the LED wants by default (`None` = none). Applied
    /// through the LED core's default-trigger map, so a trigger
    /// that loads after the LED driver still resolves.
    pub default_trigger: Option<&'static str>,
    /// Which mechanism drives it.
    pub kind: LedKind,
}

/// The seven LEDs, in cookie order: the LED's index in this table
/// is the cookie its `set_brightness` / `get_brightness` callbacks
/// receive, in both builds.
pub const LED_DEFS: &[LedDef] = &[
    LedDef {
        name: "tpacpi::kbd_backlight",
        max_brightness: KBDLIGHT_MAX_LEVEL as u32,
        default_trigger: None,
        kind: LedKind::Kbdlight,
    },
    LedDef {
        name: "platform::mute",
        max_brightness: 1,
        default_trigger: Some("audio-mute"),
        kind: LedKind::Mute,
    },
    LedDef {
        name: "platform::micmute",
        max_brightness: 1,
        default_trigger: Some("audio-micmute"),
        kind: LedKind::MicMute,
    },
    LedDef {
        name: "tpacpi::power",
        max_brightness: 1,
        default_trigger: None,
        kind: LedKind::Generic(0),
    },
    LedDef {
        name: "tpacpi::standby",
        max_brightness: 1,
        default_trigger: None,
        kind: LedKind::Generic(7),
    },
    LedDef {
        name: "tpacpi::lid_logo_dot",
        max_brightness: 1,
        default_trigger: None,
        kind: LedKind::Generic(10),
    },
    LedDef {
        name: "tpacpi::thinkvantage",
        max_brightness: 1,
        default_trigger: None,
        kind: LedKind::Generic(12),
    },
];

/// Index of the kbdlight def in [`LED_DEFS`].
pub const KBD_IDX: usize = 0;
/// Index of the speaker-mute def in [`LED_DEFS`].
pub const MUTE_IDX: usize = 1;
/// Index of the mic-mute def in [`LED_DEFS`].
pub const MICMUTE_IDX: usize = 2;

/// A Linux-safe generic LED under the EC `LED` object.
/// Reference: `tpacpi_led_names[16]` (`thinkpad_acpi.c:5595-5608`);
/// only the four `TPACPI_SAFE_LEDS` indices are constructible.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GenericLed {
    /// `tpacpi::power` — index 0.
    Power = 0,
    /// `tpacpi::standby` — index 7.
    Standby = 7,
    /// `tpacpi::lid_logo_dot` — index 10.
    LidLogoDot = 10,
    /// `tpacpi::thinkvantage` — index 12.
    ThinkVantage = 12,
}

impl GenericLed {
    /// The generic-LED index this LED is addressed by.
    pub const fn index(self) -> u8 {
        self as u8
    }

    /// The Linux sysfs name (`tpacpi_led_names[16]`).
    pub const fn linux_name(self) -> &'static str {
        match self {
            GenericLed::Power => "tpacpi::power",
            GenericLed::Standby => "tpacpi::standby",
            GenericLed::LidLogoDot => "tpacpi::lid_logo_dot",
            GenericLed::ThinkVantage => "tpacpi::thinkvantage",
        }
    }

    /// Map a raw generic-LED index to the safe LED, if it is one of
    /// the four `TPACPI_SAFE_LEDS` indices. Restricted indices
    /// (battery 1/2, dock/bay 3/4/5/8/9, unknown 6/11/13-15)
    /// return `None`.
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(GenericLed::Power),
            7 => Some(GenericLed::Standby),
            10 => Some(GenericLed::LidLogoDot),
            12 => Some(GenericLed::ThinkVantage),
            _ => None,
        }
    }
}
