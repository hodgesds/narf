//! HID Usage Table 1.4 — selected page + usage constants.
//!
//! Only pages we actively decode get a name here; full coverage
//! lives in the spec PDF. Where a usage is referenced from multiple
//! consumers (e.g. Generic Desktop X / Y for both mouse and touch
//! pad), we declare it once.

#![allow(non_upper_case_globals, missing_docs)]

/// Generic Desktop Page (HID Usage Tables 1.4 §4).
pub mod generic_desktop {
    pub const PAGE: u16 = 0x01;
    pub const POINTER: u16 = 0x01;
    pub const MOUSE: u16 = 0x02;
    pub const KEYBOARD: u16 = 0x06;
    pub const X: u16 = 0x30;
    pub const Y: u16 = 0x31;
    pub const Z: u16 = 0x32;
    pub const WHEEL: u16 = 0x38;
}

/// Keyboard / Keypad Page (HID Usage Tables 1.4 §10).
pub mod keyboard {
    pub const PAGE: u16 = 0x07;
}

/// Button Page (HID Usage Tables 1.4 §12).
pub mod button {
    pub const PAGE: u16 = 0x09;
    /// Buttons are dense — Button N has usage id N.
    pub const PRIMARY: u16 = 0x01;
    pub const SECONDARY: u16 = 0x02;
    pub const TERTIARY: u16 = 0x03;
}

/// Digitizer Page (HID Usage Tables 1.4 §16). Used by precision
/// touchpads, touchscreens, and pen tablets.
pub mod digitizer {
    pub const PAGE: u16 = 0x0D;
    pub const DIGITIZER: u16 = 0x01;
    pub const PEN: u16 = 0x02;
    pub const TOUCH_SCREEN: u16 = 0x04;
    pub const TOUCH_PAD: u16 = 0x05;
    /// Configuration TLC top-level usage — used by the Microsoft
    /// Precision Touchpad Configuration collection for Device Mode.
    pub const CONFIGURATION: u16 = 0x0E;
    pub const FINGER: u16 = 0x22;
    pub const TIP_PRESSURE: u16 = 0x30;
    pub const IN_RANGE: u16 = 0x32;
    pub const TOUCH_VALID: u16 = 0x33;
    pub const TIP_SWITCH: u16 = 0x42;
    pub const CONTACT_ID: u16 = 0x51;
    pub const CONTACT_COUNT: u16 = 0x54;
    pub const CONTACT_COUNT_MAX: u16 = 0x55;
    pub const SCAN_TIME: u16 = 0x56;
    pub const BUTTON_TYPE: u16 = 0x59;
    pub const SECONDARY_BARREL_SWITCH: u16 = 0x5A;
    pub const DEVICE_MODE: u16 = 0x60;
    pub const DEVICE_IDENTIFIER: u16 = 0x53;
}

/// Consumer Page (HID Usage Tables 1.4 §15). Media keys, brightness,
/// volume.
pub mod consumer {
    pub const PAGE: u16 = 0x0C;
    pub const VOLUME_UP: u16 = 0xE9;
    pub const VOLUME_DOWN: u16 = 0xEA;
    pub const MUTE: u16 = 0xE2;
    pub const PLAY_PAUSE: u16 = 0xCD;
}
