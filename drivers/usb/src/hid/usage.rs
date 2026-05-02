//! HID Usage Page 0x07 (Keyboard / Keypad) → `narf_input::KeyCode`.
//!
//! Reference: "Universal Serial Bus HID Usage Tables" 1.4, §10
//! ("Keyboard / Keypad Page 0x07"). The first column of each row is
//! the Usage ID firmware writes into a boot-keyboard report; the
//! second column is the kernel's `KeyCode` for that physical key.
//!
//! Coverage: every Usage ID a HID-class keyboard is required to
//! emit in Boot Protocol mode (§B.1) — letters, digits, modifiers,
//! the navigation cluster (Insert / Delete / Home / End / PageUp /
//! PageDown), arrows, F1-F12, full numpad, and the GUI / Application
//! keys most modern keyboards expose. Out-of-table Usage IDs return
//! `KeyCode::Unknown` so the caller can still emit press / release
//! events without dropping the input.

use narf_input::KeyCode;

/// Translate a single HID Usage Page 0x07 ID into a `KeyCode`.
/// Returns `KeyCode::Unknown` for IDs the kernel does not yet
/// route — those still produce events on the global ring so a
/// userspace consumer can decide what to do.
pub const fn usage_to_keycode(usage: u8) -> KeyCode {
    match usage {
        // 0x00 (no event) and 0x01..=0x03 (error roll-over / post-fail
        // / undefined) are not key presses; callers filter them out.
        0x04 => KeyCode::A,
        0x05 => KeyCode::B,
        0x06 => KeyCode::C,
        0x07 => KeyCode::D,
        0x08 => KeyCode::E,
        0x09 => KeyCode::F,
        0x0A => KeyCode::G,
        0x0B => KeyCode::H,
        0x0C => KeyCode::I,
        0x0D => KeyCode::J,
        0x0E => KeyCode::K,
        0x0F => KeyCode::L,
        0x10 => KeyCode::M,
        0x11 => KeyCode::N,
        0x12 => KeyCode::O,
        0x13 => KeyCode::P,
        0x14 => KeyCode::Q,
        0x15 => KeyCode::R,
        0x16 => KeyCode::S,
        0x17 => KeyCode::T,
        0x18 => KeyCode::U,
        0x19 => KeyCode::V,
        0x1A => KeyCode::W,
        0x1B => KeyCode::X,
        0x1C => KeyCode::Y,
        0x1D => KeyCode::Z,

        0x1E => KeyCode::Key1,
        0x1F => KeyCode::Key2,
        0x20 => KeyCode::Key3,
        0x21 => KeyCode::Key4,
        0x22 => KeyCode::Key5,
        0x23 => KeyCode::Key6,
        0x24 => KeyCode::Key7,
        0x25 => KeyCode::Key8,
        0x26 => KeyCode::Key9,
        0x27 => KeyCode::Key0,

        0x28 => KeyCode::Enter,
        0x29 => KeyCode::Escape,
        0x2A => KeyCode::Backspace,
        0x2B => KeyCode::Tab,
        0x2C => KeyCode::Space,
        0x2D => KeyCode::Minus,
        0x2E => KeyCode::Equal,
        0x2F => KeyCode::LeftBrace,
        0x30 => KeyCode::RightBrace,
        0x31 => KeyCode::Backslash,
        // 0x32 (non-US #) maps to Backslash on US layouts.
        0x32 => KeyCode::Backslash,
        0x33 => KeyCode::Semicolon,
        0x34 => KeyCode::Apostrophe,
        0x35 => KeyCode::Grave,
        0x36 => KeyCode::Comma,
        0x37 => KeyCode::Dot,
        0x38 => KeyCode::Slash,
        0x39 => KeyCode::CapsLock,

        0x3A => KeyCode::F1,
        0x3B => KeyCode::F2,
        0x3C => KeyCode::F3,
        0x3D => KeyCode::F4,
        0x3E => KeyCode::F5,
        0x3F => KeyCode::F6,
        0x40 => KeyCode::F7,
        0x41 => KeyCode::F8,
        0x42 => KeyCode::F9,
        0x43 => KeyCode::F10,
        0x44 => KeyCode::F11,
        0x45 => KeyCode::F12,

        0x46 => KeyCode::SysRq,       // PrintScreen
        0x47 => KeyCode::ScrollLock,
        0x48 => KeyCode::Pause,
        0x49 => KeyCode::Insert,
        0x4A => KeyCode::Home,
        0x4B => KeyCode::PageUp,
        0x4C => KeyCode::Delete,
        0x4D => KeyCode::End,
        0x4E => KeyCode::PageDown,
        0x4F => KeyCode::Right,
        0x50 => KeyCode::Left,
        0x51 => KeyCode::Down,
        0x52 => KeyCode::Up,

        0x53 => KeyCode::NumLock,
        0x54 => KeyCode::KpSlash,
        0x55 => KeyCode::KpAsterisk,
        0x56 => KeyCode::KpMinus,
        0x57 => KeyCode::KpPlus,
        0x58 => KeyCode::KpEnter,
        0x59 => KeyCode::Kp1,
        0x5A => KeyCode::Kp2,
        0x5B => KeyCode::Kp3,
        0x5C => KeyCode::Kp4,
        0x5D => KeyCode::Kp5,
        0x5E => KeyCode::Kp6,
        0x5F => KeyCode::Kp7,
        0x60 => KeyCode::Kp8,
        0x61 => KeyCode::Kp9,
        0x62 => KeyCode::Kp0,
        0x63 => KeyCode::KpDot,

        // 0x64 (non-US \) maps to Backslash on US layouts.
        0x64 => KeyCode::Backslash,
        0x65 => KeyCode::Menu,        // Application / Compose

        // 0xE0..=0xE7 are the modifier-byte equivalents — the boot
        // report already exposes them as the modifier mask, so no
        // translation needed here. They appear in the keys array
        // only on weird firmware and we still hand back a KeyCode
        // so press / release flow uniformly.
        0xE0 => KeyCode::LeftCtrl,
        0xE1 => KeyCode::LeftShift,
        0xE2 => KeyCode::LeftAlt,
        0xE3 => KeyCode::LeftMeta,
        0xE4 => KeyCode::RightCtrl,
        0xE5 => KeyCode::RightShift,
        0xE6 => KeyCode::RightAlt,
        0xE7 => KeyCode::RightMeta,

        _ => KeyCode::Unknown,
    }
}
