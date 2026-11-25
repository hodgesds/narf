//! US-QWERTY key-to-ASCII translation, shared by the console line
//! discipline (`filesystem::console_tty`) and the boot credential prompt.
//!
//! Caps Lock inverts Shift for letters only, as Linux's default US keymap
//! does: `kbd_keycode` (`drivers/tty/vt/keyboard.c`) flips the shift map
//! under Caps Lock only for `KT_LETTER` keysyms, and the default map
//! (`defkeymap.map`) gives digits and punctuation `KT_LATIN`. Other
//! layouts are not loaded (`/etc/vconsole.conf` is not read).

use crate::{KeyCode, Modifiers};

/// Translate one key (with the live modifier state) into one ASCII byte.
/// `None` for keys with no ASCII meaning: modifiers, function keys, the
/// navigation cluster. Enter gives `\n`, Backspace `0x7f` (DEL, as the
/// Linux console sends it), Escape `0x1b`.
pub fn key_to_ascii(code: KeyCode, mods: Modifiers) -> Option<u8> {
    use KeyCode as K;
    let shift = mods.contains(Modifiers::SHIFT);
    let letter = |c: u8| {
        if shift ^ mods.contains(Modifiers::CAPS_LOCK) {
            c.to_ascii_uppercase()
        } else {
            c
        }
    };
    let pick = |plain: u8, shifted: u8| if shift { shifted } else { plain };
    Some(match code {
        K::A => letter(b'a'),
        K::B => letter(b'b'),
        K::C => letter(b'c'),
        K::D => letter(b'd'),
        K::E => letter(b'e'),
        K::F => letter(b'f'),
        K::G => letter(b'g'),
        K::H => letter(b'h'),
        K::I => letter(b'i'),
        K::J => letter(b'j'),
        K::K => letter(b'k'),
        K::L => letter(b'l'),
        K::M => letter(b'm'),
        K::N => letter(b'n'),
        K::O => letter(b'o'),
        K::P => letter(b'p'),
        K::Q => letter(b'q'),
        K::R => letter(b'r'),
        K::S => letter(b's'),
        K::T => letter(b't'),
        K::U => letter(b'u'),
        K::V => letter(b'v'),
        K::W => letter(b'w'),
        K::X => letter(b'x'),
        K::Y => letter(b'y'),
        K::Z => letter(b'z'),
        K::Key0 => pick(b'0', b')'),
        K::Key1 => pick(b'1', b'!'),
        K::Key2 => pick(b'2', b'@'),
        K::Key3 => pick(b'3', b'#'),
        K::Key4 => pick(b'4', b'$'),
        K::Key5 => pick(b'5', b'%'),
        K::Key6 => pick(b'6', b'^'),
        K::Key7 => pick(b'7', b'&'),
        K::Key8 => pick(b'8', b'*'),
        K::Key9 => pick(b'9', b'('),
        K::Space => b' ',
        K::Enter | K::KpEnter => b'\n',
        K::Tab => b'\t',
        K::Backspace => 0x7F,
        K::Escape => 0x1B,
        K::Minus => pick(b'-', b'_'),
        K::Equal => pick(b'=', b'+'),
        K::LeftBrace => pick(b'[', b'{'),
        K::RightBrace => pick(b']', b'}'),
        K::Backslash => pick(b'\\', b'|'),
        K::Semicolon => pick(b';', b':'),
        K::Apostrophe => pick(b'\'', b'"'),
        K::Grave => pick(b'`', b'~'),
        K::Comma => pick(b',', b'<'),
        K::Dot => pick(b'.', b'>'),
        K::Slash => pick(b'/', b'?'),
        _ => return None,
    })
}
