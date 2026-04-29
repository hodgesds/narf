//! i8042 PS/2 keyboard driver (x86_64).
//!
//! Surface:
//!
//!   * `port 0x60` — data (read scancode, write commands to the
//!     keyboard or the controller depending on prior 0x64 byte).
//!   * `port 0x64` — status (read) / command (write).
//!   * `IRQ 1`     — keyboard event.
//!
//! Initialisation sequence (after Linux + Minix references):
//!   1. Disable kbd + AUX channels (so spurious data doesn't race init).
//!   2. Flush output buffer.
//!   3. Read controller config byte — clear "translation" so we get
//!      raw scancode-set-1, disable IRQs while we're configuring.
//!   4. Self-test the controller (cmd 0xAA → expect 0x55).
//!   5. Enable kbd channel + IRQ 1.
//!   6. Reset keyboard (data 0xFF → expect 0xFA + 0xAA), set scancode
//!      set 1 (data 0xF0 0x01 → 0xFA), enable scanning (data 0xF4 →
//!      0xFA).
//!
//! The IRQ handler is the simple part: read 0x60, decode, push.
//!
//! Scancode-set-1 lookup. The controller delivers two byte sequences:
//!   * Single byte: top bit = release (0x80), low bits = make code.
//!   * Two-byte extended: 0xE0 prefix + make/release.
//!
//! The driver tracks a small bit of state across IRQs (the "expecting
//! the second byte of an E0 escape" flag) and a bitset of currently
//! pressed modifier keys to stamp on every event.

use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use narf_input::{InputEvent, KeyCode, KeyEvent, Modifiers, push_global};
use narf_arch::x86_64::io_port::{inb, outb};

/// I/O ports.
pub const PS2_DATA:   u16 = 0x60;
pub const PS2_STATUS: u16 = 0x64;
pub const PS2_CMD:    u16 = 0x64;

/// Controller-status bits (read from port 0x64).
const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL:  u8 = 1 << 1;

/// Controller commands (write to port 0x64).
const CMD_DISABLE_KBD:    u8 = 0xAD;
const CMD_DISABLE_AUX:    u8 = 0xA7;
const CMD_ENABLE_KBD:     u8 = 0xAE;
const CMD_READ_CONFIG:    u8 = 0x20;
const CMD_WRITE_CONFIG:   u8 = 0x60;
const CMD_SELF_TEST:      u8 = 0xAA;

/// Config-byte bits.
const CONF_KBD_IRQ:       u8 = 1 << 0;
const CONF_AUX_IRQ:       u8 = 1 << 1;
const CONF_KBD_DISABLE:   u8 = 1 << 4;
const CONF_KBD_TRANSLATE: u8 = 1 << 6;

/// Driver state. Only one i8042 controller per system — global static.
#[derive(Debug)]
pub struct State {
    /// True after the next byte should be interpreted as the second
    /// half of an E0 escape sequence.
    extended:    AtomicBool,
    modifiers:   AtomicU16,
    initialized: AtomicBool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            extended:    AtomicBool::new(false),
            modifiers:   AtomicU16::new(0),
            initialized: AtomicBool::new(false),
        }
    }
}

/// Singleton driver state.
pub static STATE: State = State::new();

/// Errors from `init`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InitError {
    SelfTestFailed,
    KeyboardResetFailed,
    Timeout,
}

/// Spin bound for hot-path waits (controller config, self-test).
/// QEMU responds within a few iterations; bare metal is similar.
const HOT_SPINS: u32 = 10_000;
/// Spin bound for best-effort waits (keyboard reset / scancode-set
/// programming) where the keyboard may not be wired up at all (USB-only
/// system, virtio-keyboard front-end). Kept small so init failure
/// doesn't add visible latency to boot.
const COLD_SPINS: u32 = 2_000;

/// Block until the controller's input buffer is empty (so a subsequent
/// command write won't be discarded).
fn wait_input_clear() -> Result<(), InitError> {
    for _ in 0..HOT_SPINS {
        // SAFETY: I/O port read at CPL=0 is always defined; 0x64 is
        // the i8042 status register.
        if unsafe { inb(PS2_STATUS) } & STATUS_INPUT_FULL == 0 {
            return Ok(());
        }
    }
    Err(InitError::Timeout)
}

/// Block until the controller's output buffer has data; returns it.
fn wait_output_byte() -> Result<u8, InitError> {
    for _ in 0..HOT_SPINS {
        // SAFETY: same as wait_input_clear.
        if unsafe { inb(PS2_STATUS) } & STATUS_OUTPUT_FULL != 0 {
            // SAFETY: data port at CPL=0 is always defined.
            return Ok(unsafe { inb(PS2_DATA) });
        }
    }
    Err(InitError::Timeout)
}

/// Same as `wait_output_byte` but with a smaller spin bound for
/// best-effort steps where a missing reply just means "this
/// keyboard isn't there" — we don't want to add boot latency
/// hunting for a device that won't answer.
fn wait_output_byte_short() -> Option<u8> {
    for _ in 0..COLD_SPINS {
        // SAFETY: status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_OUTPUT_FULL != 0 {
            // SAFETY: data port read.
            return Some(unsafe { inb(PS2_DATA) });
        }
    }
    None
}

fn wait_input_clear_short() -> bool {
    for _ in 0..COLD_SPINS {
        // SAFETY: status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_INPUT_FULL == 0 {
            return true;
        }
    }
    false
}

fn flush_output() {
    for _ in 0..32 {
        // SAFETY: status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_OUTPUT_FULL == 0 { return; }
        // SAFETY: read + discard.
        let _ = unsafe { inb(PS2_DATA) };
    }
}

/// Initialise the controller and the keyboard. Returns `Ok` once the
/// keyboard is enabled + scanning. Idempotent.
///
/// # Safety
/// Caller must ensure no other agent is concurrently driving the
/// 8042 ports (BSP-only at boot time satisfies this).
pub unsafe fn init() -> Result<(), InitError> {
    if STATE.initialized.load(Ordering::Acquire) { return Ok(()); }

    // 1. Disable channels so init bytes don't race with stray scancodes.
    wait_input_clear()?;
    // SAFETY: 0x64 is the cmd port.
    unsafe { outb(PS2_CMD, CMD_DISABLE_KBD); }
    wait_input_clear()?;
    unsafe { outb(PS2_CMD, CMD_DISABLE_AUX); }

    // 2. Drain anything pending.
    flush_output();

    // 3. Read the config byte, clear translate + IRQs while we configure.
    wait_input_clear()?;
    unsafe { outb(PS2_CMD, CMD_READ_CONFIG); }
    let mut conf = wait_output_byte()?;
    conf &= !(CONF_KBD_TRANSLATE | CONF_KBD_IRQ | CONF_AUX_IRQ);
    wait_input_clear()?;
    unsafe { outb(PS2_CMD, CMD_WRITE_CONFIG); }
    wait_input_clear()?;
    unsafe { outb(PS2_DATA, conf); }

    // 4. Self-test.
    wait_input_clear()?;
    unsafe { outb(PS2_CMD, CMD_SELF_TEST); }
    let st = wait_output_byte()?;
    if st != 0x55 { return Err(InitError::SelfTestFailed); }

    // 5. Re-enable the keyboard channel + arm IRQ 1.
    wait_input_clear()?;
    unsafe { outb(PS2_CMD, CMD_ENABLE_KBD); }
    // Re-read config (self-test may have reset it on some chips), set IRQ.
    wait_input_clear()?;
    unsafe { outb(PS2_CMD, CMD_READ_CONFIG); }
    let mut conf2 = wait_output_byte()?;
    conf2 |= CONF_KBD_IRQ;
    conf2 &= !CONF_KBD_DISABLE;
    conf2 &= !CONF_KBD_TRANSLATE;
    wait_input_clear()?;
    unsafe { outb(PS2_CMD, CMD_WRITE_CONFIG); }
    wait_input_clear()?;
    unsafe { outb(PS2_DATA, conf2); }

    // 6. Keyboard reset / scancode-set / enable scanning. ALL of
    //    this is best-effort — a USB-only or virtio-input-only
    //    system has no PS/2 keyboard wired to the i8042, and we
    //    don't want to spend tens of milliseconds polling for
    //    replies that never arrive. Use the short bounds.
    let _ = wait_input_clear_short();
    // SAFETY: data port write.
    unsafe { outb(PS2_DATA, 0xFF); } // reset
    let _ = wait_output_byte_short(); // ACK 0xFA
    let _ = wait_output_byte_short(); // BAT 0xAA

    let _ = wait_input_clear_short();
    unsafe { outb(PS2_DATA, 0xF0); }
    let _ = wait_output_byte_short();
    let _ = wait_input_clear_short();
    unsafe { outb(PS2_DATA, 0x01); }
    let _ = wait_output_byte_short();

    let _ = wait_input_clear_short();
    unsafe { outb(PS2_DATA, 0xF4); }
    let _ = wait_output_byte_short();

    STATE.initialized.store(true, Ordering::Release);
    Ok(())
}

/// Translate a single scancode-set-1 make/break byte (without the
/// 0x80 release bit) into a `KeyCode`. `extended` indicates the byte
/// followed an `0xE0` escape.
fn decode(byte: u8, extended: bool) -> KeyCode {
    if extended {
        return match byte {
            0x1D => KeyCode::RightCtrl,
            0x38 => KeyCode::RightAlt,
            0x48 => KeyCode::Up,
            0x4B => KeyCode::Left,
            0x4D => KeyCode::Right,
            0x50 => KeyCode::Down,
            _    => KeyCode::Unknown,
        };
    }
    // Plain set-1 mapping. Codes 0..=70 line up 1:1 with our KeyCode
    // numeric values by construction (see input/lib.rs).
    if byte <= 70 {
        // SAFETY: we constructed KeyCode so 0..=70 map to defined
        // discriminants (Reserved..=ScrollLock).
        return unsafe { core::mem::transmute::<u16, KeyCode>(byte as u16) };
    }
    KeyCode::Unknown
}

/// Apply this event's effect to the modifier bitset (for modifier
/// keys) and return the *post-event* state. Returns the same
/// modifier state for non-modifier keys.
fn apply_modifiers(code: KeyCode, pressed: bool, mods: Modifiers) -> Modifiers {
    let mut m = mods;
    let bit = match code {
        KeyCode::LeftShift  | KeyCode::RightShift => Modifiers::SHIFT,
        KeyCode::LeftCtrl   | KeyCode::RightCtrl  => Modifiers::CTRL,
        KeyCode::LeftAlt    | KeyCode::RightAlt   => Modifiers::ALT,
        KeyCode::CapsLock   if pressed => { m.toggle(Modifiers::CAPS_LOCK);   return m; }
        KeyCode::NumLock    if pressed => { m.toggle(Modifiers::NUM_LOCK);    return m; }
        KeyCode::ScrollLock if pressed => { m.toggle(Modifiers::SCROLL_LOCK); return m; }
        _ => return m,
    };
    if pressed { m.insert(bit); } else { m.remove(bit); }
    m
}

/// IRQ-1 handler. Reads one byte from 0x60, decodes, pushes a
/// `KeyEvent` to the global event ring.
///
/// # Safety
/// IRQ context only.
pub unsafe fn on_irq1() {
    // SAFETY: 0x60 is the i8042 data port.
    let byte = unsafe { inb(PS2_DATA) };

    if byte == 0xE0 {
        STATE.extended.store(true, Ordering::Release);
        return;
    }

    let pressed  = byte & 0x80 == 0;
    let make     = byte & 0x7F;
    let extended = STATE.extended.swap(false, Ordering::AcqRel);
    let code     = decode(make, extended);

    let prev = Modifiers::from_bits_truncate(STATE.modifiers.load(Ordering::Acquire));
    let next = apply_modifiers(code, pressed, prev);
    STATE.modifiers.store(next.bits(), Ordering::Release);

    let ev = KeyEvent { code, pressed, modifiers: next };
    let _ = push_global(InputEvent::Key(ev));
}

/// Test-only: process a synthetic byte stream through the same
/// decode + modifier pipeline the IRQ handler uses, without
/// touching the I/O ports. Each pushed event also lands in the
/// global ring so consumers can be exercised end-to-end.
pub fn feed_bytes_for_test(bytes: &[u8]) {
    for &b in bytes {
        if b == 0xE0 {
            STATE.extended.store(true, Ordering::Release);
            continue;
        }
        let pressed  = b & 0x80 == 0;
        let make     = b & 0x7F;
        let extended = STATE.extended.swap(false, Ordering::AcqRel);
        let code     = decode(make, extended);
        let prev = Modifiers::from_bits_truncate(STATE.modifiers.load(Ordering::Acquire));
        let next = apply_modifiers(code, pressed, prev);
        STATE.modifiers.store(next.bits(), Ordering::Release);
        let ev = KeyEvent { code, pressed, modifiers: next };
        let _ = push_global(InputEvent::Key(ev));
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    STATE.extended.store(false, Ordering::Release);
    STATE.modifiers.store(0, Ordering::Release);
}
