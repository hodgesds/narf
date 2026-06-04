//! i8042 PS/2 keyboard driver (x86_64).
//!
//! Surface:
//!
//!   * `port 0x60` — data (read scancode, write commands to the
//!     keyboard or the controller depending on prior 0x64 byte).
//!   * `port 0x64` — status (read) / command (write).
//!   * `IRQ 1`     — keyboard event.
//!
//! Initialisation sequence (per Intel 8042AH controller datasheet
//! + IBM PS/2 Hardware Interface Technical Reference §7):
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

use core::sync::atomic::{AtomicBool, Ordering};

use narf_arch::x86_64::io_port::{inb, outb};
use narf_input::{
    evdev::{dispatch_key_to_node, key, DeviceCaps, DeviceNode, ROUTER},
    push_key, KeyCode,
};

extern crate alloc;
use alloc::sync::Arc;

/// PS/2 keyboard reply bytes (post-command).
const KBD_ACK: u8 = 0xFA;
const KBD_BAT_OK: u8 = 0xAA;

/// I/O ports.
pub const PS2_DATA: u16 = 0x60;
pub const PS2_STATUS: u16 = 0x64;
pub const PS2_CMD: u16 = 0x64;

/// Controller-status bits (read from port 0x64).
const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;

/// Controller commands (write to port 0x64).
const CMD_DISABLE_KBD: u8 = 0xAD;
const CMD_DISABLE_AUX: u8 = 0xA7;
const CMD_ENABLE_KBD: u8 = 0xAE;
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_SELF_TEST: u8 = 0xAA;

/// Config-byte bits.
const CONF_KBD_IRQ: u8 = 1 << 0;
const CONF_AUX_IRQ: u8 = 1 << 1;
const CONF_KBD_DISABLE: u8 = 1 << 4;
const CONF_KBD_TRANSLATE: u8 = 1 << 6;

/// Driver state. Only one i8042 controller per system — global static.
/// Modifier tracking lives in `narf_input` (shared across all keyboard
/// producers); we only keep the E0-prefix latch here.
#[derive(Debug)]
pub struct State {
    /// True after the next byte should be interpreted as the second
    /// half of an E0 escape sequence.
    extended: AtomicBool,
    initialized: AtomicBool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            extended: AtomicBool::new(false),
            initialized: AtomicBool::new(false),
        }
    }
}

/// Singleton driver state.
pub static STATE: State = State::new();

/// Evdev `DeviceNode` for the i8042 keyboard. Registered in `init()`.
static KBD_EVDEV_NODE: narf_lib::sync::IrqSafeSpinLock<Option<Arc<DeviceNode>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Cached raw pointer to the DeviceNode for lock-free IRQ access.
/// Written once in `init()` after Arc is stored; read-only thereafter.
/// SAFETY: Arc kept alive by KBD_EVDEV_NODE + ROUTER for device lifetime.
static KBD_NODE_PTR: core::sync::atomic::AtomicPtr<DeviceNode> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Errors from `init`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InitError {
    SelfTestFailed,
    KeyboardResetFailed,
    Timeout,
}

/// Controller config-byte wait. The controller-side commands (read
/// config, self-test, enable channel) respond in microseconds on
/// real silicon — 5 ms is generous.
const CONFIG_WAIT_MS: u64 = 5;
/// Keyboard-side reply wait. Reset/set-scancode/enable-scanning each
/// flow through the EC's PS/2 emulation on modern laptops, which
/// adds milliseconds to tens of milliseconds of delay (vs. nanoseconds
/// on QEMU). Pre-fix this was 2000 iterations of `inb 0x64` ≈ ~50 µs,
/// which silently lost every reply on Phoenix HawkPoint1 / Renoir,
/// so ENABLE_SCANNING was never acknowledged and the keyboard
/// channel never started emitting scancodes. 100 ms covers the
/// EC's worst-case ACK; the BAT byte after reset gets 500 ms per
/// IBM PS/2 §7 ("up to 500 ms").
const KBD_REPLY_MS: u64 = 100;
const KBD_BAT_MS: u64 = 500;

/// Wall-time TSC deadline `ms` from now. Falls back to a 1 GHz
/// estimate if `cycles_per_ns` returned 0 (calibration didn't run);
/// that still yields a measurable wait — never zero.
fn deadline_cycles(ms: u64) -> u64 {
    let cpns = narf_time::cycles_per_ns() as u64;
    let cpms = if cpns == 0 {
        1_000_000
    } else {
        cpns * 1_000_000
    };
    narf_time::now_cycles().saturating_add(cpms.saturating_mul(ms))
}

/// Block until the controller's input buffer is empty OR the
/// wall-clock deadline passes. Returns `Ok` on cleared buffer.
fn wait_input_clear_ms(ms: u64) -> Result<(), InitError> {
    let deadline = deadline_cycles(ms);
    while narf_time::now_cycles() < deadline {
        // SAFETY: I/O port read at CPL=0 is always defined; 0x64 is
        // the i8042 status register.
        if unsafe { inb(PS2_STATUS) } & STATUS_INPUT_FULL == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(InitError::Timeout)
}

/// Block until the controller's output buffer has data OR the
/// wall-clock deadline passes; returns the byte on success.
fn wait_output_byte_ms(ms: u64) -> Option<u8> {
    let deadline = deadline_cycles(ms);
    while narf_time::now_cycles() < deadline {
        // SAFETY: status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_OUTPUT_FULL != 0 {
            // SAFETY: data port read.
            return Some(unsafe { inb(PS2_DATA) });
        }
        core::hint::spin_loop();
    }
    None
}

fn flush_output() {
    for _ in 0..32 {
        // SAFETY: status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_OUTPUT_FULL == 0 {
            return;
        }
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
    if STATE.initialized.load(Ordering::Acquire) {
        return Ok(());
    }

    // 1. Disable channels so init bytes don't race with stray scancodes.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: 0x64 is the cmd port.
    unsafe {
        outb(PS2_CMD, CMD_DISABLE_KBD);
    }
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_DISABLE_AUX);
    }

    // 2. Drain anything pending.
    flush_output();

    // 3. Read the config byte, clear translate + IRQs while we configure.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_READ_CONFIG);
    }
    let mut conf = wait_output_byte_ms(CONFIG_WAIT_MS).ok_or(InitError::Timeout)?;
    conf &= !(CONF_KBD_TRANSLATE | CONF_KBD_IRQ | CONF_AUX_IRQ);
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_WRITE_CONFIG);
    }
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_DATA, conf);
    }

    // 4. Self-test.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_SELF_TEST);
    }
    let st = wait_output_byte_ms(CONFIG_WAIT_MS).ok_or(InitError::Timeout)?;
    if st != 0x55 {
        return Err(InitError::SelfTestFailed);
    }

    // 5. Re-enable the keyboard channel + arm IRQ 1.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_ENABLE_KBD);
    }
    // Re-read config (self-test may have reset it on some chips), set IRQ.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_READ_CONFIG);
    }
    let mut conf2 = wait_output_byte_ms(CONFIG_WAIT_MS).ok_or(InitError::Timeout)?;
    conf2 |= CONF_KBD_IRQ;
    conf2 &= !CONF_KBD_DISABLE;
    // ENABLE first-port translation. The i8042 controller then
    // translates whatever scancode set the keyboard emits (default
    // is set 2 post-AT) into set 1 — which is what our decode()
    // path expects (Set 1 make codes 1..=83 == Linux evdev codes
    // 1..=83). Linux's atkbd uses this approach for the same
    // reason. Renoir's EC silently ignores our explicit "set
    // scancode 1" command (0xF0 0x01) below, so the keyboard
    // emits set 2 anyway — without translation we'd see e.g.
    // set-2 'A' = 0x1C reaching `from_evdev(28)` = Enter.
    conf2 |= CONF_KBD_TRANSLATE;
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_WRITE_CONFIG);
    }
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_DATA, conf2);
    }

    // 6. Keyboard reset / set scancode-set 1 / enable scanning. On
    //    real silicon this is where the AMD Phoenix / Renoir EC's
    //    PS/2 emulation latency matters: each ACK can take tens of
    //    ms; the BAT byte after reset, up to 500 ms (IBM PS/2 §7).
    //    Verify each step. ENABLE_SCANNING (0xF4) is the load-
    //    bearing one — if its ACK doesn't arrive, the keyboard
    //    channel never starts emitting scancodes regardless of
    //    how IRQ1 is routed.
    //
    //    Controller-side init (steps 1-5) succeeding while the
    //    keyboard channel fails is a normal outcome: USB-only or
    //    virtio-input-only systems present an 8042 controller
    //    that passes self-test but has no actual PS/2 keyboard
    //    behind the kbd channel. We surface that distinction via
    //    `I8042_KBD_SCANNING_OK`: controller-init returns Ok
    //    either way (so the IRQ wiring is still installed for
    //    hot-plug cases), but `scanning` reflects whether the
    //    keyboard is genuinely live.
    let mut scanning_ok = true;
    let _ = wait_input_clear_ms(KBD_REPLY_MS);
    // SAFETY: data port write.
    unsafe {
        outb(PS2_DATA, 0xFF);
    }
    // Reset reply: ACK then BAT, or BAT alone on some keyboards.
    // The first byte arrives within ~100 ms; the second (BAT after
    // ACK) can take up to 500 ms.
    match wait_output_byte_ms(KBD_REPLY_MS) {
        Some(KBD_ACK) => match wait_output_byte_ms(KBD_BAT_MS) {
            Some(KBD_BAT_OK) => {}
            _ => scanning_ok = false,
        },
        Some(KBD_BAT_OK) => {} // reset complete in one byte
        _ => scanning_ok = false,
    }

    if scanning_ok {
        // Set scancode-set 1: 0xF0 then 0x01, each ACK'd.
        let _ = wait_input_clear_ms(KBD_REPLY_MS);
        unsafe {
            outb(PS2_DATA, 0xF0);
        }
        if wait_output_byte_ms(KBD_REPLY_MS) != Some(KBD_ACK) {
            scanning_ok = false;
        }
        if scanning_ok {
            let _ = wait_input_clear_ms(KBD_REPLY_MS);
            unsafe {
                outb(PS2_DATA, 0x01);
            }
            if wait_output_byte_ms(KBD_REPLY_MS) != Some(KBD_ACK) {
                scanning_ok = false;
            }
        }
    }

    if scanning_ok {
        // Enable scanning: 0xF4, ACK required. THIS is the bit
        // that flips the keyboard from "reset complete, idle"
        // to "actively sending scancodes."
        let _ = wait_input_clear_ms(KBD_REPLY_MS);
        unsafe {
            outb(PS2_DATA, 0xF4);
        }
        if wait_output_byte_ms(KBD_REPLY_MS) != Some(KBD_ACK) {
            scanning_ok = false;
        }
    }

    narf_input::I8042_KBD_SCANNING_OK.store(scanning_ok, Ordering::Release);
    STATE.initialized.store(true, Ordering::Release);

    // Register the i8042 keyboard as an evdev device.
    let mut caps = DeviceCaps::new();
    // Full scancode-set-1 range (codes 1..=127) + extended set.
    for c in 1u16..=127 {
        caps.add_key(c);
    }
    for c in [
        97u16, 100, 103, 104, 105, 106, 107, 108, 109, 110, 111, 125, 126, 127,
    ] {
        caps.add_key(c);
    }
    let _ = key::KEY_A; // ensure import is used
    let (_dev_id, node_arc) = ROUTER.register_device(caps);
    KBD_NODE_PTR.store(Arc::as_ptr(&node_arc) as *mut DeviceNode, Ordering::Release);
    *KBD_EVDEV_NODE.lock() = Some(node_arc);

    Ok(())
}

/// Return the evdev `DeviceNode` for the i8042 keyboard if registered.
pub fn kbd_evdev_node() -> Option<Arc<DeviceNode>> {
    KBD_EVDEV_NODE.lock().clone()
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
            _ => KeyCode::Unknown,
        };
    }
    // Plain set-1 mapping. Set-1 make codes 1..=83 match Linux evdev
    // KEY_* values 1:1 in that range — `KeyCode::from_evdev` handles
    // the conversion safely (no UB-transmute for invalid codes).
    KeyCode::from_evdev(byte as u16)
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

    let pressed = byte & 0x80 == 0;
    let make = byte & 0x7F;
    let extended = STATE.extended.swap(false, Ordering::AcqRel);
    let code = decode(make, extended);
    // Legacy global ring (for FB status panel / console consumer).
    let _ = push_key(code, pressed);

    // Evdev routing — dispatch to the per-device node if registered.
    // SAFETY: pointer written once in init() before IRQs armed; Arc
    // kept alive by KBD_EVDEV_NODE + ROUTER for device lifetime.
    let raw = KBD_NODE_PTR.load(Ordering::Acquire);
    if !raw.is_null() {
        let node_ref: &DeviceNode = unsafe { &*raw };
        dispatch_key_to_node(node_ref, code as u16, pressed);
    }
}

/// Test-only: process a synthetic byte stream through the same
/// decode + modifier pipeline the IRQ handler uses, without
/// touching the I/O ports. Each pushed event also lands in the
/// global ring AND the evdev node.
pub fn feed_bytes_for_test(bytes: &[u8]) {
    for &b in bytes {
        if b == 0xE0 {
            STATE.extended.store(true, Ordering::Release);
            continue;
        }
        let pressed = b & 0x80 == 0;
        let make = b & 0x7F;
        let extended = STATE.extended.swap(false, Ordering::AcqRel);
        let code = decode(make, extended);
        let _ = push_key(code, pressed);
        let raw = KBD_NODE_PTR.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: same as on_irq1.
            let node_ref: &DeviceNode = unsafe { &*raw };
            dispatch_key_to_node(node_ref, code as u16, pressed);
        }
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    STATE.extended.store(false, Ordering::Release);
    narf_input::__reset_modifiers_for_test();
}
