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
//! Scancode-set-1 lookup. The controller delivers three byte shapes:
//!   * Single byte: top bit = release (0x80), low bits = make code.
//!   * Two-byte extended: 0xE0 prefix + make/release.
//!   * The Pause key's six-byte 0xE1 sequence (see `process_byte`).
//!
//! The driver tracks a small bit of state across IRQs (the "expecting
//! the second byte of an E0 escape" flag) and a bitset of currently
//! pressed modifier keys to stamp on every event.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_arch::x86_64::io_port::{inb, outb};
use narf_input::{
    evdev::{dispatch_key_to_node, key, led, DeviceCaps, DeviceNode, ROUTER},
    push_key, KeyCode,
};

extern crate alloc;
use alloc::sync::Arc;

/// PS/2 keyboard reply bytes (post-command).
const KBD_ACK: u8 = 0xFA;
const KBD_BAT_OK: u8 = 0xAA;

/// PS/2 Set LEDs command byte (host → keyboard).
const KBD_SET_LEDS: u8 = 0xED;
/// PS/2 RESEND response (keyboard → host): retransmit the last byte.
const KBD_RESEND: u8 = 0xFE;

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
/// producers); we only keep the E0-prefix latch and the E1 (Pause)
/// sequence matcher here.
#[derive(Debug)]
pub struct State {
    /// True after the next byte should be interpreted as the second
    /// half of an E0 escape sequence.
    extended: AtomicBool,
    /// Stage of the 0xE1 (Pause) sequence matcher; one of the
    /// `E1_*` constants below. `E1_IDLE` = no partial sequence.
    e1_stage: AtomicU8,
    initialized: AtomicBool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            extended: AtomicBool::new(false),
            e1_stage: AtomicU8::new(E1_IDLE),
            initialized: AtomicBool::new(false),
        }
    }
}

/// Stages of the 0xE1 (Pause key) sequence matcher; see
/// `process_byte`. The set-1 Pause frame is `E1 1D 45 E1 9D C5`.
const E1_IDLE: u8 = 0;
/// Saw `E1`, expect `0x1D` (make half of the frame).
const E1_GOT_PREFIX: u8 = 1;
/// Saw `E1 1D`, expect `0x45` — completes the press.
const E1_GOT_MAKE_1D: u8 = 2;
/// Press emitted, expect the closing frame's `E1`.
const E1_GOT_PRESS: u8 = 3;
/// Saw the closing `E1`, expect `0x9D`.
const E1_GOT_PREFIX2: u8 = 4;
/// Saw `E1 9D`, expect `0xC5` — completes the release.
const E1_GOT_REL_9D: u8 = 5;

impl Default for State {
    fn default() -> Self {
        Self::new()
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

/// Wall-time TSC deadline `ms` from now.
///
/// `ns_to_cycles` is the calibrated fixed-point scale, so this no longer
/// needs the old "cycles_per_ns returned 0" fallback: the conversion
/// floors at a 1 GHz-equivalent mult before calibration rather than
/// collapsing to zero, so the wait is always measurable.
fn deadline_cycles(ms: u64) -> u64 {
    narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(ms.saturating_mul(1_000_000)))
}

/// Block until the controller's input buffer is empty OR the
/// wall-clock deadline passes. Returns `Ok` on cleared buffer.
fn wait_input_clear_ms(ms: u64) -> Result<(), InitError> {
    let deadline = deadline_cycles(ms);
    while narf_time::now_cycles() < deadline {
        // SAFETY: I/O port read at CPL=0 is always defined; 0x64 is
        // the i8042 status register.
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
    // SAFETY: `out` to cmd port `0x64`; CPL0 + the fn's `# Safety`
    // contract gives us exclusive ownership of the 8042 ports, and
    // the input buffer was just drained.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_DISABLE_AUX);
    }

    // 2. Drain anything pending.
    flush_output();

    // 3. Read the config byte, clear translate + IRQs while we configure.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: `out` to cmd port `0x64`; CPL0 + exclusive-ownership
    // contract; input buffer cleared by the wait above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_READ_CONFIG);
    }
    let mut conf = wait_output_byte_ms(CONFIG_WAIT_MS).ok_or(InitError::Timeout)?;
    conf &= !(CONF_KBD_TRANSLATE | CONF_KBD_IRQ | CONF_AUX_IRQ);
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: `out` to cmd port `0x64`; CPL0 + exclusive-ownership
    // contract; input buffer cleared by the wait above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_WRITE_CONFIG);
    }
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: `out` to data port `0x60` delivering the config byte
    // for the WRITE_CONFIG command issued above; CPL0 + exclusive
    // ownership; input buffer cleared by the wait.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_DATA, conf);
    }

    // 4. Self-test.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: `out` to cmd port `0x64`; CPL0 + exclusive-ownership
    // contract; input buffer cleared by the wait above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_SELF_TEST);
    }
    let st = wait_output_byte_ms(CONFIG_WAIT_MS).ok_or(InitError::Timeout)?;
    if st != 0x55 {
        return Err(InitError::SelfTestFailed);
    }

    // 5. Re-enable the keyboard channel + arm IRQ 1.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: `out` to cmd port `0x64`; CPL0 + exclusive-ownership
    // contract; input buffer cleared by the wait above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_ENABLE_KBD);
    }
    // Re-read config (self-test may have reset it on some chips), set IRQ.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: `out` to cmd port `0x64`; CPL0 + exclusive-ownership
    // contract; input buffer cleared by the wait above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
    // SAFETY: `out` to cmd port `0x64`; CPL0 + exclusive-ownership
    // contract; input buffer cleared by the wait above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_WRITE_CONFIG);
    }
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: `out` to data port `0x60` delivering `conf2` for the
    // WRITE_CONFIG command above; CPL0 + exclusive ownership; input
    // buffer cleared by the wait.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
        // SAFETY: `out` to data port `0x60` (keyboard "set scancode
        // set" command 0xF0); CPL0 + exclusive ownership; input
        // buffer cleared by the wait above.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            outb(PS2_DATA, 0xF0);
        }
        if wait_output_byte_ms(KBD_REPLY_MS) != Some(KBD_ACK) {
            scanning_ok = false;
        }
        if scanning_ok {
            let _ = wait_input_clear_ms(KBD_REPLY_MS);
            // SAFETY: `out` to data port `0x60` (the 0x01 argument
            // selecting scancode set 1); CPL0 + exclusive ownership;
            // input buffer cleared by the wait above.
            // SAFETY: Valid MMIO bounds or trusted driver environment
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
        // SAFETY: `out` to data port `0x60` (keyboard ENABLE_SCANNING
        // command 0xF4); CPL0 + exclusive ownership; input buffer
        // cleared by the wait above.
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
    caps.set_identity(
        "AT Translated Set 2 keyboard",
        "isa0060/serio0/input0",
        "",
        narf_input::evdev::InputId::new(narf_input::evdev::bus::I8042, 0x0001, 0x0001, 0),
    );
    // Full scancode-set-1 range (codes 1..=127) + extended set.
    for c in 1u16..=127 {
        caps.add_key(c);
    }
    for c in [
        97u16, 100, 103, 104, 105, 106, 107, 108, 109, 110, 111, 125, 126, 127,
    ] {
        caps.add_key(c);
    }
    // Lock LEDs: this keyboard answers the PS/2 Set-LEDs command;
    // LED state changes on the node are driven to `on_led_state`.
    caps.add_led(led::LED_NUML);
    caps.add_led(led::LED_CAPSL);
    caps.add_led(led::LED_SCROLLL);
    let _ = key::KEY_A; // ensure import is used
    let (_dev_id, node_arc) = ROUTER.register_device(caps);
    node_arc.set_led_sink(on_led_state);
    KBD_NODE_PTR.store(Arc::as_ptr(&node_arc) as *mut DeviceNode, Ordering::Release);
    *KBD_EVDEV_NODE.lock() = Some(node_arc);

    Ok(())
}

/// Return the evdev `DeviceNode` for the i8042 keyboard if registered.
pub fn kbd_evdev_node() -> Option<Arc<DeviceNode>> {
    KBD_EVDEV_NODE.lock().clone()
}

// ── Keyboard LED output (PS/2 Set LEDs, command 0xED) ────────────
//
// The input core owns LED *state* (`DeviceNode::leds`); this driver
// owns getting it onto the wire. The keyboard protocol (IBM PS/2
// Hardware Interface Technical Reference, keyboard commands — the
// same sequence Linux's `atkbd_set_leds` issues) is:
//
//   host → 0xED            keyboard → 0xFA (ACK)
//   host → LED data byte   keyboard → 0xFA (ACK)
//
// The data byte is bit0=Scroll Lock, bit1=Num Lock, bit2=Caps Lock,
// bits 3..=7 zero — a DIFFERENT bit order from the core bitmap
// (Linux EV_LED codes: Num=0, Caps=1, Scroll=2); `ps2_led_byte`
// converts explicitly. A keyboard may answer 0xFE (RESEND) instead
// of ACK to request retransmission of the byte just sent.
//
// The exchange is receive-driven, never polled: `on_led_state` (the
// core's LED sink, callable from IRQ or task context) records
// intent and writes only the first command byte; each following
// byte is written from the receive path when the response arrives
// (`led_route_byte`, first step of `on_irq1` /
// `feed_bytes_for_test`). No context spin-waits for an ACK, and a
// wedged exchange (dead keyboard) aborts on the next received byte
// and self-heals on the next LED state change.

/// Retransmission budget per byte before the exchange aborts.
const LED_RESEND_MAX: u8 = 3;

/// Convert the input core's LED bitmap (Linux `EV_LED` code order:
/// bit0 Num, bit1 Caps, bit2 Scroll) to the PS/2 Set-LEDs data byte
/// (bit0 Scroll, bit1 Num, bit2 Caps; all other bits zero — LEDs
/// with no PS/2 representation, e.g. Compose/Kana, are masked out).
pub fn ps2_led_byte(leds: u16) -> u8 {
    let mut b = 0u8;
    if leds & (1 << led::LED_SCROLLL) != 0 {
        b |= 1 << 0;
    }
    if leds & (1 << led::LED_NUML) != 0 {
        b |= 1 << 1;
    }
    if leds & (1 << led::LED_CAPSL) != 0 {
        b |= 1 << 2;
    }
    b
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum LedPhase {
    Idle,
    /// 0xED sent; waiting for its ACK.
    AwaitCmdAck,
    /// Data byte sent; waiting for its ACK.
    AwaitDataAck,
}

#[derive(Debug)]
struct LedTx {
    phase: LedPhase,
    /// Bitmap the in-flight data byte was encoded from.
    inflight: u16,
    /// Latest bitmap requested by the core; if it moved while an
    /// exchange was in flight, a follow-up exchange starts when the
    /// current one completes.
    desired: u16,
    /// RESEND retransmissions of the current byte.
    retries: u8,
}

impl LedTx {
    const fn new() -> Self {
        Self {
            phase: LedPhase::Idle,
            inflight: 0,
            desired: 0,
            retries: 0,
        }
    }
}

static LED_TX: narf_lib::sync::IrqSafeSpinLock<LedTx> =
    narf_lib::sync::IrqSafeSpinLock::new(LedTx::new());

/// Every byte written to the keyboard for the LED exchange, in
/// order. Production value: a bounded trace (recording stops at the
/// cap). Test value: fixtures assert the exact byte stream without
/// a port to observe.
static LED_TX_LOG: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<u8>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Recording cap for `LED_TX_LOG`.
const LED_TX_LOG_CAP: usize = 256;

/// Write one byte of the LED exchange: recorded in `LED_TX_LOG`
/// and, once the controller is initialised, driven onto the data
/// port. In the test harness `init()` never ran, so fixtures
/// exercise the full state machine with no port I/O.
fn led_write_byte(byte: u8) {
    {
        let mut log = LED_TX_LOG.lock();
        if log.len() < LED_TX_LOG_CAP {
            log.push(byte);
        }
    }
    if STATE.initialized.load(Ordering::Acquire) {
        // SAFETY: 0x60 is the i8042 data port and init() has run, so
        // the port is owned by this driver. The state machine
        // serialises LED bytes against each other; interleaving
        // into a polled init exchange cannot happen because the
        // sink is only registered at the end of init().
        unsafe { outb(PS2_DATA, byte) };
    }
}

/// Input-core LED sink for the i8042 keyboard node (registered in
/// `init()`). May run in IRQ context (physical lock-key press) or
/// task context (evdev `write()`); it never waits — it records the
/// new desired bitmap and, if no exchange is in flight, writes the
/// Set-LEDs command byte. The rest of the exchange is driven by
/// `led_route_byte` from the receive path.
pub fn on_led_state(leds: u16) {
    let mut tx = LED_TX.lock();
    tx.desired = leds;
    if tx.phase == LedPhase::Idle {
        tx.phase = LedPhase::AwaitCmdAck;
        tx.retries = 0;
        led_write_byte(KBD_SET_LEDS);
    }
}

/// Feed one received byte into the LED exchange. Returns `true`
/// when the byte was a protocol response (ACK / RESEND) consumed by
/// the exchange. A byte that is neither — e.g. a scancode arriving
/// mid-exchange — aborts the exchange and returns `false`: it is
/// NEVER swallowed; the caller decodes it as a key.
fn led_route_byte(byte: u8) -> bool {
    let mut tx = LED_TX.lock();
    let phase = tx.phase;
    if phase == LedPhase::Idle {
        return false;
    }
    if byte == KBD_ACK {
        match phase {
            LedPhase::AwaitCmdAck => {
                tx.inflight = tx.desired;
                let data = ps2_led_byte(tx.desired);
                tx.phase = LedPhase::AwaitDataAck;
                tx.retries = 0;
                led_write_byte(data);
            }
            _ => {
                // Data byte ACKed: exchange complete. If the core
                // state moved while we were in flight, immediately
                // start a follow-up exchange with the new bitmap.
                tx.phase = LedPhase::Idle;
                tx.retries = 0;
                if tx.desired != tx.inflight {
                    tx.phase = LedPhase::AwaitCmdAck;
                    led_write_byte(KBD_SET_LEDS);
                }
            }
        }
        true
    } else if byte == KBD_RESEND {
        if tx.retries < LED_RESEND_MAX {
            tx.retries += 1;
            let again = if phase == LedPhase::AwaitCmdAck {
                KBD_SET_LEDS
            } else {
                ps2_led_byte(tx.inflight)
            };
            led_write_byte(again);
        } else {
            tx.phase = LedPhase::Idle;
            tx.retries = 0;
        }
        true
    } else {
        tx.phase = LedPhase::Idle;
        tx.retries = 0;
        false
    }
}

/// Test hook: snapshot of every LED-exchange byte written so far.
#[doc(hidden)]
pub fn __led_tx_log_for_test() -> alloc::vec::Vec<u8> {
    LED_TX_LOG.lock().clone()
}

/// Test hook: `true` when no LED exchange is in flight.
#[doc(hidden)]
pub fn __led_tx_idle_for_test() -> bool {
    LED_TX.lock().phase == LedPhase::Idle
}

/// Translate a single scancode-set-1 make/break byte (without the
/// 0x80 release bit) into a `KeyCode`. `extended` indicates the byte
/// followed an `0xE0` escape.
///
/// The E0 table is the extended-key block of scancode set 1 (IBM
/// PS/2 Hardware Interface Technical Reference, scan code set 1;
/// the same key assignments Linux's atkbd reports). The navigation
/// cluster, keypad Enter / Divide, Print Screen, and the Meta /
/// Menu keys all live behind the E0 prefix, sharing make-code
/// values with unrelated keypad keys — the prefix is the only
/// thing distinguishing e.g. Home (E0 0x47) from keypad 7 (0x47).
/// One E0 byte is *not* a key and never reaches this function: the
/// "fake shift" 0x2A the keyboard wraps around Print Screen (and
/// inserts around some other E0 keys), consumed by `process_byte`.
fn decode(byte: u8, extended: bool) -> KeyCode {
    if extended {
        return match byte {
            0x1C => KeyCode::KpEnter,
            0x1D => KeyCode::RightCtrl,
            0x35 => KeyCode::KpSlash,
            0x37 => KeyCode::SysRq, // Print Screen
            0x38 => KeyCode::RightAlt,
            0x47 => KeyCode::Home,
            0x48 => KeyCode::Up,
            0x49 => KeyCode::PageUp,
            0x4B => KeyCode::Left,
            0x4D => KeyCode::Right,
            0x4F => KeyCode::End,
            0x50 => KeyCode::Down,
            0x51 => KeyCode::PageDown,
            0x52 => KeyCode::Insert,
            0x53 => KeyCode::Delete,
            0x5B => KeyCode::LeftMeta,
            0x5C => KeyCode::RightMeta,
            0x5D => KeyCode::Menu,
            _ => KeyCode::Unknown,
        };
    }
    // Plain set-1 mapping. Set-1 make codes 1..=83 match Linux evdev
    // KEY_* values 1:1 in that range — `KeyCode::from_evdev` handles
    // the conversion safely (no UB-transmute for invalid codes).
    KeyCode::from_evdev(byte as u16)
}

/// Emit one decoded key event: the legacy global ring (for the FB
/// status panel / console consumer) and the evdev node, if
/// registered.
fn emit_key(code: KeyCode, pressed: bool) {
    let _ = push_key(code, pressed);

    let raw = KBD_NODE_PTR.load(Ordering::Acquire);
    if !raw.is_null() {
        // SAFETY: `raw` was written once in init() (before IRQs were
        // armed) as `Arc::as_ptr` of the node, just null-checked, and
        // the Arc is kept alive by KBD_EVDEV_NODE + ROUTER for the
        // device's lifetime — so the borrow is valid and aligned.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let node_ref: &DeviceNode = unsafe { &*raw };
        dispatch_key_to_node(node_ref, code as u16, pressed);
    }
}

/// Advance the Pause key's 0xE1 sequence matcher by one byte.
///
/// Scancode set 1 gives Pause no ordinary make/break pair: a press
/// emits the whole six-byte frame `E1 1D 45 E1 9D C5` and a release
/// emits nothing. We mirror Linux atkbd: report the press when the
/// `45` lands and the release when the trailing `C5` lands, so
/// userspace sees a normal momentary key. A malformed tail releases an
/// already-reported press. Return false on mismatch so the current byte
/// can start a new key/prefix; bytes accepted as part of E1 never leak as
/// unrelated Ctrl or NumLock events.
fn e1_step(byte: u8) -> bool {
    let stage = STATE.e1_stage.load(Ordering::Acquire);
    let (next, emit) = match (stage, byte) {
        (E1_GOT_PREFIX, 0x1D) => (E1_GOT_MAKE_1D, None),
        (E1_GOT_MAKE_1D, 0x45) => (E1_GOT_PRESS, Some(true)),
        (E1_GOT_PRESS, 0xE1) => (E1_GOT_PREFIX2, None),
        (E1_GOT_PREFIX2, 0x9D) => (E1_GOT_REL_9D, None),
        (E1_GOT_REL_9D, 0xC5) => (E1_IDLE, Some(false)),
        _ => {
            STATE.e1_stage.store(E1_IDLE, Ordering::Release);
            if matches!(stage, E1_GOT_PRESS | E1_GOT_PREFIX2 | E1_GOT_REL_9D) {
                emit_key(KeyCode::Pause, false);
            }
            return false;
        }
    };
    STATE.e1_stage.store(next, Ordering::Release);
    if let Some(pressed) = emit {
        emit_key(KeyCode::Pause, pressed);
    }
    true
}

/// Process one byte from the keyboard channel through the decode
/// state machine (E1/Pause matcher, E0 latch, fake-shift filter)
/// and emit the resulting key event, if any. Shared verbatim by
/// the IRQ handler and the test-only synthetic byte stream, so
/// fixtures exercise exactly the production pipeline.
fn process_byte(byte: u8) {
    // Consume valid E1 bytes, but retry mismatches as the start of a new
    // key or prefix so a truncated frame cannot swallow the next key.
    if STATE.e1_stage.load(Ordering::Acquire) != E1_IDLE && e1_step(byte) {
        return;
    }
    if byte == 0xE1 {
        STATE.extended.store(false, Ordering::Release);
        STATE.e1_stage.store(E1_GOT_PREFIX, Ordering::Release);
        return;
    }
    if byte == 0xE0 {
        STATE.extended.store(true, Ordering::Release);
        return;
    }

    let pressed = byte & 0x80 == 0;
    let make = byte & 0x7F;
    let extended = STATE.extended.swap(false, Ordering::AcqRel);
    // Fake shift: the keyboard wraps Print Screen's make in
    // `E0 2A …` and its break in `… E0 AA`, and inserts the same
    // pair around some other E0 keys. 0x2A behind an E0 prefix is
    // not LeftShift (that is the un-prefixed 0x2A) — swallow it,
    // as Linux atkbd does, or Print Screen would also toggle a
    // phantom shift.
    if extended && make == 0x2A {
        return;
    }
    emit_key(decode(make, extended), pressed);
}

/// IRQ-1 handler. Reads one byte from 0x60 and runs it through the
/// decode state machine.
///
/// # Safety
/// IRQ context only.
pub unsafe fn on_irq1() {
    // SAFETY: 0x60 is the i8042 data port.
    let byte = unsafe { inb(PS2_DATA) };

    // LED exchange responses (ACK / RESEND for an in-flight Set
    // LEDs) are protocol bytes, not scancodes.
    if led_route_byte(byte) {
        return;
    }

    process_byte(byte);
}

/// Test-only: process a synthetic byte stream through the same
/// decode + modifier pipeline the IRQ handler uses, without
/// touching the I/O ports. Each pushed event also lands in the
/// global ring AND the evdev node.
pub fn feed_bytes_for_test(bytes: &[u8]) {
    for &b in bytes {
        if led_route_byte(b) {
            continue;
        }
        process_byte(b);
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    STATE.extended.store(false, Ordering::Release);
    STATE.e1_stage.store(E1_IDLE, Ordering::Release);
    narf_input::__reset_modifiers_for_test();
    *LED_TX.lock() = LedTx::new();
    LED_TX_LOG.lock().clear();
}
