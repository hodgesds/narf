//! i8042 PS/2 mouse driver — AUX channel + IRQ 12.
//!
//! The i8042 controller multiplexes two PS/2 channels behind the
//! same data port (0x60). The keyboard channel uses IRQ 1; the
//! AUX (mouse) channel uses IRQ 12. Distinguishing the two from a
//! port-0x60 read is via the controller's status register: bit 5
//! (AUX_FULL) means the next data byte came from AUX. We use the
//! per-IRQ entry instead — IRQ 1 reads keyboard, IRQ 12 reads mouse —
//! so the status check is only used by the init path that drains
//! init replies.
//!
//! Standard PS/2 mouse 3-byte packet:
//!
//! ```
//!   byte 0 — status:
//!     bit 0: left button
//!     bit 1: right button
//!     bit 2: middle button
//!     bit 3: always 1 (sync)
//!     bit 4: X sign
//!     bit 5: Y sign
//!     bit 6: X overflow (ignored)
//!     bit 7: Y overflow (ignored)
//!   byte 1 — dx (signed via bit 4 of byte 0)
//!   byte 2 — dy (signed via bit 5 of byte 0; positive = up, so
//!            we negate to match the screen-down convention)
//! ```
//!
//! Init sequence:
//!   1. Enable the AUX channel via cmd 0xA8.
//!   2. Set bit 1 (AUX IRQ) in the controller config; clear bit 5
//!      (AUX disable).
//!   3. Send 0xD4 + 0xFF on the data port to reset the device,
//!      then 0xD4 + 0xF6 (set defaults), 0xD4 + 0xF4 (enable
//!      data reporting). Each pair is best-effort — a system
//!      without a PS/2 mouse won't ack but the kernel keeps
//!      booting.

use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

use narf_arch::x86_64::io_port::{inb, outb};
use narf_input::{push_global, InputEvent, PointerButtons, PointerEvent};

use crate::i8042::{PS2_CMD, PS2_DATA, PS2_STATUS};

const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;

const CMD_ENABLE_AUX: u8 = 0xA8;
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_WRITE_AUX: u8 = 0xD4;

const CONF_KBD_IRQ: u8 = 1 << 0;
const CONF_AUX_IRQ: u8 = 1 << 1;
const CONF_AUX_DIS: u8 = 1 << 5;

/// Controller-config wait; controller commands respond in µs.
const CONFIG_WAIT_MS: u64 = 5;
/// Mouse-channel reply wait; see i8042.rs for the EC-latency rationale.
/// PS/2 mouse reset also returns a 3rd "device id" byte that can
/// arrive up to ~100 ms after BAT.
const MOUSE_REPLY_MS: u64 = 100;
const MOUSE_BAT_MS: u64 = 500;

const MOUSE_ACK: u8 = 0xFA;
const MOUSE_BAT_OK: u8 = 0xAA;

#[derive(Debug)]
pub struct State {
    /// Bytes 0..=2 of the in-flight packet. `phase` tracks how many
    /// bytes we've collected (0, 1, 2). When phase reaches 3, we
    /// emit the PointerEvent + reset to 0.
    pkt: [AtomicU8; 3],
    phase: AtomicU8,
    rel_dx_acc: AtomicI32,
    rel_dy_acc: AtomicI32,
    initialized: core::sync::atomic::AtomicBool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            pkt: [AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0)],
            phase: AtomicU8::new(0),
            rel_dx_acc: AtomicI32::new(0),
            rel_dy_acc: AtomicI32::new(0),
            initialized: core::sync::atomic::AtomicBool::new(false),
        }
    }
}

pub static STATE: State = State::new();

pub fn take_rel_delta() -> (i32, i32) {
    let dx = STATE.rel_dx_acc.swap(0, Ordering::AcqRel);
    let dy = STATE.rel_dy_acc.swap(0, Ordering::AcqRel);
    (dx, dy)
}

pub fn is_initialized() -> bool {
    STATE.initialized.load(Ordering::Acquire)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InitError {
    Timeout,
}

fn deadline_cycles(ms: u64) -> u64 {
    let cpns = narf_time::cycles_per_ns() as u64;
    let cpms = if cpns == 0 { 1_000_000 } else { cpns * 1_000_000 };
    narf_time::now_cycles().saturating_add(cpms.saturating_mul(ms))
}

fn wait_input_clear_ms(ms: u64) -> Result<(), InitError> {
    let deadline = deadline_cycles(ms);
    while narf_time::now_cycles() < deadline {
        // SAFETY: 0x64 status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_INPUT_FULL == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(InitError::Timeout)
}

fn wait_output_ms(ms: u64) -> Option<u8> {
    let deadline = deadline_cycles(ms);
    while narf_time::now_cycles() < deadline {
        // SAFETY: 0x64 status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_OUTPUT_FULL != 0 {
            // SAFETY: 0x60 data read.
            return Some(unsafe { inb(PS2_DATA) });
        }
        core::hint::spin_loop();
    }
    None
}

/// Bring up the PS/2 mouse channel. Best-effort — most QEMU configs
/// don't expose a PS/2 mouse (USB / virtio-mouse instead), in
/// which case the device-side commands will time out and we
/// proceed without sending PointerEvents.
///
/// # Safety
/// BSP-only at the time of call; assumes `i8042::init` already
/// ran (so the keyboard channel is configured). Concurrent agents
/// driving 0x60/0x64 are forbidden.
pub unsafe fn init() -> Result<(), InitError> {
    if STATE.initialized.load(Ordering::Acquire) {
        return Ok(());
    }

    // 1. Enable AUX channel.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: 0x64 cmd.
    unsafe {
        outb(PS2_CMD, CMD_ENABLE_AUX);
    }

    // 2. Update config: set AUX_IRQ, clear AUX_DIS.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_READ_CONFIG);
    }
    let mut conf = wait_output_ms(CONFIG_WAIT_MS).ok_or(InitError::Timeout)?;
    conf |= CONF_AUX_IRQ;
    conf &= !CONF_AUX_DIS;
    conf |= CONF_KBD_IRQ;
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_CMD, CMD_WRITE_CONFIG);
    }
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    unsafe {
        outb(PS2_DATA, conf);
    }

    // 3. Reset + verify ACK + BAT + device-id. AUX commands ride
    //    behind 0xD4 (WRITE_AUX) per the i8042 spec — every byte
    //    sent to the mouse needs the prefix.
    let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
    unsafe {
        outb(PS2_CMD, CMD_WRITE_AUX);
    }
    let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
    unsafe {
        outb(PS2_DATA, 0xFF);
    }
    let mut reporting_ok = wait_output_ms(MOUSE_REPLY_MS) == Some(MOUSE_ACK);
    if reporting_ok {
        if wait_output_ms(MOUSE_BAT_MS) != Some(MOUSE_BAT_OK) {
            reporting_ok = false;
        }
        // Device id (0x00 for standard mouse) follows BAT but
        // is informational; don't gate on it.
        let _ = wait_output_ms(MOUSE_REPLY_MS);
    }

    if reporting_ok {
        // 4a. Set defaults (0xF6) — ACK.
        let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
        unsafe {
            outb(PS2_CMD, CMD_WRITE_AUX);
        }
        let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
        unsafe {
            outb(PS2_DATA, 0xF6);
        }
        if wait_output_ms(MOUSE_REPLY_MS) != Some(MOUSE_ACK) {
            reporting_ok = false;
        }
    }

    if reporting_ok {
        // 4b. Enable data reporting (0xF4) — ACK. This flips the
        // mouse from "idle" to "actively sending packets."
        let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
        unsafe {
            outb(PS2_CMD, CMD_WRITE_AUX);
        }
        let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
        unsafe {
            outb(PS2_DATA, 0xF4);
        }
        if wait_output_ms(MOUSE_REPLY_MS) != Some(MOUSE_ACK) {
            reporting_ok = false;
        }
    }

    let _ = reporting_ok; // tracked via STATE.initialized only; mouse
                          // doesn't have a separate panel atom yet.
    STATE.initialized.store(true, Ordering::Release);
    Ok(())
}

/// IRQ-12 handler. Reads one byte from 0x60, advances the 3-byte
/// packet state machine, and on completion pushes a PointerEvent
/// + accumulates the relative delta.
///
/// # Safety
/// IRQ context only.
pub unsafe fn on_irq12() {
    // SAFETY: 0x60 data port read.
    let byte = unsafe { inb(PS2_DATA) };

    let phase = STATE.phase.load(Ordering::Acquire);
    if phase == 0 && (byte & 0x08) == 0 {
        // Sync bit not set — drop until we re-sync.
        return;
    }
    STATE.pkt[phase as usize].store(byte, Ordering::Release);
    let next = phase + 1;
    if next < 3 {
        STATE.phase.store(next, Ordering::Release);
        return;
    }

    // Packet complete — decode.
    let b0 = STATE.pkt[0].load(Ordering::Acquire);
    let b1 = STATE.pkt[1].load(Ordering::Acquire) as i16;
    let b2 = STATE.pkt[2].load(Ordering::Acquire) as i16;
    STATE.phase.store(0, Ordering::Release);

    let dx = if b0 & 0x10 != 0 { b1 - 256 } else { b1 } as i32;
    let dy_raw = if b0 & 0x20 != 0 { b2 - 256 } else { b2 } as i32;
    // PS/2 reports +Y as up; our screen convention is +Y is down.
    let dy = -dy_raw;

    let mut buttons = PointerButtons::EMPTY;
    if b0 & 0x01 != 0 {
        buttons.insert(PointerButtons::LEFT);
    }
    if b0 & 0x02 != 0 {
        buttons.insert(PointerButtons::RIGHT);
    }
    if b0 & 0x04 != 0 {
        buttons.insert(PointerButtons::MIDDLE);
    }

    STATE.rel_dx_acc.fetch_add(dx, Ordering::Relaxed);
    STATE.rel_dy_acc.fetch_add(dy, Ordering::Relaxed);

    let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
}

#[doc(hidden)]
pub fn __reset_for_test() {
    STATE.phase.store(0, Ordering::Release);
    STATE.rel_dx_acc.store(0, Ordering::Release);
    STATE.rel_dy_acc.store(0, Ordering::Release);
}

/// Test-only synthetic packet feed: same logic as the IRQ handler
/// but bypasses port reads. Each call pushes one byte through the
/// state machine, exactly like a real IRQ would.
pub fn feed_byte_for_test(byte: u8) {
    let phase = STATE.phase.load(Ordering::Acquire);
    if phase == 0 && (byte & 0x08) == 0 {
        return;
    }
    STATE.pkt[phase as usize].store(byte, Ordering::Release);
    let next = phase + 1;
    if next < 3 {
        STATE.phase.store(next, Ordering::Release);
        return;
    }
    let b0 = STATE.pkt[0].load(Ordering::Acquire);
    let b1 = STATE.pkt[1].load(Ordering::Acquire) as i16;
    let b2 = STATE.pkt[2].load(Ordering::Acquire) as i16;
    STATE.phase.store(0, Ordering::Release);
    let dx = if b0 & 0x10 != 0 { b1 - 256 } else { b1 } as i32;
    let dy_raw = if b0 & 0x20 != 0 { b2 - 256 } else { b2 } as i32;
    let dy = -dy_raw;
    let mut buttons = PointerButtons::EMPTY;
    if b0 & 0x01 != 0 {
        buttons.insert(PointerButtons::LEFT);
    }
    if b0 & 0x02 != 0 {
        buttons.insert(PointerButtons::RIGHT);
    }
    if b0 & 0x04 != 0 {
        buttons.insert(PointerButtons::MIDDLE);
    }
    STATE.rel_dx_acc.fetch_add(dx, Ordering::Relaxed);
    STATE.rel_dy_acc.fetch_add(dy, Ordering::Relaxed);
    let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
}
