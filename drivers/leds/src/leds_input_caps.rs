//! HID keyboard Caps Lock LED bridge.
//!
//! Reverse-bridges the LED class to the USB HID keyboard's SET_REPORT
//! path. The standard USB HID LED output report is a 1-byte mask:
//!
//! ```text
//! bit 0 — Num Lock
//! bit 1 — Caps Lock
//! bit 2 — Scroll Lock
//! bit 3 — Compose
//! bit 4 — Kana
//! ```
//!
//! When userspace writes to `/sys/class/leds/input0::capslock/brightness`,
//! this driver updates the mask and calls the registered `SetReportFn`
//! to push the new byte to the keyboard.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/hid/hid-input.c` — `hidinput_led_event`, LED output
//!   report building (line ~740 in v6.8 kernel).
//! - `drivers/input/keyboard/atkbd.c` — `atkbd_set_leds`,
//!   PS/2 LED mask byte layout.

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::class::LedDevice;
use crate::triggers::Trigger;

// ── HID LED byte constants ─────────────────────────────────────────

/// HID LED report bit for Num Lock (USB HID Usage Tables 1.4 §11,
/// usage 0x01 on LED page 0x08).
pub const HID_LED_NUM_LOCK: u8 = 0x01;

/// HID LED report bit for Caps Lock (USB HID Usage Tables 1.4 §11,
/// usage 0x02 on LED page 0x08).
pub const HID_LED_CAPS_LOCK: u8 = 0x02;

/// HID LED report bit for Scroll Lock (USB HID Usage Tables 1.4 §11,
/// usage 0x03 on LED page 0x08).
pub const HID_LED_SCROLL_LOCK: u8 = 0x04;

// ── Shared HID LED state ───────────────────────────────────────────

/// Current HID LED byte shared across Caps/Num/Scroll Lock drivers
/// on the same keyboard. Each driver reads-modify-writes its own bit.
///
/// In a full implementation this would be per-device; here it is
/// global for the first keyboard, matching the single-keyboard
/// common case.
pub(crate) static HID_LED_BYTE: AtomicU8 = AtomicU8::new(0);

/// Callback type for sending the LED byte to the keyboard hardware.
///
/// The argument is the full HID LED report byte. Implementations
/// should call USB `SET_REPORT(OUTPUT, 0x00, &[byte])` or the PS/2
/// `0xED` command as appropriate.
pub type SetReportFn = fn(led_byte: u8);

/// The registered hardware SET_REPORT callback. `None` means no
/// keyboard is wired up yet (e.g. on QEMU without USB HID).
static SET_REPORT: IrqSafeSpinLock<Option<SetReportFn>> =
    IrqSafeSpinLock::new(None);

/// Register the hardware callback for LED output.
///
/// Called by the USB HID or PS/2 keyboard driver at probe time.
pub fn register_set_report(f: SetReportFn) {
    *SET_REPORT.lock() = Some(f);
}

/// Clear the hardware callback (called at keyboard unplug).
pub fn unregister_set_report() {
    *SET_REPORT.lock() = None;
}

/// Push the current `HID_LED_BYTE` to the keyboard.
pub(crate) fn flush_led_byte() {
    let byte = HID_LED_BYTE.load(Ordering::Acquire);
    if let Some(f) = *SET_REPORT.lock() {
        f(byte);
    }
}

// ── LedCapsLock ───────────────────────────────────────────────────

/// Caps Lock LED — bridges `/sys/class/leds/input0::capslock/` to
/// the keyboard's HID LED output report.
#[derive(Debug)]
pub struct LedCapsLock {
    name: String,
    cur_brightness: AtomicU32,
    trigger: IrqSafeSpinLock<Trigger>,
}

impl LedCapsLock {
    /// Create a new Caps Lock LED.
    ///
    /// `name` should follow the Linux naming convention:
    /// `"input<N>::capslock"` where N is the input device index.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cur_brightness: AtomicU32::new(0),
            trigger: IrqSafeSpinLock::new(Trigger::KeyboardCapsLock),
        }
    }
}

impl LedDevice for LedCapsLock {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        1
    }

    fn brightness(&self) -> u32 {
        self.cur_brightness.load(Ordering::Acquire)
    }

    fn set_brightness(&self, level: u32) {
        let on = level > 0;
        self.cur_brightness.store(on as u32, Ordering::Release);
        // Update the shared LED byte and flush to hardware.
        let _ = HID_LED_BYTE.fetch_update(Ordering::AcqRel, Ordering::Acquire, |b| {
            Some(if on { b | HID_LED_CAPS_LOCK } else { b & !HID_LED_CAPS_LOCK })
        });
        flush_led_byte();
    }

    fn current_trigger(&self) -> Trigger {
        self.trigger.lock().clone()
    }

    fn set_trigger(&self, trigger: Trigger) {
        *self.trigger.lock() = trigger;
    }
}
