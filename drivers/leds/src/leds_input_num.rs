//! HID keyboard Num Lock LED bridge.
//!
//! See `leds_input_caps.rs` for the full architecture description.
//! This module handles bit 0 of the HID LED byte.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/hid/hid-input.c` — `hidinput_led_event`.
//! - `drivers/input/keyboard/atkbd.c` — `atkbd_set_leds`.

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::class::LedDevice;
use crate::leds_input_caps::{flush_led_byte, HID_LED_BYTE, HID_LED_NUM_LOCK};
use crate::triggers::Trigger;

// ── LedNumLock ────────────────────────────────────────────────────

/// Num Lock LED — bridges `/sys/class/leds/input0::numlock/` to the
/// keyboard's HID LED output report bit 0.
#[derive(Debug)]
pub struct LedNumLock {
    name: String,
    cur_brightness: AtomicU32,
    trigger: IrqSafeSpinLock<Trigger>,
}

impl LedNumLock {
    /// Create a new Num Lock LED.
    ///
    /// `name` follows the Linux naming convention: `"input<N>::numlock"`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cur_brightness: AtomicU32::new(0),
            trigger: IrqSafeSpinLock::new(Trigger::KeyboardNumLock),
        }
    }
}

impl LedDevice for LedNumLock {
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
        let _ = HID_LED_BYTE.fetch_update(Ordering::AcqRel, Ordering::Acquire, |b| {
            Some(if on {
                b | HID_LED_NUM_LOCK
            } else {
                b & !HID_LED_NUM_LOCK
            })
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
