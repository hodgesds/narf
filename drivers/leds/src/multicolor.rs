//! Multicolor (RGB) LED class — the NARF analogue of Linux's
//! `led-class-multicolor` (`drivers/leds/rgb/`). One logical device whose
//! red / green / blue channels are driven together as a single 24-bit color.
//!
//! `set_color` may touch a slow transport (I²C / SMBus on real RGB
//! controllers), so it is a *sleepable* operation. The BPF path reaches it
//! only through the [`crate::worker`] drain — never from a program's atomic
//! context (`bpf/specification/spec.md` §4.6).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// A multicolor LED.
pub trait RgbLed: Send + Sync {
    /// sysfs-style name.
    fn name(&self) -> &str;
    /// Drive the LED to `(r, g, b)`, each `0..=255`.
    fn set_color(&self, r: u8, g: u8, b: u8);
    /// The last color set.
    fn color(&self) -> (u8, u8, u8);
}

static RGB_LEDS: IrqSafeSpinLock<Vec<Arc<dyn RgbLed>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a multicolor LED. Replaces any existing device with the same
/// `name()`, matching the single-channel class's idempotency.
pub fn register_rgb_led(dev: Arc<dyn RgbLed>) {
    let mut g = RGB_LEDS.lock();
    if let Some(slot) = g.iter_mut().find(|d| d.name() == dev.name()) {
        *slot = dev;
    } else {
        g.push(dev);
    }
}

/// Snapshot the registered multicolor LEDs. Allocates — callers must be able
/// to sleep (the drain worker, not a BPF atomic kfunc).
pub fn rgb_led_devices() -> Vec<Arc<dyn RgbLed>> {
    RGB_LEDS.lock().clone()
}

/// Number of registered multicolor LEDs.
pub fn rgb_led_count() -> usize {
    RGB_LEDS.lock().len()
}

/// Look a multicolor LED up by name.
pub fn lookup_rgb_led_by_name(name: &str) -> Option<Arc<dyn RgbLed>> {
    RGB_LEDS.lock().iter().find(|d| d.name() == name).cloned()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    RGB_LEDS.lock().clear();
}

/// A software multicolor LED: stores the color, drives no hardware. The
/// registered stand-in for tests and headless boots.
#[derive(Debug)]
pub struct SimpleRgbLed {
    name: String,
    /// Packed `0x00RRGGBB`.
    rgb: AtomicU32,
}

impl SimpleRgbLed {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            rgb: AtomicU32::new(0),
        }
    }
}

impl RgbLed for SimpleRgbLed {
    fn name(&self) -> &str {
        &self.name
    }
    fn set_color(&self, r: u8, g: u8, b: u8) {
        let packed = (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b);
        self.rgb.store(packed, Ordering::Release);
    }
    fn color(&self) -> (u8, u8, u8) {
        let v = self.rgb.load(Ordering::Acquire);
        ((v >> 16) as u8, (v >> 8) as u8, v as u8)
    }
}
