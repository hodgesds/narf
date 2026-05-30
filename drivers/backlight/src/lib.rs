//! Display backlight, keyboard backlight, and brightness-key subsystem.
//!
//! This crate is the single registry point for all backlight and LED
//! devices on NARF. It owns:
//!
//! - `/sys/class/backlight/*` — panel brightness devices.
//! - `/sys/class/leds/*` — LED devices (keyboard backlight, power LED,
//!   caps-lock LED, etc.).
//! - ACPI `_BCL` / `_BCM` / `_BQC` video backlight.
//! - AMD GPU PWM bridge (delegates into `drivers/gpu/amdgpu_backlight`).
//! - Intel backlight scaffold (deferred full implementation).
//! - Keyboard backlight via vendor WMI.
//! - Brightness key handling (ACPI Notify 0x86/0x87).
//!
//! ## Architecture
//!
//! Devices are registered through the [`BacklightDevice`] and
//! [`LedDevice`] traits. The registries are globally accessible and
//! allocation-backed (`Vec<Arc<dyn …>>`).
//!
//! The brightness-key handler lives in [`brightness_keys`]: it
//! subscribes to ACPI Notify events and, on 0x86/0x87, steps the
//! first registered ACPI video backlight device and emits a
//! [`narf_input::KeyCode::BrightnessDown`] /
//! [`narf_input::KeyCode::BrightnessUp`] key event.
//!
//! ## References (GPL-2.0-or-later, direct citation allowed)
//!
//! - `drivers/video/backlight/backlight.c` — device registry shape.
//! - `drivers/video/backlight/lcd.c` — LCD class ops.
//! - `drivers/acpi/acpi_video.c` — `_BCL`/`_BCM`/`_BQC` dispatch.
//! - `drivers/platform/x86/asus-wmi.c` — WMI keyboard-backlight path.
//! - `drivers/platform/x86/dell-wmi.c` — Dell WMI hotkey GUIDs.
//! - `drivers/leds/leds-class.c` — LED class registration.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod acpi_video;
pub mod amdgpu_bl;
pub mod brightness_keys;
pub mod intel_bl;
pub mod kbd_backlight;
pub mod leds;

mod tests;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

// ── BacklightKind ──────────────────────────────────────────────────

/// The interface type of a backlight device — mirrors Linux's
/// `backlight_type` enum (`include/linux/backlight.h`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BacklightKind {
    /// Direct hardware PWM / MMIO register control.
    Raw,
    /// Controlled through platform firmware (ACPI `_BCM`, WMI, …).
    Firmware,
    /// Platform-specific (e.g. vendor EC control register).
    Platform,
}

// ── BacklightDevice trait ──────────────────────────────────────────

/// Trait implemented by every backlight device that registers with
/// the subsystem. Mirrors Linux's `backlight_ops` + `backlight_device`
/// fields (`include/linux/backlight.h`).
///
/// Implementations must be `Send + Sync` so the static registry can
/// hold them behind an `Arc`.
pub trait BacklightDevice: Send + Sync + core::fmt::Debug {
    /// Device name, e.g. `"acpi_video0"`, `"amdgpu_bl0"`.
    fn name(&self) -> &str;

    /// Maximum brightness step. For ACPI video this is
    /// `_BCL.max()`; for AMD PWM this is `0xFFFF`; for Intel it is
    /// the `BXT_BLC_PWM_FREQ1` register value.
    fn max_brightness(&self) -> u32;

    /// Current brightness. Returns 0 on any read failure.
    fn current_brightness(&self) -> u32;

    /// Set brightness to `level`. Clamped to `[0, max_brightness()]`
    /// by the caller before dispatch.
    fn set_brightness(&self, level: u32);

    /// Interface kind reported to sysfs consumers.
    fn kind(&self) -> BacklightKind;
}

// ── Global backlight registry ──────────────────────────────────────

static BACKLIGHT_DEVS: IrqSafeSpinLock<Vec<Arc<dyn BacklightDevice>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a backlight device. The name must be unique; duplicate
/// names silently replace the previous entry (matches Linux's
/// `backlight_device_register` idempotency assumption).
pub fn register_backlight(dev: Arc<dyn BacklightDevice>) {
    let name: String = dev.name().to_owned();
    let mut g = BACKLIGHT_DEVS.lock();
    if let Some(slot) = g.iter_mut().find(|d| d.name() == name) {
        *slot = dev;
    } else {
        g.push(dev);
    }
}

/// Unregister a backlight device by name.
pub fn unregister_backlight(name: &str) {
    BACKLIGHT_DEVS.lock().retain(|d| d.name() != name);
}

/// Return a snapshot of all registered backlight devices.
pub fn backlight_devices() -> Vec<Arc<dyn BacklightDevice>> {
    BACKLIGHT_DEVS.lock().clone()
}

/// Find a device by name.
pub fn backlight_device(name: &str) -> Option<Arc<dyn BacklightDevice>> {
    BACKLIGHT_DEVS.lock().iter().find(|d| d.name() == name).cloned()
}

/// Test helper: drain all registries.
#[doc(hidden)]
pub fn __reset_all_for_test() {
    BACKLIGHT_DEVS.lock().clear();
    leds::__reset_for_test();
}

// ── initcalls ─────────────────────────────────────────────────────

/// Register all Stage::Device initcalls for the backlight subsystem.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "backlight/acpi-video", || {
        acpi_video::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Device, "backlight/amdgpu", || {
        amdgpu_bl::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Device, "backlight/intel", || {
        intel_bl::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Device, "backlight/leds", || {
        leds::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Device, "backlight/kbd", || {
        kbd_backlight::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Device, "backlight/brightness-keys", || {
        brightness_keys::init();
        InitResult::Ok
    });
}
