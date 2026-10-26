//! Display backlight, keyboard backlight, and brightness-key subsystem.
//!
//! This crate is the single registry point for all backlight and LED
//! devices on NARF. It owns:
//!
//! - `/sys/class/backlight/*` — panel brightness devices.
//! - `/sys/class/leds/*` — LED devices (keyboard backlight, power LED,
//!   caps-lock LED, etc.).
//! - ACPI `_BCL` / `_BCM` / `_BQC` video backlight.
//! - Intel BXT PWM backlight (registered from the Intel GPU probe).
//! - Keyboard backlight via vendor WMI.
//! - Brightness key handling (ACPI Notify 0x86/0x87).
//!
//! The AMD panel owner lives in `drivers/gpu`
//! (`AmdgpuPanelBacklight`, over `Amdgpu::set_backlight`) and
//! registers into this crate's registry from the amdgpu PCI probe;
//! there is deliberately no AMD bridge module here — the previous
//! bridge encoded a pre-fix `BL_PWM` register scheme and was
//! retired (#951).
//!
//! ## Composition and publication
//!
//! The frame composition root (`frame/src/bare_main.rs`) calls
//! [`register_initcalls`] (#947), so this crate's Stage::Device
//! initcalls run in production boots. Sysfs publication is
//! *dynamic*: [`register_backlight`] / [`unregister_backlight`]
//! reconcile `/sys/class/backlight` with the elected owner after
//! every registry change (#952), so a device registered from a PCI
//! probe — after all Stage::Device initcalls have run — is
//! published immediately, a preempted owner is unpublished, and a
//! promoted candidate is published in its place.
//!
//! ## Architecture
//!
//! Devices are registered through the [`BacklightDevice`] and
//! [`LedDevice`] traits. The registries are globally accessible and
//! allocation-backed (`Vec<Arc<dyn …>>`).
//!
//! Panel ownership is **arbitrated**: several mechanisms can claim
//! the same panel (native GPU PWM, platform control, ACPI `_BCM`),
//! and on real laptops the firmware path usually routes to the same
//! PWM the native driver drives, so two live owners would fight
//! over one panel. Exactly one registered candidate is the panel
//! owner (see [`panel_owner`]); the rest are deferred — registered,
//! but never published or dispatched by the subsystem — until the
//! owner unregisters and they are promoted. Priority is by
//! [`BacklightKind`]: Raw > Platform > Firmware.
//!
//! The brightness-key handler lives in [`brightness_keys`]: it
//! subscribes to ACPI Notify events and, on 0x86/0x87, steps the
//! panel owner and emits a
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
pub mod brightness_keys;
pub mod intel_bl;
pub mod kbd_backlight;
pub mod leds;
pub mod sysfs_bridge;

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

impl BacklightKind {
    /// Arbitration priority when several devices claim the panel:
    /// higher wins. A native (raw) driver is preferred over platform
    /// control, which is preferred over the generic firmware (ACPI
    /// `_BCM`) path — the preference Linux resolves through
    /// `acpi_video_get_backlight_type()`, and the safe default
    /// because firmware control on most AMD laptops routes to the
    /// same PWM the native driver drives directly (audit #936 §2).
    pub fn priority(self) -> u8 {
        match self {
            BacklightKind::Raw => 3,
            BacklightKind::Platform => 2,
            BacklightKind::Firmware => 1,
        }
    }
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

    /// Step brightness up by one increment. The default moves a
    /// tenth of the range; devices with a discrete ladder (ACPI
    /// video) override this to move exactly one ladder rung.
    fn step_up(&self) {
        let max = self.max_brightness();
        let step = (max / 10).max(1);
        let cur = self.current_brightness();
        self.set_brightness(cur.saturating_add(step).min(max));
    }

    /// Step brightness down by one increment. The default moves a
    /// tenth of the range; ladder devices override it (see
    /// [`BacklightDevice::step_up`]).
    fn step_down(&self) {
        let step = (self.max_brightness() / 10).max(1);
        let cur = self.current_brightness();
        self.set_brightness(cur.saturating_sub(step));
    }

    /// Interface kind reported to sysfs consumers.
    fn kind(&self) -> BacklightKind;
}

// ── Global backlight registry + single-owner arbitration ─────────

static BACKLIGHT_DEVS: IrqSafeSpinLock<Vec<Arc<dyn BacklightDevice>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Outcome of a [`register_backlight`] call under single-owner
/// arbitration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ownership {
    /// The device is the panel's active owner: the only candidate
    /// the subsystem publishes (`/sys/class/backlight`) and
    /// dispatches brightness changes to (sysfs stores, brightness
    /// keys).
    Owner,
    /// The device is registered as a candidate, but another device
    /// owns the panel. A deferred candidate is never dispatched by
    /// the subsystem and must not drive hardware until it is
    /// promoted (the current owner unregisters, or it re-registers
    /// after the owner leaves).
    Deferred,
}

/// Elect the panel owner from the candidate list: the highest
/// [`BacklightKind::priority`] wins; ties keep the earliest
/// registration, so an incumbent owner is never displaced by an
/// equal-priority latecomer (no ownership flapping when two native
/// drivers probe in either order). A strictly higher-priority
/// candidate preempts — registration order between the Stage::Device
/// initcalls and PCI probe is not guaranteed, so the firmware
/// candidate that registered first must yield when the native
/// driver arrives.
fn elect_owner(cands: &[Arc<dyn BacklightDevice>]) -> Option<Arc<dyn BacklightDevice>> {
    let mut best: Option<&Arc<dyn BacklightDevice>> = None;
    for cand in cands {
        let wins = match best {
            None => true,
            Some(b) => cand.kind().priority() > b.kind().priority(),
        };
        if wins {
            best = Some(cand);
        }
    }
    best.cloned()
}

/// Register a backlight device as a candidate for panel ownership.
///
/// The name must be unique; duplicate names silently replace the
/// previous entry (matches Linux's `backlight_device_register`
/// idempotency assumption) and the replacement re-runs the election.
///
/// Returns the device's standing after this registration: it is the
/// panel [`Ownership::Owner`] if it won (or kept) the election, or
/// [`Ownership::Deferred`] if another candidate owns the panel.
/// Registrations are serialised by the registry lock, so concurrent
/// registrations still elect exactly one owner.
pub fn register_backlight(dev: Arc<dyn BacklightDevice>) -> Ownership {
    let name: String = dev.name().to_owned();
    let (standing, replaced) = {
        let mut g = BACKLIGHT_DEVS.lock();
        let replaced = if let Some(slot) = g.iter_mut().find(|d| d.name() == name) {
            *slot = dev;
            true
        } else {
            g.push(dev);
            false
        };
        let standing = match elect_owner(&g) {
            Some(owner) if owner.name() == name => Ownership::Owner,
            _ => Ownership::Deferred,
        };
        (standing, replaced)
    };
    // Publication follows the election dynamically (#952). The
    // sysfs attribute closures capture the device `Arc`, so a
    // same-name replacement must rebuild its directory rather than
    // leave sysfs driving the superseded device object.
    if replaced {
        sysfs_bridge::unpublish(&name);
    }
    sysfs_bridge::sync_publication();
    standing
}

/// Unregister a backlight device by name. If the removed device was
/// the panel owner, the highest-priority remaining candidate is
/// promoted automatically (see [`panel_owner`]) and the sysfs
/// publication is reconciled to match.
pub fn unregister_backlight(name: &str) {
    BACKLIGHT_DEVS.lock().retain(|d| d.name() != name);
    sysfs_bridge::sync_publication();
}

/// The panel's current owner, if any candidate is registered.
///
/// This is the only device subsystem paths may dispatch brightness
/// changes to: the sysfs bridge publishes it alone, and the
/// brightness-key handler steps it alone. Deferred candidates are
/// reachable via [`backlight_devices`] for diagnostics, but driving
/// one directly defeats the arbitration.
pub fn panel_owner() -> Option<Arc<dyn BacklightDevice>> {
    let g = BACKLIGHT_DEVS.lock();
    elect_owner(&g)
}

/// Return a snapshot of all registered backlight devices — the
/// panel owner plus any deferred candidates.
pub fn backlight_devices() -> Vec<Arc<dyn BacklightDevice>> {
    BACKLIGHT_DEVS.lock().clone()
}

/// Find a device by name.
pub fn backlight_device(name: &str) -> Option<Arc<dyn BacklightDevice>> {
    BACKLIGHT_DEVS
        .lock()
        .iter()
        .find(|d| d.name() == name)
        .cloned()
}

/// Test helper: drain all registries.
#[doc(hidden)]
pub fn __reset_all_for_test() {
    BACKLIGHT_DEVS.lock().clear();
    sysfs_bridge::sync_publication();
    leds::__reset_for_test();
}

// ── initcalls ─────────────────────────────────────────────────────

/// Register all Stage::Device initcalls for the backlight subsystem.
///
/// Called from the frame composition root
/// (`frame/src/bare_main.rs`) — before #947 nothing called this and
/// none of these initcalls ever ran in a production boot. There is
/// no AMD initcall: the AMD panel owner registers from the amdgpu
/// PCI probe, and dynamic publication (see [`register_backlight`])
/// means no initcall ordering against the probe is required.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "backlight/acpi-video", || {
        acpi_video::init();
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
    narf_init::register(Stage::Device, "backlight/sysfs", || {
        sysfs_bridge::populate_backlight_class();
        InitResult::Ok
    });
}
